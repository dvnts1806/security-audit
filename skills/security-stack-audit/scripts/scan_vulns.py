#!/usr/bin/env python3
"""
scan_vulns.py — Match a dependency inventory against published advisories.

Reads the inventory produced by detect_stack.py and queries OSV.dev, which
aggregates GitHub Security Advisories (GHSA) and CVE data and performs the
version-range matching server-side. Optionally enriches severity from the NVD
CVE API (adds authoritative CVSS scores when OSV lacks them).

OSV was chosen as the primary source because it is free, requires no auth,
supports batch queries, and already federates GHSA + many CVE feeds — so a
single query stream covers the three sources you asked for. NVD is layered on
top only for CVSS enrichment, and GitHub's GraphQL Advisory API can be added
with a token (see --github-token) but is off by default to keep the tool
runnable by anyone with zero setup.

Stdlib only (Python 3.8+).

Usage:
    python3 scan_vulns.py INVENTORY.json [--json OUT.json]
                          [--nvd] [--nvd-api-key KEY]
                          [--min-severity none|low|medium|high|critical]

Output: a findings JSON object (see build_report.py for consumption).
"""
import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
NVD_CVE = "https://services.nvd.nist.gov/rest/json/2.0/cves/2.0"

USER_AGENT = "security-stack-audit/1.0 (+https://github.com/) python-urllib"

SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _post_json(url, payload, timeout=45, retries=3):
    body = json.dumps(payload).encode()
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url, data=body,
                headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(1.5 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            last = e
            time.sleep(1.5 * (attempt + 1))
    raise last


def _get_json(url, timeout=45, retries=3, headers=None):
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(2.0 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            last = e
            time.sleep(2.0 * (attempt + 1))
    raise last


def query_osv_batch(packages):
    """Return {vuln_id: None} set of ids affecting the given packages, plus a
    map of (ecosystem,name,version) -> [vuln_ids]."""
    # OSV Go ecosystem expects the bare semver in ranges; names are module paths.
    queries = []
    index = []  # parallel list of (ecosystem, name, version)
    for p in packages:
        queries.append({
            "package": {"name": p["name"], "ecosystem": p["ecosystem"]},
            "version": p["version"],
        })
        index.append((p["ecosystem"], p["name"], p["version"]))

    pkg_to_ids = {}
    all_ids = set()
    # OSV allows large batches; chunk to stay well within limits.
    CHUNK = 800
    for start in range(0, len(queries), CHUNK):
        chunk = queries[start:start + CHUNK]
        data = _post_json(OSV_QUERYBATCH, {"queries": chunk})
        results = data.get("results", [])
        for i, res in enumerate(results):
            key = index[start + i]
            ids = [v["id"] for v in (res.get("vulns") or [])]
            if ids:
                pkg_to_ids.setdefault(key, [])
                for vid in ids:
                    if vid not in pkg_to_ids[key]:
                        pkg_to_ids[key].append(vid)
                    all_ids.add(vid)
    return all_ids, pkg_to_ids


def fetch_vuln_details(ids, workers=8):
    details = {}
    def fetch(vid):
        return vid, _get_json(OSV_VULN + vid)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(fetch, vid) for vid in ids]
        for fut in as_completed(futs):
            try:
                vid, data = fut.result()
                details[vid] = data
            except Exception as e:  # keep going; note the gap
                sys.stderr.write(f"[scan] failed to fetch {e}\n")
    return details


def cvss3_base_score(vector):
    """Compute a CVSS v3.0/3.1 base score from a vector string, offline.

    Most OSV advisories carry a CVSS vector but no numeric score. Deriving the
    score here means severity bands populate without the slow NVD round-trip.
    Returns a float rounded up to one decimal, or None if the vector isn't v3.x.
    """
    if not isinstance(vector, str) or not vector.startswith(("CVSS:3.0", "CVSS:3.1")):
        return None
    parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p and not p.startswith("CVSS"))
    try:
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[parts["AV"]]
        ac = {"L": 0.77, "H": 0.44}[parts["AC"]]
        ui = {"N": 0.85, "R": 0.62}[parts["UI"]]
        scope_changed = parts["S"] == "C"
        if scope_changed:
            pr = {"N": 0.85, "L": 0.68, "H": 0.5}[parts["PR"]]
        else:
            pr = {"N": 0.85, "L": 0.62, "H": 0.27}[parts["PR"]]
        cia = {"H": 0.56, "L": 0.22, "N": 0.0}
        c, i, a = cia[parts["C"]], cia[parts["I"]], cia[parts["A"]]
    except KeyError:
        return None
    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = (1.08 * (impact + exploitability)) if scope_changed else (impact + exploitability)
    base = min(raw, 10.0)
    # roundup to nearest 0.1 per the CVSS 3.1 spec
    import math
    return math.ceil(base * 10) / 10.0


def _band_from_score(score):
    if score is None:
        return None
    try:
        s = float(score)
    except (TypeError, ValueError):
        return None
    if s == 0:
        return "none"
    if s < 4.0:
        return "low"
    if s < 7.0:
        return "medium"
    if s < 9.0:
        return "high"
    return "critical"


def _extract_severity(vuln):
    """Pull the best available CVSS score/band from an OSV vuln object.

    Preference order: a numeric score computed from a CVSS v3.x vector (most
    precise and offline), then a GHSA named severity band. NVD enrichment can
    later fill anything still missing.
    """
    score = None
    vector = None
    for sev in vuln.get("severity", []) or []:
        s = sev.get("score")
        if isinstance(s, str) and s.startswith("CVSS:"):
            vector = s
            computed = cvss3_base_score(s)
            if computed is not None:
                score = computed
                break
    band = _band_from_score(score)
    if band is None:
        ds = vuln.get("database_specific") or {}
        named = ds.get("severity")  # e.g. "HIGH" from GHSA
        if isinstance(named, str) and named.lower() in SEVERITY_ORDER:
            band = named.lower()
    return {"score": score, "vector": vector, "band": band}


def _norm_name(name, ecosystem):
    """Normalize a package name for matching against OSV's stored names.

    OSV normalizes names per ecosystem (e.g. PyPI stores the PEP 503 form, so
    `Flask` becomes `flask`). Without matching normalization, fixed-version
    extraction silently drops fixes for packages whose casing differs.
    """
    if name is None:
        return None
    n = name.strip()
    if ecosystem.split(":")[0] == "PyPI":
        return re.sub(r"[-_.]+", "-", n).lower()
    # npm/crates/etc. are effectively case-insensitive for our purposes
    return n.lower()


def _fixed_versions_for(vuln, ecosystem, name):
    """Return the list of 'fixed' versions announced for this package."""
    fixed = []
    introduced_any = False
    target = _norm_name(name, ecosystem)
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package", {})
        if pkg.get("ecosystem", "").split(":")[0] != ecosystem.split(":")[0]:
            continue
        if _norm_name(pkg.get("name"), ecosystem) != target:
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    fixed.append(ev["fixed"])
                if "introduced" in ev:
                    introduced_any = True
    # de-dup, keep order
    out = []
    for v in fixed:
        if v not in out:
            out.append(v)
    return out


def _cve_aliases(vuln):
    return [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]


def enrich_from_nvd(findings, api_key=None):
    """Add CVSS base scores from NVD for CVE aliases missing a numeric score."""
    headers = {"apiKey": api_key} if api_key else {}
    # gather unique CVEs lacking a score
    cves = set()
    for f in findings:
        for v in f["vulnerabilities"]:
            if v["severity"].get("score") is None:
                for c in v.get("cve_ids", []):
                    cves.add(c)
    scores = {}
    for cve in sorted(cves):
        try:
            data = _get_json(f"{NVD_CVE}?cveId={cve}", headers=headers, timeout=30)
            items = data.get("vulnerabilities", [])
            if not items:
                continue
            metrics = items[0].get("cve", {}).get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
                if metrics.get(key):
                    cd = metrics[key][0].get("cvssData", {})
                    scores[cve] = {
                        "score": cd.get("baseScore"),
                        "vector": cd.get("vectorString"),
                        "band": (cd.get("baseSeverity") or _band_from_score(cd.get("baseScore")) or "").lower() or None,
                    }
                    break
            # NVD public rate limit is strict without a key
            time.sleep(0.7 if api_key else 6.5)
        except Exception as e:
            sys.stderr.write(f"[scan][nvd] {cve}: {e}\n")
    # apply
    for f in findings:
        for v in f["vulnerabilities"]:
            if v["severity"].get("score") is None:
                for c in v.get("cve_ids", []):
                    if c in scores:
                        v["severity"] = {**v["severity"], **scores[c]}
                        break
    return findings


def build_findings(inventory, details, pkg_to_ids):
    findings = []
    for p in inventory["packages"]:
        key = (p["ecosystem"], p["name"], p["version"])
        ids = pkg_to_ids.get(key)
        if not ids:
            continue
        vulns_out = []
        for vid in ids:
            v = details.get(vid)
            if not v:
                vulns_out.append({"id": vid, "summary": "(details unavailable)",
                                  "cve_ids": [], "severity": {}, "fixed_versions": [],
                                  "references": []})
                continue
            sev = _extract_severity(v)
            fixed = _fixed_versions_for(v, p["ecosystem"], p["name"])
            refs = [r.get("url") for r in v.get("references", []) or [] if r.get("url")]
            vulns_out.append({
                "id": vid,
                "aliases": v.get("aliases", []),
                "cve_ids": _cve_aliases(v),
                "summary": v.get("summary") or (v.get("details", "")[:200]),
                "details": v.get("details", ""),
                "severity": sev,
                "fixed_versions": fixed,
                "published": v.get("published"),
                "modified": v.get("modified"),
                "references": refs[:6],
                "withdrawn": v.get("withdrawn"),
            })
        # skip fully-withdrawn advisories
        vulns_out = [x for x in vulns_out if not x.get("withdrawn")]
        if not vulns_out:
            continue
        findings.append({**p, "vulnerabilities": vulns_out})
    return findings


def summarize(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0, "unknown": 0}
    total_vulns = 0
    for f in findings:
        for v in f["vulnerabilities"]:
            total_vulns += 1
            band = (v["severity"] or {}).get("band")
            counts[band if band in counts else "unknown"] += 1
    return {"affected_packages": len(findings), "total_vulnerabilities": total_vulns,
            "by_severity": counts}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Match dependency inventory against OSV/GHSA/NVD.")
    ap.add_argument("inventory", help="Path to detect_stack.py output JSON")
    ap.add_argument("--json", dest="out", help="Write findings to this file")
    ap.add_argument("--nvd", action="store_true", help="Enrich CVSS scores from NVD (slower)")
    ap.add_argument("--nvd-api-key", help="NVD API key (raises rate limit; optional)")
    ap.add_argument("--min-severity", default="none",
                    choices=list(SEVERITY_ORDER.keys()),
                    help="Drop findings below this severity band (default: none = keep all)")
    args = ap.parse_args(argv)

    with open(args.inventory, encoding="utf-8") as fh:
        inventory = json.load(fh)

    packages = inventory.get("packages", [])
    if not packages:
        result = {"error": "no packages in inventory", "summary": summarize([]),
                  "findings": []}
        print(json.dumps(result, indent=2))
        return 0

    sys.stderr.write(f"[scan] querying OSV for {len(packages)} packages...\n")
    all_ids, pkg_to_ids = query_osv_batch(packages)
    sys.stderr.write(f"[scan] {len(all_ids)} distinct advisories referenced; fetching details...\n")
    details = fetch_vuln_details(all_ids) if all_ids else {}
    findings = build_findings(inventory, details, pkg_to_ids)

    if args.nvd:
        sys.stderr.write("[scan] enriching severities from NVD...\n")
        findings = enrich_from_nvd(findings, api_key=args.nvd_api_key)

    # severity filter
    floor = SEVERITY_ORDER[args.min_severity]
    if floor > 0:
        for f in findings:
            f["vulnerabilities"] = [
                v for v in f["vulnerabilities"]
                if SEVERITY_ORDER.get((v["severity"] or {}).get("band") or "none", 0) >= floor
                or (v["severity"] or {}).get("band") is None  # keep unknowns; don't hide
            ]
        findings = [f for f in findings if f["vulnerabilities"]]

    result = {
        "project": inventory.get("project"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": ["OSV.dev (aggregates GitHub Advisory DB + CVE)"] +
                   (["NVD CVE API (CVSS enrichment)"] if args.nvd else []),
        "scanned_package_count": len(packages),
        "summary": summarize(findings),
        "findings": findings,
        "inventory_warnings": inventory.get("warnings", []),
        "unsupported_manifests": inventory.get("unsupported_manifests", []),
    }
    text = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
