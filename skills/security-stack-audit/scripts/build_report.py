#!/usr/bin/env python3
"""
build_report.py — Turn findings into a prioritized report + remediation plan.

Consumes scan_vulns.py output and produces:
  * a Markdown report (prioritized vulnerability list), and
  * a machine-readable remediation plan (plan.json) grouping upgrades per
    manifest with the exact command to run.

The plan is a *proposal only*. Nothing here modifies the project. The skill/agent
presents it for approval and applies it in batches; the "recommended" upgrade is
the lowest published fixed version at or above the installed one, with a flag when
that crosses a major version (likely breaking, needs human review).

Stdlib only (Python 3.8+).

Usage:
    python3 build_report.py FINDINGS.json [--md OUT.md] [--plan plan.json]
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone

BANDS = ["critical", "high", "medium", "low", "none", "unknown"]
BAND_RANK = {b: i for i, b in enumerate(BANDS)}
BAND_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵",
              "none": "⚪", "unknown": "⚪"}

# How to upgrade a single package, per ecosystem. {name}/{version} substituted.
UPGRADE_CMD = {
    "npm": "npm install {name}@{version}",
    "PyPI": "python -m pip install '{name}=={version}'",
    "Go": "go get {name}@v{version} && go mod tidy",
    "crates.io": "cargo update -p {name} --precise {version}",
    "RubyGems": "bundle update {name} --conservative",
    "Packagist": "composer require {name}:{version} --update-with-dependencies",
}
# For lockfile-managed transitive deps, the honest command differs.
TRANSITIVE_NOTE = {
    "npm": "transitive — may need `npm audit fix`, an override, or bumping the parent dependency",
    "PyPI": "transitive — pin via your resolver (poetry/pip-tools) and re-lock",
    "Go": "run `go get` on the module; Go MVS will select it if a parent allows",
    "crates.io": "transitive — `cargo update -p {name}` if a parent's range permits",
    "RubyGems": "transitive — `bundle update {name}` if the parent gem allows",
    "Packagist": "transitive — bump the requiring package",
}


def parse_version(v):
    """Loose version tuple for comparison. Splits on . and -, numeric parts
    compared numerically, else lexically. Good enough to order fixed versions."""
    v = str(v).lstrip("vV")
    parts = re.split(r"[.\-+]", v)
    key = []
    for p in parts:
        if p.isdigit():
            key.append((1, int(p), ""))
        else:
            # pre-release/build tags sort before a bare number of same position
            key.append((0, 0, p))
    return key


def vcmp(a, b):
    ka, kb = parse_version(a), parse_version(b)
    for i in range(max(len(ka), len(kb))):
        x = ka[i] if i < len(ka) else (1, 0, "")
        y = kb[i] if i < len(kb) else (1, 0, "")
        if x < y:
            return -1
        if x > y:
            return 1
    return 0


def major_of(v):
    m = re.match(r"[vV]?(\d+)", str(v))
    return int(m.group(1)) if m else None


def recommend_target(current, vulns):
    """Choose the lowest single version that clears EVERY matched advisory.

    Each advisory is cleared by upgrading to its own nearest fix above `current`.
    To clear them all with one upgrade, the target must be at least the highest
    of those per-advisory minimums — so we take the max. Picking the lowest fix
    across advisories (the naive approach) would leave the package exposed to any
    advisory fixed only in a later release.

    Returns (target, crosses_major, unfixable_count) where unfixable_count is the
    number of matched advisories with no published fix above `current`.
    """
    per_advisory_min = []
    unfixable = 0
    for v in vulns:
        above = [f for f in (v.get("fixed_versions") or []) if vcmp(f, current) > 0]
        if above:
            above.sort(key=parse_version)
            per_advisory_min.append(above[0])
        else:
            unfixable += 1
    if not per_advisory_min:
        return None, False, unfixable
    target = max(per_advisory_min, key=parse_version)
    cm, tm = major_of(current), major_of(target)
    crosses = (cm is not None and tm is not None and tm > cm)
    return target, crosses, unfixable


def worst_band(vulns):
    best = "unknown"
    best_rank = BAND_RANK["unknown"]
    for v in vulns:
        band = (v.get("severity") or {}).get("band") or "unknown"
        if BAND_RANK.get(band, 99) < best_rank:
            best, best_rank = band, BAND_RANK[band]
    return best


def build_plan(findings):
    """Group actionable upgrades by source manifest."""
    by_source = {}
    unresolved = []
    for f in findings:
        # collect all fixed versions across this package's vulns (for display)
        all_fixed = []
        for v in f["vulnerabilities"]:
            for fv in v.get("fixed_versions", []):
                if fv not in all_fixed:
                    all_fixed.append(fv)
        target, crosses, unfixable = recommend_target(f["version"], f["vulnerabilities"])
        eco = f["ecosystem"]
        entry = {
            "ecosystem": eco,
            "name": f["name"],
            "current_version": f["version"],
            "source": f["source"],
            "direct": f.get("direct", False),
            "worst_severity": worst_band(f["vulnerabilities"]),
            "vuln_ids": [v["id"] for v in f["vulnerabilities"]],
            "cve_ids": sorted({c for v in f["vulnerabilities"] for c in v.get("cve_ids", [])}),
            "fixed_versions_available": all_fixed,
        }
        if target:
            cmd = UPGRADE_CMD.get(eco, "(manual upgrade)").format(name=f["name"], version=target)
            notes = []
            if not f.get("direct"):
                notes.append(TRANSITIVE_NOTE.get(eco, "transitive dependency").format(name=f["name"]))
            if unfixable:
                notes.append(f"{unfixable} of {len(f['vulnerabilities'])} advisories have no "
                             "published fix — this upgrade clears the rest; see 'no fix' items")
            entry.update({
                "action": "upgrade",
                "recommended_version": target,
                "crosses_major": crosses,
                "clears_all": unfixable == 0,
                "command": cmd if (f.get("direct") or eco in ("Go", "RubyGems")) else None,
                "note": "; ".join(notes) or None,
            })
        else:
            entry.update({
                "action": "no-fix-available",
                "recommended_version": None,
                "note": "No published fix at or above the installed version. "
                        "Consider mitigations, pinning, or replacing the dependency.",
            })
            unresolved.append(entry)
        by_source.setdefault(f["source"], []).append(entry)

    # order each group by severity, then direct-first
    for src in by_source:
        by_source[src].sort(key=lambda e: (BAND_RANK.get(e["worst_severity"], 99),
                                           0 if e["direct"] else 1, e["name"]))
    return by_source, unresolved


def render_markdown(data, plan_by_source, unresolved):
    s = data.get("summary", {})
    by_sev = s.get("by_severity", {})
    lines = []
    lines.append("# Security Stack Audit")
    lines.append("")
    lines.append(f"- **Project:** `{data.get('project','.')}`")
    lines.append(f"- **Scanned:** {data.get('scanned_package_count','?')} resolved packages")
    lines.append(f"- **Sources:** {', '.join(data.get('sources', []))}")
    lines.append(f"- **Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"**{s.get('affected_packages',0)} affected packages · "
                 f"{s.get('total_vulnerabilities',0)} advisories**")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for band in BANDS:
        c = by_sev.get(band, 0)
        if c:
            lines.append(f"| {BAND_EMOJI[band]} {band.title()} | {c} |")
    lines.append("")

    if not data.get("findings"):
        lines.append("✅ **No known vulnerabilities matched the resolved dependency versions.**")
        lines.append("")
    else:
        lines.append("## Findings (most severe first)")
        lines.append("")
        # flatten and sort packages by worst band
        flat = []
        for src, entries in plan_by_source.items():
            flat.extend(entries)
        flat.sort(key=lambda e: (BAND_RANK.get(e["worst_severity"], 99),
                                 0 if e["direct"] else 1, e["name"]))
        # map source->findings for detail lookups
        fmap = {(f["ecosystem"], f["name"], f["version"]): f for f in data["findings"]}
        for e in flat:
            f = fmap.get((e["ecosystem"], e["name"], e["current_version"]), {})
            head = (f"### {BAND_EMOJI[e['worst_severity']]} `{e['name']}` "
                    f"{e['current_version']} — {e['worst_severity'].title()}")
            lines.append(head)
            tag = "direct" if e["direct"] else "transitive"
            lines.append(f"*{e['ecosystem']} · {tag} · from `{e['source']}`*")
            lines.append("")
            for v in f.get("vulnerabilities", []):
                band = (v.get("severity") or {}).get("band") or "unknown"
                cves = ", ".join(v.get("cve_ids", [])) or "—"
                score = (v.get("severity") or {}).get("score")
                score_txt = f" (CVSS {score})" if score is not None else ""
                fixed = ", ".join(v.get("fixed_versions", [])) or "no fix listed"
                summary = (v.get("summary") or "").strip().replace("\n", " ")
                lines.append(f"- **{v['id']}**{score_txt} · {BAND_EMOJI.get(band,'⚪')} {band} · CVE: {cves}")
                if summary:
                    lines.append(f"  - {summary}")
                lines.append(f"  - Fixed in: {fixed}")
            if e["action"] == "upgrade":
                warn = " ⚠️ **major version bump — review for breaking changes**" if e.get("crosses_major") else ""
                lines.append(f"- **➡ Recommended:** upgrade to **{e['recommended_version']}**{warn}")
                if e.get("command"):
                    lines.append(f"  - `{e['command']}`")
                if e.get("note"):
                    lines.append(f"  - _{e['note']}_")
            else:
                lines.append(f"- **⛔ {e['note']}**")
            lines.append("")

        lines.append("## Recommended remediation plan")
        lines.append("")
        lines.append("Grouped by manifest. Apply in order; re-run the scan after each "
                     "batch to confirm the count drops. Nothing is changed until you approve.")
        lines.append("")
        for src, entries in sorted(plan_by_source.items(),
                                   key=lambda kv: min(BAND_RANK.get(e["worst_severity"], 99) for e in kv[1])):
            actionable = [e for e in entries if e["action"] == "upgrade"]
            if not actionable:
                continue
            lines.append(f"### `{src}`")
            lines.append("")
            for e in actionable:
                warn = " ⚠️ major bump" if e.get("crosses_major") else ""
                cmd = e.get("command") or f"(resolve transitively — {e.get('note','')})"
                lines.append(f"- `{e['name']}` {e['current_version']} → **{e['recommended_version']}**{warn}")
                lines.append(f"  ```bash")
                lines.append(f"  {cmd}")
                lines.append(f"  ```")
            lines.append("")

    if unresolved:
        lines.append("## ⛔ No fix available")
        lines.append("")
        lines.append("These need mitigation, pinning, or replacement rather than an upgrade:")
        lines.append("")
        for e in unresolved:
            lines.append(f"- `{e['name']}` {e['current_version']} ({e['worst_severity']}) — "
                         f"{', '.join(e['vuln_ids'])}")
        lines.append("")

    if data.get("unsupported_manifests"):
        lines.append("## ⚠️ Not scanned (needs a lockfile or build tool)")
        lines.append("")
        for u in data["unsupported_manifests"]:
            lines.append(f"- `{u['file']}` — {u['hint']}")
        lines.append("")
    if data.get("inventory_warnings"):
        lines.append("## Notes")
        lines.append("")
        for w in data["inventory_warnings"]:
            lines.append(f"- {w}")
        lines.append("")

    lines.append("---")
    lines.append("_Version matching is done by OSV against resolved lockfile versions. "
                 "Reachability is not analyzed — a matched advisory may or may not be exploitable "
                 "in your usage. Review before applying, especially major bumps._")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build a prioritized report and remediation plan.")
    ap.add_argument("findings", help="scan_vulns.py output JSON")
    ap.add_argument("--md", dest="md", help="Write Markdown report here")
    ap.add_argument("--plan", dest="plan", help="Write machine-readable plan.json here")
    args = ap.parse_args(argv)

    with open(args.findings, encoding="utf-8") as fh:
        data = json.load(fh)

    plan_by_source, unresolved = build_plan(data.get("findings", []))
    md = render_markdown(data, plan_by_source, unresolved)

    plan = {
        "project": data.get("project"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": data.get("summary", {}),
        "batches_by_source": plan_by_source,
        "no_fix_available": unresolved,
        "unsupported_manifests": data.get("unsupported_manifests", []),
    }

    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(md)
    if args.plan:
        with open(args.plan, "w", encoding="utf-8") as fh:
            json.dump(plan, fh, indent=2)

    # Always print the markdown so the caller sees it even without --md
    print(md)
    if not args.md and not args.plan:
        sys.stderr.write("\n[build_report] tip: pass --md report.md --plan plan.json to save outputs\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
