#!/usr/bin/env python3
"""
detect_stack.py — Discover the dependency stack of a project.

Walks a project directory, finds dependency manifests and (preferring) lockfiles,
and produces a normalized inventory of resolved packages that can be matched
against vulnerability databases.

Lockfiles are preferred over manifests because they pin the *resolved* version
that is actually installed — which is what a CVE match needs. A manifest range
like "^1.2.0" tells you nothing about whether the vulnerable 1.2.3 or the fixed
1.2.9 is on disk.

Stdlib only (Python 3.8+). No third-party dependencies, no network.

Usage:
    python3 detect_stack.py [PROJECT_DIR] [--json OUT.json]

Output (stdout, and OUT.json if given): a JSON object
    {
      "project": "/abs/path",
      "generated_at": "ISO-8601",
      "packages": [
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.11",
         "direct": true, "source": "package-lock.json"}
      ],
      "sources_scanned": ["package-lock.json", "requirements.txt"],
      "unsupported_manifests": ["pom.xml"],
      "warnings": ["..."]
    }
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

# Try the stdlib TOML parser (3.11+). Fall back to a tiny extractor otherwise.
try:
    import tomllib  # type: ignore

    def _load_toml(text):
        return tomllib.loads(text)
    _HAVE_TOML = True
except Exception:  # pragma: no cover - exercised on <3.11
    _HAVE_TOML = False

# Directories we never descend into — vendored/installed trees would flood the
# inventory with duplicates and are not the project's declared stack.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "vendor",
    ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache",
    "dist", "build", "target", ".next", ".nuxt", ".gradle", ".idea",
    ".pytest_cache", "site-packages", ".cargo", ".terraform",
}

# Lockfiles/manifests OSV can match, keyed by filename.
KNOWN_FILES = {
    # npm ecosystem
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "package.json",
    # PyPI
    "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements.txt",
    # Go
    "go.mod",
    # Rust
    "Cargo.lock",
    # Ruby
    "Gemfile.lock",
    # PHP
    "composer.lock",
}

# Manifests we recognize but cannot resolve without a lockfile or a build tool.
UNSUPPORTED_HINTS = {
    "pom.xml": "Maven — no reliable lockfile; run `mvn dependency:tree` or add a lockfile",
    "build.gradle": "Gradle — enable dependency locking (gradle.lockfile) for exact versions",
    "build.gradle.kts": "Gradle — enable dependency locking (gradle.lockfile) for exact versions",
    "packages.config": "NuGet — prefer packages.lock.json",
    "mix.exs": "Hex — parse mix.lock (not yet supported here)",
    "pubspec.yaml": "Pub — parse pubspec.lock (not yet supported here)",
}


def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _minimal_toml_packages(text):
    """Extract [[package]] name/version pairs without a TOML library.

    Only needs to handle Cargo.lock / poetry.lock / uv.lock style tables, which
    are line-oriented. Good enough for inventory when tomllib is unavailable.
    """
    pkgs = []
    cur = {}
    in_pkg = False
    for line in text.splitlines():
        s = line.strip()
        if s == "[[package]]":
            if cur.get("name") and cur.get("version"):
                pkgs.append(cur)
            cur = {}
            in_pkg = True
            continue
        if s.startswith("[") and s != "[[package]]":
            if in_pkg and cur.get("name") and cur.get("version"):
                pkgs.append(cur)
            cur = {}
            in_pkg = False
            continue
        if in_pkg:
            m = re.match(r'(name|version)\s*=\s*"([^"]*)"', s)
            if m:
                cur[m.group(1)] = m.group(2)
    if in_pkg and cur.get("name") and cur.get("version"):
        pkgs.append(cur)
    return pkgs


# --------------------------------------------------------------------------- #
# Per-ecosystem parsers. Each returns a list of (name, version, direct) tuples.
# `direct` is best-effort; None when we can't tell.
# --------------------------------------------------------------------------- #

def parse_package_lock(text, direct_names):
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    seen = set()
    # v2/v3: "packages" map keyed by path ("" is the root, "node_modules/x").
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue
            ver = meta.get("version")
            # last path segment after node_modules/ is the package name
            name = path.split("node_modules/")[-1]
            if name and ver:
                key = (name, ver)
                if key not in seen:
                    seen.add(key)
                    out.append((name, ver, name in direct_names))
    # v1 fallback: nested "dependencies"
    if not out:
        def walk(deps):
            for name, meta in (deps or {}).items():
                if isinstance(meta, dict) and meta.get("version"):
                    key = (name, meta["version"])
                    if key not in seen:
                        seen.add(key)
                        out.append((name, meta["version"], name in direct_names))
                    walk(meta.get("dependencies"))
        walk(data.get("dependencies"))
    return out


def parse_yarn_lock(text, direct_names):
    out = []
    # Blocks separated by blank lines. A block header is one or more quoted or
    # bare specifiers ("foo@^1.0.0", ...) ending with ":", then an indented
    # `version "1.2.3"` line.
    block_names = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" ") and raw.rstrip().endswith(":"):
            header = raw.rstrip()[:-1]
            block_names = []
            for spec in header.split(","):
                spec = spec.strip().strip('"')
                # strip the @range suffix; keep scoped @org/name
                at = spec.rfind("@")
                nm = spec[:at] if at > 0 else spec
                if nm:
                    block_names.append(nm)
        else:
            m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', raw)
            if m and block_names:
                ver = m.group(1)
                for nm in block_names:
                    out.append((nm, ver, nm in direct_names))
                block_names = []
    return out


def parse_pnpm_lock(text, direct_names):
    out = []
    seen = set()
    # pnpm keys look like "/foo@1.2.3:" (v6) or "/foo/1.2.3:" (v5) or
    # "foo@1.2.3:" under packages:. Capture name + version broadly.
    for line in text.splitlines():
        s = line.strip()
        if not s.endswith(":") or "@" not in s and "/" not in s:
            continue
        key = s[:-1].strip().strip("'\"")
        name = ver = None
        m = re.match(r"^/?(@?[^@/]+(?:/[^@/]+)?)@([0-9][^():]*)", key)
        if m:
            name, ver = m.group(1), m.group(2)
        else:
            m = re.match(r"^/(@?[^/]+(?:/[^/]+)?)/([0-9][^_():]*)", key)
            if m:
                name, ver = m.group(1), m.group(2)
        if name and ver:
            ver = ver.split("(")[0].split("_")[0]
            k = (name, ver)
            if k not in seen:
                seen.add(k)
                out.append((name, ver, name in direct_names))
    return out


def parse_requirements_txt(text):
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        # only exact pins are meaningful for matching
        m = re.match(r"^([A-Za-z0-9._-]+)\s*==\s*([A-Za-z0-9._!+-]+)", line)
        if m:
            out.append((m.group(1), m.group(2), True))
    return out


def parse_pipfile_lock(text):
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for section, direct in (("default", True), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            ver = (meta or {}).get("version", "")
            m = re.match(r"==\s*(.+)", ver.strip())
            if m:
                out.append((name, m.group(1).strip(), direct))
    return out


def parse_toml_lock(text):
    """Cargo.lock / poetry.lock / uv.lock / pdm.lock — [[package]] tables."""
    pkgs = []
    if _HAVE_TOML:
        try:
            data = _load_toml(text)
            for p in data.get("package", []) or []:
                if p.get("name") and p.get("version"):
                    pkgs.append({"name": p["name"], "version": p["version"]})
        except Exception:
            pkgs = _minimal_toml_packages(text)
    else:
        pkgs = _minimal_toml_packages(text)
    return [(p["name"], p["version"], None) for p in pkgs]


def parse_go_mod(text):
    out = []
    seen = set()
    in_block = False
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        # single-line: require module v1.2.3   |   block line: module v1.2.3
        m = re.match(r"^(?:require\s+)?([\w./\-]+)\s+v([0-9][\w.\-+]*)", s)
        if (in_block or s.startswith("require ")) and m:
            name, ver = m.group(1), m.group(2)  # strip leading 'v' for OSV
            if "// indirect" in raw:
                direct = False
            else:
                direct = True
            k = (name, ver)
            if k not in seen:
                seen.add(k)
                out.append((name, ver, direct))
    return out


def parse_gemfile_lock(text):
    out = []
    in_specs = False
    for raw in text.splitlines():
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            if raw and not raw.startswith(" "):
                in_specs = False
                continue
            m = re.match(r"^\s{4}([A-Za-z0-9._-]+) \(([^()]+)\)", raw)
            if m:
                out.append((m.group(1), m.group(2), None))
    return out


def parse_composer_lock(text):
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    for section, direct in (("packages", True), ("packages-dev", True)):
        for p in data.get(section, []) or []:
            name = p.get("name")
            ver = (p.get("version") or "").lstrip("v")
            if name and ver:
                out.append((name, ver, direct))
    return out


def _npm_direct_names(dir_path):
    """Read package.json siblings to know which npm deps are direct."""
    names = set()
    pj = os.path.join(dir_path, "package.json")
    if os.path.exists(pj):
        try:
            data = json.loads(_read(pj))
            for field in ("dependencies", "devDependencies",
                          "optionalDependencies", "peerDependencies"):
                names.update((data.get(field) or {}).keys())
        except Exception:
            pass
    return names


# Priority: when multiple npm lockfiles exist, prefer the most authoritative.
NPM_LOCK_PRIORITY = ["package-lock.json", "npm-shrinkwrap.json",
                     "pnpm-lock.yaml", "yarn.lock"]


def scan(project_dir):
    project_dir = os.path.abspath(project_dir)
    found = {}  # filename -> abspath (first occurrence per directory handled below)
    found_list = []
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")
                   or d in {".github"}]
        for f in files:
            if f in KNOWN_FILES or f in UNSUPPORTED_HINTS:
                found_list.append(os.path.join(root, f))

    packages = []
    sources_scanned = []
    unsupported = {}
    warnings = []

    # Group by directory so we can apply npm lockfile priority per package root.
    by_dir = {}
    for path in found_list:
        by_dir.setdefault(os.path.dirname(path), []).append(os.path.basename(path))

    def rel(path):
        return os.path.relpath(path, project_dir)

    for dir_path, names in sorted(by_dir.items()):
        nameset = set(names)

        # ---- npm: pick one lockfile, fall back to package.json ranges are ignored ----
        npm_lock = next((n for n in NPM_LOCK_PRIORITY if n in nameset), None)
        if npm_lock:
            direct_names = _npm_direct_names(dir_path)
            text = _read(os.path.join(dir_path, npm_lock))
            if npm_lock in ("package-lock.json", "npm-shrinkwrap.json"):
                rows = parse_package_lock(text, direct_names)
            elif npm_lock == "yarn.lock":
                rows = parse_yarn_lock(text, direct_names)
            else:
                rows = parse_pnpm_lock(text, direct_names)
            for nm, ver, direct in rows:
                packages.append({"ecosystem": "npm", "name": nm, "version": ver,
                                 "direct": bool(direct), "source": rel(os.path.join(dir_path, npm_lock))})
            sources_scanned.append(rel(os.path.join(dir_path, npm_lock)))
        elif "package.json" in nameset:
            warnings.append(f"{rel(os.path.join(dir_path,'package.json'))}: no lockfile — "
                            "version ranges cannot be matched precisely; run `npm install` to "
                            "generate package-lock.json")

        # ---- Python ----
        for fn, parser, direct_only in (
            ("poetry.lock", parse_toml_lock, False),
            ("uv.lock", parse_toml_lock, False),
            ("pdm.lock", parse_toml_lock, False),
            ("Pipfile.lock", parse_pipfile_lock, None),
            ("requirements.txt", parse_requirements_txt, None),
        ):
            if fn in nameset:
                text = _read(os.path.join(dir_path, fn))
                rows = parser(text)
                for nm, ver, direct in rows:
                    packages.append({"ecosystem": "PyPI", "name": nm, "version": ver,
                                     "direct": bool(direct) if direct is not None else False,
                                     "source": rel(os.path.join(dir_path, fn))})
                if rows:
                    sources_scanned.append(rel(os.path.join(dir_path, fn)))

        # ---- Go ----
        if "go.mod" in nameset:
            rows = parse_go_mod(_read(os.path.join(dir_path, "go.mod")))
            for nm, ver, direct in rows:
                packages.append({"ecosystem": "Go", "name": nm, "version": ver,
                                 "direct": bool(direct), "source": rel(os.path.join(dir_path, "go.mod"))})
            if rows:
                sources_scanned.append(rel(os.path.join(dir_path, "go.mod")))

        # ---- Rust ----
        if "Cargo.lock" in nameset:
            rows = parse_toml_lock(_read(os.path.join(dir_path, "Cargo.lock")))
            for nm, ver, _ in rows:
                packages.append({"ecosystem": "crates.io", "name": nm, "version": ver,
                                 "direct": False, "source": rel(os.path.join(dir_path, "Cargo.lock"))})
            if rows:
                sources_scanned.append(rel(os.path.join(dir_path, "Cargo.lock")))

        # ---- Ruby ----
        if "Gemfile.lock" in nameset:
            rows = parse_gemfile_lock(_read(os.path.join(dir_path, "Gemfile.lock")))
            for nm, ver, _ in rows:
                packages.append({"ecosystem": "RubyGems", "name": nm, "version": ver,
                                 "direct": False, "source": rel(os.path.join(dir_path, "Gemfile.lock"))})
            if rows:
                sources_scanned.append(rel(os.path.join(dir_path, "Gemfile.lock")))

        # ---- PHP ----
        if "composer.lock" in nameset:
            rows = parse_composer_lock(_read(os.path.join(dir_path, "composer.lock")))
            for nm, ver, direct in rows:
                packages.append({"ecosystem": "Packagist", "name": nm, "version": ver,
                                 "direct": bool(direct), "source": rel(os.path.join(dir_path, "composer.lock"))})
            if rows:
                sources_scanned.append(rel(os.path.join(dir_path, "composer.lock")))

        # ---- unsupported manifests (note only if no lockfile covered them) ----
        for fn, hint in UNSUPPORTED_HINTS.items():
            if fn in nameset:
                unsupported[rel(os.path.join(dir_path, fn))] = hint

    # de-dup identical (ecosystem, name, version, source)
    seen = set()
    deduped = []
    for p in packages:
        k = (p["ecosystem"], p["name"], p["version"], p["source"])
        if k not in seen:
            seen.add(k)
            deduped.append(p)

    return {
        "project": project_dir,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "packages": deduped,
        "package_count": len(deduped),
        "sources_scanned": sorted(set(sources_scanned)),
        "unsupported_manifests": [{"file": k, "hint": v} for k, v in sorted(unsupported.items())],
        "warnings": warnings,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Detect a project's dependency stack.")
    ap.add_argument("project_dir", nargs="?", default=".", help="Project root (default: cwd)")
    ap.add_argument("--json", dest="out", help="Also write the inventory to this file")
    args = ap.parse_args(argv)

    result = scan(args.project_dir)
    text = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
    print(text)
    if not result["packages"]:
        sys.stderr.write("\n[detect_stack] No resolvable dependencies found. "
                         "Check that lockfiles exist (see unsupported_manifests / warnings).\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
