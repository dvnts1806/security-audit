#!/usr/bin/env python3
"""
run_audit.py — Run the whole audit in one command.

Chains the four steps (profile → detect → scan → report) so a full audit is a
single invocation. Each step still writes its own JSON so you can inspect or
re-run any stage independently.

Stdlib only (Python 3.8+). Network is needed only for the scan step (OSV).

Usage:
    python3 run_audit.py [PROJECT_DIR] [--out-dir DIR]
                         [--min-severity none|low|medium|high|critical]
                         [--nvd] [--nvd-api-key KEY]

Outputs (in --out-dir, default: <PROJECT_DIR>/.security-audit):
    profile.json, inventory.json, findings.json, report.md, plan.json

The report is also printed to stdout. Nothing in the project is modified — this
produces the report and the proposed plan only; applying fixes is a separate,
approval-gated step (see the skill).
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _run(step_name, args):
    """Run a bundled script with the current interpreter; stream its stderr."""
    cmd = [sys.executable, os.path.join(HERE, args[0])] + args[1:]
    sys.stderr.write(f"\n[run_audit] {step_name}: {' '.join(args)}\n")
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        sys.stderr.write(f"[run_audit] step '{step_name}' failed "
                         f"(exit {proc.returncode}); stopping.\n")
        sys.exit(proc.returncode)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run a full security stack audit in one command.")
    ap.add_argument("project_dir", nargs="?", default=".", help="Project root (default: cwd)")
    ap.add_argument("--out-dir", help="Where to write outputs (default: <project>/.security-audit)")
    ap.add_argument("--min-severity", default="none",
                    choices=["none", "low", "medium", "high", "critical"],
                    help="Drop findings below this severity band (default: keep all)")
    ap.add_argument("--nvd", action="store_true", help="Enrich CVSS scores from NVD (slower)")
    ap.add_argument("--nvd-api-key", help="NVD API key (raises rate limit; optional)")
    args = ap.parse_args(argv)

    project = os.path.abspath(args.project_dir)
    out = os.path.abspath(args.out_dir) if args.out_dir else os.path.join(project, ".security-audit")
    os.makedirs(out, exist_ok=True)

    profile = os.path.join(out, "profile.json")
    inventory = os.path.join(out, "inventory.json")
    findings = os.path.join(out, "findings.json")
    report = os.path.join(out, "report.md")
    plan = os.path.join(out, "plan.json")

    # 1 & 2: profile and detect (independent, but run in sequence for simplicity)
    _run("profile", ["profile_project.py", project, "--json", profile])
    _run("detect", ["detect_stack.py", project, "--json", inventory])

    # 3: scan against advisories
    scan_args = ["scan_vulns.py", inventory, "--json", findings,
                 "--min-severity", args.min_severity]
    if args.nvd:
        scan_args.append("--nvd")
    if args.nvd_api_key:
        scan_args += ["--nvd-api-key", args.nvd_api_key]
    _run("scan", scan_args)

    # 4: report + plan (also prints the report to stdout)
    _run("report", ["build_report.py", findings, "--md", report, "--plan", plan])

    sys.stderr.write(f"\n[run_audit] done. Outputs in {out}\n"
                     f"  report: {report}\n  plan:   {plan}\n")
    sys.stderr.write("[run_audit] This is a proposal — no files were changed. "
                     "Review before applying fixes.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
