---
description: Audit this project's stack for known vulnerabilities and propose an approval-gated patch plan
argument-hint: "[path] [--min-severity high|critical] [--nvd]"
---

Run a security stack audit on `$ARGUMENTS` (default: the current project).

Use the `security-stack-audit` skill and follow its workflow end to end:

1. Profile the architecture & exposure (`profile_project.py`) and read the entry
   points and flagged touchpoint files.
2. Detect the dependency stack (`detect_stack.py`).
3. Scan against OSV / GitHub Advisory DB / CVE (`scan_vulns.py`). If the arguments
   include `--min-severity` or `--nvd`, pass them through.
4. Build the prioritized report and plan (`build_report.py`), then re-rank by
   reachability using the profile and fold in any code-level risks you noticed.

Present the executive summary (counts by severity + top actions) and the report.
**Do not modify any files.** Stop and ask the user which remediation batch to
start with, and apply fixes only after explicit per-batch approval, re-scanning to
verify after each batch.
