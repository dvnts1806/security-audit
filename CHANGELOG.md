# Changelog

## 0.1.1

- Add `run_audit.py`: a one-shot runner that chains profile → detect → scan →
  report in a single command, writing all outputs to `<project>/.security-audit/`.
- README: document the one-command workflow.

## 0.1.0

- Initial release: `security-stack-audit` skill + `security-auditor` agent.
- Stack detection across npm, PyPI, Go, Rust, Ruby, PHP (lockfile-first).
- Vulnerability matching via OSV.dev (federates GitHub Advisory DB + CVE), with
  offline CVSS v3.1 scoring and optional NVD enrichment.
- Architecture & exposure profiling for reachability-based prioritization.
- Prioritized Markdown report + machine-readable, approval-gated remediation plan.
- `/security-audit` command and a self-hosting marketplace.
