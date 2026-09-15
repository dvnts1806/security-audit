# Remediation: how fixes are chosen, applied, and verified

## How the recommended version is chosen

For each vulnerable package, every matched advisory is cleared by upgrading to its
own nearest published fix above the installed version. To clear them **all** with a
single upgrade, `build_report.py` takes the **maximum** of those per-advisory
minimums (`recommend_target`). Picking the lowest fix across advisories — the naive
approach — would leave the package exposed to any advisory fixed only in a later
release.

- `crosses_major: true` means the recommended version is a new major line — likely
  breaking. Never present it as a safe one-liner; review changelogs, prefer a
  branch.
- `clears_all: false` means some matched advisories have **no** published fix at or
  above the installed version. The upgrade clears the rest; the remainder go in the
  report's "No fix available" section and need mitigation, not an upgrade.

## Applying fixes — batch by batch, approval-gated

Nothing is modified until the user approves. Then work in batches, re-scanning
after each:

- **Batch one:** highest-severity, lowest-risk — patch/minor bumps of **direct**
  dependencies. These rarely break anything.
- **Later batches:** major bumps and transitive resolutions, each discussed first.

### Per-ecosystem apply

| Ecosystem | Direct upgrade | Transitive (the hard case) |
| --- | --- | --- |
| npm | `npm install pkg@X` | add an `overrides` block in `package.json`, or bump the parent, then `npm install`; `npm audit fix` for simple cases |
| PyPI | `pip install 'pkg==X'` then re-lock (`poetry lock`, `pip-compile`) | pin the transitive in your resolver and re-lock |
| Go | `go get module@vX && go mod tidy` | `go get` the module; MVS selects it if a parent allows |
| Rust | `cargo update -p pkg --precise X` | `cargo update -p pkg` if a parent's range permits |
| Ruby | `bundle update pkg --conservative` | `bundle update pkg` if the parent gem allows |
| PHP | `composer require pkg:X --update-with-dependencies` | bump the requiring package |

A **top-level install usually will not move a transitive version** — that's why
verification by re-scan is non-negotiable.

## Verify — always by re-scanning

After each batch:

```bash
python3 scripts/detect_stack.py . --json .security-audit/inventory.json
python3 scripts/scan_vulns.py   .security-audit/inventory.json --json .security-audit/findings.json
python3 scripts/build_report.py .security-audit/findings.json --md .security-audit/report.md --plan .security-audit/plan.json
```

Confirm the advisory count dropped and report before/after numbers. Do not claim
"patched" or "clean" from the source change alone — only a re-scan showing zero (or
the agreed residual for no-fix items) earns that.

## When there's no fix

Some advisories have no upgrade. Options, roughly in order:

1. **Mitigate** — disable/guard the vulnerable code path (e.g. don't call the
   affected function, sanitize input, turn off the feature).
2. **Replace** — swap the dependency for a maintained alternative.
3. **Pin + monitor** — pin the version, document the accepted risk, and watch for a
   future fix.
4. **Isolate** — reduce exposure (network policy, sandboxing) if the code must stay.
