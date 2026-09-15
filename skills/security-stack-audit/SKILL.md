---
name: security-stack-audit
description: >-
  Audit a project's software stack for known, published security vulnerabilities
  and produce a prioritized, approval-gated patch plan. Use this whenever the user
  wants to check dependencies or their stack for CVEs, security advisories, or
  known vulnerabilities; asks to "scan for vulnerabilities", "run a security
  audit", "check my dependencies", "am I affected by CVE-X", "what needs
  patching", or wants a remediation/upgrade plan for vulnerable packages. Works on
  any project by detecting its languages and lockfiles, cross-references OSV.dev
  (which aggregates the GitHub Advisory Database and CVE feeds) plus optional NVD
  CVSS enrichment, weighs findings against the project's real architecture and
  exposure, and proposes fixes that are applied only after the user approves each
  batch. Trigger it even when the user names only a symptom ("is this repo safe to
  ship?", "audit before release") rather than asking for a scan by name.
---

# Security Stack Audit

Cross-reference a project's actual, resolved dependencies against published
security advisories, weigh each finding against how the code is really built and
exposed, and hand the user a prioritized list plus a remediation plan that is
**applied only on their explicit approval**.

The value of this skill is not "run a scanner." Any scanner can print a wall of
CVEs. The value is judgment: matching advisories to *resolved* versions (not
loose ranges), then filtering and ordering them by whether the vulnerable code is
actually reachable in this project, and turning that into a plan a busy person can
approve batch by batch without second-guessing it.

## When to reach for this

Trigger on any request to check a project for known vulnerabilities, CVEs, or
advisories; to audit dependencies before a release; to produce a patch/upgrade
plan; or to answer "am I affected by <CVE>?". You do not need the user to say
"security audit" — "is this safe to ship?" is enough.

## The four bundled scripts

All are **Python 3.8+ stdlib only** — no `pip install`, so they run anywhere.
They live in `scripts/` next to this file. Run them with `python3`.

| Script | Purpose | Network |
| --- | --- | --- |
| `profile_project.py` | Architecture & exposure profile (languages, frameworks, entry points, ports, security touchpoints) | No |
| `detect_stack.py` | Inventory of resolved packages from lockfiles/manifests | No |
| `scan_vulns.py` | Match inventory against OSV (GHSA + CVE); optional NVD CVSS enrichment | Yes (OSV) |
| `build_report.py` | Prioritized Markdown report + machine-readable `plan.json` | No |

Save all intermediate JSON to a working directory (e.g. `.security-audit/` in the
project, or a scratch dir) so steps compose and the run is reproducible.

## Workflow

Work through these steps in order. Steps 1–2 can run in parallel — they don't
depend on each other.

### 1. Profile the architecture and exposure

```bash
python3 scripts/profile_project.py <PROJECT_DIR> --json .security-audit/profile.json
```

This is what makes the audit *contextual* rather than a raw CVE dump. It tells you
the languages, frameworks, likely entry points, whether the app is internet-facing
(web frameworks, routes, listening ports), the deployment surface (Docker, CI,
IaC), and security touchpoints worth reading (shell/exec, raw SQL, deserialization,
crypto, secrets, template rendering, CORS).

Then **read a few of the files it points at** — the entry points and the
touchpoint files. The script gathers signals; you form the architectural picture.
You are looking for: what handles untrusted input, what's exposed to the network,
which dependencies sit on the request path vs. build/dev-only tooling. This picture
drives prioritization in step 4. Note anything notable (e.g. "a hardcoded API key
in `src/app.py`", "shell=True on a request parameter") — code-level risks like
these belong in the final report even though they aren't dependency CVEs.

### 2. Detect the dependency stack

```bash
python3 scripts/detect_stack.py <PROJECT_DIR> --json .security-audit/inventory.json
```

Prefers lockfiles (exact resolved versions — what a CVE match actually needs) over
manifests. Covers npm (package-lock/yarn/pnpm), PyPI (poetry/uv/pdm/Pipfile/pinned
requirements), Go (go.mod), Rust (Cargo.lock), Ruby (Gemfile.lock), PHP
(composer.lock). Check `warnings` and `unsupported_manifests` in the output — if a
manifest has no lockfile, tell the user precise version matching isn't possible
there and how to generate one (e.g. `npm install`, `mvn dependency:tree`).

### 3. Scan against published advisories

```bash
python3 scripts/scan_vulns.py .security-audit/inventory.json --json .security-audit/findings.json
```

Queries **OSV.dev**, which federates the **GitHub Advisory Database** and **CVE**
data and does version-range matching server-side. Severity is computed from the
CVSS vector offline, so bands are populated without extra calls.

- Add `--nvd` to enrich any still-missing CVSS scores from the **NVD** CVE API.
  It's slower (NVD rate-limits hard without a key); pass `--nvd-api-key <KEY>` if
  the user has one. Use it when authoritative CVSS scores matter to the user.
- Add `--min-severity high` (or `critical`/`medium`/`low`) to focus the scan.
  Unknown-severity advisories are always kept so nothing is silently hidden.

If OSV is unreachable (offline/firewalled), say so plainly — the audit can't be
completed against live data, and a stale local result would be worse than an
honest "couldn't reach the source."

### 4. Prioritize with architectural context, then report

```bash
python3 scripts/build_report.py .security-audit/findings.json \
    --md .security-audit/report.md --plan .security-audit/plan.json
```

`build_report.py` gives you a solid first draft: findings sorted by severity, the
recommended upgrade (the lowest single version that clears **every** matched
advisory for that package), a major-bump warning where the fix crosses a major
version, and a plan grouped by manifest.

**Now add your judgment on top of the draft** using the profile from step 1:

- **Re-rank by reachability.** A critical advisory in a package on the
  request-handling path of an internet-facing service outranks a critical one in a
  dev-only or build-time dependency. Say *why* something is ranked where it is.
- **Flag transitive vs. direct honestly.** Transitive fixes often can't be applied
  with a single `install` — they need a parent bump, an override/resolution, or a
  re-lock. The plan marks these; explain the real path.
- **Call out breaking upgrades.** Major-version bumps (flagged `crosses_major`)
  need human review; never present them as safe one-liners.
- **Fold in code-level findings** you saw in step 1 (hardcoded secrets, dangerous
  patterns) as their own section — they matter to "is this safe to ship?" even
  though they aren't dependency CVEs. Keep them clearly separated from advisory
  matches so nothing looks like a false CVE.

Present the report to the user. Lead with the count by severity and the top few
actions, not the full wall of text.

### 5. Apply fixes — only on explicit, per-batch approval

The plan is a **proposal**. Do not modify any file until the user approves. Then:

1. Propose the **first batch** — the highest-severity, lowest-risk fixes (patch/
   minor bumps of direct dependencies clear this bar; major bumps and transitive
   resolutions do not go in batch one). Show the exact commands from `plan.json`.
2. Apply that batch **only after the user says yes.** Approval of one batch is not
   approval of the next — ask again for each.
3. **Re-run steps 2–4** after each batch and confirm the advisory count actually
   dropped. "It should be fixed after `npm install`" is not verification —
   re-scanning is. Report the before/after counts.
4. For major bumps, walk the user through the breaking-change risk before touching
   anything, and prefer a separate branch.
5. For transitive dependencies, apply the real remediation (override/resolution or
   parent bump), then re-scan to prove it took — a top-level install often won't
   move a transitive version.

Never claim the project is "clean" or "patched" on the basis of the source change
alone. The claim is earned only by a re-scan that shows the count at zero (or at
the agreed residual — some advisories have no fix and need mitigation instead).

## Doing this as a one-shot

For a hands-off run, chain the steps and hand back `report.md` + `plan.json`,
then stop before applying anything and ask which batch to start with:

```bash
mkdir -p .security-audit
python3 scripts/profile_project.py . --json .security-audit/profile.json
python3 scripts/detect_stack.py   . --json .security-audit/inventory.json
python3 scripts/scan_vulns.py     .security-audit/inventory.json --json .security-audit/findings.json
python3 scripts/build_report.py   .security-audit/findings.json --md .security-audit/report.md --plan .security-audit/plan.json
```

## Honesty & scope guardrails

- **Version matching, not reachability proof.** A matched advisory means a
  vulnerable version is installed — not that it's exploitable in this app. Say so.
  Reachability is *your* reasoning from the profile, offered as judgment, not a
  guarantee.
- **Sources are point-in-time.** Advisory databases change; a clean scan today
  isn't a clean scan next week. Note the scan date.
- **No lockfile ⇒ no precise match.** Don't pretend a version range can be
  matched. Tell the user to generate a lockfile.
- **This is not a penetration test or a code-level SAST.** It finds *known,
  published* vulnerabilities in dependencies, plus a light pass over obvious code
  touchpoints. Don't oversell it.

## Reference material

- `references/sources.md` — the credible sources, their APIs, coverage, and how to
  add GitHub GraphQL advisory queries or vendor feeds.
- `references/ecosystems.md` — which manifests/lockfiles are supported, how each is
  parsed, and how to extend to Maven/NuGet/Hex/Pub.
- `references/remediation.md` — how the recommended version is chosen, how to apply
  fixes safely per ecosystem (including transitive overrides), and how to verify.
