# security-stack-audit

A Claude Code plugin that audits a project's software stack against **published
security advisories** (OSV.dev — which federates the **GitHub Advisory Database**
and **CVE** — with optional **NVD** CVSS enrichment), weighs each finding against
the project's **real architecture and exposure**, and produces a **prioritized,
approval-gated patch plan**.

It ships two things:

- a **skill** (`security-stack-audit`) that Claude invokes automatically when you
  ask to scan for vulnerabilities, audit dependencies, or plan patches, and
- an **agent** (`security-auditor`) you can delegate a full audit to.

> **What it is:** detection of *known, published* vulnerabilities in your resolved
> dependencies, plus a light pass over obvious code touchpoints, turned into a plan.
> **What it isn't:** a penetration test, a full SAST, or proof that a matched CVE is
> actually exploitable in your app. It's honest about that distinction throughout.

## Why it's different from `npm audit` / a raw scanner

- **Resolved versions, not ranges.** It reads lockfiles, so matches are real.
- **Context-ranked.** It profiles your architecture first (entry points, web
  exposure, ports, dangerous code touchpoints) and ranks findings by plausible
  reachability — a CVE on your request path outranks one in a dev-only tool.
- **Plans, then patches — on your approval.** It proposes fixes in batches, applies
  only what you approve, and **verifies by re-scanning**, never by assertion.
- **Zero setup.** The scanners are Python 3.8+ **stdlib only** — no `pip install`.

## Install

Requires Python 3.8+ and network access to `api.osv.dev`.

```bash
# From a plugin marketplace/repo that includes this plugin:
/plugin install security-stack-audit
```

Or clone into your Claude Code plugins directory / add the repo as a marketplace.
The skill and agent are picked up automatically once the plugin is installed.

## Use

Just ask, in any project:

- "Audit this project for known vulnerabilities."
- "Is this repo safe to ship? Check the dependencies for CVEs."
- "Am I affected by any critical advisories? Give me a patch plan."

Or run the slash command:

```
/security-audit                       # audit the current project
/security-audit . --min-severity high # only high/critical
/security-audit . --nvd               # add NVD CVSS enrichment
```

## Run the scanners directly (no Claude required)

One command runs the whole chain:

```bash
python3 skills/security-stack-audit/scripts/run_audit.py . --min-severity high
# outputs land in ./.security-audit/ (profile, inventory, findings, report.md, plan.json)
```

Or run each stage yourself:

```bash
S=skills/security-stack-audit/scripts
mkdir -p .security-audit
python3 $S/profile_project.py . --json .security-audit/profile.json
python3 $S/detect_stack.py   . --json .security-audit/inventory.json
python3 $S/scan_vulns.py     .security-audit/inventory.json --json .security-audit/findings.json
python3 $S/build_report.py   .security-audit/findings.json --md report.md --plan plan.json
```

`report.md` is the human-readable audit; `plan.json` is the machine-readable
remediation plan grouped by manifest.

## Supported stacks

npm (package-lock / yarn / pnpm), PyPI (poetry / uv / pdm / Pipfile / pinned
requirements), Go (go.mod), Rust (Cargo.lock), Ruby (Gemfile.lock), PHP
(composer.lock). Maven/Gradle/NuGet/Hex/Pub are detected and reported with guidance
on generating a lockfile. See
[`references/ecosystems.md`](skills/security-stack-audit/references/ecosystems.md).

## Layout

```
security-stack-audit/
├── .claude-plugin/plugin.json     # plugin manifest
├── agents/security-auditor.md     # the audit agent
├── commands/security-audit.md     # /security-audit slash command
└── skills/security-stack-audit/
    ├── SKILL.md                   # workflow Claude follows
    ├── scripts/                   # profile / detect / scan / report (stdlib only)
    └── references/                # sources, ecosystems, remediation
```

## License

MIT — see [LICENSE](LICENSE).
