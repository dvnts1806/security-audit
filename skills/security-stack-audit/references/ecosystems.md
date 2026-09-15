# Supported ecosystems & how they're parsed

`detect_stack.py` prefers **lockfiles** (exact resolved versions) over manifests,
because only a resolved version can be matched to an advisory. A range like
`^1.2.0` doesn't tell you whether the vulnerable `1.2.3` or the fixed `1.2.9` is
installed.

| Ecosystem | OSV name | Parsed from | Notes |
| --- | --- | --- | --- |
| Node | `npm` | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` | One lockfile per dir, chosen by priority; `package.json` used only to mark direct deps. `package.json` alone (no lockfile) → warning, not matched. |
| Python | `PyPI` | `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `requirements.txt` (only `==` pins) | Names normalized PEP 503 when matching fixes. |
| Go | `Go` | `go.mod` `require` block | Leading `v` stripped for OSV; `// indirect` marks transitive. |
| Rust | `crates.io` | `Cargo.lock` `[[package]]` | |
| Ruby | `RubyGems` | `Gemfile.lock` `specs:` | |
| PHP | `Packagist` | `composer.lock` `packages` / `packages-dev` | Leading `v` stripped. |

`package.json` direct-dependency detection reads `dependencies`,
`devDependencies`, `optionalDependencies`, and `peerDependencies`.

## TOML parsing

`poetry.lock` / `uv.lock` / `pdm.lock` / `Cargo.lock` use the stdlib `tomllib`
(Python 3.11+). On older Pythons a minimal line-oriented extractor pulls
`name`/`version` from `[[package]]` tables — enough for inventory.

## Not yet supported (reported as `unsupported_manifests`)

These need a lockfile or a build tool to resolve exact versions; the tool names
them and tells the user how to proceed rather than guessing:

- **Maven** (`pom.xml`) — run `mvn dependency:tree`, or emit a resolved list.
- **Gradle** (`build.gradle[.kts]`) — enable dependency locking (`gradle.lockfile`).
- **NuGet** (`packages.config`) — prefer `packages.lock.json`.
- **Hex** (`mix.exs`) — parse `mix.lock`.
- **Pub** (`pubspec.yaml`) — parse `pubspec.lock`.

## Adding an ecosystem

1. Add a parser in `detect_stack.py` returning `(name, version, direct)` tuples
   and emit packages with the correct OSV `ecosystem` string (see `sources.md`).
2. Add the install command template to `UPGRADE_CMD` in `build_report.py`, and a
   transitive-remediation note to `TRANSITIVE_NOTE`.
3. Confirm OSV supports that ecosystem name, then test against a package with a
   known advisory.
