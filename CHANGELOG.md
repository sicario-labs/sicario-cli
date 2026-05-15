# Changelog

All notable changes to Sicario are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.5] — 2026-05-15

### Added

**Core Engine & UX**

- **Smart Viewport-Aware Thresholding** — Automatically truncates CLI output to the top 10 most critical findings when exceeding 25 findings, preventing alert fatigue in interactive TTY sessions. Includes a brutalist summary footer with total counts.
- **Hardened Pre-Commit Hook** — Optimized the `auto-fix` hook workflow with robust error recovery, idempotency checks, and zero-exfiltration safety. Suppresses verbose output in favor of a minimalist intercept prompt.
- **Agentic Remediation Workflow (`--auto-pr`)** — Integrated end-to-end pull request generation for fixes. `sicario fix --auto-pr` handles branch creation, committing deterministic patches, and opening PRs on GitHub/GitLab.
- **Pre-Compiled Rule Sets (`CompiledRule`)** — Optimized scan engine by pre-compiling tree-sitter queries, significantly reducing per-file overhead during large-scale scans.
- **Parallel File Scanning (`scan_file_parallel`)** — Refactored the core scanning loop to utilize Rayon for even faster multi-core throughput.

**Language Support**

- **Enterprise Expansion (v0.3.0+)** — Full production-ready support for **Ruby, PHP, and C#**, bringing the total to 9 supported languages.
- **PHP Rule Hardening** — Resolved high-confidence syntax issues and false positives in the PHP rule set.

### Fixed

- **JSON Parsing Stability** — Resolved edge cases in JSON output serialization for complex taint traces.
- **Smoke Test Reliability** — Updated `smoke-test.sh` and `smoke-test.bat` for robust binary path resolution and non-blocking output collection.
- **Tree-Sitter Pattern Matching** — Fixed incorrect matching logic for `js/session-no-httponly` and `go/http-redirect-user-input` rules.
- **Zero-Exfiltration Invariant** — Hardened the agentic fallback loop to ensure no local source code fragments are ever included in telemetry or external API calls.

---

## [0.3.0] — 2026-05-06

### Added

**Developer Track**

- **Ollama air-gapped remediation (`sicario fix --agent=local`)** — routes LLM fix calls to a local Ollama instance (`http://127.0.0.1:11434`). Zero source code leaves the machine. Includes `OllamaClient` with model priority selection (`qwen2.5-coder` → `deepseek-coder` → first available), `MicroContextExtractor` for function-scoped prompts, and a three-stage `TreeSitterVerificationLoop` that discards any LLM output with syntax errors or hallucinated identifiers before touching disk.
- **`SqlAstRewriteTemplate`** — AST-level SQL injection fix that rewrites string concatenation and template literal queries to parameterized form (`$1`, `$2`, …). Handles single-line, template literal, and multi-line concatenation patterns. Registered under `js-sql-string-concat`, `js-sql-template-string`, and `node-sql-template-literal`.
- **Ghost Fix pre-commit hook (`sicario hook auto-fix`)** — installs a POSIX sh pre-commit hook that runs `sicario fix --staged` on every commit, auto-applies deterministic patches, and blocks the commit if unfixed Critical/High findings remain. Idempotent; respects `SICARIO_SKIP_HOOK=1` bypass.
- **`sicario fix --staged`** — restricts fix attempts to files in `git diff --cached --name-only`. Deterministic templates only (no LLM). JSON output with `{ file, rule_id, line, fixed, template_used }` per finding.
- **Proof-of-concept generation (`sicario scan --prove`)** — generates targeted exploit payloads for SQL injection (time-based), SSRF (local probe listener), command injection, and path traversal findings. Consent prompt before any payload is printed; `--format json` suppresses prompt and adds `poc` field to each finding. Safety enforced in Rust: no destructive SQL keywords, no non-localhost URLs.

**Enterprise Track**

- **Security regression guard (`sicario baseline diff --ci`)** — compares current scan against a saved baseline. Exits 1 on new findings above threshold, 0 otherwise, 2 if no baseline exists. CI-friendly summary format.
- **Compliance evidence export (`sicario report compliance`)** — generates `.sicario/compliance-report-<timestamp>.json` with remediation log, suppression audit, baseline history, and MTTR by rule. Optional SARIF export.
- **Policy-as-code enforcement (`sicario policy init/validate`)** — `.sicario/policy.yaml` supports `fail_on`, `required_rules`, `blocked_suppressions`, `scope`, and `max_findings`. Policy fields override all CLI flags.
- **MTTR tracking (`sicario report mttr`)** — per-rule mean time to remediate with trend indicators (↑/↓/→). `--since <ISO8601>` for period filtering. JSON output for Datadog/Splunk.
- **Suppression audit log (`sicario suppressions audit`)** — scans all `sicario-ignore` directives, attributes each to a git commit and author via `git blame`. JSON and CSV output. `--since` and `--author` filters.
- **Dependency license risk scanner (`sicario scan --licenses`)** — classifies npm/PyPI dependency licenses into HIGH/MEDIUM/LOW tiers. `--fail-on-license` exit code gating. Allowlist via `.sicario/license-allowlist.txt`.

**New Commands**

- **`sicario exorcise`** — rewrites local git history to remove hardcoded secrets. Detects credentials via `SecretScanner`, replaces with `process.env.VAR_NAME`, creates new commits with identical metadata. `--dry-run` shows what would change without touching the repo. Pre-flight checks enforce clean working tree and ≤50 commit limit.
- **`sicario rule`** — NLP-to-AST rule compiler. Converts a natural language description into a validated tree-sitter `SecurityRule` via a two-stage Ollama pipeline (intent extraction → query generation with 3-attempt validation loop). Saves to `.sicario/rules/` and auto-loads on every scan.
- **`sicario attack --dry-run`** — Shadow Pen-Tester. Extracts HTTP routes from Express.js, FastAPI, and Flask source files via AST analysis, then generates targeted attack payloads (SQL injection, command injection, SSRF, XSS, path traversal) bound to each route parameter. `--dry-run` prints payloads without firing requests. Safety enforced: localhost-only targets, no destructive SQL.
- **`sicario guard scan/watch/list/restore`** — Poison-Pill Interceptor. Scans `node_modules/` for behavioral anomalies using 7 tree-sitter rules (`require('child_process')`, dynamic `require()`, obfuscated `eval()`, hex-encoded payloads, etc.). Quarantines Critical packages by renaming to `.sicario-quarantined`. Persistent watch mode via filesystem watcher.

**V1 Bottleneck Fixes**

- Wired `confidence_score` and `suppressed` fields into exit code computation — `--confidence-threshold` and `sicario-ignore` now actually affect CI gating.
- Fixed Ollama model priority selection — now prefers `qwen2.5-coder` over `deepseek-coder` over first-in-list instead of always picking the first model.
- Implemented `create_pull_request` for GitHub and GitLab (was a stub returning `Err`).
- Replaced `// TODO: Add JSON schema validation` in deserialization template with a concrete `zod`-based stub.
- Wired `--auto-suppress` flag into scan output filtering.
- Wired `--confidence-threshold` into output filtering (was silently ignored).
- Added `--learn-suppressions` flag to record inline suppressions into the learner.
- Fixed `sicario config set-provider` endpoint not being read by `resolve_endpoint`.
- Emit `PatchReceipt` in batch fix mode.
- Added `sicario baseline diff` as alias for `sicario baseline compare --ci`.
- Wired `VerificationScanner` into single-file `cmd_fix`.

**Telemetry & Notifications**

- Anonymous usage telemetry (`fire_usage_ping`) fires on every `sicario scan` — opt out via `SICARIO_NO_TELEMETRY=1` or `sicario config set no_telemetry true`.
- Dynamic notification system fetches release announcements from the cloud on scan completion. Seen notifications are not shown again.

**Taint Analysis**

- `sicario scan --trace` — cross-file taint tracing via `ReachabilityAnalyzer`. Prints a box-drawing call chain from taint source to vulnerable sink. `--format json` populates `dataflow_trace` field. Capped at 50,000 nodes; JS/TS and Python only.

**New Rules**

- `js-spawn-shell-true` — detects `spawn(cmd, args, { shell: true })` (CWE-78, Critical)
- `js-child-process-exec-concat` — detects `exec('...' + userInput)` (CWE-78, Critical)
- `js-child-process-template-literal` — detects `` exec(`...${userInput}`) `` (CWE-78, Critical)
- `js-ssrf-fetch-user-url` — now matches `fetch(req.query.url)` and other member expression URLs (CWE-918, High) — previously only matched bare identifiers

### Fixed

- `BehavioralScanner` now uses `ExclusionManager::new_empty()` when scanning packages inside `node_modules/`, bypassing the parent project's `.gitignore` which typically excludes `node_modules/**`.
- `attack --dry-run` SSRF payloads use a fixed placeholder port instead of binding a real TCP listener, preventing 30-second hangs in dry-run mode.

---

## [0.2.5] — 2026-05-02

### Fixed
- **Critical: embedded rules always load on installed binaries** — `cmd_scan` was calling `discover_bundled_rules()` before attempting embedded rules. If the user's working directory happened to contain a `rules/` folder (e.g. a project with its own YAML configs), those 8 files would be loaded instead of the 500+ embedded rules. Embedded rules now always load first; disk discovery is only used as a dev-mode fallback when the embedded set is empty.

---

## [0.2.4] — 2026-05-02

### Fixed
- **`sicario fix` directory support** — `fix` now accepts a directory path and remediates all findings within it, not just single files.
- **`sicario fix` embedded rules** — `fix` and the remediation engine now load the full embedded rule set (500+ rules) instead of falling back to disk rules only, matching `scan` behaviour.
- **Windows UNC path mismatch** — introduced `normalize_path()` to resolve `.` and `..` components without calling `std::fs::canonicalize()`, which produces `\\?\`-prefixed UNC paths on Windows that don't compare equal to plain absolute paths from `read_dir`.
- **Test isolation on Windows** — `test_set_and_load_global_config` and `test_set_global_config_value_rejects_unknown_key` now set both `HOME` and `USERPROFILE` so `dirs_home()` resolves to the temp directory on all platforms.

---

## [0.2.3] — 2026-05-01

### Fixed
- Added remaining `serde` rename aliases for all `OwaspCategory` enum variants so OWASP fields round-trip correctly through JSON serialisation.

---

## [0.2.2] — 2026-05-01

### Fixed
- Added `serde` rename aliases for `OwaspCategory` enum variants to fix JSON deserialisation failures when reading scan results that contain OWASP category fields.

---

## [0.2.1] — 2026-05-01

### Added
- **Full rule set embedded in binary** — all 500+ YAML rules are now compiled into the binary via `rust-embed`, eliminating the need for a separate rules directory at runtime. `sicario scan` works out of the box on any machine without a `rules/` folder present.
- **`sicario-rules` community repository scaffold** — initial structure for the Apache 2.0 community rules repo at [github.com/sicario-labs/sicario-rules](https://github.com/sicario-labs/sicario-rules).

### Fixed
- Marked `embedded_rules` doctest as `no_run` to fix doctest compilation failure in `cargo test`.
- Rewrote `install.sh` and `install.ps1` to correctly resolve v0.2.x release asset names and download URLs.
- Fixed Homebrew formula (`Formula/sicario.rb`) — corrected org name, artifact names, and placeholder strings for tap auto-update.
- Release workflow tag resolution now uses the GitHub redirect (`/releases/latest`) to find the current tag; added `make_latest: true` to the release job.

---

## [0.2.0] — 2026-05-01

### Added
- **Deterministic template engine** — 50 built-in fix templates covering SQL injection, XSS, command injection, path traversal, SSRF, hardcoded secrets, and more across JavaScript/TypeScript and Python. Template fixes apply in sub-50ms with no API key required.
- **19-provider LLM registry** — BYOK support for OpenAI, Anthropic, Gemini, Azure OpenAI, AWS Bedrock, DeepSeek, Groq, Cerebras, Together, Fireworks, OpenRouter, Mistral, Ollama, LM Studio, xAI, Perplexity, Cohere, DeepInfra, and Novita.
- **Ollama / LM Studio auto-detection** — `sicario fix` automatically detects a running local LLM instance and uses it without any configuration.
- **Azure OpenAI support** — deployment-scoped endpoint construction from `AZURE_OPENAI_RESOURCE` and `AZURE_OPENAI_DEPLOYMENT` env vars.
- **`workflow_dispatch` on release workflow** — release builds can now be triggered manually from the GitHub Actions UI.
- **Comprehensive subdirectory rule sets** — expanded YAML rules for JavaScript, Python, Go, Java, and Rust organized into focused subdirectory files (SQL injection, XSS, SSRF, crypto, prototype pollution, etc.).

### Changed
- Removed legacy top-level `*.yaml` rule files (`javascript.yaml`, `python.yaml`, etc.) superseded by the comprehensive subdirectory rule sets.
- Smoke test updated to use a minimum-threshold check (`>= 79 findings`) rather than an exact count, accommodating rule set growth.
- Release workflow tag glob fixed from `**[0-9]+.[0-9]+.[0-9]+*` to `v[0-9]+.[0-9]+.[0-9]+*`.

### Fixed
- **Clippy `useless_conversion`** — removed redundant `.into_iter()` call in `scan_directory`.
- **Duplicate rule dedup** — loading a rule with the same ID twice now replaces the old entry instead of appending, so user rules correctly override built-ins on ID conflict.
- **`scan_file` capture dedup** — `scan_file` now takes only the widest capture per match (consistent with `scan_file_parallel`), eliminating duplicate findings from multi-capture patterns.
- **GitHub Actions annotation stdout pollution** — `::warning` / `::notice` annotation lines are now suppressed when `--format json` or `--format sarif` is active, preventing jq parse failures in CI.
- **Empty git repo telemetry** — `count_contributors` now returns `0` for repos with no commits instead of the fallback `1`.
- **Mock server race condition** — Ollama/LM Studio detection tests now use a `Barrier` to synchronize the server and client threads; flaky timing-dependent tests marked `#[ignore]`.
- **`bash -e` abort in smoke test** — `sicario scan` exits 1 when findings are found; smoke test now uses `|| true` to prevent premature script termination.

---

## [0.1.9] — 2026-04-29

### Added
- **Release distribution pipeline** — Convex File Storage backend for binary hosting; `GET /download/latest/:platform` HTTP endpoint streams binaries with correct `Content-Disposition` headers
- **Download page** (`/download`) — OS auto-detection, platform selector, SHA-256 checksum table, terminal installer blocks
- **`install.ps1`** — Windows PowerShell installer served at `https://usesicario.xyz/install.ps1`; installs to `%LOCALAPPDATA%\sicario\bin` and updates user PATH
- **`install.sh`** — served at `https://usesicario.xyz/install.sh` as a static file (previously only available via raw GitHub URL)
- **`scripts/publish_release.mjs`** — Node.js automation script to upload compiled binaries to Convex File Storage and record them in the `releases` table
- **`releases` table** in Convex schema — tracks `version`, `platform`, `storageId`, `checksum`, `fileSize`, `isActive` with `by_platform_and_active` and `by_version` indexes
- **Static Linux musl binary** (`x86_64-unknown-linux-musl`) — fully static, zero glibc dependency, produced via `cargo-zigbuild` in CI
- **`zigbuild-release.yml`** GitHub Actions workflow — cross-compiles the static Linux binary from `ubuntu-latest` using Zig's bundled clang toolchain

### Changed
- Switched `reqwest` and `tungstenite` from `native-tls` to `rustls-tls` — eliminates `openssl-sys` from the dependency tree, enabling cross-compilation without a target sysroot
- Disabled `git2` SSH feature and enabled `vendored-libgit2` globally — removes `libssh2-sys` → `openssl-sys` transitive dependency
- Workspace version bumped to `0.1.9`

### Fixed
- All CI checks (clippy, compile, fmt) that were failing due to `execution_trace` field added to `Vulnerability` and `TelemetryFinding` structs without updating all construction sites
- `clippy::type_complexity` in `sast_engine.rs` — extracted 8-tuple type into a `type DefaultRule<'a>` alias
- `clippy::manual_strip` in `exclusion_manager.rs` — replaced `line[1..]` with `line.strip_prefix('/')`
- `clippy::result_unit_err` in `iteration_guard.rs` — replaced `Result<u32, ()>` with a proper `IterationLimitError` type
- `clippy::new_without_default` in `audit/trace.rs` — added `Default` impl for `ExecutionTrace`
- Doctest failure in `diagnostics.rs` — changed bare ` ``` ` fence containing Unicode characters to ` ```text `

---

## [0.1.8] — 2026-04-25

### Added
- `cargo-zigbuild` cross-compilation pipeline configuration
- `vendored-libs` feature flag for static builds
- `.cargo/config.toml` cross-compilation target flags

---

## [0.1.7] — 2026-04-20

### Added
- **Compiler-style diagnostic output** — findings render like `rustc`/`cargo` errors with source context, span underlines, CWE headers, and rule-specific help hints
- **Accurate finding deduplication** — one finding per rule per line; eliminates 3–4× inflated counts from multiple captures per match
- **`--publish` flag on `scan`** — scan and upload results to Sicario Cloud in a single command
- **`--org <ORG_ID>` flag** — target a specific organization when publishing
- **`--no-cloud` flag** — disable automatic cloud exposure analysis
- **Auto-project creation** — server matches repository URL to an existing project or creates a new one automatically
- **Auto-provisioning** — first login creates a personal org with admin role
- **Multi-org support** — org switcher in the dashboard sidebar with localStorage persistence
- **Device auth page** (`/auth/device`) — browser-based CLI login approval
- **Accurate scan metadata** — `files_scanned` and `language_breakdown` now reflect actual values (were hardcoded to 0)
- **PR check integration** — `prNumber` in telemetry payload creates/updates a PR check record
- **`sicario link`** — link a local repository to a Sicario Cloud project
- **`sicario config`** — manage LLM API keys and provider settings
- **Execution trace** — `Vulnerability` and `TelemetryFinding` carry an optional `execution_trace` field for audit trails

### Changed
- Default behavior: `sicario` with no arguments now scans the current directory (was: launch TUI)
- TUI still available via `sicario tui`
- 331 rules now load successfully across 5 languages (was: partial load failures)
- Rule loading is tolerant of individual bad rules — skips instead of failing the whole file
- `projects.list` query requires `orgId` and filters by organization

### Fixed
- `SettingsPage` calling `projects.list` without required `orgId`
- Capture amplification bug causing inflated finding counts
- Cloud URL configuration pointing to wrong endpoint

---

## [0.1.0 – 0.1.6] — 2026-01-01 to 2026-04-15

### Initial release and iterative development

- Multi-language SAST engine with tree-sitter parsing (Go, Java, JavaScript/TypeScript, Python, Rust)
- 500+ YAML security rules across 5 languages
- Secret scanning with regex, entropy detection, and provider-specific verifiers
- SCA module with OSV.dev and GHSA advisory database integration
- Data-flow reachability analysis
- Multi-provider AI remediation (any OpenAI-compatible LLM endpoint, BYOK)
- Template-based fallback fixes for SQL injection, XSS, and command injection
- Post-fix verification scanning and safe backup/rollback
- Interactive TUI dashboard (Ratatui)
- SARIF v2.1.0 output for GitHub Code Scanning
- OWASP Top 10 compliance report (JSON + Markdown)
- Per-finding confidence scoring
- Baseline management with delta comparison
- Git-aware diff scanning (`--diff`, `--staged`)
- Inline suppression comments
- Incremental scan caching
- Language Server Protocol server for IDE integration
- VS Code extension scaffolding
- Git pre-commit hook management
- Performance benchmarking suite
- Rule quality test harness with TP/TN validation
- BYOK key management via OS keyring
- OAuth 2.0 device flow authentication with PKCE
- MCP (Model Context Protocol) server for AI assistant integration
- Cloud priority scoring with K8s exposure analysis
- Sicario Cloud platform: Convex backend + React dashboard
- GitHub Action for CI integration (`action.yml`)
- `.sicarioignore` file support
- Shell completions (bash, zsh, fish, PowerShell)
- Cross-platform builds: Linux (musl static + glibc), macOS (Intel + Apple Silicon), Windows (MSVC)
- Homebrew formula
- GitHub Actions CI/CD pipeline

[0.1.9]: https://github.com/sicario-labs/sicario-cli/releases/tag/v0.1.9
[0.1.8]: https://github.com/sicario-labs/sicario-cli/releases/tag/v0.1.8
[0.1.7]: https://github.com/sicario-labs/sicario-cli/releases/tag/v0.1.7

[0.2.0]: https://github.com/sicario-labs/sicario-cli/releases/tag/v0.2.0
[0.2.1]: https://github.com/sicario-labs/sicario-cli/releases/tag/v0.2.1
[0.2.2]: https://github.com/sicario-labs/sicario-cli/releases/tag/v0.2.2
[0.2.3]: https://github.com/sicario-labs/sicario-cli/releases/tag/v0.2.3
[0.2.5]: https://github.com/sicario-labs/sicario-cli/releases/tag/v0.2.5
[0.2.4]: https://github.com/sicario-labs/sicario-cli/releases/tag/v0.2.4
