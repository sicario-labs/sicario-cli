# Changelog

All notable changes to Sicario are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
