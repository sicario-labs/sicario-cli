# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Cloud API via Convex HTTP actions — `POST /api/v1/scans`, `GET /api/v1/whoami`, OAuth device flow endpoints
- Real SCA vulnerability data from OSV.dev — `OsvImporter` fetches live advisories and populates local SQLite cache
- Cloud exposure analysis wired into scan pipeline — auto-detects K8s manifests and adjusts finding severity
- `--no-cloud` flag to disable automatic cloud exposure analysis
- `--org <ORG_ID>` flag for `scan --publish` and `publish` to target a specific organization
- `--publish` flag on `scan` to upload results to Sicario Cloud in one step
- Multi-org support — create organizations, switch between them from the dashboard
- Org switcher dropdown component in the dashboard sidebar
- Org-scoped projects and scans — all data is scoped to the active organization
- Auto-project creation from CLI scans — server matches repository URL or creates a new project
- Auto-provisioning on first login — personal org + admin membership created automatically
- `listUserOrgs` query and `createOrg` mutation in the Convex backend
- `useCurrentOrg()` hook with multi-org switching, localStorage persistence, and fallback logic
- Device auth page (`/auth/device`) for CLI login approval in the browser
- Accurate `files_scanned` count and `language_breakdown` map in scan reports and published metadata

### Changed
- CLI default cloud URLs now point to the Convex site URL (no separate API server needed)
- `projects.list` query now requires `orgId` argument and filters by organization
- `scans.insert` mutation now accepts and stores `orgId` and `projectId`
- All dashboard pages use real authenticated `userId` and `orgId` from membership (no more `PLACEHOLDER_ORG`)
- RBAC hooks receive real org context
- Compiler-style diagnostic output with source context, span underlines, and rule-specific help hints
- Recursive rule discovery for subdirectory layouts
- 331 rules now load successfully across 5 languages
- Default behavior: `sicario` with no args now scans the current directory instead of launching the TUI
- TUI is still available via `sicario tui`

### Removed
- Removed dead `dashboard/` directory (old Next.js dashboard) — `sicario-frontend/` is the sole frontend
- Removed all references to the old dashboard from docs, configs, and CI

### Fixed
- Fixed scan report metadata — `files_scanned` and `language_breakdown` were hardcoded to `0` and empty map
- Fixed `SettingsPage` calling `projects.list` without required `orgId` argument
- Fixed capture amplification bug — findings are now deduplicated per rule per line (was inflated 3-4x)
- Rule loading is now tolerant of individual bad rules (skips instead of failing whole file)

### Previously Added
- Multi-language SAST engine with tree-sitter parsing (Go, Java, JavaScript/TypeScript, Python, Rust)
- YAML-based security rule system with 500+ built-in rules (100+ per language)
- Secret scanning with regex, entropy detection, and provider-specific verifiers
- SCA module with OSV and GHSA advisory database integration
- Data-flow reachability analysis to reduce false positives
- Multi-provider AI remediation engine (any OpenAI-compatible LLM endpoint)
- Template-based fallback fixes for SQL injection, XSS, and command injection
- Post-fix verification scanning to confirm vulnerability resolution
- Safe backup/rollback system for automated code fixes
- Interactive TUI dashboard built with Ratatui
- Professional CLI with Clap (scan, fix, report, baseline, rules, config, hook, lsp, benchmark, cache, suppressions, completions, login/logout/whoami, publish)
- SARIF v2.1.0 output for GitHub Code Scanning integration
- OWASP Top 10 compliance report generation (JSON + Markdown)
- Per-finding confidence scoring (reachability + pattern specificity + context)
- Baseline management with delta comparison (new/resolved/unchanged)
- Git-aware diff scanning for PR workflows (`--diff`, `--staged`)
- Inline suppression comments (`sicario-ignore`, `sicario-ignore:<rule-id>`)
- Learning suppressions with auto-suggest for recurring false positives
- Incremental scan caching (content-addressable, SHA-256)
- Language Server Protocol server for IDE integration
- VS Code extension scaffolding
- Git pre-commit hook management (install/uninstall/status)
- Performance benchmarking suite with per-language breakdown
- Rule quality test harness with TP/TN validation
- BYOK key management via OS keyring with precedence resolution
- OAuth 2.0 device flow authentication with PKCE
- MCP (Model Context Protocol) server for AI assistant integration
- Cloud priority scoring with internet exposure analysis
- Sicario Cloud platform: Convex backend, Axum REST API, React dashboard
- Cloud publish command for uploading scan results
- GitHub Action for CI integration (`action.yml`)
- `.sicarioignore` file support (`.gitignore` syntax)
- Shell completions (bash, zsh, fish, PowerShell)
- Cross-platform builds: Linux (musl static), macOS (Intel + Apple Silicon), Windows (MSVC)
- Homebrew formula for macOS/Linux installation
- Curl-based installer script
- GitHub Actions CI/CD pipeline with cross-compilation and automated releases
