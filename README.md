<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=40&duration=3000&pause=1000&color=2ECC71&center=true&vCenter=true&width=500&lines=SICARIO+CLI" />
    <img alt="Sicario CLI" src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=40&duration=3000&pause=1000&color=27AE60&center=true&vCenter=true&width=500&lines=SICARIO+CLI" />
  </picture>
</p>

<p align="center">
  <strong>Next-generation SAST · Secret Scanning · SCA · AI Remediation</strong><br/>
  <em>One binary. All languages. Zero compromise.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build passing" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License" /></a>
  <img src="https://img.shields.io/badge/tests-433_passing-brightgreen" alt="433 tests passing" />
  <img src="https://img.shields.io/badge/rules-500+-orange" alt="500+ security rules" />
  <img src="https://img.shields.io/badge/languages-5-blueviolet" alt="5 languages" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white" alt="Rust" />
  <img src="https://img.shields.io/badge/tree--sitter-AST_parsing-green?style=flat" alt="Tree-sitter" />
  <img src="https://img.shields.io/badge/SARIF-GitHub_Code_Scanning-purple?style=flat" alt="SARIF" />
  <img src="https://img.shields.io/badge/OWASP-Top_10-red?style=flat" alt="OWASP" />
  <img src="https://img.shields.io/badge/MCP-AI_Assistants-blue?style=flat" alt="MCP" />
</p>

---

Sicario replaces legacy Python and Node.js security scanners with a single, statically linked Rust binary. Deep static analysis with 500+ rules across 5 languages, secret detection, SCA vulnerability matching via OSV.dev, cloud exposure analysis, AI-powered remediation, and a cloud dashboard — all from your terminal.

```
   _____ _                _
  / ____(_)              (_)
 | (___  _  ___ __ _ _ __ _  ___
  \___ \| |/ __/ _` | '__| |/ _ \
  ____) | | (_| (_| | |  | | (_) |
 |_____/|_|\___\__,_|_|  |_|\___/   SAST · SCA · Secrets · AI Fix

 $ sicario scan .
   × [CRITICAL] js-eval-injection (CWE-95)
   ╭─[src/handler.js:8:5]
   7 │     // Process user input
   8 │     eval(userInput);
   ·          ^^^^^^^^^^^^^^^ Untrusted input passed to eval()
   9 │
   ╰─
   help: Replace eval() with JSON.parse() or a sandboxed interpreter

 ╭────────────────────────────────────────────────────────────╮
 │  Findings: 10 total  (C:1 H:7 M:2 L:0 I:0)                │
 │  Duration: 3.46s · 331 rules · 2 files                     │
 │  Semgrep estimate: ~34.6s (10x slower)                      │
 ╰────────────────────────────────────────────────────────────╯
```

---

## Why Sicario?

<table>
<tr>
<td width="50%">

### 🔍 The Problem

- Security scanners are **slow** — blocking CI for minutes
- **Hundreds of false positives** waste developer time
- Separate tools for SAST, SCA, and secrets
- Reports say "fix it" but don't help you fix it
- Rules are hard-coded — extending means forking

</td>
<td width="50%">

### ⚡ Sicario's Answer

- **Tree-sitter AST + Rayon parallelism** — seconds, not minutes
- **Compiler-style diagnostics** — findings render like rustc/cargo errors with source context and span underlines
- **Data-flow reachability** filters to only exploitable paths
- **One binary** covers SAST, SCA, and secret scanning
- **AI remediation** generates and applies patches automatically
- **YAML rules** — add a detector in minutes, no recompilation

</td>
</tr>
</table>

### How Sicario compares

| Capability | Sicario | Semgrep | Bandit | ESLint Security |
|---|:---:|:---:|:---:|:---:|
| Multi-language (5+) | ✅ | ✅ | ❌ | ❌ |
| Secret scanning | ✅ | ❌ | ❌ | ❌ |
| SCA / dependency audit | ✅ | ✅ | ❌ | ❌ |
| Data-flow reachability | ✅ | ✅ | ❌ | ❌ |
| Cloud exposure analysis | ✅ | ❌ | ❌ | ❌ |
| AI auto-remediation | ✅ | ❌ | ❌ | ❌ |
| Interactive TUI | ✅ | ❌ | ❌ | ❌ |
| MCP server (AI assistants) | ✅ | ❌ | ❌ | ❌ |
| Single static binary | ✅ | ❌ | ❌ | ❌ |
| SARIF + OWASP reports | ✅ | ✅ | ❌ | ❌ |
| Cloud dashboard + orgs | ✅ | ✅ | ❌ | ❌ |
| Compiler-style diagnostics | ✅ | ❌ | ❌ | ❌ |
| Zero runtime dependencies | ✅ | ❌ | ❌ | ❌ |

---

## Features

<table>
<tr>
<td>

**🛡️ Analysis**
- Multi-language SAST with 331+ rules across 5 languages (Go, Java, JS/TS, Python, Rust)
- Compiler-style diagnostic output (like rustc/cargo) with source context and span underlines
- Accurate finding deduplication — one finding per rule per line, no inflated counts
- Secret scanning with entropy + provider verifiers
- SCA via OSV.dev real-time vulnerability database with local SQLite cache
- Data-flow reachability analysis
- Cloud exposure analysis — auto-detects K8s manifests and adjusts finding severity
- Per-finding confidence scoring
- Incremental cached scanning

</td>
<td>

**🔧 Remediation**
- Multi-provider AI code fixes (any OpenAI-compatible LLM)
- Template-based fallback fixes (SQLi, XSS, CmdInj)
- Safe backup/rollback for every patch
- Post-fix verification scanning
- Git-aware diff scanning for PRs
- Baseline management for known findings
- Inline suppression comments
- Learning suppressions (auto-suggest)

</td>
</tr>
<tr>
<td>

**📊 Reporting**
- SARIF output for GitHub Code Scanning
- OWASP Top 10 compliance (JSON + Markdown)
- Compiler-style diagnostics with severity, CWE headers, and help hints
- JSON export with accurate `files_scanned` and `language_breakdown` metadata
- Multi-format simultaneous output

</td>
<td>

**🚀 Developer Experience**
- Interactive TUI dashboard (Ratatui)
- VS Code extension via Language Server Protocol
- MCP server for AI assistant integration
- Git pre-commit hook integration
- Performance benchmarking suite
- Rule quality test harness
- OAuth 2.0 + PKCE device flow authentication
- Shell completions (bash/zsh/fish/pwsh)
- Homebrew + curl installer
- Sicario Cloud dashboard with multi-org support and team collaboration

</td>
</tr>
</table>

---

## Quick start

### Install

**Homebrew (macOS / Linux)**
```bash
brew install EmmyCodes234/sicario-cli/sicario
```

**Shell installer**
```bash
curl -fsSL https://raw.githubusercontent.com/EmmyCodes234/sicario-cli/main/install.sh | sh
```

**From source**
```bash
git clone https://github.com/EmmyCodes234/sicario-cli.git
cd sicario-cli
cargo build --release
# Binary at target/release/sicario
```

### Usage

```bash
# Scan current directory (default when run with no args)
sicario

# Explicit scan command
sicario scan .

# Interactive TUI mode
sicario tui

# JSON output
sicario scan . --format json

# SARIF for GitHub Code Scanning
sicario scan . --format sarif --sarif-output results.sarif

# Diff-aware scan (only new findings vs main branch)
sicario scan . --diff main

# Scan staged files only (pre-commit)
sicario scan . --staged

# Filter by severity and confidence
sicario scan . --severity-threshold high --confidence-threshold 0.8

# Disable cloud exposure analysis (K8s auto-detection)
sicario scan . --no-cloud

# Generate OWASP compliance report
sicario report .

# AI-powered fix
sicario fix path/to/file.js --rule SQL-001

# Manage baselines
sicario baseline save --tag v1.0
sicario baseline compare v1.0

# Git pre-commit hook
sicario hook install
sicario hook status

# Performance benchmark
sicario benchmark

# Validate rules
sicario rules test
sicario rules validate

# Configure LLM provider
sicario config set-key
sicario config set-provider
sicario config show

# Cloud integration
sicario login
sicario whoami
sicario publish
sicario publish --org <ORG_ID>
sicario scan . --publish
sicario scan . --publish --org <ORG_ID>

# Shell completions
sicario completions bash >> ~/.bashrc
```

---

## Cloud platform

Sicario Cloud provides a centralized dashboard for teams to manage findings, track trends, and collaborate on remediation. The backend runs on [Convex](https://convex.dev) with a React frontend deployed on Netlify.

### Cloud features

- **Device flow login** — `sicario login` opens a browser for OAuth approval, no copy-pasting tokens
- **Scan publishing** — `sicario scan . --publish` or `sicario publish` uploads results to the cloud
- **Multi-org support** — create and switch between organizations from the dashboard
- **Auto-provisioning** — first login auto-creates a personal org with admin role
- **Org-scoped projects** — projects and scans are scoped to organizations; the server auto-creates projects from CLI scans based on repository URL
- **RBAC** — role-based access control (admin, manager, developer) per organization
- **Team management** — invite members, manage roles, configure SSO
- **Webhooks** — trigger notifications on scan events

### CLI → Cloud flow

```
sicario login          → OAuth device flow → browser approval → token stored locally
sicario scan . --publish → scan runs locally → results POST to /api/v1/scans
                          → server resolves org from membership
                          → auto-creates project if repo is new
                          → findings stored with orgId + projectId
sicario whoami         → GET /api/v1/whoami → shows user profile
```

Use `--org <ORG_ID>` with `publish` or `scan --publish` to target a specific organization when you belong to multiple.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                           SICARIO CLI                                │
│                                                                      │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌────────────────────┐  │
│  │  Parser   │  │  Engine   │  │ Scanner  │  │   Remediation      │  │
│  │ tree-     │  │ SAST +    │  │ secrets  │  │ LLM patches +      │  │
│  │ sitter    │──│ SCA +     │──│ entropy  │──│ backup/rollback    │  │
│  │ 5 langs   │  │ reachable │  │ verifier │  │ Cerebras AI        │  │
│  └──────────┘  └───────────┘  └──────────┘  └────────────────────┘  │
│                                                                      │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌────────────────────┐  │
│  │  Output   │  │   Auth    │  │  Cloud   │  │   MCP Server       │  │
│  │ SARIF     │  │ OAuth2    │  │ priority │  │ Model Context      │  │
│  │ JSON      │  │ PKCE      │  │ exposure │  │ Protocol for       │  │
│  │ tables    │  │ keyring   │  │ K8s/CSPM │  │ AI assistants      │  │
│  └──────────┘  └───────────┘  └──────────┘  └────────────────────┘  │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐    │
│  │  CLI (Clap) · TUI (Ratatui) · LSP · Git Hooks · Cache      │    │
│  └──────────────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────┐
│                        SICARIO CLOUD                                 │
│                                                                      │
│  ┌──────────────────────┐  ┌─────────────────────────────────────┐  │
│  │  Convex Backend       │  │  React Frontend (Netlify)           │  │
│  │  HTTP actions:        │  │  Dashboard with:                    │  │
│  │  · POST /api/v1/scans │  │  · Org switcher + multi-org        │  │
│  │  · GET /api/v1/whoami │  │  · Projects (org-scoped)           │  │
│  │  · OAuth device flow  │  │  · Scans + findings explorer       │  │
│  │  · Mutations/queries  │  │  · OWASP compliance view           │  │
│  │  · RBAC + memberships │  │  · Settings (members, SSO, hooks)  │  │
│  └──────────────────────┘  └─────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

<details>
<summary><strong>📦 Module breakdown (26 modules)</strong></summary>

| Module | Purpose |
|---|---|
| `parser/` | Tree-sitter multi-language AST parsing with file exclusion |
| `engine/` | SAST rule matching, data-flow reachability, SCA advisory lookup |
| `engine/sca/` | SCA sub-engine (OSV.dev importer, manifest parsing, SQLite vuln cache) |
| `scanner/` | Secret detection (patterns, entropy, provider verifiers) |
| `output/` | Branded text tables, JSON, SARIF formatters |
| `output/diagnostics.rs` | Compiler-style diagnostic renderer |
| `remediation/` | AI-powered code fixes via Cerebras, backup manager |
| `tui/` | Interactive terminal UI with async message passing |
| `auth/` | OAuth 2.0 device flow with PKCE, secure token storage |
| `cloud/` | Cloud priority scoring, K8s/CSPM exposure analysis |
| `mcp/` | Model Context Protocol server for AI assistants |
| `cli/` | Clap-based command definitions, exit codes, shell completions |
| `reporting/` | OWASP Top 10 compliance report generation |
| `baseline/` | Finding baseline management for diff-aware scanning |
| `confidence/` | Confidence scoring to rank findings |
| `diff/` | Git-aware diff scanning |
| `onboarding/` | Project detection and guided setup |
| `convex/` | Telemetry and cloud ruleset sync |
| `publish/` | Scan result publishing to Sicario Cloud |
| `cache/` | Scan result caching for incremental runs |
| `hook/` | Git hook integration |
| `lsp/` | Language Server Protocol support |
| `benchmark/` | Performance benchmarking |
| `rule_harness/` | Rule testing framework |
| `key_manager/` | API key management |
| `suppression_learner/` | ML-based suppression suggestions |

</details>

---

## Writing custom rules

Sicario rules are plain YAML. Drop a file into `rules/<language>/` and it's picked up automatically.

```yaml
id: "MY-001"
severity: high
language: javascript
message: "Potential SQL injection via string concatenation"
pattern: |
  query($USER_INPUT)
  $USER_INPUT <- "SELECT" + $TAINTED
```

<details>
<summary><strong>📁 Built-in rules (500+ across 5 languages)</strong></summary>

| Language | Rules | Categories |
|---|---|---|
| **Go** | 100+ | SQL injection, command injection, path traversal, SSRF, crypto, error handling, Gin/Echo/Fiber framework, race conditions, TLS, info leakage, XXE |
| **Java** | 100+ | SQL injection, XSS, command injection, deserialization, path traversal, crypto, Spring Boot, SSRF, XXE, LDAP injection, logging |
| **JavaScript/TS** | 100+ | SQL injection, XSS, SSRF, path traversal, deserialization, Express.js, crypto, prototype pollution, Next.js, auth/JWT, NoSQL injection, ReDoS, open redirect, TypeScript type safety |
| **Python** | 100+ | Django ORM/misconfig, Flask/SSTI, SQL injection, path traversal, deserialization, command injection, crypto, FastAPI, LDAP, XXE, mass assignment, logging |
| **Rust** | 100+ | SQL injection, command injection, path traversal, crypto, deserialization, memory safety, concurrency, Actix-web/Axum framework, info leakage |

</details>

---

## CI / CD integration

### GitHub Actions (using the Sicario Action)

```yaml
- name: Run Sicario SAST
  uses: EmmyCodes234/sicario-cli@main
  with:
    args: scan . --format sarif --sarif-output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### GitHub Actions (manual install)

```yaml
- name: Run Sicario SAST
  run: |
    curl -fsSL https://raw.githubusercontent.com/EmmyCodes234/sicario-cli/main/install.sh | sh
    sicario scan . --format sarif --sarif-output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Exit codes

| Code | Meaning |
|:---:|---|
| `0` | No findings above threshold |
| `1` | Findings detected above severity/confidence threshold |
| `2` | Internal error |

---

## Roadmap

- [x] Multi-language SAST engine (Go, Java, JS/TS, Python, Rust)
- [x] 500+ security rules across 5 languages
- [x] Secret scanning with entropy detection
- [x] SCA module with real OSV.dev vulnerability data
- [x] Data-flow reachability analysis
- [x] Cloud exposure analysis (K8s manifest auto-detection)
- [x] Multi-provider AI remediation (any OpenAI-compatible LLM)
- [x] Template-based fallback fixes (SQLi, XSS, CmdInj)
- [x] Interactive TUI dashboard
- [x] SARIF + OWASP reporting
- [x] MCP server for AI assistants
- [x] OAuth 2.0 + PKCE device flow authentication
- [x] Cross-platform CI/CD pipeline
- [x] LSP server for IDE integration
- [x] VS Code extension
- [x] Git pre-commit hook integration
- [x] Performance benchmarking suite
- [x] Rule testing harness with TP/TN validation
- [x] Suppression learning (auto-suggest)
- [x] Post-fix verification scanning
- [x] Per-finding confidence scoring
- [x] Baseline tracking with delta comparison
- [x] Incremental cached scanning
- [x] BYOK key management (OS keyring)
- [x] Sicario Cloud platform (Convex backend + React dashboard)
- [x] Cloud publish with accurate scan metadata
- [x] Multi-org support with org switcher
- [x] Org-scoped projects with auto-creation from CLI scans
- [x] Auto-provisioning on first login
- [x] GitHub Action for CI integration
- [ ] GitHub App for PR comments
- [ ] Slack/Teams webhook notifications

---

## Development

### Prerequisites

- Rust 1.75+ (stable)
- On Linux: `libsecret-1-dev`, `pkg-config`
- For the frontend: Node.js 18+

### Build & test

```bash
cargo build                  # debug build
cargo build --release        # optimized build
cargo test --workspace       # run all 433 tests
cargo test -p sicario-cli    # crate tests only
```

### Project layout

```
.
├── Cargo.toml               # workspace root
├── sicario-cli/
│   ├── Cargo.toml            # crate manifest
│   ├── src/                  # 26 modules, ~50k lines
│   ├── rules/                # 500+ YAML security rules
│   └── test-samples/         # vulnerable code samples
├── convex/                   # Convex backend (schema, mutations, queries, HTTP actions)
│   └── convex/               # Convex functions (schema.ts, http.ts, scans.ts, etc.)
├── sicario-frontend/         # React dashboard (separate repo, deployed on Netlify)
├── editors/vscode/           # VS Code extension
├── Formula/                  # Homebrew formula
├── .github/workflows/        # CI + release pipelines
├── action.yml                # GitHub Action definition
├── install.sh                # curl installer
└── Cross.toml                # cross-compilation config
```

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

Found a vulnerability? Please follow our [security policy](SECURITY.md). Do not open a public issue.

## License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  <sub>Built with ❤️ and Rust · Engineered for speed, precision, and developer happiness</sub>
</p>
