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
  <img src="https://img.shields.io/badge/rules-40+-orange" alt="40+ security rules" />
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

Sicario replaces legacy Python and Node.js security scanners with a single, statically linked Rust binary. Deep static analysis, secret detection, SCA vulnerability matching, and AI-powered remediation — all from your terminal.

```
   _____ _                _
  / ____(_)              (_)
 | (___  _  ___ __ _ _ __ _  ___
  \___ \| |/ __/ _` | '__| |/ _ \
  ____) | | (_| (_| | |  | | (_) |
 |_____/|_|\___\__,_|_|  |_|\___/   SAST · SCA · Secrets · AI Fix

 $ sicario scan .
 ┌─────────────────────────────────────────────────┐
 │ ✓ Parsed 1,247 files across 5 languages         │
 │ ✓ Matched 40 rules · 12 findings                │
 │ ✓ Reachability: 4 exploitable, 8 filtered       │
 │ ✓ SARIF report → results.sarif                  │
 └─────────────────────────────────────────────────┘
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
| AI auto-remediation | ✅ | ❌ | ❌ | ❌ |
| Interactive TUI | ✅ | ❌ | ❌ | ❌ |
| MCP server (AI assistants) | ✅ | ❌ | ❌ | ❌ |
| Single static binary | ✅ | ❌ | ❌ | ❌ |
| SARIF + OWASP reports | ✅ | ✅ | ❌ | ❌ |
| Zero runtime dependencies | ✅ | ❌ | ❌ | ❌ |

---

## Features

<table>
<tr>
<td>

**🛡️ Analysis**
- Multi-language SAST (Go, Java, JS/TS, Python, Rust)
- Secret scanning with entropy + provider verifiers
- SCA via OSV and GHSA advisory databases
- Data-flow reachability analysis
- Confidence scoring to rank findings

</td>
<td>

**🔧 Remediation**
- AI-powered code fixes (Cerebras LLM)
- Safe backup/rollback for every patch
- Git-aware diff scanning for PRs
- Baseline management for known findings
- Inline suppression comments

</td>
</tr>
<tr>
<td>

**📊 Reporting**
- SARIF output for GitHub Code Scanning
- OWASP Top 10 compliance (JSON + Markdown)
- Branded terminal tables
- JSON export for pipelines
- Multi-format simultaneous output

</td>
<td>

**🚀 Developer Experience**
- Interactive TUI dashboard (Ratatui)
- MCP server for AI assistant integration
- OAuth 2.0 + PKCE authentication
- Shell completions (bash/zsh/fish/pwsh)
- Homebrew + curl installer

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
# Scan current directory
sicario scan .

# JSON output
sicario scan . --format json

# SARIF for GitHub Code Scanning
sicario scan . --format sarif -o results.sarif

# Generate OWASP compliance report
sicario report .

# Interactive TUI
sicario tui

# AI-powered fix
sicario fix --vuln VULN-ID

# Shell completions
sicario completions bash >> ~/.bashrc
```

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
```

<details>
<summary><strong>📦 Module breakdown (26 modules)</strong></summary>

| Module | Purpose |
|---|---|
| `parser/` | Tree-sitter multi-language AST parsing with file exclusion |
| `engine/` | SAST rule matching, data-flow reachability, SCA advisory lookup |
| `scanner/` | Secret detection (patterns, entropy, provider verifiers) |
| `output/` | Branded text tables, JSON, SARIF formatters |
| `remediation/` | AI-powered code fixes via Cerebras, backup manager |
| `tui/` | Interactive terminal UI with async message passing |
| `auth/` | OAuth 2.0 device flow with PKCE, secure token storage |
| `cloud/` | Cloud priority scoring, internet exposure analysis |
| `mcp/` | Model Context Protocol server for AI assistants |
| `cli/` | Clap-based command definitions, exit codes, shell completions |
| `reporting/` | OWASP Top 10 compliance report generation |
| `baseline/` | Finding baseline management for diff-aware scanning |
| `confidence/` | Confidence scoring to rank findings |
| `diff/` | Git-aware diff scanning |
| `onboarding/` | Project detection and guided setup |
| `convex/` | Telemetry and cloud ruleset sync |
| `cache/` | Scan result caching for incremental runs |
| `hook/` | Git hook integration |
| `lsp/` | Language Server Protocol support |
| `benchmark/` | Performance benchmarking |
| `rule_harness/` | Rule testing framework |
| `key_manager/` | API key management |
| `publish/` | Rule publishing |
| `suppression_learner/` | ML-based suppression suggestions |
| `verification/` | Finding verification |
| `engine/sca/` | SCA sub-engine (OSV, GHSA, manifest parsing, vuln DB) |

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
<summary><strong>📁 Built-in rules (40+ across 5 languages)</strong></summary>

| Language | Rules | Categories |
|---|---|---|
| **Go** | 8 | Crypto, error handling, framework vulns, race conditions, SQL/cmd injection, TLS, XXE |
| **Java** | 11 | Command injection, crypto, deserialization, LDAP, logging, path traversal, Spring Boot, SQL injection, SSRF, XSS, XXE |
| **JavaScript/TS** | 7 | Express/crypto/prototype, Next.js auth, NoSQL/ReDoS, redirects, SQL injection, SSRF/path traversal, XSS |
| **Python** | 14 | Command injection, crypto, deserialization, Django misconfig/ORM, FastAPI, Flask/SSTI, LDAP, logging, mass assignment, path traversal, SQL injection, SSRF, XXE |
| **Rust** | 3 | Crypto/deserialization/memory, framework info leakage, SQL/cmd/path |

</details>

---

## CI / CD integration

### GitHub Actions

```yaml
- name: Run Sicario SAST
  run: |
    curl -fsSL https://raw.githubusercontent.com/EmmyCodes234/sicario-cli/main/install.sh | sh
    sicario scan . --format sarif -o results.sarif

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
- [x] Secret scanning with entropy detection
- [x] SCA module with OSV/GHSA advisories
- [x] Data-flow reachability analysis
- [x] AI-powered remediation (Cerebras)
- [x] Interactive TUI dashboard
- [x] SARIF + OWASP reporting
- [x] MCP server for AI assistants
- [x] OAuth 2.0 + PKCE authentication
- [x] Cross-platform CI/CD pipeline
- [ ] LSP server for IDE integration
- [ ] Git hook auto-scanning on commit
- [ ] Performance benchmarking suite
- [ ] Rule testing harness
- [ ] Suppression learning (ML-based)
- [ ] Cloud dashboard integration
- [ ] VS Code extension
- [ ] GitHub App for PR comments

---

## Development

### Prerequisites

- Rust 1.75+ (stable)
- On Linux: `libsecret-1-dev`, `pkg-config`

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
│   ├── rules/                # 40+ YAML security rules
│   └── test-samples/         # vulnerable code samples
├── Formula/                  # Homebrew formula
├── .github/workflows/        # CI + release pipelines
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
