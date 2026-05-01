<p align="center">
  <img src="sicarioicon.png" alt="Sicario" width="100" height="100" />
</p>

<h1 align="center">Sicario</h1>

<p align="center">
  <strong>Security scanning that runs where your code lives. Your source never leaves your machine.</strong><br/>
  SAST &nbsp;·&nbsp; SCA &nbsp;·&nbsp; Secret Detection &nbsp;·&nbsp; Reachability Analysis &nbsp;·&nbsp; AI Auto-Remediation
</p>

<p align="center">
  <a href="https://github.com/sicario-labs/sicario-cli/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/sicario-labs/sicario-cli/ci.yml?style=flat-square&logo=github&label=Build" alt="CI Status" />
  </a>
  <a href="https://github.com/sicario-labs/sicario-cli/releases/latest">
    <img src="https://img.shields.io/github/v/release/sicario-labs/sicario-cli?style=flat-square&color=white&label=Release" alt="Latest Release" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-FSL--1.1-orange.svg?style=flat-square" alt="FSL-1.1 License" />
  </a>
  <img src="https://img.shields.io/badge/Engine-Rust_1.75+-orange?style=flat-square&logo=rust" alt="Built with Rust" />
</p>

<p align="center">
  <a href="https://usesicario.xyz">Website</a> &nbsp;·&nbsp;
  <a href="https://usesicario.xyz/docs">Documentation</a> &nbsp;·&nbsp;
  <a href="https://usesicario.xyz/download">Download Binaries</a> &nbsp;·&nbsp;
  <a href="https://usesicario.xyz/pricing">Pricing</a>
</p>

---

> **The developer security compromise is over.**
> Traditional scanners force teams to choose between speed, accuracy, and privacy. Sicario is a Rust-native engine that replaces fragmented toolchains with a single, static binary. It completes comprehensive workspace scans in seconds, filters out noise using data-flow reachability, and **never exfiltrates your source code** to a third-party cloud.

```
$ sicario scan .

  × [CRITICAL] js/eval-injection  src/handler.js:8  CWE-95
  ╭─[src/handler.js:8:5]
  7 │   // process user input
  8 │   eval(userInput);
  ·        ^^^^^^^^^^^^ untrusted input passed to eval()
  ╰─
  help: replace eval() with JSON.parse() or a sandboxed interpreter

  ╭──────────────────────────────────────────────────────────╮
  │  Findings: 1  (C:1  H:0  M:0  L:0)                      │
  │  Duration: 3.5s · 331 rules · 125 files                  │
  ╰──────────────────────────────────────────────────────────╯
```

---

## Why Sicario

Most security tools are slow, noisy, and fragmented. Semgrep requires a Python runtime and a network call. Bandit only covers Python. ESLint security plugins miss entire vulnerability classes. None of them fix what they find.

Sicario is different:

- **Single binary, zero runtime.** One command installs it. No Python, no Node, no Docker.
- **Fast.** Tree-sitter AST parsing + Rayon parallelism. Scans complete in seconds, not minutes.
- **Low noise.** Data-flow reachability filters findings to exploitable paths only. Compiler-style output with source context — no wall of JSON.
- **Fixes vulnerabilities.** AI remediation generates and applies patches. Template-based fallbacks work without an API key.
- **Full stack.** SAST, SCA, and secret scanning in one tool. One command, one report.
- **Zero exfiltration.** Analysis runs entirely on your machine. The cloud receives only structured finding metadata — never source code.

---

## Capabilities

| | Sicario | Snyk | Checkmarx | Semgrep | Bandit |
|---|:---:|:---:|:---:|:---:|:---:|
| Multi-language (5+) | ✅ | ✅ | ✅ | ✅ | ❌ |
| Secret scanning | ✅ | ✅ | ✅ | ❌ | ❌ |
| SCA / dependency audit | ✅ | ✅ | ✅ | ✅ | ❌ |
| Data-flow reachability | ✅ | ✅ | ✅ | ✅ | ❌ |
| AI auto-remediation | ✅ | ⚠️ | ⚠️ | ❌ | ❌ |
| Interactive TUI | ✅ | ❌ | ❌ | ❌ | ❌ |
| MCP server (AI assistants) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Single static binary | ✅ | ❌ | ❌ | ❌ | ❌ |
| SARIF + OWASP reports | ✅ | ✅ | ✅ | ✅ | ❌ |
| Cloud dashboard + orgs | ✅ | ✅ | ✅ | ✅ | ❌ |
| Zero runtime dependencies | ✅ | ❌ | ❌ | ❌ | ❌ |
| Zero source code exfiltration | ✅ | ❌ | ❌ | ❌ | ✅ |
| Open source | ✅ | ⚠️ | ❌ | ⚠️ | ✅ |
| Free tier | ✅ | ✅ | ❌ | ✅ | ✅ |

<sub>⚠️ Partial — Snyk and Checkmarx offer AI fix suggestions in their cloud UI, not automated local patch application. Semgrep OSS is open source; Semgrep Pro is proprietary. Snyk CLI is open source; Snyk platform is proprietary.</sub>

---

## Installation

**macOS / Linux — curl**
```bash
curl -fsSL https://usesicario.xyz/install.sh | sh
```

**Windows — PowerShell**
```powershell
irm https://usesicario.xyz/install.ps1 | iex
```

**Homebrew**
```bash
brew install sicario-labs/sicario-cli/sicario
```

**Download a binary directly:** [usesicario.xyz/download](https://usesicario.xyz/download)

---

## Quick start

```bash
# Scan the current directory
sicario scan .

# Scan and publish results to the cloud dashboard
sicario scan . --publish

# SARIF output for GitHub Code Scanning
sicario scan . --format sarif --sarif-output results.sarif

# AI-powered fix for a specific finding
sicario fix src/db.js --rule js/sql-injection

# Generate an OWASP Top 10 compliance report
sicario report .

# Interactive TUI
sicario tui
```

---

## Features

### Analysis engine

- **SAST** — 500+ rules across JavaScript/TypeScript, Python, Rust, Go, and Java. Rules are plain YAML — add a detector in minutes without recompiling.
- **SCA** — dependency vulnerability matching via the OSV.dev database with a local SQLite cache. Parses `package.json`, `Cargo.toml`, and `requirements.txt`.
- **Secret detection** — regex + entropy analysis with provider-specific verifiers.
- **Data-flow reachability** — filters findings to paths reachable from external taint sources, dramatically reducing false positives.
- **Cloud exposure analysis** — auto-detects Kubernetes manifests and escalates severity for publicly exposed services.

### Remediation

- Multi-provider AI code fixes (any OpenAI-compatible LLM endpoint, BYOK)
- Template-based fallback fixes for SQL injection, XSS, and command injection — no API key required
- Safe backup and rollback for every patch applied
- Post-fix verification scan to confirm the vulnerability is resolved

### Reporting

- Compiler-style diagnostic output with source context and span underlines
- SARIF v2.1.0 for GitHub Code Scanning
- OWASP Top 10 compliance report (JSON + Markdown)
- JSON export with accurate scan metadata

### Developer experience

- Interactive TUI dashboard (Ratatui)
- MCP server for AI assistant integration (Claude, Cursor, Kiro)
- VS Code extension via Language Server Protocol
- Git pre-commit hook integration
- Shell completions (bash, zsh, fish, PowerShell)
- OAuth 2.0 + PKCE device flow authentication

---

## Cloud platform

`sicario scan . --publish` uploads results to [Sicario Cloud](https://usesicario.xyz) — a dashboard for teams to track findings, manage projects, and collaborate on remediation.

```bash
sicario login              # OAuth device flow — browser approval, no token copy-paste
sicario scan . --publish   # scan locally, publish results to the dashboard
sicario whoami             # verify your identity and org
```

The backend runs on [Convex](https://convex.dev). The analysis always runs locally — the cloud receives only structured finding metadata, never source code.

**Dashboard features:**
- Multi-org support with role-based access control (admin / manager / developer)
- Project management with auto-creation from CLI scans
- Findings explorer with severity filtering and triage workflow
- OWASP Top 10 compliance view
- PR check integration
- Webhook notifications

---

## CI/CD integration

**GitHub Actions — using the Sicario Action**
```yaml
- name: Sicario Security Scan
  uses: sicario-labs/sicario-cli@main
  with:
    args: scan . --format sarif --sarif-output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

**GitHub Actions — with cloud publishing**
```yaml
- name: Sicario Security Scan
  env:
    SICARIO_API_KEY: ${{ secrets.SICARIO_API_KEY }}
  run: |
    curl -fsSL https://usesicario.xyz/install.sh | sh
    sicario scan . --publish --fail-on High
```

**Exit codes**

| Code | Meaning |
|:---:|---|
| `0` | No findings above threshold |
| `1` | Findings detected above threshold |
| `2` | Internal error |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SICARIO CLI                             │
│                                                                 │
│  Parser (tree-sitter)  →  Engine (SAST + SCA + reachability)   │
│  Scanner (secrets)     →  Remediation (AI patches + rollback)  │
│  Output (SARIF/JSON)   →  Auth (OAuth2 PKCE + keyring)         │
│  MCP Server            →  Cloud (K8s exposure + priority)      │
│                                                                 │
│  CLI (Clap) · TUI (Ratatui) · LSP · Git Hooks · Cache         │
└─────────────────────────────────────────────────────────────────┘
                    │
          finding metadata only
          (no source code)
                    │
┌─────────────────────────────────────────────────────────────────┐
│                       SICARIO CLOUD                             │
│                                                                 │
│  Convex backend (HTTP actions, mutations, queries, RBAC)        │
│  React dashboard (projects, findings, OWASP, analytics)         │
│  usesicario.xyz                                                 │
└─────────────────────────────────────────────────────────────────┘
```

<details>
<summary><strong>Module breakdown</strong></summary>

| Module | Purpose |
|---|---|
| `parser/` | Tree-sitter multi-language AST parsing with file exclusion |
| `engine/` | SAST rule matching, data-flow reachability, SCA advisory lookup |
| `engine/sca/` | OSV.dev importer, manifest parsing, SQLite vulnerability cache |
| `scanner/` | Secret detection (patterns, entropy, provider verifiers) |
| `output/` | Branded text tables, JSON, SARIF formatters, compiler-style diagnostics |
| `remediation/` | AI-powered code fixes, backup manager, post-fix verification |
| `tui/` | Interactive terminal UI with async message passing |
| `auth/` | OAuth 2.0 device flow with PKCE, secure token storage |
| `cloud/` | Cloud priority scoring, K8s/CSPM exposure analysis |
| `mcp/` | Model Context Protocol server for AI assistants |
| `cli/` | Clap command definitions, exit codes, shell completions |
| `reporting/` | OWASP Top 10 compliance report generation |
| `baseline/` | Finding baseline management for diff-aware scanning |
| `confidence/` | Per-finding confidence scoring |
| `diff/` | Git-aware diff scanning |
| `convex/` | Telemetry and cloud sync |
| `publish/` | Scan result publishing to Sicario Cloud |

</details>

---

## Writing custom rules

Rules are plain YAML. Drop a file into `sicario-cli/rules/<language>/` and it's picked up automatically on the next scan.

```yaml
id: "js/hardcoded-jwt-secret"
name: "Hardcoded JWT Secret"
severity: critical
language: javascript
description: "JWT secret assigned as a string literal"
pattern: |
  jwt.sign($PAYLOAD, "$SECRET")
cwe_id: "CWE-798"
owasp_category: "A02_CryptographicFailures"
```

Built-in rules cover SQL injection, XSS, command injection, path traversal, SSRF, deserialization, cryptographic failures, hardcoded secrets, and more — across all five supported languages.

---

## Development

**Prerequisites:** Rust 1.75+ stable. On Linux: `libsecret-1-dev pkg-config`.

```bash
git clone https://github.com/sicario-labs/sicario-cli.git
cd sicario-cli
cargo build --release
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

The binary lands at `target/release/sicario`.

---

## Try it on real vulnerable code

The repo ships a **vulnerability sandbox** — 79 intentionally vulnerable files across Node.js, Python, and React/TypeScript, one pattern per file, covering 60+ CWEs.

```bash
git clone https://github.com/sicario-labs/sicario-cli.git
sicario scan sicario-cli/vuln-sandbox/
```

No setup required beyond having Sicario installed. Use it to:

- Verify detection works on your machine before scanning your own code
- Explore what Sicario's output looks like across different severity levels
- Test custom rules against known-vulnerable patterns

See [`vuln-sandbox/README.md`](vuln-sandbox/README.md) for the full directory structure and [`vuln-sandbox/MANIFEST.md`](vuln-sandbox/MANIFEST.md) for the complete file → CWE → rule ID mapping.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions are welcome — new rules, bug fixes, documentation improvements, and language support.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md). Please do not open a public issue.

## License & Enterprise Use

Sicario is governed by the [Functional Source License 1.1](LICENSE) (FSL-1.1), with Apache License 2.0 as the Change License.

**Free for:**
- Individual developers using Sicario locally or in personal CI/CD pipelines
- Open-source projects and non-profit organizations
- Commercial teams using Sicario for internal security scanning of their own code

**Requires a commercial agreement:**
- Running Sicario as a hosted security scanning service for third parties (scanning code you don't own on behalf of paying customers)

FSL-1.1 is source-available — you can read, audit, fork, and contribute to the code. Two years after each version's first public release, that version automatically converts to the Apache License 2.0, making it fully open source.

For commercial licensing inquiries, see [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) or contact the team via [usesicario.xyz](https://usesicario.xyz).
