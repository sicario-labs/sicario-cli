<p align="center">
  <img src="sicarioicon.png" alt="Sicario" width="100" height="100" />
</p>

<h1 align="center">Sicario</h1>

<p align="center">
  <strong>The Ambient, Zero-Exfiltration Security Engine for Application Code & Supply Chains.</strong><br/>
  SAST &nbsp;·&nbsp; SCA &nbsp;·&nbsp; Secrets &nbsp;·&nbsp; Dataflow Reachability &nbsp;·&nbsp; Deterministic Auto-Remediation &nbsp;·&nbsp; Supply-Chain Guard
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Engine-Rust_1.75+-orange?style=flat-square&logo=rust" alt="Built with Rust" />
  <img src="https://img.shields.io/badge/Languages-9_Supported-blue?style=flat-square" alt="Languages" />
  <img src="https://img.shields.io/badge/Privacy-Zero__Exfiltration-brightgreen?style=flat-square" alt="Zero-Exfil Guaranteed" />
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-FSL--1.1-orange.svg?style=flat-square" alt="FSL-1.1 License" />
  </a>
</p>

---

## ⚡ The Security Compromise is Over

Traditional application security tooling forces engineering teams into lose-lose trade-offs:
1. **Cloud Scanners** demand that you upload proprietary source code to multi-tenant servers, violating zero-trust IP boundaries.
2. **Linter Plugins** only catch superficial regex patterns, completely missing interprocedural taint flows.
3. **Legacy Platforms** block pull requests with thousands of low-priority info alerts, creating extreme **alert fatigue**.

**Sicario solves this.** Built entirely on a native Rust foundation with embedded `tree-sitter` grammars, Sicario scans codebases at blistering edge speeds, computes multi-hop taint reachability locally, applies guaranteed **deterministic patches** directly to the AST, and enforces an **Absolute Zero-Exfiltration Guarantee**.

---

## 🛡️ Core Capabilities & The Moat

### 1. Absolute Zero-Exfiltration (The Trust Moat)
Whether running a continuous audit locally or publishing results to the enterprise dashboard, **your source code never leaves your perimeter**. 
* Sicario computes a unique cryptographic identity (`fileHash` via SHA-256) for scanned targets alongside parsed metadata.
* Payloads sent to the dashboard exclusively emit file coordinates, severity flags, and rule fingerprints—**explicitly stripping raw source code snippets, developer comments, and execution traces**.

### 2. Native Multi-Language AST Engine
Sicario embeds highly optimized `tree-sitter` parsers directly into a single portable binary, delivering production-ready Static Application Security Testing (SAST) across **9 programming languages** without external runtime environments (No Node.js, Python, or JVM setups required):
* **Core Web/Backend:** JavaScript, TypeScript, Python, Go, Rust, Java
* **Enterprise Expansion:** Ruby, PHP, C#

### 3. Deterministic Auto-Remediation
Most modern AI agents attempt probabilistic code generation that breaks builds or hallucinates logic. Sicario utilizes a **Deterministic Template Registry** paired with abstract syntax tree rewrites (e.g., rewriting vulnerable string concatenations into safe parameterized SQL queries).
* Features automatic line-level backups and instant single-command rollbacks (`sicario fix --revert <patch_id>`).
* Includes an opt-in local AI agent for complex structural refactoring that connects to **any OpenAI-compatible local LLM** — Ollama, llama.cpp, LM Studio, or a custom server — with a **zero-exfiltration guarantee** (no code or tokens ever leave your machine).

### 4. "Invisible UX" & Alert Fatigue Hardening
Engineered for ultimate developer adoption, Sicario avoids blocking workflows with noise:
* **Smart Viewport Thresholding:** When interactive console outputs exceed a set fatigue threshold (e.g., 25 findings), Sicario automatically truncates visibility to the top 10 most critical, actionable items accompanied by a concise brutalist summary footer.
* **Pre-Commit Hook Intercept Mode (`--hook-mode`):** Integrates directly into Git hooks to suppress verbose outputs entirely. If High or Critical vulnerabilities are introduced, it simply pauses the commit with a minimalist prompt:
  ```
  🛑 Sicario Intercept: 2 Critical Vulnerabilities found (e.g., SQL Injection in /api/auth.ts)
  Our local engine has generated a secure, verified patch. 
  Apply fix and continue commit? [Y/n]
  ```
  Accepting auto-stages fixed files via `git add` and exits cleanly.

### 5. Multi-Layered Scan Scopes
* **Secrets Detection:** Multi-provider regex and entropy checks powered by fast one-way hashing to eliminate credentials in code or Git histories.
* **SCA & Supply Chain Guard:** Deep offline scanning of dependency lockfiles (`package.json`, `Cargo.toml`, `requirements.txt`) mapped against local OSV.dev cache databases. The **Guard module** monitors `node_modules/` for runtime behavioral anomalies (dynamic code evaluation, obfuscated payloads).
* **License Compliance:** Automated copyleft dependency identification categorized into clear organizational risk tiers.

---

## 🚀 Quick Start & Ergonomics

### Installation
**macOS / Linux**
```bash
curl -fsSL https://usesicario.xyz/install.sh | sh
```

**Windows (PowerShell)**
```powershell
irm https://usesicario.xyz/install.ps1 | iex
```

### Essential Workflows
```bash
# 1. Ambient Local Auditing
sicario scan .

# 2. Targeted Diff Scanning (Ideal for rapid local pre-push checks)
sicario scan --staged

# 3. Connect to the Enterprise Cloud Dashboard (Zero-Exfiltration Guaranteed)
sicario login
sicario scan . --publish

# 4. Standard CI/CD Output Interfacing
sicario scan . --format sarif --output results.sarif

# 5. Apply Safe Deterministic Remediation Patches
sicario fix src/database.js --rule js/sql-injection

# 6. Agentic Remediation: Auto-Fix and Open Pull Request
sicario fix --auto-pr

# 7. Install the Minimalist Intercept Git Hook
sicario hook auto-fix

# 8. Launch the Fully Interactive Terminal User Interface (TUI)
sicario tui

# 9. Local AI Fix — Auto-Detect (Ollama on localhost:11434)
sicario fix src/database.js --agent local

# 10. Local AI Fix — Specific Model (any model served on localhost:11434)
sicario fix src/database.js --agent local-qwen2.5-coder:7b

# 11. Local AI Fix — Bring Your Own Server (any OpenAI-compatible endpoint)
$env:SICARIO_LLM_ENDPOINT = "http://localhost:1234/v1/chat/completions"   # LM Studio, etc.
$env:SICARIO_LLM_MODEL = "my-model"
sicario fix src/database.js --agent cloud
```

---

## 🤖 Local AI Fix — Provider-Agnostic Setup

Sicario's AI fix agent works with **any local LLM** running an OpenAI-compatible API. No vendor lock-in — bring your own model, your own server, your own port.

| Approach | Command | What it does |
| :------- | :------ | :----------- |
| **Auto-detect** | `--agent local` | Probes `127.0.0.1:11434/api/tags` (Ollama), picks best model |
| **Explicit model** | `--agent local-qwen2.5-coder:7b` | Skips probe, uses your model name directly on port 11434 |
| **Custom endpoint** | `--agent cloud` + env vars | Points any OpenAI-compatible server (LM Studio `:1234`, llama.cpp, etc.) |

All three paths enforce **zero exfiltration** — no source code, token data, or IP ever leaves `127.0.0.1`. Ideal for air-gapped environments, offline workstations, or teams with strict data residency requirements.

```bash
# Examples

# Already running Ollama? It's one flag.
sicario fix src/api/auth.ts --agent local

# Using LM Studio on port 1234? Set the endpoint.
export SICARIO_LLM_ENDPOINT="http://127.0.0.1:1234/v1/chat/completions"
export SICARIO_LLM_MODEL="local-model"
sicario fix src/api/auth.ts --agent cloud

# Persistent config via config file
sicario config set llm_endpoint "http://127.0.0.1:8080/v1/chat/completions"
sicario config set llm_model "qwen2.5-1.5b"
sicario fix src/api/auth.ts --agent cloud
```

---

## 🧠 Advanced Security Operations

Beyond ambient developer guardrails, Sicario provides cutting-edge utility for security teams:
* **Proof-of-Concept Exploit Generation (`--prove`):** Generates actionable, customized verification payloads (e.g., safe local verification probes for path traversal or blind SQL injection) to prove exploitability.
* **Git History Exorcist (`sicario exorcise`):** Deeply scrubs sensitive credentials embedded deep inside repository commit histories.
* **Shadow Pen-Tester (`sicario attack`):** Parses framework source files (Express, FastAPI, Flask) to extract mapped HTTP route structures and dynamically compiles API endpoint testing suites.
* **Natural Language Rule Compilation (`sicario rule`):** Instantly translates human security policy descriptions into robust YAML + AST syntax rule structures.

---

## 🧠 Sicario Skills (AI Agent Orchestration)

Sicario Skills are portable, deterministic security workflows designed for AI coding assistants (Cursor, Windsurf, Claude Code). Unlike raw tools, Skills guide AI agents through complex, multi-step security hardening tasks while maintaining local-first data integrity.

* **Portable Workflows**: Distributed as markdown-based guidance and MCP Prompts that AI agents can discover and execute automatically.
* **Deterministic Remediation**: Guides AI to use Sicario's local AST templates for fixes rather than guessing probabilistic patches.
* **Ambient Hardening**: Skills like `supply-chain-sentinel` act as a background "security colleague" inside the IDE.

| Skill | Purpose | Key Tools |
| :--- | :--- | :--- |
| **`remediate-vulnerability`** | Detect, analyze, and apply deterministic local patches. | `analyze_ast_security`, `request_remediation_patch` |
| **`project-security-audit`** | Comprehensive project-wide risk assessment and roadmap. | `analyze_ast_security`, `log_telemetry_audit` |
| **`supply-chain-sentinel`** | Real-time monitoring of malicious dependency behavior. | `get_rules`, `Poison-Pill Interceptor` |

---

## 🏗️ Internal Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SICARIO CLI                             │
│                                                                 │
│  Tree-Sitter Parsers   →  Engine (SAST + SCA + Taint Tracing)   │
│  Secrets Scanner       →  Remediation Registry & Backup Mgr     │
│  Output Formatters     →  Key Management & Auth Module          │
│                                                                 │
│  Minimalist Hook Intercepts · Local Cache · Smart Viewport      │
┌─────────────────────────────────────────────────────────────────┐
                                │
                      Metadata & SHA-256 Only
                    (Zero Raw Snippet Exfiltration)
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       SICARIO CLOUD                             │
│                                                                 │
│  Convex Realtime Engine (RBAC, Audit Logs, Webhook Sync)        │
│  Enterprise Dashboard (Triage Matrix, Integrations, Policies)   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📖 Writing Custom Rules

Sicario rules are readable, declarative YAML files. Simply add a file to your targeted directory (`sicario-cli/rules/<lang>/`) or load an entire custom directory with `--rules-dir`:

```yaml
id: "js/eval-injection"
name: "Direct Code Evaluation Injection"
severity: critical
confidence: high
language: javascript
description: "Untrusted variable directly passed to the eval() interpreter engine."
pattern: |
  eval($INPUT)
cwe_id: "CWE-95"
owasp_category: "A03_Injection"
```

---

## 🤝 Contributing & Licensing

* **Contributing:** We welcome contributions from developers of all skill levels! See [CONTRIBUTING.md](CONTRIBUTING.md) to get started on expanding rule libraries, fixing edge cases, or adding custom grammars.
* **Security Disclosures:** Please view [SECURITY.md](SECURITY.md) to securely report sensitive framework vulnerabilities directly to our triage team.
* **Commercial Licensing:** Governed by the source-available **Functional Source License 1.1 (FSL-1.1)**, converting automatically to Apache 2.0 after two years. Free for local developer usage, open-source auditing, and internal corporate scanning. Providing third-party hosted commercial scanning requires a commercial enterprise arrangement. Visit [usesicario.xyz](https://usesicario.xyz) for deployment details.
