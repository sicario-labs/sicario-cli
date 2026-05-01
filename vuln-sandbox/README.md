# Sicario Vulnerability Sandbox

> **⚠️ WARNING: These files are intentionally vulnerable. Never deploy this code.**

A deliberately vulnerable codebase for testing and demonstrating [Sicario](https://usesicario.xyz) — the Rust-native security scanner. Safe to scan. Never deploy.

---

## Try it now

If you want to see Sicario in action before scanning your own code, this sandbox is the fastest way to do it.

**1. Install Sicario**

```bash
# macOS / Linux
curl -fsSL https://usesicario.xyz/install.sh | sh

# Windows (PowerShell)
irm https://usesicario.xyz/install.ps1 | iex

# Homebrew
brew install sicario-labs/sicario-cli/sicario
```

**2. Clone this repo and scan the sandbox**

```bash
git clone https://github.com/sicario-labs/sicario-cli.git
sicario scan sicario-cli/vuln-sandbox/
```

That's it. You'll see compiler-style diagnostics for 79 real vulnerability patterns across Node.js, Python, and React/TypeScript — no configuration, no API key, no cloud account required.

---

## Purpose

This sandbox gives you a safe, isolated target to verify Sicario's detection capabilities without touching your own codebase. Every file contains exactly one exploitable pattern that maps to a supported Sicario rule — no false positives, no extra noise.

Use it to:

- Confirm Sicario works correctly on your machine before scanning production code
- Explore what findings look like across different severity levels (Critical → Low)
- Validate rule IDs and severities against the manifest
- Test custom rules against known-vulnerable patterns
- Run regression checks after updating Sicario or writing new rules

---

## Directory structure

```
vuln-sandbox/
├── README.md          ← you are here
├── MANIFEST.md        ← full file → CWE → rule ID → severity mapping
├── node/              ← Node.js / JavaScript (40 files)
│   ├── cwe-89/        SQL Injection
│   ├── cwe-78/        OS Command Injection
│   ├── cwe-79/        Cross-Site Scripting
│   ├── cwe-22/        Path Traversal
│   ├── cwe-95/        eval() Injection
│   └── ...            one subdirectory per CWE
├── python/            ← Python (29 files)
│   ├── cwe-89/        SQL Injection
│   ├── cwe-78/        Command Injection
│   ├── cwe-94/        Server-Side Template Injection
│   └── ...
└── react/             ← React / TypeScript (10 files)
    ├── cwe-79/        XSS (dangerouslySetInnerHTML, href-javascript)
    ├── cwe-95/        eval() Injection
    └── ...
```

Each subdirectory is named `cwe-<ID>/` and contains a single file with one vulnerability pattern. This 1:1 mapping makes it easy to trace any finding back to its source.

---

## Scanning options

```bash
# Scan everything
sicario scan vuln-sandbox/

# Scan a specific language
sicario scan vuln-sandbox/node/
sicario scan vuln-sandbox/python/
sicario scan vuln-sandbox/react/

# Scan a single CWE category
sicario scan vuln-sandbox/node/cwe-89/

# JSON output
sicario scan vuln-sandbox/ --format json

# SARIF output for GitHub Code Scanning
sicario scan vuln-sandbox/ --format sarif --sarif-output results.sarif
```

---

## Excluding from production scans

If you clone this repo and run Sicario against your own code, add the following to your `.sicarioignore` to prevent sandbox findings from appearing in your results:

```
vuln-sandbox/
```

This entry is already present in the root `.sicarioignore` of this repository.

---

## Regression test manifest

[`MANIFEST.md`](MANIFEST.md) lists every file alongside its CWE, Sicario rule ID, and expected severity. It doubles as a CI regression manifest — if the finding count or a rule ID changes, something has changed in the rule engine.

---

## Security notice

These files contain real vulnerability patterns and **must never be**:

- Deployed to any server or cloud environment
- Imported or required by production code
- Used as templates for application development

If you are contributing new vulnerable files, follow the one-pattern-per-file rule and update `MANIFEST.md` accordingly.

---

## Learn more

- [usesicario.xyz](https://usesicario.xyz) — product website
- [Documentation](https://usesicario.xyz/docs) — full CLI reference and guides
- [GitHub](https://github.com/sicario-labs/sicario-cli) — source code
