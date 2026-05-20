---
sidebar:
  badge:
    text: Capabilities
---

# SAST Scanning

> Static Application Security Testing (SAST) is the foundation of Sicario's security analysis engine. It analyzes source code without executing it, identifying vulnerabilities by parsing code into Abstract Syntax Trees (ASTs) using Tree-sitter.

## Overview

Sicario's SAST engine is built from the ground up in Rust. Unlike tools that rely on regex-based pattern matching — which produce high false-positive rates and miss structural vulnerabilities — Sicario parses source code into full ASTs using the [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) parsing framework. This gives Sicario an understanding of code structure, not just text.

The SAST engine compiles security rules into Tree-sitter S-expression queries, matches them against parsed ASTs, and applies multi-stage analysis (pattern matching → data flow → reachability) to surface only actionable findings.

## Tree-sitter AST Parsing

Tree-sitter produces concrete syntax trees — not just token streams — which enables Sicario to understand code at the structural level. This is strictly more powerful than regex-based scanning for several reasons:

| Capability | Regex | Tree-sitter AST |
|---|---|---|
| Understands nested expressions | Partial | Full |
| Handles multi-line patterns | Awkward | Natural |
| Language-aware matching | No | Yes |
| Pattern exclusion (`pattern-not`) | Manual | Built-in |
| False positive rate | High | Low |
| Parse error resilience | N/A | Graceful |

### How Tree-sitter Works

Tree-sitter generates a **concrete syntax tree** (CST) from source code. Each node in the tree corresponds to a syntactic construct — function definition, variable declaration, call expression, string literal, etc. The Sicario engine runs compiled queries against this tree to find matches.

```
Source:  eval(userInput)
         ↓
AST:  (call_expression
        function: (identifier)   ← name="eval"
        arguments: (identifier)  ← name="userInput")
         ↓
Rule:  (call_expression function: (identifier) @fn (#eq? @fn "eval")) @call
         ↓
Match: Yes — `eval` call expression found at start of function node
```

### Language Support

Sicario supports **9 languages** through dedicated Tree-sitter grammars:

| Language | Grammar Crate | File Extensions | Notes |
|---|---|---|---|
| JavaScript | `tree-sitter-javascript` | `.js`, `.jsx`, `.mjs`, `.cjs` | Full ES2023+ support |
| TypeScript | `tree-sitter-typescript` | `.ts`, `.tsx`, `.mts`, `.cts` | TS 5.x support |
| Python | `tree-sitter-python` | `.py`, `.pyi`, `.pyx` | PEP 8 compliant |
| Rust | `tree-sitter-rust` | `.rs` | Edition 2021 |
| Go | `tree-sitter-go` | `.go` | Go 1.22+ |
| Java | `tree-sitter-java` | `.java` | Java 21 |
| Ruby | `tree-sitter-ruby` | `.rb`, `.erb` | Ruby 3.x |
| PHP | `tree-sitter-php` | `.php`, `.phtml` | PHP 8.x |
| C# | `tree-sitter-c-sharp` | `.cs` | .NET 8 |

> **Language-specific note:** JavaScript and TypeScript share a common grammar base but are compiled separately. TypeScript files are parsed using `tree_sitter_typescript::language_typescript()`, which handles TS-specific syntax (type annotations, enums, decorators) that the JS parser would reject as invalid.

## The 500+ Rule Library

Sicario ships with a comprehensive built-in rule library covering the most common vulnerability classes. Rules are organized into categories and mapped to both [CWE](https://cwe.mitre.org/) (Common Weakness Enumeration) and [OWASP Top 10 2021](https://owasp.org/Top10/) categories.

### Rule Categories

| Category | Example Rules | CWE | OWASP Top 10 |
|---|---|---|---|
| Injection | SQL injection, NoSQL injection, template injection | CWE-89 | A03:2021 |
| Cross-Site Scripting (XSS) | `innerHTML` assignment, `dangerouslySetInnerHTML`, reflected XSS | CWE-79 | A03:2021 |
| Command Injection | `exec()`, `child_process.exec`, `os.system`, `subprocess.call` | CWE-78 | A03:2021 |
| Path Traversal | Unsanitized file paths, `path.join` with user input | CWE-22 | A01:2021 |
| Cryptographic Failures | Hardcoded secrets, weak algorithms (MD5, SHA1), ECB mode | CWE-798/327 | A02:2021 |
| Authentication | Hardcoded credentials, missing auth checks | CWE-798 | A07:2021 |
| Insecure Design | `unsafe` blocks in Rust, `pickle.loads` in Python | CWE-119/502 | A04:2021 |
| Security Misconfiguration | `todo!()` in production, debug endpoints, CORS wildcard | CWE-248 | A05:2021 |
| SSRF | Server-Side Request Forgery via user-controlled URLs | CWE-918 | A10:2021 |

### CWE and OWASP Mapping

Every built-in rule has an associated CWE ID and OWASP category. These are embedded in the rule definition and propagated to each finding's output. The OWASP mapping is a Rust enum with all 10 categories:

```rust
pub enum OwaspCategory {
    A01_BrokenAccessControl,
    A02_CryptographicFailures,
    A03_Injection,
    A04_InsecureDesign,
    A05_SecurityMisconfiguration,
    A06_VulnerableComponents,
    A07_IdentificationAuthFailures,
    A08_SoftwareDataIntegrityFailures,
    A09_SecurityLoggingFailures,
    A10_ServerSideRequestForgery,
}
```

See the [Reporting](reporting.md) page for generating OWASP compliance reports.

### Built-in Default Rules

When no external rule files are loaded, Sicario activates a set of hardcoded default rules that work out-of-the-box. These cover high-signal patterns across JS/TS, Python, and Rust:

```javascript
// Detected by js/eval-injection (Critical, CWE-95)
const result = eval(userInput);

// Detected by js/innerhtml-xss (High, CWE-79)
element.innerHTML = userInput;

// Detected by js/hardcoded-secret (High, CWE-798)
const apiKey = "sk_live_example_placeholder_key_1234";
```

```python
# Detected by py/eval-injection (Critical, CWE-95)
result = eval(user_input)

# Detected by py/exec-injection (Critical, CWE-95)
exec(user_input)

# Detected by py/hardcoded-secret (High, CWE-798)
password = "super_secret_123"
```

```rust
// Detected by rust/unsafe-block (Medium, CWE-119)
unsafe {
    // ...
}

// Detected by rust/todo-panic (Medium, CWE-248)
todo!("implement this later");
```

## Confidence Scoring

Every rule has a **confidence level** that determines how aggressively its findings are reported. Confidence is a required field — rules without it are rejected at load time.

| Level | Score | Meaning | Typical Use |
|---|---|---|---|
| `high` | 0.9 | Precise pattern, rare false positives | `eval()`, hardcoded secrets, PEM keys |
| `medium` | 0.5 | Reasonably specific pattern | `innerHTML` assignment, `unsafe` blocks |
| `low` | 0.2 | Broad pattern, may have false positives | Generic API key patterns, entropy-based |
| Default | 1.0 | Fallback if no confidence is set | Legacy rules (prior to v0.3) |

### Filtering by Confidence

Use `--confidence-threshold` to exclude low-confidence findings:

```bash
# Only high-confidence findings
sicario scan . --confidence-threshold high

# High + medium confidence findings
sicario scan . --confidence-threshold medium

# All findings (default)
sicario scan . --confidence-threshold low
```

You can also filter by numeric score with `--confidence-score`:

```bash
# Only findings with confidence >= 0.5
sicario scan . --confidence-score 0.5
```

### How Confidence Affects Output

In JSON output, each finding includes both `confidence_level` and `confidence_score`:

```json
{
  "rule_id": "js/innerhtml-xss",
  "confidence_level": "high",
  "confidence_score": 0.9
}
```

## Rule Matching Process

The SAST engine uses a **three-stage pipeline** to match rules against source code:

### Stage 1: Pattern Matching (Tree-sitter Queries)

Each rule contains a Tree-sitter query written as an S-expression. The engine compiles these queries once and caches them for the lifetime of the scan.

```
Rule query:  (call_expression function: (identifier) @fn (#eq? @fn "eval")) @call
             ↓
Compiled →  tree_sitter::Query
             ↓
Executed →  QueryCursor::matches(query, root_node, source_bytes)
             ↓
Captures →  Named capture groups (@fn, @call) with AST node references
```

The engine selects the **widest capture** per match to avoid duplicate findings when a query has multiple capture names.

### Stage 2: Pattern-Not Exclusion

Rules can specify a `pattern-not` field — a secondary Tree-sitter query that **excludes** matches where the pattern-not query also matches:

```yaml
# Rule: detect eval() but skip cases where it's wrapped in a try-catch
pattern:
  query: "(call_expression function: (identifier) @fn (#eq? @fn \"eval\")) @call"
  pattern-not: "(try_statement body: (statement_block . (expression_statement (call_expression))))"
```

### Stage 3: Data Flow & Reachability

After pattern matching, findings are optionally annotated with **reachability data** (see [Reachability Analysis](reachability.md)). When `--taint` is enabled, the engine builds an inter-procedural call graph and traces data flow from external input sources (HTTP requests, env vars, file reads) to vulnerable sinks.

```bash
# Scan with taint analysis
sicario scan . --taint

# Scan with full execution traces
sicario scan . --taint --trace
```

## Running a Scan

### Basic Usage

```bash
# Scan the current directory
sicario scan .

# Scan a specific directory
sicario scan ./path/to/project

# Scan with verbose output
sicario scan . --verbose

# Quiet mode (only final results)
sicario scan . --quiet
```

### Specifying Paths

```bash
# Scan only specific file patterns
sicario scan . --include "src/**/*.js" --include "src/**/*.ts"

# Exclude directories
sicario scan . --exclude "tests/**" --exclude "vendor/**"

# Scan only staged files (for pre-commit hooks)
sicario scan . --staged
```

### Excluding Files

Sicario respects multiple exclusion mechanisms, evaluated in order:

1. **`.sicarioignore`** — project-level ignore rules (same format as `.gitignore`)
2. **`.gitignore`** — automatically applied unless `--no-git-ignore` is set
3. **Default skip directories** — `node_modules`, `.git`, `target`, `dist`, `build`, `__pycache__`, `.venv`, `venv`, `.sicario`
4. **`--exclude`** — CLI glob patterns
5. **`--include`** — CLI glob patterns (overrides exclusions)
6. **`--max-file-size`** — files larger than 1 MB (default) are skipped

```bash
# Disable .gitignore exclusion
sicario scan . --no-git-ignore

# Increase max file size to 5 MB
sicario scan . --max-file-size 5242880
```

### Output Formats

```bash
# Default text output with diagnostics
sicario scan .

# JSON output (machine-readable)
sicario scan . --format json

# SARIF output (for GitHub Code Scanning)
sicario scan . --format sarif

# Write to file
sicario scan . --format json --output results.json
```

### Focus Mode

For first-time users, `--focus` shows only Critical and High findings, grouped by file, with inline fix commands:

```bash
sicario scan . --focus
```

## Understanding Output

### Severity Levels

Each finding has one of five severity levels:

| Severity | Description | Example | Color |
|---|---|---|---|
| **Critical** | Immediate exploitation risk | `eval()`, hardcoded PEM keys | Red |
| **High** | Significant security risk | `innerHTML` XSS, hardcoded secrets | Orange |
| **Medium** | Moderate risk | `unsafe` blocks, `todo!()` macros | Yellow |
| **Low** | Minor concern | Deprecated APIs, informational | Cyan |
| **Info** | Informational | Coding style notes, debugging artifacts | White |

### Compiler-Style Diagnostics

The default output format uses [miette](https://docs.rs/miette/)-style diagnostics with source spans and underlines:

```text
  Error[js/eval-injection]: Dangerous eval() Usage (CWE-95)
         ┌─ src/controllers/user.js:12:5
         │
      12 │ ╭     const result = eval(userInput);
         │ └───── The eval() function executes arbitrary code
         │
         = Help: Use JSON.parse() for JSON data, or Function constructor as last resort
         = Severity: Critical
         = OWASP: A03:2021 – Injection
```

### File Locations and Spans

Each finding includes:
- Source file path (relative to project root)
- Line number (1-indexed)
- Column number (1-indexed)
- Code snippet (configurable context lines)
- Byte span for the matched node

```bash
# Control snippet context lines (default: 3)
sicario scan . --snippet-context 5

# Max lines per finding in text output (default: 5)
sicario scan . --max-lines-per-finding 10
```

### Inline Suppression

Findings can be suppressed inline with `// sicario-ignore` comments:

```javascript
// sicario-ignore: js/eval-injection
const result = eval(userInput);  // Will NOT be reported

// sicario-ignore: all
const secret = "AKIAIOSFODNN7EXAMPLE";  // All rules suppressed on next line
```

Suppressed findings are still included in output but marked with `suppressed: true`. They are excluded from exit code computation.

```bash
# Disable inline suppression processing (audit mode)
sicario scan . --no-ignore-comments
```

## Exit Codes

Sicario uses structured exit codes for CI/CD integration:

| Code | Meaning | Condition |
|---|---|---|
| `0` | Clean | No findings above threshold, or all findings are suppressed |
| `1` | Findings detected | At least one non-suppressed finding at or above severity threshold |
| `2` | Internal error | CLI crashed, invalid arguments, parse error in configuration |

### Setting Exit Thresholds

```bash
# Exit 1 only on Critical findings (default: High)
sicario scan . --fail-on Critical

# Exit 1 on Medium or above
sicario scan . --fail-on Medium

# Via environment variable
export SICARIO_FAIL_ON=Critical
sicario scan .

# Only exit on reachable SCA vulnerabilities
sicario scan . --sca --fail-on-reachable
```

### Using Exit Codes in CI Scripts

```yaml
# GitHub Actions example
- name: Run Sicario scan
  id: sicario
  run: sicario scan . --format sarif --sarif-output results.sarif

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Writing Custom Rules with YAML

Custom rules are written as YAML files and loaded via `--rules` or `--rules-dir`.

### Rule Schema

```yaml
# custom-rules.yaml
- id: "myorg/no-console-log"
  name: "Console Log in Production"
  description: "console.log statements should be removed before deployment"
  severity: Low
  confidence: high
  languages:
    - JavaScript
    - TypeScript
  pattern:
    query: "(call_expression function: (member_expression object: (identifier) (#eq? \"console\") property: (property_identifier) (#eq? \"log\"))) @call"
    captures:
      - "call"
  cwe_id: "CWE-532"
  owasp_category: A09_SecurityLoggingFailures
  fix_template: "console.log(…)"
  help_uri: "https://docs.myorg.com/rules/no-console-log"
```

### Required Fields

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique rule identifier (e.g. `org/category-rule`). Must not be empty. |
| `name` | string | Human-readable rule name |
| `description` | string | Explanation of the vulnerability |
| `severity` | string | `Critical`, `High`, `Medium`, `Low`, or `Info` |
| `confidence` | string | `high`, `medium`, or `low`. **Required** — rules missing this are skipped. |
| `languages` | array | Target languages (see [Language Support](#language-support)) |
| `pattern.query` | string | Tree-sitter S-expression query |
| `pattern.captures` | array | Named capture names to extract |

### Optional Fields

| Field | Type | Description |
|---|---|---|
| `pattern.pattern-not` | string | Tree-sitter query for exclusions |
| `fix_template` | string | Template for auto-remediation |
| `cwe_id` | string | CWE identifier (e.g. `"CWE-89"`) |
| `owasp_category` | string | OWASP category enum name (e.g. `A03_Injection`) |
| `help_uri` | string | Documentation URL for the rule |
| `test_cases` | array | Embedded TP/TN test cases for rule validation |

### Loading Custom Rules

```bash
# Load a single rule file
sicario scan . --rules custom-rules.yaml

# Load all rule files from a directory
sicario scan . --rules-dir ./security-rules/

# Load multiple files
sicario scan . --rules org-rules.yaml --rules team-rules.yaml
```

User rules take precedence over built-in rules on ID conflicts.

### Writing Tree-sitter Queries

Queries use Tree-sitter's [pattern-matching syntax](https://tree-sitter.github.io/tree-sitter/using-parsers#pattern-matching-with-queries):

```
# Match simple function calls
(call_expression function: (identifier) @func) @call

# Match method calls on a specific object
(call_expression function: (member_expression object: (identifier) @obj (#eq? @obj "console") property: (property_identifier) @method) arguments: (_) @args) @call

# Match string property assignments
(pair key: [(property_identifier) (string)] @key value: (string) @val) @pair
```

### Testing Custom Rules

Sicario supports embedded test cases for rule quality validation:

```yaml
- id: "myorg/no-eval"
  name: "No eval()"
  description: "eval() is dangerous"
  severity: Critical
  confidence: high
  languages:
    - JavaScript
  pattern:
    query: "(call_expression function: (identifier) @fn (#eq? @fn \"eval\")) @call"
    captures:
      - "call"
  test_cases:
    - code: "eval(userInput)"
      expected: TruePositive
      language: JavaScript
    - code: "JSON.parse(userInput)"
      expected: TrueNegative
      language: JavaScript
```

```bash
# Run rule tests
sicario rules validate custom-rules.yaml
```

## Performance

### Scan Speeds

Sicario is built for speed. Tree-sitter parsing is O(n) in file size, and queries execute in O(m × n) where m is the number of rules. With Rayon-based parallelism, scans scale across all available CPU cores.

| Project Size | Files | Rules | Time | Notes |
|---|---|---|---|---|
| Small (1k LOC) | ~20 | 500+ | < 1s | Cold start |
| Medium (100k LOC) | ~500 | 500+ | 3-8s | Parallel |
| Large (1M LOC) | ~5000 | 500+ | 15-45s | Parallel + cache |
| Monorepo (10M LOC) | ~50k | 500+ | 2-5 min | Parallel + cache |

### Parallelism with Rayon

The engine uses [Rayon](https://docs.rs/rayon/) to scan files in parallel. Each worker thread maintains its own Tree-sitter parser instance to avoid contention on the AST cache:

```rust
files_to_scan.par_iter().map(|file_path| {
    // Each thread has its own parser
    let mut parser = tree_sitter::Parser::new();
    // ... scan ...
})
```

Control parallelism with `--jobs`:

```bash
# Limit to 4 parallel threads
sicario scan . --jobs 4
```

### Caching

Sicario maintains an LRU cache of parsed ASTs. Repeated scans of the same files (e.g., in watch mode) reuse cached trees:

```bash
# Disable read from cache
sicario scan . --no-cache

# Disable write to cache
sicario scan . --no-cache-write
```

## Best Practices

### Effective Scanning

1. **Scan early, scan often** — integrate Sicario into your pre-commit hooks and CI pipeline
2. **Use `--focus` for new projects** — start with Critical/High findings, expand scope as you triage
3. **Set `--fail-on` in CI** — use `Critical` for strict pipelines, `High` for standard
4. **Build a suppression baseline** — use `--learn-suppressions` to capture intentional false positives
5. **Use `--diff` for PR scans** — only surface findings on changed lines

```bash
# Pre-commit hook usage
sicario scan . --staged --fail-on High

# PR scan: only new lines
sicario scan . --diff origin/main

# Learn suppression patterns
sicario scan . --learn-suppressions
```

### Writing Maintainable Rules

1. **Prefer `(#eq? ...)` over `(#match? ...)`** — exact matches are faster and more precise
2. **Include test cases** — every custom rule should have at least one TP and one TN
3. **Set appropriate `confidence`** — broad patterns get `low`, precise patterns get `high`
4. **Use `pattern-not` for exclusions** — don't write complex negative lookaheads in regex

### Reducing False Positives

1. Add `pattern-not` exclusions for common safe patterns
2. Use `--confidence-threshold high` in noisy codebases
3. Suppress known false positives with `// sicario-ignore: rule-id`
4. Use `--taint` to filter unreachable findings

## Troubleshooting

### Slow Scans

| Symptom | Likely Cause | Solution |
|---|---|---|
| Scan takes > 1 min for small project | Too many files included | Add `--exclude` patterns, check `.sicarioignore` |
| Single file takes > 10s | Very large file | Set `--max-file-size` lower |
| Scan is I/O bound | Mechanical hard drive | Use `--no-cache` to skip cache overhead |
| Scan is CPU bound | Too many parallel jobs | Use `--jobs 2` to reduce contention |

### False Positives

| Scenario | Solution |
|---|---|
| `eval` in test framework | Add `pattern-not` or use `--exclude "tests/**"` |
| Variable named `password` in example code | Add to `.sicario-allowlist.yaml` or use suppression comment |
| Generated code triggering rules | Exclude the generated directory |

### Missing Rules

If a rule doesn't fire when you expect it to:

1. Verify the file extension is supported (`.js`, `.py`, `.rs`, etc.)
2. Check the rule's `languages` field includes your language
3. Run with `--verbose` to see which files are being scanned
4. Check `--exclude` and `.sicarioignore` aren't filtering the file
5. Verify the rule has a `confidence` field — rules without it are silently skipped

```bash
# Debug rule application
sicario scan . --verbose --rules only-my-rule.yaml
```

### Parse Errors

Files with severe syntax errors produce a `[Skip]` warning but never abort the scan:

```text
[Skip] broken.js - Invalid syntax, cannot parse AST
```

## Comparison: Sicario SAST vs Alternatives

| Feature | Sicario | Semgrep | CodeQL | SonarQube |
|---|---|---|---|---|
| Parsing engine | Tree-sitter (Rust) | Generic AST (OCaml) | QL compiler (C++) | Custom (Java) |
| Languages | 9 | 30+ | 5+ | 30+ |
| Rules shipped | 500+ | 2,000+ | 3,000+ | 600+ |
| Rule language | YAML + S-expr | YAML + Python-like | QL | GUI/XML |
| Custom rules | YAML files | YAML files | QL lang | Plugin |
| Parallelism | Rayon (auto) | --jobs (manual) | --threads | Internal |
| Data flow | Inter-procedural | Intra-procedural | Full | Intra-procedural |
| Auto-remediation | ✅ (AST + AI) | ❌ | ❌ | ✅ (limited) |
| MCP server | ✅ (built-in) | ❌ | ❌ | ❌ |
| Performance | Very fast | Fast | Slow | Moderate |
| False positive rate | Low | Low | Very low | Moderate |
| CI-native exit codes | ✅ | ✅ | ✅ | ✅ |

## Related

- [SCA Scanning](sca-scanning.md) — dependency vulnerability analysis
- [Secret Detection](secrets-detection.md) — credential scanning
- [Reachability Analysis](reachability.md) — data-flow taint tracking
- [Auto-Remediation](auto-remediation.md) — automated fix generation
- [Reporting](reporting.md) — SARIF and OWASP compliance reports
