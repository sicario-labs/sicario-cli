# Design Document: sicario-v2-eta-engine

## Overview

The eta-engine spec ships seven tightly scoped capabilities that extend the beta-engine foundation into a full autonomous security platform. The work splits across two tracks:

**Developer track (Reqs 1–9):** Ollama air-gapped remediation with a deterministic cage, AST-level SQL rewrite, Ghost Fix pre-commit hook, and proof-of-concept generation.

**Enterprise track (Reqs 12–17):** Security regression guard, compliance evidence export, policy-as-code enforcement, MTTR tracking, suppression audit log, and dependency license risk scanner.

All features maintain the zero-exfiltration guarantee. No source code leaves the machine unless `--allow-ai` with a cloud provider is explicitly set.

---

## Architectural Invariants

- **Zero-Exfiltration**: Local agent calls go only to `http://127.0.0.1:11434`. Ghost Fix and `SqlAstRewriteTemplate` make zero network calls.
- **Deterministic-First**: Every new code path tries a deterministic template before any LLM call. LLM output is always verified by tree-sitter before touching disk.
- **Fallback Chain**: `MultiLinePatchTemplate` → `PatchTemplate` → LLM → comment-only warning. No step blocks the developer's workflow.
- **Idempotency**: Hook installation, baseline saves, and compliance report generation are all safe to run multiple times.

---

## Area 1: Ollama Air-Gapped Remediation

### 1.1 `--agent` Flag and `AgentSelector`

The `--agent` flag is added to `FixArgs` in `sicario-cli/src/cli/fix.rs`. Valid values: `local`, `local-<model>`, `cloud`.

```rust
// sicario-cli/src/cli/fix.rs
#[arg(long)]
pub agent: Option<String>,
```

`AgentSelector` is a new struct in `sicario-cli/src/remediation/agent_selector.rs` that parses the flag and returns an `AgentConfig`:

```rust
pub enum AgentConfig {
    Local { model_override: Option<String> },
    Cloud,
    Auto, // default: existing behavior
}
```

When `AgentConfig::Local` is resolved, `AgentSelector` sets `allow_ai = true` implicitly for the local model only — the consent guardrail is not triggered for localhost calls.

### 1.2 `OllamaClient`

New struct in `sicario-cli/src/remediation/ollama_client.rs`. Reuses the existing `LlmClient` HTTP infrastructure with `AuthStyle::None` and endpoint `http://127.0.0.1:11434/v1/chat/completions`.

**Probe flow:**

```
GET http://127.0.0.1:11434/api/tags  (500ms timeout)
  ├── success → select model by priority:
  │     1. first model containing "qwen2.5-coder"
  │     2. first model containing "deepseek-coder"
  │     3. first model in list
  └── failure → print error with ollama.ai URL + pull commands → exit non-zero
```

When `--agent=local-<model>` is specified, the probe is skipped and the model name is used directly.

IPv4 loopback (`127.0.0.1`) is used explicitly to avoid IPv6 resolution delays on platforms where `localhost` resolves to `::1`.

### 1.3 `MicroContextExtractor`

New struct in `sicario-cli/src/remediation/micro_context.rs`. Uses the existing `TreeSitterEngine` to extract the smallest enclosing function block containing the vulnerable line.

**Extraction algorithm:**
1. Parse the file with tree-sitter.
2. Walk up the AST from the vulnerable node to find the nearest `function_declaration`, `arrow_function`, `method_definition`, or equivalent node.
3. Extract the text of that node.
4. Collect all `identifier` nodes within the extracted block → `in_scope_variables: Vec<String>`.

The extracted block is capped at 2,000 tokens (≈ 1,500 characters) before being included in the prompt. If the function block exceeds this limit, the extractor falls back to a ±15 line window.

### 1.4 `LocalLlmPrompt`

The prompt struct sent to the local model:

```rust
pub struct LocalLlmPrompt {
    pub system: &'static str,   // verbatim system instruction
    pub vuln_class: String,     // e.g. "SQL Injection (CWE-89)"
    pub function_block: String, // extracted by MicroContextExtractor
    pub in_scope_variables: Vec<String>,
}
```

System instruction (verbatim, per Req 2a.3):
```
"You are a strict code transformer. Return ONLY a JSON object with a single field: {\"replacement\": \"<fixed code>\"}. Do not explain. Do not add imports. Do not invent variable names. Only use variables from the provided scope list."
```

`max_tokens: 512`, `temperature: 0.0`.

### 1.5 `TreeSitterVerificationLoop`

New struct in `sicario-cli/src/remediation/ts_verification.rs`. Three-stage pipeline:

| Stage | Check | Failure action |
|-------|-------|----------------|
| 1 | Parse response as `{"replacement": "..."}` JSON | Discard → comment-only fallback |
| 2 | Parse `replacement` with tree-sitter; check for error nodes | Discard → comment-only fallback |
| 3 | Extract identifiers from replacement AST; verify all are in `in_scope_variables` or are keywords/literals | Discard → comment-only fallback |

On pass: splice replacement into original file using existing `splice_patch`. On any failure: no retry, no partial write. The invariant holds: disk state is either syntactically valid or identical to original.

All three checks complete within 50ms for replacements up to 200 lines.

### 1.6 `PatchReceipt` Updates for Local Agent

The existing `PatchReceipt` struct in `receipt.rs` gains a `local_agent` constructor:

```rust
pub fn local_agent(
    rule_id: impl Into<String>,
    file: impl Into<String>,
    line: u32,
    execution_ms: u128,
    model_name: impl Into<String>,
) -> Self {
    Self {
        tokens_burned: 0,
        lines_exfiltrated: 0,
        template_used: format!("ollama-local ({})", model_name.into()),
        ..
    }
}
```

`tokens_burned: 0` and `lines_exfiltrated: 0` are enforced structurally — the local agent path never calls the token-counting code path.

---

## Area 2: `MultiLinePatchTemplate` and `SqlAstRewriteTemplate`

### 2.1 `MultiLinePatchTemplate` Trait

New trait in `sicario-cli/src/remediation/template_registry/mod.rs`, alongside the existing `PatchTemplate`:

```rust
pub trait MultiLinePatchTemplate: Send + Sync {
    fn name(&self) -> &'static str;
    fn generate_multiline_patch(
        &self,
        file_content: &str,
        vulnerable_line: usize,
        lang: Language,
    ) -> Option<String>;
}
```

`TemplateRegistry` gains a second map:

```rust
pub struct TemplateRegistry {
    single_line: HashMap<RegistryKey, Box<dyn PatchTemplate>>,
    multi_line:  HashMap<RegistryKey, Box<dyn MultiLinePatchTemplate>>,
}
```

`RemediationEngine::try_registry_fix` is updated to check `multi_line` first, then `single_line`. If a `MultiLinePatchTemplate` returns `Some(content)`, the content is validated with tree-sitter before being accepted. If validation fails, the result is discarded and the single-line lookup proceeds.

### 2.2 `SqlAstRewriteTemplate`

New struct in `sicario-cli/src/remediation/template_registry/sql.rs`, implementing `MultiLinePatchTemplate`.

**Supported patterns:**

| Pattern | Input | Output |
|---------|-------|--------|
| String concatenation | `db.query("SELECT * FROM t WHERE id = " + userId)` | `db.query("SELECT * FROM t WHERE id = $1", [userId])` |
| Template literal | `` db.query(`SELECT * FROM t WHERE id = ${userId}`) `` | `db.query("SELECT * FROM t WHERE id = $1", [userId])` |
| Multi-line concat | Concatenation spanning multiple lines | Single parameterized call, original indentation preserved |

**AST walk algorithm:**
1. Parse file with tree-sitter (JS/TS only; return `None` for other languages).
2. Find the node at `vulnerable_line`.
3. Walk up to the nearest `call_expression` whose callee ends in `.query` or `.execute`.
4. Extract all string/template literal parts and interpolated expressions.
5. Build parameterized query string (`$1`, `$2`, …) and variable array.
6. Reconstruct the call with original indentation.
7. Return `None` if: more than 8 interpolated variables, conditional query construction, nested function calls as arguments, or any other pattern that cannot be safely rewritten.

**Registration** (replaces existing comment-only templates):
```rust
registry.register_multi("js-sql-string-concat",  Some("89"), Box::new(SqlAstRewriteTemplate));
registry.register_multi("js-sql-template-string", Some("89"), Box::new(SqlAstRewriteTemplate));
registry.register_multi("node-sql-template-literal", Some("89"), Box::new(SqlAstRewriteTemplate));
```

Round-trip property: for all valid JS/TS files where the template produces output, `tree_sitter.parse(output).root_node().has_error() == false`.

---

## Area 3: Ghost Fix Pre-Commit Hook

### 3.1 `AutoFixHook` Script

The `HookManager` in `sicario-cli/src/hook/manager.rs` gains an `install_auto_fix()` method. The installed script block:

```sh
# BEGIN SICARIO HOOK
if [ "$SICARIO_SKIP_HOOK" = "1" ]; then
  exit 0
fi
_sicario_results=$(sicario fix --staged --format json --quiet 2>/dev/null)
_sicario_fixed=$(printf '%s' "$_sicario_results" | grep -c '"fixed":true' || true)
_sicario_unfixed=$(printf '%s' "$_sicario_results" | grep -c '"fixed":false' || true)
if [ "$_sicario_unfixed" -gt 0 ]; then
  sicario scan --staged --severity-threshold high
  exit 1
fi
if [ "$_sicario_fixed" -gt 0 ]; then
  printf '%s\n' "$_sicario_results" | grep '"file"' | sed 's/.*"file":"\([^"]*\)".*/\1/' | sort -u | xargs git add
  echo "Sicario: auto-fixed $_sicario_fixed vulnerabilities. Commit proceeding."
fi
# END SICARIO HOOK
```

POSIX `sh` syntax throughout — no bash-specific constructs. Works under Git Bash on Windows.

**Idempotency**: `install_auto_fix()` calls `remove_sicario_block()` before writing the new block, ensuring exactly one `BEGIN SICARIO HOOK` / `END SICARIO HOOK` pair regardless of prior state.

**Backup safety**: The hook calls `sicario fix --staged` which uses the existing `BackupManager`. If `git add <file>` fails after a fix, the hook restores from backup and blocks the commit.

**Performance**: The hook must complete within 2 seconds for ≤20 staged files with ≤50 findings. This is enforced by `sicario fix --staged` using only deterministic templates (no LLM calls).

### 3.2 `sicario fix --staged` Command

`FixArgs` gains a `--staged` flag:

```rust
#[arg(long)]
pub staged: bool,
```

When `--staged` is set:
1. Run `git diff --cached --name-only` to enumerate staged files.
2. Normalize path separators to forward slashes on Windows.
3. Restrict fix attempts to staged files only.
4. Skip the interactive diff confirmation prompt — apply automatically.
5. Use only `DeterministicFix` patches — no LLM fallback.
6. With `--format json`, output a JSON array:

```json
[
  { "file": "src/db.js", "rule_id": "js-sql-string-concat", "line": 42, "fixed": true, "template_used": "SqlAstRewriteTemplate" },
  { "file": "src/auth.js", "rule_id": "hardcoded-secret", "line": 7, "fixed": false, "template_used": null }
]
```

If run outside a Git repository, print a descriptive error and exit non-zero.

---

## Area 4: Proof-of-Concept Generation

### 4.1 `PocGenerator`

New struct in `sicario-cli/src/poc/generator.rs`. Activated by `--prove` on `sicario scan`.

**Consent prompt** (required before any payload is printed):
```
Warning: This will generate an active exploit payload. Ensure you are running this against a safe, local environment. Proceed? [y/N]
```

If the user does not type `y` or `yes` (case-insensitive), the finding is skipped. With `--format json`, the consent prompt is suppressed and a `poc` field is included in each finding object.

**Supported vulnerability classes:**

| CWE | Technique | Payload target |
|-----|-----------|----------------|
| 89 (SQL injection) | Time-based (`pg_sleep`, `SLEEP`, `WAITFOR DELAY`) | `http://127.0.0.1:<port>/<route>` extracted from AST |
| 918 (SSRF) | `SsrfProbeListener` on random local port | `http://127.0.0.1:<probe_port>/ssrf-probe` |
| 78 (Command injection) | `; echo sicario-poc-$(date +%s)` | Injected into detected parameter |
| 22 (Path traversal) | Read `/etc/hostname` (Unix) or `C:\Windows\System32\drivers\etc\hosts` (Windows) | Injected into detected path parameter |

**Safety enforcement (in Rust engine, not documentation):**
- Any generated URL that does not resolve to `127.0.0.1` or `::1` is rejected before printing.
- Any generated SQL payload containing `DROP`, `DELETE`, `TRUNCATE`, `UPDATE`, `INSERT`, or `ALTER` is rejected before printing.

**`PocPayload` struct:**

```rust
pub struct PocPayload {
    pub vuln_location: String,   // "src/db.js:42"
    pub curl_command: String,    // the generated curl command
    pub interpretation: String,  // e.g. "If the server takes ~5 seconds to respond, the vulnerability is confirmed."
}
```

If insufficient AST context is available, the generator skips the finding and prints `"PoC not available for this finding — insufficient AST context."` — no generic payloads are generated.

**`SsrfProbeListener`**: A short-lived `TcpListener` bound to `127.0.0.1:0` (OS-assigned port). The listener is spawned in a background thread, prints a confirmation if a connection is received, and shuts down after 30 seconds.

---

## Area 5: Security Regression Guard

### 5.1 `BaselineManager` Extensions

The existing `BaselineManager` in `sicario-cli/src/baseline/manager.rs` already implements `save()` and `compare()`. The eta-engine adds:

**`sicario baseline save` command** — already scaffolded in `cli/baseline.rs`. The `--tag` flag is already supported. The `save()` method writes to `.sicario/baselines/<timestamp>_<tag>.json` and never overwrites existing files.

**`sicario baseline diff --ci` command** — new `BaselineAction::Diff` variant in `cli/baseline.rs`:

```rust
Diff(BaselineDiffArgs),
```

```rust
pub struct BaselineDiffArgs {
    /// Tag or timestamp of the baseline to compare against (optional; uses most recent if omitted)
    pub reference: Option<String>,
    /// Exit with code 1 on new findings above threshold (for CI use)
    #[arg(long)]
    pub ci: bool,
    /// Minimum severity for CI blocking (default: High)
    #[arg(long, value_enum, default_value = "high")]
    pub threshold: SeverityLevel,
    /// Tag of a named baseline to compare against
    #[arg(long)]
    pub tag: Option<String>,
}
```

**CI output format:**
```
✓  <N> known findings (unchanged — not blocking)
✓  <M> findings resolved since baseline
✗  <K> NEW findings introduced (blocking CI)
```

**Exit codes:**
- `0`: no new findings above threshold
- `1`: new findings above threshold present
- `2`: no baseline file found (descriptive error printed)

The `BaselineDelta` struct already exists and is already JSON-serializable. The round-trip property (serialize → deserialize → equivalent delta) is guaranteed by the existing `serde` derives.

---

## Area 6: Enterprise Reporting

### 6.1 Compliance Evidence Export (`sicario report --compliance`)

New command in `sicario-cli/src/cli/` and implementation in `sicario-cli/src/reporting/compliance.rs`.

**Output file**: `.sicario/compliance-report-<timestamp>.json`

**Report structure:**

```rust
pub struct ComplianceReport {
    pub generated_at: String,          // ISO 8601
    pub sicario_version: String,
    pub scan_summary: ScanSummary,
    pub remediation_log: Vec<RemediationEntry>,
    pub suppression_log: Vec<SuppressionEntry>,
    pub baseline_history: Vec<BaselineSummary>,
    pub mttr_by_rule: Vec<MttrEntry>,
}
```

**Data sources:**
- `remediation_log`: populated from `BackupManager::load_history()` (existing `PatchHistoryEntry` records).
- `suppression_log`: scan all source files for `sicario-ignore` directives, then run `git log -S "sicario-ignore" --follow --format="%ae %aI" -- <file>` to attribute each suppression. If no git history, record file path and line without author.
- `baseline_history`: populated from `BaselineManager::trend()`.
- `mttr_by_rule`: computed from detection timestamps (baseline history) and fix timestamps (remediation log).

**SARIF export**: when `--format sarif` is specified alongside `--compliance`, write a SARIF v2.1.0 file at `.sicario/compliance-report-<timestamp>.sarif`. Reuses the existing `output/sarif.rs` serializer.

**Performance**: completes within 10 seconds for ≤10,000 source files and ≤500 findings.

### 6.2 Policy-as-Code Enforcement (`sicario policy`)

New module in `sicario-cli/src/policy/`.

**`.sicario/policy.yaml` schema:**

```yaml
fail_on: High                    # overrides --fail-on
required_rules:                  # cannot be suppressed
  - js-sql-string-concat
  - hardcoded-secret
blocked_suppressions:            # sicario-ignore prohibited
  - js-sql-string-concat
scope:                           # glob patterns
  - "src/**"
max_findings: 100                # total finding count limit
```

**Loading**: `PolicyLoader` in `sicario-cli/src/policy/loader.rs` reads `.sicario/policy.yaml` on every `sicario scan` invocation if the file exists. Policy fields override all local CLI flags.

**Enforcement points:**
- `required_rules` + `sicario-ignore` → exit 1 with policy violation message.
- `blocked_suppressions` + staged `sicario-ignore` → `AutoFixHook` blocks commit.
- `fail_on` → overrides `--fail-on` flag.
- `max_findings` → exit 1 if total finding count exceeds limit.

**`sicario policy validate`**: parses `.sicario/policy.yaml`, checks all rule IDs against the loaded rule set, prints unknown rule IDs and invalid glob patterns.

**`sicario policy init`**: generates a `.sicario/policy.yaml` template with all fields commented out.

### 6.3 MTTR Tracking (`sicario report --mttr`)

New command in `sicario-cli/src/reporting/mttr.rs`.

**MTTR formula**: for each remediated finding, `MTTR = fix_timestamp - detection_timestamp` in hours. Per-rule MTTR is the arithmetic mean across all remediated findings for that rule ID within the reporting period.

**Table output:**

```
Rule ID                  Vulnerability Class    Severity  Detected  Remediated  MTTR (hours)  Trend
js-sql-string-concat     SQL Injection          High      12        10          4.2           ↑
hardcoded-secret         Hardcoded Credentials  High      5         5           1.1           →
```

Trend indicators: `↑` (improving — MTTR decreasing), `↓` (worsening — MTTR increasing), `→` (stable — <10% change vs previous period).

If fewer than 3 findings have been remediated for a rule ID, display `"Insufficient data"` in the MTTR column.

`--format json` outputs a JSON array suitable for Datadog/Splunk ingestion.

`--since <ISO8601_date>` restricts computation to findings detected after the specified date.

**Performance**: completes within 5 seconds for ≤1,000 remediated findings.

### 6.4 Suppression Audit Log (`sicario suppressions audit`)

New subcommand under the existing `suppressions` command group in `sicario-cli/src/cli/suppressions.rs`.

**Audit entry:**

```rust
pub struct SuppressionAuditEntry {
    pub file: String,
    pub line: usize,
    pub rule_id: String,          // "all" for blanket suppressions
    pub comment_text: String,
    pub author_email: String,     // "untracked" if no git history
    pub commit_sha: String,       // "untracked" if no git history
    pub committed_at: String,     // ISO 8601, "untracked" if no git history
}
```

**Git attribution**: `git blame --porcelain -L <line>,<line> <file>` extracts commit SHA and author email. If the file is untracked, all three fields are set to `"untracked"`.

**Output formats:**
- `--format json`: JSON array of `SuppressionAuditEntry` objects.
- `--format csv`: CSV with headers `file,line,rule_id,comment,author_email,commit_sha,committed_at`.

**Filters:**
- `--since <ISO8601_date>`: restrict to suppressions introduced after the date.
- `--author <email>`: restrict to suppressions by a specific author.

**Append mode**: `--output <path>` appends to an existing file rather than overwriting.

**Performance**: completes within 10 seconds for ≤500 suppressions across ≤10,000 source files.

### 6.5 Dependency License Risk Scanner (`sicario scan --licenses`)

New module in `sicario-cli/src/engine/sca/license_scanner.rs`.

**Risk tiers:**

| Tier | Licenses |
|------|----------|
| HIGH | GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0, EUPL-1.2 |
| MEDIUM | LGPL-2.1, LGPL-3.0, MPL-2.0, CDDL-1.0 |
| LOW | MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD |

**License resolution order:**
1. Local OSV/GHSA SQLite cache (existing `cache/` module).
2. npm registry: `https://registry.npmjs.org/<package>` (2-second timeout).
3. PyPI: `https://pypi.org/pypi/<package>/json` (2-second timeout).

**Allowlist**: `.sicario/license-allowlist.txt` — one package name per line. Allowlisted packages are reported but do not contribute to the exit code.

**Output**: license risk table appended after the security findings table. With `--format json`, a `license_findings` array is included alongside `security_findings`.

**Exit code gating**: `--fail-on-license HIGH` exits 1 on any HIGH-tier dependency. `--fail-on-license MEDIUM` exits 1 on any HIGH or MEDIUM dependency.

**Performance**: completes within 15 seconds for ≤500 dependencies including network fetches.

---

## Cross-Cutting Concerns

### File Layout (new files)

```
sicario-cli/src/
  remediation/
    agent_selector.rs       # AgentConfig, AgentSelector
    ollama_client.rs        # OllamaClient, model probe
    micro_context.rs        # MicroContextExtractor, LocalLlmPrompt
    ts_verification.rs      # TreeSitterVerificationLoop
    template_registry/
      sql.rs                # SqlAstRewriteTemplate (updated)
  poc/
    mod.rs
    generator.rs            # PocGenerator, PocPayload, SsrfProbeListener
  policy/
    mod.rs
    loader.rs               # PolicyLoader, PolicyConfig
    validator.rs            # policy validate command
  reporting/
    compliance.rs           # ComplianceReport, compliance export
    mttr.rs                 # MttrReport, MTTR computation
  cli/
    fix.rs                  # --agent, --staged flags (updated)
    scan.rs                 # --prove, --licenses flags (updated)
    baseline.rs             # Diff subcommand (updated)
    suppressions.rs         # audit subcommand (updated)
    policy.rs               # policy subcommand (new)
    report.rs               # report subcommand (new)
  engine/sca/
    license_scanner.rs      # LicenseScanner, risk tier classification
```

### Zero-Exfiltration Verification Matrix

| Feature | Network calls | `lines_exfiltrated` |
|---------|--------------|---------------------|
| `--agent=local` | `127.0.0.1:11434` only | 0 |
| `SqlAstRewriteTemplate` | None | 0 |
| `AutoFixHook` | None | 0 |
| `PocGenerator` | None (SsrfProbeListener is inbound) | 0 |
| `sicario report --compliance` | None (git subprocess only) | 0 |
| `sicario scan --licenses` | npm/PyPI for uncached licenses only | 0 |

### Cross-Platform Compatibility

- `OllamaClient` uses `127.0.0.1` (IPv4) not `localhost`.
- `AutoFixHook` uses POSIX `sh` syntax.
- `HookManager::install_auto_fix()` sets `0o755` on Unix.
- `sicario fix --staged` normalizes path separators to `/` on Windows.
- `SqlAstRewriteTemplate` preserves input line endings (LF/CRLF).

---

## Area 7: V1 Bottlenecks and Incomplete Implementations

This area documents every confirmed gap found during a full codebase audit. These are not new features — they are broken or missing wires in the existing v1 code that must be fixed for v2 to be a genuine upgrade.

---

### 7.1 Exit Code Logic: Hardcoded Confidence and Suppression (CRITICAL)

**File:** `sicario-cli/src/main.rs` lines 654–661

**Current state:**
```rust
let summaries: Vec<FindingSummary> = vulns
    .iter()
    .map(|v| FindingSummary {
        severity: v.severity,
        confidence_score: 1.0, // confidence scoring not yet wired
        suppressed: false,     // suppression not yet wired
    })
    .collect();
```

Both fields are hardcoded. The `ExitCode::from_findings` function in `cli/exit_code.rs` is fully implemented and correctly handles both fields — but it is never fed real data.

**Impact:**
- `--confidence-threshold` flag is accepted but silently ignored. A finding with `confidence_score: 0.1` still triggers exit code 1 even when the user sets `--confidence-threshold 0.8`.
- Suppressed findings (those with `v.suppressed == true` from the SAST engine's inline suppression parser) still count toward the exit code. A `// sicario-ignore` comment has no effect on CI gating.

**Fix:** Replace the hardcoded values with the actual fields from the `Vulnerability` struct:
```rust
FindingSummary {
    severity: v.severity,
    confidence_score: v.confidence_score,
    suppressed: v.suppressed,
}
```

The `Vulnerability` struct already carries both fields. This is a two-line fix with no architectural change.

---

### 7.2 Ollama Model Selection: Missing Priority Logic (HIGH)

**File:** `sicario-cli/src/key_manager/manager.rs` — `try_ollama_detection()`

**Current state:**
```rust
let model_name = body["models"]
    .as_array()?
    .first()?   // ← always picks the first model, no priority
    .get("name")?
    .as_str()?
    .to_string();
```

The existing auto-detection always picks the first model in the Ollama `/api/tags` response, regardless of quality. The eta-engine spec (Req 2) requires priority selection: `qwen2.5-coder` first, `deepseek-coder` second, first-in-list as fallback.

**Impact:** Users with multiple Ollama models installed will get a random general-purpose model (e.g., `llama3`) instead of a coding-specialized model, producing lower-quality fixes.

**Fix:** Replace `.first()` with a priority selection function:
```rust
fn select_best_model(models: &[serde_json::Value]) -> Option<String> {
    // Priority 1: qwen2.5-coder
    if let Some(m) = models.iter().find(|m| {
        m.get("name").and_then(|n| n.as_str())
            .map(|n| n.contains("qwen2.5-coder"))
            .unwrap_or(false)
    }) {
        return m.get("name")?.as_str().map(|s| s.to_string());
    }
    // Priority 2: deepseek-coder
    if let Some(m) = models.iter().find(|m| {
        m.get("name").and_then(|n| n.as_str())
            .map(|n| n.contains("deepseek-coder"))
            .unwrap_or(false)
    }) {
        return m.get("name")?.as_str().map(|s| s.to_string());
    }
    // Fallback: first model
    models.first()?.get("name")?.as_str().map(|s| s.to_string())
}
```

This function is also used by the new `OllamaClient` in Area 1.2, so it should be extracted to a shared location in `key_manager/manager.rs`.

---

### 7.3 PR Creation Stub (MEDIUM)

**File:** `sicario-cli/src/remediation/remediation_engine.rs` lines 450–456

**Current state:**
```rust
pub fn create_pull_request(&self, _patch: &Patch, _git_provider: &str) -> Result<String> {
    // PR creation requires git provider API integration (future task)
    Err(anyhow::anyhow!(
        "Pull request creation is not yet implemented"
    ))
}
```

**Impact:** Any code path that calls `create_pull_request` returns an error. The GitHub App integration spec and the `sicario fix --pr` flag (if exposed) are silently broken.

**Fix:** Implement GitHub PR creation using the GitHub REST API. The implementation reads the `GITHUB_TOKEN` env var (standard in GitHub Actions), creates a branch, commits the patch, and opens a PR via `POST /repos/{owner}/{repo}/pulls`. GitLab support uses `GITLAB_TOKEN` and the GitLab MR API. The provider is auto-detected from the `git remote get-url origin` output.

```rust
pub fn create_pull_request(&self, patch: &Patch, git_provider: &str) -> Result<String> {
    match git_provider {
        "github" | "auto" => create_github_pr(patch),
        "gitlab" => create_gitlab_mr(patch),
        other => Err(anyhow::anyhow!("Unsupported git provider: {}", other)),
    }
}
```

The PR title format: `fix: [sicario] <rule_id> in <file>`. The PR body includes the patch receipt and a link to the CWE reference.

---

### 7.4 JSON Schema Validation TODO in Deserialization Template (LOW)

**File:** `sicario-cli/src/remediation/templates.rs` line 619

**Current state:**
```rust
"{indent}// SICARIO FIX: Validate deserialized data with schema validation\n\
 {indent}const parsed = JSON.parse(userInput);\n\
 {indent}// TODO: Add JSON schema validation for parsed data\n\
```

The generated fix code itself contains a `TODO` comment that gets written into the user's source file. This is unprofessional and confusing.

**Fix:** Replace the TODO comment with a concrete schema validation stub using `zod` (the de facto standard for TypeScript/JavaScript schema validation):
```javascript
// SICARIO FIX: Validate deserialized data against a schema
const { z } = require('zod');
const schema = z.object({}); // TODO: define your schema shape here
let parsed;
try {
  parsed = schema.parse(JSON.parse(userInput));
} catch (e) {
  return res.status(400).json({ error: 'Invalid input' });
}
```

---

### 7.5 `--auto-suppress` Flag Not Wired into Scan Output (MEDIUM)

**File:** `sicario-cli/src/main.rs` — `cmd_scan`

**Current state:** The `--auto-suppress` flag is accepted in `ScanArgs` and the `SuppressionLearner` module is fully implemented, but `cmd_scan` never calls `learner.auto_suppress(&vulns)` to filter the findings before output.

**Impact:** `sicario scan --auto-suppress` behaves identically to `sicario scan` — the flag is silently ignored.

**Fix:** After the scan completes and before output formatting, load the `SuppressionLearner` and apply it when `args.auto_suppress` is true:
```rust
let vulns = if args.auto_suppress {
    let learner = SuppressionLearner::load(&project_root)?;
    learner.auto_suppress(&vulns)
} else {
    vulns
};
```

---

### 7.6 `--confidence-threshold` Flag Not Enforced in Output Filtering (MEDIUM)

**File:** `sicario-cli/src/main.rs` — `cmd_scan`

**Current state:** The `--confidence-threshold` flag is accepted and passed to `ExitCode::from_findings`, but findings below the threshold are still printed in the output. Only the exit code is (incorrectly, due to 7.1) affected.

**Impact:** Users see findings they explicitly asked to suppress via `--confidence-threshold`. The output is noisy and the flag is misleading.

**Fix:** Filter `vulns` before output formatting:
```rust
let vulns: Vec<_> = vulns
    .into_iter()
    .filter(|v| v.confidence_score >= confidence_threshold)
    .collect();
```

This filter runs after the scan but before `format_output`, `submit_telemetry`, and exit code computation.

---

### 7.7 `SuppressionLearner::record` Never Called During Scan (MEDIUM)

**File:** `sicario-cli/src/main.rs` — `cmd_scan`

**Current state:** The `SuppressionLearner` is only used in `cmd_suppressions` (list/reset). The `record()` method — which is supposed to be called when a user manually adds a `sicario-ignore` comment — is never invoked during the scan flow.

**Impact:** The suppression learning system never accumulates data. `sicario suppressions list` always shows zero patterns regardless of how many suppressions the user has added.

**Fix:** After the scan, for each finding that has `v.suppressed == true` (i.e., it was suppressed by an inline comment), call `learner.record(&finding, &finding.snippet)`. This should be gated on a new `--learn-suppressions` flag (default: off) to avoid unexpected writes during CI scans.

---

### 7.8 `sicario baseline diff` Missing `--ci` Flag (HIGH)

**File:** `sicario-cli/src/cli/baseline.rs`

**Current state:** The `BaselineAction` enum has `Save`, `Compare`, and `Trend` variants. There is no `Diff` variant and no `--ci` flag. The `BaselineManager::compare()` method is fully implemented, but there is no CLI surface to invoke it with CI semantics (exit 1 on new findings, exit 0 on unchanged).

**Impact:** The regression guard feature (Req 12) has no CLI entry point. Teams cannot use `sicario baseline diff --ci` in their pipelines.

**Fix:** Add `Diff(BaselineDiffArgs)` to `BaselineAction` and implement `cmd_baseline_diff` as described in Area 5 of this design document. This is already planned in Phase 5 of tasks.md but is called out here because it is a v1 gap, not just a new feature.

---

### 7.9 `sicario report` Command Missing (HIGH)

**File:** `sicario-cli/src/cli/` — no `report.rs` exists

**Current state:** The `cmd_report_handler` referenced in the overhaul design exists for OWASP compliance reporting only (`reporting/owasp_report.rs`). There is no `sicario report --compliance`, `sicario report --mttr`, or `sicario report --sarif` command.

**Impact:** All enterprise reporting features (Reqs 13, 15) have no CLI entry point.

**Fix:** Create `sicario-cli/src/cli/report.rs` with `ReportArgs` and `ReportAction` enum covering `compliance`, `mttr`, and `sarif` subcommands. Wire into `main.rs`. This is already planned in Phase 6 of tasks.md.

---

### 7.10 `sicario policy` Command Missing (HIGH)

**File:** `sicario-cli/src/cli/` — no `policy.rs` exists

**Current state:** No policy enforcement module exists. The `policy/` directory does not exist.

**Fix:** Create `sicario-cli/src/policy/` and `sicario-cli/src/cli/policy.rs` as described in Area 6.2. Wire into `main.rs`. Already planned in Phase 7 of tasks.md.

---

### 7.11 `sicario suppressions audit` Subcommand Missing (HIGH)

**File:** `sicario-cli/src/cli/suppressions.rs`

**Current state:** `SuppressionsAction` has only `List` and `Reset` variants. There is no `Audit` variant.

**Fix:** Add `Audit(SuppressionAuditArgs)` to `SuppressionsAction` and implement `cmd_suppression_audit` as described in Area 6.4. Already planned in Phase 9 of tasks.md.

---

### 7.12 `sicario scan --prove` and `sicario scan --licenses` Flags Missing (HIGH)

**File:** `sicario-cli/src/cli/scan.rs`

**Current state:** Neither `--prove` nor `--licenses` flags exist in `ScanArgs`.

**Fix:** Add both flags to `ScanArgs` and wire them into `cmd_scan` as described in Areas 4 and 6.5. Already planned in Phases 4 and 10 of tasks.md.

---

### 7.13 `sicario hook --install --auto-fix` Flag Missing (HIGH)

**File:** `sicario-cli/src/cli/hook.rs` and `sicario-cli/src/hook/manager.rs`

**Current state:** `HookManager::install()` only installs the standard scan-and-block hook. There is no `--auto-fix` flag and no `install_auto_fix()` method.

**Fix:** Add `--auto-fix` to `HookArgs` and implement `HookManager::install_auto_fix()` as described in Area 3.1. Already planned in Phase 3 of tasks.md.

---

### 7.14 `sicario fix --staged` Flag Missing (HIGH)

**File:** `sicario-cli/src/cli/fix.rs`

**Current state:** `FixArgs` has no `--staged` flag. The `DiffScanner::staged_files()` method is fully implemented in `diff/diff_scanner.rs` but is never called from the fix command.

**Fix:** Add `staged: bool` to `FixArgs` and implement the staged-only fix path in `cmd_fix` as described in Area 3.2. Already planned in Phase 3 of tasks.md.

---

### 7.15 `sicario fix --agent` Flag Missing (HIGH)

**File:** `sicario-cli/src/cli/fix.rs`

**Current state:** `FixArgs` has no `--agent` flag. The existing `LlmClient` always uses the cloud key resolution chain.

**Fix:** Add `agent: Option<String>` to `FixArgs` and implement `AgentSelector` as described in Area 1.1. Already planned in Phase 1 of tasks.md.

---

### 7.16 Ollama Auto-Detection Blocks on Slow Networks (MEDIUM)

**File:** `sicario-cli/src/key_manager/manager.rs` — `spawn_local_llm_detection()`

**Current state:** The detection is spawned on a background thread and joined at step 9 of the resolution chain. However, if the user is on a slow network where `localhost` resolves via DNS (IPv6 → IPv4 fallback), the 500ms timeout can be exceeded by the TCP connection setup alone, causing a noticeable delay before the "No LLM API key configured" error appears.

**Fix:** Use `http://127.0.0.1:11434` (IPv4 loopback) instead of `http://localhost:11434` in both `try_ollama_detection()` and `try_lmstudio_detection()`. The current code already uses `127.0.0.1` for Ollama but the comment says `localhost` — verify and enforce IPv4 in both probes. This is already required by Req 10.1.

---

### 7.17 `PatchReceipt` Not Emitted for Batch Mode Fixes (LOW)

**File:** `sicario-cli/src/main.rs` — `cmd_fix` batch path

**Current state:** `PatchReceipt::print()` is called after single-file fixes but not after batch mode (`--yes` / `--auto`) fixes. The `generate_and_apply_batch` method in `RemediationEngine` applies patches without emitting receipts.

**Fix:** After each successful patch in `generate_and_apply_batch`, emit a `PatchReceipt`. The receipt should be suppressed when `--no-receipt` is set. The `BatchFixDetail` struct should carry enough information to construct the receipt.

---

### 7.18 `sicario baseline diff` Uses `compare` Subcommand Name Instead of `diff` (LOW)

**File:** `sicario-cli/src/cli/baseline.rs`

**Current state:** The existing `BaselineAction::Compare` variant is named `compare` in the CLI (`sicario baseline compare <reference>`). The eta-engine spec and all documentation refer to `sicario baseline diff --ci`. These are different command names for the same concept.

**Fix:** Add `Diff` as a new variant (keeping `Compare` for backward compatibility) with the `--ci` flag and the three-set output format. `Compare` remains as an alias that prints the delta in JSON without CI exit code semantics.

---

### 7.19 `VerificationScanner` Not Wired into `cmd_fix` for Batch Mode (LOW)

**File:** `sicario-cli/src/main.rs` — `cmd_fix`

**Current state:** `VerificationScanner` is used inside `RemediationEngine::generate_and_apply_batch` via `verify_in_memory`, but the standalone `VerificationScanner` in `verification/scanner.rs` is never called from the top-level `cmd_fix` handler for single-file fixes. The `--no-verify` flag is accepted but the verification path for single fixes is not wired.

**Fix:** After applying a single-file patch in `cmd_fix`, call `VerificationScanner::verify_fix` unless `--no-verify` is set. Print a warning if `VerificationResult::StillPresent` or `VerificationResult::NewFindingsIntroduced`.

---

### 7.20 `sicario config set-provider` Does Not Update `llm_endpoint` in `LlmClient` Resolution (LOW)

**File:** `sicario-cli/src/config/global_config.rs` and `sicario-cli/src/key_manager/manager.rs`

**Current state:** `set_global_config_value("llm_endpoint", ...)` writes to `~/.sicario/config.toml` under the `llm_endpoint` key. However, `resolve_endpoint()` in `key_manager/manager.rs` reads from `.sicario/config.yaml` (project-local) via `load_config_file`, not from `~/.sicario/config.toml` (global). The two config files use different keys (`endpoint` vs `llm_endpoint`) and different formats (YAML vs TOML).

**Impact:** `sicario config set-provider anthropic` writes the endpoint to the global TOML config, but `resolve_endpoint()` never reads it. The provider setting is silently ignored.

**Fix:** Update `resolve_endpoint()` to also check `load_global_config().llm_endpoint` as a fallback between the project-local config file (step 4) and the cloud config (step 5). Similarly, update `resolve_model()` to check `load_global_config().llm_model`.

---

## Area 8: Anonymous Usage Telemetry

### 8.1 Objective and Constraints

Count unique codebases running Sicario without violating the zero-exfiltration promise. The system must:

- Fire on every `sicario scan` invocation, regardless of `--publish` flag
- Never transmit usernames, raw repo names, file paths, email addresses, or IP addresses
- Add zero milliseconds of latency to the scan (fully background, fire-and-forget)
- Fail completely silently — no log output, no warning, no panic — in air-gapped environments
- Be opt-out via `SICARIO_NO_TELEMETRY=1` or `sicario_no_telemetry = true` in `~/.sicario/config.toml`

### 8.2 The Project Hash

The project identity is derived from the git remote origin URL. The URL itself is never transmitted.

```rust
fn compute_project_hash() -> Option<String> {
    // Run: git config --get remote.origin.url
    let output = std::process::Command::new("git")
        .args(["config", "--get", "remote.origin.url"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None; // not a git repo or no remote — skip telemetry
    }

    let raw_url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if raw_url.is_empty() {
        return None;
    }

    // Normalize: strip credentials, trailing .git, lowercase
    // e.g. "https://user:token@github.com/org/repo.git" → "github.com/org/repo"
    let normalized = normalize_remote_url(&raw_url);

    // SHA-256 the normalized URL — this is what gets transmitted
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    Some(format!("{:x}", hasher.finalize()))
}

fn normalize_remote_url(url: &str) -> String {
    // Strip scheme and credentials: "https://user:pass@" → ""
    let without_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("git@")
        .trim_start_matches("ssh://git@");

    // Strip credentials: "user:pass@host/path" → "host/path"
    let without_creds = if let Some(at_pos) = without_scheme.find('@') {
        &without_scheme[at_pos + 1..]
    } else {
        without_scheme
    };

    // Normalize git@github.com:org/repo → github.com/org/repo
    let normalized = without_creds.replace(':', "/");

    // Strip trailing .git
    normalized
        .trim_end_matches(".git")
        .to_lowercase()
        .to_string()
}
```

### 8.3 Environment Detection

```rust
fn detect_environment() -> &'static str {
    // Standard CI environment variables
    if std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("GITLAB_CI").is_ok()
        || std::env::var("CIRCLECI").is_ok()
        || std::env::var("TRAVIS").is_ok()
        || std::env::var("JENKINS_URL").is_ok()
        || std::env::var("BUILDKITE").is_ok()
        || std::env::var("DRONE").is_ok()
        || std::env::var("CI").is_ok()
    {
        "ci"
    } else {
        "local"
    }
}
```

### 8.4 Payload and Endpoint

The payload is minimal by design:

```json
{
  "event": "scan_run",
  "environment": "ci",
  "project_hash": "a3f8c2d1e4b7...",
  "cli_version": "0.9.0"
}
```

`cli_version` is included so we can track adoption of v2 vs v1 without any user identity. It is read from `env!("CARGO_PKG_VERSION")` at compile time.

**Endpoint:** `POST https://flexible-terrier-680.convex.site/api/v1/usage` (new route, no auth required — the payload contains no secrets).

The endpoint is resolved via `resolve_cloud_url()` (existing function in `publish/client.rs`) so it respects the `SICARIO_CLOUD_URL` env var override.

### 8.5 Rust Implementation

New module: `sicario-cli/src/usage_telemetry/mod.rs`

```rust
/// Fire-and-forget anonymous usage ping. Spawns a background thread.
/// Returns immediately — never blocks the scan.
pub fn fire_usage_ping() {
    // Opt-out check
    if std::env::var("SICARIO_NO_TELEMETRY").is_ok() {
        return;
    }
    if let Some(cfg) = crate::config::load_global_config() {
        if cfg.no_telemetry.unwrap_or(false) {
            return;
        }
    }

    std::thread::spawn(|| {
        // All errors are swallowed — this must never surface to the user
        let _ = send_usage_ping();
    });
}

fn send_usage_ping() -> Option<()> {
    let project_hash = compute_project_hash()?; // None = no git remote, skip
    let environment = detect_environment();
    let cli_version = env!("CARGO_PKG_VERSION");

    let payload = serde_json::json!({
        "event": "scan_run",
        "environment": environment,
        "project_hash": project_hash,
        "cli_version": cli_version,
    });

    let base_url = crate::publish::resolve_cloud_url();
    let url = format!("{}/api/v1/usage", base_url.trim_end_matches('/'));

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    // Fire and forget — ignore the response entirely
    let _ = client.post(&url).json(&payload).send();

    Some(())
}
```

The `std::thread::spawn` returns immediately. The background thread has a 5-second timeout on the HTTP request. If the request fails for any reason (network error, DNS failure, timeout, non-200 response), the error is discarded via `let _ = ...`. The scan process is completely unaffected.

### 8.6 Call Site

In `cmd_scan` in `main.rs`, add a single line at the very start of the function, before any scan work begins:

```rust
fn cmd_scan(args: cli::scan::ScanArgs) -> Result<ExitCode> {
    // Fire anonymous usage ping in background — zero latency, fails silently
    crate::usage_telemetry::fire_usage_ping();

    // ... rest of cmd_scan unchanged
}
```

### 8.7 Convex Backend Endpoint

New route in `convex/convex/http.ts`:

```typescript
// POST /api/v1/usage — Anonymous usage ping (no auth required)
http.route({
  path: "/api/v1/usage",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    try {
      const body = await request.json();

      // Validate: only accept known event types
      if (body.event !== "scan_run") {
        return new Response(null, { status: 204 });
      }

      // Validate project_hash is a 64-char hex string (SHA-256)
      const projectHash = body.project_hash;
      if (typeof projectHash !== "string" || !/^[0-9a-f]{64}$/.test(projectHash)) {
        return new Response(null, { status: 204 }); // silently ignore malformed
      }

      const environment = body.environment === "ci" ? "ci" : "local";
      const cliVersion = typeof body.cli_version === "string" ? body.cli_version : "unknown";

      await ctx.runMutation(api.usagePings.record, {
        projectHash,
        environment,
        cliVersion,
        receivedAt: new Date().toISOString(),
      });

      return new Response(null, { status: 204 });
    } catch {
      // Never return an error — the CLI must not see failures
      return new Response(null, { status: 204 });
    }
  }),
});
```

Always returns HTTP 204 (no content), even on errors. The CLI ignores the response entirely.

### 8.8 Convex Schema Addition

New table in `convex/convex/schema.ts`:

```typescript
usagePings: defineTable({
  projectHash:  v.string(),   // SHA-256 of normalized remote URL
  environment:  v.union(v.literal("ci"), v.literal("local")),
  cliVersion:   v.string(),
  receivedAt:   v.string(),   // ISO-8601
}).index("by_projectHash", ["projectHash"])
  .index("by_receivedAt",  ["receivedAt"]),
```

New mutation in `convex/convex/usagePings.ts`:

```typescript
export const record = mutation({
  args: {
    projectHash: v.string(),
    environment: v.union(v.literal("ci"), v.literal("local")),
    cliVersion:  v.string(),
    receivedAt:  v.string(),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert("usagePings", args);
  },
});
```

Unique project count is computed by querying `SELECT COUNT(DISTINCT project_hash)` — the dashboard can show "N unique codebases running Sicario" without ever knowing what those codebases are.

### 8.9 `GlobalConfig` Addition

Add `no_telemetry: Option<bool>` to `GlobalConfig` in `sicario-cli/src/config/global_config.rs`:

```rust
pub struct GlobalConfig {
    // ... existing fields ...
    /// Opt out of anonymous usage telemetry.
    /// Equivalent to setting SICARIO_NO_TELEMETRY=1.
    pub no_telemetry: Option<bool>,
}
```

`sicario config set no_telemetry true` writes this field. The `set_global_config_value` function is updated to handle the `"no_telemetry"` key.

---

## Area 9: Dynamic Terminal Notification System

### 9.1 Objective and Design Principles

Broadcast critical updates (v2 Beta launch, breaking changes, security advisories) directly to the terminal where developers run Sicario. The system must:

- Never block or slow down the scan
- Never show the same notification twice to the same user
- Be dismissible and respect developer attention
- Degrade gracefully when offline
- Never transmit user identity to fetch notifications

### 9.2 Notification Fetch Flow

```
sicario scan starts
  │
  ├─ spawn background thread ──────────────────────────────────────────────────┐
  │                                                                             │
  │   GET /api/v1/notifications?cli_version=0.9.0&since=<last_seen_ts>        │
  │   (no auth, no user identity)                                              │
  │                                                                             │
  │   Response: [{ id, message, severity, min_version, max_version, url }]    │
  │                                                                             │
  │   Filter: only show notifications where:                                   │
  │     - id not in ~/.sicario/seen_notifications.json                         │
  │     - min_version <= current_version <= max_version (semver)               │
  │                                                                             │
  │   Write filtered notifications to a shared channel                         │
  └─────────────────────────────────────────────────────────────────────────────┘
  │
  scan runs (unaffected)
  │
  scan output printed
  │
  ├─ drain notification channel (non-blocking)
  │   if notifications present:
  │     print separator + notification box
  │     append id to ~/.sicario/seen_notifications.json
  └─
```

Notifications are printed **after** scan output, never before or during. The developer sees their scan results first.

### 9.3 Notification Data Model

**Server-side** (Convex `notifications` table):

```typescript
notifications: defineTable({
  notificationId: v.string(),   // stable slug, e.g. "v2-beta-launch"
  message:        v.string(),   // max 200 chars, plain text
  severity:       v.union(
    v.literal("info"),          // blue — general announcements
    v.literal("warning"),       // yellow — deprecations, breaking changes
    v.literal("critical"),      // red — security advisories
  ),
  minVersion:     v.optional(v.string()),  // semver, e.g. "0.8.0"
  maxVersion:     v.optional(v.string()),  // semver, e.g. "0.9.99"
  url:            v.optional(v.string()),  // optional "learn more" link
  activeFrom:     v.string(),   // ISO-8601 — when to start showing
  activeTo:       v.optional(v.string()),  // ISO-8601 — when to stop (null = permanent)
  enabled:        v.boolean(),
}).index("by_enabled_activeFrom", ["enabled", "activeFrom"]),
```

**CLI-side** (`Notification` struct):

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct Notification {
    pub id: String,
    pub message: String,
    pub severity: NotificationSeverity,
    pub min_version: Option<String>,
    pub max_version: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NotificationSeverity {
    Info,
    Warning,
    Critical,
}
```

### 9.4 Convex Backend Endpoint

New route in `convex/convex/http.ts`:

```typescript
// GET /api/v1/notifications — Fetch active notifications (no auth)
http.route({
  path: "/api/v1/notifications",
  method: "GET",
  handler: httpAction(async (ctx, request) => {
    try {
      const url = new URL(request.url);
      const cliVersion = url.searchParams.get("cli_version") ?? "0.0.0";

      const now = new Date().toISOString();
      const active = await ctx.runQuery(api.notifications.listActive, { now });

      // Filter by version range server-side as well (defense in depth)
      const filtered = active.filter((n: any) => {
        if (n.minVersion && semverLt(cliVersion, n.minVersion)) return false;
        if (n.maxVersion && semverGt(cliVersion, n.maxVersion)) return false;
        return true;
      });

      const payload = filtered.map((n: any) => ({
        id:          n.notificationId,
        message:     n.message,
        severity:    n.severity,
        min_version: n.minVersion ?? null,
        max_version: n.maxVersion ?? null,
        url:         n.url ?? null,
      }));

      return new Response(JSON.stringify(payload), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    } catch {
      return new Response("[]", {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }
  }),
});
```

Always returns HTTP 200 with a JSON array (empty array on error). The CLI never sees a failure.

### 9.5 Seen-Notification Persistence

Seen notification IDs are stored in `~/.sicario/seen_notifications.json` as a simple JSON array of strings:

```json
["v2-beta-launch", "breaking-change-0.9.0"]
```

The file is read before displaying and written after displaying. If the file cannot be read or written (permissions, disk full), the error is silently swallowed — the notification is shown again next time rather than crashing.

### 9.6 Rust Implementation

New module: `sicario-cli/src/notifications/mod.rs`

```rust
use std::sync::mpsc;

/// Spawn the notification fetch in a background thread.
/// Returns a Receiver that yields notifications after the scan completes.
/// The receiver is non-blocking — drain it with try_recv.
pub fn spawn_notification_fetch() -> mpsc::Receiver<Vec<Notification>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(fetch_notifications());
    });
    rx
}

fn fetch_notifications() -> Vec<Notification> {
    let cli_version = env!("CARGO_PKG_VERSION");
    let base_url = crate::publish::resolve_cloud_url();
    let url = format!(
        "{}/api/v1/notifications?cli_version={}",
        base_url.trim_end_matches('/'),
        cli_version
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()
        .unwrap_or_default();

    let resp = match client.get(&url).send() {
        Ok(r) if r.status().is_success() => r,
        _ => return vec![],
    };

    let all: Vec<Notification> = match resp.json() {
        Ok(n) => n,
        Err(_) => return vec![],
    };

    // Filter by version range
    let current = semver::Version::parse(cli_version).ok();
    let seen = load_seen_ids();

    all.into_iter()
        .filter(|n| !seen.contains(&n.id))
        .filter(|n| {
            if let (Some(cur), Some(min)) = (&current, &n.min_version) {
                if let Ok(min_v) = semver::Version::parse(min) {
                    if cur < &min_v { return false; }
                }
            }
            if let (Some(cur), Some(max)) = (&current, &n.max_version) {
                if let Ok(max_v) = semver::Version::parse(max) {
                    if cur > &max_v { return false; }
                }
            }
            true
        })
        .collect()
}
```

### 9.7 Terminal Rendering

Notifications are printed after scan output using `owo-colors` (already a dependency):

```rust
pub fn print_notifications(notifications: &[Notification]) {
    if notifications.is_empty() {
        return;
    }

    eprintln!(); // blank line separator from scan output

    for n in notifications {
        let (prefix, color_fn): (&str, fn(&str) -> String) = match n.severity {
            NotificationSeverity::Info     => ("ℹ", |s| s.blue().to_string()),
            NotificationSeverity::Warning  => ("⚠", |s| s.yellow().to_string()),
            NotificationSeverity::Critical => ("✖", |s| s.red().bold().to_string()),
        };

        eprintln!("{} {}", color_fn(prefix), color_fn(&n.message));
        if let Some(url) = &n.url {
            eprintln!("  → {}", url);
        }
    }
}
```

Output goes to `stderr` so it never corrupts `--format json` or `--format sarif` output on `stdout`.

### 9.8 Call Site in `cmd_scan`

```rust
fn cmd_scan(args: cli::scan::ScanArgs) -> Result<ExitCode> {
    // Fire anonymous usage ping (background, zero latency)
    crate::usage_telemetry::fire_usage_ping();

    // Spawn notification fetch (background, zero latency)
    let notification_rx = crate::notifications::spawn_notification_fetch();

    // ... scan runs normally ...

    // After all scan output is printed, drain notifications
    if !args.quiet {
        if let Ok(notifications) = notification_rx.try_recv() {
            crate::notifications::print_notifications(&notifications);
            crate::notifications::mark_seen(&notifications);
        }
    }

    Ok(exit_code)
}
```

`--quiet` suppresses notifications entirely, consistent with its existing behavior of suppressing all non-result output.

### 9.9 `mark_seen` Implementation

```rust
pub fn mark_seen(notifications: &[Notification]) {
    if notifications.is_empty() {
        return;
    }
    // Silently swallow all errors — never crash over notification bookkeeping
    let _ = (|| -> Option<()> {
        let path = seen_notifications_path()?;
        let mut seen = load_seen_ids();
        for n in notifications {
            seen.insert(n.id.clone());
        }
        let json = serde_json::to_string(&seen.into_iter().collect::<Vec<_>>()).ok()?;
        std::fs::write(&path, json).ok()?;
        Some(())
    })();
}

fn seen_notifications_path() -> Option<std::path::PathBuf> {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    Some(std::path::PathBuf::from(home)
        .join(".sicario")
        .join("seen_notifications.json"))
}

fn load_seen_ids() -> std::collections::HashSet<String> {
    seen_notifications_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
        .map(|v| v.into_iter().collect())
        .unwrap_or_default()
}
```

### 9.10 Admin Interface

Notifications are managed via a new Convex mutation `notifications.create` callable from the Sicario dashboard (admin-only). The dashboard shows a simple form: message, severity, version range, active dates. No CLI tooling is needed for notification management.

### 9.11 Zero-Exfiltration Guarantee

The notification fetch sends only `cli_version` as a query parameter — a public version string with no user identity. No project hash, no file paths, no usernames. The server returns the same response to all callers with the same version. The endpoint requires no authentication.

---

## Area 10: Zero-Exfil Power Features

### Feasibility Assessment

Before the design, an honest 7-day build estimate for each feature:

| Feature | 7-day verdict | Rationale |
|---------|--------------|-----------|
| Cross-Boundary Taint Analysis | **Yes — scoped** | `ReachabilityAnalyzer` already builds a call graph and runs BFS. The gap is: cross-file edge resolution, a human-readable trace renderer, and wiring it to `sicario scan --trace`. Estimated: 3–4 days. |
| Git Exorcist | **Yes — scoped** | `git2` is already a dependency. The hard part is the AST-level secret replacement (reuse existing `PatchTemplate` infrastructure) and the safe history rewrite (interactive rebase equivalent via `git2`). Estimated: 3–4 days. |
| NLP-to-AST Rule Compiler | **Yes — scoped** | The Ollama client is being built in Phase 1. The compiler is a structured prompt → tree-sitter query string → `validate_and_compile_rule` pipeline. The hard part is the validation loop. Estimated: 2–3 days. |

All three are buildable in 7 days if scoped correctly. The scoping decisions are documented below.

---

### 10.1 Cross-Boundary Taint Analysis (`sicario scan --trace`)

#### What already exists

`sicario-cli/src/engine/reachability.rs` already implements:
- `CallGraph` — directed graph of `FunctionNode` structs with `calls`/`called_by` edges
- `ReachabilityAnalyzer::build_call_graph(&[PathBuf])` — two-pass extraction (function defs, then call edges) across all files using tree-sitter
- `ReachabilityAnalyzer::is_reachable(&Vulnerability)` — BFS from taint sources to the vulnerable function
- `default_taint_sources()` — framework-specific patterns for Django, FastAPI, React, fetch/axios, `process.env`

#### What is missing

1. **Cross-file call edge resolution** — the current pass 2 only wires edges where both caller and callee are in the same file. The `find_function` lookup needs to search all files.
2. **Trace path extraction** — `bfs_path` exists but is never called from the scan output pipeline.
3. **Human-readable trace renderer** — no terminal output for the path.
4. **`--trace` flag** — not in `ScanArgs`.
5. **`dataflow_trace` field population** — `Finding::dataflow_trace` exists but is never populated.

#### Design

**Cross-file edge resolution** — the existing pass 2 already searches all nodes (`self.call_graph.nodes.values().find(|n| n.name == callee_name)`). The gap is that this only matches by function name, not by import resolution. For v2, we use name-based matching with a confidence filter: if a callee name matches exactly one function across all files, wire the edge. If it matches zero or multiple, skip (conservative). This covers the 80% case (unique function names) without requiring a full module resolver.

**`TaintTrace` struct** — new struct in `reachability.rs`:

```rust
pub struct TaintTrace {
    /// Ordered list of steps from source to sink
    pub steps: Vec<TaintTraceStep>,
    /// The vulnerability at the sink
    pub sink_rule_id: String,
    pub sink_file: PathBuf,
    pub sink_line: usize,
}

pub struct TaintTraceStep {
    pub file: PathBuf,
    pub line: usize,
    pub function_name: String,
    pub description: String,  // e.g. "HTTP request parameter enters here"
}
```

**`ReachabilityAnalyzer::trace_to_vulnerability`** — new method:

```rust
pub fn trace_to_vulnerability(&self, vuln: &Vulnerability) -> Option<TaintTrace> {
    let vuln_fn_id = find_enclosing_function(&vuln.file_path, vuln.line, &self.call_graph)?;

    // Try each taint source; return the first path found
    for source_id in self.call_graph.taint_source_ids() {
        if let Some(path) = self.bfs_path(source_id, vuln_fn_id) {
            let steps = path.iter().map(|id| {
                let node = &self.call_graph.nodes[id];
                TaintTraceStep {
                    file: node.file_path.clone(),
                    line: node.line,
                    function_name: node.name.clone(),
                    description: if node.is_taint_source {
                        "External input enters here".to_string()
                    } else {
                        format!("Tainted data flows through `{}`", node.name)
                    },
                }
            }).collect();

            return Some(TaintTrace {
                steps,
                sink_rule_id: vuln.rule_id.clone(),
                sink_file: vuln.file_path.clone(),
                sink_line: vuln.line,
            });
        }
    }
    None
}
```

**Terminal renderer** — `TaintTrace::render()` produces the "attack path map":

```
  ┌─ TAINT TRACE: sql-injection in src/db/queries.js:42 ─────────────────────┐
  │                                                                            │
  │  [1] src/routes/user.js:12  handleUserRequest()                           │
  │      ↳ HTTP request parameter enters here                                 │
  │                                                                            │
  │  [2] src/services/user.js:34  getUserById()                               │
  │      ↳ Tainted data flows through `getUserById`                           │
  │                                                                            │
  │  [3] src/db/queries.js:42  buildQuery()  ← SINK                          │
  │      ↳ Tainted value reaches SQL query construction                       │
  │                                                                            │
  │  Attack vector: 3 functions across 3 files                                │
  └────────────────────────────────────────────────────────────────────────────┘
```

**`--trace` flag** — added to `ScanArgs`. When set, `cmd_scan` calls `scan_directory_with_reachability` (already exists) and then calls `trace_to_vulnerability` for each finding above the severity threshold. Traces are printed after the standard finding output. With `--format json`, traces are included in the `dataflow_trace` field of each finding.

**Performance target** — the call graph build adds at most 500ms for a 10,000-file codebase. The BFS per finding is O(V+E) and completes in <10ms per finding. Total overhead for 50 findings: <1 second.

**Scope limit** — v2 supports JS/TS and Python only. Go, Java, Rust traces are deferred. The renderer shows "Trace not available for this language" for unsupported languages rather than failing.

---

### 10.2 Git Exorcist (`sicario exorcise`)

#### What already exists

- `git2` crate is a workspace dependency (vendored libgit2, no OpenSSL)
- `BackupManager` — creates timestamped backups before any file modification
- `PatchTemplate` / `TemplateRegistry` — deterministic AST-level fixes including `HardcodedCredsTemplate` which already replaces hardcoded secrets with `process.env.X`
- `SecretScanner` — already detects hardcoded secrets in source files

#### What is missing

1. `sicario exorcise` command — no CLI entry point
2. Git history rewrite — no `git2`-based commit rewriting
3. Safe pre-flight checks — no validation before rewriting

#### Design

**Command:** `sicario exorcise [--dry-run] [--since <ref>]`

**Pre-flight checks (all must pass before any rewrite):**
1. Working tree is clean (`git status --porcelain` returns empty) — refuse if uncommitted changes exist
2. No upstream tracking branch has been pushed to (`git log @{u}..HEAD` returns commits) — refuse if commits have already been pushed
3. At least one secret is detected in the commit range — refuse if nothing to fix

The `--since <ref>` flag limits the rewrite to commits after the given ref (default: all local commits not yet pushed, i.e. `@{u}..HEAD`).

**Rewrite algorithm:**

```
1. Enumerate commits in range (oldest first) via git2 revwalk
2. For each commit:
   a. Checkout the commit's tree into a temp directory
   b. Run SecretScanner on the temp directory
   c. For each secret found, apply the matching PatchTemplate (HardcodedCredsTemplate)
      to replace the hardcoded value with process.env.VAR_NAME
   d. Write the patched files back
   e. Create a new tree object from the patched files
   f. Create a new commit with the same metadata (author, timestamp, message)
      but pointing to the new tree and the rewritten parent
3. Update HEAD to point to the final rewritten commit
4. Print a receipt showing: N commits rewritten, M secrets removed, replacement env var names
```

**`git2` implementation sketch:**

```rust
pub struct GitExorcist {
    repo: git2::Repository,
    backup_manager: BackupManager,
}

impl GitExorcist {
    pub fn exorcise(&self, since_ref: Option<&str>, dry_run: bool) -> Result<ExorcistReceipt> {
        // Pre-flight: clean working tree
        let statuses = self.repo.statuses(None)?;
        if !statuses.is_empty() {
            anyhow::bail!("Working tree has uncommitted changes. Commit or stash them first.");
        }

        // Pre-flight: not yet pushed
        let unpushed = self.count_unpushed_commits()?;
        if unpushed == 0 {
            anyhow::bail!("No local-only commits found. All commits have been pushed.");
        }

        // Collect commits to rewrite (oldest first)
        let commits = self.collect_commits_to_rewrite(since_ref)?;

        if dry_run {
            return self.dry_run_report(&commits);
        }

        // Rewrite each commit
        let mut parent_id: Option<git2::Oid> = self.find_base_commit(since_ref)?;
        let mut secrets_removed = 0;

        for commit_oid in &commits {
            let (new_oid, count) = self.rewrite_commit(*commit_oid, parent_id)?;
            parent_id = Some(new_oid);
            secrets_removed += count;
        }

        // Update HEAD
        if let Some(final_oid) = parent_id {
            self.repo.head()?.set_target(final_oid, "sicario exorcise")?;
        }

        Ok(ExorcistReceipt {
            commits_rewritten: commits.len(),
            secrets_removed,
        })
    }

    fn rewrite_commit(
        &self,
        commit_oid: git2::Oid,
        new_parent: Option<git2::Oid>,
    ) -> Result<(git2::Oid, usize)> {
        let commit = self.repo.find_commit(commit_oid)?;
        let tree = commit.tree()?;

        // Write tree to temp dir, apply patches, build new tree
        let temp = tempfile::tempdir()?;
        self.checkout_tree_to_dir(&tree, temp.path())?;

        // Scan for secrets
        let secrets = scan_for_secrets(temp.path())?;
        let mut secrets_removed = 0;

        for secret in &secrets {
            if let Some(patched) = apply_secret_patch(secret, temp.path())? {
                write_patched_file(&patched, temp.path())?;
                secrets_removed += 1;
            }
        }

        // Build new git tree from patched files
        let new_tree_oid = self.build_tree_from_dir(temp.path(), &tree)?;
        let new_tree = self.repo.find_tree(new_tree_oid)?;

        // Create new commit with same metadata
        let parents: Vec<git2::Commit> = match new_parent {
            Some(p) => vec![self.repo.find_commit(p)?],
            None => vec![],
        };
        let parent_refs: Vec<&git2::Commit> = parents.iter().collect();

        let new_oid = self.repo.commit(
            None, // don't update any ref yet
            &commit.author(),
            &commit.committer(),
            commit.message().unwrap_or(""),
            &new_tree,
            &parent_refs,
        )?;

        Ok((new_oid, secrets_removed))
    }
}
```

**Receipt output:**

```
╔══════════════════════════════════════════════════════╗
║              SICARIO GIT EXORCIST RECEIPT            ║
╠══════════════════════════════════════════════════════╣
║  Commits rewritten    3                              ║
║  Secrets removed      2                              ║
╠══════════════════════════════════════════════════════╣
║  AWS_ACCESS_KEY_ID    → process.env.AWS_ACCESS_KEY_ID║
║  DATABASE_PASSWORD    → process.env.DATABASE_PASSWORD║
╠══════════════════════════════════════════════════════╣
║  Tokens Burned        0                              ║
║  Lines Exfiltrated    0                              ║
╚══════════════════════════════════════════════════════╝

⚠  History has been rewritten. If you have collaborators,
   coordinate before force-pushing: git push --force-with-lease
```

**`--dry-run` mode** — scans the commit range and prints what would be changed without touching the git history. Safe to run at any time.

**Scope limits:**
- Only rewrites local, unpushed commits. Refuses to touch pushed history.
- Only supports JS/TS and Python secret patterns (the languages with the most complete `PatchTemplate` coverage).
- Maximum 50 commits in the rewrite range. Refuses with a descriptive error if the range is larger.
- Does not handle merge commits (skips them with a warning).

---

### 10.3 NLP-to-AST Rule Compiler (`sicario rule "<description>"`)

#### What already exists

- `OllamaClient` — being built in Phase 1 with `AuthStyle::None`, `temperature: 0.0`, `max_tokens: 512`
- `SastEngine::validate_and_compile_rule` — compiles a `SecurityRule` struct and rejects invalid tree-sitter queries
- `TemplateRegistry` — rule registration infrastructure
- `--rules-dir` flag — loads YAML rules from a directory

#### What is missing

1. `sicario rule` command — no CLI entry point
2. NLP → tree-sitter query prompt — no prompt template
3. Validation loop — no retry on invalid query
4. Rule persistence — no mechanism to save generated rules to `.sicario/rules/`

#### Design

**Command:** `sicario rule "<natural language description>" [--lang <language>] [--severity <level>] [--dry-run]`

**Examples:**
```
sicario rule "Prevent any console.log that contains a variable named 'token' or 'password'"
sicario rule "Flag any use of MD5 in the auth module" --lang python --severity high
sicario rule "Detect when req.body is passed directly to a database query" --lang javascript
```

**Prompt architecture** — the NLP compiler uses a two-stage prompt:

**Stage 1 — Intent extraction** (structured JSON output):
```
System: "You are a security rule compiler. Extract the intent from the description and return ONLY a JSON object:
{
  \"target_construct\": \"<what AST node to match>\",
  \"condition\": \"<what property makes it dangerous>\",
  \"language\": \"<javascript|typescript|python|rust|go|java>\",
  \"cwe\": \"<CWE number if applicable, else null>\"
}"

User: "Prevent any console.log that contains a variable named 'token' or 'password'"
```

**Stage 2 — Query generation** (tree-sitter query string):
```
System: "You are a tree-sitter query expert. Generate a valid tree-sitter query for the following intent.
Return ONLY the query string, no explanation, no markdown fences.
The query must use capture names starting with @.
Language: JavaScript
Tree-sitter node types for JavaScript: call_expression, member_expression, identifier, string, arguments, ..."

User: "Match: call_expression where function is console.log and arguments contain an identifier named 'token' or 'password'"
```

**Validation loop** — up to 3 attempts:

```rust
pub fn compile_rule_from_nlp(
    description: &str,
    language: Language,
    ollama: &OllamaClient,
    engine: &mut SastEngine,
) -> Result<SecurityRule> {
    // Stage 1: extract intent
    let intent = extract_intent(description, language, ollama)?;

    // Stage 2: generate query with retry
    let mut last_error = String::new();
    for attempt in 1..=3 {
        let query_str = generate_query(&intent, language, ollama, &last_error)?;

        // Validate by attempting to compile
        let test_rule = SecurityRule {
            id: format!("custom/{}", slugify(description)),
            name: description.to_string(),
            description: description.to_string(),
            severity: Severity::High,
            languages: vec![language],
            pattern: QueryPattern { query: query_str.clone(), captures: vec![] },
            fix_template: None,
            cwe_id: intent.cwe.clone(),
            owasp_category: None,
            help_uri: None,
            test_cases: None,
        };

        match engine.validate_and_compile_rule(test_rule.clone()) {
            Ok(_) => return Ok(test_rule),
            Err(e) => {
                last_error = format!("Attempt {attempt} failed: {e}. Fix the query syntax.");
                eprintln!("[sicario] Query attempt {attempt}/3 failed: {e}");
            }
        }
    }

    anyhow::bail!("Failed to generate a valid tree-sitter query after 3 attempts. Try rephrasing the description.")
}
```

**Rule persistence** — on success, the rule is written to `.sicario/rules/<slug>.yaml`:

```yaml
- id: "custom/no-console-log-token"
  name: "Prevent console.log with token/password variable"
  description: "Prevent any console.log that contains a variable named 'token' or 'password'"
  severity: High
  languages:
    - JavaScript
  pattern:
    query: |
      (call_expression
        function: (member_expression
          object: (identifier) @obj (#eq? @obj "console")
          property: (property_identifier) @prop (#eq? @prop "log"))
        arguments: (arguments
          (identifier) @arg (#match? @arg "^(token|password)$"))) @call
    captures:
      - "call"
```

The `.sicario/rules/` directory is automatically added to the scan path on subsequent `sicario scan` invocations (loaded via `--rules-dir .sicario/rules` implicitly when the directory exists).

**`--dry-run` mode** — generates the query and prints it without saving or registering it. Lets the user inspect the generated query before committing.

**Terminal output on success:**

```
[sicario] Compiling rule from: "Prevent any console.log that contains a variable named 'token' or 'password'"
[sicario] Stage 1: Extracting intent... done
[sicario] Stage 2: Generating tree-sitter query (attempt 1/3)... done
[sicario] Validating query against JavaScript grammar... ✓

Rule compiled and saved to .sicario/rules/no-console-log-token.yaml

  ID:        custom/no-console-log-token
  Language:  JavaScript
  Severity:  High
  Query:     (call_expression function: (member_expression ...) ...) @call

Run `sicario scan` to apply the new rule.
```

**Scope limits:**
- Requires a running Ollama instance (same as `--agent=local`). Prints the standard Ollama setup instructions if not available.
- Supports JS/TS and Python in v2. Go, Java, Rust deferred.
- Maximum description length: 200 characters.
- Generated rules are tagged `custom/` to distinguish them from built-in rules.
- The `--dry-run` flag never writes to disk and never modifies the engine.

---

## Area 11: The Shadow Pen-Tester (`sicario attack --local`)

### 11.1 Feasibility Assessment

**7-day verdict: Yes — scoped.**

The `PocGenerator` (Phase 4) already extracts route metadata and generates targeted payloads for SQL injection, SSRF, command injection, and path traversal. The `ReachabilityAnalyzer` already knows the shape of every function's inputs. The gap is: a local HTTP client that fires the payloads at a running dev server, captures the response, and maps the result back to the AST node. Estimated: 3–4 days.

**What this is not:** a full fuzzer. It does not generate random mutations. It generates a small, precise set of AST-guided payloads — one per vulnerability class per endpoint — and fires them. The WTF factor comes from the precision, not the volume.

### 11.2 Architecture

```
sicario attack --local --target http://localhost:3000
  │
  ├─ Phase 1: AST Input Shape Extraction (reuses ReachabilityAnalyzer)
  │   For each route handler found in the codebase:
  │     - Extract HTTP method, path, and parameter names from AST
  │     - Classify each parameter as: path param, query param, body field, header
  │     - Determine expected type: string, number, boolean, object
  │
  ├─ Phase 2: Payload Generation (reuses PocGenerator)
  │   For each finding from sicario scan:
  │     - Generate a targeted malicious payload for the vulnerability class
  │     - Bind the payload to the specific parameter at the specific route
  │     - Generate a benign baseline request for comparison
  │
  ├─ Phase 3: Local HTTP Execution
  │   For each (route, payload) pair:
  │     - Fire the benign baseline request → record response time and status
  │     - Fire the malicious payload → record response time, status, body
  │     - Compare: timing delta > 4s → time-based injection confirmed
  │                status 500 → crash confirmed (stack trace captured)
  │                response body contains payload echo → reflection confirmed
  │
  └─ Phase 4: Result Mapping and Auto-Patch
      For each confirmed vulnerability:
        - Map the HTTP response back to the AST node via route → function → line
        - Print the attack receipt
        - Offer to apply the deterministic patch (same as sicario fix)
```

### 11.3 Route Extraction

New struct `RouteExtractor` in `sicario-cli/src/attack/route_extractor.rs`:

```rust
pub struct ExtractedRoute {
    pub method: HttpMethod,          // GET, POST, PUT, DELETE, PATCH
    pub path: String,                // e.g. "/api/users/:id"
    pub handler_file: PathBuf,
    pub handler_line: usize,
    pub handler_function: String,
    pub parameters: Vec<RouteParameter>,
}

pub struct RouteParameter {
    pub name: String,
    pub location: ParamLocation,     // Path, Query, Body, Header
    pub inferred_type: ParamType,    // String, Number, Boolean, Object
}
```

**Framework detection** — tree-sitter queries for:

| Framework | Pattern | Example |
|-----------|---------|---------|
| Express.js | `app.get('/path', handler)` | `(call_expression function: (member_expression property: (property_identifier) @method (#match? @method "^(get|post|put|delete|patch)$")))` |
| FastAPI | `@app.get('/path')` decorator | `(decorator (call function: (attribute property: (identifier) @method)))` |
| Flask | `@app.route('/path', methods=['GET'])` | `(decorator (call function: (attribute property: (identifier) @route)))` |

**Parameter extraction** — for each route handler, extract:
- Path parameters: `:id`, `<int:user_id>` patterns in the route string
- Query parameters: `req.query.X` (Express), `request.args.get('X')` (Flask/Django)
- Body fields: `req.body.X` (Express), `request.json.get('X')` (FastAPI)

### 11.4 Payload Generation

Reuses `PocGenerator` from Phase 4 with one addition: payloads are bound to specific HTTP parameters rather than printed as standalone `curl` commands.

**Payload types per vulnerability class:**

| CWE | Payload | Detection method |
|-----|---------|-----------------|
| 89 (SQL injection) | `' OR SLEEP(5)--` (MySQL), `'; SELECT pg_sleep(5)--` (PostgreSQL) | Response time > 4 seconds |
| 78 (Command injection) | `; sleep 4` | Response time > 4 seconds |
| 22 (Path traversal) | `../../../../etc/hostname` | Response body contains hostname |
| 79 (XSS) | `<script>sicario_xss_probe_${timestamp}</script>` | Response body contains probe string |
| 918 (SSRF) | `http://127.0.0.1:${probe_port}/ssrf-probe` | `SsrfProbeListener` receives connection |

**Safety enforcement** (same as PocGenerator, enforced in Rust):
- All payloads target `localhost` only
- No destructive SQL (`DROP`, `DELETE`, `TRUNCATE`, `UPDATE`, `INSERT`, `ALTER`)
- No real external URLs

### 11.5 HTTP Execution Engine

New struct `LocalAttackRunner` in `sicario-cli/src/attack/runner.rs`:

```rust
pub struct AttackResult {
    pub route: ExtractedRoute,
    pub payload: AttackPayload,
    pub confirmed: bool,
    pub detection_method: DetectionMethod,
    pub response_time_ms: u64,
    pub baseline_time_ms: u64,
    pub status_code: u16,
    pub response_snippet: String,   // first 200 chars of response body
    pub mapped_finding: Option<Vulnerability>,
}

pub enum DetectionMethod {
    TimingDelta { delta_ms: u64 },
    StatusCode500 { body_snippet: String },
    ReflectionDetected { probe: String },
    SsrfProbeReceived,
}
```

**Timing threshold:** response time > baseline + 4,000ms = confirmed time-based injection. The 4-second threshold (not 5) accounts for network jitter on localhost.

**Concurrency:** attacks fire sequentially per route, not in parallel. Parallel attacks against a local dev server would produce unreliable timing measurements and could crash the server in ways that mask individual vulnerabilities.

**Timeout:** each request has a 10-second timeout. If the server doesn't respond within 10 seconds, the attack is marked as inconclusive.

### 11.6 Attack Receipt

```
╔══════════════════════════════════════════════════════════════╗
║              SICARIO SHADOW PEN-TESTER RECEIPT               ║
╠══════════════════════════════════════════════════════════════╣
║  Target         http://localhost:3000                        ║
║  Routes tested  12                                           ║
║  Payloads fired 47                                           ║
╠══════════════════════════════════════════════════════════════╣
║  ✖ CONFIRMED: SQL Injection                                  ║
║    Route:    POST /api/users/search                          ║
║    Param:    body.query                                      ║
║    Method:   Timing delta (4,823ms vs 12ms baseline)         ║
║    AST node: src/routes/users.js:34 buildSearchQuery()       ║
╠══════════════════════════════════════════════════════════════╣
║  Tokens Burned        0                                      ║
║  Lines Exfiltrated    0                                      ║
╚══════════════════════════════════════════════════════════════╝

Apply deterministic patch for SQL injection? [y/N]
```

### 11.7 CLI Entry Point

**Command:** `sicario attack --local [--target <url>] [--timeout <seconds>] [--dry-run]`

- `--target` defaults to `http://localhost:3000` (most common Express/Next.js dev port)
- `--dry-run` extracts routes and generates payloads but does not fire any HTTP requests
- `--timeout` sets the per-request timeout (default: 10 seconds)

**Pre-flight checks:**
1. Verify the target URL is `localhost` or `127.0.0.1` — refuse any other host
2. Probe the target with `GET /` — if no response within 2 seconds, print `"Target server not responding at <url>. Start your dev server first."` and exit 2
3. Require explicit confirmation: `"This will fire security test payloads at <url>. Proceed? [y/N]"`

### 11.8 Scope Limits

- Supports Express.js (JS/TS) and Flask/FastAPI (Python) route detection only
- Maximum 100 routes per scan (refuses with descriptive error if exceeded)
- Maximum 10 payloads per route
- Target must be `localhost` or `127.0.0.1` — enforced in Rust, not documentation
- Does not support authenticated routes (no session/token management in v2)

---

## Area 12: The Poison-Pill Interceptor (`sicario guard`)

### 12.1 Feasibility Assessment

**7-day verdict: Yes — scoped.**

The `SastEngine` already scans arbitrary source files. The `ManifestParser` already parses `package.json`, `Cargo.toml`, and `requirements.txt`. The gap is: a filesystem watcher on the package manager's download cache, a behavioral AST scan of the downloaded package source, and a quarantine mechanism. Estimated: 3–4 days.

**What this is not:** a runtime sandbox. It does not intercept `npm install` at the OS level via LD_PRELOAD or kernel hooks. It watches the package manager's cache directory for new files and scans them before the developer runs the package. The interception happens at the file system level, not the process level.

### 12.2 Behavioral Anomaly Detection

The core insight: a package's declared purpose (e.g., "math library") can be compared against its actual AST structure. A math library that imports `child_process`, `net`, or `fs` is structurally anomalous.

**Anomaly signals** — tree-sitter queries that detect suspicious patterns in third-party package source:

| Signal | Severity | Description |
|--------|----------|-------------|
| `child_process` import in non-build-tool package | Critical | Unexpected shell execution capability |
| `net` or `http` import in non-HTTP-client package | High | Unexpected network capability |
| `fs` import in non-file-processing package | High | Unexpected filesystem access |
| `eval()` with obfuscated string argument | Critical | Dynamic code execution with obfuscation |
| `Buffer.from(base64).toString()` + `eval` | Critical | Base64-decoded eval (classic supply chain pattern) |
| `process.env` access in postinstall script | Critical | Credential harvesting in install hook |
| Hex-encoded string literals > 100 chars | High | Obfuscated payload |
| `require()` with dynamic string argument | Medium | Dynamic module loading |
| `XMLHttpRequest` or `fetch` in Node.js package | High | Unexpected browser API in Node context |

**Package category inference** — the package's declared `keywords` and `description` in `package.json` are used to infer its expected capability set. A package with `keywords: ["math", "statistics"]` is not expected to have network or filesystem access. This is a heuristic, not a guarantee.

### 12.3 Watch Mode Architecture

`sicario guard` runs as a persistent background process watching the package manager cache:

```
sicario guard [--pm npm|pip|cargo] [--project <path>]
  │
  ├─ Resolve cache directory:
  │   npm:   ~/.npm/_npx or node_modules/.cache
  │   pip:   ~/.cache/pip/wheels or site-packages
  │   cargo: ~/.cargo/registry/src
  │
  ├─ Start filesystem watcher (reuses existing `notify` crate dependency)
  │   Watch for: Create events on .js, .ts, .py, .rs files
  │   Debounce: 200ms
  │
  ├─ On new file detected:
  │   1. Determine which package the file belongs to
  │   2. Run BehavioralScanner on the file
  │   3. If anomalies found:
  │      a. Print QUARANTINE ALERT to terminal
  │      b. Write quarantine record to .sicario/quarantine.json
  │      c. If --auto-quarantine: rename package dir to <name>.sicario-quarantined
  │   4. If clean: silent (no output)
  │
  └─ On Ctrl+C: clean exit, print summary
```

### 12.4 `BehavioralScanner`

New struct in `sicario-cli/src/guard/behavioral_scanner.rs`:

```rust
pub struct BehavioralAnomaly {
    pub signal: AnomalySignal,
    pub severity: Severity,
    pub file: PathBuf,
    pub line: usize,
    pub snippet: String,
    pub description: String,
}

pub enum AnomalySignal {
    UnexpectedChildProcess,
    UnexpectedNetworkAccess,
    UnexpectedFilesystemAccess,
    ObfuscatedEval,
    Base64DecodedEval,
    PostInstallCredentialHarvest,
    HexEncodedPayload,
    DynamicRequire,
}
```

The `BehavioralScanner` is a specialized `SastEngine` instance loaded with a fixed set of behavioral anomaly rules (not user-configurable). These rules are embedded in the binary alongside the existing security rules.

**Behavioral rules** (tree-sitter queries, JS/TS only in v2):

```yaml
# Detect child_process import
- id: "guard/unexpected-child-process"
  name: "Unexpected child_process import"
  severity: Critical
  pattern:
    query: |
      (call_expression
        function: (identifier) @fn (#eq? @fn "require")
        arguments: (arguments (string) @mod
          (#match? @mod "child_process"))) @call

# Detect eval with non-literal argument (obfuscated eval)
- id: "guard/obfuscated-eval"
  name: "eval() with non-literal argument"
  severity: Critical
  pattern:
    query: |
      (call_expression
        function: (identifier) @fn (#eq? @fn "eval")
        arguments: (arguments . [(identifier) (call_expression) (binary_expression)] @arg)) @call

# Detect process.env access in any context
- id: "guard/process-env-access"
  name: "process.env access (potential credential harvesting)"
  severity: High
  pattern:
    query: |
      (member_expression
        object: (member_expression
          object: (identifier) @proc (#eq? @proc "process")
          property: (property_identifier) @env (#eq? @env "env"))) @access
```

### 12.5 Quarantine Mechanism

When a Critical anomaly is detected:

1. **Alert** — print to terminal immediately:
```
╔══════════════════════════════════════════════════════════════╗
║           ⚠  SICARIO POISON-PILL INTERCEPTOR  ⚠             ║
╠══════════════════════════════════════════════════════════════╣
║  PACKAGE QUARANTINED: lodash@4.17.22                         ║
║  Anomaly:  Unexpected child_process import (Critical)        ║
║  File:     node_modules/lodash/dist/lodash.min.js:1          ║
║  Signal:   require('child_process') in math utility package  ║
╠══════════════════════════════════════════════════════════════╣
║  Action:   Package renamed to lodash.sicario-quarantined     ║
║  Record:   .sicario/quarantine.json updated                  ║
╠══════════════════════════════════════════════════════════════╣
║  DO NOT RUN THIS PACKAGE. Remove it from package.json and    ║
║  run npm install to restore a clean state.                   ║
╚══════════════════════════════════════════════════════════════╝
```

2. **Quarantine record** — append to `.sicario/quarantine.json`:
```json
{
  "quarantined_at": "2025-05-04T12:34:56Z",
  "package_name": "lodash",
  "version": "4.17.22",
  "ecosystem": "npm",
  "anomalies": [
    {
      "signal": "UnexpectedChildProcess",
      "severity": "Critical",
      "file": "node_modules/lodash/dist/lodash.min.js",
      "line": 1,
      "snippet": "require('child_process')"
    }
  ],
  "action": "renamed"
}
```

3. **Physical quarantine** (with `--auto-quarantine` flag) — rename the package directory:
```
node_modules/lodash → node_modules/lodash.sicario-quarantined
```
This prevents Node.js from loading the package without deleting it (preserving evidence).

### 12.6 `sicario guard scan` — One-Shot Mode

In addition to the persistent watch mode, `sicario guard scan [--dir <path>]` performs a one-shot behavioral scan of all packages in `node_modules/` (or the specified directory). This is useful for scanning existing installations without running the persistent watcher.

```
sicario guard scan
  Scanning 847 packages in node_modules/...
  ✓ 845 packages clean
  ✖ 2 packages flagged:

  lodash@4.17.22    Critical  Unexpected child_process import
  colors@1.4.44     High      Unexpected network access (fetch)

  Run `sicario guard quarantine lodash colors` to quarantine flagged packages.
```

### 12.7 Scope Limits

- **npm only in v2.** pip and cargo support deferred (different cache structures, different install hooks).
- **JS/TS behavioral rules only.** Python and Rust behavioral rules deferred.
- **No runtime interception.** The guard watches the filesystem, not the process. A developer who runs `node malicious-package` before the watcher fires is not protected. The guard is a pre-execution check, not a sandbox.
- **No network calls.** The behavioral scanner is entirely local. It does not query any threat feed or CVE database.
- **False positive acknowledgment.** Some legitimate packages (build tools, test runners) use `child_process` and `fs`. The guard prints a warning but does not auto-quarantine unless `--auto-quarantine` is explicitly set. The developer makes the final call.
