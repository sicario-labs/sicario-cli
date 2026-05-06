# Execution Roadmap: sicario-v2-eta-engine

---

## Phase 1: Ollama Air-Gapped Remediation (`--agent` flag)

### 1.1 `AgentSelector` and `--agent` Flag

- [x] **1.1 `AgentSelector` and `--agent` Flag**
  - [x] **1.1 `AgentSelector` and `--agent` Flag
**
  - [x] Add `agent: Option<String>` field to `FixArgs` in `sicario-cli/src/cli/fix.rs`
    - [x] Create `sicario-cli/src/remediation/agent_selector.rs` with:
      - [x] `AgentConfig` enum: `Local { model_override: Option<String> }`, `Cloud`, `Auto`
      - [x] `AgentSelector::parse(flag: Option<&str>) -> Result<AgentConfig>` — validates flag value, returns descriptive error listing valid values on invalid input
      - [x] `AgentSelector::parse` returns `Err` for any value not matching `local`, `local-<model>`, or `cloud`
      - [x] When `AgentConfig::Local` is resolved, set `allow_ai = true` implicitly (no consent prompt for localhost calls)
    - [x] Wire `AgentSelector::parse` into the `cmd_fix` handler in `main.rs`
    - [x] Add unit tests: `local` → `Local { model_override: None }`, `local-qwen2.5-coder:7b` → `Local { model_override: Some("qwen2.5-coder:7b") }`, `cloud` → `Cloud`, `invalid` → `Err`

### 1.2 `OllamaClient`

- [x] **1.2 `OllamaClient`**
  - [x] **1.2 `OllamaClient`
**
  - [x] Create `sicario-cli/src/remediation/ollama_client.rs` with:
      - [x] `OllamaClient::probe(timeout_ms: u64) -> Result<String>` — `GET http://127.0.0.1:11434/api/tags` with 500ms timeout, returns selected model name
      - [x] Model selection priority: (a) first model containing `qwen2.5-coder`, (b) first containing `deepseek-coder`, (c) first in list
      - [x] `OllamaClient::probe` prints error with `https://ollama.ai` URL and `ollama pull qwen2.5-coder:7b` / `ollama pull deepseek-coder-v2` commands on failure, then exits non-zero
      - [x] `OllamaClient::new_with_model(model: String)` — skips probe, uses provided model name directly
      - [x] All requests use `AuthStyle::None` (no `Authorization` header) via existing `LlmClient` infrastructure
      - [x] Use `http://127.0.0.1:11434` (IPv4) not `http://localhost:11434`
    - [x] Integrate `OllamaClient` into `RemediationEngine`: when `AgentConfig::Local`, route LLM fallback calls to `OllamaClient` instead of cloud providers
    - [x] Add unit tests with mock HTTP server: successful probe selects correct model by priority, failed probe exits non-zero, `local-<model>` skips probe

### 1.3 `MicroContextExtractor`

- [x] **1.3 `MicroContextExtractor`**
  - [x] **1.3 `MicroContextExtractor`
**
  - [x] Create `sicario-cli/src/remediation/micro_context.rs` with:
      - [x] `MicroContextExtractor::extract(file_content: &str, vulnerable_line: usize, lang: Language) -> MicroContext`
      - [x] Uses existing `TreeSitterEngine` to find the smallest enclosing function/arrow function/method containing `vulnerable_line`
      - [x] Extracts all `identifier` nodes within the function block → `in_scope_variables: Vec<String>`
      - [x] Caps extracted block at 2,000 tokens (≈1,500 chars); falls back to ±15 line window if exceeded
      - [x] `MicroContext` struct: `{ function_block: String, in_scope_variables: Vec<String> }`
    - [x] Add unit tests: extracts correct function block for JS arrow function, Python def, TypeScript method; identifier list is complete; cap triggers correctly on large functions

### 1.4 `LocalLlmPrompt` and `TreeSitterVerificationLoop`

- [x] **1.4 `LocalLlmPrompt` and `TreeSitterVerificationLoop`**
  - [x] **1.4 `LocalLlmPrompt` and `TreeSitterVerificationLoop`
**
  - [x] Create `sicario-cli/src/remediation/ts_verification.rs` with:
      - [x] `TreeSitterVerificationLoop::verify(response: &str, in_scope_variables: &[String], lang: Language, original_content: &str, vulnerable_line: usize) -> VerificationResult`
      - [x] Stage 1: parse response as `{"replacement": "..."}` JSON; on failure → `VerificationResult::Discard`
      - [x] Stage 2: parse `replacement` with tree-sitter; check `root_node().has_error()`; on error nodes → `VerificationResult::Discard`
      - [x] Stage 3: extract all identifier nodes from replacement AST; verify each is in `in_scope_variables` or is a language keyword/built-in/literal; on unknown identifier → `VerificationResult::Discard`
      - [x] Stage pass: `VerificationResult::Accept(spliced_content: String)` — calls existing `splice_patch`
      - [x] All three stages complete within 50ms for replacements up to 200 lines
      - [x] Invariant: disk is never written with broken code; either valid replacement or original unchanged
    - [x] Wire `TreeSitterVerificationLoop` into `RemediationEngine` for local agent fix path
    - [x] Add unit tests: valid JSON + valid syntax + in-scope identifiers → `Accept`; invalid JSON → `Discard`; syntax error → `Discard`; hallucinated identifier → `Discard`

### 1.5 `PatchReceipt` Updates for Local Agent

- [x] **1.5 `PatchReceipt` Updates for Local Agent**
  - [x] **1.5 `PatchReceipt` Updates for Local Agent
**
  - [x] Add `PatchReceipt::local_agent(rule_id, file, line, execution_ms, model_name)` constructor to `receipt.rs`
      - [x] Sets `tokens_burned: 0`, `lines_exfiltrated: 0`
      - [x] Sets `template_used: format!("ollama-local ({})", model_name)`
    - [x] Emit `PatchReceipt::local_agent` after every successful local agent fix in `cmd_fix`
    - [x] Add unit test: `local_agent` constructor always produces `tokens_burned: 0` and `lines_exfiltrated: 0`

### 1.6 Zero-Exfiltration Receipt for Local Agent (Req 3)

- [x] **1.6 Zero-Exfiltration Receipt for Local Agent (Req 3)**
  - [x] **1.6 Zero-Exfiltration Receipt for Local Agent (Req 3)
**
  - [x] Verify `RemediationEngine` makes no outbound HTTP requests to any endpoint other than `http://127.0.0.1:11434` when `AgentConfig::Local` is active (code review gate — add a comment asserting this invariant)
    - [x] Add integration test: `--agent=local` with mock Ollama server → `lines_exfiltrated: 0` in receipt, no requests to any other host

---

## Phase 2: `MultiLinePatchTemplate` and `SqlAstRewriteTemplate`

### 2.1 `MultiLinePatchTemplate` Trait

- [x] **2.1 `MultiLinePatchTemplate` Trait**
  - [x] **2.1 `MultiLinePatchTemplate` Trait
**
  - [x] Add `MultiLinePatchTemplate` trait to `sicario-cli/src/remediation/template_registry/mod.rs`:
      ```rust
      pub trait MultiLinePatchTemplate: Send + Sync {
          fn name(&self) -> &'static str;
          fn generate_multiline_patch(&self, file_content: &str, vulnerable_line: usize, lang: Language) -> Option<String>;
      }
      ```
    - [x] Add `multi_line: HashMap<RegistryKey, Box<dyn MultiLinePatchTemplate>>` to `TemplateRegistry`
    - [x] Add `TemplateRegistry::register_multi(rule_id, cwe, template)` method
    - [x] Update `RemediationEngine::try_registry_fix` to check `multi_line` before `single_line`:
      - [x] If `MultiLinePatchTemplate` returns `Some(content)`, validate with tree-sitter
      - [x] If validation fails, discard and fall through to `single_line` lookup
      - [x] If `MultiLinePatchTemplate` returns `None`, fall through to `single_line` lookup
    - [x] Add unit tests: `MultiLinePatchTemplate` returning `Some` is used before `PatchTemplate`; `None` falls through; invalid syntax is discarded

### 2.2 `SqlAstRewriteTemplate`

- [x] **2.2 `SqlAstRewriteTemplate`**
  - [x] **2.2 `SqlAstRewriteTemplate`
**
  - [x] Create `SqlAstRewriteTemplate` struct in `sicario-cli/src/remediation/template_registry/sql.rs` implementing `MultiLinePatchTemplate`
    - [x] Implement string concatenation rewrite:
      - [x] Use tree-sitter to find enclosing `.query(` or `.execute(` call expression from `vulnerable_line`
      - [x] Extract all concatenated string parts and user-controlled variable references
      - [x] Rewrite to `db.query("... $1 ...", [var1])` form
      - [x] Preserve original indentation
    - [x] Implement template literal rewrite:
      - [x] Detect `` `...${variable}...` `` pattern in first argument
      - [x] Replace each `${variable}` with `$1`, `$2`, … positional placeholders
      - [x] Pass variables as second array argument
    - [x] Implement multi-line concatenation rewrite:
      - [x] Walk up AST from `vulnerable_line` to find enclosing call expression spanning multiple lines
      - [x] Extract all sub-expressions across lines
      - [x] Rewrite entire call expression as single parameterized call
    - [x] Return `None` for: >8 interpolated variables, conditional query construction, nested function calls as arguments, any language other than JS/TS
    - [x] Preserve all code outside the rewritten call expression exactly (whitespace, comments, surrounding statements)
    - [x] Register in `TemplateRegistry::default()` under `js-sql-string-concat`, `js-sql-template-string`, `node-sql-template-literal`, and CWE `89` — replacing existing comment-only registrations
    - [x] Add unit tests:
      - [x] String concat rewrite produces valid parameterized query
      - [x] Template literal rewrite produces valid parameterized query
      - [x] Multi-line concat rewrite produces valid parameterized query
      - [x] >8 variables → `None`
      - [x] Non-JS/TS file → `None`
      - [x] Round-trip property: `tree_sitter.parse(output).root_node().has_error() == false` for all valid inputs
      - [x] Original indentation is preserved
      - [x] Code outside the rewritten call is unchanged

---

## Phase 3: Ghost Fix Pre-Commit Hook

### 3.1 `AutoFixHook` Installation

- [x] **3.1 `AutoFixHook` Installation**
  - [x] **3.1 `AutoFixHook` Installation
**
  - [x] Add `install_auto_fix(&self) -> Result<()>` method to `HookManager` in `sicario-cli/src/hook/manager.rs`:
      - [x] Calls `remove_sicario_block()` on existing content before writing new block (idempotency)
      - [x] Writes the `AutoFixHook` POSIX sh script block between `BEGIN SICARIO HOOK` / `END SICARIO HOOK` markers
      - [x] Sets `0o755` permissions on Unix after writing
    - [x] Add `--auto-fix` flag to `HookArgs` in `sicario-cli/src/cli/hook.rs`
    - [x] Wire `--auto-fix` to `HookManager::install_auto_fix()` in the `cmd_hook` handler
    - [x] Add unit tests:
      - [x] `install_auto_fix` on empty repo creates hook with correct script
      - [x] `install_auto_fix` on existing standard hook replaces Sicario block only
      - [x] `install_auto_fix` twice results in exactly one `BEGIN SICARIO HOOK` / `END SICARIO HOOK` pair
      - [x] `install_auto_fix` on existing `--auto-fix` hook is idempotent
      - [x] Hook script contains `SICARIO_SKIP_HOOK` bypass
      - [x] Hook script uses POSIX sh syntax (no bash-specific constructs)

### 3.2 `sicario fix --staged` Command

- [x] **3.2 `sicario fix --staged` Command**
  - [x] **3.2 `sicario fix --staged` Command
**
  - [x] Add `staged: bool` field to `FixArgs` in `sicario-cli/src/cli/fix.rs`
    - [x] Implement `--staged` behavior in `cmd_fix` handler:
      - [x] Run `git diff --cached --name-only` to enumerate staged files
      - [x] Normalize path separators to `/` on Windows
      - [x] Restrict fix attempts to staged files only
      - [x] Skip interactive diff confirmation prompt — apply automatically
      - [x] Use only `DeterministicFix` patches — no LLM fallback
      - [x] With `--format json`, output JSON array of fix result objects: `{ file, rule_id, line, fixed, template_used }`
      - [x] If run outside a Git repository, print descriptive error and exit non-zero
    - [x] Add unit tests:
      - [x] `--staged` only fixes files in `git diff --cached --name-only` output
      - [x] `--staged` with `--format json` produces correct JSON array
      - [x] `--staged` outside git repo exits non-zero with descriptive error
      - [x] `--staged` does not invoke LLM fallback

### 3.3 Ghost Fix Safety (Req 8)

- [x] **3.3 Ghost Fix Safety (Req 8)**
  - [x] **3.3 Ghost Fix Safety (Req 8)
**
  - [x] Verify `AutoFixHook` creates backup via `BackupManager` before each fix (existing behavior via `apply_patch`)
    - [x] Add hook script logic: if `git add <file>` fails after fix, restore from backup and block commit with error message
    - [x] Add unit test: `AutoFixHook` with `SICARIO_SKIP_HOOK=1` exits 0 without scanning
    - [x] Add integration test: hook with zero unfixed findings exits 0; hook with unfixed findings exits 1

---

## Phase 4: Proof-of-Concept Generation

### 4.1 `PocGenerator` Core

- [x] **4.1 `PocGenerator` Core**
  - [x] **4.1 `PocGenerator` Core
**
  - [x] Create `sicario-cli/src/poc/mod.rs` and `sicario-cli/src/poc/generator.rs`
    - [x] Define `PocPayload` struct: `{ vuln_location: String, curl_command: String, interpretation: String }`
    - [x] Implement `PocGenerator::generate(finding: &Finding) -> Option<PocPayload>`:
      - [x] SQL injection (CWE-89): detect DB driver from AST imports; generate time-based payload (`pg_sleep(5)`, `SLEEP(5)`, or `WAITFOR DELAY '0:0:5'`); extract route and port from AST
      - [x] SSRF (CWE-918): spawn `SsrfProbeListener` on `127.0.0.1:0`; generate payload targeting `http://127.0.0.1:<probe_port>/ssrf-probe`
      - [x] Command injection (CWE-78): generate `; echo sicario-poc-$(date +%s)` payload
      - [x] Path traversal (CWE-22): generate payload reading `/etc/hostname` (Unix) or `C:\Windows\System32\drivers\etc\hosts` (Windows)
      - [x] Return `None` with message `"PoC not available for this finding — insufficient AST context."` if AST context is insufficient
    - [x] Implement safety enforcement in Rust engine (not documentation):
      - [x] Reject any generated URL that does not resolve to `127.0.0.1` or `::1`
      - [x] Reject any generated SQL payload containing `DROP`, `DELETE`, `TRUNCATE`, `UPDATE`, `INSERT`, or `ALTER`
    - [x] Add unit tests: SQL injection payload uses correct DB-specific sleep function; SSRF payload targets localhost only; command injection payload uses echo-based technique; path traversal payload reads read-only file; destructive SQL keywords are rejected; non-localhost URLs are rejected

### 4.2 `SsrfProbeListener`

- [x] **4.2 `SsrfProbeListener`**
  - [x] **4.2 `SsrfProbeListener`
**
  - [x] Implement `SsrfProbeListener` in `sicario-cli/src/poc/generator.rs`:
      - [x] Bind `TcpListener` to `127.0.0.1:0` (OS-assigned port)
      - [x] Spawn background thread; print confirmation if connection received within 30 seconds
      - [x] Shut down after 30 seconds regardless
    - [x] Add unit test: listener binds successfully, returns assigned port, shuts down cleanly

### 4.3 `--prove` Flag on `sicario scan`

- [x] **4.3 `--prove` Flag on `sicario scan`**
  - [x] **4.3 `--prove` Flag on `sicario scan`
**
  - [x] Add `prove: bool` field to `ScanArgs` in `sicario-cli/src/cli/scan.rs`
    - [x] Wire `--prove` into the scan output pipeline:
      - [x] For each finding above severity threshold, call `PocGenerator::generate`
      - [x] Display consent prompt before printing any payload; skip finding if user does not confirm
      - [x] Print `vuln_location`, `curl_command`, and `interpretation` for each generated payload
      - [x] With `--format json`, suppress consent prompt and include `poc` field (string or `null`) in each finding object
    - [x] Add unit tests: consent prompt is shown before payload; `y` proceeds; anything else skips; `--format json` suppresses prompt and includes `poc` field

---

## Phase 5: Security Regression Guard

### 5.1 `sicario baseline diff --ci`

- [x] **5.1 `sicario baseline diff --ci`**
  - [x] **5.1 `sicario baseline diff --ci`
**
  - [x] Add `Diff(BaselineDiffArgs)` variant to `BaselineAction` enum in `sicario-cli/src/cli/baseline.rs`
    - [x] Define `BaselineDiffArgs`: `reference: Option<String>`, `ci: bool`, `threshold: SeverityLevel`, `tag: Option<String>`
    - [x] Implement `cmd_baseline_diff` handler:
      - [x] If no baseline file exists, print descriptive error and exit with code 2
      - [x] Run fresh scan of current directory
      - [x] Call `BaselineManager::compare(reference, &current_findings)` — uses most recent baseline if `reference` is `None`
      - [x] With `--ci`: exit 1 if `delta.new_findings` contains any finding with severity ≥ threshold; exit 0 otherwise
      - [x] Print CI summary format: `✓ <N> known findings`, `✓ <M> findings resolved`, `✗ <K> NEW findings introduced`
      - [x] List new findings in detail below summary
      - [x] Without `--ci`: print delta in JSON or text format
    - [x] Add unit tests:
      - [x] No new findings above threshold → exit 0
      - [x] New High finding → exit 1 with `--ci --threshold high`
      - [x] New Medium finding → exit 0 with `--ci --threshold high`
      - [x] No baseline file → exit 2 with descriptive error
      - [x] `--tag` selects named baseline
      - [x] `BaselineDelta` JSON round-trip produces equivalent delta

---

## Phase 6: Compliance Evidence Export

### 6.1 `ComplianceReport` and `sicario report --compliance`

- [x] **6.1 `ComplianceReport` and `sicario report --compliance`**
  - [x] **6.1 `ComplianceReport` and `sicario report --compliance`
**
  - [x] Create `sicario-cli/src/reporting/compliance.rs` with:
      - [x] `ComplianceReport` struct with all fields from design: `generated_at`, `sicario_version`, `scan_summary`, `remediation_log`, `suppression_log`, `baseline_history`, `mttr_by_rule`
      - [x] `RemediationEntry` struct: `patch_id`, `applied_at`, `file_path`, `rule_id`, `template_used`
      - [x] `SuppressionEntry` struct: `file`, `line`, `rule_id`, `comment_text`, `author_email`, `commit_sha`, `committed_at`
      - [x] `MttrEntry` struct: `rule_id`, `vuln_class`, `severity`, `findings_detected`, `findings_remediated`, `mttr_hours`
      - [x] `generate_compliance_report(project_root: &Path) -> Result<ComplianceReport>`:
        - [x] Populate `remediation_log` from `BackupManager::load_history()`
        - [x] Populate `suppression_log` by scanning source files for `sicario-ignore` directives and running `git log -S "sicario-ignore" --follow --format="%ae %aI" -- <file>`; use `"untracked"` if no git history
        - [x] Populate `baseline_history` from `BaselineManager::trend()`
        - [x] Compute `mttr_by_rule` from detection timestamps (baseline history) and fix timestamps (remediation log)
      - [x] Write report to `.sicario/compliance-report-<timestamp>.json`
      - [x] With `--format sarif`, also write `.sicario/compliance-report-<timestamp>.sarif` using existing `output/sarif.rs`
    - [x] Create `sicario-cli/src/cli/report.rs` with `ReportArgs` and `ReportAction` (compliance, mttr subcommands)
    - [x] Wire `sicario report --compliance` into `main.rs`
    - [x] Add unit tests:
      - [x] `ComplianceReport` JSON round-trip produces equivalent report with no data loss
      - [x] `suppression_log` records `"untracked"` for files with no git history
      - [x] Report completes within 10 seconds for ≤500 findings (performance assertion in integration test)

---

## Phase 7: Policy-as-Code Enforcement

### 7.1 `PolicyLoader` and `.sicario/policy.yaml`

- [x] **7.1 `PolicyLoader` and `.sicario/policy.yaml`**
  - [x] **7.1 `PolicyLoader` and `.sicario/policy.yaml`
**
  - [x] Create `sicario-cli/src/policy/mod.rs` and `sicario-cli/src/policy/loader.rs`
    - [x] Define `PolicyConfig` struct: `fail_on`, `required_rules`, `blocked_suppressions`, `scope`, `max_findings`
    - [x] Implement `PolicyLoader::load(project_root: &Path) -> Result<Option<PolicyConfig>>` — returns `None` if `.sicario/policy.yaml` does not exist
    - [x] Integrate `PolicyLoader` into `cmd_scan`: load policy on every scan invocation if file exists
    - [x] Policy enforcement:
      - [x] `fail_on` overrides `--fail-on` CLI flag
      - [x] `required_rules` + `sicario-ignore` → exit 1 with `"Policy violation: rule '<rule_id>' is marked as required and cannot be suppressed."`
      - [x] `blocked_suppressions` + staged `sicario-ignore` → `AutoFixHook` blocks commit with `"Policy violation: suppression of '<rule_id>' is prohibited by organizational policy."`
      - [x] `max_findings` → exit 1 if total finding count exceeds limit
      - [x] Policy fields cannot be overridden by CLI flags
    - [x] Add unit tests:
      - [x] Policy `fail_on` overrides CLI `--fail-on`
      - [x] `required_rules` suppression → exit 1 with correct message
      - [x] `max_findings` exceeded → exit 1
      - [x] No `.sicario/policy.yaml` → no policy enforcement

### 7.2 `sicario policy validate` and `sicario policy init`

- [x] **7.2 `sicario policy validate` and `sicario policy init`**
  - [x] **7.2 `sicario policy validate` and `sicario policy init`
**
  - [x] Create `sicario-cli/src/cli/policy.rs` with `PolicyCommand` and `PolicyAction` (validate, init)
    - [x] Implement `cmd_policy_validate`:
      - [x] Parse `.sicario/policy.yaml`
      - [x] Check all `required_rules` and `blocked_suppressions` rule IDs against loaded rule set
      - [x] Print unknown rule IDs and invalid glob patterns
      - [x] Exit 0 if valid, exit 1 if any issues found
    - [x] Implement `cmd_policy_init`:
      - [x] Generate `.sicario/policy.yaml` template with all fields commented out and example values
      - [x] Do not overwrite existing file
    - [x] Add unit tests: validate with unknown rule ID → exit 1 with message; validate with valid config → exit 0; init creates template file; init does not overwrite existing file

---

## Phase 8: MTTR Tracking

### 8.1 `sicario report --mttr`

- [x] **8.1 `sicario report --mttr`**
  - [x] **8.1 `sicario report --mttr`
**
  - [x] Create `sicario-cli/src/reporting/mttr.rs` with:
      - [x] `MttrReport` struct: `Vec<MttrEntry>`, `overall_mttr_hours`, `total_remediated`, `period`
      - [x] `compute_mttr(project_root: &Path, since: Option<DateTime<Utc>>) -> Result<MttrReport>`:
        - [x] Load remediation log from `BackupManager::load_history()`
        - [x] Load baseline history from `BaselineManager::trend()`
        - [x] For each remediated finding, compute `MTTR = fix_timestamp - detection_timestamp` in hours
        - [x] Group by rule ID; compute arithmetic mean per rule
        - [x] Compute trend indicator: `↑` (MTTR decreasing), `↓` (MTTR increasing), `→` (<10% change)
        - [x] Display `"Insufficient data"` for rule IDs with fewer than 3 remediated findings
      - [x] `render_mttr_table(report: &MttrReport) -> String` — formatted table with columns: Rule ID, Vulnerability Class, Severity, Findings Detected, Findings Remediated, MTTR (hours), Trend
      - [x] `render_mttr_json(report: &MttrReport) -> Result<String>` — JSON array for Datadog/Splunk
    - [x] Wire `sicario report --mttr` into `main.rs` via `ReportArgs`
    - [x] Support `--since <ISO8601_date>` flag to restrict computation period
    - [x] Add unit tests:
      - [x] MTTR formula: `fix_timestamp - detection_timestamp` in hours
      - [x] <3 remediated findings → `"Insufficient data"`
      - [x] `--since` restricts to findings detected after date
      - [x] JSON output is valid and contains all fields
      - [x] Completes within 5 seconds for ≤1,000 remediated findings

---

## Phase 9: Suppression Audit Log

### 9.1 `sicario suppressions audit`

- [x] **9.1 `sicario suppressions audit`**
  - [x] **9.1 `sicario suppressions audit`
**
  - [x] Add `Audit(SuppressionAuditArgs)` variant to the suppressions subcommand in `sicario-cli/src/cli/suppressions.rs`
    - [x] Define `SuppressionAuditArgs`: `format: OutputFormat`, `since: Option<String>`, `author: Option<String>`, `output: Option<String>`
    - [x] Create `sicario-cli/src/audit/suppression_audit.rs` with:
      - [x] `SuppressionAuditEntry` struct: `file`, `line`, `rule_id`, `comment_text`, `author_email`, `commit_sha`, `committed_at`
      - [x] `collect_suppression_audit(project_root: &Path) -> Result<Vec<SuppressionAuditEntry>>`:
        - [x] Scan all source files for `sicario-ignore`, `sicario-ignore-next-line`, `sicario-ignore:<rule-id>` directives using existing `suppression_parser`
        - [x] For each directive, run `git blame --porcelain -L <line>,<line> <file>` to extract commit SHA and author email
        - [x] Set `"untracked"` for all three fields if file has no git history
      - [x] Filter by `--since` (committed_at after date) and `--author` (author_email matches)
      - [x] `--format json`: output JSON array
      - [x] `--format csv`: output CSV with headers `file,line,rule_id,comment,author_email,commit_sha,committed_at`
      - [x] `--output <path>`: append to existing file rather than overwriting
    - [x] Add unit tests:
      - [x] Detects all three suppression directive forms
      - [x] `"untracked"` for files with no git history
      - [x] `--since` filter works correctly
      - [x] `--author` filter works correctly
      - [x] `--output` appends to existing file
      - [x] Completes within 10 seconds for ≤500 suppressions (performance assertion)

---

## Phase 10: Dependency License Risk Scanner

### 10.1 `LicenseScanner`

- [x] **10.1 `LicenseScanner`**
  - [x] **10.1 `LicenseScanner`
**
  - [x] Create `sicario-cli/src/engine/sca/license_scanner.rs` with:
      - [x] `LicenseRisk` enum: `High`, `Medium`, `Low`, `Unknown`
      - [x] `LicenseFinding` struct: `package`, `version`, `license`, `risk`, `ecosystem`
      - [x] `LicenseScanner::scan(manifest_deps: &[Dependency]) -> Result<Vec<LicenseFinding>>`:
        - [x] Check local OSV/GHSA SQLite cache first
        - [x] On cache miss: fetch from npm registry (`https://registry.npmjs.org/<package>`) or PyPI (`https://pypi.org/pypi/<package>/json`) with 2-second timeout per package
        - [x] Classify license into `High`, `Medium`, `Low` tiers per design table
        - [x] Check `.sicario/license-allowlist.txt`; allowlisted packages are reported but do not affect exit code
      - [x] `LicenseScanner::render_table(findings: &[LicenseFinding]) -> String` — formatted table with columns: Package, Version, License, Risk Tier, Ecosystem
    - [x] Add `--licenses` flag to `ScanArgs` in `sicario-cli/src/cli/scan.rs`
    - [x] Add `--fail-on-license` flag to `ScanArgs`: `High` or `Medium`
    - [x] Wire `--licenses` into `cmd_scan`: run `LicenseScanner` after security scan; append license table to output; with `--format json`, include `license_findings` array alongside `security_findings`
    - [x] Apply `--fail-on-license` exit code gating after license scan
    - [x] Add unit tests:
      - [x] GPL-3.0 → `High`; LGPL-2.1 → `Medium`; MIT → `Low`
      - [x] Allowlisted package does not affect exit code
      - [x] `--fail-on-license HIGH` exits 1 on HIGH-tier dependency
      - [x] `--fail-on-license MEDIUM` exits 1 on HIGH or MEDIUM dependency
      - [x] Cache hit skips network fetch
      - [x] Network fetch timeout (2s) is respected
      - [x] Completes within 15 seconds for ≤500 dependencies (performance assertion)

---

## Phase 11: Cross-Cutting Verification

### 11.1 Zero-Exfiltration Audit

- [x] **11.1 Zero-Exfiltration Audit**
  - [x] **11.1 Zero-Exfiltration Audit
**
  - [x] Code review gate: verify `OllamaClient` makes no requests outside `127.0.0.1:11434` — add `#[cfg(test)]` assertion or comment block
    - [x] Code review gate: verify `SqlAstRewriteTemplate::generate_multiline_patch` contains no network calls
    - [x] Code review gate: verify `AutoFixHook` script contains no `curl`, `wget`, or network commands
    - [x] Code review gate: verify `PocGenerator` makes no outbound requests (SsrfProbeListener is inbound only)
    - [x] Add integration test: run all new features with network monitoring; assert zero outbound requests except `127.0.0.1:11434` (for local agent) and npm/PyPI (for license scanner)

### 11.2 Cross-Platform Compatibility

- [x] **11.2 Cross-Platform Compatibility**
  - [x] **11.2 Cross-Platform Compatibility
**
  - [x] Add CI matrix job for Windows (Git Bash) testing `AutoFixHook` POSIX sh syntax
    - [x] Add CI test: `sicario fix --staged` on Windows normalizes path separators to `/`
    - [x] Add CI test: `SqlAstRewriteTemplate` preserves CRLF line endings on Windows input
    - [x] Verify `OllamaClient` uses `127.0.0.1` not `localhost` in all code paths

### 11.3 Performance Assertions

- [x] **11.3 Performance Assertions**
  - [x] **11.3 Performance Assertions
**
  - [x] `TreeSitterVerificationLoop`: add benchmark asserting all three stages complete within 50ms for 200-line replacement
    - [x] `AutoFixHook`: add integration test asserting completion within 2 seconds for 20 staged files with 50 findings
    - [x] `sicario report --compliance`: add integration test asserting completion within 10 seconds for 500 findings
    - [x] `sicario report --mttr`: add integration test asserting completion within 5 seconds for 1,000 remediated findings
    - [x] `sicario suppressions audit`: add integration test asserting completion within 10 seconds for 500 suppressions
    - [x] `sicario scan --licenses`: add integration test asserting completion within 15 seconds for 500 dependencies

---

## Phase 12: V1 Bottlenecks and Incomplete Implementations

These tasks fix confirmed gaps in the existing v1 codebase. They are not new features — they are broken or missing wires that must be resolved for v2 to be a genuine upgrade. All tasks in this phase are independent of each other and can be parallelized.

### 12.1 Wire Confidence Score and Suppression into Exit Code (CRITICAL)

- [x] **12.1 Wire Confidence Score and Suppression into Exit Code (CRITICAL)**
  - [x] **12.1 Wire Confidence Score and Suppression into Exit Code (CRITICAL)
**
  **File:** `sicario-cli/src/main.rs` lines 654–661
    - [x] Replace `confidence_score: 1.0` with `confidence_score: v.confidence_score` in the `FindingSummary` mapping
    - [x] Replace `suppressed: false` with `suppressed: v.suppressed` in the `FindingSummary` mapping
    - [x] Add unit test: finding with `confidence_score: 0.1` and `--confidence-threshold 0.8` → exit code 0
    - [x] Add unit test: finding with `suppressed: true` → exit code 0 regardless of severity
    - [x] Verify `ExitCode::from_findings` is now fed real data (no hardcoded values remain)

### 12.2 Fix Ollama Model Priority Selection (HIGH)

- [x] **12.2 Fix Ollama Model Priority Selection (HIGH)**
  - [x] **12.2 Fix Ollama Model Priority Selection (HIGH)
**
  **File:** `sicario-cli/src/key_manager/manager.rs` — `try_ollama_detection()`
    - [x] Extract a `select_best_model(models: &[serde_json::Value]) -> Option<String>` function that implements priority: (a) first model containing `qwen2.5-coder`, (b) first containing `deepseek-coder`, (c) first in list
    - [x] Replace the `.first()` call in `try_ollama_detection()` with `select_best_model(&models)`
    - [x] Reuse `select_best_model` in the new `OllamaClient::probe()` (Phase 1.2) so the logic is not duplicated
    - [x] Add unit tests: list with `qwen2.5-coder:7b` and `llama3` → selects `qwen2.5-coder:7b`; list with only `deepseek-coder` → selects `deepseek-coder`; list with only `llama3` → selects `llama3`; empty list → `None`

### 12.3 Implement PR Creation (MEDIUM)

- [x] **12.3 Implement PR Creation (MEDIUM)**
  - [x] **12.3 Implement PR Creation (MEDIUM)
**
  **File:** `sicario-cli/src/remediation/remediation_engine.rs`
    - [x] Implement `create_github_pr(patch: &Patch) -> Result<String>` in a new `sicario-cli/src/remediation/pr_client.rs`:
      - [x] Read `GITHUB_TOKEN` env var; return descriptive error if absent
      - [x] Auto-detect GitHub repo from `git remote get-url origin` output
      - [x] Create a branch named `sicario/fix-<rule_id>-<timestamp>` via `POST /repos/{owner}/{repo}/git/refs`
      - [x] Commit the patch to the branch via `PUT /repos/{owner}/{repo}/contents/{path}`
      - [x] Open a PR via `POST /repos/{owner}/{repo}/pulls` with title `fix: [sicario] <rule_id> in <file>` and body containing the patch receipt
      - [x] Return the PR URL on success
    - [x] Implement `create_gitlab_mr(patch: &Patch) -> Result<String>` with equivalent GitLab API calls using `GITLAB_TOKEN`
    - [x] Update `RemediationEngine::create_pull_request` to dispatch to the correct implementation based on `git_provider` or auto-detection from remote URL
    - [x] Add `--pr` flag to `FixArgs` that calls `create_pull_request` after a successful patch application
    - [x] Add unit tests with mock HTTP server: GitHub PR creation succeeds; missing `GITHUB_TOKEN` returns descriptive error; unsupported provider returns error

### 12.4 Fix JSON Schema Validation TODO in Deserialization Template (LOW)

- [x] **12.4 Fix JSON Schema Validation TODO in Deserialization Template (LOW)**
  - [x] **12.4 Fix JSON Schema Validation TODO in Deserialization Template (LOW)
**
  **File:** `sicario-cli/src/remediation/templates.rs` line 619
    - [x] Replace the `// TODO: Add JSON schema validation for parsed data` comment with a concrete `zod`-based schema validation stub
    - [x] The generated fix should use `z.object({})` with a comment instructing the developer to define the schema shape
    - [x] Add unit test: generated fix for JS deserialization does not contain the word `TODO`

### 12.5 Wire `--auto-suppress` Flag into Scan Output (MEDIUM)

- [x] **12.5 Wire `--auto-suppress` Flag into Scan Output (MEDIUM)**
  - [x] **12.5 Wire `--auto-suppress` Flag into Scan Output (MEDIUM)
**
  **File:** `sicario-cli/src/main.rs` — `cmd_scan`
    - [x] After the scan completes and before output formatting, check `args.auto_suppress`
    - [x] If `true`, load `SuppressionLearner::load(&project_root)` and call `learner.auto_suppress(&vulns)` to filter findings
    - [x] Apply the filtered list to all downstream steps: output formatting, telemetry submission, exit code computation
    - [x] Add integration test: scan with `--auto-suppress` on a project with 3+ recorded suppressions for a rule → that rule's findings are excluded from output

### 12.6 Wire `--confidence-threshold` into Output Filtering (MEDIUM)

- [x] **12.6 Wire `--confidence-threshold` into Output Filtering (MEDIUM)**
  - [x] **12.6 Wire `--confidence-threshold` into Output Filtering (MEDIUM)
**
  **File:** `sicario-cli/src/main.rs` — `cmd_scan`
    - [x] After the scan completes and before output formatting, filter `vulns` to only those with `confidence_score >= confidence_threshold`
    - [x] Apply the filtered list to all downstream steps: output formatting, telemetry submission, exit code computation
    - [x] Add unit test: finding with `confidence_score: 0.3` is excluded from output when `--confidence-threshold 0.5` is set
    - [x] Verify this filter runs before `--auto-suppress` (confidence filter first, then suppression filter)

### 12.7 Wire `SuppressionLearner::record` into Scan Flow (MEDIUM)

- [x] **12.7 Wire `SuppressionLearner::record` into Scan Flow (MEDIUM)**
  - [x] **12.7 Wire `SuppressionLearner::record` into Scan Flow (MEDIUM)
**
  **File:** `sicario-cli/src/main.rs` — `cmd_scan`
    - [x] Add `--learn-suppressions` flag to `ScanArgs` (default: off)
    - [x] When `--learn-suppressions` is set, after the scan, for each finding with `v.suppressed == true`, call `learner.record(&finding, &finding.snippet)`
    - [x] Save the learner after all recordings: `learner.save()?`
    - [x] Add integration test: scan with `--learn-suppressions` on a file with `// sicario-ignore` → `sicario suppressions list` shows the recorded pattern

### 12.8 Fix `sicario config set-provider` Endpoint Not Read by `resolve_endpoint` (LOW)

- [x] **12.8 Fix `sicario config set-provider` Endpoint Not Read by `resolve_endpoint` (LOW)**
  - [x] **12.8 Fix `sicario config set-provider` Endpoint Not Read by `resolve_endpoint` (LOW)
**
  **File:** `sicario-cli/src/key_manager/manager.rs` — `resolve_endpoint_with_source()`
    - [x] After the project-local config file check (step 4), add a check for `load_global_config().llm_endpoint`
    - [x] Similarly update `resolve_model_with_source()` to check `load_global_config().llm_model` at the same priority level
    - [x] Add integration test: `set_global_config_value("llm_endpoint", "https://api.anthropic.com/v1")` → `resolve_endpoint()` returns `"https://api.anthropic.com/v1"`
    - [x] Add integration test: `set_global_config_value("llm_model", "claude-opus-4-5")` → `resolve_model()` returns `"claude-opus-4-5"`

### 12.9 Emit `PatchReceipt` in Batch Mode (LOW)

- [x] **12.9 Emit `PatchReceipt` in Batch Mode (LOW)**
  - [x] **12.9 Emit `PatchReceipt` in Batch Mode (LOW)
**
  **File:** `sicario-cli/src/remediation/remediation_engine.rs` — `generate_and_apply_batch`
    - [x] Add `no_receipt: bool` parameter to `generate_and_apply_batch` (passed from `FixArgs::no_receipt`)
    - [x] After each successful patch application in the batch loop, construct and emit a `PatchReceipt::deterministic(...)` unless `no_receipt` is true
    - [x] Add unit test: batch mode with 2 successful fixes emits 2 receipts; `--no-receipt` suppresses both

### 12.10 Add `sicario baseline diff` as Alias for `sicario baseline compare --ci` (LOW)

- [x] **12.10 Add `sicario baseline diff` as Alias for `sicario baseline compare --ci` (LOW)**
  - [x] **12.10 Add `sicario baseline diff` as Alias for `sicario baseline compare --ci` (LOW)
**
  **File:** `sicario-cli/src/cli/baseline.rs`
    - [x] Add `Diff(BaselineDiffArgs)` variant to `BaselineAction` (keeping `Compare` for backward compatibility)
    - [x] `BaselineDiffArgs` includes: `reference: Option<String>`, `ci: bool`, `threshold: SeverityLevel`, `tag: Option<String>`
    - [x] `sicario baseline diff --ci` exits 1 on new findings above threshold, exits 0 otherwise, exits 2 if no baseline exists
    - [x] `sicario baseline compare <reference>` retains existing behavior (prints delta in JSON/text, no CI exit code semantics)
    - [x] Add unit test: `diff --ci` with new High finding → exit 1; no new findings → exit 0; no baseline → exit 2

### 12.11 Wire `VerificationScanner` into Single-File `cmd_fix` (LOW)

- [x] **12.11 Wire `VerificationScanner` into Single-File `cmd_fix` (LOW)**
  - [x] **12.11 Wire `VerificationScanner` into Single-File `cmd_fix` (LOW)
**
  **File:** `sicario-cli/src/main.rs` — `cmd_fix` single-file path
    - [x] After applying a single-file patch and before printing the receipt, call `VerificationScanner::verify_fix` unless `args.no_verify` is set
    - [x] On `VerificationResult::StillPresent`: print `"[sicario] warning: vulnerability still detected after fix — manual review recommended"` and exit with code 1
    - [x] On `VerificationResult::NewFindingsIntroduced(fps)`: print `"[sicario] warning: fix introduced <N> new finding(s) — review the patch before committing"` and list the new fingerprints
    - [x] On `VerificationResult::Resolved`: proceed normally (print receipt, exit 0)
    - [x] Add unit test: `--no-verify` skips verification entirely; `StillPresent` prints warning and exits 1

### 12.12 Verify IPv4 Loopback in All Local LLM Probes (LOW)

- [x] **12.12 Verify IPv4 Loopback in All Local LLM Probes (LOW)**
  - [x] **12.12 Verify IPv4 Loopback in All Local LLM Probes (LOW)
**
  **File:** `sicario-cli/src/key_manager/manager.rs`
    - [x] Confirm `try_ollama_detection()` uses `http://127.0.0.1:11434/api/tags` (not `http://localhost:11434`)
    - [x] Confirm `try_lmstudio_detection()` uses `http://127.0.0.1:1234/v1/models` (not `http://localhost:1234`)
    - [x] Add a compile-time assertion or comment block documenting the IPv4 requirement (Req 10.1)
    - [x] Add unit test: mock server bound to `127.0.0.1` is detected; mock server bound to `::1` only is not detected (simulates IPv6-only localhost)

---

## Phase 13: Anonymous Usage Telemetry

### 13.1 Rust CLI — `usage_telemetry` Module

- [x] **13.1 Rust CLI — `usage_telemetry` Module**
  - [x] **13.1 Rust CLI — `usage_telemetry` Module
**
  - [x] Create `sicario-cli/src/usage_telemetry/mod.rs` with:
      - [x] `fire_usage_ping()` — public entry point; checks opt-out, spawns background thread, returns immediately
      - [x] `send_usage_ping() -> Option<()>` — private; computes hash, builds payload, fires HTTP POST; returns `None` on any failure (never panics, never logs)
      - [x] `compute_project_hash() -> Option<String>`:
        - [x] Run `git config --get remote.origin.url` via `std::process::Command`
        - [x] Return `None` if command fails, exits non-zero, or produces empty output
        - [x] Call `normalize_remote_url` on the raw output
        - [x] SHA-256 hash the normalized URL using the existing `sha2` crate
        - [x] Return the hex-encoded hash string
      - [x] `normalize_remote_url(url: &str) -> String`:
        - [x] Strip scheme: `https://`, `http://`, `git@`, `ssh://git@`
        - [x] Strip credentials: everything before and including `@`
        - [x] Normalize `git@github.com:org/repo` colon separator to `/`
        - [x] Strip trailing `.git`
        - [x] Lowercase the result
      - [x] `detect_environment() -> &'static str`:
        - [x] Return `"ci"` if any of `GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `TRAVIS`, `JENKINS_URL`, `BUILDKITE`, `DRONE`, `CI` env vars are set
        - [x] Return `"local"` otherwise
      - [x] Opt-out logic: return early from `fire_usage_ping` if `SICARIO_NO_TELEMETRY` env var is set OR `GlobalConfig::no_telemetry == Some(true)`
      - [x] HTTP client: use `reqwest::blocking::Client` with 5-second timeout; ignore response body and status code entirely
      - [x] Endpoint: `{resolve_cloud_url()}/api/v1/usage`
      - [x] Payload: `{ "event": "scan_run", "environment": "ci"|"local", "project_hash": "<hex>", "cli_version": env!("CARGO_PKG_VERSION") }`
    - [x] Add `mod usage_telemetry;` to `sicario-cli/src/main.rs`
    - [x] Add unit tests:
      - [x] `normalize_remote_url` handles HTTPS with credentials, SSH git@ format, trailing .git, mixed case
      - [x] `detect_environment` returns `"ci"` when `GITHUB_ACTIONS` is set; `"local"` when no CI vars present
      - [x] `compute_project_hash` returns `None` when not in a git repo
      - [x] `compute_project_hash` returns a 64-char hex string for a valid remote URL
      - [x] Two different URLs with same normalized form produce the same hash
      - [x] `SICARIO_NO_TELEMETRY=1` causes `fire_usage_ping` to return without spawning a thread (verify via mock)

### 13.2 Opt-Out Config Support

- [x] **13.2 Opt-Out Config Support**
  - [x] **13.2 Opt-Out Config Support
**
  - [x] Add `no_telemetry: Option<bool>` field to `GlobalConfig` in `sicario-cli/src/config/global_config.rs`
    - [x] Update `set_global_config_value` to handle `"no_telemetry"` key: parse `"true"`/`"false"` string to bool
    - [x] Add unit test: `set_global_config_value("no_telemetry", "true")` → `load_global_config().no_telemetry == Some(true)`

### 13.3 Wire into `cmd_scan`

- [x] **13.3 Wire into `cmd_scan`**
  - [x] **13.3 Wire into `cmd_scan`
**
  - [x] Add `crate::usage_telemetry::fire_usage_ping();` as the **first line** of `cmd_scan` in `main.rs`, before any scan work
    - [x] Add integration test: `cmd_scan` with mock HTTP server — verify the usage ping is sent to `/api/v1/usage` with correct payload shape; verify scan completes normally even if mock server is unreachable

### 13.4 Convex Backend — `usagePings` Table and Mutation

- [x] **13.4 Convex Backend — `usagePings` Table and Mutation**
  - [x] **13.4 Convex Backend — `usagePings` Table and Mutation
**
  - [x] Add `usagePings` table to `convex/convex/schema.ts`:
      - [x] Fields: `projectHash: v.string()`, `environment: v.union(v.literal("ci"), v.literal("local"))`, `cliVersion: v.string()`, `receivedAt: v.string()`
      - [x] Indexes: `by_projectHash` on `["projectHash"]`, `by_receivedAt` on `["receivedAt"]`
    - [x] Create `convex/convex/usagePings.ts` with:
      - [x] `record` mutation: inserts a new `usagePings` document
      - [x] `uniqueProjectCount` query: returns `COUNT(DISTINCT projectHash)` for dashboard display
      - [x] `recentActivity` query: returns ping counts grouped by day for the last 30 days

### 13.5 Convex Backend — `/api/v1/usage` HTTP Route

- [x] **13.5 Convex Backend — `/api/v1/usage` HTTP Route**
  - [x] **13.5 Convex Backend — `/api/v1/usage` HTTP Route
**
  - [x] Add `POST /api/v1/usage` route to `convex/convex/http.ts`:
      - [x] No authentication required
      - [x] Parse JSON body; silently ignore (return 204) if `event !== "scan_run"`
      - [x] Validate `project_hash` is a 64-char hex string; silently ignore if malformed
      - [x] Normalize `environment` to `"ci"` or `"local"` (default `"local"` for unknown values)
      - [x] Call `api.usagePings.record` mutation
      - [x] Always return HTTP 204 (no content), even on internal errors
      - [x] Add `OPTIONS /api/v1/usage` preflight handler for CORS
    - [x] Add unit test: valid payload → 204; malformed project_hash → 204; missing event field → 204; server error → 204

---

## Phase 14: Dynamic Terminal Notification System

### 14.1 Rust CLI — `notifications` Module

- [x] **14.1 Rust CLI — `notifications` Module**
  - [x] **14.1 Rust CLI — `notifications` Module
**
  - [x] Create `sicario-cli/src/notifications/mod.rs` with:
      - [x] `Notification` struct: `id: String`, `message: String`, `severity: NotificationSeverity`, `min_version: Option<String>`, `max_version: Option<String>`, `url: Option<String>`
      - [x] `NotificationSeverity` enum: `Info`, `Warning`, `Critical` — with `#[serde(rename_all = "lowercase")]`
      - [x] `spawn_notification_fetch() -> mpsc::Receiver<Vec<Notification>>`:
        - [x] Spawns a background thread that calls `fetch_notifications()`
        - [x] Sends result over the channel; returns receiver immediately
      - [x] `fetch_notifications() -> Vec<Notification>` (private):
        - [x] Build URL: `{resolve_cloud_url()}/api/v1/notifications?cli_version={CARGO_PKG_VERSION}`
        - [x] Use `reqwest::blocking::Client` with 3-second timeout
        - [x] Return empty `Vec` on any network error, non-200 response, or JSON parse failure
        - [x] Filter results: exclude notifications whose `id` is in `load_seen_ids()`
        - [x] Filter results: exclude notifications outside the current CLI version range (semver comparison using `semver` crate)
      - [x] `print_notifications(notifications: &[Notification])`:
        - [x] Print to `stderr` (never `stdout`)
        - [x] Print a blank line separator before the first notification
        - [x] `Info` → blue `ℹ` prefix using `owo-colors`
        - [x] `Warning` → yellow `⚠` prefix
        - [x] `Critical` → red bold `✖` prefix
        - [x] Print `url` on the next line with `  → ` prefix if present
      - [x] `mark_seen(notifications: &[Notification])`:
        - [x] Load existing seen IDs from `~/.sicario/seen_notifications.json`
        - [x] Add new IDs to the set
        - [x] Write back as JSON array
        - [x] Swallow all errors silently (file permission errors, disk full, etc.)
      - [x] `load_seen_ids() -> HashSet<String>` (private): reads `~/.sicario/seen_notifications.json`; returns empty set on any error
      - [x] `seen_notifications_path() -> Option<PathBuf>` (private): resolves `~/.sicario/seen_notifications.json` via `HOME`/`USERPROFILE`
    - [x] Add `mod notifications;` to `sicario-cli/src/main.rs`
    - [x] Add unit tests:
      - [x] `print_notifications` with empty slice → no output
      - [x] `print_notifications` with Info notification → blue prefix on stderr
      - [x] `print_notifications` with Critical notification → red bold prefix on stderr
      - [x] `mark_seen` writes IDs to file; subsequent `load_seen_ids` returns them
      - [x] `mark_seen` with unwritable path → no panic, no error output
      - [x] `fetch_notifications` filters out already-seen IDs
      - [x] `fetch_notifications` filters out notifications outside version range
      - [x] `fetch_notifications` returns empty vec when server is unreachable

### 14.2 Wire into `cmd_scan`

- [x] **14.2 Wire into `cmd_scan`**
  - [x] **14.2 Wire into `cmd_scan`
**
  - [x] At the start of `cmd_scan`, after `fire_usage_ping()`, add: `let notification_rx = crate::notifications::spawn_notification_fetch();`
    - [x] After all scan output is printed (after `format_output`, before `return Ok(exit_code)`), add:
      ```rust
      if !args.quiet {
          if let Ok(notifications) = notification_rx.try_recv() {
              crate::notifications::print_notifications(&notifications);
              crate::notifications::mark_seen(&notifications);
          }
      }
      ```
    - [x] Verify `--quiet` suppresses notifications (no `print_notifications` call)
    - [x] Verify `--format json` scan output on stdout is not contaminated (notifications go to stderr)
    - [x] Add integration test: mock server returns one notification → it appears after scan output on stderr; second run → notification not shown again (seen_notifications.json updated)

### 14.3 Convex Backend — `notifications` Table and Queries

- [x] **14.3 Convex Backend — `notifications` Table and Queries**
  - [x] **14.3 Convex Backend — `notifications` Table and Queries
**
  - [x] Add `notifications` table to `convex/convex/schema.ts`:
      - [x] Fields: `notificationId: v.string()`, `message: v.string()`, `severity: v.union(v.literal("info"), v.literal("warning"), v.literal("critical"))`, `minVersion: v.optional(v.string())`, `maxVersion: v.optional(v.string())`, `url: v.optional(v.string())`, `activeFrom: v.string()`, `activeTo: v.optional(v.string())`, `enabled: v.boolean()`
      - [x] Index: `by_enabled_activeFrom` on `["enabled", "activeFrom"]`
    - [x] Create `convex/convex/notifications.ts` with:
      - [x] `listActive` query: returns all notifications where `enabled == true` AND `activeFrom <= now` AND (`activeTo` is null OR `activeTo >= now`)
      - [x] `create` mutation (internal/admin): inserts a new notification document
      - [x] `disable` mutation (internal/admin): sets `enabled = false` by `notificationId`
 
### 14.4 Convex Backend — `/api/v1/notifications` HTTP Route

- [x] **14.4 Convex Backend — `/api/v1/notifications` HTTP Route**
  - [x] **14.4 Convex Backend — `/api/v1/notifications` HTTP Route
**
  - [x] Add `GET /api/v1/notifications` route to `convex/convex/http.ts`:
      - [x] No authentication required
      - [x] Read `cli_version` query parameter (default `"0.0.0"` if absent)
      - [x] Call `api.notifications.listActive` with current timestamp
      - [x] Filter by version range: exclude notifications where `minVersion > cli_version` or `maxVersion < cli_version` (semver comparison)
      - [x] Map to response shape: `{ id, message, severity, min_version, max_version, url }`
      - [x] Return HTTP 200 with JSON array; return `[]` on any internal error (never return non-200)
      - [x] Add `OPTIONS /api/v1/notifications` preflight handler
    - [x] Add unit tests: active notification returned; disabled notification excluded; expired notification excluded; version-filtered notification excluded; server error returns empty array

### 14.5 Seed Initial Notification

- [x] **14.5 Seed Initial Notification**
  - [x] **14.5 Seed Initial Notification
**
  - [x] Create a one-time seed script or Convex dashboard entry for the v2 Beta launch notification:
      ```json
      {
        "notificationId": "v2-beta-launch",
        "message": "Sicario v2 Beta is live — 10 new features including Ollama air-gapped fixes and Ghost Fix hooks.",
        "severity": "info",
        "minVersion": "0.9.0",
        "maxVersion": null,
        "url": "https://usesicario .xyz/changelog",
        "activeFrom": "<v2 release date>",
        "activeTo": null,
        "enabled": true
      }
      ```
    - [x] Verify the notification appears on first `sicario scan` after upgrading to v2
    - [x] Verify the notification does not appear on the second run (seen_notifications.json updated)

---

## Phase 15: Cross-Boundary Taint Analysis (`sicario scan --trace`)

### 15.1 Fix Cross-File Call Edge Resolution in `ReachabilityAnalyzer`

- [x] **15.1 Fix Cross-File Call Edge Resolution in `ReachabilityAnalyzer`**
  - [x] **15.1 Fix Cross-File Call Edge Resolution in `ReachabilityAnalyzer`
**
  **File:** `sicario-cli/src/engine/reachability.rs`
    - [x] In pass 2 of `build_call_graph`, replace the same-file-only callee lookup with a global search across all nodes: `self.call_graph.nodes.values().find(|n| n.name == callee_name)`
    - [x] Add a confidence filter: only wire the edge if exactly one node across all files has that function name (skip ambiguous matches to avoid false edges)
    - [x] Add unit test: two-file JS project where `handler` in `routes.js` calls `buildQuery` in `db.js` → edge is present in call graph after `build_call_graph`
    - [x] Add unit test: ambiguous callee name (same function name in two files) → no edge wired (conservative)

### 15.2 `TaintTrace` and `TaintTraceStep` Structs

- [x] **15.2 `TaintTrace` and `TaintTraceStep` Structs**
  - [x] **15.2 `TaintTrace` and `TaintTraceStep` Structs
**
  **File:** `sicario-cli/src/engine/reachability.rs`
    - [x] Add `TaintTraceStep` struct: `file: PathBuf`, `line: usize`, `function_name: String`, `description: String`
    - [x] Add `TaintTrace` struct: `steps: Vec<TaintTraceStep>`, `sink_rule_id: String`, `sink_file: PathBuf`, `sink_line: usize`
    - [x] Implement `TaintTrace::render() -> String` — produces the box-drawing terminal output with numbered steps, file paths, function names, and descriptions
    - [x] `render()` output goes to stderr (never stdout) to avoid contaminating `--format json`
    - [x] Add unit test: `TaintTrace::render()` with 3 steps produces correct box structure

### 15.3 `ReachabilityAnalyzer::trace_to_vulnerability`

- [x] **15.3 `ReachabilityAnalyzer::trace_to_vulnerability`**
  - [x] **15.3 `ReachabilityAnalyzer::trace_to_vulnerability`
**
  **File:** `sicario-cli/src/engine/reachability.rs`
    - [x] Implement `trace_to_vulnerability(&self, vuln: &Vulnerability) -> Option<TaintTrace>`:
      - [x] Find the enclosing function for the vulnerability using `find_enclosing_function`
      - [x] Iterate over all taint source IDs; call `bfs_path(source_id, vuln_fn_id)` for each
      - [x] Return the first path found as a `TaintTrace` with populated `TaintTraceStep` entries
      - [x] Return `None` if no path exists (vulnerability is not reachable from any taint source)
    - [x] Populate `TaintTraceStep::description` based on whether the node `is_taint_source` (first step) or is an intermediate node
    - [x] Add unit test: 3-node chain (source → middle → sink) → `trace_to_vulnerability` returns `Some(TaintTrace)` with 3 steps
    - [x] Add unit test: disconnected sink → returns `None`

### 15.4 `--trace` Flag and `cmd_scan` Integration

- [x] **15.4 `--trace` Flag and `cmd_scan` Integration**
  - [x] **15.4 `--trace` Flag and `cmd_scan` Integration
**
  **File:** `sicario-cli/src/cli/scan.rs` and `sicario-cli/src/main.rs`
    - [x] Add `trace: bool` field to `ScanArgs` with `#[arg(long)]`
    - [x] When `--trace` is set, call `scan_directory_with_reachability` instead of `scan_directory` in `cmd_scan`
    - [x] After standard finding output, for each finding above severity threshold, call `analyzer.trace_to_vulnerability(&vuln)`
    - [x] If a trace is found, call `trace.render()` and print to stderr
    - [x] If no trace is found, print `"  [trace] No taint path found for this finding"` to stderr
    - [x] With `--format json`, populate `finding.dataflow_trace` with the trace steps instead of printing to stderr
    - [x] With `--quiet`, suppress trace output entirely
    - [x] Add unit test: `--trace` on a two-file JS project with a known taint path → trace appears in output
    - [x] Add unit test: `--trace` with `--format json` → `dataflow_trace` field populated in JSON output

### 15.5 Performance Guard

- [x] **15.5 Performance Guard**
  - [x] **15.5 Performance Guard
**
  - [x] Add a timing assertion: `build_call_graph` on a 1,000-file project completes within 2 seconds (benchmark test)
    - [x] Add a cap: if the call graph has more than 50,000 nodes, skip trace generation and print `"[trace] Project too large for taint tracing — use --trace on a subdirectory"` to stderr
    - [x] Add language guard: if the finding is in a language other than JS/TS or Python, print `"[trace] Taint tracing not yet supported for <language>"` and skip

---

## Phase 16: Git Exorcist (`sicario exorcise`)

### 16.1 `GitExorcist` Core

- [x] **16.1 `GitExorcist` Core**
  - [x] **16.1 `GitExorcist` Core
**
  **File:** `sicario-cli/src/exorcist/mod.rs` (new module)
    - [x] Create `sicario-cli/src/exorcist/mod.rs` with:
      - [x] `GitExorcist` struct: `repo: git2::Repository`, `backup_manager: BackupManager`
      - [x] `ExorcistReceipt` struct: `commits_rewritten: usize`, `secrets_removed: usize`, `replacements: Vec<(String, String)>` (original var name → env var name)
      - [x] `GitExorcist::new(project_root: &Path) -> Result<Self>`: opens the git repo via `git2::Repository::discover`
      - [x] `GitExorcist::exorcise(since_ref: Option<&str>, dry_run: bool) -> Result<ExorcistReceipt>`

### 16.2 Pre-Flight Checks

- [x] **16.2 Pre-Flight Checks**
  - [x] **16.2 Pre-Flight Checks
**
  **File:** `sicario-cli/src/exorcist/mod.rs`
    - [x] Implement `check_working_tree_clean(&self) -> Result<()>`: run `self.repo.statuses(None)` and bail if any entry has a non-empty status
    - [x] Implement `count_unpushed_commits(&self) -> Result<usize>`: use `git2` revwalk from HEAD to `@{u}` (upstream); return 0 if no upstream is configured (treat all commits as local)
    - [x] Implement `collect_commits_to_rewrite(&self, since_ref: Option<&str>) -> Result<Vec<git2::Oid>>`: revwalk from HEAD to `since_ref` (or to the upstream base if `since_ref` is None); collect in oldest-first order; bail if count > 50
    - [x] Add unit test: clean working tree → check passes; dirty working tree → check fails with descriptive error
    - [x] Add unit test: 3 local commits → `collect_commits_to_rewrite` returns 3 OIDs in oldest-first order

### 16.3 Commit Rewrite Engine

- [x] **16.3 Commit Rewrite Engine**
  - [x] **16.3 Commit Rewrite Engine
**
  **File:** `sicario-cli/src/exorcist/mod.rs`
    - [x] Implement `rewrite_commit(&self, commit_oid: git2::Oid, new_parent: Option<git2::Oid>) -> Result<(git2::Oid, usize, Vec<(String, String)>)>`:
      - [x] Find the commit via `self.repo.find_commit(commit_oid)`
      - [x] Checkout the commit's tree to a `tempfile::tempdir()`
      - [x] Run `SecretScanner` on the temp directory to find secrets
      - [x] For each secret, apply the matching `PatchTemplate` (reuse `TemplateRegistry`) to replace the hardcoded value with `process.env.VAR_NAME`
      - [x] Build a new git tree from the patched temp directory using `git2::TreeBuilder`
      - [x] Create a new commit with the same author, committer, timestamp, and message but pointing to the new tree and the rewritten parent
      - [x] Return the new commit OID, count of secrets removed, and list of replacements
    - [x] Implement `checkout_tree_to_dir(&self, tree: &git2::Tree, dir: &Path) -> Result<()>`: walk the tree recursively and write blobs to the temp directory
    - [x] Implement `build_tree_from_dir(&self, dir: &Path, original_tree: &git2::Tree) -> Result<git2::Oid>`: walk the directory and create git blob objects for each file, then build a tree
    - [x] Add unit test: single commit with one hardcoded secret → rewrite produces a new commit OID, secret is replaced with `process.env.X`, original commit OID is unchanged

### 16.4 HEAD Update and Receipt

- [x] **16.4 HEAD Update and Receipt**
  - [x] **16.4 HEAD Update and Receipt
**
  **File:** `sicario-cli/src/exorcist/mod.rs`
    - [x] After all commits are rewritten, update HEAD to point to the final rewritten commit via `self.repo.find_reference("HEAD")?.set_target(final_oid, "sicario exorcise")`
    - [x] Implement `ExorcistReceipt::render() -> String` — produces the box-drawing receipt (same style as `PatchReceipt`) showing commits rewritten, secrets removed, and replacement mappings
    - [x] Add the `⚠ History has been rewritten` warning to the receipt output
    - [x] Add unit test: receipt renders correctly with known values

### 16.5 `--dry-run` Mode

- [x] **16.5 `--dry-run` Mode**
  - [x] **16.5 `--dry-run` Mode
**
  **File:** `sicario-cli/src/exorcist/mod.rs`
    - [x] Implement `dry_run_report(&self, commits: &[git2::Oid]) -> Result<ExorcistReceipt>`:
      - [x] For each commit, checkout to temp dir and scan for secrets (same as rewrite, but don't create new commits)
      - [x] Return a receipt with `commits_rewritten: 0` and the list of secrets that would be removed
    - [x] Print `"[dry-run] No changes made to git history"` at the end of dry-run output
    - [ ] Add unit test: dry-run on a repo with 2 secrets → receipt shows 2 secrets, git log is unchanged

### 16.6 CLI Entry Point

- [x] **16.6 CLI Entry Point**
  - [x] **16.6 CLI Entry Point
**
  **File:** `sicario-cli/src/cli/mod.rs` and `sicario-cli/src/main.rs`
    - [x] Add `Exorcise(ExorciseArgs)` variant to the `Command` enum in `cli/mod.rs`
    - [x] Define `ExorciseArgs` in `sicario-cli/src/cli/exorcise.rs`:
      - [x] `--dry-run: bool` — scan and report without rewriting
      - [x] `--since <ref>: Option<String>` — limit rewrite to commits after this ref
      - [x] `--yes: bool` — skip confirmation prompt
    - [x] Implement `cmd_exorcise(args: ExorciseArgs) -> Result<ExitCode>` in `main.rs`:
      - [x] Run pre-flight checks; print descriptive errors and exit 2 on failure
      - [x] Unless `--yes` or `--dry-run`, print a confirmation prompt: `"This will rewrite your local git history. Proceed? [y/N]"` and require `y`
      - [x] Call `GitExorcist::exorcise(args.since.as_deref(), args.dry_run)`
      - [x] Print the receipt
      - [x] Exit 0 on success
    - [x] Add `mod exorcist;` to `main.rs`
    - [x] Add integration test: `sicario exorcise --dry-run` on a test repo with a hardcoded secret → prints receipt, git log unchanged

---

## Phase 17: NLP-to-AST Rule Compiler (`sicario rule`)

### 17.1 `RuleCompiler` Core

- [x] **17.1 `RuleCompiler` Core**
  - [x] **17.1 `RuleCompiler` Core
**
  **File:** `sicario-cli/src/rule_compiler/mod.rs` (new module)
    - [x] Create `sicario-cli/src/rule_compiler/mod.rs` with:
      - [x] `RuleCompiler` struct: `ollama: OllamaClient`, `engine: SastEngine`
      - [x] `RuleIntent` struct: `target_construct: String`, `condition: String`, `language: Language`, `cwe: Option<String>`
      - [x] `RuleCompiler::compile(description: &str, language: Language, severity: Severity) -> Result<SecurityRule>`

### 17.2 Stage 1 — Intent Extraction

- [x] **17.2 Stage 1 — Intent Extraction**
  - [x] **17.2 Stage 1 — Intent Extraction
**
  **File:** `sicario-cli/src/rule_compiler/mod.rs`
    - [x] Implement `extract_intent(description: &str, language: Language, ollama: &OllamaClient) -> Result<RuleIntent>`:
      - [x] Build a system prompt instructing the model to return ONLY a JSON object with `target_construct`, `condition`, `language`, `cwe` fields
      - [x] Set `temperature: 0.0`, `max_tokens: 256`
      - [x] Parse the response as JSON; bail with descriptive error if parsing fails
      - [x] Validate that `language` in the response matches the requested language (or override if the description implies a different language)
    - [x] Add unit test: `"Prevent console.log with token variable"` → `RuleIntent { target_construct: "call_expression", condition: "console.log with identifier named token", language: JavaScript, cwe: None }`

### 17.3 Stage 2 — Query Generation with Validation Loop

- [x] **17.3 Stage 2 — Query Generation with Validation Loop**
  - [x] **17.3 Stage 2 — Query Generation with Validation Loop
**
  **File:** `sicario-cli/src/rule_compiler/mod.rs`
    - [x] Implement `generate_query(intent: &RuleIntent, language: Language, ollama: &OllamaClient, prior_error: &str) -> Result<String>`:
      - [x] Build a system prompt with: the intent, the language, a list of common tree-sitter node types for that language, and the prior error (if any)
      - [x] Instruct the model to return ONLY the raw tree-sitter query string (no markdown, no explanation)
      - [x] Set `temperature: 0.0`, `max_tokens: 512`
      - [x] Strip any markdown fences from the response using `strip_markdown_fences`
    - [x] Implement the 3-attempt validation loop in `RuleCompiler::compile`:
      - [x] Attempt 1: call `generate_query` with empty `prior_error`
      - [x] Validate by calling `engine.validate_and_compile_rule(test_rule)` — this compiles the tree-sitter query
      - [x] On failure: extract the error message, pass it as `prior_error` to the next attempt
      - [x] On 3rd failure: bail with `"Failed to generate a valid tree-sitter query after 3 attempts. Try rephrasing."`
    - [x] Add unit test: valid query on first attempt → returns `SecurityRule` with correct fields
    - [x] Add unit test: invalid query on first attempt, valid on second → returns `SecurityRule` after retry
    - [x] Add unit test: 3 consecutive invalid queries → returns `Err`

### 17.4 Rule Persistence

- [x] **17.4 Rule Persistence**
  - [x] **17.4 Rule Persistence
**
  **File:** `sicario-cli/src/rule_compiler/mod.rs`
    - [x] Implement `save_rule(rule: &SecurityRule, project_root: &Path) -> Result<PathBuf>`:
      - [x] Create `.sicario/rules/` directory if it doesn't exist
      - [x] Generate filename from rule ID: `slugify(rule.id)` + `.yaml`
      - [x] Serialize the rule as a YAML array (`[rule]`) using `serde_yaml`
      - [x] Write to `.sicario/rules/<slug>.yaml`
      - [x] Return the path
    - [x] Implement `slugify(s: &str) -> String`: replace non-alphanumeric chars with `-`, lowercase, strip leading/trailing `-`
    - [x] Add unit test: `save_rule` writes a valid YAML file that can be loaded back by `SastEngine::load_rules`

### 17.5 Auto-Load `.sicario/rules/` on Scan

- [x] **17.5 Auto-Load `.sicario/rules/` on Scan**
  - [x] **17.5 Auto-Load `.sicario/rules/` on Scan
**
  **File:** `sicario-cli/src/main.rs` — `cmd_scan`
    - [x] After loading embedded rules and `--rules-dir` rules, check if `.sicario/rules/` exists in the project root
    - [x] If it exists, call `engine.load_rules` for each `.yaml` file in the directory
    - [x] Print `"[sicario] Loaded N custom rules from .sicario/rules/"` (suppressed with `--quiet`)
    - [x] Add unit test: `.sicario/rules/custom.yaml` with a valid rule → rule is active during scan

### 17.6 CLI Entry Point

- [x] **17.6 CLI Entry Point**
  - [x] **17.6 CLI Entry Point
**
  **File:** `sicario-cli/src/cli/mod.rs` and `sicario-cli/src/main.rs`
    - [x] Add `Rule(RuleArgs)` variant to the `Command` enum
    - [x] Define `RuleArgs` in `sicario-cli/src/cli/rule.rs`:
      - [x] `description: String` — positional argument (the natural language description)
      - [x] `--lang <language>: Option<String>` — target language (default: auto-detect from project)
      - [x] `--severity <level>: Option<SeverityLevel>` — default: High
      - [x] `--dry-run: bool` — generate and print the query without saving
    - [x] Implement `cmd_rule(args: RuleArgs) -> Result<ExitCode>` in `main.rs`:
      - [x] Validate description length ≤ 200 characters
      - [x] Probe Ollama (`OllamaClient::probe`); print setup instructions and exit 2 if not available
      - [x] Resolve language from `--lang` flag or auto-detect from project files
      - [x] Print progress: `"[sicario] Compiling rule from: \"<description>\""`
      - [x] Call `RuleCompiler::compile`
      - [x] If `--dry-run`: print the generated query and exit 0 without saving
      - [x] Otherwise: call `save_rule` and print the success summary
      - [x] Exit 0 on success, exit 1 on compilation failure
    - [x] Add `mod rule_compiler;` to `main.rs`
    - [x] Add integration test: `sicario rule "Detect eval usage" --lang javascript --dry-run` with mock Ollama → prints a tree-sitter query containing `eval`, exits 0, no file written

---

## Phase 18: Shadow Pen-Tester (`sicario attack --local`)

### 18.1 `RouteExtractor` — AST-Based Route Discovery

- [x] **18.1 `RouteExtractor` — AST-Based Route Discovery**
  - [x] **18.1 `RouteExtractor` — AST-Based Route Discovery
**
  **File:** `sicario-cli/src/attack/route_extractor.rs` (new module)
    - [x] Create `sicario-cli/src/attack/mod.rs` and `route_extractor.rs`
    - [x] Define `ExtractedRoute` struct: `method: HttpMethod`, `path: String`, `handler_file: PathBuf`, `handler_line: usize`, `handler_function: String`, `parameters: Vec<RouteParameter>`
    - [x] Define `RouteParameter` struct: `name: String`, `location: ParamLocation` (Path/Query/Body/Header), `inferred_type: ParamType` (String/Number/Boolean/Object)
    - [x] Implement `RouteExtractor::extract(project_root: &Path) -> Result<Vec<ExtractedRoute>>`:
      - [x] Express.js: tree-sitter query matching `app.get/post/put/delete/patch('/path', handler)` — extract method, path string, and handler function name
      - [x] FastAPI: tree-sitter query matching `@app.get('/path')` decorator on async function — extract method, path, and function parameters
      - [x] Flask: tree-sitter query matching `@app.route('/path', methods=['GET'])` — extract method list and path
      - [x] For each route, scan the handler function body for `req.query.X`, `req.body.X`, `req.params.X` (Express) or function parameter annotations (FastAPI) to extract parameter names and locations
      - [x] Return `None` for unsupported frameworks (no error, just empty list)
    - [x] Add unit tests:
      - [x] Express.js file with 3 routes → `extract` returns 3 `ExtractedRoute` entries with correct methods and paths
      - [x] FastAPI file with 2 routes → correct extraction
      - [x] File with no routes → empty list, no error
      - [x] Route with path params (`:id`) → `RouteParameter` with `location: Path`

### 18.2 `AttackPayloadGenerator` — Bind PocPayloads to Routes

- [x] **18.2 `AttackPayloadGenerator` — Bind PocPayloads to Routes**
  - [x] **18.2 `AttackPayloadGenerator` — Bind PocPayloads to Routes
**
  **File:** `sicario-cli/src/attack/payload_generator.rs`
    - [x] Implement `AttackPayloadGenerator::generate(route: &ExtractedRoute, finding: &Vulnerability) -> Vec<AttackPayload>`:
      - [x] For each `RouteParameter` in the route, generate a targeted payload for the finding's CWE
      - [x] SQL injection (CWE-89): `' OR SLEEP(5)--` (MySQL), `'; SELECT pg_sleep(5)--` (PostgreSQL), `' WAITFOR DELAY '0:0:5'--` (SQL Server) — detect DB from AST imports
      - [x] Command injection (CWE-78): `; sleep 4`
      - [x] Path traversal (CWE-22): `../../../../etc/hostname`
      - [x] XSS (CWE-79): `<script>sicario_xss_probe_${timestamp}</script>`
      - [x] SSRF (CWE-918): `http://127.0.0.1:${probe_port}/ssrf-probe` (spawn `SsrfProbeListener`)
      - [x] Also generate a benign baseline payload for each parameter (empty string, `"test"`, `1`)
    - [x] Enforce safety constraints in Rust (not documentation):
      - [x] Reject any payload URL that does not resolve to `127.0.0.1` or `::1`
      - [x] Reject any SQL payload containing `DROP`, `DELETE`, `TRUNCATE`, `UPDATE`, `INSERT`, `ALTER`
    - [x] Add unit tests:
      - [x] SQL injection finding + Express route with body param → payload contains `SLEEP` or `pg_sleep`
      - [x] Destructive SQL keyword in generated payload → rejected before return
      - [x] Non-localhost URL in SSRF payload → rejected before return

### 18.3 `LocalAttackRunner` — HTTP Execution Engine

- [x] **18.3 `LocalAttackRunner` — HTTP Execution Engine**
  - [x] **18.3 `LocalAttackRunner` — HTTP Execution Engine
**
  **File:** `sicario-cli/src/attack/runner.rs`
    - [x] Define `AttackResult` struct: `route`, `payload`, `confirmed: bool`, `detection_method: DetectionMethod`, `response_time_ms: u64`, `baseline_time_ms: u64`, `status_code: u16`, `response_snippet: String`, `mapped_finding: Option<Vulnerability>`
    - [x] Define `DetectionMethod` enum: `TimingDelta { delta_ms: u64 }`, `StatusCode500 { body_snippet: String }`, `ReflectionDetected { probe: String }`, `SsrfProbeReceived`
    - [x] Implement `LocalAttackRunner::run(target: &str, routes: &[ExtractedRoute], findings: &[Vulnerability], timeout_secs: u64) -> Result<Vec<AttackResult>>`:
      - [x] For each (route, finding) pair, call `AttackPayloadGenerator::generate`
      - [x] Fire baseline request first; record response time and status
      - [x] Fire malicious payload; record response time, status, first 200 chars of body
      - [x] Detection logic:
        - [x] `response_time_ms > baseline_time_ms + 4000` → `TimingDelta` confirmed
        - [x] `status_code == 500` → `StatusCode500` confirmed
        - [x] Response body contains XSS probe string → `ReflectionDetected` confirmed
        - [x] `SsrfProbeListener` received connection → `SsrfProbeReceived` confirmed
      - [x] Attacks fire sequentially (not parallel) to preserve timing accuracy
      - [x] Per-request timeout: `timeout_secs` (default 10)
      - [x] Use `reqwest::blocking::Client` — no async needed for sequential execution
    - [x] Add unit tests with mock HTTP server:
      - [x] Server that delays 5 seconds on SQL payload → `TimingDelta` confirmed
      - [x] Server that returns 500 on injection → `StatusCode500` confirmed
      - [x] Server that echoes XSS probe → `ReflectionDetected` confirmed
      - [x] Server unreachable → result marked inconclusive, no panic

### 18.4 Pre-Flight Checks and CLI Entry Point

- [x] **18.4 Pre-Flight Checks and CLI Entry Point**
  - [x] **18.4 Pre-Flight Checks and CLI Entry Point
**
  **File:** `sicario-cli/src/cli/attack.rs` and `sicario-cli/src/main.rs`
    - [x] Define `AttackArgs` in `sicario-cli/src/cli/attack.rs`:
      - [x] `--target <url>: String` — default `http://localhost:3000`
      - [x] `--timeout <seconds>: u64` — default 10
      - [x] `--dry-run: bool` — extract routes and generate payloads, do not fire requests
      - [x] `--yes: bool` — skip confirmation prompt
    - [x] Implement `cmd_attack(args: AttackArgs) -> Result<ExitCode>` in `main.rs`:
      - [x] Pre-flight 1: validate target URL is `localhost` or `127.0.0.1` — exit 2 with error if not
      - [x] Pre-flight 2: probe `GET /` on target with 2-second timeout — exit 2 with `"Target server not responding"` if no response
      - [x] Pre-flight 3: unless `--yes` or `--dry-run`, print confirmation prompt and require `y`
      - [x] Run `sicario scan` on current directory to get findings
      - [x] Run `RouteExtractor::extract` on current directory
      - [x] If `--dry-run`: print extracted routes and generated payloads, exit 0
      - [x] Run `LocalAttackRunner::run`
      - [x] Print attack receipt for each confirmed vulnerability
      - [x] For each confirmed vulnerability, offer to apply deterministic patch (same as `cmd_fix`)
      - [x] Exit 0 if no confirmed vulnerabilities; exit 1 if any confirmed
    - [x] Add `Attack(AttackArgs)` variant to `Command` enum in `cli/mod.rs`
    - [x] Add `mod attack;` to `main.rs`
    - [x] Add integration test: `sicario attack --local --dry-run` on a project with Express routes → prints route list, exits 0, no HTTP requests fired

---

## Phase 19: Poison-Pill Interceptor (`sicario guard`)

### 19.1 Behavioral Anomaly Rules

- [x] **19.1 Behavioral Anomaly Rules**
  - [x] **19.1 Behavioral Anomaly Rules
**
  **File:** `sicario-cli/src/guard/behavioral_rules.rs` (new module)
    - [x] Create `sicario-cli/src/guard/mod.rs` and `behavioral_rules.rs`
    - [x] Define `AnomalySignal` enum: `UnexpectedChildProcess`, `UnexpectedNetworkAccess`, `UnexpectedFilesystemAccess`, `ObfuscatedEval`, `Base64DecodedEval`, `PostInstallCredentialHarvest`, `HexEncodedPayload`, `DynamicRequire`
    - [x] Define `BehavioralAnomaly` struct: `signal: AnomalySignal`, `severity: Severity`, `file: PathBuf`, `line: usize`, `snippet: String`, `description: String`
    - [x] Implement `behavioral_rules() -> Vec<SecurityRule>` — returns the fixed set of behavioral anomaly rules as `SecurityRule` structs with embedded tree-sitter queries:
      - [x] `guard/unexpected-child-process`: `require('child_process')` in any JS/TS file — Critical
      - [x] `guard/unexpected-net-access`: `require('net')` or `require('http')` — High
      - [x] `guard/unexpected-fs-access`: `require('fs')` or `require('fs/promises')` — High
      - [x] `guard/obfuscated-eval`: `eval()` with non-literal argument (identifier, call_expression, binary_expression) — Critical
      - [x] `guard/process-env-access`: `process.env.X` access — High
      - [x] `guard/dynamic-require`: `require(variable)` where argument is not a string literal — Medium
      - [x] `guard/hex-encoded-string`: string literal matching `/^[0-9a-f]{100,}$/i` — High
    - [x] Add unit tests: each rule fires on a matching snippet; does not fire on a clean snippet

### 19.2 `BehavioralScanner`

- [x] **19.2 `BehavioralScanner`**
  - [x] **19.2 `BehavioralScanner`
**
  **File:** `sicario-cli/src/guard/behavioral_scanner.rs`
    - [x] Implement `BehavioralScanner::scan_package(package_dir: &Path) -> Result<Vec<BehavioralAnomaly>>`:
      - [x] Create a `SastEngine` instance loaded with `behavioral_rules()` only
      - [x] Call `engine.scan_directory(package_dir)` to get `Vec<Vulnerability>`
      - [x] Map each `Vulnerability` to a `BehavioralAnomaly` using the rule ID to determine `AnomalySignal`
      - [x] Read `package.json` from `package_dir` to get `name`, `version`, `keywords`, `description`
      - [x] Apply category filter: if the package's keywords include `http`, `request`, `network`, `fetch`, suppress `UnexpectedNetworkAccess` anomalies (legitimate HTTP client packages)
      - [x] Apply category filter: if keywords include `fs`, `file`, `io`, `stream`, suppress `UnexpectedFilesystemAccess` anomalies
      - [x] Return remaining anomalies sorted by severity (Critical first)
    - [x] Add unit tests:
      - [x] Package with `require('child_process')` → `UnexpectedChildProcess` anomaly returned
      - [x] HTTP client package (keywords: `["http", "request"]`) with `require('http')` → anomaly suppressed
      - [x] Clean math package → empty anomaly list
      - [x] Package with `eval(Buffer.from(hex).toString())` → `ObfuscatedEval` anomaly returned

### 19.3 Quarantine Mechanism

- [x] **19.3 Quarantine Mechanism**
  - [x] **19.3 Quarantine Mechanism
**
  **File:** `sicario-cli/src/guard/quarantine.rs`
    - [x] Define `QuarantineRecord` struct: `quarantined_at: String`, `package_name: String`, `version: String`, `ecosystem: String`, `anomalies: Vec<BehavioralAnomaly>`, `action: QuarantineAction`
    - [x] Define `QuarantineAction` enum: `Renamed`, `Flagged` (flagged but not renamed)
    - [x] Implement `QuarantineManager::quarantine(package_dir: &Path, anomalies: &[BehavioralAnomaly], auto_quarantine: bool) -> Result<QuarantineRecord>`:
      - [x] If `auto_quarantine`: rename `package_dir` to `{package_dir}.sicario-quarantined`
      - [x] Append `QuarantineRecord` to `.sicario/quarantine.json` (append-only, never overwrite)
      - [x] Return the record
    - [x] Implement `QuarantineManager::list(project_root: &Path) -> Result<Vec<QuarantineRecord>>`: reads `.sicario/quarantine.json`
    - [x] Add unit tests:
      - [x] `quarantine` with `auto_quarantine: true` → directory renamed, record written
      - [x] `quarantine` with `auto_quarantine: false` → directory not renamed, record written
      - [x] `list` returns all records from `.sicario/quarantine.json`
      - [x] Append-only: calling `quarantine` twice → two records in file, not one

### 19.4 Filesystem Watcher (`sicario guard` persistent mode)

- [x] **19.4 Filesystem Watcher (`sicario guard` persistent mode)**
  - [x] **19.4 Filesystem Watcher (`sicario guard` persistent mode)
**
  **File:** `sicario-cli/src/guard/watcher.rs`
    - [x] Implement `PackageWatcher::watch(cache_dir: &Path, project_root: &Path, auto_quarantine: bool)`:
      - [x] Use the existing `notify` crate (already a workspace dependency) to watch `cache_dir` for `Create` events on `.js`, `.ts`, `.py` files
      - [x] Debounce: 200ms (same as `--watch` mode)
      - [x] On new file: determine package name and version from the file path
      - [x] Call `BehavioralScanner::scan_package` on the package directory
      - [x] If Critical anomalies found: print quarantine alert, call `QuarantineManager::quarantine`
      - [x] If High anomalies found: print warning (no auto-quarantine unless `--auto-quarantine`)
      - [x] If clean: silent
      - [x] Handle `Ctrl+C` (SIGINT) with clean exit and summary: `"Sicario Guard: monitored N packages, flagged M"`
    - [x] Implement `resolve_npm_cache_dir() -> Option<PathBuf>`: check `node_modules/` in project root first, then `~/.npm/_npx`
    - [x] Add unit tests:
      - [x] Watcher detects new file in watched directory → `BehavioralScanner::scan_package` called
      - [x] Critical anomaly → quarantine alert printed, `QuarantineManager::quarantine` called
      - [x] Clean package → no output

### 19.5 `sicario guard scan` — One-Shot Mode

- [x] **19.5 `sicario guard scan` — One-Shot Mode**
  - [x] **19.5 `sicario guard scan` — One-Shot Mode
**
  **File:** `sicario-cli/src/main.rs`
    - [x] Implement `cmd_guard_scan(project_root: &Path, auto_quarantine: bool) -> Result<ExitCode>`:
      - [x] Resolve `node_modules/` directory in `project_root`
      - [x] Enumerate all package directories in `node_modules/` (top-level only, not nested)
      - [x] For each package, call `BehavioralScanner::scan_package`
      - [x] Print progress: `"Scanning N packages in node_modules/..."`
      - [x] Print summary table: package name, version, severity, anomaly description
      - [x] For Critical packages: call `QuarantineManager::quarantine` if `--auto-quarantine`
      - [x] Exit 1 if any Critical anomalies found; exit 0 otherwise
    - [x] Add integration test: `node_modules/` with one clean package and one package containing `require('child_process')` → exit 1, flagged package listed

### 19.6 CLI Entry Point

- [x] **19.6 CLI Entry Point**
  - [x] **19.6 CLI Entry Point
**
  **File:** `sicario-cli/src/cli/guard.rs` and `sicario-cli/src/main.rs`
    - [x] Define `GuardCommand` in `sicario-cli/src/cli/guard.rs` with subcommands:
      - [x] `Watch(GuardWatchArgs)`: `--pm <npm|pip|cargo>` (default: npm), `--project <path>`, `--auto-quarantine: bool`
      - [x] `Scan(GuardScanArgs)`: `--dir <path>` (default: `./node_modules`), `--auto-quarantine: bool`
      - [x] `List`: list all quarantined packages from `.sicario/quarantine.json`
      - [x] `Restore(GuardRestoreArgs)`: `package_name: String` — rename `<name>.sicario-quarantined` back to `<name>`
    - [x] Implement `cmd_guard(args: GuardCommand) -> Result<ExitCode>` in `main.rs`
    - [x] Add `Guard(GuardCommand)` variant to `Command` enum in `cli/mod.rs`
    - [x] Add `mod guard;` to `main.rs`
    - [x] Add integration test: `sicario guard scan` on a directory with a clean `node_modules/` → exit 0, `"N packages clean"` printed
    - [x] Add integration test: `sicario guard list` with no quarantine records → `"No packages quarantined"` printed
