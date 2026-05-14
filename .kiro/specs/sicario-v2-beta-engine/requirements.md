# Requirements Document

## Introduction

Sicario v2 Beta Engine ships ten tightly scoped, high-impact capabilities across two tracks: five developer-facing features that transform Sicario into an air-gapped autonomous security engineer, and five enterprise-facing features that give CISOs the compliance evidence, policy enforcement, and operational metrics they need to justify procurement and pass audits.

**Developer track:**

1. **Ollama Air-Gapped Fallback (`--agent=local`)** — Local LLM remediation constrained by a deterministic cage: micro-context targeting, structured JSON output protocol, and tree-sitter verification loop. 100% air-gapped AI auto-remediation.

2. **Multi-Line AST SQL Rewrite (`SqlAstRewriteTemplate`)** — tree-sitter-powered rewrite of multi-line SQL injection patterns into parameterized queries. Deterministic, verified, never breaks surrounding code.

3. **Ghost Fix Pre-Commit Hook (`sicario hook --install --auto-fix`)** — Silently applies deterministic fixes to staged files and re-stages them before the commit lands. Invisible remediation.

4. **Proof-of-Concept Generation (`sicario scan --prove`)** — Generates benign, time-based exploit payloads targeting localhost to prove vulnerabilities are real. Eliminates the false-positive argument.

5. **Security Regression Guard (`sicario baseline diff --ci`)** — CI exits with code 1 only on new findings. Existing debt never blocks the build. The first SAST tool that doesn't punish teams for technical debt.

**Enterprise track:**

6. **Compliance Evidence Export (`sicario report --compliance`)** — Single-command SOC 2 / ISO 27001 audit package: remediation log, suppression log, baseline history, MTTR by rule, SARIF export.

7. **Policy-as-Code Enforcement (`sicario policy`)** — `.sicario/policy.yaml` defines org-wide rules that override all local flags. Required rules cannot be suppressed. Blocked suppressions fail CI.

8. **MTTR Tracking and Board-Ready Report (`sicario report --mttr`)** — Computes Mean Time to Remediate per vulnerability class with trend indicators. JSON output for Datadog/Splunk ingestion.

9. **Suppression Audit Log (`sicario suppressions audit`)** — Complete git-attributed audit trail of every `sicario-ignore` directive: who added it, when, for which rule. CSV/JSON export for SIEM/GRC platforms.

10. **Dependency License Risk Scanner (`sicario scan --licenses`)** — Flags GPL, AGPL, SSPL dependencies in proprietary codebases. Three-tier risk classification. Allowlist support for reviewed exceptions.

All ten features maintain the zero-exfiltration guarantee: no source code leaves the machine unless `--allow-ai` with a cloud provider is explicitly set.

---

## Glossary

- **Agent**: The remediation backend selected by the `--agent` flag. Valid values: `local`, `local-<model>`, `cloud`.
- **AgentSelector**: The CLI argument parser and routing component that reads the `--agent` flag and configures the `RemediationEngine` accordingly.
- **OllamaClient**: The component responsible for probing the local Ollama instance, selecting a model, and routing fix requests to `http://127.0.0.1:11434/v1/chat/completions`.
- **MicroContextExtractor**: The component that uses the existing tree-sitter AST to extract only the vulnerable function block and the locally-scoped variable names — never the full file — before constructing the LLM prompt.
- **LocalLlmPrompt**: The structured prompt sent to the local model. Contains: the vulnerability class, the vulnerable AST node text, the list of in-scope variable names, and a strict instruction to return only a JSON object with a `replacement` field.
- **TreeSitterVerificationLoop**: The post-generation validation pipeline that parses the LLM's output back through tree-sitter, checks for syntax errors, checks for error nodes, and checks that all referenced identifiers exist in the extracted scope. Any failure causes the output to be discarded and the fallback chain to continue.
- **RemediationEngine**: The existing orchestrator that coordinates template lookup → LLM fallback → patch application.
- **TemplateRegistry**: The existing map of rule IDs and CWE numbers to `PatchTemplate` implementations.
- **PatchTemplate**: The existing trait with `generate_patch(&self, vulnerable_line: &str, lang: Language) -> Option<String>`.
- **MultiLinePatchTemplate**: A new trait that extends `PatchTemplate` by receiving the full file content and the vulnerable line number, enabling AST-level multi-line rewrites.
- **SqlAstRewriteTemplate**: The new `MultiLinePatchTemplate` implementation that rewrites SQL injection patterns using tree-sitter.
- **HookManager**: The existing component that manages `.git/hooks/pre-commit` using `BEGIN SICARIO HOOK` / `END SICARIO HOOK` markers.
- **AutoFixHook**: The new pre-commit hook script variant installed by `sicario hook --install --auto-fix`.
- **GhostFix**: The user-facing name for the auto-fix pre-commit hook capability.
- **PatchReceipt**: The existing receipt struct printed after every successful patch, containing `tokens_burned` and `lines_exfiltrated` fields.
- **ZeroExfiltrationGuarantee**: The invariant that no source code is transmitted to any remote endpoint unless `--allow-ai` with a cloud provider is explicitly set by the user.
- **StagedDiff**: The set of files added to the Git index via `git add` that are pending commit.
- **DeterministicFix**: A fix produced by a `PatchTemplate` or `MultiLinePatchTemplate` without any LLM call.
- **ParameterizedQuery**: A SQL query that uses positional placeholders (`$1`, `%s`, `?`) and passes user-supplied values as a separate argument array, preventing SQL injection.
- **TreeSitter**: The existing incremental parsing library used throughout the codebase for AST analysis.
- **PreferredLocalModels**: The ordered list of coding-specialized models recommended for local use: `qwen2.5-coder:7b` (first preference), `deepseek-coder-v2` (second preference). General-purpose models such as `llama3` are not recommended for code transformation tasks.
- **PocGenerator**: The component that uses the tree-sitter AST to extract route metadata (HTTP method, path, parameter names, injection point) and generates a benign, time-based exploit payload targeting localhost.
- **PocPayload**: A generated proof-of-concept exploit. Always targets `127.0.0.1` or `localhost`. Always uses time-based or echo-based techniques — never destructive SQL operations, never real metadata endpoints.
- **SsrfProbeListener**: A short-lived TCP listener that Sicario spawns on a random local port to catch SSRF proof-of-concept requests. Used instead of real external URLs to prevent credential exposure.
- **BaselineManager**: The existing `baseline/manager.rs` component that saves and compares scan snapshots using stable finding fingerprints.
- **BaselineDelta**: The result of comparing a current scan against a saved baseline: three disjoint sets — new findings (introduced since baseline), resolved findings (present in baseline but not current scan), and unchanged findings.
- **RegressionGuard**: The `--ci` mode of `sicario baseline diff` that exits with code 1 only when new findings above the severity threshold are present, ignoring unchanged findings from the baseline.

---

## Requirements

### Requirement 1: `--agent` Flag on `sicario fix`

**User Story:** As a security engineer, I want to select the remediation backend via a `--agent` flag, so that I can explicitly control whether fixes use a local model or a cloud provider.

#### Acceptance Criteria

1. THE `AgentSelector` SHALL accept a `--agent` flag on the `sicario fix` command with valid values: `local`, `local-<model>` (where `<model>` is any non-empty string), and `cloud`.
2. WHEN `--agent=cloud` is specified, THE `RemediationEngine` SHALL use the existing cloud key resolution chain (env vars, keyring, config file) unchanged.
3. WHEN `--agent=local` is specified, THE `RemediationEngine` SHALL bypass all cloud key resolution steps and route LLM fallback calls exclusively to the local Ollama endpoint at `http://127.0.0.1:11434/v1/chat/completions`.
4. WHEN `--agent=local-<model>` is specified, THE `AgentSelector` SHALL extract the model name from the flag value and pass it as the `model_override` to the `OllamaClient`, overriding any auto-detected model.
5. WHEN `--agent` is not specified, THE `RemediationEngine` SHALL preserve the existing resolution behavior (auto-detect Ollama, then cloud providers) with no change to current behavior.
6. THE `AgentSelector` SHALL reject any `--agent` value that does not match `local`, `local-<model>`, or `cloud`, and SHALL print a descriptive error message listing the valid values.
7. WHERE `--agent=local` or `--agent=local-<model>` is set, THE `AgentSelector` SHALL treat the session as having `--allow-ai` implicitly enabled for the local model only, so the AI-fallback consent guardrail is not triggered for local calls.

---

### Requirement 2: Ollama Connectivity and Model Selection

**User Story:** As a security engineer using `--agent=local`, I want Sicario to connect to my running Ollama instance and select the correct model, so that fixes are generated locally without any network egress.

#### Acceptance Criteria

1. WHEN `--agent=local` is specified, THE `OllamaClient` SHALL probe `http://127.0.0.1:11434/api/tags` with a timeout of 500 milliseconds to verify Ollama is running.
2. WHEN the probe to `http://127.0.0.1:11434/api/tags` succeeds, THE `OllamaClient` SHALL select the active model using the following priority: (a) the first model in the returned list whose name contains `qwen2.5-coder`, (b) the first model whose name contains `deepseek-coder`, (c) the first model in the list regardless of name.
3. WHEN `--agent=local-<model>` is specified, THE `OllamaClient` SHALL use the specified model name directly without probing `/api/tags` for model selection.
4. IF the probe to `http://127.0.0.1:11434/api/tags` fails or times out when `--agent=local` is specified, THEN THE `OllamaClient` SHALL print an error message that includes: the failure reason, the Ollama download URL (`https://ollama.ai`), and the recommended pull commands (`ollama pull qwen2.5-coder:7b` as first recommendation, `ollama pull deepseek-coder-v2` as second).
5. IF the probe to `http://127.0.0.1:11434/api/tags` fails or times out when `--agent=local` is specified, THEN THE `OllamaClient` SHALL exit with a non-zero status code without attempting any fix.
6. WHEN `--agent=local` or `--agent=local-<model>` is active, THE `OllamaClient` SHALL send fix requests to `http://127.0.0.1:11434/v1/chat/completions` using `AuthStyle::None` (no `Authorization` header).
7. WHEN `--agent=local` or `--agent=local-<model>` is active, THE `RemediationEngine` SHALL use the existing `LlmClient` infrastructure with the Ollama endpoint and `AuthStyle::None`, requiring no new HTTP client code.

---

### Requirement 2a: Micro-Context Targeting — Deterministic Cage for Local LLM

**User Story:** As a security engineer, I want the local LLM to receive only the minimal, precisely bounded context it needs to generate a fix, so that hallucinations are structurally impossible rather than merely unlikely.

#### Acceptance Criteria

1. WHEN constructing a prompt for a local LLM fix, THE `MicroContextExtractor` SHALL use the existing tree-sitter AST to extract only the vulnerable function block (the smallest enclosing function or arrow function containing the vulnerable line) — never the full file content.
2. THE `MicroContextExtractor` SHALL extract the names of all identifiers declared or referenced within the extracted function block and include them as an explicit `in_scope_variables` list in the prompt.
3. THE `LocalLlmPrompt` sent to the local model SHALL use the following system instruction verbatim: `"You are a strict code transformer. Return ONLY a JSON object with a single field: {\"replacement\": \"<fixed code>\"}. Do not explain. Do not add imports. Do not invent variable names. Only use variables from the provided scope list."`.
4. THE `LocalLlmPrompt` SHALL include: the vulnerability class (e.g., `"SQL Injection (CWE-89)"`), the extracted vulnerable function block as a code string, and the `in_scope_variables` list.
5. THE `LocalLlmPrompt` SHALL NOT include any code outside the extracted function block — the model SHALL never see the full file, other functions, or import statements.
6. THE `LocalLlmPrompt` SHALL set `max_tokens` to 512 and `temperature` to 0.0 (deterministic sampling) for all local model requests.

---

### Requirement 2b: Tree-Sitter Verification Loop — Sandboxed AI Output

**User Story:** As a security engineer, I want every local LLM output to be verified by the tree-sitter engine before it touches the codebase, so that a hallucinating model can never break the build.

#### Acceptance Criteria

1. WHEN the local LLM returns a response, THE `TreeSitterVerificationLoop` SHALL first attempt to parse the response as a JSON object with a `replacement` field. IF parsing fails, THE `TreeSitterVerificationLoop` SHALL discard the response and fall through to the comment-only fallback.
2. WHEN the `replacement` field is successfully extracted, THE `TreeSitterVerificationLoop` SHALL parse the replacement string through tree-sitter for the detected language. IF tree-sitter produces any error nodes in the resulting AST, THE `TreeSitterVerificationLoop` SHALL discard the replacement and fall through to the comment-only fallback.
3. WHEN the replacement passes syntax validation, THE `TreeSitterVerificationLoop` SHALL extract all identifier nodes from the replacement's AST and verify that every identifier is either: (a) present in the `in_scope_variables` list extracted by the `MicroContextExtractor`, (b) a language keyword or built-in (e.g., `const`, `await`, `null`), or (c) a string or numeric literal. IF any identifier fails this check, THE `TreeSitterVerificationLoop` SHALL discard the replacement and fall through to the comment-only fallback.
4. WHEN the replacement passes all three checks (JSON parse, syntax validation, scope check), THE `TreeSitterVerificationLoop` SHALL splice the replacement into the original file using the existing `splice_patch` function and write the result to disk.
5. WHEN the `TreeSitterVerificationLoop` discards a replacement at any stage, THE `RemediationEngine` SHALL fall through to the comment-only warning template — it SHALL NOT retry the LLM call or block the developer's workflow.
6. THE `TreeSitterVerificationLoop` SHALL complete all three validation checks within 50 milliseconds for any replacement string up to 200 lines.
7. FOR ALL local LLM fix attempts, the invariant SHALL hold: either the file on disk is syntactically valid after the fix, or the file on disk is identical to the original (no partial writes, no broken code).

---

### Requirement 3: Zero-Exfiltration Receipt for Local Agent Fixes

**User Story:** As a security engineer, I want the patch receipt to show `tokens_burned: 0` and `lines_exfiltrated: 0` for local agent fixes, so that I can prove to auditors that no code left the machine.

#### Acceptance Criteria

1. WHEN a fix is applied using `--agent=local` or `--agent=local-<model>`, THE `PatchReceipt` SHALL set `tokens_burned` to `0`.
2. WHEN a fix is applied using `--agent=local` or `--agent=local-<model>`, THE `PatchReceipt` SHALL set `lines_exfiltrated` to `0`.
3. WHEN a fix is applied using `--agent=local` or `--agent=local-<model>`, THE `PatchReceipt` SHALL set `template_used` to `"ollama-local"` followed by the model name in parentheses (e.g., `"ollama-local (llama3)"`).
4. THE `PatchReceipt` SHALL render the `tokens_burned` and `lines_exfiltrated` fields in the receipt box regardless of whether the fix was deterministic, local-agent, or cloud-agent.
5. WHEN a fix is applied using `--agent=cloud` with an LLM call, THE `PatchReceipt` SHALL set `tokens_burned` to the actual token count reported by the provider API and `lines_exfiltrated` to the line count of the transmitted context window.

---

### Requirement 4: `MultiLinePatchTemplate` Trait

**User Story:** As a Sicario developer, I want a `MultiLinePatchTemplate` trait that receives the full file content and the vulnerable line number, so that templates can perform AST-level multi-line rewrites that the single-line `PatchTemplate` trait cannot express.

#### Acceptance Criteria

1. THE `MultiLinePatchTemplate` trait SHALL define a method `generate_multiline_patch(&self, file_content: &str, vulnerable_line: usize, lang: Language) -> Option<String>` that returns the complete rewritten file content on success or `None` to signal graceful decline.
2. THE `MultiLinePatchTemplate` trait SHALL define a `name(&self) -> &'static str` method for diagnostics, consistent with the existing `PatchTemplate` trait.
3. THE `TemplateRegistry` SHALL support registration of `MultiLinePatchTemplate` implementations alongside existing `PatchTemplate` implementations, using the same rule-ID and CWE lookup keys.
4. WHEN the `RemediationEngine` calls `try_registry_fix`, THE `RemediationEngine` SHALL attempt `MultiLinePatchTemplate` lookup before falling back to the single-line `PatchTemplate` lookup for the same rule ID and CWE.
5. WHEN a `MultiLinePatchTemplate` returns `None`, THE `RemediationEngine` SHALL fall through to the single-line `PatchTemplate` lookup and then to the LLM fallback, preserving the existing fallback chain.
6. IF a `MultiLinePatchTemplate` returns a rewritten file content that fails tree-sitter syntax validation, THEN THE `RemediationEngine` SHALL discard the result, log a warning, and fall through to the next fallback step — never writing broken code to disk.

---

### Requirement 5: `SqlAstRewriteTemplate` — AST-Based SQL Injection Rewrite

**User Story:** As a developer, I want Sicario to automatically rewrite multi-line SQL injection patterns into parameterized queries using AST analysis, so that the fix is structurally correct and does not break surrounding code.

#### Acceptance Criteria

1. WHEN `SqlAstRewriteTemplate` is invoked on a TypeScript or JavaScript file containing a `.query(` or `.execute(` call whose first argument is a string concatenation expression involving a user-controlled variable, THE `SqlAstRewriteTemplate` SHALL rewrite the call to use a parameterized placeholder (`$1`, `$2`, …) and move the concatenated variables into a second array argument.
2. WHEN `SqlAstRewriteTemplate` is invoked on a TypeScript or JavaScript file containing a `.query(` or `.execute(` call whose first argument is a template literal with `${variable}` interpolations, THE `SqlAstRewriteTemplate` SHALL rewrite the call to replace each `${variable}` with a positional placeholder (`$1`, `$2`, …) and pass the variables as a second array argument.
3. WHEN `SqlAstRewriteTemplate` processes a multi-line concatenation spanning more than one source line, THE `SqlAstRewriteTemplate` SHALL use tree-sitter to walk up the AST from the vulnerable line to find the enclosing `.query(` or `.execute(` call expression, extract all concatenated sub-expressions, and rewrite the entire call expression as a single parameterized call.
4. THE `SqlAstRewriteTemplate` SHALL preserve the original indentation of the rewritten call expression.
5. THE `SqlAstRewriteTemplate` SHALL preserve all code outside the rewritten call expression exactly, including whitespace, comments, and surrounding statements.
6. IF the AST pattern at the reported line is too complex to rewrite safely (e.g., dynamic query construction with conditionals, nested function calls as arguments, or more than 8 interpolated variables), THEN THE `SqlAstRewriteTemplate` SHALL return `None` to signal graceful decline — never producing broken or semantically incorrect code.
7. THE `SqlAstRewriteTemplate` SHALL return `None` for any language other than JavaScript or TypeScript.
8. THE `SqlAstRewriteTemplate` SHALL be registered in `TemplateRegistry::default()` under rule IDs `js-sql-string-concat`, `js-sql-template-string`, `node-sql-template-literal`, and CWE `89`, replacing the existing comment-only `SqlStringConcatTemplate` and `SqlTemplateStringTemplate` registrations for JavaScript and TypeScript.
9. FOR ALL valid JavaScript and TypeScript files where `SqlAstRewriteTemplate` produces a rewrite, parsing the rewritten file with tree-sitter SHALL produce a syntax-valid AST with no error nodes (round-trip property).

---

### Requirement 6: `--auto-fix` Flag on `sicario hook --install`

**User Story:** As a developer, I want to install a Ghost Fix pre-commit hook with `sicario hook --install --auto-fix`, so that deterministic security fixes are applied silently before every commit without any manual intervention.

#### Acceptance Criteria

1. THE `HookManager` SHALL accept an `--auto-fix` flag on `sicario hook --install` that installs the `AutoFixHook` script instead of the standard scan-and-block script.
2. WHEN `--auto-fix` is specified, THE `HookManager` SHALL write a hook script that: runs `sicario fix --staged --format json --quiet` to collect findings, attempts a deterministic template fix for each finding, re-stages fixed files with `git add <file>`, and prints a summary line.
3. WHEN `--auto-fix` is specified and a hook is already installed (with or without `--auto-fix`), THE `HookManager` SHALL replace the existing Sicario hook block with the new `AutoFixHook` block without duplicating the `BEGIN SICARIO HOOK` / `END SICARIO HOOK` markers.
4. THE `AutoFixHook` script SHALL print a summary in the format: `Sicario: auto-fixed N vulnerabilities. Commit proceeding.` where `N` is the count of successfully applied deterministic fixes.
5. IF any finding in the staged diff has no available deterministic template fix, THEN THE `AutoFixHook` SHALL block the commit and print the standard scan error output for the unfixed findings, consistent with the existing hook behavior.
6. THE `AutoFixHook` SHALL never invoke an LLM or make any outbound network request, preserving the ZeroExfiltrationGuarantee for all hook-applied fixes.
7. THE `AutoFixHook` SHALL complete all scanning and fixing operations within 2 seconds for a staged diff of up to 20 files containing up to 50 findings.
8. THE `AutoFixHook` SHALL be idempotent: installing with `--auto-fix` twice SHALL result in exactly one `BEGIN SICARIO HOOK` / `END SICARIO HOOK` block in the pre-commit file.
9. THE `AutoFixHook` SHALL work on macOS, Linux, and Windows (Git Bash) by using POSIX-compatible shell syntax in the hook script.

---

### Requirement 7: `sicario fix --staged` Command

**User Story:** As a developer, I want a `sicario fix --staged` command that applies deterministic template fixes to all staged files, so that the Ghost Fix hook can invoke it as a subprocess.

#### Acceptance Criteria

1. THE `RemediationEngine` SHALL accept a `--staged` flag on `sicario fix` that restricts the set of files to be fixed to those currently in the Git index (staged files only).
2. WHEN `--staged` is specified, THE `RemediationEngine` SHALL enumerate staged files by running `git diff --cached --name-only` and SHALL only attempt fixes on files present in that list.
3. WHEN `--staged` is specified with `--format json`, THE `RemediationEngine` SHALL output a JSON array of fix result objects, each containing: `file`, `rule_id`, `line`, `fixed` (boolean), and `template_used` (string or null).
4. WHEN `--staged` is specified and a fix is successfully applied, THE `RemediationEngine` SHALL NOT print the interactive diff confirmation prompt — fixes SHALL be applied automatically.
5. WHEN `--staged` is specified and a fix is successfully applied to a file, THE `RemediationEngine` SHALL only apply DeterministicFix patches — it SHALL NOT invoke the LLM fallback for any finding.
6. IF `--staged` is specified outside a Git repository, THEN THE `RemediationEngine` SHALL print a descriptive error and exit with a non-zero status code.

---

### Requirement 8: Ghost Fix Hook Idempotency and Safety

**User Story:** As a developer, I want the Ghost Fix hook to be safe and idempotent, so that it never blocks a commit due to a fix failure and never corrupts the repository state.

#### Acceptance Criteria

1. IF a deterministic fix applied by the `AutoFixHook` fails to write to disk (e.g., permission error, disk full), THEN THE `AutoFixHook` SHALL fall through to the standard scan-and-block behavior for that finding rather than aborting the entire hook.
2. IF `git add <file>` fails after a fix is applied, THEN THE `AutoFixHook` SHALL restore the original file content from the backup created before the fix attempt and SHALL block the commit with an error message.
3. THE `AutoFixHook` SHALL create a backup of each file before applying any fix, consistent with the existing `BackupManager` behavior.
4. WHEN the `AutoFixHook` completes with zero unfixed findings, THE `AutoFixHook` SHALL exit with status code `0` to allow the commit to proceed.
5. WHEN the `AutoFixHook` completes with one or more unfixed findings (no template available), THE `AutoFixHook` SHALL exit with status code `1` to block the commit.
6. THE `AutoFixHook` SHALL respect the `SICARIO_SKIP_HOOK=1` environment variable to allow bypassing the hook, consistent with the existing hook behavior.

---

### Requirement 9: Zero-Exfiltration Guarantee Across All Three Features

**User Story:** As a security officer, I want a verifiable guarantee that none of the three new features transmit source code to any remote endpoint without explicit user consent, so that Sicario can be deployed in air-gapped and regulated environments.

#### Acceptance Criteria

1. WHEN `--agent=local` or `--agent=local-<model>` is active, THE `RemediationEngine` SHALL make no outbound HTTP requests to any endpoint other than `http://127.0.0.1:11434` (localhost only).
2. THE `AutoFixHook` SHALL make no outbound HTTP requests to any endpoint — all fix operations SHALL be deterministic template applications only.
3. WHEN `SqlAstRewriteTemplate` generates a patch, THE `SqlAstRewriteTemplate` SHALL make no network calls of any kind.
4. THE `PatchReceipt` SHALL display `lines_exfiltrated: 0` for any fix produced by `--agent=local`, `--agent=local-<model>`, `SqlAstRewriteTemplate`, or the `AutoFixHook`.
5. WHEN `--agent=local` is combined with `--allow-ai`, THE `AgentSelector` SHALL treat the combination as valid (local model IS allowed AI, just local) and SHALL NOT require a separate consent prompt for the local model call.
6. THE `MicroContextExtractor` SHALL transmit only the extracted function block (not the full file) to the local model. The maximum size of any single prompt sent to the local model SHALL not exceed 2,000 tokens.
7. FOR ALL local LLM fix attempts, the `TreeSitterVerificationLoop` invariant SHALL hold: either the file on disk is syntactically valid after the fix, or the file on disk is identical to the original — broken code SHALL never be written to disk under any circumstances.

---

### Requirement 10: Cross-Platform Compatibility

**User Story:** As a developer on macOS, Linux, or Windows, I want all three new features to work correctly on my platform, so that the team can adopt Sicario regardless of operating system.

#### Acceptance Criteria

1. THE `OllamaClient` SHALL use `http://127.0.0.1:11434` (IPv4 loopback) rather than `http://localhost:11434` to avoid IPv6 resolution delays on platforms where `localhost` resolves to `::1`.
2. THE `AutoFixHook` script SHALL use POSIX `sh` syntax (not `bash`-specific syntax) so that it executes correctly under Git Bash on Windows.
3. THE `HookManager` SHALL set the pre-commit hook file to executable mode (`0o755`) on Unix platforms after writing the `AutoFixHook` script, consistent with the existing `install()` behavior.
4. WHEN `sicario fix --staged` enumerates staged files on Windows, THE `RemediationEngine` SHALL normalize path separators to forward slashes when comparing against `git diff --cached --name-only` output.
5. THE `SqlAstRewriteTemplate` SHALL produce output with the same line endings as the input file (LF on Unix, CRLF on Windows) to avoid spurious diffs in cross-platform repositories.


---

### Requirement 11: Proof-of-Concept Generation (`sicario scan --prove`)

**User Story:** As a developer, I want Sicario to generate a benign, runnable exploit payload for each detected vulnerability, so that I can confirm the vulnerability is real and exploitable before spending time on a fix.

#### Acceptance Criteria

1. THE `PocGenerator` SHALL accept a `--prove` flag on `sicario scan` that, for each finding above the severity threshold, attempts to generate a `PocPayload` using the AST context of the finding.
2. BEFORE printing any `PocPayload` to the terminal, THE CLI SHALL display the following consent prompt and require explicit `y` confirmation: `"Warning: This will generate an active exploit payload. Ensure you are running this against a safe, local environment. Proceed? [y/N]"`. IF the user does not confirm, THE CLI SHALL skip PoC generation for that finding and continue scanning.
3. THE `PocGenerator` SHALL support PoC generation for the following vulnerability classes in the 7-day scope: SQL injection (CWE-89), SSRF (CWE-918), command injection (CWE-78), and path traversal (CWE-22).
4. FOR SQL injection findings, THE `PocGenerator` SHALL generate a time-based payload using `pg_sleep(5)` (PostgreSQL), `SLEEP(5)` (MySQL), or `WAITFOR DELAY '0:0:5'` (SQL Server), selected based on the database driver detected in the AST import statements. The generated `curl` command SHALL target `http://127.0.0.1:<port>/<route>` where `<port>` and `<route>` are extracted from the AST context.
5. FOR SSRF findings, THE `PocGenerator` SHALL spawn a `SsrfProbeListener` on a random available local port and generate a payload that causes the target application to make a request to `http://127.0.0.1:<probe_port>/ssrf-probe`. THE `PocGenerator` SHALL NOT generate payloads targeting cloud metadata endpoints (e.g., `169.254.169.254`) or any external domain.
6. FOR command injection findings, THE `PocGenerator` SHALL generate a payload using `; echo sicario-poc-$(date +%s)` as the injected command, which produces a unique, identifiable output without modifying any files or system state.
7. FOR path traversal findings, THE `PocGenerator` SHALL generate a payload that attempts to read `/etc/hostname` (Unix) or `C:\Windows\System32\drivers\etc\hosts` (Windows) — read-only files that contain no secrets.
8. THE `PocGenerator` SHALL physically enforce the localhost constraint in the Rust engine: any generated URL that does not resolve to `127.0.0.1` or `::1` SHALL be rejected before printing. This check SHALL be performed in the engine, not in documentation.
9. THE `PocGenerator` SHALL physically enforce the non-destructive constraint in the Rust engine: any generated SQL payload that contains `DROP`, `DELETE`, `TRUNCATE`, `UPDATE`, `INSERT`, or `ALTER` keywords SHALL be rejected before printing.
10. WHEN a `PocPayload` is successfully generated, THE CLI SHALL print: the vulnerability location, the generated `curl` command or payload, and an interpretation line (e.g., `"If the server takes ~5 seconds to respond, the vulnerability is confirmed."`).
11. IF the `PocGenerator` cannot extract sufficient AST context to generate a safe, targeted payload for a finding, THEN THE `PocGenerator` SHALL skip that finding and print `"PoC not available for this finding — insufficient AST context."` — it SHALL NOT generate a generic or untargeted payload.
12. THE `--prove` flag SHALL be compatible with `--format json`: when both are specified, THE CLI SHALL include a `poc` field in each finding's JSON object containing the generated payload string (or `null` if not available), without printing the consent prompt.

---

### Requirement 12: Security Regression Guard (`sicario baseline diff --ci`)

**User Story:** As a CI/CD engineer, I want `sicario baseline diff --ci` to exit with code 1 only when new findings are introduced above the severity threshold, so that my pipeline blocks security regression without punishing the team for existing technical debt.

#### Acceptance Criteria

1. THE `BaselineManager` SHALL implement a `sicario baseline save` command that scans the current directory, computes a stable fingerprint for each finding (`SHA-256(rule_id + file_path + snippet_hash)`), and writes the fingerprints to `.sicario/baseline.json` with a timestamp and optional `--tag` label.
2. THE `BaselineManager` SHALL implement a `sicario baseline diff` command that runs a fresh scan, computes fingerprints for all current findings, and computes a `BaselineDelta` by comparing against the most recent saved baseline (or the baseline matching `--tag` if specified).
3. THE `BaselineDelta` SHALL partition findings into exactly three disjoint sets: new findings (fingerprint present in current scan but not in baseline), resolved findings (fingerprint present in baseline but not in current scan), and unchanged findings (fingerprint present in both).
4. WHEN `--ci` is specified on `sicario baseline diff`, THE CLI SHALL exit with code `1` if and only if the `BaselineDelta` contains at least one new finding with severity ≥ the configured threshold (default: `High`). Unchanged findings and resolved findings SHALL NOT contribute to the exit code.
5. WHEN `--ci` is specified, THE CLI SHALL print a summary in the following format:
   ```
   ✓  <N> known findings (unchanged — not blocking)
   ✓  <M> findings resolved since baseline
   ✗  <K> NEW findings introduced (blocking CI)
   ```
   where only the new findings are listed in detail below the summary.
6. WHEN `--ci` is specified and there are zero new findings above the threshold, THE CLI SHALL exit with code `0` and print: `"✓ No new findings above <threshold> severity. Security posture maintained."`.
7. IF `sicario baseline diff` is run without a saved baseline file, THEN THE CLI SHALL print a descriptive error explaining that `sicario baseline save` must be run first, and SHALL exit with code `2` (internal error) rather than code `1`.
8. THE `BaselineManager` SHALL use the existing `baseline/manager.rs` scaffolding — the `save()`, `compare()`, and `BaselineDelta` types are already designed and SHALL be implemented to match the existing interface.
9. THE `--tag` flag on `sicario baseline save` SHALL allow teams to label baselines by branch name or sprint (e.g., `sicario baseline save --tag main`), and `sicario baseline diff --tag main` SHALL compare against the named baseline rather than the most recent one.
10. THE `BaselineManager` SHALL retain all saved baselines in `.sicario/baselines/` as timestamped JSON files, never overwriting previous baselines, so that teams can compare against any historical snapshot.
11. FOR ALL valid baseline save/compare round-trips, serializing a `BaselineDelta` to JSON and deserializing it SHALL produce an equivalent `BaselineDelta` with identical new, resolved, and unchanged finding sets.

---

### Requirement 13: Compliance Evidence Export (`sicario report --compliance`)

**User Story:** As a CISO preparing for a SOC 2 Type II or ISO 27001 audit, I want a machine-readable compliance evidence package that documents every vulnerability found, every fix applied, every suppression added, and the time elapsed between detection and remediation, so that I can hand auditors a single artifact instead of manually assembling evidence from multiple tools.

#### Acceptance Criteria

1. THE CLI SHALL implement a `sicario report --compliance` command that generates a compliance evidence package as a single JSON file at `.sicario/compliance-report-<timestamp>.json`.
2. THE compliance report SHALL include the following sections: `scan_summary` (total findings by severity and language), `remediation_log` (all patches applied via `sicario fix` with timestamps, rule IDs, file paths, and template used), `suppression_log` (all `sicario-ignore` directives present in the codebase with file path, line, rule ID, and the git author and timestamp of the commit that introduced the suppression), `baseline_history` (all saved baselines with timestamps and finding counts), and `mttr_by_rule` (mean time to remediate in hours, computed per rule ID from detection timestamp to fix timestamp).
3. THE `remediation_log` SHALL be populated from the existing `BackupManager` patch history, which already records timestamps and file paths for every applied patch.
4. THE `suppression_log` SHALL be populated by scanning all source files for `sicario-ignore` comment directives and running `git log -S "sicario-ignore" --follow --format="%ae %aI" -- <file>` to attribute each suppression to a git author email and ISO 8601 timestamp. IF the repository has no git history, THE suppression log SHALL record the file path and line without author attribution.
5. THE compliance report SHALL include a `generated_at` ISO 8601 timestamp and a `sicario_version` field.
6. WHEN `--format sarif` is specified alongside `--compliance`, THE CLI SHALL also write a SARIF v2.1.0 file at `.sicario/compliance-report-<timestamp>.sarif` containing all current findings, suitable for upload to GitHub Advanced Security or Azure DevOps.
7. THE compliance report JSON SHALL be schema-valid: FOR ALL valid compliance reports, serializing and deserializing the JSON SHALL produce an equivalent report with no data loss.
8. THE `sicario report --compliance` command SHALL complete within 10 seconds for repositories with up to 10,000 source files and 500 findings.

---

### Requirement 14: Policy-as-Code Enforcement (`sicario policy`)

**User Story:** As an enterprise security team lead, I want to define organization-wide security policies in a YAML file that Sicario enforces in CI, so that I can mandate specific rules, severity thresholds, and file scope restrictions without modifying every developer's local configuration.

#### Acceptance Criteria

1. THE CLI SHALL support a `.sicario/policy.yaml` file in the repository root that defines organization-wide enforcement rules. WHEN this file is present, THE CLI SHALL load and apply it automatically on every `sicario scan` invocation.
2. THE `policy.yaml` file SHALL support the following top-level fields: `fail_on` (minimum severity to exit with code 1, overrides `--fail-on`), `required_rules` (list of rule IDs that must be enabled and cannot be suppressed), `blocked_suppressions` (list of rule IDs for which `sicario-ignore` directives are prohibited), `scope` (glob patterns restricting which files the policy applies to), and `max_findings` (integer — if the total finding count exceeds this value, exit with code 1 regardless of severity).
3. WHEN a `required_rules` entry is present in `policy.yaml` and a developer adds a `sicario-ignore` directive for that rule ID, THE CLI SHALL exit with code 1 and print: `"Policy violation: rule '<rule_id>' is marked as required and cannot be suppressed."`.
4. WHEN a `blocked_suppressions` entry is present in `policy.yaml` and a `sicario-ignore` directive for that rule ID is detected in a staged file, THE `AutoFixHook` SHALL block the commit and print: `"Policy violation: suppression of '<rule_id>' is prohibited by organizational policy."`.
5. THE `policy.yaml` file SHALL take precedence over all local `--fail-on`, `--min-severity`, and `--exclude-rule` flags. A developer cannot override policy via CLI flags.
6. WHEN `sicario policy validate` is run, THE CLI SHALL parse `.sicario/policy.yaml`, check all referenced rule IDs against the loaded rule set, and print a validation report listing any unknown rule IDs or invalid glob patterns.
7. THE CLI SHALL include a `sicario policy init` command that generates a `.sicario/policy.yaml` template with commented-out examples of all supported fields.
8. THE `policy.yaml` format SHALL be documented in `sicario policy --help` output with field descriptions and example values.

---

### Requirement 15: MTTR Tracking and Board-Ready Report (`sicario report --mttr`)

**User Story:** As a CISO presenting to the board, I want a single command that computes Mean Time to Remediate per vulnerability class and outputs a board-ready summary, so that I can demonstrate the security team's operational effectiveness without manually correlating data from multiple tools.

#### Acceptance Criteria

1. THE CLI SHALL implement a `sicario report --mttr` command that computes Mean Time to Remediate (MTTR) in hours for each rule ID, using the detection timestamp from the baseline history and the fix timestamp from the remediation log.
2. THE MTTR report SHALL be output as a formatted table to stdout with columns: `Rule ID`, `Vulnerability Class`, `Severity`, `Findings Detected`, `Findings Remediated`, `MTTR (hours)`, `Trend` (↑ improving / ↓ worsening / → stable, compared to the previous baseline period).
3. WHEN `--format json` is specified, THE CLI SHALL output the MTTR data as a JSON array of objects with the same fields as the table, suitable for ingestion by Datadog, Splunk, or a custom dashboard.
4. THE MTTR computation SHALL use the following formula: for each remediated finding, MTTR = (fix_timestamp - detection_timestamp) in hours. The per-rule MTTR is the arithmetic mean across all remediated findings for that rule ID within the reporting period.
5. WHEN `--since <ISO8601_date>` is specified, THE CLI SHALL restrict the MTTR computation to findings detected after the specified date.
6. IF fewer than 3 findings have been remediated for a given rule ID, THE CLI SHALL display `"Insufficient data"` in the MTTR column rather than a potentially misleading average.
7. THE MTTR report SHALL include a summary line: `"Overall MTTR: <N> hours across <M> remediated findings in the last <period>."`.
8. THE `sicario report --mttr` command SHALL complete within 5 seconds for repositories with up to 1,000 remediated findings in the patch history.

---

### Requirement 16: Suppression Audit Log (`sicario suppressions audit`)

**User Story:** As a compliance officer, I want a complete, tamper-evident audit log of every suppression directive in the codebase — who added it, when, and for which rule — so that I can demonstrate to auditors that suppressed findings were reviewed and approved rather than silently ignored.

#### Acceptance Criteria

1. THE CLI SHALL implement a `sicario suppressions audit` command that scans all source files for `sicario-ignore`, `sicario-ignore-next-line`, and `sicario-ignore:<rule-id>` directives and produces a structured audit log.
2. FOR EACH suppression directive found, THE audit log SHALL record: file path, line number, rule ID (or `"all"` for blanket suppressions), the full comment text, the git author email of the commit that introduced the line (via `git blame`), the git commit SHA, and the ISO 8601 timestamp of that commit.
3. WHEN `--format json` is specified, THE CLI SHALL output the audit log as a JSON array suitable for ingestion by a SIEM or GRC platform.
4. WHEN `--format csv` is specified, THE CLI SHALL output the audit log as a CSV file with headers: `file,line,rule_id,comment,author_email,commit_sha,committed_at`.
5. THE CLI SHALL support a `--since <ISO8601_date>` flag that restricts the audit log to suppressions introduced after the specified date, enabling periodic compliance reviews.
6. THE CLI SHALL support a `--author <email>` flag that restricts the audit log to suppressions introduced by a specific git author, enabling per-developer compliance reviews.
7. IF a suppression directive is found in a file with no git history (e.g., a new untracked file), THE audit log SHALL record `"untracked"` for the author email, commit SHA, and timestamp fields.
8. THE `sicario suppressions audit` command SHALL complete within 10 seconds for repositories with up to 500 suppression directives across 10,000 source files.
9. THE audit log output SHALL be append-only when written to a file via `--output <path>`: if the file already exists, new entries SHALL be appended rather than overwriting existing entries, preserving the historical record.

---

### Requirement 17: Dependency License Risk Scanner (`sicario scan --licenses`)

**User Story:** As a CISO at a fintech or defense contractor, I want Sicario to flag dependencies with license terms that create legal risk for my proprietary codebase — specifically GPL, AGPL, and SSPL licenses — so that I can identify and remediate license compliance violations before they become legal liabilities.

#### Acceptance Criteria

1. THE CLI SHALL accept a `--licenses` flag on `sicario scan` that, in addition to security scanning, analyzes all dependencies in detected lockfiles and manifest files for license risk.
2. THE license scanner SHALL classify each dependency's license into one of three risk tiers: `HIGH` (GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0, EUPL-1.2 — copyleft licenses that may require proprietary code disclosure), `MEDIUM` (LGPL-2.1, LGPL-3.0, MPL-2.0, CDDL-1.0 — weak copyleft licenses with specific obligations), and `LOW` (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD — permissive licenses with minimal obligations).
3. THE license scanner SHALL resolve license information using the existing SCA dependency list (already parsed from lockfiles by `ManifestParser`) and SHALL look up license data from the local OSV/GHSA SQLite cache. IF license data is not in the local cache, THE scanner SHALL attempt to fetch it from the npm registry (`https://registry.npmjs.org/<package>`) or PyPI (`https://pypi.org/pypi/<package>/json`) with a 2-second timeout per package.
4. WHEN `--licenses` is specified, THE CLI SHALL output a license risk table after the security findings table, with columns: `Package`, `Version`, `License`, `Risk Tier`, `Ecosystem`.
5. WHEN `--fail-on-license HIGH` is specified, THE CLI SHALL exit with code 1 if any dependency has a `HIGH` risk license tier. WHEN `--fail-on-license MEDIUM` is specified, THE CLI SHALL exit with code 1 if any dependency has a `HIGH` or `MEDIUM` risk license tier.
6. THE license scanner SHALL support an allowlist via `.sicario/license-allowlist.txt` — one package name per line. Packages in the allowlist SHALL be reported but SHALL NOT contribute to the exit code, enabling teams to document reviewed exceptions.
7. WHEN `--format json` is specified alongside `--licenses`, THE CLI SHALL include a `license_findings` array in the JSON output alongside the existing `security_findings` array.
8. THE license scanner SHALL complete within 15 seconds for repositories with up to 500 dependencies, including network fetches for uncached license data.
