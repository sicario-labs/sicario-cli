# Requirements Document

## Introduction

Sicario v0.3.5 is the release that makes Sicario undeniably better than Semgrep — not just comparable. It is built on seven engineering pillars: rule quality and validation, language breadth expansion, production validation against known-vulnerable applications, interprocedural taint analysis, universal autofix coverage, developer-facing power tools (CI supply-chain guard, auto-PR fix loop, scan performance at scale, interactive rule authoring), and a formally auditable zero-exfiltration architecture that is structurally stronger than any competitor.

The release targets 53 concrete outcomes across CLI engine quality, dashboard/CLI integration, dashboard gap closure, signup and onboarding, custom rule editor, Semgrep parity features, dashboard features, CLI/dashboard contract enforcement, and gap closure tasks identified in audit.

---

## Glossary

- **Sicario_CLI**: The Sicario command-line security scanning application.
- **SAST_Engine**: The static application security testing core that parses source files and matches security rules.
- **Tree_Sitter_Engine**: The Rust-based parsing engine that generates concrete syntax trees using tree-sitter grammars.
- **Rule_Harness**: The test runner in `sicario-cli/src/rule_harness.rs` that executes TP/TN assertions from YAML `test_cases` blocks against the SAST engine.
- **Vuln_Sandbox**: The directory `vuln-sandbox/` containing intentionally vulnerable files used as a regression test corpus.
- **FP_Corpus**: The false-positive corpus consisting of clean, popular open-source repositories used to assert zero false positives.
- **Benchmark_Command**: The `sicario benchmark` CLI subcommand that runs the full Vuln_Sandbox and FP_Corpus, computes precision/recall/F1, and prints a structured report.
- **Confidence_Field**: The `confidence` metadata field on a security rule with valid values `high`, `medium`, and `low`.
- **Confidence_Threshold**: The `--confidence-threshold` CLI flag that filters scan output to rules at or above the specified confidence level.
- **Taint_Analyzer**: The interprocedural taint analysis component that tracks data flow from taint sources to taint sinks across function boundaries.
- **Taint_Source**: An expression that introduces attacker-controlled data: HTTP request parameters, environment variable reads, and file reads.
- **Taint_Sink**: An expression that consumes tainted data in a dangerous way: SQL query execution, shell command execution, file path construction, outbound HTTP requests, and HTML rendering.
- **Taint_Path**: The ordered sequence of nodes from a Taint_Source through zero or more intermediate call sites to a Taint_Sink.
- **Precision**: The fraction of reported findings that are true positives: `TP / (TP + FP)`.
- **Recall**: The fraction of actual vulnerabilities that are detected: `TP / (TP + FN)`.
- **F1_Score**: The harmonic mean of Precision and Recall: `2 * (Precision * Recall) / (Precision + Recall)`.
- **Known_Vulnerable_App**: A deliberately insecure application used for security training: DVWA, WebGoat, Juice Shop, or OWASP NodeGoat.
- **ReachabilityAnalyzer**: The existing cross-file data-flow component in `sicario-cli/src/engine/` that traces tainted variables.
- **YAML_Rule**: A security rule defined in a YAML file following the existing schema with `id`, `name`, `severity`, `language`, `pattern`, `cwe_id`, `owasp_category`, and `test_cases` fields.
- **Fix_Template**: A deterministic code transformation registered in the template registry that rewrites a vulnerable code pattern into a safe equivalent without requiring an LLM call.
- **Guard_Scanner**: The behavioral anomaly scanner in `sicario-cli/src/guard/` that inspects `node_modules/` and Python `site-packages/` for supply-chain attack indicators.
- **Auto_PR**: The automated pull request creation workflow triggered by `--auto-pr` that branches, commits fixes, and opens a PR via the GitHub or GitLab API.
- **Incremental_Cache**: The SQLite-backed scan cache in `.sicario/cache/scan-cache.db` that stores content hashes and finding fingerprints to enable file-level incremental scanning.
- **Rule_REPL**: The interactive pattern-matching loop entered via `sicario rule test --interactive` that evaluates tree-sitter patterns against a loaded file in real time.
- **Match_Based_ID**: A SHA-256 fingerprint of (file path + rule ID + rule pattern with metavariable values substituted) used to track a finding's identity across branches and line-number changes. Contains no raw source code.
- **Syntactic_ID**: A SHA-256 fingerprint of (file path + rule ID + literal matched code + match index) used for internal deduplication. Never transmitted to Sicario Cloud.
- **Policy_Mode**: The per-rule action mode configured in Sicario Cloud: Monitor (dashboard only), Comment (PR/MR comment), Block (CI exit 1), or Disabled (rule skipped).
- **Managed_CI_Config**: The zero-config onboarding workflow that generates and commits a CI workflow file to a repository via the SCM API, enabling `sicario ci` scanning without manual CI configuration. Source code never leaves the customer's infrastructure.
- **Audit_Log**: The machine-readable JSON file written to `.sicario/audit/scan-<timestamp>.json` after every scan, recording every outbound network transmission made during the scan with payload type, size, and lines-of-code-transmitted counts.
- **Zero_Exfil_Guarantee**: The formal property that Sicario Cloud never receives source code. Only structured finding metadata (rule ID, file path, line, severity, CWE, truncated snippet ≤100 chars) is uploaded when `--publish` is active. LLM context is transmitted only to the user-configured LLM provider with explicit consent, never to Sicario Cloud.
- **SCA_Scanner**: The Software Composition Analysis scanner (`sicario scan --sca`) that parses lockfiles, checks dependencies against the local vulnerability database, and reports CVEs with reachability analysis.
- **Vuln_DB**: The local SQLite vulnerability database at `.sicario/cache/vuln_cache.db` populated from OSV, NVD, and GitHub Advisory Database feeds. Updated via `sicario update --vuln-db`.
- **Suppression_Metadata**: The array of inline `sicario-ignore` comment records included in the scan publish payload: `{file_path, line, rule_id, committer_email, suppression_comment}`. Contains no source code.
- **License_Policy**: The SPDX-based dependency license policy configured in the dashboard (allow/block/warn lists) and synced to the CLI via `sicario ci` policy fetch. Local `--license-policy <path>` YAML overrides the cloud policy.
- **Code_Search**: The cross-repository pattern search feature accessible via `sicario search --pattern <query>` (CLI) and `/dashboard/search` (dashboard). Dashboard search operates on stored finding metadata only — no repository cloning.
- **Pre_Commit_Hook**: The Git pre-commit hook installed by `sicario install-hook` that runs `sicario scan --staged --secrets --fail-on medium` before each commit. Managed via `sicario hook install/uninstall/status`.
- **Shared_Rule**: A custom rule shared via a URL token generated by `sicario rule share`. The rule YAML is stored in Sicario Cloud; the token is used to retrieve it. Test code is never stored.
- **Device_Auth_Token**: The opaque token stored in `~/.sicario/config.toml` under `[auth] token` after `sicario login` completes the device authorization flow. Used to authenticate CLI requests to Sicario Cloud.
- **Demo_Project**: A pre-seeded project containing 10 Juice Shop vulnerability findings, created by the onboarding wizard's "Demo" path. Labeled `[Demo]` in the dashboard. No real code is scanned.

---

## Requirements

### Requirement 1: Vuln-Sandbox Expansion to 500+ Files

**User Story:** As a security engineer, I want the vuln-sandbox to cover 500+ intentionally vulnerable files with one true-positive and one true-negative per rule, so that every rule in the engine has a regression test that runs in CI.

#### Acceptance Criteria

1. THE Vuln_Sandbox SHALL contain at least 500 intentionally vulnerable files organized by language and CWE, with one true-positive file and one true-negative file per YAML_Rule.
2. WHEN a new YAML_Rule is added to the rule set, THE Vuln_Sandbox SHALL include a corresponding true-positive file that triggers the rule and a true-negative file that does not trigger the rule.
3. THE Vuln_Sandbox MANIFEST.md SHALL be updated to list every file, its CWE, its rule ID, and its expected outcome (TruePositive or TrueNegative).
4. WHEN `sicario scan vuln-sandbox/ --format json` is executed, THE SAST_Engine SHALL produce exactly one finding per true-positive file and zero findings matching the corresponding rule ID for each true-negative file.
5. THE Vuln_Sandbox SHALL include true-positive and true-negative files for all languages supported by the SAST_Engine, including JavaScript, TypeScript, Python, Go, Rust, Java, Ruby, PHP, and C#.

---

### Requirement 2: False-Positive Corpus

**User Story:** As a security engineer, I want Sicario to assert zero false positives against clean, popular open-source repositories, so that I can demonstrate low noise to prospective users and enterprise customers.

#### Acceptance Criteria

1. THE FP_Corpus SHALL consist of at least 10 popular open-source repositories including Express.js, Django, FastAPI, Next.js, Flask, Rails, Laravel, Spring Boot, ASP.NET Core, and NestJS.
2. WHEN `sicario benchmark --fp-corpus` is executed, THE Benchmark_Command SHALL clone or reference each FP_Corpus repository and run the full SAST_Engine rule set against it.
3. WHEN scanning FP_Corpus repositories, THE Benchmark_Command SHALL assert that the number of findings with `confidence: high` is zero for each repository.
4. THE Benchmark_Command SHALL output a per-repository false-positive count table showing repository name, total findings, high-confidence findings, and pass/fail status.
5. IF any FP_Corpus repository produces one or more `confidence: high` findings, THEN THE Benchmark_Command SHALL exit with a non-zero status code and print the offending findings with file paths and rule IDs.
6. WHERE `--benchmark` CI mode is active, THE Sicario_CLI SHALL fail the CI job if the false-positive rate for `confidence: high` rules exceeds zero across all FP_Corpus repositories.

---

### Requirement 3: Confidence Metadata Field on Rules

**User Story:** As a security engineer, I want every security rule to carry a `confidence` field with value `high`, `medium`, or `low`, so that I can filter scan output to only the findings I trust most.

#### Acceptance Criteria

1. THE YAML_Rule schema SHALL include a required `confidence` field with valid values `high`, `medium`, and `low`.
2. THE SAST_Engine SHALL reject any YAML_Rule that does not include a `confidence` field and SHALL log a warning with the rule ID and file path.
3. WHEN loading rules, THE SAST_Engine SHALL populate the `confidence` field on every parsed rule from the YAML `confidence` key.
4. THE Sicario_CLI SHALL accept a `--confidence-threshold <level>` flag on `sicario scan` where `<level>` is `high`, `medium`, or `low`.
5. WHEN `--confidence-threshold high` is specified, THE SAST_Engine SHALL include only findings from rules with `confidence: high` in the output.
6. WHEN `--confidence-threshold medium` is specified, THE SAST_Engine SHALL include findings from rules with `confidence: high` or `confidence: medium` in the output.
7. WHEN `--confidence-threshold low` is specified or `--confidence-threshold` is omitted, THE SAST_Engine SHALL include findings from all rules regardless of confidence level.
8. THE Sicario_CLI SHALL display the `confidence` level alongside each finding in text output and include it as a field in JSON and SARIF output.
9. THE Sicario_CLI SHALL backfill all existing built-in YAML rules with an appropriate `confidence` value before the v0.3.5 release.

---

### Requirement 4: Rule Test Harness Wired into CI

**User Story:** As a Sicario developer, I want the `sicario rules test` command to actually execute TP/TN assertions from YAML `test_cases` blocks, so that rule regressions are caught automatically in CI before they reach users.

#### Acceptance Criteria

1. THE Rule_Harness SHALL execute `sicario rules test` by loading all YAML rules, extracting their `test_cases` blocks, and running each test case through the SAST_Engine.
2. WHEN a test case has `expected: TruePositive`, THE Rule_Harness SHALL assert that the SAST_Engine produces at least one finding matching the rule ID for the test case code snippet.
3. WHEN a test case has `expected: TrueNegative`, THE Rule_Harness SHALL assert that the SAST_Engine produces zero findings matching the rule ID for the test case code snippet.
4. WHEN all test cases pass, THE Rule_Harness SHALL exit with status code `0` and print a summary in the format `N rules tested, M test cases passed`.
5. WHEN any test case fails, THE Rule_Harness SHALL exit with status code `1` and print the rule ID, the failing test case code, the expected outcome, and the actual outcome.
6. THE CI workflow (`.github/workflows/ci.yml`) SHALL execute `sicario rules test` as a required step that blocks merges on failure.
7. FOR ALL YAML rules that include `test_cases`, the Rule_Harness SHALL execute every test case — no test cases SHALL be silently skipped.
8. THE Rule_Harness SHALL complete all test cases for the full built-in rule set within 60 seconds on a standard CI runner.

---

### Requirement 5: `sicario benchmark` Command

**User Story:** As a security engineer, I want a `sicario benchmark` command that runs the full vuln-sandbox, computes precision/recall/F1, and prints a structured report, so that I can measure and track the accuracy of the engine over time.

#### Acceptance Criteria

1. THE Benchmark_Command SHALL accept a `sicario benchmark` invocation that runs the SAST_Engine against the full Vuln_Sandbox and computes Precision, Recall, and F1_Score.
2. THE Benchmark_Command SHALL compute Precision as `TP / (TP + FP)`, Recall as `TP / (TP + FN)`, and F1_Score as `2 * (Precision * Recall) / (Precision + Recall)` using the Vuln_Sandbox MANIFEST.md as the ground truth.
3. THE Benchmark_Command SHALL print a report containing: total true positives, false positives, false negatives, Precision, Recall, F1_Score, and per-language breakdowns of the same metrics.
4. THE Benchmark_Command SHALL accept a `--target <path>` flag that runs the benchmark against a specified directory instead of the default Vuln_Sandbox path.
5. WHEN `--target` points to a Known_Vulnerable_App directory, THE Benchmark_Command SHALL use the app's known vulnerability manifest (if present) as ground truth for metric computation.
6. THE Benchmark_Command SHALL accept a `--format json` flag that outputs the benchmark report as a JSON object suitable for ingestion by CI dashboards and time-series stores.
7. THE Benchmark_Command SHALL accept a `--benchmark` flag that enables CI mode: THE Benchmark_Command SHALL exit with status code `1` if Precision drops below a configurable threshold (default: `0.80`).
8. WHEN `--benchmark` CI mode is active, THE Benchmark_Command SHALL accept a `--min-precision <value>` flag where `<value>` is a decimal between `0.0` and `1.0` that overrides the default precision threshold.
9. THE Benchmark_Command SHALL save each benchmark run result to `.sicario/benchmarks/benchmark-<ISO8601_timestamp>.json` for historical comparison.
10. THE Benchmark_Command SHALL complete a full Vuln_Sandbox benchmark run within 30 seconds on a standard CI runner.

---

### Requirement 6: Ruby Language Support

**User Story:** As a security engineer, I want Sicario to scan Ruby source files for security vulnerabilities, so that Rails and Sinatra applications receive the same coverage as JavaScript and Python codebases.

#### Acceptance Criteria

1. THE Tree_Sitter_Engine SHALL parse Ruby source files using the `tree-sitter-ruby` grammar compiled into the Sicario binary.
2. THE SAST_Engine SHALL load and apply YAML rules with `language: Ruby` against parsed Ruby ASTs.
3. THE SAST_Engine SHALL detect SQL injection (CWE-89) in Ruby code where string interpolation or concatenation is used to construct SQL queries passed to ActiveRecord or raw database adapters.
4. THE SAST_Engine SHALL detect command injection (CWE-78) in Ruby code where user-controlled input is passed to `system()`, backtick execution, `exec()`, `spawn()`, or `Open3` methods.
5. THE SAST_Engine SHALL detect path traversal (CWE-22) in Ruby code where user-controlled input is used to construct file paths passed to `File.read`, `File.open`, `IO.read`, or `send_file`.
6. THE SAST_Engine SHALL detect XSS (CWE-79) in Ruby/ERB templates where user-controlled input is rendered without the `html_escape` or `h()` helper.
7. THE SAST_Engine SHALL detect hardcoded secrets (CWE-798) in Ruby code where string literals matching credential patterns are assigned to variables named `secret`, `password`, `api_key`, `token`, or `key`.
8. THE SAST_Engine SHALL detect SSRF (CWE-918) in Ruby code where user-controlled input is passed to `Net::HTTP.get`, `open-uri`, `RestClient`, or `HTTParty` methods.
9. THE Vuln_Sandbox SHALL include at least one true-positive and one true-negative Ruby file for each of the six vulnerability classes defined in acceptance criteria 3–8.
10. WHEN `sicario scan` is run against a directory containing Ruby files, THE SAST_Engine SHALL include Ruby findings in the output without requiring any additional flags or configuration.

---

### Requirement 7: PHP Language Support

**User Story:** As a security engineer, I want Sicario to scan PHP source files for security vulnerabilities, so that WordPress, Laravel, and Symfony applications can be audited with the same tool as the rest of the stack.

#### Acceptance Criteria

1. THE Tree_Sitter_Engine SHALL parse PHP source files using the `tree-sitter-php` grammar compiled into the Sicario binary.
2. THE SAST_Engine SHALL load and apply YAML rules with `language: PHP` against parsed PHP ASTs.
3. THE SAST_Engine SHALL detect SQL injection (CWE-89) in PHP code where `$_GET`, `$_POST`, `$_REQUEST`, or `$_COOKIE` values are interpolated or concatenated into strings passed to `mysqli_query`, `PDO::query`, or `mysql_query`.
4. THE SAST_Engine SHALL detect command injection (CWE-78) in PHP code where user-controlled input is passed to `exec()`, `shell_exec()`, `system()`, `passthru()`, or backtick execution.
5. THE SAST_Engine SHALL detect path traversal (CWE-22) in PHP code where user-controlled input is used to construct file paths passed to `file_get_contents`, `include`, `require`, `fopen`, or `readfile`.
6. THE SAST_Engine SHALL detect XSS (CWE-79) in PHP code where user-controlled input is echoed or printed without `htmlspecialchars()` or `htmlentities()` wrapping.
7. THE SAST_Engine SHALL detect hardcoded secrets (CWE-798) in PHP code where string literals matching credential patterns are assigned to variables or constants named `password`, `secret`, `api_key`, `token`, or `db_pass`.
8. THE SAST_Engine SHALL detect SSRF (CWE-918) in PHP code where user-controlled input is passed to `curl_setopt` with `CURLOPT_URL`, `file_get_contents` with a URL, or `fsockopen`.
9. THE Vuln_Sandbox SHALL include at least one true-positive and one true-negative PHP file for each of the six vulnerability classes defined in acceptance criteria 3–8.
10. WHEN `sicario scan` is run against a directory containing PHP files, THE SAST_Engine SHALL include PHP findings in the output without requiring any additional flags or configuration.

---

### Requirement 8: C# Language Support

**User Story:** As a security engineer, I want Sicario to scan C# source files for security vulnerabilities, so that ASP.NET Core and .NET applications receive the same coverage as other supported languages.

#### Acceptance Criteria

1. THE Tree_Sitter_Engine SHALL parse C# source files using the `tree-sitter-c-sharp` grammar compiled into the Sicario binary.
2. THE SAST_Engine SHALL load and apply YAML rules with `language: CSharp` against parsed C# ASTs.
3. THE SAST_Engine SHALL detect SQL injection (CWE-89) in C# code where string interpolation or concatenation is used to construct SQL queries passed to `SqlCommand`, `ExecuteReader`, `ExecuteNonQuery`, or Entity Framework raw SQL methods.
4. THE SAST_Engine SHALL detect command injection (CWE-78) in C# code where user-controlled input is passed to `Process.Start` with `UseShellExecute: true` or where `ProcessStartInfo.Arguments` is constructed via string concatenation.
5. THE SAST_Engine SHALL detect path traversal (CWE-22) in C# code where user-controlled input is used to construct file paths passed to `File.ReadAllText`, `File.Open`, `FileStream`, or `Path.Combine` without normalization.
6. THE SAST_Engine SHALL detect XSS (CWE-79) in C# Razor templates where user-controlled input is rendered using `@Html.Raw()` instead of the default auto-encoded `@` expression.
7. THE SAST_Engine SHALL detect hardcoded secrets (CWE-798) in C# code where string literals matching credential patterns are assigned to variables or constants named `password`, `secret`, `apiKey`, `connectionString`, or `token`.
8. THE SAST_Engine SHALL detect SSRF (CWE-918) in C# code where user-controlled input is passed to `HttpClient.GetAsync`, `WebClient.DownloadString`, or `WebRequest.Create`.
9. THE Vuln_Sandbox SHALL include at least one true-positive and one true-negative C# file for each of the six vulnerability classes defined in acceptance criteria 3–8.
10. WHEN `sicario scan` is run against a directory containing C# files (`.cs` extension), THE SAST_Engine SHALL include C# findings in the output without requiring any additional flags or configuration.

---

### Requirement 9: Production Validation Against Known-Vulnerable Applications

**User Story:** As a security engineer, I want benchmark results published against DVWA, WebGoat, Juice Shop, and OWASP NodeGoat, so that I can compare Sicario's detection rate against a known ground truth and demonstrate production-grade accuracy.

#### Acceptance Criteria

1. THE Benchmark_Command SHALL support `--target <path>` where `<path>` points to a local clone of a Known_Vulnerable_App (DVWA, WebGoat, Juice Shop, or OWASP NodeGoat).
2. WHEN `--target` is used with a Known_Vulnerable_App, THE Benchmark_Command SHALL load a bundled ground-truth manifest for that application listing the expected vulnerable files and rule IDs.
3. THE Benchmark_Command SHALL compute Precision, Recall, and F1_Score for each Known_Vulnerable_App using the bundled ground-truth manifest as the source of truth.
4. THE Benchmark_Command SHALL print a per-application benchmark table showing application name, total expected findings, true positives, false positives, false negatives, Precision, Recall, and F1_Score.
5. THE Sicario_CLI documentation SHALL include benchmark results for all four Known_Vulnerable_Apps showing Precision ≥ 0.80 and Recall ≥ 0.70 for each application.
6. WHERE `--benchmark` CI mode is active with `--target` pointing to a Known_Vulnerable_App, THE Benchmark_Command SHALL exit with status code `1` if Precision drops below the configured `--min-precision` threshold for that application.
7. THE Benchmark_Command SHALL save Known_Vulnerable_App benchmark results to `.sicario/benchmarks/benchmark-<app_name>-<ISO8601_timestamp>.json`.

---

### Requirement 10: Interprocedural Taint Analysis (`sicario scan --taint`)

**User Story:** As a security engineer, I want Sicario to track tainted data across function boundaries, so that I can detect vulnerabilities where the source and sink are in different functions or files.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL accept a `--taint` flag on `sicario scan` that enables interprocedural taint analysis mode via the Taint_Analyzer.
2. THE Taint_Analyzer SHALL identify Taint_Sources in JavaScript, TypeScript, and Python source files including: HTTP request parameters (`req.query`, `req.body`, `req.params`, `request.GET`, `request.POST`, `request.args`, `request.form`), environment variable reads (`process.env`, `os.environ`), and file reads (`fs.readFile`, `fs.readFileSync`, `open()`, `Path.read_text()`).
3. THE Taint_Analyzer SHALL identify Taint_Sinks in JavaScript, TypeScript, and Python source files for the following five categories: SQL query execution (CWE-89), shell command execution (CWE-78), file path construction (CWE-22), outbound HTTP requests (CWE-918), and HTML rendering (CWE-79).
4. THE Taint_Analyzer SHALL perform 2-hop interprocedural taint analysis: tracking taint flow from a Taint_Source through at most one intermediate function call to a Taint_Sink within the same file or across files in the same project.
5. WHEN a Taint_Path is detected, THE Taint_Analyzer SHALL report the finding with a `taint_path` field containing the ordered sequence of nodes: source location, intermediate call site (if any), and sink location.
6. WHEN `--taint` is active and `--format json` is specified, THE Sicario_CLI SHALL include a `taint_path` array in each taint finding object with entries containing `file`, `line`, `column`, and `node_type` fields.
7. WHEN `--taint` is active and text output is used, THE Sicario_CLI SHALL render the Taint_Path as a box-drawing chain in the format `source → [intermediate →] sink` with file and line references for each node.
8. THE Taint_Analyzer SHALL cap analysis at 50,000 AST nodes per file to prevent unbounded execution time on large codebases.
9. WHEN `--taint` is active, THE Sicario_CLI SHALL complete taint analysis for a project of 10,000 source lines within 30 seconds on a standard developer machine.
10. THE Taint_Analyzer SHALL not produce duplicate findings: if the same Taint_Source → Taint_Sink pair is reachable via multiple paths, THE Taint_Analyzer SHALL report it once using the shortest path.

---

### Requirement 11: Taint Analysis — Source and Sink Coverage

**User Story:** As a security engineer, I want taint analysis to cover the top five sink categories across JS/TS and Python, so that the most impactful interprocedural vulnerabilities are detected without requiring manual data-flow tracing.

#### Acceptance Criteria

1. THE Taint_Analyzer SHALL detect SQL injection (CWE-89) taint paths where a Taint_Source flows into `db.query()`, `db.execute()`, `cursor.execute()`, `connection.query()`, or equivalent ORM raw query methods.
2. THE Taint_Analyzer SHALL detect command injection (CWE-78) taint paths where a Taint_Source flows into `child_process.exec()`, `child_process.spawn()` with `shell: true`, `subprocess.run()`, `subprocess.call()`, `os.system()`, or `os.popen()`.
3. THE Taint_Analyzer SHALL detect path traversal (CWE-22) taint paths where a Taint_Source flows into `fs.readFile()`, `fs.readFileSync()`, `path.join()` used as a file path argument, `open()`, or `Path()` constructors.
4. THE Taint_Analyzer SHALL detect SSRF (CWE-918) taint paths where a Taint_Source flows into `fetch()`, `axios.get()`, `http.get()`, `requests.get()`, `requests.post()`, `httpx.get()`, or `urllib.request.urlopen()`.
5. THE Taint_Analyzer SHALL detect XSS (CWE-79) taint paths where a Taint_Source flows into `innerHTML`, `document.write()`, `dangerouslySetInnerHTML`, `render_template_string()`, or `Markup()`.
6. THE Vuln_Sandbox SHALL include at least two interprocedural taint test cases per sink category (one 1-hop and one 2-hop) for both JavaScript/TypeScript and Python, totaling at least 20 new taint-specific test files.
7. WHEN `sicario scan --taint` is run against the taint-specific Vuln_Sandbox files, THE Taint_Analyzer SHALL detect all 20 taint test cases with zero false negatives.

---

### Requirement 12: Benchmark CI Integration

**User Story:** As a CI/CD engineer, I want the benchmark command to integrate with CI pipelines so that precision regressions block merges automatically, preventing rule quality from degrading over time.

#### Acceptance Criteria

1. THE Benchmark_Command SHALL accept a `--benchmark` flag that enables CI mode with non-zero exit on precision regression.
2. WHEN `--benchmark` is active, THE Benchmark_Command SHALL exit with status code `0` if Precision is greater than or equal to the configured threshold.
3. WHEN `--benchmark` is active, THE Benchmark_Command SHALL exit with status code `1` if Precision drops below the configured threshold, and SHALL print a human-readable message identifying the failing rules and their false-positive counts.
4. THE CI workflow (`.github/workflows/ci.yml`) SHALL include a benchmark step that runs `sicario benchmark --benchmark --min-precision 0.80` against the Vuln_Sandbox as a required CI check.
5. WHEN `--format json` is combined with `--benchmark`, THE Benchmark_Command SHALL output the full benchmark report as JSON to stdout and print the pass/fail status to stderr, so that CI log parsers can consume the JSON without interference.
6. THE Benchmark_Command SHALL accept a `--save-baseline` flag that saves the current benchmark result as the reference baseline for future `--benchmark` comparisons.
7. WHEN `--compare-baseline <path>` is specified, THE Benchmark_Command SHALL compare the current run against the saved baseline and report metric deltas (Precision Δ, Recall Δ, F1 Δ) alongside absolute values.


---

### Requirement 13: Universal Autofix — Every Rule Has a Fix

**User Story:** As a developer, I want every security rule with a deterministic fix pattern to have a corresponding fix template, so that `sicario scan --fix` can close all fixable findings in a single pass without any human intervention.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL accept a `--fix` flag on `sicario scan` that applies all deterministic fix templates to findings in a single pass immediately after scanning.
2. WHEN `--fix` is active, THE Sicario_CLI SHALL apply fixes for all findings where a deterministic Fix_Template exists, create a backup of each modified file via the BackupManager before writing, and print a per-finding receipt showing rule ID, file, line, and template used.
3. WHEN `--fix` is active, THE Sicario_CLI SHALL skip findings where no deterministic Fix_Template exists and SHALL print a summary of unfixed findings with the message `N findings require --allow-ai or manual review`.
4. EVERY built-in YAML_Rule with a `cwe_id` in the set {CWE-89, CWE-78, CWE-22, CWE-79, CWE-798, CWE-918, CWE-327, CWE-326, CWE-916, CWE-347, CWE-613, CWE-384, CWE-502, CWE-295} SHALL have a corresponding deterministic Fix_Template registered in the template registry.
5. THE Fix_Template coverage rate SHALL be at least 80% of all built-in rules — meaning at least 80% of rules SHALL have a registered deterministic fix.
6. WHEN `--fix` and `--staged` are both active, THE Sicario_CLI SHALL apply fixes only to staged files and re-stage the fixed files via `git add` after applying each fix.
7. WHEN `--fix` and `--format json` are both active, THE Sicario_CLI SHALL output a JSON array where each element contains `file`, `rule_id`, `line`, `fixed` (boolean), and `template_used` (string or null).
8. THE `sicario fix` standalone command SHALL be updated to accept a directory path and apply all deterministic fixes to all findings in that directory in a single pass, equivalent to `sicario scan <dir> --fix`.
9. WHEN `--fix` is active, THE Sicario_CLI SHALL run a post-fix verification scan and report any findings that remain after fixing, so that the user knows if the fix was incomplete.
10. THE Fix_Template for each CWE SHALL be validated against the Vuln_Sandbox true-positive files: applying the template to each true-positive file SHALL produce output that passes the corresponding true-negative assertion.

---

### Requirement 14: CI Supply-Chain Guard

**User Story:** As a CI/CD engineer, I want `sicario guard` to intercept package installations in CI pipelines and block anomalous packages before they land in the build environment, so that supply-chain attacks are stopped at the point of installation rather than discovered after the fact.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL accept a `sicario guard --ci` subcommand that runs the behavioral anomaly scanner against a specified `node_modules/` or Python virtual environment directory and exits with a non-zero status code if any Critical-severity anomalies are found.
2. WHEN `sicario guard --ci` is executed, THE Guard_Scanner SHALL scan all packages in the target directory using the existing 7 behavioral anomaly rules and SHALL complete within 60 seconds for a directory containing up to 1,000 packages.
3. WHEN `sicario guard --ci` detects a Critical-severity anomaly, THE Sicario_CLI SHALL print the package name, anomaly type, and the offending code snippet to stderr and SHALL exit with status code `1`.
4. WHEN `sicario guard --ci` detects no Critical-severity anomalies, THE Sicario_CLI SHALL print a summary of packages scanned and exit with status code `0`.
5. THE CI workflow (`.github/workflows/ci.yml`) SHALL include a supply-chain guard step that runs `sicario guard --ci node_modules/` after every `npm install` or `pip install` step as a required CI check.
6. THE Sicario_CLI SHALL accept a `sicario guard --ci --allowlist <path>` flag that loads a YAML allowlist of known-safe packages to exclude from anomaly scanning, preventing false positives on trusted packages.
7. WHEN `--format json` is specified with `sicario guard --ci`, THE Sicario_CLI SHALL output a JSON array of anomaly findings with `package`, `rule_id`, `severity`, `file`, `line`, and `snippet` fields.
8. THE Guard_Scanner SHALL support scanning Python virtual environment `site-packages/` directories in addition to Node.js `node_modules/` directories.
9. THE Sicario_CLI SHALL accept a `sicario guard install <package>` subcommand that runs `npm install <package>` or `pip install <package>` and immediately scans the newly installed package before allowing the installation to complete, blocking installation if Critical anomalies are found.
10. WHEN `sicario guard install` blocks a package installation, THE Sicario_CLI SHALL restore the package directory to its pre-installation state by removing the newly installed package files.

---

### Requirement 15: Auto-PR Fix Loop

**User Story:** As a developer, I want Sicario to automatically open a pull request with the fix applied when a finding is published to the cloud dashboard, so that I can review and merge security fixes without manually running `sicario fix`.

#### Acceptance Criteria

1. WHEN `sicario scan --publish` produces findings for which deterministic Fix_Templates exist, THE Sicario_CLI SHALL offer to create a pull request with all deterministic fixes applied via a `--auto-pr` flag.
2. WHEN `--auto-pr` is active, THE Sicario_CLI SHALL create a new git branch named `sicario/autofix-<timestamp>`, apply all deterministic fixes to the branch, commit the changes with a message listing the fixed rule IDs and file paths, and push the branch to the remote.
3. WHEN `--auto-pr` is active and the remote is GitHub, THE Sicario_CLI SHALL create a pull request via the GitHub API with a title in the format `[Sicario] Auto-fix N security findings` and a body listing each fixed finding with its rule ID, CWE, file, and line.
4. WHEN `--auto-pr` is active and the remote is GitLab, THE Sicario_CLI SHALL create a merge request via the GitLab API with equivalent title and description.
5. THE pull request body SHALL include a zero-exfiltration notice stating that no source code was transmitted to any external service during fix generation for deterministic patches.
6. WHEN `--auto-pr` is active and `--agent=local` is also specified, THE Sicario_CLI SHALL apply AI-powered fixes via the local Ollama agent for findings without deterministic templates and include them in the same pull request, with the PR body noting which fixes were AI-generated.
7. THE Sicario_CLI SHALL accept a `--auto-pr` flag on `sicario fix` as well, so that `sicario fix <dir> --auto-pr` creates a PR with all fixes applied without requiring a preceding scan.
8. WHEN the pull request is created successfully, THE Sicario_CLI SHALL print the PR URL to stdout.
9. WHEN the pull request creation fails (missing token, API error, etc.), THE Sicario_CLI SHALL print a descriptive error to stderr and exit with status code `2`, but SHALL NOT roll back the local branch or commits.
10. THE Auto-PR workflow SHALL be idempotent: if a branch named `sicario/autofix-<same-timestamp>` already exists on the remote, THE Sicario_CLI SHALL append a counter suffix (`-2`, `-3`, etc.) rather than failing.

---

### Requirement 16: Scan Performance at Scale

**User Story:** As a developer working on a large monorepo, I want Sicario to scan 1 million lines of code in under 60 seconds and only re-scan files that have changed since the last scan, so that security scanning never becomes a bottleneck in my development workflow.

#### Acceptance Criteria

1. THE SAST_Engine SHALL complete a full scan of a codebase containing 1,000,000 source lines across JavaScript, TypeScript, Python, Go, Rust, and Java files within 60 seconds on a 4-core developer machine.
2. THE Sicario_CLI SHALL implement incremental scanning: WHEN `sicario scan` is run on a directory that has been scanned before, THE SAST_Engine SHALL only re-parse and re-match files whose content hash has changed since the last scan.
3. THE incremental scan cache SHALL be stored in `.sicario/cache/scan-cache.db` (the existing SQLite cache) and SHALL record the content hash, last-scanned timestamp, and finding fingerprints for each scanned file.
4. WHEN incremental scanning is active and no files have changed, THE SAST_Engine SHALL complete the scan in under 1 second by returning cached results without re-parsing any files.
5. WHEN incremental scanning is active and 10 files have changed in a 10,000-file project, THE SAST_Engine SHALL complete the scan in under 5 seconds by only re-parsing the 10 changed files.
6. THE Sicario_CLI SHALL accept a `--no-cache` flag that disables incremental scanning and forces a full re-scan of all files.
7. THE SAST_Engine SHALL use Rayon parallel iterators for file parsing and rule matching, distributing work across all available CPU cores.
8. THE SAST_Engine SHALL report scan throughput in the scan summary: `N files scanned in X.Xs (Y files/s, Z KLOC/s)`.
9. THE Sicario_CLI SHALL accept a `--jobs <N>` flag that limits the number of parallel worker threads used for scanning, defaulting to the number of logical CPU cores.
10. THE incremental scan cache SHALL be invalidated automatically when the rule set changes (new rules loaded, rule files modified), ensuring that cached results from an older rule set are never returned after a rule update.

---

### Requirement 17: Interactive Rule Authoring

**User Story:** As a security engineer writing custom rules, I want a `sicario rule test` command that shows live pattern matches against a code snippet and a `sicario rule validate` command that runs TP/TN assertions, so that I can iterate on rules in seconds rather than minutes.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL accept a `sicario rule test <pattern> <file>` subcommand that parses `<file>` with the Tree_Sitter_Engine and prints all AST nodes matching `<pattern>` with their file path, line number, column, and matched source text.
2. WHEN `sicario rule test` is invoked, THE Sicario_CLI SHALL complete and print results within 2 seconds for any single file up to 10,000 lines.
3. THE Sicario_CLI SHALL accept a `sicario rule test <pattern> --lang <language>` flag that specifies the language for parsing when the file extension is ambiguous.
4. THE Sicario_CLI SHALL accept a `sicario rule validate <rule-file>` subcommand that loads the YAML rule from `<rule-file>`, extracts its `test_cases` block, runs each test case through the SAST_Engine, and prints a pass/fail result for each test case.
5. WHEN `sicario rule validate` finds all test cases passing, THE Sicario_CLI SHALL exit with status code `0` and print `All N test cases passed for rule <rule-id>`.
6. WHEN `sicario rule validate` finds any failing test case, THE Sicario_CLI SHALL exit with status code `1` and print the failing test case code, the expected outcome, and the actual findings (if any).
7. THE Sicario_CLI SHALL accept a `sicario rule test --interactive` flag that enters a REPL loop where the user can type patterns and immediately see matches against a loaded file, with each pattern evaluated within 500ms.
8. THE `sicario rule test` output SHALL include a count of total matches and a list of matched node kinds to help the rule author understand which AST node types the pattern is matching.
9. THE Sicario_CLI SHALL accept a `sicario rule new` subcommand that scaffolds a new YAML rule file with the correct schema, placeholder fields, and an empty `test_cases` block, saving it to `.sicario/rules/<rule-id>.yaml`.
10. WHEN `sicario rule new` is invoked with `--from-finding <finding-id>`, THE Sicario_CLI SHALL pre-populate the rule scaffold with the `language`, `cwe_id`, and a pattern derived from the AST node of the specified finding, giving the rule author a starting point rather than a blank template.

---

### Requirement 18: Finding Fingerprinting and Cross-Branch Triage Propagation

**User Story:** As a security engineer, I want a finding triaged on one branch to automatically carry that triage state to all other branches where the same finding appears, so that I never have to triage the same vulnerability twice across feature branches, PRs, and the default branch.

#### Acceptance Criteria

1. THE SAST_Engine SHALL compute a `match_based_id` fingerprint for every finding using a SHA-256 hash of: the relative file path, the rule ID, and the rule pattern with all metavariable values substituted from the matched code. No raw source code SHALL be included in the fingerprint input — only the abstracted pattern with values.
2. THE SAST_Engine SHALL compute a `syntactic_id` fingerprint for every finding using a SHA-256 hash of: the relative file path, the rule ID, the literal matched code text, and the match index within the file. The `syntactic_id` is used for internal deduplication only and SHALL NOT be transmitted to Sicario Cloud.
3. WHEN a finding is published to Sicario Cloud via `--publish`, THE Sicario_CLI SHALL include the `match_based_id` in the telemetry payload alongside the existing finding metadata. The `match_based_id` SHALL be the only identifier used for cross-branch correlation — no source code is transmitted.
4. WHEN a finding's triage state is updated in Sicario Cloud (ignored, to-fix, reviewing), THE Sicario Cloud backend SHALL propagate that triage state to all other findings with the same `match_based_id` across all branches of the same project.
5. WHEN `sicario scan --publish` runs on a branch and a finding's `match_based_id` matches a finding that was previously triaged on another branch, THE Sicario_CLI SHALL receive the existing triage state from the cloud and display it alongside the finding in the scan output.
6. THE `match_based_id` SHALL be stable across line number changes: if lines are added or removed above the matched code without changing the matched code itself, the `match_based_id` SHALL remain identical.
7. WHEN the same rule matches the same code pattern multiple times in the same file, THE SAST_Engine SHALL append a zero-indexed counter to the `match_based_id` hash (e.g., `<hash>_0`, `<hash>_1`) to distinguish the instances while preserving their relationship.
8. THE `match_based_id` and `syntactic_id` SHALL be included in JSON output (`--format json`) as top-level fields on each finding object, enabling external tools to perform their own deduplication.
9. THE zero-exfiltration invariant SHALL be maintained: the `match_based_id` is an opaque hash — it reveals nothing about the source code to Sicario Cloud. Sicario Cloud SHALL never store or process raw source code as part of fingerprint computation.

---

### Requirement 19: Per-Rule Policy Modes and Cloud Policy Sync

**User Story:** As an AppSec team lead, I want to configure per-rule modes (Monitor, Comment, Block, Disabled) in the Sicario Cloud dashboard and have `sicario ci` automatically fetch and apply those modes before scanning, so that I can control which findings block PRs without modifying CI configuration files.

#### Acceptance Criteria

1. THE Sicario Cloud dashboard SHALL allow org admins to assign one of four modes to each rule: **Monitor** (finding goes to dashboard only), **Comment** (finding posts a PR/MR comment), **Block** (finding blocks the PR/MR and exits CI with code 1), or **Disabled** (rule is not applied during `sicario ci` scans).
2. THE Sicario_CLI SHALL accept a `sicario ci` subcommand that, when a `SICARIO_API_KEY` is present, fetches the org's current policy configuration from Sicario Cloud before scanning and applies the downloaded rule modes during the scan.
3. WHEN fetching the policy, THE Sicario_CLI SHALL download only a list of rule IDs and their assigned modes — no source code, no finding data, and no user data is transmitted during policy fetch. The policy payload is purely configuration metadata.
4. WHEN `sicario ci` runs and a finding is generated by a rule in **Block** mode, THE Sicario_CLI SHALL exit with status code `1` after uploading findings to the cloud.
5. WHEN `sicario ci` runs and a finding is generated by a rule in **Comment** mode, THE Sicario_CLI SHALL post a PR/MR comment via the SCM API and exit with status code `0`.
6. WHEN `sicario ci` runs and a finding is generated by a rule in **Monitor** mode, THE Sicario_CLI SHALL upload the finding to the cloud dashboard and exit with status code `0` without posting any PR/MR comment.
7. WHEN `sicario ci` runs and a rule is in **Disabled** mode, THE SAST_Engine SHALL skip that rule entirely during the scan, as if it were not loaded.
8. WHEN no `SICARIO_API_KEY` is present, `sicario ci` SHALL behave identically to `sicario scan` — using embedded rules, applying no cloud policy, and exiting with code `1` on any finding above the `--fail-on` threshold.
9. THE policy fetch SHALL be cached locally in `.sicario/cache/policy-<org-id>.json` with a TTL of 1 hour, so that `sicario ci` does not make a network request on every scan when the policy has not changed.
10. THE zero-exfiltration invariant SHALL be maintained: policy sync is a one-way download of rule configuration metadata. No source code, no file paths, and no finding data are transmitted during policy fetch.

---

### Requirement 20: Managed CI Config (Zero-Config Repo Onboarding)

**User Story:** As an AppSec team lead, I want to onboard hundreds of repositories to Sicario scanning from the dashboard without manually editing CI configuration files in each repo, so that I can achieve full coverage across my organization's codebase in minutes rather than weeks.

#### Acceptance Criteria

1. THE Sicario Cloud dashboard SHALL provide a "Scan new project" workflow that allows org admins to select one or more repositories from a connected GitHub or GitLab organization and automatically configure them for `sicario ci` scanning.
2. WHEN a repository is selected for onboarding, THE Sicario Cloud backend SHALL generate a CI workflow file (`.github/workflows/sicario.yml` for GitHub, `.gitlab-ci.yml` addition for GitLab) and commit it to the repository's default branch via the SCM API, using the org's service token.
3. THE generated CI workflow file SHALL configure `sicario ci` to run on every pull request (diff-aware scan) and on a daily schedule against the default branch (full scan). The workflow SHALL use the org's `SICARIO_API_KEY` stored as a repository secret.
4. THE Sicario Cloud backend SHALL NOT clone, store, or process any source code during the onboarding workflow. The onboarding action is limited to: reading the repository's default branch name, writing a CI workflow YAML file, and storing the repository secret. Source code analysis runs entirely on the customer's own CI runners.
5. WHEN the generated CI workflow runs for the first time, THE Sicario_CLI SHALL perform a full scan of the repository on the customer's CI runner, upload finding metadata to Sicario Cloud, and post PR comments according to the org's policy configuration.
6. THE Sicario Cloud dashboard SHALL display the onboarding status of each repository: Pending (workflow committed, first scan not yet run), Active (at least one scan completed), or Error (workflow present but scan failing).
7. THE generated CI workflow SHALL be idempotent: if the workflow file already exists in the repository, THE Sicario Cloud backend SHALL update it in place rather than creating a duplicate.
8. THE zero-exfiltration invariant SHALL be maintained and SHALL be explicitly documented in the generated CI workflow file as a comment: "Sicario scans run entirely on your CI runners. Only structured finding metadata (rule ID, file path, line number, severity) is uploaded to Sicario Cloud. Source code never leaves your infrastructure."
9. THE Sicario Cloud dashboard SHALL provide a "Remove from Sicario" action that deletes the generated CI workflow file from the repository and revokes the repository's service token, cleanly offboarding the repository from managed scanning.
10. THE Managed CI Config feature SHALL support GitHub Actions and GitLab CI/CD at launch. Azure DevOps and Bitbucket support SHALL be documented as planned for a future release.

---

### Requirement 21: Zero-Exfiltration Audit Log

**User Story:** As a security-conscious developer or enterprise compliance officer, I want every Sicario scan to produce a machine-readable audit log showing exactly what data was transmitted and to where, so that the zero-exfiltration guarantee is verifiable and auditable rather than just claimed.

#### Acceptance Criteria

1. WHEN `sicario scan` completes, THE Sicario_CLI SHALL write a machine-readable audit log entry to `.sicario/audit/scan-<ISO8601_timestamp>.json` recording: the scan start and end timestamps, the number of files scanned, the number of findings, and a `transmissions` array listing every outbound network call made during the scan.
2. EACH entry in the `transmissions` array SHALL contain: `destination` (the URL or service name), `payload_type` (one of: `finding_metadata`, `policy_fetch`, `telemetry_ping`, `llm_context`), `payload_size_bytes` (the size of the transmitted payload), `lines_of_code_transmitted` (always 0 for `finding_metadata`, `policy_fetch`, and `telemetry_ping`; the actual line count for `llm_context`), and `consent_obtained` (boolean, always `true` for `llm_context` transmissions).
3. WHEN no `--publish` flag is used and no `SICARIO_API_KEY` is set, THE `transmissions` array SHALL be empty, confirming that the scan was fully air-gapped.
4. WHEN `--publish` is active, THE `transmissions` array SHALL contain exactly one entry with `payload_type: finding_metadata`, `lines_of_code_transmitted: 0`, and `destination: "sicario-cloud"`.
5. WHEN `--allow-ai` or `--agent=cloud` is active, THE `transmissions` array SHALL contain one entry with `payload_type: llm_context`, `lines_of_code_transmitted: N` (the actual number of lines in the transmitted context), `consent_obtained: true`, and `destination` set to the LLM provider's endpoint hostname (e.g., `"api.anthropic.com"`).
6. WHEN `--agent=local` is active, THE `transmissions` array SHALL contain one entry with `payload_type: llm_context`, `destination: "127.0.0.1:11434"`, `lines_of_code_transmitted: N`, and `consent_obtained: true`. This confirms that the LLM call was made to the local Ollama instance only.
7. THE Sicario_CLI SHALL accept a `sicario audit show` subcommand that reads the most recent audit log entry and prints a human-readable summary in the format: `Scan completed. N findings. Transmissions: [list of destinations and payload types]. Lines of code transmitted: 0.`
8. THE Sicario_CLI SHALL accept a `sicario audit verify` subcommand that reads all audit log entries in `.sicario/audit/` and asserts that no entry contains a `transmissions` entry with `payload_type: llm_context` and `destination` not equal to `"127.0.0.1:11434"` unless `consent_obtained: true`. If any such entry is found, `sicario audit verify` SHALL exit with status code `1` and print the offending entry.
9. THE audit log SHALL be written atomically: the file is written to a `.tmp` path first and then renamed, so that a partial write never produces a corrupt audit entry.
10. THE Sicario_CLI SHALL include the path to the audit log in the scan summary output: `Audit log: .sicario/audit/scan-<timestamp>.json`. This makes the audit log discoverable without requiring users to know the path.
11. THE zero-exfiltration guarantee SHALL be formally stated in the audit log schema as a `guarantee` field with the value: `"Source code is never transmitted to Sicario Cloud. Only structured finding metadata (rule_id, file_path, line, severity, cwe_id, snippet_truncated_100_chars) is uploaded when --publish is active."` This field is present in every audit log entry regardless of whether `--publish` was used.

---

### Requirement 22: Finding Triage Lifecycle States

**User Story:** As an AppSec engineer, I want findings to carry rich triage states beyond open/ignored — including Reviewing, To Fix, and a clear distinction between Fixed and Removed — so that my team can track findings through a real remediation workflow and compute accurate MTTR.

#### Acceptance Criteria

1. THE Sicario Cloud backend SHALL support the following triage states for every finding: **Open** (default, finding is active and unaddressed), **Reviewing** (under investigation), **To Fix** (confirmed true positive, assigned for remediation), **Ignored** (deprioritized or false positive), **Fixed** (finding was present in a previous scan but is no longer detected due to a code change), and **Removed** (finding is no longer detected because the rule was disabled, the file was deleted, or the file was added to `.sicarioignore`).
2. THE Sicario Cloud dashboard SHALL allow users to transition a finding between **Open**, **Reviewing**, **To Fix**, and **Ignored** states manually via the findings UI.
3. WHEN a finding transitions to **Ignored**, THE Sicario Cloud backend SHALL require the user to select an ignore reason from: `false_positive`, `acceptable_risk`, or `no_time_to_fix`. An optional free-text comment SHALL also be accepted.
4. WHEN `sicario ci` rescans a branch and a previously detected finding is no longer present, THE Sicario_CLI SHALL mark the finding as **Fixed** if the code was changed, or **Removed** if the rule was disabled or the file was deleted/ignored.
5. THE **Fixed** and **Removed** states SHALL be mutually exclusive and SHALL be set automatically by the scan engine — they SHALL NOT be manually assignable by users.
6. WHEN computing MTTR, THE Sicario Cloud backend SHALL use only **Fixed** findings (not **Removed** findings) as the denominator for remediation velocity, since **Removed** findings do not represent actual code fixes.
7. THE Sicario_CLI SHALL include the `triage_state` field in JSON output (`--format json`) for every finding, with value one of: `open`, `reviewing`, `to_fix`, `ignored`, `fixed`, `removed`.
8. WHEN `sicario scan --publish` uploads findings, THE Sicario Cloud backend SHALL return the current `triage_state` for any finding whose `match_based_id` already exists in the cloud, and THE Sicario_CLI SHALL display that state alongside the finding in scan output.
9. THE Sicario Cloud backend SHALL maintain a full audit trail of triage state transitions per finding, recording: the previous state, the new state, the timestamp, the user who made the change, and the ignore reason (if applicable).
10. WHEN a finding is in **Reviewing** or **To Fix** state and a rescan detects it again, THE Sicario Cloud backend SHALL preserve the existing triage state rather than resetting it to **Open**.

---

### Requirement 23: PR Comment Triage Commands

**User Story:** As a developer, I want to triage Sicario findings directly from a pull request comment without opening the dashboard, so that I can dismiss false positives or acknowledge risks in the same workflow where I review code.

#### Acceptance Criteria

1. WHEN `sicario ci` posts a finding as a PR/MR comment in **Comment** or **Block** mode, THE comment SHALL include a footer section listing the available triage commands: `/fp <reason>`, `/ar <reason>`, `/other <reason>`, and `/open <reason>`.
2. WHEN a user replies to a Sicario PR comment with `/fp <reason>`, THE Sicario Cloud backend SHALL set the finding's triage state to **Ignored** with ignore reason `false_positive` and SHALL record the `<reason>` text as the triage comment.
3. WHEN a user replies to a Sicario PR comment with `/ar <reason>`, THE Sicario Cloud backend SHALL set the finding's triage state to **Ignored** with ignore reason `acceptable_risk` and SHALL record the `<reason>` text as the triage comment.
4. WHEN a user replies to a Sicario PR comment with `/other <reason>`, THE Sicario Cloud backend SHALL set the finding's triage state to **Ignored** with ignore reason `no_time_to_fix` and SHALL record the `<reason>` text as the triage comment.
5. WHEN a user replies to a Sicario PR comment with `/open <reason>`, THE Sicario Cloud backend SHALL reopen a previously ignored finding, setting its state back to **Open**, and SHALL record the `<reason>` text as the reopen comment.
6. AFTER processing a triage command, THE Sicario Cloud backend SHALL post a reply to the PR comment confirming the action taken, in the format: `✓ Finding marked as [state] (reason: [reason]). — Sicario`.
7. WHEN a triage command is received, THE Sicario Cloud backend SHALL propagate the triage state to all findings with the same `match_based_id` across all branches of the same project, consistent with Requirement 18.
8. THE PR comment triage feature SHALL require a valid `SICARIO_API_KEY` to be configured in the repository. If the webhook is received without a valid key, THE Sicario Cloud backend SHALL ignore the comment and SHALL NOT post a reply.
9. THE Sicario Cloud dashboard SHALL provide a toggle in org settings to enable or disable PR comment triage. When disabled, triage commands in PR comments SHALL be silently ignored.
10. THE zero-exfiltration invariant SHALL be maintained: triage commands contain only the command keyword and a free-text reason string. No source code is transmitted as part of the triage webhook payload.

---

### Requirement 24: Dashboard Backlog Activity and Guardrails Adoption Metrics

**User Story:** As an AppSec team lead, I want the Sicario Cloud dashboard to show backlog activity trends and guardrails adoption rates, so that I can demonstrate to engineering leadership that the security program is moving in the right direction.

#### Acceptance Criteria

1. THE Sicario Cloud dashboard SHALL display a **Backlog Activity** chart showing, per time period (daily/weekly/monthly, user-selectable): the count of new findings, fixed findings, ignored findings, and the net change (new − fixed − ignored) for the default branch.
2. THE Sicario Cloud dashboard SHALL display a **Production Backlog** chart showing the total count of open findings on the default branch over time, enabling teams to see whether the backlog is growing or shrinking.
3. THE Sicario Cloud dashboard SHALL display a **Guardrails Adoption** section showing: (a) the number of findings surfaced to developers in PR/MR comments as a percentage of total findings, and (b) the number of findings fixed before reaching the default branch as a percentage of findings shown in PR comments.
4. THE Sicario Cloud dashboard SHALL display a **Most Findings by Project** table listing projects sorted by open finding count, filterable by severity (Critical, High, Medium, Low) and scan type (SAST, supply-chain guard).
5. THE Sicario Cloud dashboard SHALL display a **Median Open Age** metric showing the median age (in days) of all currently open findings, grouped by severity. The median SHALL be used rather than the mean to avoid skew from long-tail outliers.
6. THE Sicario Cloud dashboard SHALL display an **MTTR by Severity** chart showing mean time to remediate broken down by severity level (Critical, High, Medium, Low), computed from **Fixed** findings only (not **Removed**).
7. ALL dashboard metrics SHALL be computable from the structured finding metadata already uploaded by `sicario ci --publish` (rule_id, file_path, line, severity, cwe_id, match_based_id, triage_state, timestamps). No additional source code access is required to compute any metric.
8. THE Sicario Cloud dashboard SHALL support filtering all charts by: date range, project, severity, CWE category, and rule ID.
9. THE Sicario Cloud dashboard SHALL provide a `sicario report --dashboard` CLI command that fetches the current dashboard metrics for the authenticated org and prints them as a structured JSON object, enabling ingestion into external observability tools (Datadog, Splunk, Grafana).
10. THE zero-exfiltration invariant SHALL be maintained: all dashboard metrics are derived from structured finding metadata. The dashboard SHALL never display, store, or process raw source code.

---

### Requirement 25: Finding Snippet vs. Hash in Publish Payload

**User Story:** As an enterprise compliance officer, I want the data Sicario uploads to the cloud to be provably non-reversible to source code, so that I can satisfy data residency and code confidentiality requirements without relying on contractual assurances alone.

#### Acceptance Criteria

1. WHEN `sicario scan --publish` uploads findings to Sicario Cloud, THE default payload for each finding SHALL include: `rule_id`, `file_path`, `line`, `column`, `severity`, `cwe_id`, `match_based_id`, `triage_state`, and a `code_hash` field — a one-way SHA-256 hash of the matched code text. The raw matched code SHALL NOT be included in the default payload.
2. THE `code_hash` field SHALL be computed as `SHA-256(matched_code_text)` and SHALL be used by Sicario Cloud solely for deduplication and change detection. It is not reversible to source code without the original text.
3. THE Sicario_CLI SHALL accept a `--publish-with-snippet` flag that, when explicitly provided, includes a `snippet` field in the upload payload containing the matched code truncated to 100 characters. This flag SHALL require explicit user opt-in and SHALL be documented as transmitting a partial code excerpt.
4. WHEN `--publish-with-snippet` is active, THE Audit_Log `transmissions` entry for the upload SHALL set `lines_of_code_transmitted` to the number of lines covered by all snippets in the payload, rather than 0.
5. THE Sicario Cloud dashboard SHALL display findings using the `rule_id`, `file_path`, `line`, and `severity` fields. It SHALL NOT require the `snippet` field to render a useful finding card.
6. THE zero-exfiltration guarantee statement in the Audit_Log `guarantee` field SHALL be updated to reflect the hash-based approach: `"Source code is never transmitted to Sicario Cloud. A one-way SHA-256 hash of matched code is uploaded for deduplication. The hash is not reversible to source code. Raw code excerpts are only transmitted when --publish-with-snippet is explicitly provided."`.
7. THE `code_hash` approach SHALL be documented in the Sicario Cloud privacy policy and in the `sicario audit show` output as the mechanism that makes the zero-exfiltration guarantee structurally verifiable rather than contractually asserted.
8. WHEN `--publish-with-snippet` is NOT provided (the default), THE `sicario audit verify` subcommand SHALL confirm that no `snippet` fields were transmitted by asserting that all `transmissions` entries with `payload_type: finding_metadata` have `lines_of_code_transmitted: 0`.

---

### Requirement 26: Branch Field on Findings and Production Backlog Scoping

**User Story:** As an AppSec team lead, I want every finding to carry the branch it was detected on, so that I can separate production backlog (default branch findings) from PR findings, and so that triage state propagates correctly across branches.

#### Acceptance Criteria

1. THE `findings` schema SHALL include a `branch` field (string) populated at scan-insert time from the scan record's `branch` field. All new findings inserted via `scans.insert` SHALL have `branch` set.
2. THE `listAdvanced` findings query SHALL accept a `branch` filter parameter that restricts results to findings detected on the specified branch.
3. THE `listAdvanced` findings query SHALL accept a `branchType` filter parameter with values `default` (findings on the project's configured primary branch) and `pr` (findings on any non-default branch).
4. THE `projects` schema SHALL include a `primaryBranch` field (string, default `"main"`) that identifies which branch is treated as the production default for backlog metrics.
5. WHEN computing the **Production Backlog** metric, THE analytics backend SHALL count only open findings whose `branch` matches the project's `primaryBranch`.
6. THE `scans.insert` mutation SHALL denormalize the `branch` value from the scan payload onto every finding it creates or updates, so that findings always reflect the branch of the scan that last detected them.
7. THE `analytics.overview` query SHALL accept an optional `branch` filter so that the summary counts can be scoped to a specific branch or to the primary branch only.
8. THE `analytics.trends` query SHALL accept an optional `branchType` filter so that the backlog activity chart can be scoped to default-branch findings only (production backlog view) or all findings.
9. WHEN a finding is detected on a PR branch and later detected on the default branch (after merge), THE Sicario Cloud backend SHALL preserve the finding's existing triage state rather than creating a duplicate, using `match_based_id` for correlation.
10. THE zero-exfiltration invariant SHALL be maintained: `branch` is a git branch name string. No source code is transmitted.

---

### Requirement 27: Structured Ignore Reason and Finding Event Log

**User Story:** As an AppSec engineer, I want triage actions to record a structured reason and be preserved in an append-only activity log per finding, so that my team can audit why a finding was ignored and track the full lifecycle of every vulnerability.

#### Acceptance Criteria

1. THE `findings` schema SHALL include an `ignoreReason` field with valid values: `"false_positive"`, `"acceptable_risk"`, `"no_time_to_fix"`, or `null`. This field SHALL only be set when `triageState` is `"Ignored"` or `"AutoIgnored"`.
2. THE `findings.triage` mutation SHALL accept an `ignoreReason` parameter and SHALL enforce that `ignoreReason` is non-null when `triageState` is `"Ignored"`.
3. THE `findings.bulkTriage` mutation SHALL accept an `ignoreReason` parameter with the same enforcement rule.
4. THE Sicario Cloud backend SHALL maintain a `findingEvents` table as an append-only event log with the following fields per event: `eventId`, `findingId`, `orgId`, `eventType` (one of: `opened`, `triaged`, `reopened`, `note_added`, `auto_fixed`, `auto_removed`), `fromState`, `toState`, `ignoreReason`, `userId`, `note`, `timestamp`.
5. WHEN any triage mutation is called, THE Sicario Cloud backend SHALL append a `findingEvents` record capturing the state transition, the actor, and any note or ignore reason.
6. WHEN a finding is auto-resolved (AutoFixed or AutoIgnored) by the scan engine, THE Sicario Cloud backend SHALL append a `findingEvents` record with `userId: null` and `eventType: "auto_fixed"` or `"auto_removed"` as appropriate.
7. THE `findings.getTimeline` query SHALL be replaced by a `findingEvents.list` query that returns all events for a given `findingId` in chronological order, including `eventType`, `fromState`, `toState`, `ignoreReason`, `userId`, `note`, and `timestamp`.
8. THE Sicario Cloud dashboard SHALL display the full event log on the finding detail page as an **Activity** panel, showing each event with its timestamp, actor, state transition, and any note.
9. THE `findingEvents` table SHALL support a `note_added` event type that allows any team member with at least `developer` role to append a free-text note to a finding's activity log without changing its triage state.
10. THE `findingEvents` records SHALL be immutable — no update or delete mutations SHALL exist for this table. The audit trail is append-only.

---

### Requirement 28: Findings Page — Group by Rule View and Missing Filters

**User Story:** As a security engineer reviewing findings for a large project, I want to group findings by rule and filter by branch, CWE, language, and date range, so that I can triage systematically by vulnerability class rather than scrolling through hundreds of individual findings.

#### Acceptance Criteria

1. THE Sicario Cloud backend SHALL expose a `findings.groupByRule` query that returns findings aggregated by `ruleId`, with each group containing: `ruleId`, `ruleName`, `severity`, `cweId`, `owaspCategory`, `openCount`, `affectedFiles` (array of distinct file paths, capped at 10), and `oldestFindingDate`.
2. THE `findings.groupByRule` query SHALL accept the same filter parameters as `listAdvanced` (orgId, severity, triageState, projectId, branch, branchType, dateFrom, dateTo) so that the grouped view respects all active filters.
3. THE `listAdvanced` findings query SHALL accept a `cweId` filter parameter that restricts results to findings with the specified CWE identifier.
4. THE `listAdvanced` findings query SHALL accept a `language` filter parameter that restricts results to findings whose `filePath` extension matches the specified language (e.g., `"javascript"` matches `.js` and `.jsx`; `"python"` matches `.py`).
5. THE `listAdvanced` findings query SHALL accept `dateFrom` and `dateTo` ISO-8601 string parameters that filter findings by `createdAt` timestamp.
6. THE `listAdvanced` findings query SHALL accept a `committedBy` filter parameter (string) that restricts results to findings whose `committedBy` field matches the specified committer identity.
7. THE `findings` schema SHALL include a `committedBy` field (string, nullable) populated from the scan's commit author metadata when available.
8. THE Sicario Cloud backend SHALL expose a `findings.savedFilters` table and associated CRUD mutations allowing users to save named filter presets (e.g., `"Critical open in auth service"`) scoped to their `orgId` and `userId`.
9. WHEN `findings.groupByRule` is called, THE query SHALL complete within 5 seconds for an org with up to 50,000 findings.
10. THE zero-exfiltration invariant SHALL be maintained: `committedBy` stores only the git committer name/email string from the scan metadata. No source code is transmitted.

---

### Requirement 29: Finding Detail Page — Activity, SCM Links, and Structured Taint Trace

**User Story:** As a developer reviewing a finding, I want to see the full activity history, a direct link to the vulnerable line in my SCM, and a structured dataflow trace, so that I can understand the finding's context and history without leaving the dashboard.

#### Acceptance Criteria

1. THE finding detail page SHALL display a direct **SCM deep link** to the vulnerable file and line, assembled as `{repositoryUrl}/blob/{commitSha}/{filePath}#L{line}` for GitHub and the equivalent for GitLab. This link SHALL be computed at display time from fields already stored on the finding and its parent scan.
2. THE `findings` schema SHALL include a `taintPath` field (nullable JSON array) with each element containing: `file` (string), `line` (number), `column` (number), `nodeType` (string), and `role` (one of: `"source"`, `"intermediate"`, `"sink"`). This replaces the existing unstructured `executionTrace: string[]` field.
3. WHEN a finding has a non-null `taintPath`, THE Sicario Cloud dashboard SHALL render the dataflow trace as a visual chain: `source (file:line) → [intermediate (file:line) →] sink (file:line)`, with each node linking to its SCM deep link.
4. THE finding detail page SHALL display the **CWE name and description** inline alongside the CWE identifier, sourced from a static CWE lookup table embedded in the dashboard frontend. No external API call is required.
5. THE finding detail page SHALL display the **OWASP category name and description** inline alongside the OWASP category identifier, sourced from a static lookup table.
6. THE finding detail page SHALL display the **branch** and **commit SHA** on which the finding was detected, sourced from the finding's `branch` field (Requirement 26) and the parent scan's `commitSha`.
7. THE finding detail page SHALL display a **permalink** — a stable URL that links directly to this finding's detail page — with a copy-to-clipboard button.
8. THE finding detail page SHALL display an **alert box** at the top of the page when the finding's severity is `Critical`, when `reachable` is `true`, or when `cloudExposed` is `true`, drawing the reviewer's attention to the highest-priority signals first.
9. THE `findings.triage` mutation SHALL accept a `note` parameter that, when provided, appends a `note_added` event to the `findingEvents` log (Requirement 27) without changing the triage state.
10. THE zero-exfiltration invariant SHALL be maintained: the SCM deep link is assembled client-side from metadata fields. No source code is fetched or displayed by the Sicario Cloud backend.

---

### Requirement 30: Projects Page — Tags, Primary Branch, Path Ignores, and Scan Metadata

**User Story:** As an AppSec team lead managing dozens of repositories, I want to tag projects, set their primary branch, configure path ignores, and see scan type and status at a glance, so that I can manage coverage and policy scoping at scale.

#### Acceptance Criteria

1. THE `projects` schema SHALL include a `tags` field (`string[]`, default `[]`) that allows org admins to attach arbitrary labels to a project (e.g., `"team:payments"`, `"external-facing"`, `"tier-1"`).
2. THE `projects.update` mutation SHALL accept a `tags` parameter that replaces the project's tag list. Tags SHALL be validated as non-empty strings with a maximum length of 64 characters each, and a maximum of 20 tags per project.
3. THE `projects.list` and `projects.listByOrg` queries SHALL accept a `tags` filter parameter (array of strings) that returns only projects matching all specified tags.
4. THE `projects` schema SHALL include a `primaryBranch` field (string, default `"main"`) configurable per project. This field is used by analytics queries to scope production backlog metrics (Requirement 26).
5. THE `projects` schema SHALL include a `pathIgnores` field (`string[]`, default `[]`) containing glob patterns for file paths to exclude from scan results. When a finding's `filePath` matches any pattern in `pathIgnores`, the finding SHALL be automatically set to `AutoIgnored` at insert time.
6. THE `scans` schema SHALL include a `scanType` field with values `"full"` and `"diff_aware"`. The CLI SHALL populate this field based on whether the scan was triggered on a PR event (diff-aware) or a push/schedule event (full).
7. THE `scans` schema SHALL include a `scanStatus` field with values `"completed"`, `"error"`, and `"running"`. Scans inserted via `scans.insert` SHALL default to `"completed"`. A future `scans.markError` mutation SHALL allow the CLI to report scan failures.
8. THE `projects.listByOrg` query SHALL return, for each project, the `lastScanAt` timestamp, `lastScanStatus`, `lastScanType`, and `openFindingsCount` as computed fields, so that the Projects page can display a rich summary row without additional queries.
9. THE Sicario Cloud dashboard SHALL display a **Scanning** tab (projects with at least one completed scan) and a **Not Scanning** tab (projects with no completed scan or in `pending` provisioning state) on the Projects page.
10. THE `projects.update` mutation SHALL accept a `pathIgnores` parameter. WHEN `pathIgnores` is updated, THE Sicario Cloud backend SHALL retroactively apply the new ignore patterns to all existing open findings for that project, setting matching findings to `AutoIgnored`.

---

### Requirement 31: Analytics — Date Range Filters, Fix Rate, and Guardrails Adoption

**User Story:** As an AppSec team lead, I want all dashboard analytics to be filterable by date range and project, and I want to see fix rate and guardrails adoption metrics, so that I can track security program progress over any time window.

#### Acceptance Criteria

1. THE `analytics.overview` query SHALL accept `dateFrom`, `dateTo`, and `projectId` optional parameters. When provided, all counts SHALL be scoped to findings created within the date range and/or belonging to the specified project.
2. THE `analytics.mttr` query SHALL accept `dateFrom`, `dateTo`, and `projectId` optional parameters with the same scoping behavior.
3. THE `analytics.topVulnerableProjects` query SHALL accept `dateFrom` and `dateTo` optional parameters that scope the open finding counts to findings created within the date range.
4. THE `analytics.owaspCompliance` query SHALL accept `dateFrom`, `dateTo`, and `projectId` optional parameters.
5. THE `analytics.trends` query SHALL accept a `branchType` parameter (`"default"` or `"all"`) and a `projectId` parameter, in addition to the existing `from`/`to`/`interval` parameters.
6. THE Sicario Cloud backend SHALL expose an `analytics.fixRate` query that returns, for the specified org (and optional `projectId`, `dateFrom`, `dateTo`): `totalDetected`, `totalFixed`, `totalIgnored`, `fixRatePct` (fixed / detected × 100), and `ignoreRatePct`.
7. THE `findings` schema SHALL include a `surfacedInPr` boolean field (default `false`) set to `true` at insert time when the finding was detected during a diff-aware scan on a PR branch and the rule's policy mode is `"comment"` or `"block"`.
8. THE Sicario Cloud backend SHALL expose an `analytics.guardrailsAdoption` query that returns: `findingsSurfacedInPr`, `findingsTotal`, `adoptionRatePct`, `fixedBeforeBacklog` (findings surfaced in PR that were Fixed before appearing on the default branch), and `fixedBeforeBacklogPct`.
9. THE `analytics.medianOpenAge` query SHALL return, for each severity level, the median age in days of all currently open findings, computed as `median(now - createdAt)` across open findings for the specified org (and optional `projectId`).
10. THE zero-exfiltration invariant SHALL be maintained: all analytics queries operate on structured finding metadata fields. No source code is accessed or returned by any analytics query.

---

### Requirement 32: SARIF Export and Group-by-Rule Findings View

**User Story:** As a security engineer, I want to export findings as SARIF 2.1.0 for integration with GitHub Advanced Security and other SARIF-compatible tools, and I want a Group by Rule view in the dashboard that reduces visual noise when many findings share the same root cause.

#### Acceptance Criteria

1. THE Sicario Cloud backend SHALL expose a `findings.exportSarif` query that returns a SARIF 2.1.0-compliant JSON document for all findings matching the specified filters (orgId, projectId, severity, triageState).
2. THE SARIF output SHALL include, for each finding: `ruleId`, `message.text` (rule name + CWE), `locations[0].physicalLocation` (file path + line + column), `level` (mapped from Sicario severity: Critical/High → `"error"`, Medium → `"warning"`, Low/Info → `"note"`), and `fingerprints.matchBasedId`.
3. THE SARIF output SHALL include a `runs[0].tool.driver.rules` array listing each unique rule with its `id`, `name`, `shortDescription.text`, `helpUri` (link to CWE reference), and `properties.tags` (OWASP category, CWE ID).
4. THE SARIF `$schema` field SHALL be set to `"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"` and `version` SHALL be `"2.1.0"`.
5. THE Sicario_CLI SHALL accept a `sicario scan --format sarif` flag that outputs findings as SARIF 2.1.0 to stdout, enabling direct upload to GitHub Advanced Security via `github/codeql-action/upload-sarif`.
6. THE Sicario Cloud dashboard SHALL provide a **Group by Rule** toggle on the Findings page. When enabled, findings SHALL be displayed as rule cards, each showing the rule name, severity, CWE, open finding count, and a list of up to 5 affected file paths.
7. WHEN **Group by Rule** is active, clicking a rule card SHALL expand it to show the individual findings for that rule, or navigate to a filtered **No Grouping** view pre-filtered to that rule ID.
8. THE `findings.groupByRule` query (Requirement 28) SHALL be the data source for the Group by Rule view.
9. THE SARIF export SHALL be available via the dashboard UI as a download button on the Findings page, in addition to the CLI flag.
10. THE zero-exfiltration invariant SHALL be maintained: the SARIF export contains only structured finding metadata (rule_id, file_path, line, severity, CWE). The `snippet` field SHALL NOT be included in SARIF output unless `--publish-with-snippet` was active when the finding was uploaded.

---

### Requirement 33: Jira Integration and Viewer Role

**User Story:** As an AppSec team lead, I want to create Jira tickets from findings with a single click and assign read-only dashboard access to stakeholders who should see metrics but not triage findings.

#### Acceptance Criteria

1. THE Sicario Cloud backend SHALL support a Jira integration configuration per org, storing: `jiraBaseUrl`, `jiraProjectKey`, `jiraIssueType` (default `"Bug"`), and an encrypted `jiraApiToken`. These SHALL be configurable from the org Settings page.
2. WHEN a Jira integration is configured, THE Sicario Cloud dashboard SHALL display a **Create Jira Ticket** button on the finding detail page and on the Group by Rule card.
3. WHEN **Create Jira Ticket** is triggered for a finding, THE Sicario Cloud backend SHALL POST to the Jira REST API with a ticket containing: `summary` (`[Sicario] {ruleName} in {filePath}:{line}`), `description` (rule description + CWE + OWASP category + remediation guidance + finding permalink), `priority` (mapped from severity), and `labels` (`["sicario", "security", cweId]`). No source code SHALL be included in the Jira ticket payload.
4. WHEN a Jira ticket is created for a finding, THE Sicario Cloud backend SHALL store the Jira issue key (e.g., `SEC-123`) on the finding record and display it as a link on the finding detail page.
5. WHEN a Jira ticket is created, THE Sicario Cloud backend SHALL append a `findingEvents` record (Requirement 27) with `eventType: "jira_ticket_created"` and the Jira issue key as the note.
6. THE Jira integration SHALL support bulk ticket creation: selecting multiple findings in the Group by Rule view and clicking **Create Jira Tickets** SHALL create one ticket per selected finding (up to 75 findings per bulk operation).
7. THE RBAC system SHALL include a `viewer` role with read-only access: viewers can read findings, analytics, and project data but cannot call any mutation (triage, bulk triage, create project, update project, etc.).
8. THE `ROLE_LEVELS` map in `rbac.ts` SHALL be updated to include `viewer: 0` below `developer: 1`. The `requireRole` function SHALL enforce that `viewer` role users are blocked from all mutations.
9. THE `memberships.create` mutation SHALL accept `"viewer"` as a valid role value.
10. THE zero-exfiltration invariant SHALL be maintained: the Jira ticket payload contains only structured finding metadata and a human-readable remediation message. No source code, no `snippet` field, and no `code_hash` are included in the Jira API request.

---

### Requirement 34: Signup and Account Creation Flow

**User Story:** As a new user, I want to sign up for Sicario with my GitHub account or email/password in under 60 seconds, and immediately land in a state where I understand what to do next, so that I don't have to read documentation to get my first scan running.

#### Acceptance Criteria

1. THE Sicario signup page SHALL offer three authentication paths: **Continue with GitHub** (OAuth), **Continue with GitLab** (OAuth), and **Sign up with email** (email + password). All three paths SHALL be available on the same page without requiring navigation.
2. WHEN a user signs up via GitHub or GitLab OAuth, THE Sicario Cloud backend SHALL automatically populate the user's display name and email from the OAuth provider's profile. No additional form fields SHALL be required before the user reaches the dashboard.
3. WHEN a user signs up via email/password, THE Sicario Cloud backend SHALL send a welcome email immediately after account creation. The welcome email SHALL include the two-command quickstart (`curl ... | sh` and `sicario scan . --publish`) so the user can start scanning without opening the dashboard.
4. WHEN a new user's account is created for the first time (not an existing user logging in), THE Sicario Cloud backend SHALL automatically create a personal organization named `{displayName}'s Organization`, assign the user as `admin`, and seed a free-tier subscription — all in a single atomic operation before the user sees the dashboard.
5. THE Sicario Cloud backend SHALL automatically redeem any pending invitations for the user's email address at account creation time, adding the user to any organizations they were invited to before they signed up.
6. WHEN a user signs up via GitHub OAuth, THE Sicario Cloud backend SHALL offer to connect the user's GitHub organization to Sicario during the signup flow, so that the user can onboard repositories immediately after account creation without a separate settings step.
7. THE signup page SHALL display a zero-exfiltration trust badge with the text: "Your source code never leaves your machine. Only structured finding metadata is uploaded." This SHALL be visible before the user clicks any signup button.
8. THE signup flow SHALL complete — from clicking "Continue with GitHub" to landing on the dashboard — in no more than 3 redirects and no more than 10 seconds on a standard connection.
9. WHEN a user who was invited to an existing org signs up, THE Sicario Cloud backend SHALL redirect them to that org's dashboard rather than creating a new personal org, if the invitation was the primary reason for signup.
10. THE Sicario Cloud backend SHALL NOT require email verification before allowing a new user to access the dashboard and run their first scan. Email verification SHALL be optional and prompted as a non-blocking nudge after the user's first scan completes.

---

### Requirement 35: Post-Signup Onboarding Wizard

**User Story:** As a new user who just created an account, I want a guided onboarding wizard that collects my role and goals, then walks me through connecting a repository and running my first scan, so that I reach a populated dashboard with real findings rather than an empty state.

#### Acceptance Criteria

1. WHEN a new user lands on the dashboard for the first time (determined by `userProfiles.onboardingCompleted === false` and `userProfiles.onboardingSkipped === false`), THE dashboard SHALL display a full-screen onboarding wizard rather than the empty dashboard.
2. THE onboarding wizard SHALL consist of exactly four steps, displayed as a progress indicator: **Step 1 — About You**, **Step 2 — Connect Your Code**, **Step 3 — Run Your First Scan**, **Step 4 — See Your Findings**.
3. **Step 1 — About You** SHALL collect: the user's role (Security Engineer, Developer, AppSec Lead, DevOps Engineer, Other), their team size (Solo, 2–10, 11–50, 51–200, 200+), their primary languages (multi-select: JavaScript/TypeScript, Python, Go, Rust, Java, Ruby, PHP, C#, Other), and their primary goal (Find vulnerabilities in my code, Set up CI scanning for my team, Evaluate Sicario for my org, Other). All fields SHALL be optional — the user can skip Step 1 entirely.
4. THE data collected in Step 1 SHALL be saved to `userProfiles` via the existing `userProfiles.upsert` mutation. This data SHALL be used only to personalize the onboarding experience (e.g., showing the correct install command for their OS, pre-selecting relevant language rules). It SHALL NOT be transmitted to any third party.
5. **Step 2 — Connect Your Code** SHALL present three paths: **Scan locally with the CLI** (the default and recommended path — no SCM connection required), **Set up CI scanning on GitHub** (for teams who want automated CI), and **Set up CI scanning on GitLab** (for teams who want automated CI). A fourth option, **Skip for now — show me a demo**, SHALL always be available. The CLI path SHALL be visually emphasized as the primary option.
6. WHEN the user selects **Scan locally with the CLI**, Step 2 SHALL display a personalized install command based on the user's OS (detected from the browser's `navigator.userAgent`) and a `sicario login` command that links the CLI to their account via device auth (Requirement 37). No GitHub or GitLab connection is required for this path. The user's source code never leaves their machine on this path.
7. WHEN the user selects **Set up CI scanning on GitHub** or **Set up CI scanning on GitLab**, THE dashboard SHALL display an explicit permission disclosure before initiating any OAuth flow, stating: "Sicario will request permission to read your repository list and write one CI workflow file. Sicario will never read your source code." The user must click **I understand — continue** to proceed. THE SCM OAuth connection SHALL request only the minimum scopes required to write a CI workflow file and store a repository secret: `repo` scope on GitHub (scoped to selected repositories only via GitHub App installation), `api` scope on GitLab. THE Sicario Cloud backend SHALL use these permissions exclusively to: (a) list repository names and default branch names, (b) commit the generated CI workflow YAML file, and (c) store the `SICARIO_API_KEY` as a repository secret. THE Sicario Cloud backend SHALL NOT read any file contents, commit history, pull request data, or any other repository data beyond what is listed in (a)–(c).
8. WHEN the user selects **Skip for now — show me a demo**, THE Sicario Cloud backend SHALL load a pre-seeded demo project (based on OWASP Juice Shop findings) into the user's org so that the dashboard is populated with realistic findings immediately. The demo project SHALL be clearly labeled as `[Demo]` and SHALL be deletable at any time.
9. **Step 3 — Run Your First Scan** SHALL display a real-time status indicator that polls for the first scan result for the user's org. WHEN a scan result arrives (either from the CLI or from the Managed CI Config workflow), the step SHALL automatically advance to Step 4 without requiring the user to click anything.
10. **Step 4 — See Your Findings** SHALL display a summary of the first scan: total findings, severity breakdown (Critical/High/Medium/Low), and the top 3 findings by severity with their rule name, file path, and line number. A **Go to Dashboard** button SHALL complete the onboarding wizard and mark `userProfiles.onboardingCompleted = true`.
11. THE onboarding wizard SHALL be dismissible at any step via a **Skip setup** link that calls `userProfiles.skipOnboarding`. Users who skip SHALL land on the empty dashboard with a persistent **Getting Started** banner that can re-launch the wizard.
12. THE zero-exfiltration invariant SHALL be maintained throughout onboarding: the wizard collects only profile metadata (role, team size, languages, goals). No source code is accessed or transmitted during any onboarding step.

---

### Requirement 36: Empty State and Getting Started Checklist

**User Story:** As a new user who skipped the onboarding wizard or has no findings yet, I want the dashboard to show me a clear checklist of what to do next rather than a blank page, so that I always know my next action.

#### Acceptance Criteria

1. WHEN a user's org has zero completed scans, THE dashboard home page SHALL display an **empty state** with a **Getting Started** checklist instead of the analytics charts. The analytics charts SHALL be hidden until at least one scan has completed.
2. THE Getting Started checklist SHALL contain the following items, each with a completion indicator (checked/unchecked): ☐ **Install the CLI** (links to install docs), ☐ **Log in to your account** (`sicario login`), ☐ **Run your first scan** (`sicario scan . --publish`), ☐ **Add a project** (links to project creation), ☐ **Invite your team** (links to member invite), ☐ **Set up CI scanning** (links to Managed CI Config).
3. EACH checklist item SHALL be automatically marked as complete when the corresponding action is detected: CLI install is inferred from the first `usagePings` record for the org; login is inferred from the first device auth token issued; first scan is inferred from the first `scans` record; project creation from the first `projects` record; team invite from the first `pendingInvitations` record; CI setup from the first project with `provisioningState: "active"` that was created via the Managed CI Config flow.
4. WHEN all six checklist items are complete, THE Getting Started checklist SHALL be replaced by the full analytics dashboard. A **Dismiss** option SHALL allow users to hide the checklist early.
5. THE empty state SHALL include a **See a demo** button that loads the pre-seeded demo project (Requirement 35, AC 8) so the user can explore the dashboard without running a real scan.
6. WHEN a user has completed onboarding but their org has findings, THE dashboard SHALL display the full analytics view with no empty state. The Getting Started checklist SHALL be accessible from a collapsible **Getting Started** section in the sidebar, not shown as the primary content.
7. THE Getting Started checklist completion state SHALL be stored server-side (derived from actual data, not a separate boolean field) so that it is consistent across devices and sessions.
8. THE empty state SHALL display the zero-exfiltration guarantee prominently: "Sicario scans run entirely on your machine. Only structured finding metadata is uploaded here." This reinforces the trust message at the moment when the user is deciding whether to run their first scan.
9. THE Sicario_CLI SHALL display a post-scan message when `--publish` is active and the scan is the user's first: "First scan complete. View your findings at https://app.usesicario.xyz/dashboard". This bridges the CLI experience back to the dashboard.
10. THE `userProfiles` schema SHALL include a `lastNotificationDismissedAt` field (already present) used to track when the user last dismissed the Getting Started banner, so it does not reappear on every page load after dismissal.

---

### Requirement 37: CLI Device Auth Login Flow (`sicario login`)

**User Story:** As a developer, I want to run `sicario login` in my terminal and be authenticated to Sicario Cloud in under 30 seconds without copying and pasting API keys, so that I can start publishing scan results immediately after installing the CLI.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL accept a `sicario login` subcommand that initiates a device authorization flow: the CLI generates a device code, prints a URL and user code to the terminal, and polls the Sicario Cloud backend for approval.
2. WHEN `sicario login` is run, THE Sicario_CLI SHALL print output in the format:
   ```
   Open this URL in your browser to log in:
   https://app.usesicario.xyz/device?code=XXXX-XXXX

   Waiting for authorization...
   ```
   The URL SHALL be openable directly from most terminals via click or Cmd/Ctrl+click.
3. THE Sicario Cloud dashboard SHALL display a **Device Authorization** page at `/device?code=XXXX-XXXX` that shows the user code, the device name (derived from the CLI's hostname), and **Approve** / **Deny** buttons. The user SHALL be required to be logged in to the dashboard to approve.
4. WHEN the user clicks **Approve**, THE Sicario Cloud backend SHALL issue a long-lived access token, store it in the `deviceCodes` table (already present in schema), and make it available to the CLI's polling endpoint.
5. WHEN the CLI's polling detects an approved token, THE Sicario_CLI SHALL store the token in the global config file (`~/.sicario/config.toml` under `[auth] token = "..."`) and print: `✓ Logged in as {email}. Your scans will now publish to {orgName}.`
6. THE device code SHALL expire after 15 minutes if not approved. WHEN the code expires, THE Sicario_CLI SHALL print: `Login timed out. Run 'sicario login' to try again.` and exit with status code 1.
7. WHEN `sicario login` is run and a valid token already exists in the config, THE Sicario_CLI SHALL print: `Already logged in as {email}. Run 'sicario logout' to switch accounts.` and exit with status code 0 without opening a browser.
8. THE Sicario_CLI SHALL accept a `sicario logout` subcommand that removes the stored token from `~/.sicario/config.toml` and prints: `Logged out. Run 'sicario login' to authenticate again.`
9. THE device auth flow SHALL NOT require the user to copy and paste any token or API key. The entire flow SHALL be completable by clicking a link and clicking one button in the browser.
10. THE zero-exfiltration invariant SHALL be maintained: the device auth flow transmits only the device code, user code, and the resulting access token. No source code, no finding data, and no project metadata are transmitted during the login flow.

---

### Requirement 38: Onboarding Emails — First Scan Nudge and Day-3 Re-engagement

**User Story:** As a new user who signed up but hasn't run a scan yet, I want to receive a timely, helpful email that shows me exactly how to run my first scan, so that I don't forget about Sicario and lose momentum.

#### Acceptance Criteria

1. THE Sicario Cloud backend SHALL send a **First Scan Nudge** email to any new user who has not completed a scan within 24 hours of account creation. This email SHALL be sent exactly once per user.
2. THE First Scan Nudge email SHALL contain: a subject line of `"Run your first Sicario scan"`, a two-step quickstart (install command + `sicario scan . --publish`), a link to the dashboard, and a link to the docs. The email SHALL be styled consistently with the existing email design system in `emails.ts`.
3. THE Sicario Cloud backend SHALL send a **Day-3 Re-engagement** email to any user who has not completed a scan within 72 hours of account creation. This email SHALL be sent exactly once per user and only if the First Scan Nudge was already sent.
4. THE Day-3 Re-engagement email SHALL contain: a subject line of `"Still haven't scanned? Here's a 60-second path"`, a link to the demo project option, a link to the Managed CI Config quickstart, and a one-click unsubscribe link.
5. WHEN a user completes their first scan, THE Sicario Cloud backend SHALL cancel any pending nudge or re-engagement emails for that user that have not yet been sent.
6. THE Sicario Cloud backend SHALL send a **First Findings** email when a user's first scan completes and produces at least one finding. This email SHALL contain: the total finding count, the count of Critical and High findings, the name of the scanned project, and a **View Findings** button linking to the dashboard.
7. THE First Findings email SHALL be sent only once per user (on their first scan with findings). Subsequent scans SHALL trigger the existing critical findings alert email (already implemented) only when the severity threshold is met.
8. ALL onboarding emails SHALL include a one-click unsubscribe link that sets a `marketingEmailsOptedOut: boolean` field on the user's profile. Transactional emails (password reset, invitation, critical alerts) SHALL NOT be affected by this opt-out.
9. THE `userProfiles` schema SHALL include `firstScanNudgeSentAt`, `dayThreeReengagementSentAt`, and `firstFindingsEmailSentAt` timestamp fields (nullable) to track which onboarding emails have been sent and prevent duplicates.
10. THE onboarding email sequence SHALL be implemented as Convex scheduled functions (crons) that run hourly and check for users who meet the send criteria. The cron SHALL be idempotent — running it multiple times SHALL NOT send duplicate emails.

---

### Requirement 39: Custom Rule Editor — Dashboard Rule Authoring

**User Story:** As a security engineer, I want to write, test, and save custom security rules directly in the Sicario dashboard and have them automatically available to the CLI on the next scan, so that I can encode organization-specific security policies without editing YAML files by hand.

#### Acceptance Criteria

1. THE Sicario Cloud dashboard SHALL provide a **Rule Editor** page at `/dashboard/policies/rules/new` (and `/dashboard/policies/rules/:id/edit` for editing existing rules) with a split-pane layout: a YAML editor on the left and a live test panel on the right.

2. THE YAML editor SHALL be a syntax-highlighted, line-numbered code editor pre-populated with a rule scaffold containing all required fields:
   ```yaml
   - id: "org/my-rule-name"
     name: "My Rule Name"
     description: ""
     severity: High
     languages:
       - JavaScript
     pattern:
       query: ""
       captures:
         - "match"
     cwe_id: null
     owasp_category: null
     test_cases:
       - code: ""
         expected: TruePositive
       - code: ""
         expected: TrueNegative
   ```

3. THE live test panel SHALL contain a code input area where the user can paste a code snippet. WHEN the user types in the YAML editor or the test code area, THE dashboard SHALL send the current rule YAML and test code to a validation endpoint and display the match result within 2 seconds — highlighted matched nodes if the pattern fires, or "No match" if it does not.

4. THE validation endpoint SHALL accept `{rule_yaml: string, test_code: string, language: string}` and return `{matched: boolean, match_locations: [{line, column, end_line, end_column, node_type}], error: string | null}`. The test code is sent to the Sicario Cloud backend for validation — it is treated as ephemeral test data, is never stored, and is deleted from memory immediately after the validation response is returned.

5. THE dashboard SHALL display a **Schema Validation** panel below the YAML editor showing real-time validation errors for the rule YAML (missing required fields, invalid severity values, unknown language names, malformed tree-sitter query syntax). Errors SHALL be shown as inline annotations in the editor gutter and as a list below the editor.

6. THE dashboard SHALL provide an **AI Assist** button that, when clicked, opens a panel where the user can describe the vulnerability in plain English (e.g. "detect SQL queries built with string concatenation in JavaScript"). The panel generates a copyable `sicario rule new --description "..." --lang <language> --severity <severity>` CLI command client-side — no backend API call is made. The user runs this command locally; the LLM call happens on their machine using their configured provider (Ollama, Claude, GPT-4, or any BYOK provider). The generated rule is saved to `.sicario/rules/` and synced to the dashboard via `sicario rule push`. A "Paste YAML" shortcut allows users who have already run the CLI to paste the generated YAML directly into the editor. The AI Assist panel includes a note: "Your LLM keys stay on your machine. Sicario Cloud never sees them."

7. THE dashboard SHALL display a **Test Cases** section in the test panel showing the results of running all `test_cases` blocks from the rule YAML against the validation engine. Each test case SHALL show: the code snippet, the expected outcome (TruePositive/TrueNegative), and the actual outcome (pass ✓ / fail ✗). This mirrors the `sicario rule validate` CLI command.

8. WHEN the user clicks **Save Rule**, THE Sicario Cloud backend SHALL store the rule YAML in a `customRules` table scoped to the org, with fields: `ruleId`, `orgId`, `name`, `yaml`, `language`, `severity`, `cweId`, `owaspCategory`, `isEnabled`, `policyMode` (Monitor/Comment/Block/Disabled), `createdBy`, `createdAt`, `updatedAt`. The rule SHALL be validated server-side before saving — invalid YAML or invalid tree-sitter queries SHALL be rejected with a descriptive error.

9. WHEN `sicario ci` runs and a `SICARIO_API_KEY` is present, THE Sicario_CLI SHALL fetch the org's custom rules from Sicario Cloud as part of the policy sync (Requirement 19). Custom rules SHALL be downloaded as YAML and written to a temporary directory, then loaded into the SAST engine alongside the embedded built-in rules. Custom rules SHALL take precedence over built-in rules with the same `id`.

10. THE custom rule download payload SHALL contain only the rule YAML (id, name, description, severity, languages, pattern, cwe_id, owasp_category, test_cases). No source code, no finding data, and no user data is included in the custom rule download. The download is a one-way pull of rule configuration metadata — consistent with the zero-exfil model.

11. THE Sicario_CLI SHALL accept a `sicario rule push` subcommand that reads all YAML files from `.sicario/rules/` and uploads them to Sicario Cloud, making locally-authored rules available to the dashboard and to all team members. This is the inverse of the policy sync download.

12. THE Sicario_CLI SHALL accept a `sicario rule pull` subcommand that downloads all org custom rules from Sicario Cloud and writes them to `.sicario/rules/`, making dashboard-authored rules available for local scans without requiring `sicario ci`.

13. THE Rules & Policies page (`/dashboard/policies`) SHALL display a table of all custom rules with columns: Rule ID, Name, Language, Severity, CWE, Policy Mode, Status (Enabled/Disabled), Last Updated, Actions (Edit, Duplicate, Delete). Built-in rules SHALL be listed in a separate read-only section below the custom rules table.

14. THE dashboard SHALL allow users to **fork** any built-in rule: clicking "Fork" on a built-in rule creates a copy in the custom rules table with the same YAML, prefixed with `org/`, which the user can then edit. This is equivalent to Semgrep's "fork rule" feature in their editor.

15. THE zero-exfiltration invariant SHALL be maintained throughout the rule editor: test code entered in the live test panel is ephemeral and never stored; rule YAML contains only pattern metadata (no source code); the AI Assist feature sends only the plain-English description to the LLM, never source code.

---

### Requirement 40: Custom Rule Sync — CLI ↔ Dashboard Round-Trip

**User Story:** As a developer, I want rules I write locally with `sicario rule new` or by editing YAML files to automatically sync to the dashboard, and rules my AppSec team writes in the dashboard to automatically appear in my local scans, so that the team's security policies are always consistent regardless of where they were authored.

#### Acceptance Criteria

1. WHEN `sicario ci --publish` runs, THE Sicario_CLI SHALL include a `custom_rules_hash` field in the scan metadata payload — a SHA-256 hash of all custom rule IDs and their content hashes. This allows the cloud to detect when the local rule set has diverged from the cloud rule set.

2. WHEN the `custom_rules_hash` in a scan payload differs from the hash of the org's cloud-stored custom rules, THE Sicario Cloud backend SHALL include a `rules_out_of_sync: true` flag in the scan acknowledgment response, prompting the CLI to display: `[sicario] Custom rules are out of sync. Run 'sicario rule pull' to fetch the latest rules from the dashboard.`

3. THE `sicario rule push` subcommand SHALL upload all YAML files from `.sicario/rules/` to Sicario Cloud. WHEN a rule with the same `id` already exists in the cloud, THE CLI SHALL prompt: `Rule '{id}' already exists in the cloud. Overwrite? [y/N]` unless `--force` is specified.

4. THE `sicario rule pull` subcommand SHALL download all org custom rules from Sicario Cloud and write them to `.sicario/rules/`. WHEN a local file with the same rule ID already exists, THE CLI SHALL prompt: `Rule '{id}' exists locally. Overwrite? [y/N]` unless `--force` is specified.

5. THE `sicario rule push` and `sicario rule pull` subcommands SHALL require a valid `SICARIO_API_KEY` in the environment or `~/.sicario/config.toml`. If no key is present, THE CLI SHALL print: `Not authenticated. Run 'sicario login' first.`

6. THE `sicario rule list` subcommand SHALL display a table of all rules currently loaded (embedded built-in rules + custom rules from `.sicario/rules/`), showing: Rule ID, Name, Language, Severity, Source (built-in / local / cloud-synced).

7. WHEN `sicario scan` runs without `--publish` and without a `SICARIO_API_KEY`, THE CLI SHALL still load custom rules from `.sicario/rules/` automatically (this already works per the existing `main.rs` logic). The sync commands are additive — they do not change the existing local-first behavior.

8. THE Sicario Cloud backend SHALL expose a `GET /api/v1/orgs/{org_id}/rules` endpoint that returns all custom rules for the org as a JSON array of rule objects. This endpoint is authenticated via `SICARIO_API_KEY` and is used by both `sicario rule pull` and the policy sync in `sicario ci`.

9. THE Sicario Cloud backend SHALL expose a `PUT /api/v1/orgs/{org_id}/rules/{rule_id}` endpoint that creates or updates a custom rule. This endpoint validates the rule YAML server-side before storing it.

10. THE zero-exfiltration invariant SHALL be maintained: `sicario rule push` transmits only rule YAML (pattern metadata). `sicario rule pull` downloads only rule YAML. No source code is transmitted in either direction.

---

### Requirement 41: Rule Editor — Share via URL

**User Story:** As a security engineer, I want to share a rule and its test code via a URL so that teammates can open the exact same editor state without needing to save the rule first, and so I can publish rules to the community registry with a single click.

#### Acceptance Criteria

1. THE Rule Editor SHALL display a **Share** button in the top menu bar. Clicking it opens a Share modal with three options: **Copy link** (private), **Make public**, and **Publish to Registry**.

2. **Copy link (private):** THE dashboard SHALL generate a URL in the format `https://app.usesicario.xyz/editor?s=<token>` where `<token>` is a short opaque identifier (8–12 chars, URL-safe base62). The token maps server-side to a `sharedRules` record containing the rule YAML, test code, and language. This link requires the recipient to be logged in to a Sicario account to open. The link is valid indefinitely unless the author deletes it.

3. **Permalink toggle:** WHEN the Share modal is open, a **Permalink** toggle SHALL be available. When enabled, the generated token is bound to the *current exact state* of the rule YAML and test code at the moment of sharing. Subsequent edits to the rule do NOT update the permalink. When disabled (default), the link always reflects the latest saved state of the rule.

4. **Make public:** THE dashboard SHALL allow the rule author to toggle the rule's visibility to **Public**, making it accessible to anyone with the link — including users who are not logged in to Sicario. Public rules are read-only for non-authenticated visitors: they can view the YAML, run the test code against the validation endpoint, and fork the rule into their own org, but cannot save changes.

5. WHEN a public rule link is opened by an unauthenticated user, THE dashboard SHALL render the Rule Editor in a **read-only playground mode**: the YAML editor is non-editable, the test panel is fully functional (live validation runs), and a **"Fork to my org"** button is shown in the top menu. Clicking Fork prompts login and then copies the rule into the user's org.

6. **Publish to Registry:** THE Share modal SHALL include a **Publish to Registry** option that opens a form collecting: rule description, tags (e.g. `security`, `best-practices`), and the author's GitHub handle. Submitting creates a pull request against the `sicario-rules` GitHub repository with the rule YAML added under the appropriate language directory. The PR body is pre-populated with the rule metadata and a link to the live editor share URL.

7. **URL-encoded share (no login required for viewing):** THE dashboard SHALL support a second URL format `https://app.usesicario.xyz/editor?r=<base64url>` where `<base64url>` is a URL-safe Base64 encoding of a JSON object `{yaml: string, code: string, lang: string}`. This format encodes the entire editor state in the URL itself — no server storage, no authentication required to view. The URL is generated client-side and works immediately without a round-trip. This is the "quick share" path for sharing rule ideas in Slack, GitHub issues, or blog posts.

8. WHEN a `?r=<base64url>` URL is opened, THE dashboard SHALL decode the payload client-side, populate the YAML editor and test code panel with the decoded content, and run validation automatically. A banner SHALL be shown: "You're viewing a shared rule. Log in to save it to your org." with a **Fork to my org** button.

9. **Expiring links:** THE Share modal SHALL offer an optional **Expiry** selector for private links: Never (default), 7 days, 30 days, 90 days. Expired links SHALL redirect to a "This link has expired" page with a prompt to log in and create a new share.

10. **Embed mode:** THE Share modal SHALL include a **Embed** tab that generates an `<iframe>` snippet for embedding a live read-only editor into external pages (docs, blog posts). The embed URL is `https://app.usesicario.xyz/editor/embed?r=<base64url>`. The embedded editor renders the YAML and test panel in a compact layout with no sidebar, no top nav, and a "Open in Sicario Editor" link in the footer.

11. THE zero-exfiltration invariant SHALL be maintained: the `?r=<base64url>` format encodes only rule YAML and test code entered by the user in the editor. The test code in the editor is sample/demonstration code provided by the rule author — it is not production source code. The `sharedRules` server-side records store only rule YAML and test code; no org data, no finding data, and no source code from scans is ever included.

12. WHEN a rule is saved to the org and then shared, THE share link SHALL reflect the saved rule's `ruleId` in the URL as `https://app.usesicario.xyz/editor/rules/<ruleId>` for authenticated org members. This is the canonical permalink for a saved rule and is always accessible to org members regardless of the share visibility setting.

---

### Requirement 42: Inline Suppression Comments (`sicario-ignore`)

**User Story:** As a developer, I want to suppress a specific finding inline in my code with a comment, so that I can document intentional exceptions without disabling the rule globally or cluttering the dashboard with known false positives.

#### Acceptance Criteria

1. THE SAST_Engine SHALL recognize the inline comment `// sicario-ignore` (JavaScript/TypeScript/Java/Go/Rust/C#), `# sicario-ignore` (Python/Ruby), and `{/* sicario-ignore */}` (JSX/TSX) on the same line as a match or on the line immediately preceding a match as a suppression directive.
2. WHEN a suppression directive is present, THE SAST_Engine SHALL still generate a finding record but SHALL automatically set its `triage_state` to `Ignored` with `ignoreReason: "inline_suppression"`. The finding SHALL appear in the dashboard as Ignored, not as Open.
3. THE SAST_Engine SHALL support rule-specific suppression: `// sicario-ignore: rule-id` suppresses only the named rule. `// sicario-ignore: rule-id-1, rule-id-2` suppresses multiple rules. `// sicario-ignore` with no rule ID suppresses all rules matching that line.
4. WHEN `--format json` is used, THE SAST_Engine SHALL include suppressed findings in the output with `"suppressed": true` and `"suppression_comment": "<the comment text>"` fields, so that suppression auditing is possible.
5. THE Sicario_CLI SHALL accept a `--no-ignore-comments` flag that disables inline suppression processing, causing all matches to be reported regardless of suppression comments. This is useful for security audits where suppressions should be reviewed.
6. THE `sicario audit suppression` subcommand SHALL scan a directory and report all inline suppression comments found, including: file path, line number, rule ID being suppressed, and the git committer who added the comment. This enables AppSec teams to audit suppression debt.
7. THE `.sicarioignore` file SHALL follow `.gitignore` syntax and SHALL cause the SAST_Engine to skip matching files and directories entirely (no findings generated, no suppressed findings). This is distinct from inline suppression which generates an Ignored finding.
8. THE SAST_Engine SHALL respect `.gitignore` patterns by default, skipping files that git would ignore. A `--no-git-ignore` flag SHALL override this behavior.
9. WHEN `sicario scan --publish` is active, suppressed findings SHALL be uploaded to Sicario Cloud with `triage_state: "ignored"` and `ignoreReason: "inline_suppression"`, so that the dashboard accurately reflects the suppression state.
10. THE zero-exfiltration invariant SHALL be maintained: suppression comment text is included in the publish payload only as a short string (the comment itself, capped at 200 chars). No surrounding source code is transmitted.

---

### Requirement 43: Pre-Commit Hook Integration

**User Story:** As a developer, I want Sicario to run automatically before every `git commit`, blocking commits that introduce new security findings, so that vulnerabilities never enter the repository's history.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL accept a `sicario install-hook` subcommand that installs a git pre-commit hook in the current repository's `.git/hooks/pre-commit` file. The hook runs `sicario scan --staged --fail-on high` before every commit.
2. WHEN the pre-commit hook runs, THE SAST_Engine SHALL scan only the staged files (files added to the git index via `git add`), not the entire working directory. This keeps the hook fast.
3. WHEN the pre-commit hook detects findings at or above the configured severity threshold, THE hook SHALL print the findings to stderr and exit with code 1, blocking the commit.
4. WHEN the pre-commit hook detects no findings above the threshold, THE hook SHALL exit with code 0, allowing the commit to proceed.
5. THE Sicario_CLI SHALL accept a `sicario uninstall-hook` subcommand that removes the pre-commit hook from `.git/hooks/pre-commit`.
6. THE pre-commit hook SHALL complete within 10 seconds for a typical staged changeset of up to 50 files, so that it does not disrupt developer flow.
7. THE pre-commit hook SHALL be compatible with the `pre-commit` framework (https://pre-commit.com): a `.pre-commit-hooks.yaml` file SHALL be added to the repository root defining a `sicario` hook entry that can be referenced from a project's `.pre-commit-config.yaml`.
8. WHEN `sicario install-hook` is run, THE CLI SHALL check if a pre-commit hook already exists and prompt the user before overwriting: "A pre-commit hook already exists. Overwrite? [y/N]"
9. THE pre-commit hook SHALL respect `.sicarioignore` and `.gitignore` patterns, skipping ignored files even if they are staged.
10. THE zero-exfiltration invariant SHALL be maintained: the pre-commit hook runs entirely locally. No findings are published to Sicario Cloud during a pre-commit scan unless `--publish` is explicitly added to the hook command.

---

### Requirement 44: ~~IDE Extension — VS Code and JetBrains~~

> **Deferred.** IDE extensions are out of scope for v0.3.5. This requirement is retained as a placeholder for a future release.

---

### Requirement 45: Secrets Detection with Entropy Analysis

**User Story:** As a security engineer, I want Sicario to detect hardcoded secrets, API keys, and credentials in source code using both pattern matching and entropy analysis, so that leaked credentials are caught before they reach version control.

#### Acceptance Criteria

1. THE SAST_Engine SHALL include a dedicated secrets detection mode activated by `sicario scan --secrets` that runs a specialized rule set targeting credential patterns across all supported languages and file types.
2. THE secrets rule set SHALL detect the following credential types using regex patterns: AWS access keys and secret keys, GitHub personal access tokens and fine-grained tokens, Stripe API keys (live and test), Slack tokens (bot, user, webhook), Google API keys, Anthropic API keys, OpenAI API keys, Twilio auth tokens, SendGrid API keys, Cloudflare API tokens, database connection strings (PostgreSQL, MySQL, MongoDB), private SSH keys (RSA, ECDSA, Ed25519), and generic high-entropy strings in variable assignments named `password`, `secret`, `token`, `key`, `credential`, or `api_key`.
3. THE SAST_Engine SHALL apply Shannon entropy analysis to string literals: strings with entropy above 4.5 bits/char AND length between 20 and 100 characters AND assigned to a variable with a credential-like name SHALL be flagged as potential secrets, even if they don't match a known pattern.
4. WHEN `sicario scan --secrets` is run, THE SAST_Engine SHALL scan not only source files but also configuration files (`.env`, `.env.*`, `*.yaml`, `*.yml`, `*.json`, `*.toml`, `*.ini`, `*.cfg`), Dockerfiles, and CI/CD configuration files (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`).
5. THE secrets rule set SHALL include a `confidence` field on each rule: `high` for known provider-specific patterns with checksum validation (e.g., AWS key format), `medium` for generic patterns, `low` for entropy-only matches.
6. THE Sicario_CLI SHALL accept a `sicario scan --secrets --historical` flag that scans the full git history of the repository for secrets that may have been committed and later deleted. This scan checks all commits reachable from HEAD.
7. WHEN `--historical` is active, THE SAST_Engine SHALL report each secret finding with the commit SHA, commit timestamp, and author email (from git log) where the secret was introduced. No commit message content is transmitted to Sicario Cloud.
8. THE secrets findings SHALL be included in the standard JSON and SARIF output formats alongside SAST findings, with a `scan_type: "secrets"` field to distinguish them.
9. THE pre-commit hook (Requirement 43) SHALL include secrets detection by default: `sicario scan --staged --secrets --fail-on medium` blocks commits containing medium or high confidence secrets.
10. THE zero-exfiltration invariant SHALL be maintained: secrets detection runs entirely locally. When `--publish` is active, the finding metadata uploaded to Sicario Cloud includes the rule ID, file path, line, severity, and a `code_hash` of the matched string — never the actual secret value. The `--historical` flag scans git history locally; no commit data is transmitted to Sicario Cloud.

---

### Requirement 46: Dependency Vulnerability Scanning with Reachability (SCA)

**User Story:** As a developer, I want Sicario to scan my project's dependencies for known CVEs and tell me which vulnerabilities are actually reachable from my code, so that I can prioritize fixes based on real exploitability rather than theoretical risk.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL accept a `sicario scan --sca` flag that activates Software Composition Analysis mode, parsing lockfiles and manifest files to identify third-party dependencies and their versions.
2. THE SCA scanner SHALL support the following lockfile formats: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` (Node.js), `Pipfile.lock`, `poetry.lock`, `requirements.txt` (Python), `Cargo.lock` (Rust), `go.sum` (Go), `Gemfile.lock` (Ruby), `composer.lock` (PHP), `pom.xml` / `build.gradle` (Java).
3. THE SCA scanner SHALL check identified dependencies against a locally-cached vulnerability database (updated via `sicario update --vuln-db`) sourced from OSV (Open Source Vulnerabilities), NVD (National Vulnerability Database), and GitHub Advisory Database. The vulnerability check runs entirely locally — no dependency names or versions are transmitted to Sicario Cloud.
4. WHEN a vulnerable dependency is identified, THE SCA scanner SHALL perform reachability analysis: it SHALL check whether the vulnerable function or code pattern from the dependency is actually called in the project's source code. Only reachable vulnerabilities SHALL be reported as `reachable: true`.
5. THE SCA scanner SHALL report each finding with: package name, installed version, fixed version, CVE ID, CVSS score, severity, whether the vulnerability is reachable, and the call site in the project's source code that reaches the vulnerable function (if reachable).
6. THE SCA scanner SHALL accept a `--fail-on-reachable` flag that exits with code 1 only when reachable vulnerabilities are found, ignoring unreachable ones. This reduces CI noise from theoretical vulnerabilities in unused code paths.
7. THE Sicario_CLI SHALL accept a `sicario update --vuln-db` subcommand that downloads the latest vulnerability database snapshot to `.sicario/cache/vuln_cache.db`. The download is a structured database file — no source code or project metadata is transmitted.
8. THE SCA scanner SHALL detect transitive dependencies (dependencies of dependencies) in addition to direct dependencies, and SHALL flag transitive vulnerabilities with a `transitive: true` field.
9. THE SCA findings SHALL be included in the standard JSON and SARIF output formats with a `scan_type: "sca"` field, and SHALL be published to Sicario Cloud via `--publish` as structured metadata (package name, version, CVE ID, reachability) — no source code is transmitted.
10. THE zero-exfiltration invariant SHALL be maintained: the vulnerability database is cached locally. Dependency names and versions are checked against the local cache only. When `--publish` is active, the SCA finding metadata uploaded includes package name, version, CVE ID, severity, and reachability — no source code, no lockfile contents beyond package identifiers.

---

### Requirement 47: License Compliance Scanning

**User Story:** As an engineering lead, I want Sicario to detect open-source dependencies with license terms that conflict with my organization's policies, so that I can prevent GPL-licensed code from entering a proprietary codebase before it ships.

#### Acceptance Criteria

1. THE SCA scanner (Requirement 46) SHALL include license detection: for each identified dependency, THE scanner SHALL determine the license from the package metadata in the local vulnerability database.
2. THE Sicario_CLI SHALL accept a `sicario scan --sca --license-policy <path>` flag that loads a YAML license policy file defining allowed and blocked license identifiers (SPDX format).
3. THE license policy file format SHALL be:
   ```yaml
   allow:
     - MIT
     - Apache-2.0
     - BSD-2-Clause
     - BSD-3-Clause
     - ISC
   block:
     - GPL-2.0
     - GPL-3.0
     - AGPL-3.0
     - LGPL-2.1
   warn:
     - MPL-2.0
     - EUPL-1.2
   ```
4. WHEN a dependency's license matches a `block` entry, THE SCA scanner SHALL report it as a Critical finding with `scan_type: "license"` and exit with code 1 when `--fail-on critical` is active.
5. WHEN a dependency's license matches a `warn` entry, THE SCA scanner SHALL report it as a Medium finding.
6. WHEN a dependency's license is unknown or cannot be determined, THE SCA scanner SHALL report it as a Low finding with `rule_id: "unknown-license"`.
7. THE Sicario Cloud dashboard SHALL display license findings in the findings table with a `License` scan type badge, filterable separately from SAST and secrets findings.
8. THE zero-exfiltration invariant SHALL be maintained: license detection runs entirely locally against the cached vulnerability database. No dependency names, versions, or license information is transmitted to Sicario Cloud beyond the structured finding metadata (package name, license identifier, severity).

---

### Requirement 48: Cross-Repository Code Search

**User Story:** As a security engineer, I want to run a Sicario rule across all repositories in my organization simultaneously and see every match, so that I can hunt for a vulnerability pattern across the entire codebase in seconds rather than cloning and scanning each repo individually.

#### Acceptance Criteria

1. THE Sicario Cloud dashboard SHALL provide a **Code Search** page at `/dashboard/search` where authenticated users can enter a rule YAML or a tree-sitter pattern and run it against all projects in their org that have completed at least one scan.
2. WHEN a Code Search query is submitted, THE Sicario Cloud backend SHALL NOT clone or access any repository. Instead, it SHALL re-run the pattern against the finding metadata already stored in the `findings` table — specifically, it SHALL match the pattern against the `snippet` field (when `--publish-with-snippet` was active) or return findings whose `ruleId` matches the query.
3. FOR users who want to search against live code (not cached findings), THE dashboard SHALL display a CLI command: `sicario search --pattern "<pattern>" --lang <language> --all-projects` that the user runs locally. This command reads the list of project repository URLs from Sicario Cloud, clones each repo locally, runs the pattern, and reports matches. Source code never leaves the user's machine.
4. THE `sicario search` CLI subcommand SHALL accept `--pattern <tree-sitter-query>`, `--lang <language>`, `--project <name>` (single project), and `--all-projects` (all projects in the org). Results are printed to stdout in the standard finding format.
5. WHEN `sicario search --all-projects` is run, THE CLI SHALL fetch the list of project repository URLs from `GET /api/v1/orgs/{org_id}/projects` and clone each repo to a temporary directory, scan it, and delete the clone after scanning. No source code is transmitted to Sicario Cloud.
6. THE Code Search dashboard page SHALL display results as a table: project name, file path, line number, matched snippet (if available from stored findings), and a link to the SCM deep link for each match.
7. THE Code Search feature SHALL complete a search across 100 projects' stored findings within 5 seconds on the dashboard.
8. THE zero-exfiltration invariant SHALL be maintained: dashboard Code Search operates only on finding metadata already stored in Sicario Cloud (no new code access). CLI `sicario search` clones repos locally and never transmits source code to Sicario Cloud.

---

### Requirement 49: Monorepo Support and Path-Scoped Scanning

**User Story:** As a developer working in a monorepo, I want to scan only the service or package I'm working on rather than the entire repository, so that CI scans stay fast and findings are scoped to the relevant team.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL accept a `--include <glob>` flag that restricts scanning to files matching the specified glob pattern (e.g., `--include "services/payments/**"`).
2. THE Sicario_CLI SHALL accept an `--exclude <glob>` flag that excludes files matching the specified glob pattern from scanning (e.g., `--exclude "**/*.test.ts"`).
3. THE Sicario_CLI SHALL accept a `--max-file-size <bytes>` flag that skips files larger than the specified size. The default SHALL be 1 MB.
4. THE Sicario Cloud dashboard SHALL support **monorepo projects**: a single repository can be registered as multiple projects, each with a different `rootPath` (e.g., `services/payments`, `services/auth`). Findings are scoped to the project's `rootPath`.
5. WHEN `sicario ci --publish` runs in a monorepo, THE CLI SHALL detect the project's `rootPath` from the Sicario Cloud project configuration and automatically apply `--include "{rootPath}/**"` to scope the scan.
6. THE `projects` Convex schema SHALL include a `rootPath` field (string, default `"."`) that defines the subdirectory within the repository that this project covers.
7. WHEN computing the production backlog metric (Requirement 26), THE analytics backend SHALL scope findings to the project's `rootPath`, so that monorepo services have independent backlogs.
8. THE Sicario_CLI SHALL accept a `--jobs <N>` flag (already in Requirement 16) and additionally a `--timeout <seconds>` flag that sets the maximum time to spend scanning a single file before skipping it (default: 30 seconds).
9. THE zero-exfiltration invariant SHALL be maintained: path scoping is a local filter applied before scanning. No file path information beyond what is already in finding metadata is transmitted to Sicario Cloud.

---

### Requirement 50: Rule Quality Dashboard Page

**User Story:** As a security engineer maintaining Sicario's rule set, I want to see precision/recall/F1 trends over time in the dashboard, so that I can track whether rule quality is improving or regressing across releases.

#### Acceptance Criteria

1. THE Sicario_CLI SHALL accept a `sicario benchmark --publish` flag that, after computing benchmark results, uploads the structured result to Sicario Cloud via `POST /api/v1/orgs/{org_id}/benchmark-results`.
2. THE benchmark result payload SHALL contain: `timestamp`, `precision`, `recall`, `f1_score`, `total_tp`, `total_fp`, `total_fn`, `per_language` breakdown, `vuln_sandbox_size`, and `cli_version`. No source code or file contents are included.
3. THE Sicario Cloud backend SHALL store benchmark results in a `benchmarkResults` Convex table indexed by `orgId` and `timestamp`.
4. THE Sicario Cloud dashboard SHALL display a **Rule Quality** page at `/dashboard/rule-quality` showing: a line chart of Precision/Recall/F1 over time, the most recent benchmark result as a summary card, and a per-language breakdown table.
5. THE Rule Quality page SHALL display a "Regression detected" alert when the most recent F1 score is more than 5 percentage points below the previous result.
6. THE zero-exfiltration invariant SHALL be maintained: benchmark results contain only aggregate metrics (counts and ratios). No source code, no file paths from the vuln-sandbox, and no rule patterns are transmitted.

---

### Requirement 51: Suppression Debt Dashboard View

**User Story:** As an AppSec team lead, I want to see an org-wide view of all inline suppression comments across all projects, so that I can identify suppression debt and ensure suppressions are justified.

#### Acceptance Criteria

1. WHEN `sicario scan --publish` runs and inline suppression comments are present, THE CLI SHALL include a `suppression_metadata` array in the scan payload containing: `file_path`, `line`, `rule_id`, `committer_email` (from git blame), and `suppression_comment` (the comment text, capped at 200 chars) for each suppression.
2. THE Sicario Cloud backend SHALL store suppression metadata in a `suppressions` Convex table indexed by `orgId`, `projectId`, and `ruleId`.
3. THE Sicario Cloud dashboard SHALL display a **Suppression Debt** section on the Policies page showing: total suppression count by rule, total by committer, trend over time (suppressions added vs. removed per week), and a table of all active suppressions with file path, rule ID, committer, and comment.
4. THE dashboard SHALL allow AppSec admins to flag a suppression as "Requires review" — this creates a `findingEvents` record and notifies the committer via the configured notification channel.
5. THE zero-exfiltration invariant SHALL be maintained: suppression metadata contains only file path, line number, rule ID, committer email, and the comment text (capped at 200 chars). No surrounding source code is transmitted.

---

### Requirement 52: License Policy Dashboard Configuration

**User Story:** As an AppSec team lead, I want to configure my organization's open-source license policy in the dashboard and have it automatically applied to all CLI scans, so that developers don't need to manage a local policy file.

#### Acceptance Criteria

1. THE Sicario Cloud dashboard SHALL provide a **License Policy** configuration page under Settings where admins can define `allow`, `block`, and `warn` lists of SPDX license identifiers using a visual interface (tag input, not raw YAML).
2. THE license policy SHALL be stored in the `organizations` Convex table as a `licensePolicy` JSON field.
3. WHEN `sicario ci` fetches the org policy, THE policy sync payload SHALL include the `licensePolicy` object, which the CLI applies during `--sca` scans.
4. A local `--license-policy <path>` YAML file (Requirement 47) SHALL override the cloud policy when present, enabling air-gap and per-project overrides.
5. THE dashboard SHALL display the current license policy alongside a list of all dependencies detected across all projects, with their licenses, so admins can see which packages would be blocked or warned under the current policy.
6. THE zero-exfiltration invariant SHALL be maintained: the license policy is a list of SPDX identifiers (strings). No source code, no dependency source code, and no lockfile contents are transmitted.

---

### Requirement 53: Pre-Commit Coverage and Vuln DB Status

**User Story:** As an AppSec team lead, I want to see which projects have the pre-commit hook installed and whether their vulnerability database is up to date, so that I can ensure consistent security coverage across the org.

#### Acceptance Criteria

1. WHEN `sicario scan --publish` runs, THE CLI SHALL include `hook_installed: boolean` (true when the pre-commit hook is active in the current repo) and `vuln_db_version: string` (the ISO-8601 date of the local vuln DB snapshot) in the scan metadata payload.
2. THE Sicario Cloud backend SHALL store `hookInstalled` and `vulnDbVersion` on the `scans` table record.
3. THE Sicario Cloud dashboard SHALL display a **Security Coverage** section on the Projects page showing, for each project: whether the pre-commit hook is installed (green checkmark / red X), the vuln DB version in use, and whether a newer vuln DB snapshot is available.
4. WHEN the CLI fetches the org policy via `sicario ci`, THE sync payload SHALL include `vuln_db_latest_version` (the most recent available snapshot date). THE CLI SHALL print a notice when the local DB is more than 7 days behind: `[sicario] Vulnerability database is 8 days old. Run 'sicario update --vuln-db' to update.`
5. THE zero-exfiltration invariant SHALL be maintained: `hook_installed` is a boolean and `vuln_db_version` is a date string. No source code or file system information is transmitted.
