# Requirements Document

## Introduction

Sicario is a Rust-based Static Application Security Testing (SAST) tool accepted into the Canopy program by Founders Inc. This document specifies the requirements for transforming Sicario from a working prototype into a fundable, production-grade SAST product. The overhaul focuses on seven core areas — CLI UX modernization with `clap`, security rule coverage expansion to 100+ rules per language across JavaScript/TypeScript, Python, Rust, Go, and Java, SARIF output for CI/CD integration, proper CI/CD exit codes and flags, diff-aware scanning for developer adoption, improved AI remediation architecture, and inline suppression comments — plus nine additional features that differentiate Sicario from every other SAST tool on the market: per-finding AI confidence scoring, security debt baseline tracking, learning suppressions, post-fix verification scanning, pre-commit hook integration, VS Code extension via Language Server Protocol, performance benchmarking, rule quality enforcement, and incremental cached scanning.

## Glossary

- **CLI**: The Sicario command-line interface binary (`sicario`), the primary user-facing entry point
- **SAST_Engine**: The core static analysis engine that loads YAML security rules, compiles tree-sitter queries, and scans source files for vulnerabilities
- **Rule_Loader**: The component within the SAST_Engine responsible for parsing YAML rule files and compiling tree-sitter queries
- **SARIF_Emitter**: The component responsible for serializing scan results into SARIF (Static Analysis Results Interchange Format) v2.1.0 JSON
- **Diff_Scanner**: The component that integrates with Git to compute changed lines and filter scan results to only new findings
- **Remediation_Engine**: The component that orchestrates AI-powered patch generation, syntax validation, backup creation, and patch application
- **LLM_Client**: The HTTP client component that communicates with OpenAI-compatible LLM API endpoints for code fix generation
- **Suppression_Parser**: The component that detects inline suppression comments in source code and filters matching findings
- **Confidence_Scorer**: The component that assigns a 0.0–1.0 confidence score to each Finding based on reachability, data-flow context, and pattern specificity
- **Baseline_Manager**: The component that persists scan results as a baseline snapshot and computes deltas between scans over time
- **Suppression_Learner**: The component that analyzes suppressed findings to identify recurring false-positive patterns and suggests automatic suppressions for similar findings
- **Verification_Scanner**: The component that re-scans a file after a fix is applied to confirm the targeted vulnerability is no longer detected
- **Finding**: A single vulnerability or security issue detected by the SAST_Engine, identified by rule ID, file path, line, column, severity, and CWE
- **Severity**: One of five levels — Info, Low, Medium, High, Critical — assigned to each Finding
- **Confidence_Score**: A floating-point value between 0.0 and 1.0 indicating the likelihood that a Finding represents a true positive
- **Baseline**: A persisted JSON snapshot of all Findings from a scan, used as a reference point for tracking security debt over time
- **SARIF**: Static Analysis Results Interchange Format, an OASIS standard (v2.1.0) for expressing static analysis results as JSON
- **Tree-sitter_Query**: A pattern-matching expression used by tree-sitter to identify AST nodes matching a security rule
- **Security_Debt**: The accumulated set of known, unresolved Findings in a codebase, tracked over time via Baseline snapshots
- **Output_Formatter**: The component responsible for rendering scan results to the terminal with colors, tables, progress bars, and severity-coded formatting
- **Key_Manager**: The component that securely stores and retrieves LLM API keys using the operating system's native credential store
- **Cloud_Platform**: The Sicario Cloud web application and API that provides centralized findings management, triage workflows, trend dashboards, and team collaboration across repositories
- **Publish_Client**: The component that authenticates with the Sicario Cloud Platform and uploads scan results, metadata, and triage state
- **Hook_Manager**: The component that installs, configures, and manages Git pre-commit hooks for automated scanning of staged changes
- **LSP_Server**: The Language Server Protocol server component that exposes Sicario scan results to IDE extensions via the standard LSP interface
- **Benchmark_Runner**: The component that executes standardized performance benchmarks and reports timing data for scan operations
- **Rule_Test_Harness**: The component that validates rule quality by executing each rule against curated true-positive and true-negative test cases
- **Scan_Cache**: The component that persists parsed AST representations and file content hashes to enable incremental scanning of only changed files

## Requirements

### Requirement 1: Clap-Based CLI with Subcommands

**User Story:** As a developer, I want a well-structured CLI with discoverable subcommands and shell completions, so that I can efficiently use Sicario in both interactive and scripted workflows.

#### Acceptance Criteria

1. THE CLI SHALL use the `clap` crate (v4+) with the derive API to define all commands and arguments
2. THE CLI SHALL expose the following top-level subcommands: `scan`, `init`, `report`, `fix`, `baseline`, `config`, `suppressions`, `completions`, `login`, `logout`, `publish`, `whoami`, `tui`, `hook`, and `benchmark`
3. WHEN the `scan` subcommand is invoked, THE CLI SHALL accept `--dir <path>`, `--rules <file>...`, `--format <json|sarif|text>`, `--severity-threshold <level>`, `--diff <commit-or-branch>`, `--confidence-threshold <0.0-1.0>`, `--quiet`, `--verbose`, `--exclude <pattern>...`, `--include <pattern>...`, `--jobs <n>`, `--timeout <seconds>`, `--max-lines-per-finding <n>`, `--staged`, and `--dataflow-traces` flags
4. WHEN the `init` subcommand is invoked, THE CLI SHALL run the project onboarding flow that detects languages and generates a `.sicario/config.yaml` configuration file
5. WHEN the `report` subcommand is invoked, THE CLI SHALL accept `--dir <path>`, `--output <dir>`, and `--format <owasp|sarif>` flags and generate the requested report
6. WHEN the `fix` subcommand is invoked with a file path and optional rule ID, THE CLI SHALL invoke the Remediation_Engine to generate and optionally apply patches
7. WHEN the `baseline` subcommand is invoked with `save`, THE CLI SHALL persist the current scan results as a Baseline snapshot
8. WHEN the `tui` subcommand is invoked, THE CLI SHALL launch the interactive Ratatui terminal UI scanning the specified or current directory
9. WHEN no subcommand is provided, THE CLI SHALL default to launching the `tui` subcommand for backward compatibility
10. THE CLI SHALL support `--version` and `--help` flags at both the top level and for each subcommand
11. THE CLI SHALL generate shell completion scripts for Bash, Zsh, Fish, and PowerShell via a `completions` subcommand

### Requirement 2: Structured Exit Codes for CI/CD

**User Story:** As a CI/CD pipeline author, I want Sicario to return meaningful exit codes, so that I can gate deployments based on scan results.

#### Acceptance Criteria

1. WHEN a scan completes with zero Findings at or above the severity threshold, THE CLI SHALL exit with code 0
2. WHEN a scan completes with one or more Findings at or above the severity threshold, THE CLI SHALL exit with code 1
3. IF an internal error occurs during scanning, THEN THE CLI SHALL exit with code 2 and print a diagnostic message to stderr
4. WHEN the `--severity-threshold` flag is set to a Severity level, THE CLI SHALL only count Findings at or above that level when determining the exit code
5. WHEN the `--severity-threshold` flag is omitted, THE CLI SHALL default the threshold to Low
6. WHEN the `--confidence-threshold` flag is set, THE CLI SHALL only count Findings with a Confidence_Score at or above that threshold when determining the exit code

### Requirement 3: Quiet and Verbose Output Modes

**User Story:** As a CI/CD pipeline author, I want to control Sicario's output verbosity, so that I can minimize noise in automated pipelines or get detailed diagnostics when debugging.

#### Acceptance Criteria

1. WHEN the `--quiet` flag is set, THE CLI SHALL suppress all output to stdout except the final results (JSON, SARIF, or summary line)
2. WHEN the `--verbose` flag is set, THE CLI SHALL print detailed progress information including files scanned, rules loaded, timing data, and suppressed Finding counts to stderr
3. WHEN neither `--quiet` nor `--verbose` is set, THE CLI SHALL print a concise summary of findings grouped by severity to stdout
4. IF both `--quiet` and `--verbose` are provided, THEN THE CLI SHALL return an error indicating the flags are mutually exclusive

### Requirement 4: JavaScript/TypeScript Rule Expansion

**User Story:** As a security engineer, I want comprehensive JavaScript and TypeScript rule coverage with at least 100 rules, so that Sicario can detect the most common web application vulnerabilities across frameworks.

#### Acceptance Criteria

1. THE Rule_Loader SHALL load and compile a minimum of 100 JavaScript/TypeScript security rules from YAML files
2. THE SAST_Engine SHALL detect SQL injection patterns including string concatenation in query builders, template literal interpolation in SQL strings, and raw query calls in ORMs (Sequelize, Knex, Prisma, TypeORM, Drizzle)
3. THE SAST_Engine SHALL detect Cross-Site Scripting (XSS) patterns including `dangerouslySetInnerHTML` in React/JSX, unescaped template rendering in EJS/Handlebars/Pug, `document.write` with dynamic content, and `v-html` in Vue
4. THE SAST_Engine SHALL detect Server-Side Request Forgery (SSRF) patterns including unvalidated URL construction from user input in `fetch`, `axios`, `http.request`, `got`, and `node-fetch` calls
5. THE SAST_Engine SHALL detect path traversal patterns including unsanitized user input in `fs.readFile`, `fs.readFileSync`, `fs.createReadStream`, `path.join`, and `path.resolve` calls
6. THE SAST_Engine SHALL detect insecure deserialization patterns including `JSON.parse` of untrusted input without schema validation, `eval`-based deserialization, and `node-serialize` usage
7. THE SAST_Engine SHALL detect Express.js security patterns including missing helmet middleware, missing rate limiting, missing CORS configuration, disabled CSRF protection, and verbose error responses in production
8. THE SAST_Engine SHALL detect insecure cryptography patterns including use of MD5, SHA1 for password hashing, hardcoded encryption keys, weak random number generation with `Math.random`, and deprecated `createCipher` usage
9. THE SAST_Engine SHALL detect prototype pollution patterns including unsafe recursive merge operations, unvalidated property access via bracket notation with user input, and `Object.assign` with untrusted sources
10. THE SAST_Engine SHALL detect Next.js-specific patterns including SSRF in `getServerSideProps`, exposed API keys in client bundles, missing authentication in API routes, and unsafe redirect handling
11. THE SAST_Engine SHALL detect authentication and authorization patterns including JWT verification bypass, missing token expiration checks, hardcoded JWT secrets, and insecure session configuration
12. THE SAST_Engine SHALL detect NoSQL injection patterns including unvalidated user input in MongoDB query operators (`$where`, `$regex`, `$gt`), Mongoose raw queries, and Redis command injection
13. THE SAST_Engine SHALL detect regular expression denial of service (ReDoS) patterns including catastrophic backtracking in user-facing regex patterns
14. THE SAST_Engine SHALL detect open redirect patterns including unvalidated redirect URLs from user input in `res.redirect`, `window.location`, and `router.push`
15. THE SAST_Engine SHALL detect TypeScript-specific type safety bypass patterns including `as any` type assertions in security-sensitive contexts (authentication checks, input validation, authorization guards), explicit `any` type annotations on function parameters that handle user input, and unsafe type narrowing that bypasses runtime validation (e.g., casting `unknown` to a trusted type without a type guard)
16. WHEN a new rule is added to a YAML file, THE Rule_Loader SHALL load it without requiring code changes to the SAST_Engine

### Requirement 5: Python Rule Expansion

**User Story:** As a security engineer, I want comprehensive Python rule coverage with at least 100 rules, so that Sicario can detect vulnerabilities in Django, Flask, FastAPI, and general Python applications.

#### Acceptance Criteria

1. THE Rule_Loader SHALL load and compile a minimum of 100 Python security rules from YAML files
2. THE SAST_Engine SHALL detect Django ORM injection patterns including `extra()`, `raw()`, `RawSQL`, and `cursor.execute` with string formatting of user input
3. THE SAST_Engine SHALL detect Flask/Jinja2 Server-Side Template Injection (SSTI) patterns including `render_template_string` with user-controlled input and `Environment` with unsafe settings
4. THE SAST_Engine SHALL detect SQL injection patterns including f-string and %-format interpolation in `cursor.execute`, `sqlalchemy.text`, `engine.execute`, and raw SQL calls
5. THE SAST_Engine SHALL detect path traversal patterns including `open()`, `os.path.join`, `pathlib.Path`, `shutil.copy`, and `send_file` with unsanitized user input
6. THE SAST_Engine SHALL detect insecure deserialization patterns including `yaml.load` without `SafeLoader`, `pickle.loads` of untrusted data, `marshal.loads`, `shelve.open`, and `jsonpickle.decode`
7. THE SAST_Engine SHALL detect command injection patterns including `os.system`, `os.popen`, `subprocess.call` with `shell=True`, and string-formatted arguments in subprocess calls
8. THE SAST_Engine SHALL detect insecure cryptography patterns including use of `hashlib.md5`, `hashlib.sha1` for password storage, `random` module for security-sensitive operations, and weak `Fernet` key derivation
9. THE SAST_Engine SHALL detect Django-specific misconfiguration patterns including `DEBUG = True`, `ALLOWED_HOSTS = ['*']`, missing CSRF middleware, `SECRET_KEY` hardcoded in settings, and `@csrf_exempt` on sensitive views
10. THE SAST_Engine SHALL detect FastAPI-specific patterns including missing dependency injection for authentication, unvalidated path parameters, missing CORS middleware, and exposed debug endpoints
11. THE SAST_Engine SHALL detect LDAP injection patterns including unsanitized user input in `ldap.search_s` and `ldap3` filter construction
12. THE SAST_Engine SHALL detect XML External Entity (XXE) patterns including `xml.etree.ElementTree.parse`, `lxml.etree.parse`, and `xml.sax` without disabling external entities
13. THE SAST_Engine SHALL detect mass assignment patterns including unvalidated `**kwargs` in Django model creation and Flask-SQLAlchemy bulk updates from request data
14. THE SAST_Engine SHALL detect logging sensitive data patterns including passwords, tokens, and API keys passed to `logging.info`, `logging.debug`, `print`, and `logger` calls
15. WHEN a new rule is added to a YAML file, THE Rule_Loader SHALL load it without requiring code changes to the SAST_Engine

### Requirement 6: Rust Rule Expansion

**User Story:** As a security engineer, I want comprehensive Rust rule coverage with at least 100 rules focused on actual security vulnerabilities, so that Sicario can detect injection flaws, memory corruption, and exploitable patterns without generating noise from code-quality linting.

#### Acceptance Criteria

1. THE Rule_Loader SHALL load and compile a minimum of 100 Rust security rules from YAML files
2. THE SAST_Engine SHALL detect SQL injection patterns including string formatting in `sqlx::query`, `diesel::sql_query`, `rusqlite::execute`, and `tokio-postgres` raw query calls
3. THE SAST_Engine SHALL detect command injection patterns including `std::process::Command` with unsanitized user input in arguments and `shell` invocations
4. THE SAST_Engine SHALL detect path traversal patterns including unsanitized user input in `std::fs::read`, `std::fs::write`, `std::fs::File::open`, and `tokio::fs` operations
5. THE SAST_Engine SHALL detect insecure cryptography patterns including use of `md5` and `sha1` crates for password hashing, hardcoded keys in `aes` and `chacha20` usage, and `rand::thread_rng` for security-sensitive operations instead of `rand::rngs::OsRng`
6. THE SAST_Engine SHALL detect insecure deserialization patterns including `serde_json::from_str` and `serde_yaml::from_str` of untrusted input without size limits or type validation
7. THE SAST_Engine SHALL detect memory safety vulnerabilities including raw pointer dereferences without bounds checks, `transmute` between incompatible types, `from_raw_parts` usage without proper length validation, and use-after-free patterns in `unsafe` blocks
8. THE SAST_Engine SHALL detect concurrency vulnerabilities including data races via `unsafe` shared mutable state, `Send`/`Sync` trait misimplementation on types with interior mutability, and unprotected shared state across `tokio::spawn` boundaries
9. THE SAST_Engine SHALL detect Actix-web and Axum framework patterns including missing authentication extractors, unvalidated path parameters, missing CORS configuration, and exposed debug endpoints
10. THE SAST_Engine SHALL detect information leakage patterns including `Debug` trait implementations on types containing secrets, `Display` implementations that expose sensitive fields, and verbose error messages returned to clients
11. THE SAST_Engine SHALL NOT flag generic `unwrap()` or `expect()` calls as security findings — these are code quality concerns handled by Clippy, not exploitable vulnerabilities
12. THE SAST_Engine SHALL NOT flag `unsafe` blocks as security findings by default — the presence of `unsafe` alone is not a vulnerability without an exploitable pattern within the block
13. WHEN a new rule is added to a YAML file, THE Rule_Loader SHALL load it without requiring code changes to the SAST_Engine

### Requirement 7: Go Rule Expansion

**User Story:** As a security engineer, I want comprehensive Go rule coverage with at least 100 rules, so that Sicario can detect vulnerabilities in Go web services, CLI tools, and cloud-native applications.

#### Acceptance Criteria

1. THE Rule_Loader SHALL load and compile a minimum of 100 Go security rules from YAML files
2. THE SAST_Engine SHALL detect SQL injection patterns including string concatenation in `database/sql` queries, `fmt.Sprintf` in SQL strings, and raw queries in GORM, sqlx, and ent
3. THE SAST_Engine SHALL detect command injection patterns including `os/exec.Command` with unsanitized user input, `os.StartProcess`, and shell invocations via `bash -c`
4. THE SAST_Engine SHALL detect path traversal patterns including unsanitized user input in `os.Open`, `os.ReadFile`, `ioutil.ReadFile`, `filepath.Join`, and `http.ServeFile`
5. THE SAST_Engine SHALL detect Server-Side Request Forgery (SSRF) patterns including unvalidated URL construction in `http.Get`, `http.Post`, `http.NewRequest`, and `resty` client calls
6. THE SAST_Engine SHALL detect insecure cryptography patterns including use of `crypto/md5`, `crypto/sha1` for password hashing, `math/rand` instead of `crypto/rand` for security operations, and hardcoded keys
7. THE SAST_Engine SHALL detect error handling anti-patterns including unchecked error returns (`_ = err`), deferred function calls with ignored errors, and missing error checks after `io.Reader` and `io.Writer` operations
8. THE SAST_Engine SHALL detect Gin, Echo, and Fiber framework patterns including missing authentication middleware, unvalidated request binding, missing CORS configuration, and verbose error responses
9. THE SAST_Engine SHALL detect race condition patterns including goroutine access to shared variables without synchronization, missing mutex locks, and unsafe use of `sync.WaitGroup`
10. THE SAST_Engine SHALL detect insecure TLS patterns including `InsecureSkipVerify: true`, weak TLS versions (`tls.VersionTLS10`, `tls.VersionTLS11`), and disabled certificate validation
11. THE SAST_Engine SHALL detect information leakage patterns including sensitive data in `log.Printf`, `fmt.Printf`, and structured logging calls, and verbose error messages returned in HTTP responses
12. THE SAST_Engine SHALL detect XML External Entity (XXE) patterns including `xml.NewDecoder` without disabling external entities and `encoding/xml` with untrusted input
13. WHEN a new rule is added to a YAML file, THE Rule_Loader SHALL load it without requiring code changes to the SAST_Engine

### Requirement 8: Java Rule Expansion

**User Story:** As a security engineer, I want comprehensive Java rule coverage with at least 100 rules, so that Sicario can detect vulnerabilities in Spring Boot, Jakarta EE, and general Java applications.

#### Acceptance Criteria

1. THE Rule_Loader SHALL load and compile a minimum of 100 Java security rules from YAML files
2. THE SAST_Engine SHALL detect SQL injection patterns including string concatenation in `Statement.execute`, `PreparedStatement` misuse, JPQL/HQL injection in Hibernate, and Spring Data `@Query` with concatenated parameters
3. THE SAST_Engine SHALL detect Cross-Site Scripting (XSS) patterns including unescaped output in JSP, Thymeleaf `th:utext`, and Spring MVC response body construction with user input
4. THE SAST_Engine SHALL detect command injection patterns including `Runtime.exec` with unsanitized input, `ProcessBuilder` with user-controlled arguments, and JNDI injection via `InitialContext.lookup`
5. THE SAST_Engine SHALL detect insecure deserialization patterns including `ObjectInputStream.readObject` of untrusted data, `XMLDecoder`, `XStream` without allowlists, and `SnakeYAML` without safe constructors
6. THE SAST_Engine SHALL detect path traversal patterns including unsanitized user input in `new File()`, `Paths.get()`, `FileInputStream`, and Spring `Resource` loading
7. THE SAST_Engine SHALL detect insecure cryptography patterns including use of `MD5`, `SHA1` via `MessageDigest` for password hashing, `DES` and `3DES` encryption, `ECB` mode, hardcoded keys, and `java.util.Random` for security operations
8. THE SAST_Engine SHALL detect Spring Boot security patterns including disabled CSRF protection, permissive CORS configuration, missing `@PreAuthorize` on sensitive endpoints, exposed actuator endpoints, and `DEBUG` logging in production profiles
9. THE SAST_Engine SHALL detect SSRF patterns including unvalidated URL construction in `HttpURLConnection`, `HttpClient`, `RestTemplate`, and `WebClient` calls
10. THE SAST_Engine SHALL detect XML External Entity (XXE) patterns including `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, and `TransformerFactory` without disabling external entities
11. THE SAST_Engine SHALL detect LDAP injection patterns including unsanitized user input in `DirContext.search` and Spring LDAP template queries
12. THE SAST_Engine SHALL detect logging sensitive data patterns including passwords, tokens, and API keys passed to `Logger.info`, `Logger.debug`, `System.out.println`, and SLF4J calls
13. WHEN a new rule is added to a YAML file, THE Rule_Loader SHALL load it without requiring code changes to the SAST_Engine

### Requirement 9: SARIF Output Format

**User Story:** As a DevSecOps engineer, I want Sicario to output results in SARIF format, so that I can integrate scan results with GitHub Code Scanning, GitLab SAST, and Azure DevOps.

#### Acceptance Criteria

1. WHEN the `--format sarif` flag is provided to the `scan` subcommand, THE SARIF_Emitter SHALL produce a valid SARIF v2.1.0 JSON document on stdout
2. THE SARIF_Emitter SHALL include a `tool` object with the Sicario tool name, version, and semantic version
3. THE SARIF_Emitter SHALL include a `rules` array in the tool driver containing the rule ID, name, short description, full description, help URI, and default severity for each rule that produced a Finding
4. THE SARIF_Emitter SHALL include a `results` array with one entry per Finding, containing the rule ID, message, severity level, physical location (file URI, start line, start column), and Confidence_Score as a property bag entry
5. THE SARIF_Emitter SHALL map Sicario Severity levels to SARIF severity levels: Critical and High to "error", Medium to "warning", Low and Info to "note"
6. THE SARIF_Emitter SHALL include CWE identifiers in the `taxa` property of each result when available
7. THE SARIF_Emitter SHALL produce output that validates against the SARIF v2.1.0 JSON schema
8. THE SARIF_Emitter SHALL format Finding data back into valid SARIF JSON documents (pretty-printer)
9. FOR ALL valid Finding lists, serializing to SARIF then deserializing back SHALL produce an equivalent set of Findings (round-trip property)

### Requirement 10: Diff-Aware Scanning

**User Story:** As a developer, I want to see only new security findings introduced in my changes, so that I am not overwhelmed by pre-existing issues on every pull request.

#### Acceptance Criteria

1. WHEN the `--diff <ref>` flag is provided, THE Diff_Scanner SHALL use `git2` to compute the set of changed lines between the current working tree and the specified Git reference (commit SHA, branch name, or tag)
2. WHEN the `--diff` flag is provided, THE SAST_Engine SHALL filter scan results to include only Findings on lines that were added or modified relative to the specified reference
3. WHEN the `--diff` flag is provided with a branch name, THE Diff_Scanner SHALL resolve the branch to its HEAD commit before computing the diff
4. IF the specified Git reference does not exist, THEN THE CLI SHALL exit with code 2 and print a descriptive error message to stderr
5. IF the current directory is not a Git repository, THEN THE CLI SHALL exit with code 2 and print a descriptive error message to stderr
6. WHEN the `--diff` flag is combined with `--format sarif`, THE SARIF_Emitter SHALL include only the filtered Findings in the output
7. THE Diff_Scanner SHALL handle renamed files by tracking the new file path and including Findings on changed lines in the renamed file

### Requirement 11: Multi-Provider AI Remediation

**User Story:** As a developer, I want reliable AI-powered fix suggestions that work with multiple LLM providers, so that I can use my preferred AI service and get consistent remediation results.

#### Acceptance Criteria

1. THE LLM_Client SHALL support any OpenAI-compatible chat completions API endpoint configurable via the `SICARIO_LLM_ENDPOINT` environment variable
2. THE LLM_Client SHALL read the API key from the `SICARIO_LLM_API_KEY` environment variable, falling back to `CEREBRAS_API_KEY` for backward compatibility
3. THE LLM_Client SHALL read the model name from the `SICARIO_LLM_MODEL` environment variable, defaulting to `llama3.1-8b`
4. THE LLM_Client SHALL use non-blocking async HTTP calls via `reqwest` and integrate with the Tokio runtime without creating nested runtimes
5. WHEN the LLM API returns an error or times out after 30 seconds, THE Remediation_Engine SHALL fall back to rule-specific template fixes rather than returning the original code unchanged
6. THE Remediation_Engine SHALL validate the syntax of LLM-generated code using tree-sitter before applying any patch
7. WHEN the `fix` subcommand is invoked, THE Remediation_Engine SHALL generate a patch, display the unified diff to the user, and prompt for confirmation before applying
8. THE Remediation_Engine SHALL create a backup of the original file before applying any patch and support reverting via `sicario fix --revert <patch-id>`
9. THE Remediation_Engine SHALL ship template-based fixes for at minimum the following vulnerability classes: SQL injection (rewrite to parameterized queries), Cross-Site Scripting (apply context-appropriate output encoding), and command injection (replace shell invocation with allowlist-validated arguments)
10. WHEN the template fallback is invoked, THE Remediation_Engine SHALL produce a syntactically valid patch that differs from the original code — returning the original code unchanged is not an acceptable fallback

### Requirement 12: Inline Suppression Comments for SAST Findings

**User Story:** As a developer, I want to suppress specific SAST findings with inline comments, so that I can acknowledge known false positives without disabling rules globally.

#### Acceptance Criteria

1. WHEN a source line is preceded by a comment containing `sicario-ignore`, THE Suppression_Parser SHALL suppress all SAST Findings on that line
2. WHEN a source line is preceded by a comment containing `sicario-ignore-next-line`, THE Suppression_Parser SHALL suppress all SAST Findings on the next line of code
3. WHEN a comment contains `sicario-ignore:<rule-id>`, THE Suppression_Parser SHALL suppress only the Finding matching the specified rule ID on the applicable line
4. THE Suppression_Parser SHALL recognize suppression directives in all supported comment styles: `//`, `#`, `/* */`, and `<!-- -->`
5. WHEN a Finding is suppressed, THE SAST_Engine SHALL exclude the Finding from the results, exit code calculation, and all output formats (JSON, SARIF, text)
6. THE Suppression_Parser SHALL support the existing `sicario-ignore-secret` directive for backward compatibility with the secret scanner
7. WHEN the `--verbose` flag is set, THE CLI SHALL report the count of suppressed Findings to stderr

### Requirement 13: GitHub Action for CI Integration

**User Story:** As a DevOps engineer, I want a ready-to-use GitHub Action for Sicario, so that I can add security scanning to any repository with minimal configuration.

#### Acceptance Criteria

1. THE CLI SHALL be distributable as a GitHub Action usable via `uses: sicario/scan-action@v1` in workflow YAML files
2. WHEN the GitHub Action is invoked, THE CLI SHALL accept `severity-threshold`, `diff-base`, `format`, and `scan-path` as action inputs
3. WHEN the `format` input is set to `sarif`, THE GitHub Action SHALL upload the SARIF output to GitHub Code Scanning via the `github/codeql-action/upload-sarif` action
4. WHEN the `diff-base` input is provided, THE GitHub Action SHALL pass it as the `--diff` flag to enable diff-aware scanning on pull requests
5. THE GitHub Action SHALL set the `findings-count` and `exit-code` as action outputs for use in subsequent workflow steps
6. THE GitHub Action SHALL cache the Sicario binary between workflow runs to minimize download time

### Requirement 14: Per-Finding AI Confidence Scoring

**User Story:** As a developer, I want each finding to include a confidence score indicating how likely it is to be a true positive, so that I can prioritize high-confidence findings and reduce time wasted on false positives.

#### Acceptance Criteria

1. THE Confidence_Scorer SHALL assign a Confidence_Score between 0.0 and 1.0 to every Finding produced by the SAST_Engine
2. THE Confidence_Scorer SHALL compute the score based on at least three signals: reachability analysis result (whether tainted data flows from a source to the sink), pattern specificity (how precise the tree-sitter query match is), and contextual indicators (presence of sanitization functions, validation guards, or framework-provided protections in the surrounding code)
3. WHEN a Finding has a confirmed taint path from a user-controlled source to the vulnerable sink, THE Confidence_Scorer SHALL assign a score of 0.8 or higher
4. WHEN a Finding matches a generic pattern with no confirmed data-flow path, THE Confidence_Scorer SHALL assign a score of 0.5 or lower
5. WHEN the `--confidence-threshold` flag is provided, THE SAST_Engine SHALL exclude Findings with a Confidence_Score below the specified threshold from results and exit code calculation
6. THE SARIF_Emitter SHALL include the Confidence_Score in the SARIF output as a `rank` property on each result (scaled 0–100)
7. WHEN the `--format text` output is used, THE CLI SHALL display the Confidence_Score next to each Finding as a percentage (e.g., "92% confidence")
8. THE Confidence_Scorer SHALL be deterministic: the same source code and rules SHALL produce the same Confidence_Score on every scan

### Requirement 15: Security Debt Baseline Tracking

**User Story:** As a security team lead, I want to track security debt over time by saving scan baselines and comparing against them, so that I can measure whether the codebase is getting more or less secure with each release.

#### Acceptance Criteria

1. WHEN the `baseline save` subcommand is invoked, THE Baseline_Manager SHALL persist the current scan results as a timestamped JSON Baseline file in `.sicario/baselines/`
2. WHEN the `baseline save` subcommand is invoked with `--tag <name>`, THE Baseline_Manager SHALL associate the Baseline with the specified tag for easy retrieval
3. WHEN the `baseline compare` subcommand is invoked with a tag or timestamp, THE Baseline_Manager SHALL compute and display the delta: new Findings introduced, Findings resolved, and Findings unchanged since the specified Baseline
4. WHEN the `baseline compare` subcommand is invoked with `--format json`, THE Baseline_Manager SHALL output the delta as a structured JSON document
5. WHEN the `baseline trend` subcommand is invoked, THE Baseline_Manager SHALL display a summary of Finding counts across all saved Baselines, showing the security debt trajectory over time
6. THE Baseline_Manager SHALL identify Findings across Baselines using a stable fingerprint computed from the rule ID, file path, and code snippet hash, so that Findings are tracked even when line numbers shift
7. FOR ALL valid Baseline JSON files, serializing then deserializing SHALL produce an equivalent Baseline object (round-trip property)

### Requirement 16: Learning Suppressions

**User Story:** As a developer, I want Sicario to learn from my suppression patterns and suggest automatic suppressions for similar false positives, so that I spend less time re-suppressing the same types of findings across the codebase.

#### Acceptance Criteria

1. WHEN a Finding is suppressed via an inline comment, THE Suppression_Learner SHALL record the suppression pattern including the rule ID, the AST node type of the suppressed code, and the surrounding code context
2. WHEN the Suppression_Learner has recorded three or more suppressions for the same rule ID with similar AST context patterns, THE Suppression_Learner SHALL flag subsequent matching Findings as "suggested suppression" in the scan output
3. WHEN the `scan` subcommand is invoked with `--auto-suppress`, THE SAST_Engine SHALL automatically suppress Findings that match learned suppression patterns and report the count of auto-suppressed Findings to stderr
4. THE Suppression_Learner SHALL persist learned patterns in `.sicario/learned_suppressions.json` so that patterns survive across scan invocations
5. WHEN the `--verbose` flag is set, THE CLI SHALL report the count of Findings matching learned suppression patterns separately from manually suppressed Findings
6. THE Suppression_Learner SHALL provide a `sicario suppressions list` subcommand that displays all learned suppression patterns with their rule ID, match count, and example code snippet
7. THE Suppression_Learner SHALL provide a `sicario suppressions reset` subcommand that clears all learned patterns

### Requirement 17: Post-Fix Verification Scanning

**User Story:** As a developer, I want Sicario to automatically verify that an applied fix actually resolves the vulnerability, so that I have confidence the remediation worked and did not introduce new issues.

#### Acceptance Criteria

1. WHEN the Remediation_Engine applies a patch via the `fix` subcommand, THE Verification_Scanner SHALL automatically re-scan the patched file for the specific rule that triggered the original Finding
2. WHEN the re-scan detects that the original Finding is no longer present, THE Verification_Scanner SHALL report "Fix verified: vulnerability resolved" to stdout
3. WHEN the re-scan detects that the original Finding is still present after the fix, THE Verification_Scanner SHALL report "Fix incomplete: vulnerability still detected" to stderr and offer to revert the patch
4. WHEN the re-scan detects new Findings in the patched file that were not present before the fix, THE Verification_Scanner SHALL report "Fix introduced new findings" with details to stderr and offer to revert the patch
5. THE Verification_Scanner SHALL compare Findings using the stable fingerprint (rule ID, file path, code snippet hash) to distinguish pre-existing Findings from newly introduced ones
6. WHEN the `fix` subcommand is invoked with `--no-verify`, THE Verification_Scanner SHALL be skipped

### Requirement 18: Professional CLI Output and Visual Design

**User Story:** As a developer, I want Sicario's CLI output to look polished and professional with color-coded severity, progress indicators, and well-formatted tables, so that the tool feels credible and is pleasant to use daily.

#### Acceptance Criteria

1. THE CLI SHALL use colored output by default: Critical findings in red, High in orange/yellow, Medium in yellow, Low in blue, and Info in gray
2. THE CLI SHALL display a progress bar with file count and elapsed time during scanning when output is connected to a terminal (TTY)
3. WHEN output is piped to a non-TTY destination, THE CLI SHALL automatically disable colors and progress indicators to produce clean machine-readable output
4. THE CLI SHALL support a `--no-color` flag to explicitly disable colored output regardless of TTY detection
5. THE CLI SHALL support a `--force-color` flag to enable colored output even when piped to a non-TTY destination
6. THE CLI SHALL display scan results in a formatted table with aligned columns for severity, confidence, rule ID, file path, and line number
7. WHEN a scan completes, THE CLI SHALL display a summary banner showing total findings by severity, scan duration, files scanned, rules loaded, and an estimated comparison showing how long the equivalent scan would take with Semgrep (computed as `sicario_duration * 10`)
8. THE CLI SHALL use Unicode box-drawing characters for table borders and section separators when the terminal supports UTF-8, falling back to ASCII characters on terminals that do not
9. WHEN the `fix` subcommand displays a diff, THE CLI SHALL use syntax-highlighted diff output with green for additions and red for deletions
10. WHEN the `--version` flag is used, THE CLI SHALL display a branded ASCII art Sicario logo followed by the version string, build date, and target triple
11. THE CLI SHALL support `--max-lines-per-finding <n>` to control how many lines of code context are shown per finding, defaulting to 5
12. THE CLI SHALL support `--max-chars-per-line <n>` to truncate long lines in output, defaulting to 160 characters

### Requirement 19: Advanced Scan Control

**User Story:** As a developer, I want fine-grained control over what files are scanned, how many threads are used, and per-file timeouts, so that I can optimize scan performance and scope for my specific project.

#### Acceptance Criteria

1. WHEN the `--exclude <pattern>` flag is provided, THE SAST_Engine SHALL skip any file or directory whose path matches the glob pattern, supporting multiple `--exclude` flags
2. WHEN the `--include <pattern>` flag is provided, THE SAST_Engine SHALL scan only files whose path matches the glob pattern, supporting multiple `--include` flags
3. THE CLI SHALL support a `.sicarioignore` file in the project root that follows `.gitignore` syntax to permanently exclude files and directories from scanning
4. WHEN the `--jobs <n>` flag is provided, THE SAST_Engine SHALL use the specified number of parallel threads for scanning, defaulting to the number of CPU cores detected on the system
5. WHEN the `--timeout <seconds>` flag is provided, THE SAST_Engine SHALL skip any single file that takes longer than the specified duration to scan, logging a warning to stderr
6. WHEN the `--timeout` flag is omitted, THE SAST_Engine SHALL default to a 30-second per-file timeout
7. THE CLI SHALL support writing output to multiple formats simultaneously via `--json-output <file>`, `--sarif-output <file>`, and `--text-output <file>` flags
8. WHEN the `--dataflow-traces` flag is provided, THE CLI SHALL include an explanation of how tainted data flows from source to sink for each Finding in text and SARIF output
9. WHEN the `--time` flag is provided, THE CLI SHALL include a timing summary showing time spent per rule and per file in the output
10. THE CLI SHALL support `--exclude-rule <rule-id>` to skip specific rules during a scan, supporting multiple `--exclude-rule` flags

### Requirement 20: Bring Your Own Key (BYOK) Management

**User Story:** As a developer, I want a secure and convenient way to configure and manage my LLM API keys for AI remediation, so that I can use my preferred provider without exposing keys in shell history or environment files.

#### Acceptance Criteria

1. THE CLI SHALL provide a `sicario config set-key` subcommand that securely stores the LLM API key using the operating system's native credential store (macOS Keychain, Windows Credential Manager, Linux Secret Service via the `keyring` crate)
2. WHEN the `config set-key` subcommand is invoked, THE CLI SHALL prompt for the API key via a masked input field that does not echo characters to the terminal
3. THE CLI SHALL provide a `sicario config set-provider` subcommand that stores the LLM provider configuration (endpoint URL and model name) in `.sicario/config.yaml`
4. THE LLM_Client SHALL resolve the API key using the following precedence order: `SICARIO_LLM_API_KEY` environment variable, then OS credential store, then `CEREBRAS_API_KEY` environment variable
5. THE CLI SHALL provide a `sicario config show` subcommand that displays the current provider configuration (endpoint, model) and whether an API key is configured, without revealing the key value
6. THE CLI SHALL provide a `sicario config delete-key` subcommand that removes the stored API key from the OS credential store
7. WHEN no API key is configured via any method and the `fix` subcommand is invoked, THE CLI SHALL print a helpful message explaining how to configure a key and fall back to template-based fixes
8. THE CLI SHALL support a `sicario config test` subcommand that sends a minimal test request to the configured LLM endpoint to verify connectivity and authentication

### Requirement 21: Sicario Cloud Dashboard Integration

**User Story:** As a security team lead, I want a centralized cloud dashboard comparable to Semgrep AppSec Platform and Snyk Analytics, so that I can manage findings across repositories, measure AppSec program health across four pillars (coverage, exposure, management, prevention), triage issues with AI assistance, and demonstrate ROI to leadership.

#### Acceptance Criteria

##### CLI-to-Cloud Integration

1. THE CLI SHALL provide a `sicario login` subcommand that authenticates the user with the Sicario Cloud Platform via a browser-based OAuth flow and stores the resulting API token securely in the OS credential store
2. THE CLI SHALL provide a `sicario logout` subcommand that removes the stored API token from the OS credential store
3. WHEN the user is authenticated, THE CLI SHALL provide a `sicario publish` subcommand that uploads scan results (Findings, metadata, and scan context) to the Sicario Cloud Platform API
4. WHEN the `scan` subcommand is invoked with `--publish`, THE CLI SHALL automatically upload scan results to the Sicario Cloud Platform after the scan completes
5. THE CLI SHALL include repository name, branch, commit SHA, scan timestamp, scan duration, rules loaded count, files scanned count, and language breakdown as metadata when publishing results to the cloud platform
6. THE CLI SHALL function fully offline without authentication — the cloud platform is an optional enhancement, not a requirement for scanning
7. THE CLI SHALL provide a `sicario whoami` subcommand that displays the currently authenticated user, organization, and plan tier

##### Dashboard Overview (Semgrep-style)

8. THE Sicario Cloud Platform SHALL provide a web-based dashboard overview page displaying the organization's security posture with filterable charts covering: time period, product type (SAST, SCA, Secrets), project/repository, severity, confidence, and reachability
9. THE dashboard overview SHALL display a "Production Backlog" section showing: total open findings, total fixed, total ignored, and net new findings over the selected time period, with a stacked area chart showing the open backlog trend over time
10. THE dashboard overview SHALL display a "Secure Guardrails" section showing: findings shown to developers in PR/MR comments, findings fixed before reaching the default branch (shift-left rate), and a guardrails adoption percentage chart over time
11. THE dashboard overview SHALL display a "Most Findings by Project" table ranking repositories from most open findings to least, groupable by severity or scan product
12. THE dashboard overview SHALL display a "Median Open Age" chart showing the median number of days findings remain in the Open state, grouped by severity, helping teams identify remediation bottlenecks
13. THE dashboard overview SHALL support exporting the current view as a PDF report for stakeholder presentations

##### Analytics Pillars (Snyk-style)

14. THE Sicario Cloud Platform SHALL provide an Analytics section organized around four pillars: Coverage (% of repositories and languages being scanned), Exposure (open critical/high findings, zero-day exposure count, baseline vs new findings breakdown), Management (mean time to resolve by severity, SLA compliance rate, issues resolved over time), and Prevention (findings caught in PRs before merge, developer shift-left adoption rate via CLI/IDE usage)
15. THE Analytics section SHALL display developer adoption metrics showing which team members are actively using the CLI and IDE extension, with usage frequency and scan counts per developer
16. THE Analytics section SHALL support grouping metrics by team, application, or repository owner — not just by repository — using metadata tags configured via `sicario publish --tag <team:frontend>`
17. THE Analytics section SHALL track and display Mean Time to Resolve (MTTR) for each severity level, with configurable SLA targets that trigger alerts when MTTR exceeds the target

##### Triage Workflow (Semgrep-style)

18. THE Sicario Cloud Platform SHALL support the following triage states for each Finding: Open (default), Reviewing (under investigation), To Fix (assigned for remediation), Fixed (no longer detected in latest scan), Ignored (manually deprioritized), and Auto-Ignored (AI-flagged as likely false positive)
19. THE dashboard SHALL provide bulk triage actions allowing users to select multiple Findings and apply a triage state, add notes, or assign to a team member in a single operation
20. THE dashboard SHALL provide a Finding details page showing: severity, confidence score, CWE/OWASP category, data-flow trace (source → sink path), the relevant code snippet with syntax highlighting, activity history (when opened, triaged, fixed, by whom), and AI-generated remediation guidance
21. THE dashboard SHALL support AI-assisted triage that analyzes Finding context and suggests whether a Finding is likely a true positive or false positive, with an explanation of the reasoning, similar to Semgrep Multimodal
22. WHEN a Finding is triaged as "false positive" or "ignored" on the dashboard, THE CLI SHALL exclude that Finding from future scan results and exit code calculation when the `--publish` flag is used and the user is authenticated
23. THE dashboard SHALL support generating AI-powered fix suggestions directly from the Finding details page, with the option to open a draft PR/MR with the fix applied

##### Priority View

24. THE dashboard SHALL provide a "Priority" tab that displays only high-priority Findings defined as: Critical or High severity AND high confidence (≥0.8) AND reachable (confirmed taint path), with admin-customizable priority filter definitions
25. THE Priority tab SHALL be the default landing view for developers, showing only actionable findings that require immediate attention

##### API and Extensibility

26. THE Sicario Cloud Platform SHALL expose a REST API (versioned, with OpenAPI spec) that allows programmatic access to: Findings (CRUD + triage), scan history, analytics metrics, project configuration, and team management
27. THE Sicario Cloud Platform SHALL support webhook notifications that fire when: new Critical findings are detected, SLA targets are breached, or scan failures occur, with configurable delivery to Slack, Microsoft Teams, PagerDuty, or custom HTTP endpoints
28. THE Sicario Cloud Platform SHALL support data export in CSV format and via a documented data schema for integration with BI tools (Grafana, Looker, Snowflake)

##### Access Control and Organization

29. THE Sicario Cloud Platform SHALL support a hierarchical access model: Organization → Teams → Projects, where permissions are inherited downward and admins can restrict visibility to specific teams or projects
30. THE Sicario Cloud Platform SHALL support role-based access control with at minimum: Admin (full access, manage teams, configure policies), Manager (view all projects in their teams, triage findings, view analytics), and Developer (view findings in assigned projects, apply fixes, publish scans)
31. THE Sicario Cloud Platform SHALL support SSO via SAML 2.0 and OpenID Connect for enterprise customers

### Requirement 22: Pre-Commit Hook Integration

**User Story:** As a developer, I want Sicario to integrate as a Git pre-commit hook that scans only staged files, so that I catch security issues before they enter the repository without slowing down my workflow.

#### Acceptance Criteria

1. WHEN the `scan` subcommand is invoked with the `--staged` flag, THE Diff_Scanner SHALL use `git2` to identify only files in the Git staging area (index) and THE SAST_Engine SHALL scan only those files
2. WHEN the `--staged` flag is combined with `--severity-threshold`, THE CLI SHALL exit with code 1 (blocking the commit) only if Findings at or above the specified severity are detected in staged files
3. THE CLI SHALL provide a `sicario hook install` subcommand that creates a `.git/hooks/pre-commit` script invoking `sicario scan --staged --severity-threshold high --quiet`
4. WHEN the `hook install` subcommand is invoked and a pre-commit hook already exists, THE Hook_Manager SHALL append the Sicario invocation to the existing hook rather than overwriting it
5. THE CLI SHALL provide a `sicario hook uninstall` subcommand that removes the Sicario invocation from the `.git/hooks/pre-commit` script without affecting other hook content
6. WHEN the `--staged` scan completes with zero Findings above the threshold, THE CLI SHALL exit with code 0 and print a single-line summary (e.g., "sicario: 12 files scanned, 0 findings — commit OK") to stderr
7. WHEN the `--staged` scan detects Findings above the threshold, THE CLI SHALL exit with code 1 and print a concise summary of blocking Findings to stderr, including file path, line number, rule ID, and severity
8. THE Hook_Manager SHALL support a `sicario hook status` subcommand that reports whether the pre-commit hook is installed and its current configuration
9. WHEN the `SICARIO_SKIP_HOOK` environment variable is set to `1`, THE pre-commit hook SHALL skip the scan and exit with code 0, allowing developers to bypass the hook for exceptional commits

### Requirement 23: VS Code Extension and Language Server Protocol Interface

**User Story:** As a developer, I want Sicario to provide a VS Code extension that shows inline vulnerability squiggles and quick-fix suggestions, so that I can find and fix security issues without leaving my editor.

#### Acceptance Criteria

1. THE CLI SHALL provide a `sicario lsp` subcommand that starts a Language Server Protocol server communicating over stdin/stdout using the LSP JSON-RPC protocol
2. WHEN a file is opened or saved in the IDE, THE LSP_Server SHALL scan the file using the SAST_Engine and publish Findings as LSP Diagnostic objects with severity mapped to DiagnosticSeverity (Critical/High → Error, Medium → Warning, Low/Info → Information)
3. THE LSP_Server SHALL include the rule ID, CWE identifier, and Confidence_Score in the Diagnostic message and `data` field for each Finding
4. WHEN the IDE requests code actions for a Diagnostic, THE LSP_Server SHALL provide quick-fix code actions that invoke the Remediation_Engine to generate a patch for the selected Finding
5. THE LSP_Server SHALL support the `textDocument/didOpen`, `textDocument/didChange`, `textDocument/didSave`, `textDocument/didClose`, `textDocument/publishDiagnostics`, and `textDocument/codeAction` LSP methods
6. THE LSP_Server SHALL debounce scan requests so that rapid keystrokes do not trigger redundant scans, waiting at least 500 milliseconds after the last change before scanning
7. THE LSP_Server SHALL respect `.sicarioignore` and inline suppression comments when publishing Diagnostics
8. THE VS Code extension SHALL be packaged as a `.vsix` file that configures the LSP client to launch `sicario lsp` and maps Sicario Diagnostics to editor squiggles with severity-appropriate colors
9. THE VS Code extension SHALL provide a "Sicario: Scan Workspace" command that triggers a full workspace scan and populates the Problems panel with all Findings

### Requirement 24: Performance Benchmarking and Speed Verification

**User Story:** As a developer evaluating Sicario, I want a built-in benchmark command that proves Sicario's speed claims with reproducible data, so that I can trust the "10x faster" positioning and compare against other tools.

#### Acceptance Criteria

1. THE CLI SHALL provide a `sicario benchmark` subcommand that runs a standardized benchmark suite against the specified directory or a built-in synthetic test corpus
2. WHEN the `benchmark` subcommand is invoked, THE Benchmark_Runner SHALL measure and report: total scan wall-clock time, files scanned per second, rules evaluated per second, peak memory usage, and per-language breakdown of scan time
3. WHEN the `benchmark` subcommand is invoked with `--format json`, THE Benchmark_Runner SHALL output the timing data as a structured JSON document suitable for automated tracking
4. THE SAST_Engine SHALL complete a full scan of 10,000 source files (mixed JavaScript, Python, Rust, Go, and Java with an average of 200 lines per file) in under 10 seconds on a machine with 8 CPU cores and 16 GB RAM
5. WHEN the `benchmark` subcommand is invoked with `--compare-baseline`, THE Benchmark_Runner SHALL compare the current run against the most recent saved benchmark result and report performance regressions or improvements as a percentage delta
6. THE Benchmark_Runner SHALL persist benchmark results in `.sicario/benchmarks/` as timestamped JSON files for historical tracking
7. THE Benchmark_Runner SHALL warm up the scan engine with a single throwaway run before collecting timing measurements to exclude JIT and cache-cold effects

### Requirement 25: Rule Quality and False Positive Rate Enforcement

**User Story:** As a security engineer, I want every rule to be validated against a curated test corpus with known true-positive and true-negative cases, so that I can trust the rule set maintains a low false positive rate and each rule is demonstrably correct.

#### Acceptance Criteria

1. THE Rule_Test_Harness SHALL require each security rule to ship with a minimum of 3 true-positive test cases (code snippets that the rule must detect) and 3 true-negative test cases (code snippets that the rule must not flag)
2. THE Rule_Test_Harness SHALL execute all rule test cases as part of the `cargo test` suite and fail the build if any rule produces a false positive (flags a true-negative case) or a false negative (misses a true-positive case)
3. THE Rule_Test_Harness SHALL maintain a curated test corpus of at least 500 labeled code samples across all supported languages, with each sample annotated as vulnerable or safe for specific CWE categories
4. WHEN the full rule set is evaluated against the curated test corpus, THE Rule_Test_Harness SHALL verify that the aggregate false positive rate is below 15% (measured as false positives divided by total flagged findings)
5. THE Rule_Test_Harness SHALL generate a rule quality report showing per-rule precision, recall, and false positive rate when invoked via `sicario rules test --report`
6. WHEN a new rule is added without the required minimum test cases, THE Rule_Test_Harness SHALL reject the rule and report which test case types (true-positive or true-negative) are missing
7. THE Rule_Test_Harness SHALL support a `sicario rules validate` subcommand that checks all rules for syntactic correctness (valid tree-sitter queries), required metadata fields, and minimum test case coverage without running a full scan

### Requirement 26: Incremental Cached Scanning

**User Story:** As a developer working in a large monorepo, I want Sicario to cache parse trees and only re-scan files that have changed since the last scan, so that repeat scans complete in seconds instead of minutes.

#### Acceptance Criteria

1. THE Scan_Cache SHALL persist parsed AST representations and file content hashes in `.sicario/cache/` using a content-addressable storage scheme keyed by the SHA-256 hash of each file's contents
2. WHEN the `scan` subcommand is invoked and a cache exists, THE SAST_Engine SHALL compare each file's current content hash against the cached hash and skip re-parsing and re-scanning files that have not changed
3. WHEN a file has changed since the last cached scan, THE SAST_Engine SHALL re-parse and re-scan only that file and update the cache entry
4. WHEN a YAML rule file has changed since the last cached scan, THE Scan_Cache SHALL invalidate all cached results for the languages affected by the changed rules and trigger a full re-scan of those files
5. THE Scan_Cache SHALL support a `sicario cache clear` subcommand that deletes all cached data from `.sicario/cache/`
6. THE Scan_Cache SHALL support a `sicario cache stats` subcommand that reports the cache size on disk, number of cached files, cache hit rate for the last scan, and age of the oldest cache entry
7. WHEN the `scan` subcommand is invoked with `--no-cache`, THE SAST_Engine SHALL bypass the cache and perform a full scan, optionally updating the cache with fresh results unless `--no-cache-write` is also specified
8. THE Scan_Cache SHALL handle file deletions by removing stale cache entries for files that no longer exist in the scanned directory
9. WHEN scanning a repository with 50,000 or more files where fewer than 1% of files have changed since the last cached scan, THE SAST_Engine SHALL complete the incremental scan in under 5 seconds on a machine with 8 CPU cores and 16 GB RAM
