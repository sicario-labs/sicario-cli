# Implementation Plan: Sicario CLI Overhaul

## Overview

This plan transforms Sicario from a working SAST prototype into a production-grade security platform. Tasks are ordered so that foundational pieces (CLI framework, output formatting) land first, followed by engine improvements, rule expansion, AI remediation, integrations, and cloud features. All work targets the existing `sicario-cli` Rust crate — new functionality is added as new modules, existing modules are extended.

## Tasks

- [x] 1. CLI Foundation — Replace hand-rolled arg parsing with clap derive API
  - [x] 1.1 Create `cli/mod.rs` with top-level `SicarioCli` struct and `Command` enum using clap derive
    - Define `SicarioCli` with `#[derive(Parser)]` and `Command` enum with `#[derive(Subcommand)]`
    - Include all subcommands: `scan`, `init`, `report`, `fix`, `baseline`, `config`, `suppressions`, `completions`, `login`, `logout`, `publish`, `whoami`, `tui`, `hook`, `lsp`, `benchmark`, `rules`, `cache`
    - When `command` is `None`, default to launching the TUI for backward compatibility
    - _Requirements: 1.1, 1.2, 1.8, 1.9, 1.10_

  - [x] 1.2 Create `cli/scan.rs` with `ScanArgs` struct
    - Define all scan flags: `--dir`, `--rules`, `--format`, `--severity-threshold`, `--diff`, `--confidence-threshold`, `--quiet`, `--verbose`, `--exclude`, `--include`, `--jobs`, `--timeout`, `--max-lines-per-finding`, `--staged`, `--dataflow-traces`, `--no-color`, `--force-color`, `--exclude-rule`, `--json-output`, `--sarif-output`, `--text-output`, `--time`, `--no-cache`, `--no-cache-write`, `--auto-suppress`, `--publish`
    - Add clap validation: `--quiet` and `--verbose` are mutually exclusive
    - _Requirements: 1.3, 2.4, 2.5, 2.6, 3.1, 3.2, 3.3, 3.4, 18.4, 18.5, 19.1, 19.2, 19.4, 19.5, 19.7, 19.8, 19.9, 19.10_

  - [x] 1.3 Create remaining `cli/*.rs` subcommand arg structs
    - `cli/fix.rs`: `FixArgs` with file path, optional rule ID, `--revert <patch-id>`, `--no-verify`
    - `cli/baseline.rs`: `BaselineCommand` with `save`/`compare`/`trend` subcommands, `--tag`, `--format json`
    - `cli/config.rs`: `ConfigCommand` with `set-key`/`set-provider`/`show`/`delete-key`/`test` subcommands
    - `cli/hook.rs`: `HookCommand` with `install`/`uninstall`/`status` subcommands
    - `cli/benchmark.rs`: `BenchmarkArgs` with `--format json`, `--compare-baseline`
    - `cli/rules.rs`: `RulesCommand` with `test`/`validate` subcommands, `--report`
    - `cli/cache.rs`: `CacheCommand` with `clear`/`stats` subcommands
    - `cli/suppressions.rs`: `SuppressionsCommand` with `list`/`reset` subcommands
    - `cli/lsp.rs`: `LspArgs` (no flags needed, stdin/stdout)
    - _Requirements: 1.4, 1.5, 1.6, 1.7, 1.8, 1.11, 15.1, 15.2, 15.3, 15.5, 16.6, 16.7, 17.6, 20.1, 20.3, 20.5, 20.6, 20.8, 22.3, 22.5, 22.8, 24.1, 24.3, 24.5, 25.5, 25.7, 26.5, 26.6, 26.7_

  - [x] 1.4 Rewrite `main.rs` to use clap dispatch
    - Replace hand-rolled `args.get(1)` matching with `SicarioCli::parse()` and `match` on `Command`
    - Wire each subcommand variant to its handler function
    - Preserve `discover_bundled_rules()` and TUI launch as default
    - Add `clap_complete` shell completion generation for Bash, Zsh, Fish, PowerShell
    - _Requirements: 1.1, 1.9, 1.10, 1.11_

  - [x] 1.5 Add `ExitCode` enum and structured exit code logic
    - Define `ExitCode` enum: `Clean = 0`, `FindingsDetected = 1`, `InternalError = 2`
    - Implement exit code determination: filter findings by severity threshold and confidence threshold, exclude suppressed findings
    - Wire into `main.rs` so `std::process::exit()` uses the computed code
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

  - [ ]* 1.6 Write property test for exit code correctness
    - **Property 1: Exit code correctness**
    - Generate random findings with random severities and confidence scores, random thresholds, random suppression states
    - Assert exit code is 0 iff zero findings meet severity ≥ threshold AND confidence ≥ threshold AND not suppressed
    - **Validates: Requirements 2.1, 2.2, 2.4, 2.6, 12.5**

  - [x] 1.7 Update `lib.rs` to declare new modules
    - Add `pub mod cli;`, `pub mod output;`, `pub mod diff;`, `pub mod confidence;`, `pub mod baseline;`, `pub mod suppression_learner;`, `pub mod verification;`, `pub mod cache;`, `pub mod hook;`, `pub mod lsp;`, `pub mod benchmark;`, `pub mod rule_harness;`, `pub mod key_manager;`, `pub mod publish;`
    - _Requirements: all (structural)_

9- [x] 2. Checkpoint — CLI foundation compiles and `sicario --help` works
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Output Formatting — Professional terminal output with colors, tables, SARIF
  - [x] 3.1 Create `output/formatter.rs` with color-coded severity output
    - Use `owo-colors` for severity coloring: Critical=red, High=orange/yellow, Medium=yellow, Low=blue, Info=gray
    - Use `comfy-table` for aligned columns: severity, confidence, rule ID, file path, line number
    - Use `indicatif` for progress bar with file count and elapsed time during scanning
    - Auto-detect TTY: disable colors and progress when piped to non-TTY
    - Support `--no-color` and `--force-color` flags
    - Support `--max-lines-per-finding` (default 5) and `--max-chars-per-line` (default 160)
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.6, 18.8, 18.11, 18.12_

  - [x] 3.2 Create `output/branded.rs` with ASCII logo and summary banner
    - Implement branded `--version` output: ASCII art logo, version string, build date, target triple
    - Implement scan summary banner: total findings by severity, scan duration, files scanned, rules loaded, Semgrep comparison estimate (`duration * 10`)
    - Use Unicode box-drawing characters with ASCII fallback
    - _Requirements: 18.7, 18.10_

  - [x] 3.3 Create `output/sarif.rs` implementing `SarifEmitter` trait
    - Define SARIF data model structs: `SarifDocument`, `SarifRun`, `SarifTool`, `SarifDriver`, `SarifRule`, `SarifResult`, `SarifLocation`, `SarifMessage`, `SarifPropertyBag`
    - Implement severity mapping: Critical/High → "error", Medium → "warning", Low/Info → "note"
    - Include `tool.driver` with name, version, semanticVersion, and rules array
    - Include CWE identifiers in `taxa` property when available
    - Include confidence score as `properties.rank` (0–100 scale)
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9_

  - [ ]* 3.4 Write property test for SARIF structural validity
    - **Property 3: SARIF structural validity**
    - Generate random findings, assert results array length matches input, severity mapping correct, CWE taxa present, rank equals confidence * 100, tool.driver fields present
    - **Validates: Requirements 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8**

  - [ ]* 3.5 Write property test for SARIF round-trip
    - **Property 4: SARIF round-trip**
    - Generate random findings, serialize to SARIF JSON, deserialize back, assert equivalent findings
    - **Validates: Requirements 9.9**

  - [x] 3.4a Implement `--format` dispatch in scan command handler
    - Wire `--format text|json|sarif` to the appropriate emitter
    - Wire `--json-output`, `--sarif-output`, `--text-output` for simultaneous multi-format output to files
    - Implement `--format text` diff display with syntax-highlighted green/red for `fix` command
    - _Requirements: 9.1, 18.9, 19.7_

- [x] 4. Checkpoint — Output formatting works, `sicario scan --format sarif` produces valid SARIF
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Engine Improvements — Exit codes, diff scanning, caching, suppressions, confidence
  - [x] 5.1 Create `diff/diff_scanner.rs` implementing `DiffScanning` trait
    - Use `git2` to compute changed lines between working tree and a Git reference (commit, branch, tag)
    - Implement `changed_lines(&self, reference: &str) -> Result<HashMap<PathBuf, HashSet<usize>>>`
    - Implement `staged_files(&self) -> Result<Vec<PathBuf>>` for `--staged` flag
    - Resolve branch names to HEAD commit before diffing
    - Handle renamed files by tracking new file path
    - Return exit code 2 with descriptive error if ref doesn't exist or not a git repo
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 22.1_

  - [ ]* 5.2 Write property test for diff-aware filtering
    - **Property 5: Diff-aware filtering**
    - Generate random findings and random changed-lines maps, filter findings, assert every remaining finding's (file, line) is in the changed-lines map
    - **Validates: Requirements 10.2**

  - [x] 5.3 Create `cache/scan_cache.rs` implementing `ScanCaching` trait
    - Content-addressable cache keyed by SHA-256 of file contents
    - Store cached results in `.sicario/cache/` as JSON files named by content hash
    - Include `rule_set_hash` in cache entries — invalidate when rules change
    - Implement `get`, `put`, `invalidate_language`, `clear`, `stats` methods
    - Handle file deletions by removing stale cache entries
    - Wire `--no-cache` and `--no-cache-write` flags
    - _Requirements: 26.1, 26.2, 26.3, 26.4, 26.5, 26.6, 26.7, 26.8, 26.9_

  - [ ]* 5.4 Write property test for cache hit/miss correctness
    - **Property 19: Cache hit/miss correctness**
    - Assert: same content hash + same rule set hash → cache hit; changed content → cache miss; changed rule file → language invalidation
    - **Validates: Requirements 26.2, 26.3, 26.4**

  - [ ]* 5.5 Write property test for cache stale entry cleanup
    - **Property 20: Cache stale entry cleanup**
    - Assert: when a cached file no longer exists on disk, its cache entry is removed on next scan
    - **Validates: Requirements 26.8**

  - [x] 5.6 Extend `scanner/suppression_parser.rs` with rule-specific suppressions and all comment styles
    - Add support for `sicario-ignore`, `sicario-ignore-next-line`, `sicario-ignore:<rule-id>` directives
    - Recognize all comment styles: `//`, `#`, `/* */`, `<!-- -->`
    - Blanket directives suppress all findings on the line; rule-specific suppress only matching rule ID
    - Suppressed findings excluded from results, exit code, and all output formats
    - Preserve backward compatibility with existing `sicario-ignore-secret`
    - Report suppressed finding count in `--verbose` mode
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7_

  - [ ]* 5.7 Write property test for suppression correctness
    - **Property 8: Suppression correctness**
    - Generate source files with random suppression directives in various comment styles, assert correct suppression behavior for blanket vs rule-specific directives
    - **Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5**

  - [x] 5.8 Extend `engine/vulnerability.rs` with `Finding` struct
    - Add `confidence_score: f64`, `fingerprint: String`, `dataflow_trace: Option<Vec<TraceStep>>`, `suppressed: bool`, `suppression_rule: Option<String>`, `suggested_suppression: bool` fields
    - Implement stable fingerprint: `SHA-256(rule_id + file_path + snippet_hash)`
    - Add `TraceStep` struct for source→sink path
    - _Requirements: 14.1, 15.6, 17.5_

  - [x] 5.9 Extend `engine/security_rule.rs` with `test_cases` and `help_uri` fields
    - Add `test_cases: Option<Vec<RuleTestCase>>` and `help_uri: Option<String>` to `SecurityRule`
    - Define `RuleTestCase` struct with `code`, `expected` (TruePositive/TrueNegative), `language`
    - _Requirements: 25.1, 25.2_

  - [x] 5.10 Extend `engine/sast_engine.rs` with cache integration and confidence scoring hooks
    - Before scanning a file, check cache by content hash — skip if cache hit with matching rule set hash
    - After scanning, store results in cache
    - After finding generation, compute confidence score via `Confidence_Scorer`
    - Apply suppression filtering via `Suppression_Parser`
    - Apply diff filtering when `--diff` or `--staged` is active
    - Support `--exclude`, `--include`, `.sicarioignore`, `--exclude-rule` filtering
    - Support `--jobs` for thread count, `--timeout` for per-file timeout
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6, 19.10, 26.2, 26.3_

  - [ ]* 5.11 Write property test for file exclusion/inclusion correctness
    - **Property 15: File exclusion/inclusion correctness**
    - Generate random file paths and glob patterns, assert a file is scanned iff it matches include (or no includes specified) AND doesn't match exclude AND not in .sicarioignore AND rule IDs not in --exclude-rule
    - **Validates: Requirements 19.1, 19.2, 19.3, 19.10**

- [ ] 6. Checkpoint — Engine improvements compile, diff scanning and caching work
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Confidence Scoring
  - [x] 7.1 Create `confidence/scorer.rs` implementing `ConfidenceScoring` trait
    - Compute deterministic 0.0–1.0 score per finding using three signals:
      - Reachability (0.4 weight): confirmed taint path → high score
      - Pattern specificity (0.3 weight): precise query match → higher score
      - Contextual indicators (0.3 weight): presence of sanitization/validation → lower score
    - If confirmed taint path from user-controlled source to sink → score ≥ 0.8
    - If generic pattern with no data-flow path → score ≤ 0.5
    - Display as percentage in `--format text` output (e.g., "92% confidence")
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 14.7, 14.8_

  - [ ]* 7.2 Write property test for confidence scoring invariants
    - **Property 9: Confidence scoring invariants**
    - Assert score in [0.0, 1.0], confirmed taint path → ≥ 0.8, generic pattern no data-flow → ≤ 0.5
    - **Validates: Requirements 14.1, 14.2, 14.3, 14.4**

  - [ ]* 7.3 Write property test for confidence scoring determinism
    - **Property 10: Confidence scoring determinism**
    - Compute score twice for same finding + same source + same rules, assert bitwise equal f64
    - **Validates: Requirements 14.8**

- [x] 8. Baseline Tracking
  - [x] 8.1 Create `baseline/manager.rs` implementing `BaselineManagement` trait
    - Implement `save`: persist findings as timestamped JSON in `.sicario/baselines/`, support `--tag`
    - Implement `compare`: compute delta (new, resolved, unchanged) by fingerprint matching
    - Implement `trend`: summarize finding counts across all saved baselines
    - Use stable fingerprint `SHA-256(rule_id + file_path + snippet_hash)` — line/column changes don't affect identity
    - Support `--format json` for delta output
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 15.7_

  - [ ]* 8.2 Write property test for baseline delta correctness
    - **Property 11: Baseline delta correctness**
    - Generate two random finding sets, compute delta, assert three disjoint sets whose union equals union of old and new fingerprints
    - **Validates: Requirements 15.3**

  - [ ]* 8.3 Write property test for baseline fingerprint stability
    - **Property 12: Baseline fingerprint stability**
    - Change only line/column on a finding, assert fingerprint unchanged
    - **Validates: Requirements 15.6, 17.5**

  - [ ]* 8.4 Write property test for baseline round-trip
    - **Property 13: Baseline round-trip**
    - Serialize baseline to JSON, deserialize back, assert equivalent
    - **Validates: Requirements 15.7**

- [ ] 9. Checkpoint — Confidence scoring and baseline tracking work
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Rule Expansion — JavaScript/TypeScript (100+ YAML rules with test cases)
  - [x] 10.1 Write SQL injection rules for JS/TS (15+ rules)
    - Write YAML rule files in `sicario-cli/rules/javascript/` covering: string concatenation in query builders, template literal interpolation in SQL strings, raw query calls in Sequelize, Knex, Prisma, TypeORM, Drizzle
    - Each rule must include ≥3 TP and ≥3 TN test cases in the YAML
    - _Requirements: 4.2, 4.16_

  - [x] 10.2 Write XSS rules for JS/TS (15+ rules)
    - Cover: `dangerouslySetInnerHTML` in React/JSX, unescaped template rendering in EJS/Handlebars/Pug, `document.write` with dynamic content, `v-html` in Vue, `innerHTML` assignment
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 4.3, 4.16_

  - [x] 10.3 Write SSRF, path traversal, and deserialization rules for JS/TS (15+ rules)
    - SSRF: unvalidated URL in `fetch`, `axios`, `http.request`, `got`, `node-fetch`
    - Path traversal: unsanitized input in `fs.readFile`, `fs.readFileSync`, `fs.createReadStream`, `path.join`, `path.resolve`
    - Deserialization: `JSON.parse` without schema validation, `eval`-based deserialization, `node-serialize`
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 4.4, 4.5, 4.6, 4.16_

  - [x] 10.4 Write Express.js, crypto, and prototype pollution rules for JS/TS (15+ rules)
    - Express: missing helmet, missing rate limiting, missing CORS, disabled CSRF, verbose error responses
    - Crypto: MD5/SHA1 for passwords, hardcoded keys, `Math.random`, deprecated `createCipher`
    - Prototype pollution: unsafe recursive merge, unvalidated bracket notation, `Object.assign` with untrusted sources
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 4.7, 4.8, 4.9, 4.16_

  - [x] 10.5 Write Next.js, auth, NoSQL injection, ReDoS, open redirect, and TS type safety rules (40+ rules)
    - Next.js: SSRF in `getServerSideProps`, exposed API keys in client bundles, missing auth in API routes, unsafe redirects
    - Auth: JWT verification bypass, missing token expiration, hardcoded JWT secrets, insecure session config
    - NoSQL injection: unvalidated input in MongoDB operators, Mongoose raw queries, Redis command injection
    - ReDoS: catastrophic backtracking in user-facing regex
    - Open redirect: unvalidated redirect URLs in `res.redirect`, `window.location`, `router.push`
    - TypeScript: `as any` in security contexts, explicit `any` on user input params, unsafe type narrowing bypassing validation
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 4.10, 4.11, 4.12, 4.13, 4.14, 4.15, 4.16_

  - [ ]* 10.6 Write property test for rule loading round-trip (JS/TS)
    - **Property 2: Rule loading round-trip (JS/TS subset)**
    - Serialize a valid SecurityRule to YAML, load via Rule_Loader, assert compiled rule matches same AST patterns
    - **Validates: Requirements 4.16**

- [x] 11. Rule Expansion — Python (100+ YAML rules with test cases)
  - [x] 11.1 Write Django and Flask/Jinja2 rules for Python (20+ rules)
    - Django ORM injection: `extra()`, `raw()`, `RawSQL`, `cursor.execute` with string formatting
    - Flask SSTI: `render_template_string` with user input, `Environment` with unsafe settings
    - Django misconfig: `DEBUG = True`, `ALLOWED_HOSTS = ['*']`, missing CSRF middleware, hardcoded `SECRET_KEY`, `@csrf_exempt`
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 5.2, 5.3, 5.9, 5.15_

  - [x] 11.2 Write SQL injection, path traversal, deserialization, and command injection rules for Python (25+ rules)
    - SQLi: f-string/%-format in `cursor.execute`, `sqlalchemy.text`, `engine.execute`
    - Path traversal: `open()`, `os.path.join`, `pathlib.Path`, `shutil.copy`, `send_file` with unsanitized input
    - Deserialization: `yaml.load` without `SafeLoader`, `pickle.loads`, `marshal.loads`, `shelve.open`, `jsonpickle.decode`
    - Command injection: `os.system`, `os.popen`, `subprocess.call` with `shell=True`, string-formatted subprocess args
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 5.4, 5.5, 5.6, 5.7, 5.15_

  - [x] 11.3 Write crypto, FastAPI, LDAP, XXE, mass assignment, and logging rules for Python (55+ rules)
    - Crypto: `hashlib.md5`/`sha1` for passwords, `random` module for security, weak Fernet key derivation
    - FastAPI: missing auth dependency injection, unvalidated path params, missing CORS, exposed debug endpoints
    - LDAP injection: unsanitized input in `ldap.search_s`, `ldap3` filter construction
    - XXE: `xml.etree.ElementTree.parse`, `lxml.etree.parse`, `xml.sax` without disabling external entities
    - Mass assignment: unvalidated `**kwargs` in Django model creation, Flask-SQLAlchemy bulk updates
    - Logging: passwords/tokens/API keys in `logging.info`, `logging.debug`, `print`, `logger` calls
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 5.8, 5.10, 5.11, 5.12, 5.13, 5.14, 5.15_

  - [ ]* 11.4 Write property test for rule loading round-trip (Python)
    - **Property 2: Rule loading round-trip (Python subset)**
    - **Validates: Requirements 5.15**

- [-] 12. Rule Expansion — Rust (100+ YAML rules with test cases)
  - [x] 12.1 Write SQL injection, command injection, and path traversal rules for Rust (20+ rules)
    - SQLi: string formatting in `sqlx::query`, `diesel::sql_query`, `rusqlite::execute`, `tokio-postgres` raw queries
    - Command injection: `std::process::Command` with unsanitized user input, shell invocations
    - Path traversal: unsanitized input in `std::fs::read`, `std::fs::write`, `std::fs::File::open`, `tokio::fs`
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - Do NOT flag generic `unwrap()`/`expect()` or bare `unsafe` blocks
    - _Requirements: 6.2, 6.3, 6.4, 6.11, 6.12, 6.13_

  - [x] 12.2 Write crypto, deserialization, memory safety, and concurrency rules for Rust (40+ rules)
    - Crypto: `md5`/`sha1` crates for passwords, hardcoded keys, `rand::thread_rng` for security instead of `OsRng`
    - Deserialization: `serde_json::from_str`/`serde_yaml::from_str` of untrusted input without size limits
    - Memory safety: raw pointer dereferences without bounds checks, `transmute` between incompatible types, `from_raw_parts` without length validation, use-after-free in `unsafe`
    - Concurrency: data races via `unsafe` shared mutable state, `Send`/`Sync` misimplementation, unprotected state across `tokio::spawn`
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 6.5, 6.6, 6.7, 6.8, 6.13_

  - [x] 12.3 Write Actix-web/Axum framework and information leakage rules for Rust (40+ rules)
    - Framework: missing auth extractors, unvalidated path params, missing CORS, exposed debug endpoints
    - Info leakage: `Debug` on types with secrets, `Display` exposing sensitive fields, verbose error messages to clients
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 6.9, 6.10, 6.13_

  - [ ]* 12.4 Write property test for rule loading round-trip (Rust)
    - **Property 2: Rule loading round-trip (Rust subset)**
    - **Validates: Requirements 6.13**

- [x] 13. Rule Expansion — Go (100+ YAML rules with test cases)
  - [x] 13.1 Write SQL injection, command injection, path traversal, and SSRF rules for Go (25+ rules)
    - SQLi: string concatenation in `database/sql`, `fmt.Sprintf` in SQL, raw queries in GORM/sqlx/ent
    - Command injection: `os/exec.Command` with unsanitized input, `os.StartProcess`, `bash -c` invocations
    - Path traversal: unsanitized input in `os.Open`, `os.ReadFile`, `ioutil.ReadFile`, `filepath.Join`, `http.ServeFile`
    - SSRF: unvalidated URL in `http.Get`, `http.Post`, `http.NewRequest`, `resty` client
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 7.2, 7.3, 7.4, 7.5, 7.13_

  - [x] 13.2 Write crypto, error handling, framework, race condition, TLS, info leakage, and XXE rules for Go (75+ rules)
    - Crypto: `crypto/md5`/`crypto/sha1` for passwords, `math/rand` for security, hardcoded keys
    - Error handling: unchecked error returns (`_ = err`), deferred calls with ignored errors, missing io.Reader/Writer error checks
    - Frameworks (Gin/Echo/Fiber): missing auth middleware, unvalidated request binding, missing CORS, verbose errors
    - Race conditions: goroutine shared variable access without sync, missing mutex, unsafe `sync.WaitGroup`
    - TLS: `InsecureSkipVerify: true`, weak TLS versions, disabled cert validation
    - Info leakage: sensitive data in `log.Printf`/`fmt.Printf`, verbose HTTP error messages
    - XXE: `xml.NewDecoder` without disabling external entities
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 7.6, 7.7, 7.8, 7.9, 7.10, 7.11, 7.12, 7.13_

  - [ ]* 13.3 Write property test for rule loading round-trip (Go)
    - **Property 2: Rule loading round-trip (Go subset)**
    - **Validates: Requirements 7.13**

- [x] 14. Rule Expansion — Java (100+ YAML rules with test cases)
  - [x] 14.1 Write SQL injection, XSS, command injection, and deserialization rules for Java (25+ rules)
    - SQLi: string concatenation in `Statement.execute`, `PreparedStatement` misuse, JPQL/HQL injection, Spring `@Query` concatenation
    - XSS: unescaped JSP output, Thymeleaf `th:utext`, Spring MVC response body with user input
    - Command injection: `Runtime.exec` with unsanitized input, `ProcessBuilder` with user args, JNDI injection via `InitialContext.lookup`
    - Deserialization: `ObjectInputStream.readObject`, `XMLDecoder`, `XStream` without allowlists, `SnakeYAML` without safe constructors
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 8.2, 8.3, 8.4, 8.5, 8.13_

  - [x] 14.2 Write path traversal, crypto, Spring Boot, SSRF, XXE, LDAP, and logging rules for Java (75+ rules)
    - Path traversal: unsanitized input in `new File()`, `Paths.get()`, `FileInputStream`, Spring `Resource` loading
    - Crypto: MD5/SHA1 via `MessageDigest`, DES/3DES, ECB mode, hardcoded keys, `java.util.Random` for security
    - Spring Boot: disabled CSRF, permissive CORS, missing `@PreAuthorize`, exposed actuator, DEBUG logging in production
    - SSRF: unvalidated URL in `HttpURLConnection`, `HttpClient`, `RestTemplate`, `WebClient`
    - XXE: `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory` without disabling external entities
    - LDAP injection: unsanitized input in `DirContext.search`, Spring LDAP template queries
    - Logging: passwords/tokens/API keys in `Logger.info`/`Logger.debug`/`System.out.println`/SLF4J
    - Each rule must include ≥3 TP and ≥3 TN test cases
    - _Requirements: 8.6, 8.7, 8.8, 8.9, 8.10, 8.11, 8.12, 8.13_

  - [ ]* 14.3 Write property test for rule loading round-trip (Java)
    - **Property 2: Rule loading round-trip (Java subset)**
    - **Validates: Requirements 8.13**

- [x] 15. Checkpoint — All 500+ YAML rules written with test cases across 5 languages
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 16. AI Remediation Improvements — Multi-provider LLM client, template fixes, verification
  - [ ] 16.1 Rename `remediation/cerebras_client.rs` → `remediation/llm_client.rs` and generalize to OpenAI-compatible API
    - Make endpoint configurable via `SICARIO_LLM_ENDPOINT` env var
    - Model configurable via `SICARIO_LLM_MODEL` env var, default `llama3.1-8b`
    - Use non-blocking async HTTP via `reqwest` with 30s timeout
    - Integrate with tokio runtime without creating nested runtimes
    - _Requirements: 11.1, 11.2, 11.3, 11.4_

  - [ ] 16.2 Create `key_manager/manager.rs` implementing key resolution precedence
    - Resolution order: `SICARIO_LLM_API_KEY` env → OS keyring (via `keyring` crate) → `CEREBRAS_API_KEY` env
    - Implement `config set-key`: masked input prompt, store in OS credential store
    - Implement `config set-provider`: store endpoint URL and model in `.sicario/config.yaml`
    - Implement `config show`: display provider config and whether key is configured (without revealing key)
    - Implement `config delete-key`: remove from OS credential store
    - Implement `config test`: send minimal test request to verify connectivity
    - When no key configured and `fix` invoked, print helpful message and fall back to template fixes
    - _Requirements: 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7, 20.8_

  - [ ]* 16.3 Write property test for key resolution precedence
    - **Property 16: Key resolution precedence**
    - Assert correct precedence: env SICARIO_LLM_API_KEY > keyring > env CEREBRAS_API_KEY
    - **Validates: Requirements 20.4**

  - [ ] 16.4 Expand template-based fixes in `remediation/remediation_engine.rs`
    - Ensure template fixes exist for: SQL injection (parameterized queries), XSS (output encoding), command injection (allowlist-validated args)
    - On LLM error/timeout, fall back to template fix — never return original code unchanged
    - Validate LLM-generated code syntax via tree-sitter before applying
    - Display unified diff with confirmation prompt before applying
    - Create backup before applying, support `fix --revert <patch-id>`
    - _Requirements: 11.5, 11.6, 11.7, 11.8, 11.9, 11.10_

  - [ ]* 16.5 Write property test for patch backup round-trip
    - **Property 6: Patch backup round-trip**
    - Apply a patch then revert via `fix --revert`, assert file restored byte-for-byte
    - **Validates: Requirements 11.8**

  - [ ]* 16.6 Write property test for template fix validity
    - **Property 7: Template fix validity**
    - For vulnerable code matching SQLi/XSS/CmdInj, assert template fix differs from original and parses without tree-sitter errors
    - **Validates: Requirements 11.10**

  - [ ] 16.7 Create `verification/scanner.rs` implementing `VerificationScanning` trait
    - After fix application, re-scan patched file for the specific rule
    - Report "Fix verified: vulnerability resolved" if finding gone
    - Report "Fix incomplete: vulnerability still detected" if still present, offer revert
    - Report "Fix introduced new findings" if new findings detected, offer revert
    - Compare using stable fingerprint to distinguish pre-existing from new findings
    - Support `--no-verify` to skip verification
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6_

- [ ] 17. Learning Suppressions
  - [ ] 17.1 Create `suppression_learner/learner.rs` implementing `SuppressionLearning` trait
    - Record suppression patterns: rule ID, AST node type, surrounding code context
    - After 3+ suppressions for same rule ID with similar AST context, flag subsequent matches as "suggested suppression"
    - When `--auto-suppress` is active, exclude matching findings from results
    - Persist learned patterns in `.sicario/learned_suppressions.json`
    - Report auto-suppressed count separately in `--verbose` mode
    - Implement `suppressions list` and `suppressions reset` subcommands
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 16.7_

  - [ ]* 17.2 Write property test for learning suppression correctness
    - **Property 14: Learning suppression correctness**
    - Generate sequences of suppression events, assert that 3+ similar suppressions trigger "suggested suppression" flag, and `--auto-suppress` excludes them
    - **Validates: Requirements 16.2, 16.3**

- [ ] 18. Checkpoint — AI remediation, verification, and learning suppressions work
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 19. Pre-Commit Hook Integration
  - [ ] 19.1 Create `hook/manager.rs` implementing `HookManagement` trait
    - `install`: create/append to `.git/hooks/pre-commit` with `sicario scan --staged --severity-threshold high --quiet`
    - Append to existing hooks rather than overwriting
    - `uninstall`: remove only the Sicario invocation from the hook script
    - `status`: report whether hook is installed and its configuration
    - Support `SICARIO_SKIP_HOOK=1` env var to bypass hook
    - Wire `--staged` scan: use `staged_files()` from `DiffScanner`, scan only staged files
    - Exit 0 with single-line summary when clean, exit 1 with concise finding summary when blocking
    - _Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.6, 22.7, 22.8, 22.9_

- [ ] 20. LSP Server and VS Code Extension
  - [ ] 20.1 Create `lsp/server.rs` implementing LSP JSON-RPC over stdin/stdout
    - Use `lsp-server` and `lsp-types` crates
    - Support methods: `textDocument/didOpen`, `textDocument/didChange`, `textDocument/didSave`, `textDocument/didClose`, `textDocument/publishDiagnostics`, `textDocument/codeAction`
    - Map findings to `Diagnostic` objects: Critical/High → Error, Medium → Warning, Low/Info → Information
    - Include rule ID, CWE, confidence score in diagnostic message and data field
    - Provide quick-fix code actions that invoke Remediation_Engine
    - Debounce scan requests: 500ms after last change before scanning
    - Respect `.sicarioignore` and inline suppressions
    - _Requirements: 23.1, 23.2, 23.3, 23.4, 23.5, 23.6, 23.7_

  - [ ]* 20.2 Write property test for LSP diagnostic severity mapping
    - **Property 17: LSP diagnostic severity mapping**
    - Assert Critical/High → Error, Medium → Warning, Low/Info → Information
    - **Validates: Requirements 23.2**

  - [ ] 20.3 Create VS Code extension package
    - Package as `.vsix` file configuring LSP client to launch `sicario lsp`
    - Map Sicario diagnostics to editor squiggles with severity-appropriate colors
    - Provide "Sicario: Scan Workspace" command for full workspace scan
    - _Requirements: 23.8, 23.9_

- [ ] 21. GitHub Action for CI Integration
  - [ ] 21.1 Create GitHub Action definition (`action.yml`) and wrapper script
    - Usable via `uses: sicario/scan-action@v1`
    - Accept inputs: `severity-threshold`, `diff-base`, `format`, `scan-path`
    - When `format: sarif`, upload via `github/codeql-action/upload-sarif`
    - When `diff-base` provided, pass as `--diff` flag
    - Set `findings-count` and `exit-code` as action outputs
    - Cache Sicario binary between workflow runs
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 13.6_

- [ ] 22. Checkpoint — Integrations (hooks, LSP, GitHub Action) work
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 23. Cloud Platform — Publish client (CLI side)
  - [ ] 23.1 Extend `auth/` module with cloud login/logout/whoami
    - `login`: browser-based OAuth flow, store API token in OS credential store
    - `logout`: remove stored API token
    - `whoami`: display authenticated user, organization, plan tier
    - _Requirements: 21.1, 21.2, 21.7_

  - [ ] 23.2 Create `publish/client.rs` implementing `PublishClient`
    - Authenticated upload of `ScanReport` payload (findings + metadata) to Cloud API
    - Include metadata: repository, branch, commit SHA, timestamp, duration, rules loaded, files scanned, language breakdown, tags
    - Wire `--publish` flag on `scan` command for auto-upload after scan
    - CLI functions fully offline — cloud is optional enhancement
    - _Requirements: 21.3, 21.4, 21.5, 21.6_

  - [ ]* 23.3 Cloud Platform — REST API (server side)
    - Define OpenAPI v1 spec for REST API: Findings CRUD + triage, scan history, analytics, project config, team management
    - Implement versioned REST API (Rust/Axum or Node.js) with JWT auth
    - PostgreSQL + TimescaleDB for time-series analytics
    - Webhook dispatcher for Slack/Teams/PagerDuty/custom HTTP on critical findings, SLA breaches, scan failures
    - Support CSV export and documented data schema for BI tools (Grafana, Looker)
    - _Requirements: 21.26, 21.27, 21.28_

  - [ ]* 23.4 Cloud Platform — Dashboard web frontend
    - Next.js + React dashboard with:
      - Overview page: filterable charts (time period, product type, project, severity, confidence, reachability)
      - Production Backlog: open/fixed/ignored/net-new findings, stacked area chart
      - Secure Guardrails: PR findings shown, shift-left rate, adoption chart
      - Most Findings by Project table, Median Open Age chart
      - PDF export for stakeholder presentations
    - Analytics pillars: Coverage, Exposure, Management, Prevention
    - Developer adoption metrics, team/app/repo grouping via tags
    - MTTR tracking with configurable SLA targets and alerts
    - Triage workflow: Open/Reviewing/To Fix/Fixed/Ignored/Auto-Ignored states
    - Bulk triage actions, finding details page with data-flow trace and AI guidance
    - AI-assisted triage (true positive vs false positive suggestion)
    - Priority tab: Critical/High + high confidence + reachable findings as default developer view
    - _Requirements: 21.8–21.25_

  - [ ]* 23.5 Cloud Platform — RBAC and SSO
    - Organization → Teams → Projects hierarchy with inherited permissions
    - Roles: Admin, Manager, Developer
    - SSO via SAML 2.0 and OpenID Connect
    - _Requirements: 21.29, 21.30, 21.31_

  - [ ]* 23.6 Cloud Platform — Snowflake/BI data export integration
    - Documented data schema for Snowflake integration
    - _Requirements: 21.28_

- [ ] 24. Benchmarking and Rule Quality Enforcement
  - [ ] 24.1 Create `benchmark/runner.rs` implementing `BenchmarkRunner`
    - Measure: total wall-clock time, files/second, rules/second, peak memory (via `sysinfo`), per-language breakdown
    - Support `--format json` for structured output
    - Support `--compare-baseline` to compare against previous benchmark
    - Persist results in `.sicario/benchmarks/` as timestamped JSON
    - Warm up with throwaway run before collecting measurements
    - Target: 10,000 files (mixed languages, ~200 lines each) in under 10 seconds on 8-core/16GB machine
    - _Requirements: 24.1, 24.2, 24.3, 24.4, 24.5, 24.6, 24.7_

  - [ ] 24.2 Create `rule_harness/harness.rs` implementing `RuleQualityValidation` trait
    - Validate each rule has ≥3 TP and ≥3 TN test cases
    - Execute all test cases: every TP must produce ≥1 finding, every TN must produce 0 findings
    - Reject rules missing required test cases
    - Generate quality report: per-rule precision, recall, FP rate via `sicario rules test --report`
    - `sicario rules validate`: check syntactic correctness, required metadata, minimum test case coverage
    - Aggregate FP rate across full corpus must be <15%
    - Maintain curated test corpus of ≥500 labeled code samples across all languages
    - _Requirements: 25.1, 25.2, 25.3, 25.4, 25.5, 25.6, 25.7_

  - [ ]* 24.3 Write property test for rule quality enforcement
    - **Property 18: Rule quality enforcement**
    - Assert: each rule has ≥3 TP and ≥3 TN test cases, every TP produces ≥1 finding, every TN produces 0 findings
    - **Validates: Requirements 25.1, 25.2**

- [ ] 25. Final Checkpoint — Full integration
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 26. Wire everything together and update Cargo.toml
  - [ ] 26.1 Add new dependencies to workspace `Cargo.toml`
    - Add: `clap` (v4.5, features: derive, env, string), `clap_complete` (v4.5), `indicatif` (v0.17), `owo-colors` (v4.0), `comfy-table` (v7.1), `console` (v0.15), `lsp-server` (v0.7), `lsp-types` (v0.95), `sysinfo` (v0.30)
    - Add these to `[workspace.dependencies]` and reference from `sicario-cli/Cargo.toml`
    - _Requirements: all (structural)_

  - [ ] 26.2 Update `.sicarioignore` support in `parser/exclusion_manager.rs`
    - Add `.sicarioignore` file parsing following `.gitignore` syntax
    - Wire into SAST_Engine file discovery
    - _Requirements: 19.3_

  - [ ] 26.3 Final integration: ensure all subcommands dispatch correctly from `main.rs`
    - Verify each `Command` variant routes to its handler
    - Verify default (no subcommand) launches TUI
    - Verify `--version` and `--help` work at top level and per subcommand
    - _Requirements: 1.9, 1.10_

- [ ] 27. Final Checkpoint — All tests pass, all subcommands functional
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP — these include property-based tests, the cloud dashboard web frontend (23.4), cloud RBAC/SSO (23.5), Snowflake integration (23.6), and the cloud REST API server (23.3)
- The CLI publish client (23.1, 23.2) is required; the cloud server-side components are optional for initial release
- Rule expansion tasks (10–14) involve writing YAML rule files with embedded test cases — no engine code changes needed since the Rule_Loader already supports arbitrary YAML rules
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation throughout the build
- Property tests validate the 20 correctness properties defined in the design document
