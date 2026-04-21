# Implementation Plan: Sicario CLI Core

## Overview

This implementation plan breaks down the Sicario CLI into discrete, incremental tasks that build toward a complete, production-ready security scanning tool. The approach prioritizes establishing core infrastructure first (parsing, rule matching, TUI), then layering on advanced features (reachability analysis, AI remediation, cloud integration). Each task is designed to produce working, testable code that integrates with previous steps.

## Tasks

- [x] 1. Project scaffolding and core infrastructure
  - Initialize Rust project with Cargo workspace structure
  - Set up dependencies: tree-sitter, ratatui, crossterm, rayon, tokio, serde
  - Create module structure: `parser/`, `scanner/`, `engine/`, `tui/`, `auth/`, `remediation/`
  - Configure build for cross-platform compilation (Linux, macOS, Windows)
  - _Requirements: 12.1_

- [x] 2. Implement Tree-sitter parsing engine with exclusion management
  - [x] 2.1 Create TreeSitterEngine with language detection and AST caching
    - Implement parser initialization for JavaScript, TypeScript, Python, Rust, Go, Java
    - Build LRU cache for parsed ASTs using `lru` crate
    - Add language detection from file extensions
    - _Requirements: 2.1, 2.2, 2.4, 2.5_

  - [x] 2.2 Write property test for parallel parsing correctness
    - **Property 5: Parallel parsing correctness**
    - **Validates: Requirements 2.3**

  - [x] 2.3 Write property test for AST cache consistency
    - **Property 6: AST cache consistency**
    - **Validates: Requirements 2.4**

  - [x] 2.4 Implement ExclusionManager for intelligent file filtering
    - Load and parse `.gitignore` patterns using `ignore` crate
    - Load and parse `.sicarioignore` with glob pattern support
    - Define default exclusions (node_modules/, dist/, build/, target/, *.min.js)
    - Integrate exclusion checks into `should_scan_file()` method
    - _Requirements: 15.1, 15.2, 15.3, 15.4_

  - [x] 2.5 Write property test for exclusion pattern effectiveness
    - **Property 34: Exclusion pattern effectiveness**
    - **Validates: Requirements 15.1, 15.2, 15.3, 15.4**

- [-] 3. Build YAML-based security rule engine
  - [x] 3.1 Define SecurityRule and QueryPattern data models
    - Create Rust structs for SecurityRule with OWASP category mapping
    - Implement YAML deserialization using `serde_yaml`
    - Add CWE ID and OWASP category fields
    - _Requirements: 3.1, 17.1, 17.2_

  - [x] 3.2 Implement YAML rule loading and compilation
    - Parse YAML rule files into SecurityRule structs
    - Compile tree-sitter query patterns from rule definitions
    - Validate rule syntax and report errors
    - _Requirements: 3.1, 3.2_

  - [x] 3.3 Write property test for YAML rule compilation correctness
    - **Property 7: YAML rule compilation correctness**
    - **Validates: Requirements 3.2**

  - [x] 3.3 Create SAST engine core with pattern matching
    - Implement `scan_file()` to apply all rules to a single AST
    - Capture match metadata (file path, line, column, snippet, severity)
    - Build Vulnerability structs with OWASP category from matched rules
    - _Requirements: 3.3, 3.4_

  - [x] 3.4 Write property test for rule metadata preservation
    - **Property 8: Rule metadata preservation**
    - **Validates: Requirements 3.4**

  - [x] 3.5 Implement parallel directory scanning with Rayon
    - Use `rayon::par_iter()` to scan multiple files concurrently
    - Collect vulnerabilities from all files
    - Sort results by severity and file path
    - _Requirements: 2.3_

  - [x] 3.6 Write property test for custom rule merging
    - **Property 9: Custom rule merging**
    - **Validates: Requirements 3.5**

- [x] 4. Checkpoint - Ensure core scanning works
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement secret scanner with active verification
  - [x] 5.1 Create SecretPattern definitions and regex compilation
    - Define patterns for AWS keys, Stripe tokens, GitHub PATs, database URLs
    - Compile regex patterns with entropy threshold calculations
    - _Requirements: 1.2_

  - [x] 5.2 Write property test for secret pattern detection completeness
    - **Property 1: Secret pattern detection completeness**
    - **Validates: Requirements 1.2**

  - [x] 5.3 Implement SecretVerifier trait and concrete verifiers
    - Create AWS verifier using STS GetCallerIdentity API
    - Create GitHub verifier using /user endpoint
    - Create Stripe verifier using /v1/charges endpoint
    - Handle API rate limits and network errors gracefully
    - _Requirements: 1.3_

  - [x] 5.4 Write property test for active credential verification accuracy
    - **Property 2: Active credential verification accuracy**
    - **Validates: Requirements 1.3**

  - [x] 5.5 Implement SuppressionParser for inline comment detection
    - Use tree-sitter to parse comment nodes
    - Detect `// sicario-ignore-secret` and `# sicario-ignore-secret` patterns
    - Support suppression in all target languages
    - _Requirements: 16.1, 16.2, 16.3, 16.4_

  - [x] 5.6 Write property test for inline suppression recognition
    - **Property 35: Inline suppression recognition**
    - **Validates: Requirements 16.1, 16.2**

  - [x] 5.7 Integrate secret scanning with git2 for staged files and history
    - Scan staged files using `git2::Repository::statuses()`
    - Traverse git history across all branches
    - Filter out suppressed secrets before verification
    - _Requirements: 1.1, 1.5, 16.5_

  - [x] 5.8 Write property test for verified credential blocking
    - **Property 3: Verified credential blocking**
    - **Validates: Requirements 1.4**

  - [x] 5.9 Write property test for git history traversal completeness
    - **Property 4: Git history traversal completeness**
    - **Validates: Requirements 1.5**

- [x] 6. Build Ratatui TUI with worker thread architecture
  - [x] 6.1 Create AppState enum and TUI message types
    - Define AppState variants (Welcome, Scanning, Results, PatchPreview)
    - Define TuiMessage enum for worker-to-UI communication
    - Set up mpsc channels for message passing
    - _Requirements: 4.2, 4.5_

  - [x] 6.2 Write property test for message passing reliability
    - **Property 10: Message passing reliability**
    - **Validates: Requirements 4.5**

  - [x] 6.3 Implement Ratatui event loop and rendering
    - Initialize terminal with crossterm backend
    - Implement immediate-mode rendering loop
    - Handle keyboard input (arrow keys, Enter, Esc, q)
    - Render progress bars, vulnerability lists, and code snippets
    - _Requirements: 4.1, 4.2, 4.4, 4.6_

  - [x] 6.4 Write property test for TUI responsiveness under load
    - **Property 11: TUI responsiveness under load**
    - **Validates: Requirements 4.6**

  - [x] 6.5 Integrate worker threads for background scanning
    - Spawn Rayon worker pool for file parsing and rule matching
    - Send ScanProgress and VulnerabilityFound messages to TUI
    - Ensure UI remains responsive during heavy computation
    - _Requirements: 4.3_

- [x] 7. Implement data-flow reachability analyzer
  - [x] 7.1 Build inter-procedural call graph
    - Parse function definitions and call sites across all files
    - Create FunctionNode structs with call relationships
    - Build bidirectional edges (calls and called_by)
    - _Requirements: 5.1_

  - [x] 7.2 Identify taint sources for framework-specific patterns
    - Define TaintSource patterns for Django (request.GET, request.POST)
    - Define TaintSource patterns for FastAPI (Request parameters)
    - Define TaintSource patterns for React (component props)
    - Use tree-sitter queries to match framework patterns
    - _Requirements: 5.5_

  - [x] 7.3 Write property test for framework pattern recognition
    - **Property 14: Framework pattern recognition**
    - **Validates: Requirements 5.5**

  - [x] 7.4 Implement forward data-flow analysis with worklist algorithm
    - Trace tainted variables from sources through call graph
    - Perform fixed-point iteration until no new taint propagates
    - Determine if vulnerability locations are reachable from taint sources
    - _Requirements: 5.1, 5.2, 5.3_

  - [x] 7.5 Write property test for reachability analysis soundness
    - **Property 12: Reachability analysis soundness**
    - **Validates: Requirements 5.1, 5.2, 5.3**

  - [x] 7.6 Integrate reachability results into vulnerability prioritization
    - Mark vulnerabilities as reachable or unreachable
    - Suppress or deprioritize unreachable vulnerabilities
    - _Requirements: 5.4_

  - [x] 7.7 Write property test for unreachable vulnerability suppression
    - **Property 13: Unreachable vulnerability suppression**
    - **Validates: Requirements 5.4**

- [-] 8. Build Software Composition Analysis (SCA) engine with open-source CVE database
  - [x] 8.1 Define KnownVulnerability data model and SQLite schema
    - Create `KnownVulnerability` struct with `cve_id`, `ghsa_id`, `package_name`, `ecosystem`, `vulnerable_versions`, `patched_version`, `summary`, `severity`, `owasp_category`, `last_synced_at`
    - Create `sca/` module under `engine/`
    - Define SQLite schema with `known_vulnerabilities` table indexed on `(ecosystem, package_name)`
    - Add `rusqlite` and `semver` to `Cargo.toml`
    - _Requirements: 5.1_

  - [x] 8.2 Implement VulnerabilityDatabaseManager core with SQLite cache
    - Implement `VulnerabilityDatabaseManager::new()` — open or create `~/.sicario/vuln_cache.db`, run schema migrations
    - Implement `query_package(ecosystem, package_name, version)` — evaluate installed version against stored semver ranges using the `semver` crate; return matching `KnownVulnerability` entries
    - Implement `last_synced_at()` — read sync timestamp from a `metadata` table
    - Enable SQLite WAL mode for concurrent read access from Rayon scan workers
    - _Requirements: 5.1_

  - [x]* 8.3 Write property test for CVE version range matching
    - **Property 38: CVE version range matching correctness**
    - For any package name, ecosystem, and semver version string, `query_package()` should return a finding if and only if the version falls within a stored vulnerable range, and return empty when the version is patched or unaffected
    - **Validates: Requirements 5.1**

  - [x] 8.4 Implement OSV.dev bulk JSON import
    - Download and decompress `https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip` for npm, PyPI, crates.io, Maven, and Go ecosystems using `reqwest`
    - Parse OSV JSON schema (`id`, `aliases`, `affected[].package`, `affected[].ranges`, `severity`) into `KnownVulnerability` structs
    - Upsert records into SQLite using the OSV `modified` field for delta detection — skip records that have not changed since last sync
    - _Requirements: 5.1_

  - [x] 8.5 Implement GHSA GraphQL import
    - Query the GitHub Advisory Database GraphQL API (`https://api.github.com/graphql`) using the `securityVulnerabilities` query, paginating with cursors
    - Map GHSA fields (`ghsaId`, `advisory.identifiers`, `package.name`, `package.ecosystem`, `vulnerableVersionRange`, `firstPatchedVersion`) to `KnownVulnerability`
    - Upsert into SQLite, cross-referencing existing CVE IDs from OSV records
    - _Requirements: 5.1_

  - [x] 8.6 Implement background sync thread
    - Implement `start_background_sync(interval, tx)` — spawn a `std::thread` that loops: sleep for `interval` (default 24 h), call `sync_now()`, send `DbSyncComplete` or `DbSyncError` over the `mpsc::Sender`
    - Implement `sync_now()` — orchestrate OSV and GHSA imports sequentially, return count of new/updated entries
    - Wire `DbSyncComplete` and `DbSyncError` into the existing `TuiMessage` enum so the TUI can display sync status and stale-cache warnings (>7 days since last sync)
    - _Requirements: 5.1_

  - [x] 8.7 Write property test for background sync non-interference


    - **Property 39: Background sync non-interference**
    - For any concurrent combination of `query_package()` calls and an in-progress `sync_now()`, all queries should return consistent results and never observe a partially-written record
    - **Validates: Requirements 5.1**

  - [x] 8.8 Implement manifest parser for dependency extraction
    - Parse `package.json` (`dependencies`, `devDependencies`) → npm ecosystem
    - Parse `Cargo.toml` (`[dependencies]`, `[dev-dependencies]`) → crates.io ecosystem
    - Parse `requirements.txt` (including version specifiers `==`, `>=`, `~=`) → PyPI ecosystem
    - Return a `Vec<(ecosystem, package_name, resolved_version)>` for each manifest found under the scanned directory
    - _Requirements: 5.1_

  - [x] 8.9 Write property test for manifest parsing round-trip

    - **Property 40: Manifest parsing completeness**
    - For any generated `package.json`, `Cargo.toml`, or `requirements.txt` containing a known set of dependencies, the manifest parser should extract every declared package name and version without omission
    - **Validates: Requirements 5.1**

  - [x] 8.10 Implement SastEngine::scan_manifests() and reachability integration
    - Implement `scan_manifests(dir)` in `SastEngine` — call the manifest parser, then call `VulnerabilityDatabaseManager::query_package()` for each dependency
    - For each CVE hit, use tree-sitter queries to locate call sites in the project that invoke the affected package's API surface
    - Pass those call site `FunctionId`s to `ReachabilityAnalyzer::is_vulnerable_dependency_reachable()` — only surface the finding if the call is reachable from an external taint source
    - Construct a `Vulnerability` struct from the `KnownVulnerability` record (mapping `cve_id` → `rule_id`, `severity`, `owasp_category`) and append to scan results
    - _Requirements: 5.1, 5.2, 5.3, 5.4_

  - [x] 8.11 Write property test for SCA false-positive elimination

    - **Property 41: SCA false-positive elimination**
    - For any project where a vulnerable dependency is declared but none of its affected API functions are invoked, `scan_manifests()` should return zero findings for that CVE
    - **Validates: Requirements 5.4**

- [x] 9. Checkpoint - Ensure reachability analysis and SCA work
  - Ensure all tests pass, ask the user if questions arise.

- [-] 10. Implement AI-powered remediation engine
  - [x] 10.1 Create CerebrasClient for LLM integration
    - Implement async HTTP client using `reqwest`
    - Define FixContext struct with vulnerability details and code context
    - Send requests to Cerebras API with specialized security fix prompt
    - Handle API errors and timeouts gracefully
    - _Requirements: 13.1, 13.2, 13.3_

  - [x] 10.2 Write property test for LLM-generated patch syntax validity

    - **Property 31: LLM-generated patch syntax validity**
    - **Validates: Requirements 13.4**

  - [x] 10.3 Implement BackupManager for safe patch application
    - Create `.sicario/backups/{timestamp}/` directory structure
    - Copy original files to backup location before modification
    - Maintain patch history log with timestamps and file paths
    - Implement automatic cleanup of backups older than 30 days
    - _Requirements: 14.1, 14.2, 14.5_

  - [x] 10.4 Write property test for patch backup creation

    - **Property 32: Patch backup creation**
    - **Validates: Requirements 14.1**

  - [x] 10.5 Build RemediationEngine with patch generation and application
    - Extract vulnerability context using tree-sitter
    - Generate patches using LLM or AST-based templates
    - Validate generated code syntax before presenting to user
    - Apply patches with backup creation
    - Implement `revert_patch()` to restore from backup
    - _Requirements: 9.1, 9.2, 9.4, 13.4, 13.5, 14.3, 14.4_


  - [x] 10.6 Write property test for patch correctness and syntax validity

    - **Property 24: Patch correctness and syntax validity**
    - **Validates: Requirements 9.1, 9.2**


  - [x]* 10.7 Write property test for patch application idempotence
    - **Property 25: Patch application idempotence**
    - **Validates: Requirements 9.4**

  - [x]* 10.8 Write property test for patch revert correctness
    - **Property 33: Patch revert correctness**
    - **Validates: Requirements 14.3**

  - [x] 10.9 Integrate patch preview and application into TUI
    - Display patch diff with syntax highlighting in PatchPreview state
    - Provide single-keystroke prompt to apply or reject patch
    - Show success/error messages after patch application
    - _Requirements: 9.3_

- [-] 11. Implement OAuth 2.0 Device Flow authentication
  - [x] 11.1 Create AuthModule with PKCE support
    - Generate cryptographically random code_verifier
    - Compute code_challenge as base64url(SHA256(code_verifier))
    - Send POST to `/oauth/device/code` with client_id and code_challenge
    - _Requirements: 7.1, 7.2, 7.6_

  - [x] 11.2 Write property test for OAuth Device Flow compliance

    - **Property 19: OAuth Device Flow compliance**
    - **Validates: Requirements 7.1**



  - [x] 11.3 Write property test for PKCE cryptographic binding

    - **Property 20: PKCE cryptographic binding**
    - **Validates: Requirements 7.6**

  - [x] 11.4 Implement token polling and storage
    - Display verification_uri and user_code in TUI
    - Poll `/oauth/token` endpoint asynchronously at specified intervals
    - Store tokens in system keychain using `keyring` crate
    - Implement automatic token refresh
    - _Requirements: 7.3, 7.4, 7.5, 7.7_

  - [x] 11.5 Write property test for token storage security

    - **Property 21: Token storage security**
    - **Validates: Requirements 7.7**

- [x] 12. Build Convex backend client for telemetry and rulesets
  - [x] 12.1 Implement ConvexClient with WebSocket connection
    - Establish WebSocket connection with JWT in Authorization header
    - Handle connection errors and automatic reconnection
    - _Requirements: 8.1_

  - [x] 12.2 Implement telemetry push functionality
    - Create TelemetryEvent structs for detected, dismissed, and fixed vulnerabilities
    - Send telemetry as JSON messages over WebSocket
    - Include all vulnerability attributes (file path, type, severity, timestamp, OWASP category)
    - _Requirements: 8.2, 17.4_

  - [x] 12.3 Write property test for telemetry data integrity

    - **Property 22: Telemetry data integrity**
    - **Validates: Requirements 8.2**

  - [x] 12.4 Implement ruleset subscription and real-time updates
    - Subscribe to Convex query for organizational rulesets
    - Receive and apply ruleset updates via WebSocket
    - Reload rules in SAST engine when updates arrive
    - _Requirements: 8.4_


  - [ ]* 12.5 Write property test for real-time ruleset synchronization
    - **Property 23: Real-time ruleset synchronization**
    - **Validates: Requirements 8.4**

- [x] 13. Implement Model Context Protocol server
  - [x] 13.1 Create McpServer with JSON-RPC 2.0 protocol
    - Listen on localhost TCP port for MCP client connections
    - Parse JSON-RPC requests and route to appropriate handlers
    - Implement `scan_file`, `scan_code`, and `get_rules` methods
    - _Requirements: 6.1, 6.2_

  - [x] 13.2 Write property test for MCP protocol compliance

    - **Property 15: MCP protocol compliance**
    - **Validates: Requirements 6.1**

  - [x] 13.3 Integrate MCP server with SAST engine
    - Execute scans on worker thread pool to avoid blocking
    - Return vulnerability findings in structured JSON format
    - Ensure scan results match direct CLI scans
    - _Requirements: 6.3, 6.4_

  - [x] 13.4 Write property test for MCP scan result accuracy

    - **Property 16: MCP scan result accuracy**
    - **Validates: Requirements 6.3**

  - [x] 13.5 Write property test for MCP non-blocking execution

    - **Property 17: MCP non-blocking execution**
    - **Validates: Requirements 6.4**

  - [x] 13.6 Implement Assistant Memory for triage decision learning
    - Store historical triage decisions in local SQLite database
    - Query Assistant Memory to dismiss previously approved patterns
    - _Requirements: 6.5_


  - [ ]* 13.7 Write property test for Assistant Memory pattern dismissal
    - **Property 18: Assistant Memory pattern dismissal**
    - **Validates: Requirements 6.5**

- [x] 14. Checkpoint - Ensure authentication and integrations work
  - Ensure all tests pass, ask the user if questions arise.

- [x] 15. Implement zero-configuration onboarding
  - [x] 15.1 Create interactive welcome screen with Ratatui
    - Design welcome screen with gradient styling and box borders
    - Display Sicario logo and version information
    - _Requirements: 10.1_

  - [x] 15.2 Implement auto-detection for languages and frameworks
    - Detect languages from file extensions and manifest files
    - Detect package managers (package.json, requirements.txt, go.mod, Cargo.toml)
    - Detect frameworks (Next.js, Django, FastAPI, React) from config files
    - _Requirements: 10.2_

  - [x] 15.3 Write property test for auto-detection accuracy

    - **Property 26: Auto-detection accuracy**
    - **Validates: Requirements 10.2**

  - [x] 15.4 Configure optimal rule subsets based on detected technologies
    - Load language-specific and framework-specific rules
    - Skip irrelevant rules for undetected technologies
    - _Requirements: 10.3_

  - [x] 15.5 Write property test for rule configuration based on detection


    - **Property 27: Rule configuration based on detection**
    - **Validates: Requirements 10.3**

  - [x] 15.6 Implement "Magic Moment" onboarding flow
    - Run initial scan with progress bar
    - Present first actionable fix immediately upon completion
    - Provide single-keystroke prompt to apply first patch
    - Display celebratory success state after patch application
    - _Requirements: 10.4, 10.5_

- [-] 16. Implement cloud-to-code traceability
  - [x] 16.1 Create cloud telemetry integration interfaces
    - Define interfaces for Kubernetes config parsing
    - Define interfaces for CSPM data ingestion
    - _Requirements: 11.1_

  - [x] 16.2 Implement cloud exposure determination
    - Query Kubernetes configs to identify publicly exposed services
    - Query CSPM data for internet-facing resources
    - Match vulnerability file paths to deployed services
    - _Requirements: 11.2_

  - [ ] 16.3 Write property test for cloud exposure determination

    - **Property 28: Cloud exposure determination**
    - **Validates: Requirements 11.2**

  - [x] 16.4 Implement priority assignment based on exposure
    - Assign critical priority to vulnerabilities in publicly exposed services
    - Deprioritize vulnerabilities in internal isolated services
    - _Requirements: 11.3, 11.4_

  - [x] 16.5 Write property test for priority assignment by exposure

    - **Property 29: Priority assignment by exposure**
    - **Validates: Requirements 11.3, 11.4**

  - [x] 16.6 Display cloud context metadata in TUI
    - Show exposure status alongside vulnerability findings
    - Add cloud context to vulnerability detail view
    - _Requirements: 11.5_

- [-] 17. Bujild OWASP compliance reporting
  - [x] 17.1 Implement OWASP category grouping in TUI
    - Group vulnerabilities by OWASP Top 10 category in results view
    - Display category counts and severity distribution
    - _Requirements: 17.3_

  - [x] 17.2 Write property test for OWASP category mapping consistency

    - **Property 36: OWASP category mapping consistency**
    - **Validates: Requirements 17.1, 17.2**

  - [x] 17.3 Generate compliance reports
    - Create compliance report showing coverage across all OWASP Top 10 categories
    - Export reports in JSON and Markdown formats
    - _Requirements: 17.5_

  - [x] 17.4 Write property test for OWASP compliance report completeness

    - **Property 37: OWASP compliance report completeness**
    - **Validates: Requirements 17.3, 17.4, 17.5**

- [-] 18. Cross-platform binary compilation and distribution
  - [x] 18.1 Configure cross-compilation for Linux, macOS, and Windows
    - Set up GitHub Actions CI/CD pipeline
    - Configure Rust cross-compilation targets
    - Build statically linked binaries for each platform
    - _Requirements: 12.1_

  - [x] 18.2 Write property test for binary portability and independence

    - **Property 30: Binary portability and independence**
    - **Validates: Requirements 12.4**

  - [x] 18.3 Create Homebrew formula and shell installer
    - Write Homebrew formula for macOS and Linux distribution
    - Create shell script installer that detects platform and downloads binary
    - Test installation on all target platforms
    - _Requirements: 12.2, 12.3_

  - [x] 18.4 Verify global PATH availability
    - Test that installed binary is available globally
    - Verify binary footprint is under 50MB
    - _Requirements: 12.4, 12.5_

- [x] 19. Final checkpoint - End-to-end integration testing
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- All property-based tests are required for comprehensive correctness validation
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties using the `proptest` crate with minimum 100 iterations
- Unit tests validate specific examples and edge cases
- The implementation follows a bottom-up approach: core infrastructure → scanning → UI → advanced features → integrations
