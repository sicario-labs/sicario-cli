# Implementation Plan: PR Scan Workflow

## Overview

Implement the end-to-end PR scan workflow: a TypeScript SAST engine that runs inside Convex Node.js actions, triggered by the existing webhook handler. The implementation converts YAML SAST rules to TypeScript regex patterns, scans changed PR files, stores findings, updates prChecks records, and posts GitHub Check Runs.

## Tasks

- [x] 1. Create the SAST engine pure-function module (`prSastEngine.ts`)
  - [x] 1.1 Create `convex/convex/prSastEngine.ts` with core types and interfaces
    - Define `SastRule`, `ScanFinding`, `ScanReport`, `FileToScan` interfaces
    - Implement `detectLanguage(filePath: string): string | null` mapping file extensions to language names (`.js`→JavaScript, `.ts`→TypeScript, `.py`→Python, `.java`→Java, `.go`→Go, `.rs`→Rust, etc.)
    - Implement `computeFingerprint(ruleId, filePath, snippet): string` using a SHA-256 hash of the concatenated inputs
    - Implement `evaluateThreshold(findings, threshold): { passed, criticalCount, highCount, totalCount }` with severity hierarchy Critical > High > Medium > Low > Info
    - Implement `scanFiles(files, rules, metadata): ScanReport` that iterates files, filters rules by language, runs regex patterns line-by-line, and collects findings with correct file paths, line numbers, columns, and snippets
    - _Requirements: 3.1, 3.2, 3.3, 4.4, 5.1, 5.2, 5.3_

  - [x] 1.2 Write property test: Finding file paths reference input file paths
    - **Property 1: Finding file paths reference input file paths**
    - **Validates: Requirements 3.2**

  - [x] 1.3 Write property test: Scan report contains all required metadata
    - **Property 2: Scan report contains all required metadata**
    - **Validates: Requirements 3.3**

  - [x] 1.4 Write property test: Fingerprint determinism
    - **Property 3: Fingerprint determinism**
    - **Validates: Requirements 4.4**

  - [x] 1.5 Write property test: Threshold evaluation correctness
    - **Property 4: Threshold evaluation correctness**
    - **Validates: Requirements 5.1, 5.2**

  - [x] 1.6 Write property test: Finding severity counts are accurate
    - **Property 5: Finding severity counts are accurate**
    - **Validates: Requirements 5.3**

  - [x] 1.7 Write unit tests for `detectLanguage` and `scanFiles` against known vulnerable snippets
    - Test language detection for all supported extensions
    - Test rule matching against known vulnerable code from YAML test cases (SQL injection concat, XSS innerHTML, etc.)
    - Test that non-matching code produces zero findings
    - _Requirements: 3.1, 3.2_

- [x] 2. Checkpoint - Ensure SAST engine tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Create the embedded SAST rules module (`prSastRules.ts`)
  - [x] 3.1 Create `convex/convex/prSastRules.ts` with TypeScript regex rules converted from YAML
    - Convert the tree-sitter query patterns from `sicario-cli/rules/javascript/` (sql_injection, xss, nosql_redos, express_crypto_prototype, ssrf_path_traversal_deserialization, redirect_typescript, nextjs_auth) to equivalent TypeScript `RegExp` patterns
    - Convert rules from `sicario-cli/rules/python/` (sql_injection, command_injection, deserialization, path_traversal, ssrf_redirect, flask_ssti, django_misconfig, django_orm_injection, crypto, xxe, ldap_injection, logging_sensitive, mass_assignment, fastapi)
    - Convert rules from `sicario-cli/rules/java/` (sql_injection, command_injection, xss, deserialization, path_traversal, ssrf, crypto, xxe, ldap_injection, logging_sensitive, spring_boot)
    - Convert rules from `sicario-cli/rules/go/` (sql_cmd_path_ssrf, crypto, error_handling, race_conditions, tls_config, xxe, info_leakage, framework_gin_echo_fiber)
    - Convert rules from `sicario-cli/rules/rust/` (sql_cmd_path, crypto_deser_memory_concurrency, framework_info_leakage)
    - Export as `PR_SAST_RULES: SastRule[]` array with id, name, description, severity, languages, pattern (RegExp), cweId, and owaspCategory for each rule
    - _Requirements: 3.1, 3.2_

  - [x] 3.2 Write unit tests validating rule matching against YAML test cases
    - For each language category, test at least 3 rules against their TruePositive and TrueNegative test cases from the YAML files
    - _Requirements: 3.1, 3.2_

- [x] 4. Create the scan orchestrator action (`prScanWorkflow.ts`)
  - [x] 4.1 Create `convex/convex/prScanWorkflow.ts` as a `"use node"` Convex action
    - Implement `runPrScan` action with args: `checkId`, `repositoryUrl`, `prNumber`, `projectId`, `orgId`, `installationId`
    - Step 1: Update prCheck status to "running" via `ctx.runMutation(api.prChecks.updatePrCheck, ...)`
    - Step 2: Acquire installation token using `generateAppJwt` and `getInstallationToken` from `githubApp.ts`
    - Step 3: Create GitHub Check Run (POST `/repos/{owner}/{repo}/check-runs`) with status "in_progress" and name "Sicario Security Scan"
    - Step 4: Fetch changed files from GitHub PR Files API (`GET /repos/{owner}/{repo}/pulls/{pr}/files`), filter to "added"/"modified" status, cap at 300 files
    - Step 5: Download raw file contents for each changed file, skip files that fail to download
    - Step 6: Run `scanFiles()` from `prSastEngine.ts` with `PR_SAST_RULES` from `prSastRules.ts`
    - Step 7: Store scan results via `ctx.runMutation(api.scans.insert, ...)` with `orgId`, `projectId`, and `["pr-scan"]` tag
    - Step 8: Fetch project's `severityThreshold` (default "high") and run `evaluateThreshold()`
    - Step 9: Update prCheck record with status ("passed"/"failed"), findingsCount, criticalCount, highCount, and githubCheckRunId
    - Step 10: Update GitHub Check Run (PATCH) with conclusion ("success"/"failure"), summary text, and up to 50 annotations
    - Implement helper `buildCheckRunSummary(totalCount, criticalCount, highCount, threshold): string`
    - Implement helper `buildAnnotations(findings, maxCount=50): annotation[]` mapping severity to annotation_level
    - Wrap entire workflow in a timeout guard (120 seconds)
    - Handle errors: set prCheck to "failed" on GitHub API failures, skip individual file download failures, log and continue on Check Run API failures
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.3, 3.4, 4.1, 4.2, 4.3, 4.4, 5.1, 5.2, 5.3, 5.4, 6.1, 6.2, 6.3, 6.4, 6.5, 7.1, 7.2, 7.3, 8.2_

  - [x] 4.2 Write property test: Check Run summary contains required information
    - **Property 6: Check Run summary contains required information**
    - **Validates: Requirements 6.3**

  - [x] 4.3 Write property test: Annotations are capped and well-formed
    - **Property 7: Annotations are capped and well-formed**
    - **Validates: Requirements 6.4**

  - [x] 4.4 Write unit tests for orchestrator error handling paths
    - Test that missing installation ID sets prCheck to "failed"
    - Test that GitHub API failure sets prCheck to "failed"
    - Test that scan engine failure sets prCheck to "failed"
    - Test timeout handling sets prCheck to "failed"
    - _Requirements: 1.3, 2.4, 3.4, 7.1, 7.2_

- [x] 5. Checkpoint - Ensure orchestrator tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Wire webhook handler to schedule the scan action
  - [x] 6.1 Modify `convex/convex/http.ts` to schedule `runPrScan` from the webhook handler
    - In the `action === "opened" || action === "synchronize"` branch, after `createPrCheck`, replace the `// TODO: trigger actual scan workflow on the PR diff` comment
    - Read `installationId` from `matchedProject.github_app_installation_id`
    - If no `installationId`, update prCheck status to "failed" and skip scheduling
    - Otherwise call `ctx.scheduler.runAfter(0, api.prScanWorkflow.runPrScan, { checkId, repositoryUrl: repoUrl, prNumber, projectId, orgId, installationId })`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 8.1, 8.3_

- [x] 7. Sync shared files to `sicario-frontend/convex/`
  - [x] 7.1 Copy the new files to `sicario-frontend/convex/`
    - Copy `prSastEngine.ts`, `prSastRules.ts`, and `prScanWorkflow.ts` to `sicario-frontend/convex/`
    - Copy the updated `http.ts` to `sicario-frontend/convex/`
    - Ensure both directories stay in sync
    - _Requirements: 1.1, 1.2_

- [x] 8. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document using `fast-check`
- Unit tests validate specific examples and edge cases using `vitest`
- All test files go in `convex/convex/__tests__/`
- The SAST engine (`prSastEngine.ts`) is pure functions with no external dependencies, making it straightforward to test
- The orchestrator (`prScanWorkflow.ts`) requires mocking for GitHub API calls and Convex mutations in tests
