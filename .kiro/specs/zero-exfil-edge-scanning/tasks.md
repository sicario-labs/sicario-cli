# Implementation Plan: Zero-Exfiltration Edge Scanning

## Overview

This plan migrates Sicario from a cloud-side code-fetching model to a zero-exfiltration edge scanning architecture. Deletions come first to establish a clean slate, followed by backend telemetry ingestion, CLI enhancements (snippet extraction, auth chain, telemetry client, exit code gating), property-based tests, and optional frontend updates. All CLI work is in Rust; all backend work is in TypeScript (Convex).

## Tasks

- [x] 1. Delete cloud-side PR scan and GitHub App modules
  - [x] 1.1 Delete PR scan workflow and SAST engine files
    - Delete `convex/convex/prScanWorkflow.ts`, `convex/convex/prSastEngine.ts`, `convex/convex/prSastRules.ts`
    - Delete `convex/convex/githubApp.ts`, `convex/convex/githubAppNode.ts`
    - _Requirements: 2.1, 2.2, 2.3, 3.1, 3.2_
  - [x] 1.2 Delete PR scan test files
    - Delete all six PR scan test files from `convex/convex/__tests__/`: `pr-scan-workflow.test.ts`, `pr-scan-engine.test.ts`, `pr-scan-rules.test.ts`, `pr-scan-annotations.test.ts`, `pr-scan-fingerprint.test.ts`, `pr-scan-threshold.test.ts`
    - _Requirements: 2.4_
  - [x] 1.3 Remove GitHub webhook route and inlined utils from http.ts
    - Remove `POST /api/v1/github/webhook` route and its `OPTIONS` preflight
    - Remove `GET /api/v1/github/repos` route and its `OPTIONS` preflight
    - Remove `validateWebhookSignature()` helper function
    - Remove all inlined GitHub App utility functions: `ghBase64UrlEncode`, `ghBase64UrlEncodeString`, `requireGitHubAppEnv`, `generateAppJwt`, `getInstallationToken`, `listInstallationRepos`, `GH_REQUIRED_ENV_VARS`, `GH_API_HEADERS`
    - _Requirements: 1.1, 1.2, 1.3, 3.3, 3.4, 10.1_
  - [x] 1.4 Remove `githubAppInstallationId` from projects schema and mutations
    - Remove `githubAppInstallationId: v.optional(v.string())` from the `projects` table in `convex/convex/schema.ts`
    - Update `createV2` mutation in `convex/convex/projects.ts` to no longer accept or store `githubAppInstallationId`
    - Update `mapProject` helper in `convex/convex/projects.ts` to no longer map `github_app_installation_id`
    - _Requirements: 5.1, 5.2, 5.3_
  - [x] 1.5 Remove `githubCheckRunId` from prChecks schema and mutations
    - Remove `githubCheckRunId: v.optional(v.string())` from the `prChecks` table in `convex/convex/schema.ts`
    - Update `updatePrCheck` mutation in `convex/convex/prChecks.ts` to no longer accept or store `githubCheckRunId`
    - Remove `github_check_run_id` from `mapPrCheck` helper in `convex/convex/prChecks.ts`
    - _Requirements: 4.1, 4.2, 4.3_

- [x] 2. Checkpoint — Verify deletions compile cleanly
  - Ensure the Convex backend has no TypeScript compilation errors after all deletions
  - Verify no remaining references to deleted files, `githubAppInstallationId`, `githubCheckRunId`, or GitHub App env vars across Convex source files
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Build telemetry ingestion endpoint (Convex backend)
  - [x] 3.1 Add `POST /api/v1/telemetry/scan` route and OPTIONS preflight to http.ts
    - Register the new route in the HTTP router with CORS preflight
    - Implement authentication via existing `resolveIdentity(ctx, request)` — return 401 if null
    - Parse JSON body from request
    - _Requirements: 6.1, 6.2, 6.3_
  - [x] 3.2 Implement payload validation logic
    - Validate required fields: `projectId`, `repositoryUrl`, `commitSha`, `scanId`, `findings` — return 400 with descriptive error if missing
    - Validate severity enum on each finding (must be `"Critical"`, `"High"`, `"Medium"`, or `"Low"`) — return 400 if invalid
    - Validate findings count ≤ 5000 — return 400 if exceeded
    - Check for duplicate `scanId` in `scans` table — return 409 if exists
    - Truncate each finding's `snippet` to 100 characters
    - _Requirements: 6.4, 6.5, 7.1, 7.2, 7.3, 7.4_
  - [x] 3.3 Implement org resolution, project matching, and data insertion
    - Resolve org from identity (project API key auto-resolves; JWT/sic_ token uses membership lookup or `X-Sicario-Org` header)
    - Match `projectId` to existing project in resolved org — return 404 if not found
    - Insert `scans` record with metadata (repository URL, commit SHA, scan ID, timestamp, optional duration/rules/files)
    - Insert one `findings` record per finding entry, mapping `rule` → `ruleId`/`ruleName`, `severity`, `file` → `filePath`, `line`, `snippet`
    - If `prNumber` is present, create or update a `prChecks` record with findings count, critical/high counts, pass/fail status
    - Transition project from "pending" to "active" on first scan
    - Return 200 with `{ scan_id, project_id, dashboard_url }`
    - _Requirements: 6.6, 6.7, 6.8, 6.9, 6.10, 6.11, 6.12_

- [x] 4. Checkpoint — Verify telemetry endpoint compiles and basic tests pass
  - Ensure the Convex backend compiles with the new telemetry endpoint
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. CLI snippet extraction module (Rust)
  - [x] 5.1 Create `sicario-cli/src/snippet/` module with `extractor.rs`
    - Implement `SnippetConfig` struct with `context_lines` (default: 3, min: 0, max: 10) and `max_line_length` (default: 100)
    - Implement `SnippetExtractor::extract(content, target_line, config)` that extracts context window lines and truncates each to `max_line_length`
    - Handle edge cases: target_line = 0, target_line > total lines (return empty string + log warning), empty file, context_lines = 0
    - Register `mod snippet` in `sicario-cli/src/main.rs`
    - _Requirements: 15.1, 15.2, 15.4, 15.6_
  - [x] 5.2 Write property test for snippet line truncation (Property 2)
    - **Property 2: Snippet Line Truncation Invariant**
    - Create `sicario-cli/src/snippet/snippet_property_tests.rs`
    - Generate random file contents with lines of 0–500 chars, random target lines; verify all output lines ≤ `max_line_length` (100) chars
    - **Validates: Requirements 15.2, 7.1**
  - [x] 5.3 Write property test for zero-exfiltration snippet window correctness (Property 5)
    - **Property 5: Zero-Exfiltration Snippet Window Correctness**
    - Generate files with unique line markers (e.g., `LINE_N`), random target lines and context sizes (0–10); verify no out-of-window markers appear in snippet
    - **Validates: Requirements 15.1, 15.5**

- [x] 6. CLI auth priority chain update (Rust)
  - [x] 6.1 Update `AuthModule::resolve_auth_token()` in `sicario-cli/src/auth/auth_module.rs`
    - Implement the 5-level priority chain: (1) `SICARIO_API_KEY` env var → `"Bearer project:{key}"`, (2) cloud OAuth token from keychain → `"Bearer {token}"`, (3) `SICARIO_PROJECT_API_KEY` env var → `"Bearer project:{key}"`, (4) project API key from keychain → `"Bearer project:{key}"`, (5) `api_key` field from `.sicario/config.yaml` → `"Bearer project:{key}"`
    - If none available, exit with error: `"Run 'sicario login' or set SICARIO_API_KEY"`
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.6_
  - [x] 6.2 Write property test for auth priority chain (Property 4)
    - **Property 4: Auth Priority Chain Resolution**
    - Create or update `sicario-cli/src/auth/auth_property_tests.rs`
    - Generate random boolean vectors for credential availability states; verify highest-priority credential is always selected and formatted correctly
    - **Validates: Requirements 14.1, 14.2, 14.6**

- [x] 7. CLI telemetry client module (Rust)
  - [x] 7.1 Create `sicario-cli/src/publish/telemetry_client.rs`
    - Define `TelemetryPayload`, `TelemetryFinding`, and `TelemetryResponse` structs with serde `Serialize`/`Deserialize` derives and camelCase field renaming
    - Implement `TelemetryClient::new(base_url, auth_token)` and `TelemetryClient::submit(payload)` that POSTs to `/api/v1/telemetry/scan`
    - On HTTP 200: return `Ok(TelemetryResponse)`
    - On HTTP 401: log descriptive error about invalid/expired API key
    - On other HTTP errors or network failures: log warning, return error (caller handles gracefully)
    - Register the module in `sicario-cli/src/publish/mod.rs`
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 14.5_
  - [x] 7.2 Write property test for telemetry payload serialization round-trip (Property 1)
    - **Property 1: Telemetry Payload Serialization Round-Trip**
    - Create `sicario-cli/src/publish/telemetry_property_tests.rs`
    - Generate random `TelemetryPayload` with valid severities, random strings, random finding counts (0–100), snippets ≤ 100 chars; verify serialize → deserialize produces equal object
    - **Validates: Requirements 9.1, 9.2, 9.3, 9.4**
  - [x] 7.3 Write property test for severity enum validation (Property 3)
    - **Property 3: Severity Enum Validation**
    - Generate arbitrary strings; verify acceptance iff string ∈ {"Critical", "High", "Medium", "Low"}
    - **Validates: Requirements 7.2**
  - [x] 7.4 Write property test for required field validation (Property 7)
    - **Property 7: Telemetry Payload Required Field Validation**
    - Generate random JSON objects with subsets of required fields removed; verify rejection iff any required field is missing
    - **Validates: Requirements 6.4, 6.5**

- [x] 8. CLI `--fail-on` exit code gating and `--snippet-context` flag (Rust)
  - [x] 8.1 Add `--fail-on` flag and `SICARIO_FAIL_ON` env var to `ScanArgs`
    - Add `--fail-on` flag to `ScanArgs` in `sicario-cli/src/cli/scan.rs` accepting `"Critical"`, `"High"`, `"Medium"`, `"Low"` (default: `"High"`)
    - Add `SICARIO_FAIL_ON` env var support; `--fail-on` flag takes precedence
    - Invalid values → exit code 2 (`InternalError`) with descriptive error listing valid values
    - In GitHub Actions (`GITHUB_ACTIONS` env var present), emit a summary annotation to stdout
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6_
  - [x] 8.2 Add `--snippet-context` flag and `SICARIO_SNIPPET_CONTEXT` env var to `ScanArgs`
    - Add `--snippet-context <N>` flag (default: 3, min: 0, max: 10)
    - Add `SICARIO_SNIPPET_CONTEXT` env var support
    - Invalid values → exit code 2 with descriptive error
    - _Requirements: 15.3_
  - [x] 8.3 Write property test for exit code threshold correctness (Property 6)
    - **Property 6: Exit Code Threshold Correctness**
    - Create `sicario-cli/src/cli/exit_code_property_tests.rs`
    - Generate random finding lists with random severities/suppression states, random thresholds; verify exit code is 1 iff at least one non-suppressed finding has severity ≥ threshold
    - **Validates: Requirements 16.1, 16.2, 16.7**

- [x] 9. Wire telemetry submission into `cmd_scan()` (Rust)
  - [x] 9.1 Integrate snippet extraction into scan findings
    - In `cmd_scan()` in `sicario-cli/src/main.rs`, after scanning, use `SnippetExtractor` to extract and truncate snippets for each finding using the `--snippet-context` value
    - _Requirements: 15.1, 15.2, 15.4_
  - [x] 9.2 Integrate telemetry submission into `cmd_scan()`
    - After scan completes and `--publish` is set, resolve auth token via `AuthModule::resolve_auth_token()`
    - Build `TelemetryPayload` from scan results (project ID, repo URL, commit SHA, generated scan ID, branch, optional PR number, duration, rules loaded, files scanned, findings array)
    - Submit via `TelemetryClient::submit()` — log success with dashboard URL on 200, log warning on errors, never fail the scan
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_
  - [x] 9.3 Wire `--fail-on` into exit code computation
    - Parse `--fail-on` value (or `SICARIO_FAIL_ON` env var) into a `Severity` threshold
    - Pass to `ExitCode::from_findings()` as the severity threshold for exit code determination
    - If in GitHub Actions, emit summary annotation with findings count and pass/fail status
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.6_

- [x] 10. Checkpoint — Full CLI and backend integration verification
  - Ensure the Rust CLI compiles with all new modules (`snippet`, `telemetry_client`, updated auth, new flags)
  - Ensure the Convex backend compiles with the telemetry endpoint and schema changes
  - Ensure all tests pass, ask the user if questions arise.

- [x] 11. Frontend dashboard updates for zero-exfiltration model
  - [x] 11.1 Redesign onboarding flow for CLI-first model
    - In `sicario-frontend/src/pages/dashboard/OnboardingV2Page.tsx`, remove the GitHub App installation step ("Install GitHub App" button and `handleGitHubAppInstall` redirect)
    - Remove GitHub App callback handling (parsing `installation_id` from URL params, fetching repos via `GET /api/v1/github/repos`)
    - Replace repository selection step with a manual project creation form (project name + optional repo URL)
    - Call `projects.create` mutation instead of `projects.createV2` since `githubAppInstallationId` is no longer required
    - Retain the "Waiting Room" screen with CLI install instructions, project API key, and `sicario scan . --publish` command
    - Update introductory copy to reflect zero-exfiltration model ("Your code never leaves your machine")
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_
  - [x] 11.2 Update PR Checks panel messaging
    - Update `PrChecksPanel` empty state description from GitHub App messaging to CLI CI pipeline messaging ("Add Sicario to your CI pipeline to automatically scan pull requests")
    - Remove or hide `github_check_run_id` from `PrCheckDetailPage` detail view
    - _Requirements: 12.1, 12.2, 12.3_
  - [x] 11.3 Remove GitHub App references from project detail
    - Ensure `ProjectDetailPage` no longer displays `github_app_installation_id`
    - Remove any frontend code calling `GET /api/v1/github/repos`
    - Update `action.yml` if it references the GitHub App webhook flow to reflect CLI-only scanning
    - _Requirements: 13.1, 13.2, 13.3_

- [ ] 12. Final checkpoint — Full system verification
  - Ensure all Convex backend tests pass
  - Ensure all Rust CLI tests pass (including property-based tests if implemented)
  - Verify no remaining references to deleted GitHub App files, env vars, or schema fields
  - Ensure all tests pass, ask the user if questions arise.

---

# EPIC: Zero-Exfiltration Edge Engine & Deterministic Remediation

## Context & Architectural Pivot

Sicario is enforcing a strict "Zero-Exfiltration" and "Zero-Liability" boundary:
1. **Zero-Exfiltration:** The cloud backend must never fetch or store raw source code. All AST parsing happens locally.
2. **Zero-Liability (BYOK):** The cloud backend must never store third-party LLM API keys. All LLM authentication happens locally on the edge.
3. **Architectural Guardrails:** The Rust CLI will act as a local Model Context Protocol (MCP) server for safe AI auto-remediation, strictly preventing AI agents from executing destructive generic shell commands.
4. **Auditability:** The CLI will bundle its deterministic reasoning into the telemetry payload to prove its math in the cloud dashboard.

## Phase 1: Rust CLI Upgrades (The Edge Engine)

- [x] 13. Edge BYOK Configuration
  - [x] 13.1 Implement environment variable priority for LLM keys
    - Default to reading system environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) for seamless CI/CD integration
    - Implement fallback chain: env vars → local config file
    - _Validates: Zero-Liability boundary_
  - [x] 13.2 Implement `sicario config set <KEY> <VALUE>` command
    - Write to a local, user-permission-restricted file (`~/.sicario/config.toml`)
    - Ensure file permissions are restricted to user-only (0600 on Unix)
    - _Validates: Zero-Liability boundary_
  - [x] 13.3 Ensure `SICARIO_API_KEY` is used strictly for telemetry endpoint auth
    - Verify the CLI uses `SICARIO_API_KEY` only for HTTP POST requests to the Convex telemetry endpoint
    - Document the separation between telemetry auth and LLM auth
    - _Validates: Zero-Exfiltration boundary_

- [x] 14. Embedded MCP Server (Architectural Guardrails)
  - [x] 14.1 Implement MCP server foundation in CLI
    - The CLI already has an MCP server module at `sicario-cli/src/mcp/` with JSON-RPC handling and a `sicario mcp` subcommand
    - Extend the existing module rather than creating from scratch
    - Review `sicario-cli/src/mcp/server.rs` and `sicario-cli/src/mcp/protocol.rs` for current state
    - _Validates: Architectural Guardrails_
  - [x] 14.2 Implement type-safe MCP tools
    - The existing MCP server has different tools (`scan_file`, `scan_code`, `get_rules`) — extend it with:
    - `get_ast_node(file_path, line_number)`: Returns only localized AST context
    - `analyze_reachability(source_node, sink_node)`: Traces inter-procedural data flow
    - `propose_safe_mutation(node_id, patched_syntax)`: Queues an AST-level code patch for developer review
    - Keep existing tools; add new ones alongside them
    - _Validates: Architectural Guardrails_
  - [x] 14.3 Enforce security rule: No generic shell execution
    - Explicitly block any MCP tool that could execute arbitrary shell commands
    - Add validation layer to reject dangerous tool proposals
    - Write property test: No MCP tool can execute shell commands
    - _Validates: Architectural Guardrails_

- [x] 15. Infinite Loop Prevention (The Runaway Cap)
  - [x] 15.1 Implement `--max-iterations` flag for `sicario fix`
    - Default to 3 iterations
    - Allow user override via flag or `SICARIO_MAX_ITERATIONS` env var
    - _Validates: Runaway prevention_
  - [x] 15.2 Implement graceful degradation on iteration limit
    - If LLM fails to produce valid AST mutation within limit, log failure to `.sicario/trace.log`
    - Execute `exit 1` to block CI pipeline
    - Include diagnostic information in log (which iterations failed, why)
    - _Validates: Runaway prevention_

- [x] 16. Execution Audit Trail Logging
  - [x] 16.1 Implement execution trace capture during analysis
    - Capture steps internally (e.g., `["0.01s: Parsed CST for db.js", "0.04s: Traced untrusted input to Line 8", "0.06s: Flagged CWE-89"]`)
    - Store in memory during scan execution
    - _Validates: Auditability_
  - [x] 16.2 Attach `executionTrace` array to telemetry payload
    - Add `executionTrace: Vec<String>` to `TelemetryFinding` struct
    - Include in JSON payload sent to `POST /api/v1/telemetry/scan`
    - _Validates: Auditability_

## Phase 2: Convex Backend Upgrades (The Cloud Memory)

- [ ] 17. Deprecate Cloud BYOK & Webhooks
  - [x] 17.1 Schema cleanup for LLM key storage
    - COMPLETED: `providerSettings` table, `convex/convex/providerSettings.ts`, all `/api/v1/provider-settings` HTTP routes, and the "Provider" tab in SettingsPage have been deleted
    - The `providerSettings` table has been removed from `convex/convex/schema.ts`
    - Zero-Liability boundary is now enforced: no LLM keys stored in cloud
    - _Validates: Zero-Liability boundary_
  - [x] 17.2 Verify GitHub webhook removal
    - Confirmed `api/v1/github/webhook` endpoint is deleted (completed in Task 1)
    - No remaining webhook-related code for GitHub App
    - _Validates: Zero-Exfiltration boundary_
  - [x] 17.3 Verify telemetry endpoint auth
    - Ensure `POST /api/v1/telemetry/scan` validates `SICARIO_API_KEY` (project API key) for authorization
    - Note: `resolveIdentity()` intentionally supports multiple auth methods (project API key, OAuth JWT, device token) — this is correct behavior for CLI + dashboard compatibility
    - Do NOT remove OAuth/JWT paths; they are needed for dashboard users
    - Only verify that project API key auth works correctly for CLI telemetry
    - _Validates: Zero-Exfiltration boundary_

- [x] 18. Enforce Snippet Truncation (Server-Side Exfiltration Block)
  - [ ] 18.1 Update telemetry ingestion to enforce 500-char snippet limit
    - Update `POST /api/v1/telemetry/scan` ingestion logic
    - If `snippet.length > 500` characters, forcefully truncate to 500
    - Log a warning when truncation occurs
    - Note: The CLI already truncates to 100 chars (Task 3.2). The server-side 500-char limit is a defense-in-depth backstop for direct API calls. Both limits are intentional and correct — do not unify them.
    - _Validates: Zero-Exfiltration boundary_
  - [ ] 18.2 Write property test for server-side snippet truncation
    - Generate payloads with snippets of various lengths
    - Verify all stored snippets are ≤ 500 characters
    - _Validates: Zero-Exfiltration boundary_

- [x] 19. Schema Updates for Audit Trail
  - [x] 19.1 Add `executionTrace` field to findings schema
    - Modify `convex/schema.ts` to include `executionTrace: v.optional(v.array(v.string()))` in the `findings` table
    - _Validates: Auditability_
  - [x] 19.2 Update ingestion mutation for executionTrace
    - Update the telemetry ingestion mutation to correctly map and insert incoming `executionTrace` arrays
    - _Validates: Auditability_

## Phase 3: Dashboard Frontend Upgrades (The Command Center)

- [x] 20. Remove Supply-Chain Risks (Read-Only Enforcement)
  - [x] 20.1 Remove OAuth/GitHub App install UI
    - Completely remove any UI components related to GitHub OAuth, GitHub App installation, or repository connection
    - Verify removal in OnboardingV2Page, Settings pages, and Project pages
    - _Validates: Zero-Exfiltration boundary_
  - [x] 20.2 Update onboarding for CLI-first model
    - Project creation should exclusively generate a `SICARIO_API_KEY`
    - Display CLI installation instructions: `npm install -g sicario-cli && sicario login --token=<KEY>`
    - _Validates: Zero-Exfiltration boundary_
  - [x] 20.3 Clean Settings UI
    - COMPLETED: "Provider" tab (LLM Provider Settings) removed from SettingsPage
    - `providerSettings.ts` Convex module deleted
    - `providerSettings` table removed from schema
    - All `/api/v1/provider-settings` HTTP routes removed from http.ts
    - _Validates: Zero-Liability boundary_
  - [x] 20.4 Remove cloud fix buttons
    - Remove any UI buttons that suggest the dashboard can push code or create PRs directly
    - Replace with read-only text blocks instructing: `sicario fix --id=<VULN_ID>`
    - _Validates: Zero-Exfiltration boundary_

- [x] 21. Display the Audit Trail
  - [x] 21.1 Implement Execution Audit Trail UI component
    - Navigate to expanded view for individual Findings
    - Underneath the Snippet display, implement a terminal-style UI block titled "Execution Audit Trail"
    - Use a premium, luxury-minimalist design with monospace font
    - _Validates: Auditability_
  - [x] 21.2 Map executionTrace array to UI
    - Display chronological steps the Rust CLI took to find the vulnerability
    - Include timestamps and action descriptions
    - Prove deterministic execution visually
    - _Validates: Auditability_

- [ ] 22. Final checkpoint — Epic completion verification
  - Ensure all Rust CLI tests pass (including new MCP and audit trail tests)
  - Ensure all Convex backend tests pass (including schema migration tests)
  - Ensure all frontend tests pass
  - Verify zero references to cloud-side LLM key storage
  - Verify snippet truncation is enforced at both CLI (100 chars) and backend (500 chars)
  - Verify executionTrace is correctly stored and displayed

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation after each major workstream
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- Frontend tasks (task 11) are required to ensure the dashboard reflects the zero-exfiltration architecture

---

# ADDENDUM: Edge Cases & Premium DX

## Phase A: Rust CLI Upgrades

- [x] 23. Terminal Trust Prompt (Consent Guardrail)
  - [x] 23.1 Add git-style diff display and `[Y/n]` consent prompt to `propose_safe_mutation`
    - Note: `display_diff_and_confirm()` already exists in `sicario-cli/src/remediation/remediation_engine.rs` — extend it rather than creating from scratch
    - Before writing any file, print a clean git-style diff of the proposed AST mutation to the terminal
    - Prompt the developer: `Apply this patch? [Y/n]` and block until explicit input is received
    - Only write the file if the user confirms with `Y` or `y`; abort silently on `n`, `N`, or empty input
    - Never silently overwrite files under any code path

- [x] 24. Project ID Routing (`sicario link`)
  - [x] 24.1 Implement `sicario link --project=<PROJECT_ID>` command
    - Add `link` subcommand to the CLI that accepts `--project <PROJECT_ID>`
    - Write the `project_id` value to `~/.sicario/config.toml` under key `project_id`
    - Print confirmation: `Linked to project <PROJECT_ID>. Telemetry will be routed to this project.`
  - [x] 24.2 Read `project_id` from config and attach to telemetry payload
    - When building `TelemetryPayload` in `cmd_scan()`, read `project_id` from `~/.sicario/config.toml` if not already set via flag or env var
    - Attach it as the `projectId` field in the JSON payload sent to `POST /api/v1/telemetry/scan`

## Phase B: Convex Backend Upgrades

- [x] 25. Execution Trace Bloat Prevention
  - [x] 25.1 Enforce `executionTrace` array cap in telemetry ingestion
    - In `POST /api/v1/telemetry/scan`, after receiving a finding's `executionTrace` array, truncate it to a maximum of 20 items
    - For each string in the array that exceeds 250 characters, truncate it to 250 chars and append `"...trace truncated"`
    - Apply this truncation before inserting into the `findings` table

## Phase C: Dashboard Frontend Upgrades

- [x] 26. Premium Auto-Fix Handoff UI
  - [x] 26.1 Replace cloud fix buttons with copyable `sicario fix` command block
    - Where cloud fix buttons previously existed (finding detail views, vulnerability cards), display a read-only terminal block showing: `sicario fix --id=<VULN_ID>`
    - Wrap in a premium, luxury-minimalist terminal-style UI block with a one-click "Copy to Clipboard" button
    - Style: dark background (`#0d0d0d`), monospace font, accent-colored command text, subtle border

- [-] 27. Onboarding UX & Project ID Discovery
  - [ ] 27.1 Add "Quick Start" terminal block to project empty state
    - When a project has 0 findings, display a "Quick Start" terminal UI block with three copy-pasteable commands:
      1. `npm install -g sicario-cli`
      2. `sicario login --token=<THEIR_ACTUAL_API_KEY>` (populated with the real project API key)
      3. `sicario link --project=<THEIR_ACTUAL_PROJECT_ID>` (populated with the real project ID)
    - Each command should have its own "Copy" button
  - [ ] 27.2 Add "CLI Integration" section to project settings
    - In the project settings/detail page, add a permanent "CLI Integration" section
    - Display the project's `Project ID` in a copyable terminal block
    - Display the full `sicario link --project=<PROJECT_ID>` command with a "Copy" button
    - Style consistently with the rest of the premium terminal UI language
