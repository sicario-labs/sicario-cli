# Requirements Document

## Introduction

This feature pivots the Sicario platform to a "Zero-Exfiltration Edge Scanning" architecture. The core change: all AST parsing and SAST scanning happens locally on the developer's machine or within their own CI runner (via athe Sicario Rust CLI). The Convex cloud backend is reduced to a telemetry ingestor and dashboard presentation layer. No source code ever leaves the developer's environment.

This requires three workstreams:
1. Removing all cloud-side code-fetching, GitHub webhook processing, and GitHub App authentication logic from the Convex backend.
2. Building a new telemetry ingestion HTTP endpoint that accepts structured scan findings from the CLI.
3. Updating the Rust CLI to serialize and submit scan results to the new telemetry endpoint.

## Glossary

- **Convex_Backend**: The Convex cloud deployment that hosts HTTP endpoints, mutations, queries, and the database schema. Located under `convex/convex/`.
- **CLI**: The Sicario Rust CLI binary (`sicario-cli/`) that performs local SAST scanning, secret detection, and SCA analysis on the developer's machine or CI runner.
- **Telemetry_Endpoint**: The new `POST /api/v1/telemetry/scan` HTTP endpoint on the Convex_Backend that accepts scan result payloads from the CLI.
- **Telemetry_Payload**: The JSON object sent by the CLI to the Telemetry_Endpoint containing project context, commit metadata, and an array of findings.
- **Finding**: A single security vulnerability detected by the CLI, containing rule identifier, severity, file path, line number, and a short code snippet.
- **GitHub_Webhook_Endpoint**: The existing `POST /api/v1/github/webhook` HTTP route in `convex/http.ts` that receives GitHub PR events. To be removed.
- **PR_Scan_Workflow**: The existing `convex/prScanWorkflow.ts` Node.js action that fetches code from GitHub and runs a TypeScript SAST engine. To be removed.
- **GitHub_App_Modules**: The existing `convex/githubApp.ts` and `convex/githubAppNode.ts` modules providing JWT signing, installation token acquisition, and repository listing for the GitHub App integration. To be removed.
- **PR_SAST_Engine**: The existing `convex/prSastEngine.ts` TypeScript SAST scanning engine. To be removed.
- **PR_SAST_Rules**: The existing `convex/prSastRules.ts` TypeScript SAST rule definitions. To be removed.
- **Scan_Record**: A row in the `scans` database table containing scan metadata (repository, branch, commit SHA, duration, language breakdown, etc.).
- **Finding_Record**: A row in the `findings` database table containing a single vulnerability's details, linked to a Scan_Record by `scanId`.
- **PR_Check_Record**: A row in the `prChecks` database table tracking CI scan results for a pull request.
- **Existing_Scan_Endpoint**: The current `POST /api/v1/scans` HTTP route that already accepts scan reports from the CLI with authentication and org resolution.
- **Dashboard**: The Sicario frontend React application (`sicario-frontend/`) that displays scan results, findings, projects, and PR check data.
- **OnboardingV2Page**: The frontend onboarding wizard (`sicario-frontend/src/pages/dashboard/OnboardingV2Page.tsx`) that currently guides users through GitHub App installation and repository connection.
- **PrChecksPanel**: The frontend component (`sicario-frontend/src/components/dashboard/PrChecksPanel.tsx`) that displays PR security check results on the Overview page.
- **PrCheckDetailPage**: The frontend page (`sicario-frontend/src/pages/dashboard/PrCheckDetailPage.tsx`) that shows detailed findings for a specific PR check.

## Requirements

### Requirement 1: Remove GitHub Webhook Endpoint

**User Story:** As a platform maintainer, I want the GitHub webhook HTTP endpoint removed, so that the Convex_Backend no longer receives or processes GitHub PR events.

#### Acceptance Criteria

1. WHEN the GitHub_Webhook_Endpoint route (`POST /api/v1/github/webhook`) is removed from `convex/http.ts`, THE Convex_Backend SHALL no longer register an HTTP handler for that path.
2. WHEN the GitHub_Webhook_Endpoint route is removed, THE Convex_Backend SHALL also remove the corresponding OPTIONS preflight route for `/api/v1/github/webhook`.
3. WHEN the webhook signature validation helper (`validateWebhookSignature`) is no longer referenced by any remaining endpoint, THE Convex_Backend SHALL remove the helper function from `convex/http.ts`.

### Requirement 2: Remove PR Scan Workflow

**User Story:** As a platform maintainer, I want the cloud-side PR scan workflow removed, so that the Convex_Backend no longer downloads code diffs or runs TypeScript AST checks.

#### Acceptance Criteria

1. WHEN the PR_Scan_Workflow file (`convex/prScanWorkflow.ts`) is deleted, THE Convex_Backend SHALL no longer export or schedule the `runPrScan` action.
2. WHEN the PR_Scan_Workflow is removed, THE Convex_Backend SHALL also delete the PR_SAST_Engine file (`convex/prSastEngine.ts`).
3. WHEN the PR_Scan_Workflow is removed, THE Convex_Backend SHALL also delete the PR_SAST_Rules file (`convex/prSastRules.ts`).
4. WHEN the PR_Scan_Workflow is removed, THE Convex_Backend SHALL also delete all associated test files in `convex/convex/__tests__/` that reference PR scan workflow, PR SAST engine, PR SAST rules, PR scan annotations, PR scan fingerprints, or PR scan thresholds.

### Requirement 3: Remove GitHub App Authentication Modules

**User Story:** As a platform maintainer, I want the GitHub App JWT signing and installation token logic removed, so that the Convex_Backend no longer authenticates with GitHub's API.

#### Acceptance Criteria

1. WHEN the GitHub_App_Modules are removed, THE Convex_Backend SHALL delete the `convex/githubAppNode.ts` file containing Node.js crypto-based JWT generation and installation token acquisition.
2. WHEN the GitHub_App_Modules are removed, THE Convex_Backend SHALL delete the `convex/githubApp.ts` file containing Web Crypto-based JWT generation, installation token acquisition, and repository listing.
3. WHEN the GitHub_App_Modules are removed, THE Convex_Backend SHALL remove the inlined GitHub App utility functions (`ghBase64UrlEncode`, `ghBase64UrlEncodeString`, `requireGitHubAppEnv`, `generateAppJwt`, `getInstallationToken`, `listInstallationRepos`) from `convex/http.ts`.
4. WHEN the GitHub_App_Modules are removed, THE Convex_Backend SHALL remove the `GET /api/v1/github/repos` HTTP route and its corresponding OPTIONS preflight route from `convex/http.ts`.

### Requirement 4: Clean Up PR Checks Module

**User Story:** As a platform maintainer, I want the PR checks module updated to remove GitHub Check Run integration while preserving CI scan tracking, so that the prChecks table remains useful for dashboard display of CI-triggered scan results.

#### Acceptance Criteria

1. WHEN the GitHub_App_Modules are removed, THE Convex_Backend SHALL remove the `githubCheckRunId` field from the `prChecks` table schema definition in `convex/schema.ts`.
2. WHEN the `githubCheckRunId` field is removed from the schema, THE Convex_Backend SHALL update the `updatePrCheck` mutation in `convex/prChecks.ts` to no longer accept or store the `githubCheckRunId` argument.
3. THE Convex_Backend SHALL retain the `prChecks` table, its indexes, and the `createPrCheck`, `updatePrCheck`, `listByOrg`, `listByProject`, and `getByCheckId` queries and mutations for tracking CI scan results submitted via the Telemetry_Endpoint.

### Requirement 5: Remove GitHub App Installation References from Projects

**User Story:** As a platform maintainer, I want GitHub App installation references removed from the projects schema, so that the data model reflects the new zero-exfiltration architecture.

#### Acceptance Criteria

1. WHEN the GitHub_App_Modules are removed, THE Convex_Backend SHALL remove the `githubAppInstallationId` field from the `projects` table schema definition in `convex/schema.ts`.
2. WHEN the `githubAppInstallationId` field is removed, THE Convex_Backend SHALL update the `createV2` mutation in `convex/projects.ts` to no longer accept or store the `githubAppInstallationId` argument.
3. WHEN the `githubAppInstallationId` field is removed, THE Convex_Backend SHALL ensure the `mapProject` helper in `convex/projects.ts` no longer maps or returns `github_app_installation_id`.

### Requirement 6: Build Telemetry Ingestion Endpoint

**User Story:** As a CLI developer, I want a dedicated telemetry ingestion endpoint that accepts structured scan findings, so that the CLI can submit local scan results to the Convex_Backend for dashboard display.

#### Acceptance Criteria

1. THE Convex_Backend SHALL expose a new HTTP route at `POST /api/v1/telemetry/scan` in `convex/http.ts`.
2. THE Telemetry_Endpoint SHALL also register a corresponding OPTIONS preflight route at `/api/v1/telemetry/scan` that returns CORS headers.
3. WHEN a request arrives at the Telemetry_Endpoint without a valid Bearer token (Convex Auth JWT, opaque `sic_` device token, or `project:` API key), THE Telemetry_Endpoint SHALL return HTTP 401 with a JSON error body `{"error": "Unauthorized"}`.
4. WHEN a valid Telemetry_Payload is received, THE Telemetry_Endpoint SHALL validate that the payload contains the required fields: `projectId` (string), `repositoryUrl` (string), `commitSha` (string), `scanId` (string), and `findings` (array).
5. IF the Telemetry_Payload is missing any required field, THEN THE Telemetry_Endpoint SHALL return HTTP 400 with a JSON error body describing the missing fields.
6. WHEN a valid Telemetry_Payload is received, THE Telemetry_Endpoint SHALL resolve the organization from the authenticated identity using the same org-resolution logic as the Existing_Scan_Endpoint (membership lookup or `X-Sicario-Org` header or project API key).
7. WHEN a valid Telemetry_Payload is received, THE Telemetry_Endpoint SHALL match the `projectId` from the payload to an existing project in the resolved organization, or return HTTP 404 if no matching project is found.
8. WHEN a valid Telemetry_Payload is received with a `prNumber` field, THE Telemetry_Endpoint SHALL create or update a PR_Check_Record with the scan results (findings count, critical count, high count, pass/fail status based on the project's severity threshold).
9. WHEN a valid Telemetry_Payload is received, THE Telemetry_Endpoint SHALL insert a Scan_Record into the `scans` table with the metadata from the payload (repository URL, commit SHA, scan ID, timestamp).
10. WHEN a valid Telemetry_Payload is received, THE Telemetry_Endpoint SHALL insert one Finding_Record into the `findings` table for each entry in the `findings` array, mapping `rule` to `ruleId` and `ruleName`, `severity` to `severity`, `file` to `filePath`, `line` to `line`, and `snippet` to `snippet`.
11. WHEN the Telemetry_Endpoint successfully processes a payload, THE Telemetry_Endpoint SHALL return HTTP 200 with a JSON body containing `scan_id`, `project_id`, and `dashboard_url`.
12. IF an internal error occurs during processing, THEN THE Telemetry_Endpoint SHALL return HTTP 500 with a JSON error body `{"error": "<message>"}`.

### Requirement 7: Telemetry Payload Validation

**User Story:** As a platform maintainer, I want the telemetry endpoint to enforce strict payload validation, so that malformed or oversized data does not corrupt the database.

#### Acceptance Criteria

1. WHEN a Telemetry_Payload contains a `snippet` field longer than 100 characters in any Finding, THE Telemetry_Endpoint SHALL truncate the snippet to 100 characters before storage.
2. WHEN a Telemetry_Payload contains a `severity` value that is not one of `"Critical"`, `"High"`, `"Medium"`, or `"Low"`, THE Telemetry_Endpoint SHALL reject the payload with HTTP 400 and a descriptive error message.
3. WHEN a Telemetry_Payload contains more than 5000 findings, THE Telemetry_Endpoint SHALL reject the payload with HTTP 400 and an error message indicating the maximum findings limit.
4. WHEN a Telemetry_Payload contains a `scanId` that already exists in the `scans` table, THE Telemetry_Endpoint SHALL return HTTP 409 (Conflict) with an error message indicating the scan has already been submitted.

### Requirement 8: CLI Telemetry Submission

**User Story:** As a CLI developer, I want the Rust CLI to serialize scan results into the Telemetry_Payload format and submit them to the Telemetry_Endpoint, so that local scan results appear on the cloud dashboard.

#### Acceptance Criteria

1. WHEN a scan completes, THE CLI SHALL serialize the scan results into a JSON Telemetry_Payload containing `projectId`, `repositoryUrl`, `commitSha`, `scanId`, and `findings` array.
2. WHEN the CLI serializes findings, THE CLI SHALL map each vulnerability to the Finding format with `rule` (rule identifier), `severity` (one of `"Critical"`, `"High"`, `"Medium"`, `"Low"`), `file` (relative file path), `line` (1-indexed line number), and `snippet` (truncated to 100 characters).
3. WHEN the CLI submits a Telemetry_Payload, THE CLI SHALL send an HTTP POST request to the Telemetry_Endpoint with the `Authorization` header containing the resolved auth token.
4. IF the Telemetry_Endpoint returns HTTP 200, THEN THE CLI SHALL log a success message including the `dashboard_url` from the response.
5. IF the Telemetry_Endpoint returns a non-200 status, THEN THE CLI SHALL log a warning with the HTTP status code and error message, and continue execution without failing the scan.
6. IF the HTTP request to the Telemetry_Endpoint fails due to a network error, THEN THE CLI SHALL log a warning and continue execution without failing the scan.

### Requirement 9: Telemetry Payload Serialization Round-Trip

**User Story:** As a developer, I want the Telemetry_Payload serialization to be correct and lossless, so that scan results are faithfully transmitted from the CLI to the backend.

#### Acceptance Criteria

1. FOR ALL valid Telemetry_Payload objects, serializing to JSON and then deserializing back SHALL produce an equivalent object (round-trip property).
2. FOR ALL valid Finding objects within a Telemetry_Payload, the `severity` field SHALL always be one of the four allowed values after round-trip serialization.
3. FOR ALL valid Finding objects, the `snippet` field SHALL have a length of 100 characters or fewer after serialization.
4. FOR ALL valid Telemetry_Payload objects, the `findings` array length in the deserialized output SHALL equal the `findings` array length in the original input.

### Requirement 10: Remove GitHub App Environment Variable Dependencies

**User Story:** As a platform maintainer, I want all references to GitHub App environment variables removed from the Convex_Backend, so that the deployment no longer requires GitHub App credentials.

#### Acceptance Criteria

1. WHEN the GitHub_App_Modules are removed, THE Convex_Backend SHALL no longer reference the environment variables `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY_BASE64`, `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`, or `GITHUB_WEBHOOK_SECRET` in any source file.
2. WHEN the GitHub_App_Modules are removed, THE Convex_Backend SHALL remove or update any documentation or configuration files that reference GitHub App setup instructions.

### Requirement 11: Redesign Onboarding Flow for Zero-Exfiltration Model

**User Story:** As a new user, I want the onboarding flow to guide me through CLI-based project setup instead of GitHub App installation, so that the experience reflects the zero-exfiltration architecture.

#### Acceptance Criteria

1. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL remove the GitHub App installation step (the "Install GitHub App" button and the `handleGitHubAppInstall` redirect to `github.com/apps/sicario-security/installations/new`).
2. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL remove the GitHub App callback handling (parsing `installation_id` from URL search params and fetching repos via `GET /api/v1/github/repos`).
3. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL replace the repository selection step with a manual project creation form that accepts a project name and an optional repository URL.
4. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL call the existing `projects.create` mutation (instead of `projects.createV2`) since `githubAppInstallationId` is no longer required.
5. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL retain the "Waiting Room" screen that shows CLI installation instructions, the project API key, and the `sicario scan . --publish` command.
6. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL update the introductory copy to reflect the zero-exfiltration model (e.g., "Your code never leaves your machine" instead of "Authorize Sicario's GitHub App").

### Requirement 12: Update PR Checks Panel for CLI-Driven CI Results

**User Story:** As a dashboard user, I want the PR Checks panel to reflect that CI scan results come from the CLI (not from a GitHub App), so that the messaging is accurate and actionable.

#### Acceptance Criteria

1. WHEN the PrChecksPanel empty state is displayed, THE Dashboard SHALL update the description from "Install the Sicario GitHub App on your repositories to automatically scan pull requests" to messaging that instructs users to add the Sicario CLI to their CI pipeline (e.g., "Add Sicario to your CI pipeline to automatically scan pull requests").
2. WHEN the PrCheckDetailPage displays a PR check, THE Dashboard SHALL remove or hide the `github_check_run_id` field from the detail view since GitHub Check Run integration is removed.
3. THE Dashboard SHALL retain the PR Checks panel on the Overview page, the `pr-checks/:checkId` route, and the PrCheckDetailPage for displaying CI scan results submitted via the Telemetry_Endpoint.

### Requirement 13: Remove GitHub App References from Project Detail and Settings

**User Story:** As a dashboard user, I want all GitHub App installation references removed from the project and settings UI, so that the dashboard accurately represents the zero-exfiltration architecture.

#### Acceptance Criteria

1. WHEN the `githubAppInstallationId` field is removed from the schema, THE Dashboard SHALL ensure the ProjectDetailPage no longer displays or references `github_app_installation_id` in the project metadata.
2. WHEN the `GET /api/v1/github/repos` endpoint is removed, THE Dashboard SHALL remove any frontend code that calls this endpoint (currently in OnboardingV2Page).
3. THE Dashboard SHALL update the `action.yml` GitHub Action configuration (if it references the GitHub App webhook flow) to reflect the CLI-only scanning model where the action runs `sicario scan` and submits results via the Telemetry_Endpoint.

### Requirement 14: CLI Project API Key Authentication

**User Story:** As a CI pipeline operator, I want the Rust CLI to authenticate with the Convex_Backend using a project API key, so that headless environments can submit telemetry without interactive OAuth login.

#### Acceptance Criteria

1. WHEN the `SICARIO_API_KEY` environment variable is set, THE CLI SHALL use its value as the project API key for all Telemetry_Endpoint requests, taking precedence over the `SICARIO_PROJECT_API_KEY` environment variable and the system keychain.
2. WHEN the CLI resolves a project API key (from `SICARIO_API_KEY`, `SICARIO_PROJECT_API_KEY`, or the system keychain), THE CLI SHALL format the HTTP Authorization header as `Bearer project:{key}` for all requests to the Telemetry_Endpoint, matching the token format expected by the `resolveIdentity` function in `convex/http.ts`.
3. WHEN neither a cloud OAuth token nor a project API key is available, THE CLI SHALL exit with a descriptive error message instructing the user to either run `sicario login` or set the `SICARIO_API_KEY` environment variable.
4. WHEN the CLI reads a project API key from a `.sicario/config.yaml` file containing an `api_key` field, THE CLI SHALL use that value as a fallback if no environment variable or keychain entry is available.
5. IF the Telemetry_Endpoint returns HTTP 401 in response to a project API key, THEN THE CLI SHALL log an error message indicating the API key is invalid or expired and suggest regenerating the key in the Sicario dashboard.
6. THE CLI SHALL resolve authentication credentials in the following priority order: (1) `SICARIO_API_KEY` environment variable, (2) cloud OAuth token from keychain, (3) `SICARIO_PROJECT_API_KEY` environment variable, (4) project API key from keychain, (5) `api_key` field in `.sicario/config.yaml`.

### Requirement 15: CLI-Side Snippet Extraction and Truncation (Zero-Exfiltration Guarantee)

**User Story:** As a security-conscious developer, I want the CLI to extract only the minimal surrounding context lines around a vulnerability and enforce strict character limits before transmitting any data, so that raw source code is never exfiltrated beyond the snippet window.

#### Acceptance Criteria

1. WHEN the CLI detects a vulnerability at a given line number, THE CLI SHALL extract only the configurable number of surrounding context lines (default: 3 lines above and 3 lines below the vulnerable line) from the source file.
2. WHEN the CLI constructs a Finding snippet, THE CLI SHALL truncate each extracted line to a maximum of 100 characters before including it in the Telemetry_Payload.
3. THE CLI SHALL support a `--snippet-context` flag (and `SICARIO_SNIPPET_CONTEXT` environment variable) that allows the user to configure the number of surrounding context lines, with a minimum of 0 and a maximum of 10.
4. THE CLI SHALL enforce that the total snippet field in each Finding of the Telemetry_Payload contains only the extracted context lines and does not exceed `(2 * context_lines + 1) * 100` characters.
5. FOR ALL Finding objects produced by the CLI, the `snippet` field SHALL contain only content from the extracted context window and SHALL NOT include any source code from lines outside that window (zero-exfiltration correctness property).
6. IF the vulnerable line number exceeds the total number of lines in the source file, THEN THE CLI SHALL produce an empty snippet and log a warning rather than reading beyond the file boundary.

### Requirement 16: CLI Exit Code CI/CD Gate (Kill Switch)

**User Story:** As a CI pipeline operator, I want the CLI to return a non-zero exit code when findings at or above a configurable severity threshold are detected, so that the CI pipeline (e.g., GitHub Actions) fails the build and blocks the PR merge.

#### Acceptance Criteria

1. WHEN the CLI completes a scan and detects one or more findings with severity at or above the configured threshold, THE CLI SHALL return exit code 1 (`FindingsDetected`).
2. WHEN the CLI completes a scan and detects no findings at or above the configured threshold, THE CLI SHALL return exit code 0 (`Clean`).
3. THE CLI SHALL support a `--fail-on` flag that accepts one of `"Critical"`, `"High"`, `"Medium"`, or `"Low"` to set the severity threshold for exit code determination, with a default of `"High"`.
4. WHEN the `SICARIO_FAIL_ON` environment variable is set to a valid severity value, THE CLI SHALL use it as the severity threshold, with the `--fail-on` flag taking precedence if both are provided.
5. IF the `--fail-on` flag or `SICARIO_FAIL_ON` environment variable contains an invalid severity value, THEN THE CLI SHALL exit with exit code 2 (`InternalError`) and a descriptive error message listing the valid severity values.
6. WHEN the CLI is invoked in a GitHub Actions environment (detected by the presence of the `GITHUB_ACTIONS` environment variable), THE CLI SHALL include a summary annotation in stdout indicating the number of findings at or above the threshold and the resulting pass/fail status.
7. FOR ALL combinations of finding severities and threshold values, the exit code SHALL be 1 if and only if at least one non-suppressed finding has severity greater than or equal to the threshold (exit code correctness property).
2. WHEN the GitHub_App_Modules are removed, THE Convex_Backend SHALL remove or update any documentation or configuration files that reference GitHub App setup instructions.

### Requirement 11: Redesign Onboarding Flow for Zero-Exfiltration Model

**User Story:** As a new user, I want the onboarding flow to guide me through CLI-based project setup instead of GitHub App installation, so that the experience reflects the zero-exfiltration architecture.

#### Acceptance Criteria

1. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL remove the GitHub App installation step (the "Install GitHub App" button and the `handleGitHubAppInstall` redirect to `github.com/apps/sicario-security/installations/new`).
2. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL remove the GitHub App callback handling (parsing `installation_id` from URL search params and fetching repos via `GET /api/v1/github/repos`).
3. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL replace the repository selection step with a manual project creation form that accepts a project name and an optional repository URL.
4. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL call the existing `projects.create` mutation (instead of `projects.createV2`) since `githubAppInstallationId` is no longer required.
5. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL retain the "Waiting Room" screen that shows CLI installation instructions, the project API key, and the `sicario scan . --publish` command.
6. WHEN the OnboardingV2Page is updated, THE Dashboard SHALL update the introductory copy to reflect the zero-exfiltration model (e.g., "Your code never leaves your machine" instead of "Authorize Sicario's GitHub App").

---

# EPIC: Zero-Exfiltration Edge Engine & Deterministic Remediation

## Context & Architectural Pivot

Sicario is enforcing a strict "Zero-Exfiltration" and "Zero-Liability" boundary:
1. **Zero-Exfiltration:** The cloud backend must never fetch or store raw source code. All AST parsing happens locally.
2. **Zero-Liability (BYOK):** The cloud backend must never store third-party LLM API keys. All LLM authentication happens locally on the edge.
3. **Architectural Guardrails:** The Rust CLI will act as a local Model Context Protocol (MCP) server for safe AI auto-remediation, strictly preventing AI agents from executing destructive generic shell commands.
4. **Auditability:** The CLI will bundle its deterministic reasoning into the telemetry payload to prove its math in the cloud dashboard.

## Phase 1: Rust CLI Upgrades (The Edge Engine)

### Requirement 12: Edge BYOK Configuration

**User Story:** As a developer, I want the CLI to securely handle third-party LLM keys locally for remediation, so that the cloud backend never stores sensitive API keys.

#### Acceptance Criteria

1. WHEN the CLI executes `sicario fix`, THE CLI SHALL read LLM API keys from system environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) for seamless CI/CD integration.
2. WHEN the `SICARIO_CONFIG` environment variable is not set, THE CLI SHALL write LLM API keys to a local, user-permission-restricted file (`~/.sicario/config.toml`) when the user runs `sicario config set <KEY> <VALUE>`.
3. WHEN the CLI writes to `~/.sicario/config.toml`, THE CLI SHALL set file permissions to user-only (0600 on Unix, read/write for owner only on Windows).
4. WHEN the CLI authenticates to the Convex telemetry endpoint, THE CLI SHALL use the `SICARIO_API_KEY` environment variable strictly for that purpose, separate from LLM API key handling.
5. WHEN the CLI reads credentials, THE CLI SHALL implement a fallback chain: environment variables → local config file → keychain storage.

### Requirement 13: Embedded MCP Server (Architectural Guardrails)

**User Story:** As a security-conscious developer, I want the CLI to act as a local MCP server for safe AI auto-remediation, so that AI agents cannot execute destructive generic shell commands.

#### Acceptance Criteria

1. WHEN the CLI starts the MCP server, THE CLI SHALL expose only type-safe tools: `get_ast_node`, `analyze_reachability`, `propose_safe_mutation`.
2. WHEN the MCP server receives a tool call, THE MCP server SHALL NOT expose any generic shell execution capability (e.g., `exec`, `run`, `shell`).
3. WHEN the MCP server receives a tool call that would execute shell commands, THE MCP server SHALL reject the call with an error message.
4. WHEN the `propose_safe_mutation` tool is called, THE CLI SHALL queue an AST-level code patch for developer review without autonomously overwriting files.

### Requirement 14: Infinite Loop Prevention (The Runaway Cap)

**User Story:** As a CI pipeline operator, I want the CLI to prevent infinite loops during auto-remediation, so that the pipeline fails safely if the LLM cannot produce valid patches.

#### Acceptance Criteria

1. WHEN the CLI executes `sicario fix`, THE CLI SHALL implement a `--max-iterations` flag that defaults to 3 iterations.
2. WHEN the `SICARIO_MAX_ITERATIONS` environment variable is set, THE CLI SHALL use it as the maximum iteration limit, with the `--max-iterations` flag taking precedence.
3. IF the LLM fails to produce a syntactically valid and secure AST mutation within the iteration limit, THE CLI SHALL log the failure to `.sicario/trace.log` and execute `exit 1` to block the CI pipeline.
4. WHEN the iteration limit is reached, THE CLI SHALL include diagnostic information in the log (which iterations failed, why).

### Requirement 15: Execution Audit Trail Logging

**User Story:** As a security auditor, I want the CLI to bundle its deterministic reasoning into the telemetry payload, so that the cloud dashboard can prove how vulnerabilities were found.

#### Acceptance Criteria

1. WHEN the CLI performs analysis, THE CLI SHALL capture execution steps internally (e.g., `["0.01s: Parsed CST for db.js", "0.04s: Traced untrusted input to Line 8", "0.06s: Flagged CWE-89"]`).
2. WHEN the CLI constructs a Telemetry_Payload, THE CLI SHALL attach the `executionTrace` array to each Finding in the findings array.
3. WHEN the Telemetry_Payload is submitted to the Convex backend, THE Convex backend SHALL store the `executionTrace` array in the `findings` table.

## Phase 2: Convex Backend Upgrades (The Cloud Memory)

### Requirement 16: Deprecate Cloud BYOK & Webhooks

**User Story:** As a platform maintainer, I want the Convex backend to never store third-party LLM keys or process GitHub webhooks, so that the cloud has zero liability for sensitive credentials.

#### Acceptance Criteria

1. WHEN the Convex backend schema is queried, THE Convex backend SHALL NOT contain any table definitions, fields, or queries related to storing or retrieving third-party LLM keys.
2. WHEN the Convex backend receives a request to `api/v1/github/webhook`, THE Convex backend SHALL return HTTP 404 (Not Found) since the endpoint is deleted.
3. WHEN the Convex backend receives a request to `POST /api/v1/telemetry/scan`, THE Convex backend SHALL validate the `SICARIO_API_KEY` for authorization and reject any OAuth/JWT paths that could bypass API key auth.

### Requirement 17: Enforce Snippet Truncation (Server-Side Exfiltration Block)

**User Story:** As a platform maintainer, I want the Convex backend to enforce strict snippet truncation, so that raw source code is never stored beyond the zero-exfiltration limit.

#### Acceptance Criteria

1. WHEN a Telemetry_Payload is received with a `snippet` field longer than 500 characters, THE Convex backend SHALL forcefully truncate the snippet to 500 characters before storage.
2. WHEN the Convex backend truncates a snippet, THE Convex backend SHALL log a warning with the original length and truncated length.
3. FOR ALL stored findings, THE Convex backend SHALL guarantee that the `snippet` field has a length of 500 characters or fewer.

### Requirement 18: Schema Updates for Audit Trail

**User Story:** As a platform maintainer, I want the Convex backend to store execution traces for auditability, so that the cloud dashboard can display how vulnerabilities were found.

#### Acceptance Criteria

1. WHEN the `findings` table schema is defined, THE Convex backend SHALL include `executionTrace: v.optional(v.array(v.string()))` in the schema.
2. WHEN a Telemetry_Payload is received with an `executionTrace` array, THE Convex backend SHALL correctly map and insert the incoming `executionTrace` arrays into the `findings` table.

## Phase 3: Dashboard Frontend Upgrades (The Command Center)

### Requirement 19: Remove Supply-Chain Risks (Read-Only Enforcement)

**User Story:** As a security-conscious developer, I want the dashboard to remove all GitHub OAuth and GitHub App installation UI, so that the dashboard cannot introduce supply-chain risks.

#### Acceptance Criteria

1. WHEN the OnboardingV2Page is rendered, THE Dashboard SHALL NOT display any UI components related to GitHub OAuth, GitHub App installation, or repository connection.
2. WHEN the project creation form is displayed, THE Dashboard SHALL exclusively generate a `SICARIO_API_KEY` and display CLI installation instructions: `npm install -g sicario-cli && sicario login --token=<KEY>`.
3. WHEN the Settings page is rendered, THE Dashboard SHALL NOT display "LLM Providers" or "API Keys" input sections.
4. WHEN the Findings detail page is rendered, THE Dashboard SHALL NOT display any UI buttons that suggest the dashboard can push code or create PRs directly. Instead, the Dashboard SHALL display read-only text blocks instructing: `sicario fix --id=<VULN_ID>`.

### Requirement 20: Display the Audit Trail

**User Story:** As a security auditor, I want the dashboard to display the execution audit trail, so that I can verify the deterministic execution of the Rust CLI.

#### Acceptance Criteria

1. WHEN the Findings detail page is rendered, THE Dashboard SHALL display a premium, luxury-minimalist terminal-style UI block titled "Execution Audit Trail" underneath the Snippet display.
2. WHEN the `executionTrace` array is available, THE Dashboard SHALL map over the array to display the chronological steps the Rust CLI took to find the vulnerability.
3. WHEN the Execution Audit Trail is displayed, THE Dashboard SHALL include timestamps and action descriptions to prove deterministic execution.