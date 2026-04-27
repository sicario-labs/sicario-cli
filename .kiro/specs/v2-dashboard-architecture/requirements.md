# Requirements Document

## Introduction

Sicario is a zero-exfiltration security platform. The CLI runs locally — code never leaves the developer's machine. The dashboard provides fleet-wide visibility, automated PR blocking, and autonomous vulnerability patching. This spec defines the V2 architecture that transforms Sicario from a developer tool into an enterprise security platform: zero-friction onboarding via GitHub App, automated CI/CD enforcement that blocks vulnerable PRs, autonomous fix PRs for zero-day CVEs, and organization-wide coverage mapping.

## Glossary

- **Onboarding_Flow**: The multi-step wizard that guides a new user from GitHub OAuth login through org provisioning, repository connection, and first scan to the project dashboard.
- **Dashboard**: The authenticated React SPA served at `/dashboard/*` that displays security findings, project status, PR check results, auto-fix PR status, and organizational analytics.
- **Provisioning_Engine**: The Convex backend logic that auto-creates organizations, memberships, and projects during onboarding without user-facing forms.
- **Repo_Connect**: The unskippable onboarding step where the user authorizes Sicario's GitHub App to access their repositories and selects which repository to connect.
- **Waiting_Room**: The dynamic terminal-style loading screen displayed while the CLI is being installed and the first scan is in progress, showing the `sicario-cli` install command and a unique project API key.
- **Coverage_Map**: A visual dashboard component that displays the ratio of protected (scanned) repositories to unprotected (shadow IT) repositories across a GitHub organization.
- **PR_Security_Check**: The automated workflow where Sicario's GitHub App receives PR webhook events, runs a cloud-side SAST scan on the PR diff, and posts a GitHub Check Run that blocks merges when critical or high severity findings are detected.
- **Auto_Fix_PR**: An autonomous pull request opened by Sicario via the GitHub App when a new CVE is detected in a project's SCA dependencies, containing the dependency version bump that resolves the vulnerability.
- **Webhook_Handler**: The Convex HTTP action endpoint that receives GitHub webhook events (pull_request.opened, pull_request.synchronize), validates the webhook signature, and triggers the PR scan workflow.
- **Trust_Badge**: A trust marker UI element that reminds users Sicario only receives telemetry metadata, not source code.
- **Project**: A Convex database record representing a scanned repository, extended with `provisioningState` and `githubAppInstallationId` fields.
- **GitHub_App_Installation**: The record linking a Sicario organization to a GitHub App installation for CI/CD integration and autonomous PR capabilities.
- **Convex_Schema**: The Convex database schema defined in `convex/convex/schema.ts` that stores all application data.
- **CLI_Telemetry_Module**: The Rust module at `sicario-cli/src/convex/telemetry.rs` that defines `TelemetryEvent` and `TelemetryAction` types for sending vulnerability events to the Convex backend.
- **CLI_Token_Store**: The Rust module at `sicario-cli/src/auth/token_store.rs` that securely stores and retrieves authentication credentials (access tokens, refresh tokens, cloud API tokens) in the system keychain.
- **CLI_Auth_Module**: The Rust module at `sicario-cli/src/auth/auth_module.rs` that implements OAuth 2.0 Device Flow + PKCE authentication and cloud login/logout.
- **CLI_Convex_Client**: The Rust module at `sicario-cli/src/convex/client.rs` that manages the WebSocket connection to the Convex backend for telemetry push and ruleset subscription.
- **Project_API_Key**: A unique secret key generated during V2 onboarding and associated with a project record, used to authenticate CLI scan uploads without requiring a full OAuth flow.
- **GitHub_Check_Run**: A GitHub Checks API object posted by Sicario's GitHub App to a pull request, reporting pass/fail status based on SAST scan results.

## Requirements

### Requirement 1: GitHub OAuth Zero-Friction Authentication

**User Story:** As a new user, I want to sign in with my GitHub account in one click, so that I can start using Sicario without creating a separate account.

#### Acceptance Criteria

1. WHEN a user clicks "Continue with GitHub" on the auth page, THE Onboarding_Flow SHALL initiate GitHub OAuth and redirect the user to the GitHub authorization screen.
2. WHEN GitHub OAuth completes successfully, THE Onboarding_Flow SHALL redirect the user to the onboarding wizard at `/dashboard/onboarding/v2` instead of the generic dashboard.
3. IF GitHub OAuth fails or times out after 15 seconds, THEN THE Onboarding_Flow SHALL display an error message with a "Try Again" button.
4. WHEN a returning user with a completed onboarding profile signs in, THE Onboarding_Flow SHALL redirect the user directly to `/dashboard` bypassing the onboarding wizard.

### Requirement 2: Invisible Organization Provisioning

**User Story:** As a new user, I want my organization to be created automatically after sign-in, so that I do not have to fill out any forms before connecting a repository.

#### Acceptance Criteria

1. WHEN a new user completes GitHub OAuth and has no existing membership, THE Provisioning_Engine SHALL create a default organization named `"{DisplayName}'s Org"` using the GitHub profile display name.
2. WHEN the default organization is created, THE Provisioning_Engine SHALL assign the authenticated user the "admin" role in the new organization.
3. THE Provisioning_Engine SHALL complete organization creation and membership assignment within a single Convex mutation to prevent race conditions.
4. IF organization provisioning fails, THEN THE Provisioning_Engine SHALL retry once and display an error message to the user if the retry also fails.
5. WHEN a user already has at least one organization membership, THE Provisioning_Engine SHALL skip organization creation.

### Requirement 3: Mandatory Repository Connection via GitHub App

**User Story:** As a new user, I want to authorize Sicario to access my GitHub repositories during onboarding, so that Sicario can immediately start protecting my codebase.

#### Acceptance Criteria

1. WHEN the user reaches the repository connection step, THE Repo_Connect SHALL initiate the GitHub App installation flow, redirecting the user to GitHub to authorize Sicario's GitHub App for their account or organization.
2. WHEN the user completes GitHub App authorization and is redirected back, THE Repo_Connect SHALL fetch the list of repositories accessible via the GitHub App installation and display them for selection.
3. THE Repo_Connect SHALL NOT provide a "Skip" button; the user must authorize the GitHub App and select a repository to proceed.
4. WHEN the user selects a repository from the list and confirms, THE Provisioning_Engine SHALL create a new Project record with `provisioningState` set to `"pending"` and store the `githubAppInstallationId`.
5. IF the GitHub App authorization fails or the user cancels the GitHub authorization flow, THEN THE Repo_Connect SHALL display an error message with a "Try Again" button to restart the authorization.
6. WHEN the Project record is created, THE Provisioning_Engine SHALL generate a unique project API key and associate it with the project.
7. THE Repo_Connect SHALL display an optional "Framework" dropdown after repository selection to capture framework metadata before proceeding.

### Requirement 4: Waiting Room

**User Story:** As a new user, I want to see a dynamic loading screen with CLI installation instructions while my project is being provisioned, so that I can install the CLI and run my first scan.

#### Acceptance Criteria

1. WHEN the user confirms repository selection on the Repo Connect screen, THE Waiting_Room SHALL display a terminal-style animated loading screen.
2. THE Waiting_Room SHALL display the `sicario-cli` install command (`brew install EmmyCodes234/sicario-cli/sicario`) with a copy-to-clipboard button.
3. THE Waiting_Room SHALL display the unique project API key with a copy-to-clipboard button.
4. THE Waiting_Room SHALL display the `sicario scan . --publish` command with a copy-to-clipboard button.
5. WHILE the project `provisioningState` is `"pending"`, THE Waiting_Room SHALL show an animated progress indicator.
6. WHEN the project `provisioningState` transitions to `"active"` (first scan received), THE Waiting_Room SHALL automatically redirect the user to the project dashboard at `/dashboard/projects/{projectId}`.
7. IF the project `provisioningState` transitions to `"failed"`, THEN THE Waiting_Room SHALL display an error message with a "Retry" button.
8. THE Waiting_Room SHALL display a "Skip — I'll scan later" link that redirects to `/dashboard` after 30 seconds of waiting.

### Requirement 5: Coverage Map

**User Story:** As a security lead, I want to see a visual map of which repositories in my organization are protected by Sicario and which are not, so that I can identify coverage gaps.

#### Acceptance Criteria

1. THE Coverage_Map SHALL display a summary showing the count of protected repositories and the count of unprotected repositories (e.g., "12 of 30 repos protected").
2. THE Coverage_Map SHALL display a visual indicator (progress bar or grid) representing the ratio of protected to total repositories.
3. WHEN a new project is created with `provisioningState` set to `"active"`, THE Coverage_Map SHALL update the protected count in real time via Convex live queries.
4. THE Coverage_Map SHALL be displayed on the main dashboard overview page at `/dashboard`.
5. WHEN the user has zero projects, THE Coverage_Map SHALL display an empty state prompting the user to connect a repository.

### Requirement 6: PR Security Check

**User Story:** As a security lead, I want PRs automatically scanned and blocked if they contain critical vulnerabilities, so that vulnerable code never reaches production even if developers forget to run the CLI.

#### Acceptance Criteria

1. WHEN a `pull_request.opened` or `pull_request.synchronize` webhook event is received from GitHub, THE Webhook_Handler SHALL validate the webhook signature using the GitHub App secret and trigger the PR_Security_Check workflow.
2. WHEN the PR_Security_Check workflow is triggered, THE Provisioning_Engine SHALL run a cloud-side SAST scan on the PR diff using the Sicario rule engine.
3. WHEN the SAST scan completes, THE PR_Security_Check SHALL post a GitHub_Check_Run to the pull request via the GitHub Checks API with a summary of findings.
4. WHEN the SAST scan detects one or more findings at or above the configured severity threshold, THE PR_Security_Check SHALL set the GitHub_Check_Run conclusion to `"failure"`, blocking the merge.
5. WHEN the SAST scan detects zero findings at or above the configured severity threshold, THE PR_Security_Check SHALL set the GitHub_Check_Run conclusion to `"success"`, allowing the merge.
6. THE Dashboard SHALL display PR check results in real time on the main dashboard overview page, grouped by status: "Passed", "Failed", and "Pending".
7. THE PR_Security_Check SHALL support a configurable severity threshold per project, defaulting to `"high"` (block on critical and high findings).
8. IF the webhook signature validation fails, THEN THE Webhook_Handler SHALL reject the request with HTTP 401 and log the invalid signature attempt.
9. THE Dashboard SHALL display for each PR check entry: the repository name, PR number, PR title, status badge, findings count, and a link to the GitHub PR.
10. WHEN no PR check data is available for a project, THE Dashboard SHALL display an informational message explaining how to enable PR blocking via the GitHub App.

### Requirement 7: Autonomous Fix PRs

**User Story:** As a CTO, I want Sicario to automatically open PRs fixing vulnerable dependencies across all my repos, so that zero-day vulnerabilities are patched before my team even wakes up.

#### Acceptance Criteria

1. THE Provisioning_Engine SHALL run background SCA scans against connected repositories on a configurable schedule, defaulting to once every 24 hours.
2. WHEN a background SCA scan detects a vulnerability in a project dependency with a known fix version, THE Provisioning_Engine SHALL generate a dependency version bump fix.
3. WHEN a fix is generated, THE Provisioning_Engine SHALL open a pull request on the repository via the GitHub App API containing the dependency file update and a description of the CVE being fixed.
4. THE Provisioning_Engine SHALL create an `autoFixPRs` record in the Convex_Schema with status `"opened"` when the PR is successfully created on GitHub.
5. THE Dashboard SHALL display pending and completed auto-fix PRs on the main dashboard overview page, showing: CVE ID, package name, version change, PR link, and status.
6. IF the GitHub API rejects the PR creation (e.g., insufficient permissions), THEN THE Provisioning_Engine SHALL record the failure in the `autoFixPRs` table with status `"failed"` and surface the error on the Dashboard.
7. THE Provisioning_Engine SHALL support a configurable toggle per project to enable or disable autonomous fix PRs, defaulting to enabled.
8. WHEN an auto-fix PR is merged on GitHub, THE Provisioning_Engine SHALL update the `autoFixPRs` record status to `"merged"` upon receiving the corresponding webhook event.
9. THE Provisioning_Engine SHALL NOT open duplicate auto-fix PRs for the same CVE and package in the same project if an existing open PR already addresses the vulnerability.

### Requirement 8: Trust Badge

**User Story:** As a security-conscious user, I want visible trust markers reminding me that Sicario only receives telemetry and not my source code, so that I feel confident using the tool.

#### Acceptance Criteria

1. THE Trust_Badge SHALL be displayed in the dashboard sidebar footer area.
2. THE Trust_Badge SHALL display the text "Zero-Exfiltration: Telemetry Only" with a shield icon.
3. WHEN the user hovers over or clicks the Trust_Badge, THE Dashboard SHALL display a tooltip or popover explaining that Sicario CLI processes code locally and only sends finding metadata to the cloud.
4. THE Trust_Badge SHALL be visible on every dashboard page.

### Requirement 9: Convex Schema Extensions for Projects and PR Monitoring

**User Story:** As a backend developer, I want the database schema to support project provisioning state, PR check results, and auto-fix PR tracking, so that the onboarding flow, PR blocking, and autonomous patching features have the data they need.

#### Acceptance Criteria

1. THE Convex_Schema SHALL add a `provisioningState` field of type `string` to the `projects` table with allowed values: `"pending"`, `"active"`, `"failed"`.
2. THE Convex_Schema SHALL add a `githubAppInstallationId` field of type `optional string` to the `projects` table.
3. THE Convex_Schema SHALL add a `framework` field of type `optional string` to the `projects` table.
4. THE Convex_Schema SHALL add a `projectApiKey` field of type `string` to the `projects` table with an index `by_projectApiKey` for lookup.
5. THE Convex_Schema SHALL set the default value of `provisioningState` to `"pending"` when a new project is inserted during onboarding.
6. THE Convex_Schema SHALL define a `prChecks` table with fields: `checkId` (string), `projectId` (string), `orgId` (string), `prNumber` (number), `prTitle` (string), `repositoryUrl` (string), `status` (string, allowed values: `"pending"`, `"passed"`, `"failed"`, `"blocked"`), `findingsCount` (number), `criticalCount` (number), `highCount` (number), `githubCheckRunId` (optional string), `createdAt` (string), `updatedAt` (string).
7. THE Convex_Schema SHALL index the `prChecks` table by `orgId` and by `projectId` for efficient dashboard queries.
8. THE Convex_Schema SHALL define an `autoFixPRs` table with fields: `fixId` (string), `projectId` (string), `orgId` (string), `cveId` (string), `packageName` (string), `fromVersion` (string), `toVersion` (string), `prNumber` (optional number), `prUrl` (optional string), `status` (string, allowed values: `"pending"`, `"opened"`, `"merged"`, `"closed"`, `"failed"`), `createdAt` (string).
9. THE Convex_Schema SHALL index the `autoFixPRs` table by `orgId` and by `projectId` for efficient dashboard queries.
10. THE Convex_Schema SHALL add a `severityThreshold` field of type `optional string` to the `projects` table, defaulting to `"high"`, to configure the PR blocking threshold.
11. THE Convex_Schema SHALL add an `autoFixEnabled` field of type `optional boolean` to the `projects` table, defaulting to `true`, to toggle autonomous fix PRs per project.

### Requirement 10: GitHub App Webhook Handler

**User Story:** As a backend developer, I want a webhook endpoint that receives GitHub PR events, so that Sicario can automatically scan PRs when they are opened or updated.

#### Acceptance Criteria

1. THE Convex_Schema SHALL expose an HTTP action endpoint at `/api/v1/github/webhook` that accepts POST requests containing GitHub webhook payloads.
2. WHEN a webhook request is received, THE Webhook_Handler SHALL validate the `X-Hub-Signature-256` header against the stored GitHub App webhook secret using HMAC-SHA256.
3. IF the webhook signature is invalid or missing, THEN THE Webhook_Handler SHALL return HTTP 401 and discard the payload.
4. WHEN a valid `pull_request.opened` event is received, THE Webhook_Handler SHALL create a `prChecks` record with status `"pending"` and trigger the PR_Security_Check scan workflow.
5. WHEN a valid `pull_request.synchronize` event is received, THE Webhook_Handler SHALL update the existing `prChecks` record for the PR to status `"pending"` and trigger a new PR_Security_Check scan.
6. WHEN a valid `pull_request.closed` event is received where the PR was merged and the PR matches an `autoFixPRs` record, THE Webhook_Handler SHALL update the `autoFixPRs` record status to `"merged"`.
7. THE Webhook_Handler SHALL resolve the `projectId` and `orgId` from the repository URL in the webhook payload by matching against the `projects` table.
8. IF the webhook payload references a repository that does not match any connected project, THEN THE Webhook_Handler SHALL return HTTP 200 (acknowledge) and take no further action.

### Requirement 11: V2 Onboarding Route Structure

**User Story:** As a frontend developer, I want the V2 onboarding flow to have its own route structure, so that it can coexist with the existing onboarding during migration.

#### Acceptance Criteria

1. THE Dashboard SHALL register a new route at `/dashboard/onboarding/v2` for the V2 onboarding wizard.
2. THE Dashboard SHALL preserve all existing routes at their current paths without modification.
3. WHEN an unauthenticated user navigates to any `/dashboard/*` route, THE Dashboard SHALL redirect to `/auth`.

### Requirement 12: Dashboard Dark-Mode Aesthetic

**User Story:** As a user, I want the dashboard to have a consistent dark-mode "Command Center" aesthetic, so that the interface feels premium and cohesive.

#### Acceptance Criteria

1. THE Dashboard SHALL use the existing dark-mode color palette defined in `design-tokens.css` and Tailwind configuration.
2. THE Dashboard SHALL apply the dark background color (`bg-bg-main`) to all new dashboard pages and components.
3. THE Dashboard SHALL use the accent color (`#ADFF2F`) for primary interactive elements, status indicators, and the Sicario brand identity across all new components.
4. THE Dashboard SHALL ensure all new text elements meet WCAG AA contrast ratio requirements against the dark background.

### Requirement 13: Project Provisioning State Transitions

**User Story:** As a backend developer, I want clear state transitions for project provisioning, so that the onboarding flow and dashboard can react to provisioning progress.

#### Acceptance Criteria

1. WHEN a project is created during onboarding, THE Provisioning_Engine SHALL set `provisioningState` to `"pending"`.
2. WHEN the first scan result is received for a project with `provisioningState` equal to `"pending"`, THE Provisioning_Engine SHALL transition `provisioningState` to `"active"`.
3. IF provisioning encounters an unrecoverable error, THEN THE Provisioning_Engine SHALL transition `provisioningState` to `"failed"`.
4. THE Provisioning_Engine SHALL NOT allow transitions from `"active"` back to `"pending"`.
5. WHEN `provisioningState` transitions to `"active"`, THE Provisioning_Engine SHALL emit a real-time update that Convex live queries can observe.

### Requirement 14: Project API Key Authentication in the CLI

**User Story:** As a developer, I want to authenticate my CLI scan using a project API key from the Waiting Room, so that I can publish scan results to a specific project without completing the full OAuth device flow.

#### Acceptance Criteria

1. THE CLI_Token_Store SHALL support storing and retrieving a `project_api_key` credential in the system keychain under the key `"project_api_key"`.
2. WHEN the `sicario scan . --publish` command is invoked and a `project_api_key` is available in the Token_Store or via the `SICARIO_PROJECT_API_KEY` environment variable, THE CLI_Auth_Module SHALL use the project API key for authentication instead of requiring a cloud OAuth token.
3. THE Convex_Schema SHALL validate incoming scan requests against the `by_projectApiKey` index on the `projects` table and resolve the associated `orgId` and `projectId` from the matched project record.
4. IF a scan request provides a `project_api_key` that does not match any project record, THEN THE Convex_Schema SHALL reject the request and return an authentication error.
5. THE CLI_Auth_Module SHALL prefer the cloud OAuth token over the project API key when both credentials are available, falling back to the project API key only when no OAuth token is present.
6. WHEN a project API key is used for authentication, THE CLI_Convex_Client SHALL include the key in the WebSocket `Authorization` header using the scheme `Bearer project:{projectApiKey}`.

### Requirement 15: Backward-Compatible Schema Migration for Provisioning State

**User Story:** As a backend developer, I want existing projects without a `provisioningState` field to default to "active", so that the V2 dashboard does not break for users who created projects before the schema extension.

#### Acceptance Criteria

1. WHEN the Convex_Schema adds the `provisioningState` field to the `projects` table, THE Convex_Schema SHALL define the field as `v.optional(v.string())` to avoid breaking existing records that lack the field.
2. WHEN a query or mutation reads a project record where `provisioningState` is `undefined`, THE Provisioning_Engine SHALL treat the project as having `provisioningState` equal to `"active"`.
3. THE Convex_Schema SHALL define the `githubAppInstallationId`, `framework`, `projectApiKey`, `severityThreshold`, and `autoFixEnabled` fields as optional on the `projects` table so that existing project records remain valid without migration.
4. WHEN the `projects.create` mutation is called from the V2 onboarding flow, THE Provisioning_Engine SHALL explicitly set `provisioningState` to `"pending"` and generate a `projectApiKey`.
5. WHEN the `projects.create` mutation is called from a non-V2 code path that does not provide `provisioningState`, THE Provisioning_Engine SHALL omit the field, allowing the read-time default of `"active"` to apply.

### Requirement 16: Scan Insert Triggers Provisioning State Transition

**User Story:** As a backend developer, I want the scan insert mutation to automatically transition a project from "pending" to "active" when the first scan arrives, so that the Waiting Room redirects the user without manual intervention.

#### Acceptance Criteria

1. WHEN the `scans.insert` mutation receives a scan with a `projectId` that matches a project with `provisioningState` equal to `"pending"`, THE Provisioning_Engine SHALL transition the project's `provisioningState` to `"active"`.
2. WHEN the `scans.insert` mutation receives a scan with a `projectId` that matches a project with `provisioningState` equal to `"active"` or `undefined`, THE Provisioning_Engine SHALL NOT modify the project's `provisioningState`.
3. WHEN the `scans.insert` mutation receives a scan without a `projectId`, THE Provisioning_Engine SHALL skip the provisioning state check and insert the scan normally.
4. THE Provisioning_Engine SHALL perform the provisioning state transition and the scan insertion within the same Convex mutation to prevent race conditions.
5. IF the provisioning state transition fails due to a concurrent update, THEN THE Provisioning_Engine SHALL log the conflict and proceed with the scan insertion without failing the mutation.

### Requirement 17: Backward-Compatible `sicario scan . --publish` Workflow

**User Story:** As an existing CLI user, I want the `sicario scan . --publish` command to continue working with the new schema, so that my existing workflows are not disrupted by the V2 dashboard changes.

#### Acceptance Criteria

1. WHEN `sicario scan . --publish` is invoked with a valid cloud OAuth token and no project API key, THE CLI_Convex_Client SHALL authenticate using the cloud OAuth token and publish the scan as before.
2. WHEN `sicario scan . --publish` is invoked with a valid project API key and no cloud OAuth token, THE CLI_Convex_Client SHALL authenticate using the project API key and associate the scan with the corresponding project.
3. WHEN `sicario scan . --publish` is invoked with neither a cloud OAuth token nor a project API key, THE CLI_Auth_Module SHALL display an error message instructing the user to run `sicario login` or set the `SICARIO_PROJECT_API_KEY` environment variable.
4. THE CLI_Convex_Client SHALL continue to send `orgId` and `projectId` as optional fields in the `scans.insert` mutation payload; the Convex backend SHALL accept scans with or without these fields.
5. WHEN the Convex backend receives a scan via `scans.insert` with a `projectId` resolved from a project API key, THE Provisioning_Engine SHALL populate the `orgId` field from the matched project record so that the scan is correctly attributed to the organization.
