# Requirements Document

## Introduction

The Sicario platform receives pull_request webhooks via its GitHub App and creates `prChecks` records with status "pending", but no actual scan is triggered — checks stay stuck at "Pending" forever. This feature implements the end-to-end PR scan workflow: fetching changed files from GitHub, running the Sicario SAST/SCA scan engine against them, storing findings, updating the prChecks record, and posting a GitHub Check Run back to the PR.

## Glossary

- **Webhook_Handler**: The Convex HTTP action at `convex/convex/http.ts` that receives GitHub `pull_request` webhook events and creates `prChecks` records.
- **Scan_Orchestrator**: A Convex Node.js action responsible for coordinating the full PR scan lifecycle — fetching diffs, invoking the scan engine, storing results, and updating statuses.
- **PR_Check_Record**: A row in the `prChecks` Convex table tracking the status and findings summary for a single pull request scan.
- **Installation_Token**: A short-lived GitHub token scoped to a specific GitHub App installation, used to call GitHub APIs on behalf of the repository.
- **Check_Run**: A GitHub Checks API object posted to a pull request that displays pass/fail status and a summary directly in the PR UI.
- **Scan_Engine**: The Sicario SAST/SCA analysis engine (Rust binary `sicario-cli`) that scans source files for security vulnerabilities.
- **Changed_Files**: The set of files added or modified in a pull request, retrieved via the GitHub REST API.
- **Severity_Threshold**: A per-project configurable severity level (default: "high") at or above which findings cause a PR check to fail.
- **Finding**: A single security vulnerability or issue detected by the Scan_Engine, stored in the `findings` table.

## Requirements

### Requirement 1: Trigger Scan Orchestration from Webhook

**User Story:** As a developer, I want PR scans to start automatically when I open or update a pull request, so that I get security feedback without manual intervention.

#### Acceptance Criteria

1. WHEN a `pull_request` webhook with action "opened" is received, THE Webhook_Handler SHALL schedule the Scan_Orchestrator with the checkId, repositoryUrl, prNumber, projectId, orgId, and the GitHub App installation ID from the matched project.
2. WHEN a `pull_request` webhook with action "synchronize" is received, THE Webhook_Handler SHALL schedule the Scan_Orchestrator with the same parameters as for "opened".
3. IF the matched project has no `githubAppInstallationId`, THEN THE Webhook_Handler SHALL update the PR_Check_Record status to "failed" and skip scheduling the Scan_Orchestrator.
4. THE Webhook_Handler SHALL return an HTTP 200 response to GitHub within 10 seconds of receiving the webhook, before the scan completes.

### Requirement 2: Fetch Changed Files from GitHub

**User Story:** As a security engineer, I want the scan to analyze only the files changed in the PR, so that scans are fast and focused on new code.

#### Acceptance Criteria

1. WHEN the Scan_Orchestrator starts, THE Scan_Orchestrator SHALL acquire an Installation_Token using the project's `githubAppInstallationId`.
2. WHEN the Installation_Token is acquired, THE Scan_Orchestrator SHALL fetch the list of Changed_Files from the GitHub Pull Request Files API (`GET /repos/{owner}/{repo}/pulls/{pr_number}/files`).
3. THE Scan_Orchestrator SHALL retrieve the raw content of each changed file using the GitHub Contents API or the raw download URL provided in the files response.
4. IF the GitHub API returns a non-2xx response when fetching Changed_Files, THEN THE Scan_Orchestrator SHALL update the PR_Check_Record status to "failed" and record the error.
5. WHEN the pull request contains more than 300 Changed_Files, THE Scan_Orchestrator SHALL process only the first 300 files and continue the scan.

### Requirement 3: Execute Security Scan on Changed Files

**User Story:** As a security engineer, I want the Sicario scan engine to analyze PR diffs for vulnerabilities, so that security issues are caught before merge.

#### Acceptance Criteria

1. WHEN Changed_Files are retrieved, THE Scan_Orchestrator SHALL invoke the Scan_Engine against the retrieved file contents.
2. THE Scan_Orchestrator SHALL pass the file paths and contents to the Scan_Engine so that findings reference correct file paths relative to the repository root.
3. THE Scan_Engine SHALL produce a scan report containing metadata (repository, branch, commit SHA, duration, files scanned, rules loaded) and a list of findings.
4. IF the Scan_Engine fails or times out, THEN THE Scan_Orchestrator SHALL update the PR_Check_Record status to "failed" and record the error.

### Requirement 4: Store Scan Results

**User Story:** As a platform user, I want PR scan findings stored in the database, so that I can review and triage them from the dashboard.

#### Acceptance Criteria

1. WHEN the Scan_Engine produces a scan report, THE Scan_Orchestrator SHALL insert a scan record into the `scans` table with the projectId and orgId from the PR_Check_Record.
2. WHEN the Scan_Engine produces findings, THE Scan_Orchestrator SHALL insert each Finding into the `findings` table linked to the scan record, with orgId and projectId set.
3. THE Scan_Orchestrator SHALL set the `triageState` of each new Finding to "Open".
4. THE Scan_Orchestrator SHALL compute a `fingerprint` for each Finding based on the ruleId, filePath, and code snippet, so that duplicate findings across scans can be identified.

### Requirement 5: Update PR Check Record with Results

**User Story:** As a developer, I want to see whether my PR passed or failed the security check, so that I know if I need to fix issues before merging.

#### Acceptance Criteria

1. WHEN the scan completes with zero findings at or above the project Severity_Threshold, THE Scan_Orchestrator SHALL update the PR_Check_Record status to "passed".
2. WHEN the scan completes with one or more findings at or above the project Severity_Threshold, THE Scan_Orchestrator SHALL update the PR_Check_Record status to "failed".
3. THE Scan_Orchestrator SHALL update the PR_Check_Record with the total `findingsCount`, `criticalCount`, and `highCount` from the scan results.
4. THE Scan_Orchestrator SHALL store the GitHub Check_Run ID on the PR_Check_Record after posting the Check_Run.

### Requirement 6: Post GitHub Check Run to Pull Request

**User Story:** As a developer, I want to see the Sicario scan result directly on my GitHub pull request, so that I get feedback in my normal workflow.

#### Acceptance Criteria

1. WHEN the Scan_Orchestrator begins processing, THE Scan_Orchestrator SHALL create a GitHub Check_Run via the Checks API (`POST /repos/{owner}/{repo}/check-runs`) with status "in_progress" and the name "Sicario Security Scan".
2. WHEN the scan completes successfully, THE Scan_Orchestrator SHALL update the Check_Run conclusion to "success" when the PR_Check_Record status is "passed", or "failure" when the status is "failed".
3. THE Scan_Orchestrator SHALL include a summary in the Check_Run output containing the total findings count, critical count, high count, and the Severity_Threshold used.
4. WHEN the Check_Run output includes findings, THE Scan_Orchestrator SHALL include up to 50 annotations on the Check_Run, each referencing the file path, line number, severity, and rule name of a Finding.
5. IF the GitHub Checks API returns a non-2xx response, THEN THE Scan_Orchestrator SHALL log the error and continue without failing the overall scan workflow.

### Requirement 7: Handle Scan Timeout and Resource Limits

**User Story:** As a platform operator, I want PR scans to complete within bounded time and resource limits, so that the system remains responsive.

#### Acceptance Criteria

1. THE Scan_Orchestrator SHALL complete the entire scan workflow (fetch files, run scan, store results, post Check_Run) within 120 seconds.
2. IF the Scan_Orchestrator exceeds the 120-second limit, THEN THE Scan_Orchestrator SHALL update the PR_Check_Record status to "failed" with an indication that the scan timed out.
3. WHILE the Scan_Orchestrator is processing, THE Scan_Orchestrator SHALL update the PR_Check_Record status to "running" so the frontend can display scan progress.

### Requirement 8: Support Concurrent PR Scans

**User Story:** As a team lead, I want multiple PRs to be scanned independently and concurrently, so that one slow scan does not block others.

#### Acceptance Criteria

1. THE Webhook_Handler SHALL schedule each scan as an independent Convex action, so that concurrent pull request events are processed in parallel.
2. THE Scan_Orchestrator SHALL operate only on the PR_Check_Record identified by its checkId, so that concurrent scans do not interfere with each other.
3. WHEN a "synchronize" event arrives for a PR that already has a "pending" or "running" scan, THE Webhook_Handler SHALL create a new PR_Check_Record for the new commit and schedule a new scan, leaving the previous scan to complete independently.
