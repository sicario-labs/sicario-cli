# Implementation Plan: V2 Dashboard Architecture

## Overview

This plan implements the V2 Dashboard Architecture in a layered build order: Convex schema extensions first, then backend mutations/queries/HTTP actions, then React frontend components, and finally CLI auth extensions. Each task builds incrementally on the previous, ensuring no orphaned code. Property-based tests use `fast-check` for TypeScript/Convex and `proptest` for Rust/CLI.

## Tasks

- [x] 1. Extend Convex schema with V2 project fields and new tables
  - [x] 1.1 Add optional V2 fields to the `projects` table in `convex/convex/schema.ts`
    - Add `provisioningState: v.optional(v.string())`, `githubAppInstallationId: v.optional(v.string())`, `framework: v.optional(v.string())`, `projectApiKey: v.optional(v.string())`, `severityThreshold: v.optional(v.string())`, `autoFixEnabled: v.optional(v.boolean())`
    - Add index `by_projectApiKey` on `["projectApiKey"]`
    - All fields are optional to preserve backward compatibility with existing records
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.10, 9.11, 15.1, 15.3_

  - [x] 1.2 Define the `prChecks` table in `convex/convex/schema.ts`
    - Add table with fields: `checkId`, `projectId`, `orgId`, `prNumber`, `prTitle`, `repositoryUrl`, `status`, `findingsCount`, `criticalCount`, `highCount`, `githubCheckRunId` (optional), `createdAt`, `updatedAt`
    - Add indexes: `by_checkId`, `by_orgId`, `by_projectId`, `by_orgId_status`
    - _Requirements: 9.6, 9.7_

  - [x] 1.3 Define the `autoFixPRs` table in `convex/convex/schema.ts`
    - Add table with fields: `fixId`, `projectId`, `orgId`, `cveId`, `packageName`, `fromVersion`, `toVersion`, `prNumber` (optional), `prUrl` (optional), `status`, `createdAt`
    - Add indexes: `by_fixId`, `by_orgId`, `by_projectId`, `by_projectId_cveId`
    - _Requirements: 9.8, 9.9_

  - [ ]* 1.4 Write property test for optional project field defaults (Property 6)
    - **Property 6: Optional project fields resolve to correct defaults**
    - Test that `provisioningState` defaults to `"active"`, `severityThreshold` defaults to `"high"`, `autoFixEnabled` defaults to `true` when fields are undefined
    - Use `fast-check` to generate project records with random combinations of present/absent optional fields
    - **Validates: Requirements 6.7, 7.7, 15.2**

- [x] 2. Implement V2 project mutations and provisioning logic
  - [x] 2.1 Add `createV2` mutation to `convex/convex/projects.ts`
    - Accept `id`, `name`, `repositoryUrl`, `orgId`, `githubAppInstallationId`, optional `framework`
    - Set `provisioningState` to `"pending"`, generate unique `projectApiKey` via `crypto.randomUUID()`
    - Return `{ id, projectApiKey }`
    - _Requirements: 3.4, 3.6, 9.5, 13.1, 15.4_

  - [x] 2.2 Add `transitionProvisioningState` mutation to `convex/convex/projects.ts`
    - Accept `projectId`, `from`, `to` states
    - Enforce state machine: reject `"active" → "pending"` transitions
    - Return `true` on success, `false` on invalid transition
    - _Requirements: 13.4_

  - [x] 2.3 Add `getByApiKey` query to `convex/convex/projects.ts`
    - Look up project by `projectApiKey` using the `by_projectApiKey` index
    - Return the full project record or `null`
    - _Requirements: 14.3_

  - [x] 2.4 Add helper function `resolveProjectDefaults` to `convex/convex/projects.ts`
    - Pure function that applies read-time defaults: `provisioningState ?? "active"`, `severityThreshold ?? "high"`, `autoFixEnabled ?? true`
    - Update `mapProject` to include V2 fields with defaults applied
    - _Requirements: 15.2_

  - [ ]* 2.5 Write property test for V2 project creation (Property 3)
    - **Property 3: V2 project creation sets provisioning fields and generates unique API key**
    - Use `fast-check` to generate random repo URLs and installation IDs
    - Verify `provisioningState === "pending"`, non-empty unique `projectApiKey`
    - **Validates: Requirements 3.4, 3.6, 9.5, 13.1, 15.4**

  - [ ]* 2.6 Write property test for provisioning state machine (Property 8)
    - **Property 8: Provisioning state machine transitions**
    - Test valid transitions (`pending → active`, `pending → failed`, `failed → pending`) and invalid (`active → pending`)
    - **Validates: Requirements 13.2, 13.4, 16.1, 16.2**

  - [ ]* 2.7 Write property test for project API key lookup (Property 9)
    - **Property 9: Project API key lookup resolves correct project and org**
    - **Validates: Requirements 14.3, 17.5**

- [x] 3. Extend scan insert to trigger provisioning state transition
  - [x] 3.1 Modify `scans.insert` in `convex/convex/scans.ts` to check provisioning state
    - After inserting the scan, if `projectId` is provided, look up the project
    - If `provisioningState === "pending"`, transition to `"active"` via `ctx.db.patch`
    - If `provisioningState` is `"active"` or `undefined`, do nothing
    - Perform transition within the same mutation (atomic)
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5_

  - [ ]* 3.2 Write unit tests for scan-triggered provisioning transition
    - Test: scan with pending project → transitions to active
    - Test: scan with active project → no change
    - Test: scan with no projectId → no provisioning check
    - _Requirements: 16.1, 16.2, 16.3_

- [x] 4. Checkpoint — Ensure schema and backend mutations are correct
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Implement PR Checks module
  - [x] 5.1 Create `convex/convex/prChecks.ts` with mutations and queries
    - `createPrCheck` mutation: insert a new prChecks record with status `"pending"`
    - `updatePrCheck` mutation: update status, findingsCount, criticalCount, highCount, githubCheckRunId
    - `listByOrg` query: return prChecks filtered by orgId, ordered by createdAt desc
    - `listByProject` query: return prChecks filtered by projectId
    - _Requirements: 6.3, 6.6, 6.9, 9.6, 9.7, 10.4, 10.5_

  - [ ]* 5.2 Write property test for severity threshold decision (Property 5)
    - **Property 5: PR check conclusion is determined by severity threshold**
    - Generate random lists of findings with varying severities and random thresholds
    - Verify conclusion is `"failure"` iff any finding meets or exceeds threshold
    - **Validates: Requirements 6.4, 6.5**

- [x] 6. Implement Auto-Fix PRs module
  - [x] 6.1 Create `convex/convex/autoFixPRs.ts` with mutations and queries
    - `createAutoFix` mutation: insert autoFixPRs record, check for duplicates first
    - `updateAutoFixStatus` mutation: update status, prNumber, prUrl
    - `listByOrg` query: return autoFixPRs filtered by orgId
    - `listByProject` query: return autoFixPRs filtered by projectId
    - `hasDuplicateOpenFix` query: check if open/pending fix exists for same projectId + cveId + packageName
    - _Requirements: 7.4, 7.5, 7.6, 7.8, 7.9, 9.8, 9.9_

  - [ ]* 6.2 Write property test for auto-fix duplicate prevention (Property 7)
    - **Property 7: No duplicate auto-fix PRs for same CVE and package**
    - **Validates: Requirements 7.9**

- [x] 7. Implement GitHub webhook handler
  - [x] 7.1 Add HMAC-SHA256 webhook signature validation helper in `convex/convex/http.ts`
    - Implement `validateWebhookSignature(payload: string, signature: string, secret: string): Promise<boolean>` using `crypto.subtle.importKey` + `crypto.subtle.sign`
    - Compare computed HMAC hex digest against `X-Hub-Signature-256` header value
    - _Requirements: 6.1, 6.8, 10.2, 10.3_

  - [x] 7.2 Add `POST /api/v1/github/webhook` route in `convex/convex/http.ts`
    - Validate `X-Hub-Signature-256` header; return 401 on failure
    - Parse `X-GitHub-Event` header to determine event type
    - For `pull_request.opened` / `pull_request.synchronize`: resolve projectId from repo URL, create/update prChecks record, trigger scan workflow
    - For `pull_request.closed` (merged): update matching autoFixPRs record to `"merged"`
    - For unrecognized repos: return 200 and take no action
    - _Requirements: 6.1, 6.2, 6.8, 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8_

  - [x] 7.3 Add project API key authentication to `resolveIdentity` in `convex/convex/http.ts`
    - Detect `Bearer project:{key}` scheme in Authorization header
    - Look up project by API key via `projects.getByApiKey`
    - Return identity with resolved `projectId` and `orgId`
    - _Requirements: 14.3, 14.4, 14.6, 17.2, 17.5_

  - [x] 7.4 Add OPTIONS preflight route for `/api/v1/github/webhook`
    - _Requirements: 10.1_

  - [ ]* 7.5 Write property test for HMAC-SHA256 validation (Property 4)
    - **Property 4: HMAC-SHA256 webhook signature validation**
    - Generate random payloads and secrets, verify accept on correct signature and reject on incorrect
    - **Validates: Requirements 6.1, 6.8, 10.2, 10.3**

  - [ ]* 7.6 Write property test for webhook repo URL resolution (Property 12)
    - **Property 12: Webhook repo URL resolves to correct project**
    - **Validates: Requirements 10.7**

- [x] 8. Implement scheduled SCA scan function
  - [x] 8.1 Create `convex/convex/scheduledScans.ts` with scheduled function
    - Define a Convex cron job that runs every 24 hours
    - Iterate over projects with `autoFixEnabled !== false`
    - Stub the SCA analysis logic (to be filled with actual CVE detection)
    - Create autoFixPRs records for detected CVEs, checking for duplicates
    - _Requirements: 7.1, 7.2, 7.3, 7.7, 7.9_

- [x] 9. Checkpoint — Ensure all backend modules are correct
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Implement V2 Onboarding Wizard frontend
  - [x] 10.1 Create `OnboardingV2Page.tsx` at `sicario-frontend/src/pages/dashboard/OnboardingV2Page.tsx`
    - Multi-step wizard with three screens: Repo Connect, Waiting Room, Redirect
    - Step 1 (Repo Connect): GitHub App installation flow button, repository list after auth, optional framework dropdown, confirm button
    - Call `projects.createV2` mutation on confirm
    - _Requirements: 1.2, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 11.1_

  - [x] 10.2 Implement Waiting Room screen within `OnboardingV2Page.tsx`
    - Terminal-style animated loading screen with dark theme
    - Display CLI install command with copy button: `brew install EmmyCodes234/sicario-cli/sicario`
    - Display project API key with copy button
    - Display `sicario scan . --publish` command with copy button
    - Subscribe to project record via Convex live query; auto-redirect on `provisioningState === "active"`
    - Show error + retry on `provisioningState === "failed"`
    - Show "Skip — I'll scan later" link after 30 seconds
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 13.5_

  - [x] 10.3 Register `/dashboard/onboarding/v2` route in the router
    - Add route in the existing router configuration (likely in `App.tsx` or `DashboardLayout.tsx`)
    - Ensure existing routes are not modified
    - _Requirements: 11.1, 11.2_

  - [x] 10.4 Update post-login routing in `Auth.tsx` to redirect new users to V2 onboarding
    - After GitHub OAuth success, call `ensureOrg` mutation
    - If `isNew === true`, redirect to `/dashboard/onboarding/v2`
    - If `isNew === false`, redirect to `/dashboard`
    - _Requirements: 1.2, 1.4, 2.1, 2.2, 2.3, 2.4, 2.5_

  - [ ]* 10.5 Write property test for org provisioning (Property 1)
    - **Property 1: Org provisioning creates correct org name and admin membership**
    - **Validates: Requirements 2.1, 2.2**

  - [ ]* 10.6 Write property test for ensureOrg idempotency (Property 2)
    - **Property 2: ensureOrg is idempotent for existing members**
    - **Validates: Requirements 2.5**

- [x] 11. Implement dashboard V2 panels
  - [x] 11.1 Create `CoverageMap.tsx` at `sicario-frontend/src/components/dashboard/CoverageMap.tsx`
    - Use Convex live query on `projects.listByOrg` filtered by current org
    - Compute protected count (projects with effective `provisioningState === "active"`) vs total
    - Display progress bar + counts (e.g., "12 of 30 repos protected")
    - Empty state: prompt to connect a repository
    - Use dark theme with `#ADFF2F` accent
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 12.1, 12.2, 12.3_

  - [ ]* 11.2 Write property test for coverage count computation (Property 13)
    - **Property 13: Coverage count computation**
    - Generate random sets of projects with various provisioning states
    - Verify protected count equals projects with effective state `"active"`
    - **Validates: Requirements 5.1**

  - [x] 11.3 Create `PrChecksPanel.tsx` at `sicario-frontend/src/components/dashboard/PrChecksPanel.tsx`
    - Use Convex live query on `prChecks.listByOrg`
    - Group by status: Passed, Failed, Pending
    - Each entry shows: repo name, PR number, PR title, status badge, findings count, GitHub PR link
    - Empty state: explain how to enable PR blocking via GitHub App
    - _Requirements: 6.6, 6.9, 6.10, 12.1, 12.2, 12.3_

  - [x] 11.4 Create `AutoFixPanel.tsx` at `sicario-frontend/src/components/dashboard/AutoFixPanel.tsx`
    - Use Convex live query on `autoFixPRs.listByOrg`
    - Each entry shows: CVE ID, package name, version change (from → to), PR link, status badge
    - _Requirements: 7.5, 12.1, 12.2, 12.3_

  - [x] 11.5 Create `TrustBadge.tsx` at `sicario-frontend/src/components/dashboard/TrustBadge.tsx`
    - Shield icon + "Zero-Exfiltration: Telemetry Only" text
    - Hover/click shows popover explaining local-only code processing
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 11.6 Wire V2 panels into the dashboard
    - Add `CoverageMap`, `PrChecksPanel`, `AutoFixPanel` to `OverviewPage.tsx`
    - Add `TrustBadge` to `Sidebar.tsx` footer
    - Ensure Trust Badge is visible on every dashboard page
    - _Requirements: 5.4, 6.6, 7.5, 8.1, 8.4, 12.1, 12.2, 12.3, 12.4_

- [x] 12. Checkpoint — Ensure frontend components render correctly
  - Ensure all tests pass, ask the user if questions arise.

- [x] 13. Extend CLI with project API key auth
  - [x] 13.1 Add `store_project_api_key`, `get_project_api_key`, `clear_project_api_key` methods to `sicario-cli/src/auth/token_store.rs`
    - Store under keychain key `"project_api_key"`
    - Also check `SICARIO_PROJECT_API_KEY` environment variable in `get_project_api_key`
    - Follow existing `cloud_token` pattern with `#[cfg(test)]` in-memory support
    - _Requirements: 14.1, 14.2_

  - [x] 13.2 Add `resolve_auth_token` method to `sicario-cli/src/auth/auth_module.rs`
    - Priority: cloud OAuth token → project API key → error
    - When using project API key, format as `"Bearer project:{key}"`
    - When using cloud OAuth token, format as `"Bearer {token}"`
    - Error message: "Run `sicario login` or set `SICARIO_PROJECT_API_KEY`"
    - _Requirements: 14.2, 14.5, 14.6, 17.1, 17.2, 17.3_

  - [x] 13.3 Update `sicario-cli/src/convex/client.rs` to use `resolve_auth_token` for Authorization header
    - Ensure backward compatibility: existing OAuth flow continues to work
    - Project API key auth uses `Bearer project:{key}` scheme
    - _Requirements: 14.6, 17.1, 17.2, 17.4_

  - [ ]* 13.4 Write property test for token store round-trip (Property 11)
    - **Property 11: Token store round-trip for project API key**
    - Use `proptest` to generate random API key strings
    - Store via `store_project_api_key`, retrieve via `get_project_api_key`, assert equality
    - Use `TokenStore::in_memory()` for test isolation
    - **Validates: Requirements 14.1**

  - [ ]* 13.5 Write property test for auth token resolution priority (Property 10)
    - **Property 10: CLI auth token resolution priority**
    - Use `proptest` to generate random credential states (both, OAuth only, API key only, neither)
    - Verify correct priority and format
    - **Validates: Requirements 14.5, 14.6, 17.1, 17.2, 17.3**

- [x] 14. Update scan publish flow for project API key support
  - [x] 14.1 Modify the `/api/v1/scans` handler in `convex/convex/http.ts` to support project API key auth
    - When identity is resolved from a project API key, auto-populate `orgId` and `projectId` from the matched project record
    - Ensure scans without `projectId` continue to work (backward compatibility)
    - _Requirements: 17.2, 17.4, 17.5_

- [ ] 15. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document
- Unit tests validate specific examples and edge cases
- All Convex code is TypeScript; all CLI code is Rust
- The schema changes in task 1 are backward-compatible — existing records without new fields continue to work via read-time defaults
