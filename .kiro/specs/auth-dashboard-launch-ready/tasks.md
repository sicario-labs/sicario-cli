# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Full Table Scan, Missing Org-Scoping, N+1, and Unnecessary Mutation Bugs
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bugs exist
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bugs exist across all 11 defect categories
  - **Scoped PBT Approach**: For these deterministic bugs, scope properties to concrete failing cases:
    - Test `findings.list()` with no `orgId` parameter — call the query and assert it returns only findings for a specific org (will fail: returns all orgs' findings)
    - Test `analytics.overview()` with no `orgId` parameter — assert it scopes results to a single org (will fail: aggregates all orgs)
    - Test `teams.list()` with no `orgId` parameter — insert teams for org-A and org-B, assert only one org's teams are returned (will fail: returns both)
    - Test `scans.list()` enrichment — assert finding counts are computed without N+1 individual queries per scan (will fail: N+1 pattern exists)
    - Test `useCurrentOrg` behavior — for a user who already has an org, assert `ensureOrg` mutation is NOT called (will fail: mutation fires every load)
    - Test `findings.listAdvanced()` — assert it accepts `orgId` and scopes results (will fail: no `orgId` param exists)
    - Test `findings.listForExport()` — assert it accepts `orgId` and scopes results (will fail: no `orgId` param exists)
    - Test `findings.getAdjacentIds()` — assert it accepts `orgId` and scopes results (will fail: no `orgId` param exists)
    - Test Auth.tsx GitHub OAuth — assert a timeout indicator appears after 15 seconds (will fail: no timeout exists)
  - Run tests on UNFIXED code
  - **EXPECTED OUTCOME**: Tests FAIL (this is correct - it proves the bugs exist)
  - Document counterexamples found to understand root cause
  - Mark task complete when tests are written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.10, 1.11_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Unchanged Behavior for Non-Buggy Inputs
  - **IMPORTANT**: Follow observation-first methodology
  - Observe behavior on UNFIXED code for non-buggy inputs, then write property-based tests capturing observed behavior:
    - Observe: `findings.get({ id: "known-id" })` returns the correct finding via `by_findingId` index
    - Observe: `findings.getCriticalForScan({ scanId: "known-scan" })` returns critical findings via `by_scanId` index
    - Observe: `findings.triage({ id, triageState: "Fixed", userId, orgId })` enforces RBAC and updates the finding
    - Observe: `findings.bulkTriage({ ids, triageState: "Ignored", userId, orgId })` enforces RBAC and updates all findings
    - Observe: `findings.getTimeline({ id })` returns creation and triage events
    - Observe: `scans.get({ id })` resolves project/org names correctly
    - Observe: `scans.insert({ scanId, report, orgId, projectId })` inserts scan + findings correctly
    - Observe: `organizations.ensureOrg()` creates org + admin membership for first-time users (no existing membership)
    - Observe: `organizations.createOrg({ name })` creates a new org and admin membership
    - Observe: `memberships.list({ orgId, userId })` enforces admin-only access
    - Observe: `deviceAuth.createDeviceCode(...)` inserts a pending device code
    - Observe: `deviceAuth.approveDeviceCode({ userCode, userId })` transitions status to "approved"
    - Observe: `deviceAuth.consumeDeviceCode({ deviceCode, accessToken })` transitions status to "consumed"
    - Observe: PKCE `generate_code_verifier()` produces 43-128 char verifiers with valid charset
    - Observe: PKCE `compute_code_challenge(verifier)` is deterministic and base64url-encoded
    - Observe: `TokenStore` round-trip — store then retrieve returns identical token
  - Write property-based tests asserting these observed behaviors hold for generated inputs
  - Run tests on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10_

- [x] 3. Schema changes — Add composite indexes to findings table
  - [x] 3.1 Add composite indexes to `convex/convex/schema.ts`
    - Add `.index("by_orgId", ["orgId"])` to findings table
    - Add `.index("by_orgId_severity", ["orgId", "severity"])` to findings table
    - Add `.index("by_orgId_triageState", ["orgId", "triageState"])` to findings table
    - Add `.index("by_orgId_createdAt", ["orgId", "createdAt"])` to findings table
    - These indexes are required by all subsequent backend query rewrites
    - _Bug_Condition: isBugCondition(input) where input.compositeIndexExists = false_
    - _Expected_Behavior: Composite indexes exist for orgId+severity, orgId+triageState, orgId+createdAt_
    - _Preservation: Existing indexes (by_findingId, by_scanId, by_severity, by_triageState, by_fingerprint, by_createdAt) must remain unchanged_
    - _Requirements: 1.11, 2.11_

- [x] 4. Backend findings.ts optimization — Rewrite queries with orgId and indexes
  - [x] 4.1 Rewrite `findings.list()` in `convex/convex/findings.ts`
    - Add `orgId: v.string()` parameter
    - Replace `ctx.db.query("findings").order("desc").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))` as base query
    - Use `by_orgId_severity` composite index when single `severity` filter is provided
    - Use `by_orgId_triageState` composite index when single `triageState` filter is provided
    - Keep JS-level filtering for `confidenceMin` and `scanId`
    - _Bug_Condition: isBugCondition(input) where input.collectsEntireTable = true AND input.orgId IS NULL_
    - _Expected_Behavior: Query uses index, accepts orgId, returns same logical result scoped to org_
    - _Preservation: Pagination logic (page, perPage, offset, slice) must remain unchanged_
    - _Requirements: 1.2, 2.2, 1.6, 2.6_

  - [x] 4.2 Rewrite `findings.listAdvanced()` in `convex/convex/findings.ts`
    - Add `orgId: v.string()` parameter
    - Replace full table scan with `by_orgId` as base index
    - Use `by_orgId_severity` when single severity filter provided
    - Use `by_orgId_triageState` when single triageState filter provided
    - Keep JS-level filtering for multi-value arrays, search, confidence range, reachable, owaspCategory
    - Keep existing sort logic unchanged
    - _Bug_Condition: isBugCondition(input) where input.collectsEntireTable = true AND input.orgId IS NULL_
    - _Expected_Behavior: Query uses index, accepts orgId, returns same logical result scoped to org_
    - _Preservation: Sort logic, cursor pagination, and all filter combinations must produce equivalent results_
    - _Requirements: 1.2, 2.2, 1.6, 2.6_

  - [x] 4.3 Rewrite `findings.listForExport()` in `convex/convex/findings.ts`
    - Add `orgId: v.string()` parameter
    - Replace `ctx.db.query("findings").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))`
    - Use composite indexes when single severity or triageState filter provided
    - _Bug_Condition: isBugCondition(input) where input.collectsEntireTable = true AND input.orgId IS NULL_
    - _Expected_Behavior: Query uses index, accepts orgId, returns same logical result scoped to org_
    - _Requirements: 1.2, 2.2_

  - [x] 4.4 Rewrite `findings.getAdjacentIds()` in `convex/convex/findings.ts`
    - Add `orgId: v.string()` parameter
    - Replace `ctx.db.query("findings").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))`
    - Keep existing sort and adjacency logic unchanged
    - _Bug_Condition: isBugCondition(input) where input.collectsEntireTable = true AND input.orgId IS NULL_
    - _Expected_Behavior: Query uses index, accepts orgId, returns correct previousId/nextId scoped to org_
    - _Requirements: 1.2, 2.2_

- [x] 5. Backend analytics.ts optimization — Rewrite all 6 queries with orgId and indexes
  - [x] 5.1 Rewrite `analytics.overview()` in `convex/convex/analytics.ts`
    - Add `orgId: v.string()` parameter
    - Replace `ctx.db.query("findings").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`
    - Replace `ctx.db.query("scans").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`
    - Keep aggregation logic (counting by triageState, severity) unchanged
    - _Bug_Condition: isBugCondition(input) where input.collectsEntireTable = true AND input.orgId IS NULL_
    - _Expected_Behavior: Query uses index, accepts orgId, returns same aggregation scoped to org_
    - _Requirements: 1.1, 2.1, 1.6, 2.6_

  - [x] 5.2 Rewrite `analytics.trends()` in `convex/convex/analytics.ts`
    - Add `orgId: v.string()` parameter
    - Replace full table scan with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))`
    - Keep day-bucketing and trend calculation logic unchanged
    - _Bug_Condition: isBugCondition(input) where input.collectsEntireTable = true AND input.orgId IS NULL_
    - _Expected_Behavior: Query uses index, accepts orgId, returns same trend data scoped to org_
    - _Requirements: 1.1, 2.1_

  - [x] 5.3 Rewrite `analytics.mttr()` in `convex/convex/analytics.ts`
    - Add `orgId: v.string()` parameter
    - Replace full table scan with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))`
    - Keep MTTR calculation logic unchanged
    - _Bug_Condition: isBugCondition(input) where input.collectsEntireTable = true AND input.orgId IS NULL_
    - _Expected_Behavior: Query uses index, accepts orgId, returns same MTTR scoped to org_
    - _Requirements: 1.1, 2.1_

  - [x] 5.4 Rewrite `analytics.topVulnerableProjects()` in `convex/convex/analytics.ts`
    - Add `orgId: v.string()` parameter
    - Replace `ctx.db.query("projects").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`
    - Replace `ctx.db.query("findings").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`
    - Use `f.projectId` directly from findings instead of joining through scans table
    - Remove the scans table query entirely
    - Keep top-10 sorting and severity breakdown logic unchanged
    - _Bug_Condition: isBugCondition(input) where input.collectsEntireTable = true AND input.orgId IS NULL_
    - _Expected_Behavior: Query uses index, accepts orgId, returns same top-10 projects scoped to org_
    - _Requirements: 1.1, 1.4, 2.1, 2.4_

  - [x] 5.5 Rewrite `analytics.owaspCompliance()` in `convex/convex/analytics.ts`
    - Add `orgId: v.string()` parameter
    - Replace full table scan with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))`
    - Keep OWASP category aggregation and compliance score logic unchanged
    - _Bug_Condition: isBugCondition(input) where input.collectsEntireTable = true AND input.orgId IS NULL_
    - _Expected_Behavior: Query uses index, accepts orgId, returns same compliance data scoped to org_
    - _Requirements: 1.1, 2.1_

  - [x] 5.6 Rewrite `analytics.findingsByLanguage()` in `convex/convex/analytics.ts`
    - Add `orgId: v.string()` parameter
    - Replace `ctx.db.query("scans").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`
    - Replace `ctx.db.query("findings").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`
    - Keep language breakdown aggregation logic unchanged
    - _Bug_Condition: isBugCondition(input) where input.collectsEntireTable = true AND input.orgId IS NULL_
    - _Expected_Behavior: Query uses index, accepts orgId, returns same language stats scoped to org_
    - _Requirements: 1.1, 2.1_

- [x] 6. Backend scans.ts N+1 fix — Batch-load finding counts
  - [x] 6.1 Eliminate N+1 pattern in `scans.list()` in `convex/convex/scans.ts`
    - After paginating scans, instead of querying findings per scan individually, batch-load all findings for the org using `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`
    - Build a `scanId → count` map from the batch result
    - Look up counts from the map for each paginated scan
    - Keep existing pagination, filtering, and response shape unchanged
    - _Bug_Condition: isBugCondition(input) where input.enrichesFindingsPerScanIndividually = true_
    - _Expected_Behavior: Finding counts computed via single batch query, no N+1_
    - _Preservation: Response shape { page, per_page, total, items } must remain identical_
    - _Requirements: 1.3, 2.3_

- [x] 7. Backend teams.ts org-scoping — Add orgId parameter
  - [x] 7.1 Add org-scoping to `teams.list()` in `convex/convex/teams.ts`
    - Add `orgId: v.string()` parameter
    - Replace `ctx.db.query("teams").order("desc").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).order("desc").collect()`
    - Keep `mapTeam` helper unchanged
    - _Bug_Condition: isBugCondition(input) where input.queryName = 'teams.list' AND input.orgId IS NULL_
    - _Expected_Behavior: Query accepts orgId, uses by_orgId index, returns only teams for specified org_
    - _Preservation: Response shape and mapTeam mapping must remain identical_
    - _Requirements: 1.5, 2.5_

- [x] 8. Backend organizations.ts — Document N+1 trade-off, add hasOrg query
  - [x] 8.1 Document N+1 trade-off in `organizations.listUserOrgs()` in `convex/convex/organizations.ts`
    - Add a comment documenting that the Promise.all with indexed `.first()` lookups is the idiomatic Convex pattern for small N (< 10 memberships per user)
    - No code change needed — the N+1 here uses indexed point lookups and N is bounded
    - _Requirements: 1.9, 2.9_

  - [x] 8.2 Add `organizations.hasOrg` read query in `convex/convex/organizations.ts`
    - Create a new query `hasOrg` that checks if the authenticated user has any membership via `by_userId` index
    - Return `boolean` — `true` if at least one membership exists, `false` otherwise
    - This query will be used by `useCurrentOrg` to avoid unnecessary `ensureOrg` mutation calls
    - _Bug_Condition: isBugCondition(input) where input.userAlreadyHasOrg = true AND input.ensureOrgMutationFired = true_
    - _Expected_Behavior: Read query returns boolean without side effects_
    - _Requirements: 1.7, 2.7_

- [x] 9. Frontend useCurrentOrg.ts optimization — Use hasOrg before ensureOrg
  - [x] 9.1 Optimize `useCurrentOrg` hook in `sicario-frontend/src/hooks/useCurrentOrg.ts`
    - Add `useQuery(api.organizations.hasOrg)` to check org existence before calling `ensureOrg`
    - In the `useEffect`, only call `ensureOrgMutation()` when `hasOrg` returns `false`
    - Keep all other hook behavior unchanged (localStorage persistence, switchOrg, createOrg, fallback logic)
    - _Bug_Condition: isBugCondition(input) where input.userAlreadyHasOrg = true AND input.ensureOrgMutationFired = true_
    - _Expected_Behavior: ensureOrg mutation only fires when hasOrg returns false_
    - _Preservation: First-time users (hasOrg = false) must still get auto-created org_
    - _Requirements: 1.7, 2.7, 3.3_

- [x] 10. Frontend Auth.tsx hardening — OAuth timeout, per-button loading, rate-limit UI, password strength, redirect guard
  - [x] 10.1 Add GitHub OAuth timeout/retry in `sicario-frontend/src/pages/Auth.tsx`
    - Add `oauthTimedOut` state and a 15-second timeout timer in `handleGitHubSignIn`
    - When timeout fires, show "GitHub is taking longer than expected" with a "Try Again" button
    - On retry, reset state and re-initiate OAuth
    - Add `useEffect` cleanup to clear timeout on unmount
    - _Bug_Condition: isBugCondition(input) where input.githubOAuthInitiated AND input.hasTimeoutIndicator = false_
    - _Expected_Behavior: Timeout indicator appears after 15s with retry button_
    - _Requirements: 1.8, 2.8_

  - [x] 10.2 Add per-button loading states in `sicario-frontend/src/pages/Auth.tsx`
    - Replace single `loading` state with `githubLoading` and `passwordLoading`
    - GitHub button shows loading only when GitHub OAuth is in progress
    - Password submit button shows loading only when password auth is in progress
    - _Expected_Behavior: Each auth method tracks loading independently_
    - _Requirements: 2.8_

  - [x] 10.3 Add login rate-limit UI in `sicario-frontend/src/pages/Auth.tsx`
    - Track consecutive failed login attempts with a counter
    - After 3 consecutive failures, show cooldown message ("Too many attempts. Please wait 30 seconds.") with countdown timer
    - Prevent form submission during cooldown
    - Reset counter on successful login or mode switch
    - _Expected_Behavior: Rate-limit UI appears after 3 failed attempts with 30s cooldown_
    - _Requirements: 2.8_

  - [x] 10.4 Add password strength indicator in `sicario-frontend/src/pages/Auth.tsx`
    - Show visual strength meter (weak/medium/strong) below password field during `signUp` mode only
    - Use basic entropy checks: length ≥ 12, mixed case, numbers, symbols
    - _Expected_Behavior: Strength indicator shows correct level during signup_
    - _Requirements: 2.8_

  - [x] 10.5 Fix redirect guard in `sicario-frontend/src/pages/Auth.tsx`
    - Replace imperative `navigate('/dashboard', { replace: true })` inside render body with `<Navigate to="/dashboard" replace />` component
    - This avoids React warnings about state updates during render
    - _Expected_Behavior: Authenticated users redirected via Navigate component_
    - _Preservation: Redirect behavior must remain functionally identical_
    - _Requirements: 2.8, 3.2_

- [x] 11. Backend deviceAuth.ts hardening — Expiration check, input validation, cleanup
  - [x] 11.1 Add expiration check to `getDeviceCodeByDeviceCode` in `convex/convex/deviceAuth.ts`
    - In the query handler, after fetching the record, check if `Date.now() > record.expiresAt` and status is `"pending"`
    - Note: Convex queries cannot mutate, so log/return the expired status but cannot patch in a query
    - Alternative: Convert to a mutation or add expiration check in `consumeDeviceCode` and `approveDeviceCode`
    - Ensure the CLI receives a clear signal when the device code is expired
    - _Bug_Condition: isBugCondition(input) where input.deviceCodeExpired = true AND input.statusNotUpdatedToExpired = true_
    - _Expected_Behavior: Expired device codes are identified and signaled to the client_
    - _Requirements: 3.10_

  - [x] 11.2 Add input validation to `approveDeviceCode` in `convex/convex/deviceAuth.ts`
    - Validate that `userId` is non-empty before approving
    - Throw an error if `userId` is empty string
    - _Expected_Behavior: Empty userId rejected with clear error_
    - _Requirements: 3.10_

  - [x] 11.3 Add cleanup mutation for stale device codes in `convex/convex/deviceAuth.ts`
    - Add `cleanupExpiredDeviceCodes` mutation that deletes device codes older than 24 hours
    - Can be called periodically or as a Convex cron to prevent table bloat
    - _Expected_Behavior: Stale device codes cleaned up_
    - _Requirements: 3.10_

- [x] 12. Frontend query updates — Pass orgId to all queries
  - [x] 12.1 Update `ProjectsPage.tsx` to pass orgId to `teams.list` and `analytics.topVulnerableProjects`
    - Change `useQuery(api.teams.list)` to `useQuery(api.teams.list, orgId ? { orgId } : 'skip')`
    - Change `useQuery(api.analytics.topVulnerableProjects)` to `useQuery(api.analytics.topVulnerableProjects, orgId ? { orgId } : 'skip')`
    - _Expected_Behavior: Queries pass orgId and skip when orgId is not yet available_
    - _Requirements: 2.5, 2.6_

  - [x] 12.2 Update `OverviewPage.tsx` to pass orgId to all analytics queries
    - Import `useCurrentOrg` and get `orgId`
    - Change `useQuery(api.analytics.overview)` to `useQuery(api.analytics.overview, orgId ? { orgId } : 'skip')`
    - Change `useQuery(api.analytics.mttr)` to `useQuery(api.analytics.mttr, orgId ? { orgId } : 'skip')`
    - Change `useQuery(api.analytics.topVulnerableProjects)` to `useQuery(api.analytics.topVulnerableProjects, orgId ? { orgId } : 'skip')`
    - Update the `AiFixesCard` component to also pass orgId to `analytics.overview`
    - Update the `TopVulnerableProjects` component to also pass orgId to `analytics.topVulnerableProjects`
    - _Expected_Behavior: All analytics queries scoped to current org_
    - _Requirements: 1.10, 2.10, 2.6_

- [x] 13. CLI auth_module.rs hardening — Exponential backoff, network retry, polling progress, better errors
  - [x] 13.1 Add exponential backoff on `slow_down` in `poll_for_token` in `sicario-cli/src/auth/auth_module.rs`
    - On `"slow_down"` response, double the poll interval (capped at 30 seconds) instead of just sleeping an extra fixed interval
    - This follows RFC 8628 §3.5 more precisely
    - _Bug_Condition: isBugCondition(input) where input.noExponentialBackoffOnSlowDown = true_
    - _Expected_Behavior: Poll interval doubles on each slow_down, capped at 30s_
    - _Preservation: authorization_pending, access_denied, expired_token handling must remain unchanged_
    - _Requirements: 3.4_

  - [x] 13.2 Add network retry with backoff to `initiate_device_flow` in `sicario-cli/src/auth/auth_module.rs`
    - If the POST to `/oauth/device/code` fails due to a network error (not HTTP error), retry up to 3 times with exponential backoff (1s, 2s, 4s)
    - Only retry on network/connection errors, not on HTTP status errors
    - _Bug_Condition: isBugCondition(input) where input.noRetryOnNetworkError = true_
    - _Expected_Behavior: Network errors retried up to 3 times with backoff_
    - _Requirements: 3.4_

  - [x] 13.3 Add polling progress messages to `cloud_login` in `sicario-cli/src/auth/auth_module.rs`
    - Print a periodic status message every 30 seconds during polling: "Still waiting for browser authentication..."
    - Track elapsed time since polling started
    - _Bug_Condition: isBugCondition(input) where input.noPollingProgressFeedback = true_
    - _Expected_Behavior: Progress message printed every 30s during polling_
    - _Requirements: 3.4_

  - [x] 13.4 Improve error messages for token refresh in `sicario-cli/src/auth/auth_module.rs`
    - In `refresh_token()`, when refresh fails with 401, provide clearer message: "Your session has expired. Run `sicario login` to re-authenticate."
    - _Expected_Behavior: 401 refresh failure gives actionable error message_
    - _Requirements: 3.4_

- [x] 14. CLI token_store.rs hardening — Graceful keychain errors, token validation
  - [x] 14.1 Add graceful keychain error handling in `sicario-cli/src/auth/token_store.rs`
    - When `Entry::new()` or `set_password()` / `get_password()` fails, provide a fallback message: "Could not access system keychain. If running in CI, use SICARIO_API_TOKEN environment variable instead."
    - Wrap keychain errors with context using `anyhow::Context`
    - _Expected_Behavior: Keychain failures produce helpful error with CI workaround_
    - _Requirements: 3.4_

  - [x] 14.2 Add token sanity validation on retrieval in `sicario-cli/src/auth/token_store.rs`
    - When `get_access_token()`, `get_cloud_token()`, or `get_refresh_token()` returns a token, validate it is non-empty and has reasonable length (> 0, < 10000 chars)
    - Return an error if the token fails sanity checks instead of returning corrupted data
    - _Expected_Behavior: Corrupted/empty tokens rejected with clear error_
    - _Requirements: 3.4_

- [x] 15. Verify bug condition exploration test now passes
  - [x] 15.1 Re-run bug condition exploration test
    - **Property 1: Expected Behavior** - Indexed Query Execution with Org-Scoping
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bugs are fixed)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.10, 2.11_

  - [x] 15.2 Re-run preservation tests
    - **Property 2: Preservation** - Unchanged Behavior for Non-Buggy Inputs
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all tests still pass after fix (no regressions)

- [x] 16. Checkpoint - Ensure all tests pass
  - Run the full test suite to verify all exploration and preservation tests pass
  - Verify no TypeScript compilation errors in `convex/` and `sicario-frontend/`
  - Verify no Rust compilation errors in `sicario-cli/`
  - Ensure all tests pass, ask the user if questions arise
