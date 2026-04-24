# Auth & Dashboard Launch-Ready Bugfix Design

## Overview

The Sicario Cloud backend and frontend have 11 interrelated performance and security defects that make the system unsuitable for production launch. The core issues are: (1) backend Convex queries perform full table scans via `.collect()` then filter in JavaScript instead of using database indexes, (2) several queries lack org-scoping and leak cross-tenant data, (3) the `useCurrentOrg` hook fires a write mutation on every page load even when the org already exists, (4) the GitHub OAuth flow has no timeout/retry UX, and (5) N+1 query patterns exist in `scans.list()` and `organizations.listUserOrgs()`. The fix strategy is to add composite indexes to the schema, rewrite queries to use `.withIndex()`, add org-scoping parameters, optimize the frontend auth hook, and add OAuth timeout UX.

## Glossary

- **Bug_Condition (C)**: Any query or UI interaction that triggers a full table scan, cross-tenant data leak, unnecessary mutation, N+1 pattern, or missing timeout UX
- **Property (P)**: Queries use database indexes, are org-scoped, avoid N+1 patterns; the auth hook avoids unnecessary writes; OAuth has timeout/retry UX
- **Preservation**: Existing single-record lookups, auth flows, RBAC enforcement, device auth, triage operations, and UI rendering must remain unchanged
- **`.collect()`**: Convex method that loads all matching documents into memory — the root cause of full table scans
- **`.withIndex()`**: Convex method that uses a database index to filter at the query level before loading documents
- **N+1 pattern**: Executing N additional queries inside a loop after an initial query, causing linear query growth
- **Composite index**: A database index on multiple fields (e.g., `["orgId", "severity"]`) enabling efficient multi-field filtering

## Bug Details

### Bug Condition

The bugs manifest across the backend and frontend when queries load entire tables into memory, lack org-scoping, fire unnecessary mutations, exhibit N+1 patterns, or provide no timeout UX for OAuth.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type SystemRequest
  OUTPUT: boolean

  // Category 1: Full table scan queries (no index used for primary filter)
  IF input.queryName IN ['analytics.overview', 'analytics.trends', 'analytics.mttr',
     'analytics.topVulnerableProjects', 'analytics.owaspCompliance',
     'analytics.findingsByLanguage', 'findings.list', 'findings.listAdvanced',
     'findings.listForExport', 'findings.getAdjacentIds']
     AND input.collectsEntireTable = true
  THEN RETURN true

  // Category 2: Missing org-scoping (cross-tenant data leak)
  IF input.queryName IN ['teams.list', 'analytics.overview', 'analytics.trends',
     'analytics.mttr', 'analytics.topVulnerableProjects',
     'analytics.owaspCompliance', 'analytics.findingsByLanguage',
     'findings.list', 'findings.listAdvanced', 'findings.listForExport',
     'findings.getAdjacentIds']
     AND input.orgId IS NULL
  THEN RETURN true

  // Category 3: N+1 query patterns
  IF input.queryName = 'scans.list'
     AND input.enrichesFindingsPerScanIndividually = true
  THEN RETURN true

  IF input.queryName = 'organizations.listUserOrgs'
     AND input.queriesOrgPerMembershipIndividually = true
  THEN RETURN true

  // Category 4: Unnecessary mutation on page load
  IF input.type = 'dashboardNavigation'
     AND input.userAlreadyHasOrg = true
     AND input.ensureOrgMutationFired = true
  THEN RETURN true

  // Category 5: Missing OAuth timeout UX
  IF input.type = 'githubOAuthInitiated'
     AND input.hasTimeoutIndicator = false
  THEN RETURN true

  // Category 6: Missing composite indexes
  IF input.queryName IN ['findings.*']
     AND input.filterFields INTERSECT ['orgId+severity', 'orgId+triageState', 'orgId+createdAt']
     AND input.compositeIndexExists = false
  THEN RETURN true

  // Category 7: Login/Signup UX gaps
  IF input.type = 'passwordAuthSubmit'
     AND (input.noRateLimitUI = true
          OR input.noPasswordStrengthIndicator = true
          OR input.singleLoadingStateForAllMethods = true)
  THEN RETURN true

  // Category 8: CLI auth robustness gaps
  IF input.type = 'cliDeviceFlow'
     AND (input.noExponentialBackoffOnSlowDown = true
          OR input.noRetryOnNetworkError = true
          OR input.noPollingProgressFeedback = true)
  THEN RETURN true

  // Category 9: Device auth backend gaps
  IF input.queryName = 'deviceAuth.getDeviceCodeByDeviceCode'
     AND input.deviceCodeExpired = true
     AND input.statusNotUpdatedToExpired = true
  THEN RETURN true

  RETURN false
END FUNCTION
```

### Examples

- `analytics.overview({})` loads ALL findings + ALL scans into memory via `.collect()`, then iterates in JS — O(n) per call, no org filter
- `findings.listAdvanced({ severity: ["Critical"] })` collects the entire findings table, then filters in JS — should use `by_orgId_severity` composite index
- `teams.list()` takes no arguments and returns every team across all orgs — cross-tenant data leak
- `scans.list({ page: 1, perPage: 20 })` fetches 20 scans, then for each scan queries ALL its findings just to count them — N+1 pattern
- `useCurrentOrg` calls `ensureOrg()` mutation on every dashboard page navigation even when the user already has an org
- GitHub OAuth button click sets `loading=true` but provides no timeout indicator or retry if GitHub is slow

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Single-record lookups via existing indexes (`by_findingId`, `by_scanId`, `by_fingerprint`, `by_projectId`, `by_teamId`) must continue to work
- `findings.triage()` and `findings.bulkTriage()` with RBAC enforcement must continue to work
- `findings.getCriticalForScan()` using `by_scanId` index must continue to work
- `findings.getTimeline()` must continue to work
- `scans.insert()` must continue to insert scan records and findings correctly
- `scans.get()` must continue to resolve project/org names correctly
- GitHub OAuth and email/password authentication must continue to work
- First-time users with no org must still get auto-created org via `ensureOrg`
- `memberships.*` CRUD operations with admin-only RBAC must continue to work
- `organizations.createOrg()` must continue to work
- Device auth flow (`deviceAuth.ts`) must continue to work
- OrgSwitcher component must continue to persist active org to localStorage
- Dashboard layout (sidebar, header, command palette, keyboard shortcuts, error boundary) must continue to render correctly
- CLI OAuth Device Flow with PKCE must continue to work

**Scope:**
All inputs that do NOT involve the 11 identified defects should be completely unaffected. This includes single-record lookups by ID, write mutations, RBAC checks, device auth, and UI rendering.

## Hypothesized Root Cause

Based on the code analysis, the root causes are:

1. **Missing composite indexes on findings table**: The schema only has single-field indexes (`by_severity`, `by_triageState`, `by_createdAt`) but no composite indexes combining `orgId` with these fields. This forces queries to either use a single index and filter the rest in JS, or skip indexes entirely.

2. **Queries use `.collect()` without index filtering**: `findings.list()`, `findings.listAdvanced()`, `findings.listForExport()`, `findings.getAdjacentIds()`, and all `analytics.*` queries call `ctx.db.query("findings").collect()` which loads the entire table into memory, then filter with JS `.filter()`.

3. **Missing `orgId` parameter on queries**: `teams.list()`, all `analytics.*` queries, and all `findings.*` list queries accept no `orgId` parameter, so they cannot scope data to a single organization.

4. **N+1 in `scans.list()`**: After paginating scans, the code runs `Promise.all(paged.map(async (s) => { const findings = await ctx.db.query("findings").withIndex("by_scanId"...).collect(); }))` — one findings query per scan in the page.

5. **N+1 in `organizations.listUserOrgs()`**: After fetching memberships, the code runs `Promise.all(memberships.map(async (m) => { const org = await ctx.db.query("organizations").withIndex("by_orgId"...).first(); }))` — one org query per membership.

6. **`useCurrentOrg` always calls `ensureOrg` mutation**: The hook fires `ensureOrgMutation()` on every authenticated page load without first checking if the user already has an org via a read query.

7. **No OAuth timeout UX in `Auth.tsx`**: `handleGitHubSignIn` sets `loading=true` and calls `signIn("github", ...)` but has no timeout, no progress indicator for slow responses, and no retry mechanism.

## Correctness Properties

Property 1: Bug Condition - Indexed Query Execution

_For any_ backend query where the bug condition holds (query previously performed a full table scan via `.collect()` without index), the fixed query SHALL use `.withIndex()` to filter at the database level, accept an `orgId` parameter for org-scoping, and return the same logical result set (scoped to the given org) as the original query would have returned for that org's data.

**Validates: Requirements 2.1, 2.2, 2.4, 2.6, 2.10, 2.11**

Property 2: Preservation - Unchanged Behavior for Non-Buggy Inputs

_For any_ input where the bug condition does NOT hold (single-record lookups, write mutations, RBAC enforcement, device auth, first-time org creation, UI rendering), the fixed code SHALL produce exactly the same behavior as the original code, preserving all existing functionality.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `convex/convex/schema.ts`

**Specific Changes**:
1. **Add composite indexes to findings table**:
   - `.index("by_orgId", ["orgId"])` — base org-scoped index
   - `.index("by_orgId_severity", ["orgId", "severity"])` — for org+severity filtering
   - `.index("by_orgId_triageState", ["orgId", "triageState"])` — for org+triageState filtering
   - `.index("by_orgId_createdAt", ["orgId", "createdAt"])` — for org+date sorting/filtering

---

**File**: `convex/convex/findings.ts`

**Function**: `list()`

**Specific Changes**:
1. **Add `orgId` parameter** (required `v.string()`)
2. **Replace full table scan** with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))` as the base query
3. **When `severity` filter is provided**, use `.withIndex("by_orgId_severity", q => q.eq("orgId", args.orgId).eq("severity", args.severity))` instead
4. **When `triageState` filter is provided**, use `.withIndex("by_orgId_triageState", q => q.eq("orgId", args.orgId).eq("triageState", args.triageState))` instead
5. **Keep remaining JS filters** for `confidenceMin` and `scanId` (low-cardinality filters applied after index narrowing)

**Function**: `listAdvanced()`

**Specific Changes**:
1. **Add `orgId` parameter** (required `v.string()`)
2. **Replace full table scan** with index-based query using `by_orgId` as the base
3. **When single severity filter**, use `by_orgId_severity` composite index
4. **When single triageState filter**, use `by_orgId_triageState` composite index
5. **Keep JS-level filtering** for multi-value severity/triageState arrays, search, confidence range, reachable, owaspCategory (applied after index narrowing to org)

**Function**: `listForExport()`

**Specific Changes**:
1. **Add `orgId` parameter** (required `v.string()`)
2. **Replace full table scan** with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))`
3. **Use composite indexes** when single severity or triageState filter is provided

**Function**: `getAdjacentIds()`

**Specific Changes**:
1. **Add `orgId` parameter** (required `v.string()`)
2. **Replace full table scan** with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))`

---

**File**: `convex/convex/analytics.ts`

**Function**: `overview()`

**Specific Changes**:
1. **Add `orgId` parameter** (required `v.string()`)
2. **Replace** `ctx.db.query("findings").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`
3. **Replace** `ctx.db.query("scans").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`

**Function**: `trends()`

**Specific Changes**:
1. **Add `orgId` parameter** (required `v.string()`)
2. **Replace** full table scan with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))`

**Function**: `mttr()`

**Specific Changes**:
1. **Add `orgId` parameter** (required `v.string()`)
2. **Replace** full table scan with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))`

**Function**: `topVulnerableProjects()`

**Specific Changes**:
1. **Add `orgId` parameter** (required `v.string()`)
2. **Replace** `ctx.db.query("projects").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`
3. **Replace** `ctx.db.query("findings").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`
4. **Remove** the scans table query entirely — use `f.projectId` directly from findings (findings already have `projectId` field) instead of joining through scans
5. **Build project lookup** from the org-scoped projects query

**Function**: `owaspCompliance()`

**Specific Changes**:
1. **Add `orgId` parameter** (required `v.string()`)
2. **Replace** full table scan with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))`

**Function**: `findingsByLanguage()`

**Specific Changes**:
1. **Add `orgId` parameter** (required `v.string()`)
2. **Replace** `ctx.db.query("scans").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`
3. **Replace** `ctx.db.query("findings").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect()`

---

**File**: `convex/convex/scans.ts`

**Function**: `list()`

**Specific Changes**:
1. **Eliminate N+1 pattern**: Instead of querying findings per scan, batch-load all findings for the page's scan IDs in a single pass
2. **Approach**: After paginating scans, collect all `scanId` values, query findings once using `by_orgId` index scoped to the org, then group counts by `scanId` in JS
3. **Alternative simpler approach**: Query all findings for the org, build a `scanId → count` map, then look up counts — avoids N individual queries

---

**File**: `convex/convex/teams.ts`

**Function**: `list()`

**Specific Changes**:
1. **Add `orgId` parameter** (required `v.string()`)
2. **Replace** `ctx.db.query("teams").order("desc").collect()` with `.withIndex("by_orgId", q => q.eq("orgId", args.orgId)).order("desc").collect()`

---

**File**: `convex/convex/organizations.ts`

**Function**: `listUserOrgs()`

**Specific Changes**:
1. **Optimize N+1 pattern**: The current approach queries organizations individually per membership. Since the number of memberships per user is typically small (< 10), this is a low-severity N+1. However, we can optimize by noting that `organizations` table has a `by_orgId` index and each lookup is `.first()` — these are already indexed point lookups. The N+1 here is acceptable for small N but can be documented as a known trade-off.
2. **Alternative**: If Convex supported batch `getMany`, we'd use it. Since it doesn't, the current `Promise.all` with indexed `.first()` lookups is the idiomatic Convex pattern for small N. Keep as-is but add a comment documenting the trade-off.

---

**File**: `sicario-frontend/src/hooks/useCurrentOrg.ts`

**Specific Changes**:
1. **Add a read query** to check if the user already has an org before calling `ensureOrg` mutation
2. **Create a new Convex query** `organizations.hasOrg` that checks membership existence via `by_userId` index and returns `boolean`
3. **In the `useEffect`**: Use `useQuery(api.organizations.hasOrg)` to check org existence. Only call `ensureOrgMutation()` when `hasOrg` returns `false`.
4. **This avoids** firing a write mutation on every page load for returning users

---

**File**: `sicario-frontend/src/pages/Auth.tsx`

**Function**: `handleGitHubSignIn()`

**Specific Changes**:
1. **Add a timeout timer** (15 seconds) that starts when GitHub OAuth is initiated
2. **Add state**: `oauthTimedOut` boolean
3. **When timeout fires**: Show a message like "GitHub is taking longer than expected" with a "Try Again" button
4. **On retry**: Reset state and re-initiate the OAuth flow
5. **Clear timeout** on successful auth or component unmount

**Function**: `handlePasswordSubmit()` — Login/Signup Hardening

**Specific Changes**:
1. **Add rate-limit awareness**: After 3 consecutive failed login attempts, show a cooldown message ("Too many attempts. Please wait 30 seconds.") with a countdown timer, preventing rapid brute-force attempts from the UI side
2. **Add password strength indicator on signup**: Show a visual strength meter (weak/medium/strong) below the password field during `signUp` mode using basic entropy checks (length ≥ 12, mixed case, numbers, symbols)
3. **Add form-level validation before submit**: Validate email format client-side before calling `signIn()` — currently the form relies on HTML5 `required` and `type="email"` but has no explicit JS validation that could provide better error messages
4. **Improve error messages**: Replace generic "Invalid email or password" with more specific guidance: "Check your email address" for format issues, keep generic message for actual auth failures (to avoid user enumeration)
5. **Add loading state per-button**: Track which auth method is loading (`githubLoading` vs `passwordLoading`) so the user can see which flow is in progress — currently a single `loading` state disables all buttons
6. **Redirect guard fix**: Replace the imperative `navigate('/dashboard', { replace: true })` inside the render body (which fires on every render when `isAuthenticated`) with a `<Navigate>` component to avoid React warnings about state updates during render

**General Auth Page Hardening**:
1. **Add `useEffect` cleanup** for the GitHub OAuth timeout timer to prevent memory leaks on unmount
2. **Disable form submission while loading**: The submit button is already disabled, but also prevent Enter key re-submission by checking `loading` state in `handlePasswordSubmit`

---

**File**: `convex/convex/deviceAuth.ts` — Device Auth Backend Hardening

**Specific Changes**:
1. **Add expiration check to `getDeviceCodeByDeviceCode`**: Currently the query returns the device code record without checking if it's expired. Add a check: if `Date.now() > record.expiresAt` and status is still `"pending"`, patch status to `"expired"` and return the expired record so the CLI gets a clear signal
2. **Add cleanup for stale device codes**: Add a new mutation `cleanupExpiredDeviceCodes` that can be called periodically (or as a Convex cron) to delete device codes older than 24 hours, preventing table bloat
3. **Add input validation to `approveDeviceCode`**: Validate that `userId` is non-empty before approving — currently accepts any string including empty

---

**File**: `sicario-cli/src/auth/auth_module.rs` — CLI Auth Hardening

**Specific Changes**:
1. **Add exponential backoff to `poll_for_token`**: Currently uses a fixed `poll_interval` for every retry. On `"slow_down"` response, double the interval (capped at 30 seconds) instead of just sleeping an extra interval — this follows RFC 8628 §3.5 more precisely
2. **Add connection retry with backoff to `initiate_device_flow`**: If the initial POST to `/oauth/device/code` fails due to a network error (not an HTTP error), retry up to 3 times with exponential backoff (1s, 2s, 4s) before failing — currently a single network failure aborts the entire flow
3. **Add timeout feedback to `cloud_login`**: The current `cloud_login` method prints the verification URI and user code but provides no progress feedback during polling. Add a periodic status message every 30 seconds: "Still waiting for browser authentication..." so the user knows the CLI hasn't hung
4. **Improve error messages for token refresh**: In `refresh_token()`, when the refresh fails with 401, provide a clearer message: "Your session has expired. Run `sicario login` to re-authenticate." instead of the generic status code error

**File**: `sicario-cli/src/auth/token_store.rs` — Token Store Hardening

**Specific Changes**:
1. **Add graceful keychain error handling**: Currently, if the system keychain is locked or unavailable (common in headless CI environments), `Entry::new()` or `set_password()` will return an error that propagates as a generic `anyhow` error. Add a fallback message: "Could not access system keychain. If running in CI, use SICARIO_API_TOKEN environment variable instead."
2. **Add token validation on retrieval**: When `get_access_token()` or `get_cloud_token()` returns a token, do a basic sanity check (non-empty, reasonable length) before returning — prevents returning corrupted keychain entries

**File**: `sicario-cli/src/auth/pkce.rs` — PKCE Hardening (Preservation)

**Specific Changes**:
1. **No code changes needed** — the PKCE implementation is correct per RFC 7636. The existing tests cover verifier length, charset, challenge determinism, and base64url encoding. This file is preservation-only.

---

**File**: `sicario-frontend/src/pages/dashboard/ProjectsPage.tsx`

**Specific Changes**:
1. **Update `teams.list` call** to pass `orgId`: `useQuery(api.teams.list, orgId ? { orgId } : 'skip')`
2. **Update `analytics.topVulnerableProjects` call** to pass `orgId`: `useQuery(api.analytics.topVulnerableProjects, orgId ? { orgId } : 'skip')`

---

**File**: `sicario-frontend/src/pages/dashboard/OverviewPage.tsx`

**Specific Changes**:
1. **Update all analytics query calls** to pass `orgId` from `useCurrentOrg()`
2. **Update** `useQuery(api.analytics.overview)` → `useQuery(api.analytics.overview, orgId ? { orgId } : 'skip')`
3. **Update** `useQuery(api.analytics.mttr)` → `useQuery(api.analytics.mttr, orgId ? { orgId } : 'skip')`
4. **Update** `useQuery(api.analytics.topVulnerableProjects)` → `useQuery(api.analytics.topVulnerableProjects, orgId ? { orgId } : 'skip')`

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bugs on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bugs BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write tests that call the unfixed backend queries and assert they use indexes / are org-scoped. Run these tests on the UNFIXED code to observe failures and understand the root cause.

**Test Cases**:
1. **Full Table Scan Test**: Call `analytics.overview({})` and verify it loads all findings regardless of org — demonstrates the full table scan and missing org-scoping (will fail on unfixed code)
2. **Cross-Tenant Leak Test**: Insert findings for org-A and org-B, call `teams.list()` and verify it returns teams from both orgs — demonstrates cross-tenant data leak (will fail on unfixed code)
3. **N+1 Scan Test**: Call `scans.list({ page: 1, perPage: 5 })` with 5 scans each having findings, count the number of findings queries executed — demonstrates N+1 pattern (will fail on unfixed code)
4. **Unnecessary Mutation Test**: Simulate `useCurrentOrg` hook behavior for a user who already has an org, verify `ensureOrg` mutation is called — demonstrates unnecessary write (will fail on unfixed code)

**Expected Counterexamples**:
- `analytics.overview({})` returns findings from all orgs, not scoped to any single org
- `teams.list()` returns teams from multiple orgs
- `scans.list()` executes N+1 findings queries
- `ensureOrg` mutation fires on every page load even for existing users

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  result := fixedFunction(input)
  ASSERT result.allRecordsBelongToOrg(input.orgId) = true
  ASSERT result.queryUsedIndex = true
  ASSERT result.noFullTableScan = true
  ASSERT result.logicallyEquivalentToOriginal(input.orgId) = true
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT originalFunction(input) = fixedFunction(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code first for single-record lookups, triage operations, and auth flows, then write property-based tests capturing that behavior.

**Test Cases**:
1. **Single-Record Lookup Preservation**: Verify `findings.get()`, `scans.get()`, `projects.get()` continue to return correct results via existing indexes
2. **Triage Preservation**: Verify `findings.triage()` and `findings.bulkTriage()` continue to enforce RBAC and update findings correctly
3. **Auth Flow Preservation**: Verify GitHub OAuth and email/password sign-in continue to work
4. **First-Time User Preservation**: Verify `ensureOrg` still creates org for users with no existing membership
5. **Device Auth Preservation**: Verify device code creation, approval, and consumption continue to work
6. **Scan Insert Preservation**: Verify `scans.insert()` continues to insert scan records and findings correctly

### Unit Tests

- Test each analytics query with `orgId` parameter returns only data for that org
- Test `findings.list()` with `orgId` uses index and returns correct paginated results
- Test `teams.list({ orgId })` returns only teams for the specified org
- Test `scans.list()` returns correct `findings_count` without N+1 pattern
- Test `useCurrentOrg` hook does not call `ensureOrg` when user already has an org
- Test Auth.tsx GitHub OAuth timeout shows retry button after 15 seconds
- Test composite indexes exist and are used for `orgId+severity`, `orgId+triageState`, `orgId+createdAt` queries
- Test Auth.tsx login rate-limit UI shows cooldown after 3 failed attempts
- Test Auth.tsx signup password strength indicator shows correct levels
- Test Auth.tsx separate loading states for GitHub vs password auth
- Test Auth.tsx redirect guard uses `<Navigate>` instead of imperative `navigate()`
- Test `deviceAuth.approveDeviceCode` rejects empty userId
- Test `deviceAuth.getDeviceCodeByDeviceCode` marks expired codes
- Test CLI `poll_for_token` uses exponential backoff on `slow_down` response
- Test CLI `initiate_device_flow` retries on network errors up to 3 times
- Test CLI `cloud_login` prints periodic status messages during polling
- Test CLI `token_store` provides helpful error when keychain is unavailable
- Test CLI `token_store` validates token sanity on retrieval

### Property-Based Tests

- Generate random org IDs and finding sets, verify all analytics queries return only findings belonging to the specified org
- Generate random filter combinations for `findings.listAdvanced()`, verify results are equivalent to full-scan-then-filter but scoped to org
- Generate random scan/finding configurations, verify `scans.list()` returns correct finding counts
- Generate random user/org configurations, verify `useCurrentOrg` only calls `ensureOrg` when no org exists
- Generate random PKCE verifiers, verify code_challenge is deterministic and base64url-encoded (preservation)
- Generate random token strings, verify token_store round-trip (store → retrieve) returns identical tokens
- Generate random device code expiration times, verify expired codes are correctly identified

### Integration Tests

- Test full dashboard load flow: auth → org resolution → overview page with all analytics queries passing `orgId`
- Test project creation flow with org-scoped `teams.list()` and `analytics.topVulnerableProjects()`
- Test org switching updates all queries to use the new `orgId`
- Test GitHub OAuth timeout and retry flow end-to-end
- Test full login flow: email/password sign-in → redirect to dashboard → org resolution
- Test full signup flow: email/password sign-up → auto-org creation → redirect to dashboard
- Test CLI auth flow: `initiate_device_flow` → `poll_for_token` → token stored in keychain
- Test CLI cloud login flow: `cloud_login` → device code display → polling → token stored
- Test CLI token refresh flow: expired token → `refresh_token()` → new token stored
- Test device auth lifecycle: create → approve → consume → verify consumed status
