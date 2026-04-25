# User Identity Propagation Bugfix Design

## Overview

When users authenticate via the CLI device auth flow (`sicario login`), their display name and email are lost at the `approveDeviceCode` boundary. The frontend DeviceAuth page passes only the raw `tokenIdentifier` as `userId`, and the `deviceCodes` table has no fields for name or email. Downstream, `resolveIdentity` returns a bare `{ subject }` for device-auth sessions, `whoami` reports "unknown", and `ensureOrg` uses the raw Convex internal hash (e.g., `ks7dtkrb3e1m5w9cbkbprjvrn585fmhp`) as the org display name. This also affects dashboard-only users whose `identity.name` and `identity.email` happen to be absent — the `split("|").pop()` fallback produces a hash, not a human-readable name.

The fix propagates name and email through the device code record, enriches `resolveIdentity` for CLI sessions, and adds self-healing to `ensureOrg` so existing hash-named orgs get corrected on next login.

## Glossary

- **Bug_Condition (C)**: The condition that triggers the bug — device-auth sessions lack name/email in the device code record, and `ensureOrg` falls back to a raw hash for the org display name
- **Property (P)**: The desired behavior — device-auth sessions carry name and email through to `resolveIdentity` and `whoami`; org names use human-readable display names
- **Preservation**: Existing Convex Auth JWT sessions, PKCE verification, device code expiration, project API key auth, and all non-device-auth flows must remain unchanged
- **`approveDeviceCode`**: Mutation in `convex/convex/deviceAuth.ts` that marks a device code as approved and associates a userId
- **`getByAccessToken`**: Query in `convex/convex/deviceAuth.ts` that looks up a consumed device code by its opaque `sic_` token
- **`resolveIdentity`**: Helper in `convex/convex/http.ts` that resolves the authenticated user from either a Convex Auth JWT or an opaque `sic_` token
- **`ensureOrg`**: Mutation in `convex/convex/organizations.ts` that auto-creates a personal org + admin membership for first-time users
- **`DeviceAuth`**: React page at `sicario-frontend/src/pages/DeviceAuth.tsx` that renders the device code approval UI

## Bug Details

### Bug Condition

The bug manifests in two related scenarios:

1. **Device auth identity loss**: When a user approves a device code, the frontend passes only `tokenIdentifier` as `userId`. The `approveDeviceCode` mutation stores no name or email. Later, `getByAccessToken` returns only `{ userId }`, so `resolveIdentity` returns `{ subject: record.userId }` with no name or email. The `whoami` endpoint then falls through all its lookups and reports "unknown".

2. **Hash-based org names**: When `ensureOrg` creates a new org, it computes `displayName = identity.name ?? identity.email ?? userId` where `userId = identity.tokenIdentifier.split("|").pop()`. For device-auth users (and any user whose JWT lacks `name` and `email`), this produces a raw hash like `ks7dtkrb3e1m5w9cbkbprjvrn585fmhp`, resulting in org names like `ks7dtkrb3e1m5w9cbkbprjvrn585fmhp's Organization`.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type { authMethod, token, identityFields, orgCreation }
  OUTPUT: boolean

  // Case 1: Device auth session with missing identity fields
  IF input.authMethod = "device_auth"
     AND input.token starts with "sic_"
     AND (input.deviceCodeRecord.userName IS NULL
          AND input.deviceCodeRecord.userEmail IS NULL)
  THEN RETURN true

  // Case 2: Org creation where display name is a raw hash
  IF input.orgCreation = true
     AND input.identity.name IS NULL
     AND input.identity.email IS NULL
     AND displayName = input.identity.tokenIdentifier.split("|").pop()
     AND looksLikeHash(displayName)
  THEN RETURN true

  RETURN false
END FUNCTION
```

### Examples

- **Device auth whoami**: User "Jane Doe" (jane@example.com) approves device code → CLI calls `/api/v1/whoami` with `sic_` token → response returns `{ username: "unknown", email: "" }` instead of `{ username: "Jane Doe", email: "jane@example.com" }`
- **Device auth org creation**: Same user's first login triggers `ensureOrg` → org created as `ks7dtkrb3e1m5w9cbkbprjvrn585fmhp's Organization` instead of `Jane Doe's Organization`
- **Dashboard signup**: New user signs up via email/password, JWT has `name: null` → `ensureOrg` creates org as `abc123hash's Organization` instead of using their email
- **Existing hash org**: User who already has `ks7dtkrb3e1m5w9cbkbprjvrn585fmhp's Organization` logs in again with name now available → org name stays as the hash (no self-healing)

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Convex Auth JWT sessions must continue to resolve identity with name and email from JWT claims
- PKCE S256 challenge verification during token exchange must work exactly as before
- Device code expiration, denial, and status transitions must remain unchanged
- `ensureOrg` must continue to be idempotent — returning existing orgId for users who already have a membership
- Project API key authentication (`project:<key>`) must continue to resolve correctly
- Mouse/keyboard interactions on the DeviceAuth approval page must continue to work
- The `cleanupExpiredDeviceCodes` cron must continue to function

**Scope:**
All inputs that do NOT involve device-auth identity resolution or org name display should be completely unaffected by this fix. This includes:
- Standard browser-session API calls authenticated via Convex Auth JWT
- Project API key authenticated requests
- Unauthenticated requests (which should still return 401)
- Device code creation, polling, and PKCE verification flows

## Hypothesized Root Cause

Based on the bug description and code analysis, the root causes are:

1. **Missing schema fields**: The `deviceCodes` table in `schema.ts` has no `userName` or `userEmail` fields, so there is nowhere to store the approving user's identity

2. **`approveDeviceCode` discards identity**: The mutation accepts only `{ userCode, userId }` — the frontend's `identity.name` and `identity.email` are available in the `currentIdentity` query result but never passed to the mutation

3. **`getByAccessToken` returns bare userId**: The query returns only `{ userId: record.userId }` with no name or email fields, even if they were stored

4. **`resolveIdentity` doesn't enrich device-auth sessions**: When the opaque token lookup succeeds, it returns `{ subject: record.userId }` without including name or email from the device code record

5. **`ensureOrg` fallback uses raw hash**: The line `const displayName = identity.name ?? identity.email ?? userId` falls through to `userId` (which is `tokenIdentifier.split("|").pop()` — a hash) when the identity object lacks name and email. For device-auth sessions, `resolveIdentity` never populates these fields, so the hash is always used

6. **No self-healing for existing orgs**: `ensureOrg` returns early when a membership exists (`if (existing) return { orgId: existing.orgId, isNew: false }`), so orgs created with hash names are never corrected

## Correctness Properties

Property 1: Bug Condition - Device Auth Identity Propagation

_For any_ device code approval where the approving user has a name or email in their authenticated identity, the fixed `approveDeviceCode` mutation SHALL store `userName` and `userEmail` in the device code record, and the fixed `resolveIdentity` function SHALL return `{ subject, name, email }` when resolving a `sic_` token associated with that record.

**Validates: Requirements 2.1, 2.2, 2.3**

Property 2: Bug Condition - Org Display Name Uses Human-Readable Name

_For any_ call to `ensureOrg` where the authenticated user's identity includes a name or email, the fixed function SHALL use `identity.name ?? identity.email` (not the raw `tokenIdentifier` hash) as the org display name, and SHALL update existing hash-named orgs to use the correct display name.

**Validates: Requirements 2.4, 2.5, 2.6**

Property 3: Preservation - Non-Device-Auth Identity Resolution

_For any_ authentication request that uses a Convex Auth JWT or project API key (not a `sic_` opaque token), the fixed `resolveIdentity` function SHALL produce the same result as the original function, preserving all existing identity resolution behavior.

**Validates: Requirements 3.1, 3.5, 3.6**

Property 4: Preservation - Device Code Lifecycle

_For any_ device code operation (creation, expiration, denial, PKCE verification), the fixed code SHALL produce the same behavior as the original code, preserving all device code state transitions and validation logic.

**Validates: Requirements 3.2, 3.3, 3.4**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**File**: `convex/convex/schema.ts`

**Table**: `deviceCodes`

**Specific Changes**:
1. **Add identity fields to schema**: Add `userName: v.optional(v.string())` and `userEmail: v.optional(v.string())` to the `deviceCodes` table definition. Optional so existing records and the `createDeviceCode` mutation (which runs before approval) are unaffected.

---

**File**: `convex/convex/deviceAuth.ts`

**Function**: `approveDeviceCode`

**Specific Changes**:
2. **Accept name and email args**: Add `userName: v.optional(v.string())` and `userEmail: v.optional(v.string())` to the mutation args
3. **Store name and email**: Include `userName` and `userEmail` in the `ctx.db.patch` call alongside `status` and `userId`

**Function**: `getByAccessToken`

**Specific Changes**:
4. **Return name and email**: Change the return from `{ userId: record.userId }` to `{ userId: record.userId, userName: record.userName ?? null, userEmail: record.userEmail ?? null }`

---

**File**: `convex/convex/http.ts`

**Function**: `resolveIdentity`

**Specific Changes**:
5. **Enrich device-auth identity**: When the opaque token lookup returns a record with `userName` or `userEmail`, include them in the returned identity object: `{ subject: record.userId, name: record.userName, email: record.userEmail }`

**Route**: `GET /api/v1/whoami`

**Specific Changes**:
6. **Use enriched identity**: The existing whoami handler already reads `identity.name` and `identity.email` — once `resolveIdentity` returns them for device-auth sessions, whoami will automatically return the correct values. No changes needed to the whoami handler itself.

---

**File**: `sicario-frontend/src/pages/DeviceAuth.tsx`

**Function**: `handleApprove`

**Specific Changes**:
7. **Pass name and email to approve mutation**: Update the `approve()` call to include `userName: identity.name` and `userEmail: identity.email` from the `currentIdentity` query result

---

**File**: `convex/convex/organizations.ts`

**Function**: `ensureOrg`

**Specific Changes**:
8. **Fix display name fallback**: The current code already uses `identity.name ?? identity.email ?? userId` — this is correct for JWT sessions where `identity.name` is populated. For device-auth sessions, the fix to `resolveIdentity` will ensure `identity.name` and `identity.email` are available. However, `ensureOrg` runs server-side via `ctx.auth.getUserIdentity()`, not via `resolveIdentity`. For device-auth users calling `ensureOrg` through the dashboard (after logging in via browser), the JWT identity should already have name/email. No change needed here for the primary flow.

9. **Add self-healing for hash-named orgs**: After the early return for existing memberships, look up the org and check if its name matches a hash pattern (e.g., 32-char alphanumeric followed by `'s Organization`). If so, and if `identity.name` or `identity.email` is available, update the org name.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write tests that simulate the device auth approval flow and verify that identity fields are propagated. Run these tests on the UNFIXED code to observe failures and understand the root cause.

**Test Cases**:
1. **Device auth identity loss**: Approve a device code, consume it, call `getByAccessToken` — verify `userName` and `userEmail` are returned (will fail on unfixed code because fields don't exist)
2. **resolveIdentity enrichment**: Simulate a request with a `sic_` token, call `resolveIdentity` — verify `name` and `email` are present in the result (will fail on unfixed code)
3. **whoami with sic_ token**: Call `/api/v1/whoami` with a device-auth token — verify response includes real username and email (will fail on unfixed code, returns "unknown")
4. **Hash-based org name**: Create a user with no `identity.name` or `identity.email`, call `ensureOrg` — verify org name is not a hash (will fail on unfixed code)

**Expected Counterexamples**:
- `getByAccessToken` returns `{ userId: "..." }` with no `userName` or `userEmail` fields
- `resolveIdentity` returns `{ subject: "..." }` with no `name` or `email` for device-auth tokens
- `whoami` returns `{ username: "unknown", email: "" }` for device-auth sessions
- Possible causes: missing schema fields, mutation not accepting/storing identity, query not returning identity

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds, the fixed function produces the expected behavior.

**Pseudocode:**
```
FOR ALL input WHERE isBugCondition(input) DO
  // Device auth identity propagation
  IF input.authMethod = "device_auth" THEN
    record ← approveDeviceCode'(input.userCode, input.userId, input.userName, input.userEmail)
    tokenRecord ← getByAccessToken'(input.accessToken)
    ASSERT tokenRecord.userName = input.userName
    ASSERT tokenRecord.userEmail = input.userEmail
    identity ← resolveIdentity'(ctx, request_with_sic_token)
    ASSERT identity.name = input.userName OR identity.email = input.userEmail
  END IF

  // Org display name
  IF input.orgCreation = true THEN
    result ← ensureOrg'(ctx_with_identity)
    org ← getOrg(result.orgId)
    ASSERT NOT looksLikeHash(org.name)
  END IF
END FOR
```

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold, the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT resolveIdentity(input) = resolveIdentity'(input)
  ASSERT ensureOrg(input) = ensureOrg'(input)
  ASSERT approveDeviceCode(input) = approveDeviceCode'(input)  // for non-identity fields
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code first for JWT-authenticated sessions, project API key auth, and device code lifecycle operations, then write property-based tests capturing that behavior.

**Test Cases**:
1. **JWT identity preservation**: Verify that `resolveIdentity` returns the same `{ subject, name, email }` for Convex Auth JWT sessions before and after the fix
2. **Project API key preservation**: Verify that project API key authentication continues to resolve correctly
3. **Device code lifecycle preservation**: Verify that device code creation, expiration, denial, and PKCE verification work identically before and after the fix
4. **Existing org idempotency preservation**: Verify that `ensureOrg` returns existing orgId without creating duplicates for users who already have memberships

### Unit Tests

- Test `approveDeviceCode` stores `userName` and `userEmail` when provided
- Test `approveDeviceCode` works correctly when `userName` and `userEmail` are omitted (backward compatibility)
- Test `getByAccessToken` returns `userName` and `userEmail` from the device code record
- Test `resolveIdentity` returns name and email for device-auth tokens
- Test `resolveIdentity` returns name and email for JWT tokens (unchanged)
- Test `ensureOrg` self-healing updates hash-named orgs
- Test `ensureOrg` does not modify orgs that already have human-readable names
- Test DeviceAuth frontend passes name and email to approve mutation

### Property-Based Tests

- Generate random user identities (with/without name, with/without email) and verify `approveDeviceCode` + `getByAccessToken` round-trips identity fields correctly
- Generate random authentication contexts (JWT, sic_ token, project key, unauthenticated) and verify `resolveIdentity` returns correct identity shape for each
- Generate random org names and verify `ensureOrg` self-healing only triggers for hash-pattern names, not for legitimate org names

### Integration Tests

- Test full device auth flow: create device code → approve with identity → consume → call whoami → verify correct username and email
- Test dashboard signup flow: register → ensureOrg → verify org name uses display name
- Test self-healing flow: create org with hash name → login with name available → call ensureOrg → verify org name updated
- Test mixed auth: verify JWT session and device-auth session for the same user both resolve correctly
