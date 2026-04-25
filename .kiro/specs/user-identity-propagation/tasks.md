# Implementation Plan

- [x] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Device Auth Identity Loss and Hash-Based Org Names
  - **CRITICAL**: This test MUST FAIL on unfixed code — failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior — it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists in two areas
  - **Scoped PBT Approach**: Scope the property to concrete failing cases:
    - Case 1 (Device auth identity loss): Approve a device code with a user who has name/email, consume it, then call `getByAccessToken` — assert `userName` and `userEmail` are returned (they won't be, because the schema has no such fields and `approveDeviceCode` doesn't accept them)
    - Case 2 (Hash-based org name): For any user identity where `name` is null and `email` is null, the `ensureOrg` display name fallback `identity.tokenIdentifier.split("|").pop()` produces a raw hash — assert the org name does NOT look like a hash (it will, confirming the bug)
  - **Test file**: `convex/convex/__tests__/identity-propagation-bug.test.ts`
  - Use `fast-check` to generate random user names and emails, then verify the device code round-trip preserves them
  - Bug Condition from design: `isBugCondition(input)` where `input.authMethod = "device_auth" AND deviceCodeRecord.userName IS NULL AND deviceCodeRecord.userEmail IS NULL` OR `input.orgCreation = true AND displayName = tokenIdentifier.split("|").pop() AND looksLikeHash(displayName)`
  - Expected Behavior from design: `approveDeviceCode` stores `userName`/`userEmail`, `getByAccessToken` returns them, `resolveIdentity` includes `name`/`email` for `sic_` tokens
  - Run test on UNFIXED code
  - **EXPECTED OUTCOME**: Test FAILS (this is correct — it proves the bug exists)
  - Document counterexamples found: `getByAccessToken` returns `{ userId }` with no `userName`/`userEmail`; org names contain raw hashes
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6_

- [x] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - Non-Device-Auth Identity Resolution and Device Code Lifecycle
  - **IMPORTANT**: Follow observation-first methodology
  - **Test file**: `convex/convex/__tests__/identity-propagation-preservation.test.ts`
  - Use `fast-check` to generate test inputs across the non-buggy input domain
  - **Observe on UNFIXED code**:
    - Convex Auth JWT sessions resolve identity with `{ subject, name, email }` from JWT claims — this must remain unchanged
    - Project API key auth (`project:<key>`) resolves to `{ subject: "project:<id>", projectId, orgId }` — this must remain unchanged
    - Device code creation stores all fields correctly (deviceCode, userCode, codeChallenge, clientId, status="pending", expiresAt)
    - Pending device codes reject token exchange with "authorization_pending"
    - Expired device codes are rejected with appropriate error
    - `ensureOrg` is idempotent — returns existing orgId for users who already have a membership without creating duplicates
    - `approveDeviceCode` rejects empty userId, non-pending codes, and expired codes
  - **Write property-based tests**:
    - For all random `(deviceCode, userCode, codeChallenge, clientId)` tuples: `createDeviceCode` → `getDeviceCodeByUserCode` round-trips correctly
    - For all random device codes in "pending" status past `expiresAt`: approval throws "expired" error
    - For all random device codes in "approved" status: `consumeDeviceCode` transitions to "consumed" and stores accessToken
    - For all random non-empty userId strings: `approveDeviceCode` stores userId correctly; for empty strings: throws error
  - Preservation Requirements from design: Requirements 3.1–3.6
  - Run tests on UNFIXED code
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

- [x] 3. Fix for device auth identity loss and hash-based org names

  - [x] 3.1 Add `userName` and `userEmail` fields to `deviceCodes` schema
    - In `convex/convex/schema.ts`, add `userName: v.optional(v.string())` and `userEmail: v.optional(v.string())` to the `deviceCodes` table definition
    - Fields are optional so existing records and `createDeviceCode` (which runs before approval) are unaffected
    - _Bug_Condition: isBugCondition(input) where deviceCodeRecord.userName IS NULL AND deviceCodeRecord.userEmail IS NULL_
    - _Requirements: 2.1_

  - [x] 3.2 Update `approveDeviceCode` to accept and store name/email
    - In `convex/convex/deviceAuth.ts`, add `userName: v.optional(v.string())` and `userEmail: v.optional(v.string())` to the `approveDeviceCode` mutation args
    - Include `userName` and `userEmail` in the `ctx.db.patch` call alongside `status` and `userId`
    - _Bug_Condition: approveDeviceCode discards identity — only stores userId_
    - _Expected_Behavior: approveDeviceCode stores userName and userEmail from the approving user's identity_
    - _Preservation: Existing calls without userName/userEmail continue to work (fields are optional)_
    - _Requirements: 2.1_

  - [x] 3.3 Update `getByAccessToken` to return name/email
    - In `convex/convex/deviceAuth.ts`, change the return from `{ userId: record.userId ?? null }` to `{ userId: record.userId ?? null, userName: record.userName ?? null, userEmail: record.userEmail ?? null }`
    - _Bug_Condition: getByAccessToken returns bare userId with no name/email_
    - _Expected_Behavior: getByAccessToken returns userId, userName, and userEmail_
    - _Preservation: Callers that only read userId are unaffected (additional fields are additive)_
    - _Requirements: 2.2_

  - [x] 3.4 Enrich `resolveIdentity` for device-auth sessions
    - In `convex/convex/http.ts`, update the opaque token lookup branch to include `name` and `email` from the device code record: `return { subject: record.userId, name: record.userName ?? undefined, email: record.userEmail ?? undefined }`
    - _Bug_Condition: resolveIdentity returns { subject: record.userId } with no name or email for sic_ tokens_
    - _Expected_Behavior: resolveIdentity returns { subject, name, email } for device-auth sessions_
    - _Preservation: JWT and project API key paths are untouched_
    - _Requirements: 2.2, 2.3_

  - [x] 3.5 Update DeviceAuth frontend to pass name/email to approve mutation
    - In `sicario-frontend/src/pages/DeviceAuth.tsx`, update the `handleApprove` function to pass `userName: identity.name` and `userEmail: identity.email` from the `currentIdentity` query result to the `approve()` mutation call
    - _Bug_Condition: Frontend passes only tokenIdentifier as userId, discarding name and email_
    - _Expected_Behavior: Frontend passes userName and userEmail alongside userId_
    - _Requirements: 2.1_

  - [x] 3.6 Fix `ensureOrg` display name fallback and add self-healing
    - In `convex/convex/organizations.ts`, update `ensureOrg`:
      - Keep the existing `displayName = identity.name ?? identity.email ?? userId` logic (this is correct when identity has name/email)
      - Add a `looksLikeHash(str)` helper: returns true if the string is 20+ alphanumeric chars with no spaces
      - After the early return for existing memberships, look up the org and check if its name matches the hash pattern (e.g., `<hash>'s Organization`). If so, and if `identity.name` or `identity.email` is available, update the org name
    - _Bug_Condition: ensureOrg uses tokenIdentifier.split("|").pop() (a hash) as display name when identity.name and identity.email are both absent_
    - _Expected_Behavior: ensureOrg uses identity.name ?? identity.email for display name; self-heals existing hash-named orgs_
    - _Preservation: Orgs with legitimate human-readable names are not modified; ensureOrg remains idempotent for existing memberships_
    - _Requirements: 2.4, 2.5, 2.6_

  - [x] 3.7 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Device Auth Identity Propagation
    - **IMPORTANT**: Re-run the SAME test from task 1 — do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_

  - [x] 3.8 Verify preservation tests still pass
    - **Property 2: Preservation** - Non-Device-Auth Identity Resolution and Device Code Lifecycle
    - **IMPORTANT**: Re-run the SAME tests from task 2 — do NOT write new tests
    - Run preservation property tests from step 2
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all tests still pass after fix (no regressions)

- [x] 4. Checkpoint - Ensure all tests pass
  - Run `npm run test` in the `convex/` directory to execute all tests
  - Ensure both bug condition and preservation tests pass
  - Ensure no other existing tests are broken
  - Ask the user if questions arise
