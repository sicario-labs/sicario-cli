# Bugfix Requirements Document

## Introduction

When a user authenticates via the CLI device auth flow (`sicario login`), the user's display name, email, and organization name are not propagated correctly through the system. The `approveDeviceCode` mutation only stores the user's `tokenIdentifier` as `userId` but discards the user's name and email. Downstream, the `resolveIdentity` function in `http.ts` returns only a bare `subject` with no name or email for device-auth sessions, the `whoami` endpoint reports "unknown" for the username, and `ensureOrg` falls back to using the raw Convex internal hash as the organization display name. This affects the CLI output, the dashboard sidebar, and any newly created organizations for device-auth users.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN a user approves a device code via the frontend DeviceAuth page THEN the system stores only the `tokenIdentifier` as `userId` in the `deviceCodes` record, discarding the user's name and email

1.2 WHEN the CLI calls `/api/v1/whoami` using a `sic_` opaque token THEN the system returns "unknown" for the username and an empty string for the email because `resolveIdentity` only returns `{ subject: record.userId }` with no name or email fields

1.3 WHEN the CLI completes `sicario login` THEN the system displays "Authenticated as: unknown" because the whoami response lacks the user's display name

1.4 WHEN `ensureOrg` creates a new organization for a device-auth user whose identity lacks `name` and `email` THEN the system falls back to the raw `tokenIdentifier` hash and creates an org named `<hash>'s Organization` (e.g., `ks7dtkrb3e1m5w9cbkbprjvrn585fmhp's Organization`)

1.5 WHEN the dashboard sidebar displays the organization name for a device-auth user THEN the system shows the raw hash-based name instead of the user's display name

1.6 WHEN a new user signs up via the dashboard (email/password or GitHub OAuth) and `ensureOrg` auto-creates their organization THEN the system uses `identity.tokenIdentifier.split("|").pop()` as the display name fallback, which produces a raw hash like `ks7dtkrb3e1m5w9cbkbprjvrn585fmhp` instead of the user's actual name or email — this affects ALL new users, not just CLI device-auth users

### Expected Behavior (Correct)

2.1 WHEN a user approves a device code via the frontend DeviceAuth page THEN the system SHALL store the user's `name` and `email` (from their authenticated identity) alongside the `userId` in the `deviceCodes` record

2.2 WHEN the CLI calls `/api/v1/whoami` using a `sic_` opaque token THEN the system SHALL return the user's display name and email from the device code record, so the response includes the correct `userName` and `userEmail`

2.3 WHEN the CLI completes `sicario login` THEN the system SHALL display "Authenticated as: <user's display name>" using the name returned by the whoami endpoint

2.4 WHEN `ensureOrg` creates a new organization for ANY user (dashboard signup or device-auth) THEN the system SHALL use the user's display name (from `identity.name` or `identity.email`) for the org name (e.g., `Jane Doe's Organization` or `jane@example.com's Organization`) instead of the raw tokenIdentifier hash

2.5 WHEN the dashboard sidebar displays the organization name THEN the system SHALL show the human-readable org name derived from the user's display name

2.6 WHEN an existing organization has a hash-based name (from before this fix) THEN the system SHALL update the org name to use the user's display name on the next `ensureOrg` call

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a user authenticates via Convex Auth JWT (standard browser session) THEN the system SHALL CONTINUE TO resolve their identity with name and email from the JWT claims as before

3.2 WHEN a device code is in "pending" status and has not been approved THEN the system SHALL CONTINUE TO reject token exchange attempts with the appropriate error

3.3 WHEN a device code has expired THEN the system SHALL CONTINUE TO mark it as expired and reject approval or consumption attempts

3.4 WHEN `ensureOrg` is called for a user who already has an existing membership THEN the system SHALL CONTINUE TO return the existing orgId without creating a duplicate organization

3.5 WHEN the CLI authenticates with a valid `sic_` token for a consumed device code THEN the system SHALL CONTINUE TO successfully authenticate and authorize API requests

3.6 WHEN a project API key (`project:<key>`) is used for authentication THEN the system SHALL CONTINUE TO resolve the project identity correctly without being affected by the device auth changes

---

## Bug Condition

### Deriving the Bug Condition

**Bug Condition Function** — Identifies inputs that trigger the bug:

```pascal
FUNCTION isBugCondition(X)
  INPUT: X of type AuthRequest or OrgCreation
  OUTPUT: boolean

  // Bug triggers in two cases:
  // 1. Device auth: opaque sic_ token with no name/email in device code record
  // 2. Org creation: ensureOrg uses tokenIdentifier hash as display name fallback
  //    when identity.name and identity.email are both absent or when the
  //    userId extracted via split("|").pop() is used as the display name
  RETURN (X.authMethod = "device_auth" AND X.token starts with "sic_")
      OR (X.type = "org_creation" AND displayName = tokenIdentifier.split("|").pop())
END FUNCTION
```

**Property Specification** — Defines correct behavior for buggy inputs:

```pascal
// Property: Fix Checking — Device auth identity includes name and email
FOR ALL X WHERE isBugCondition(X) DO
  identity ← resolveIdentity'(X)
  ASSERT identity.name IS NOT NULL OR identity.email IS NOT NULL
  ASSERT identity.subject IS NOT NULL
END FOR
```

**Preservation Goal** — Ensures non-device-auth flows are unchanged:

```pascal
// Property: Preservation Checking
FOR ALL X WHERE NOT isBugCondition(X) DO
  ASSERT resolveIdentity(X) = resolveIdentity'(X)
END FOR
```
