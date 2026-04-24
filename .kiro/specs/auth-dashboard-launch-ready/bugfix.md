# Bugfix Requirements Document

## Introduction

The auth (GitHub OAuth + Convex Auth) and dashboard systems have critical performance bugs that make them unsuitable for production launch. Backend queries perform full table scans with `.collect()` then filter in JavaScript (O(n) on every request), the auth flow triggers unnecessary write operations on every page load, frontend pages fire multiple heavy queries simultaneously, and several queries lack org-scoping (returning data across all organizations). These issues will cause the system to degrade severely under load and represent both performance and security defects that must be fixed before launch.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN any analytics query is executed (`overview`, `trends`, `mttr`, `topVulnerableProjects`, `owaspCompliance`, `findingsByLanguage`) THEN the system loads the entire findings table (and often scans + projects tables) into memory via `.collect()` and filters in JavaScript, resulting in O(n) time complexity per query that degrades linearly with data growth

1.2 WHEN `findings.list()` or `findings.listAdvanced()` or `findings.listForExport()` or `findings.getAdjacentIds()` is called THEN the system performs a full table scan of the findings table via `.collect()` and filters in JavaScript instead of using database indexes

1.3 WHEN `scans.list()` is called THEN the system exhibits an N+1 query pattern where for each scan in the paginated result, it individually loads ALL findings for that scan to compute `findings_count`

1.4 WHEN `analytics.topVulnerableProjects` is called THEN the system loads ALL projects, ALL scans, AND ALL findings into memory simultaneously, creating extreme memory pressure

1.5 WHEN `teams.list()` is called THEN the system returns ALL teams across ALL organizations with no org filtering, leaking cross-tenant data

1.6 WHEN analytics queries are called THEN the system returns findings/metrics across all organizations with no org-scoping, leaking cross-tenant data

1.7 WHEN a user navigates to any authenticated dashboard page THEN `useCurrentOrg` calls the `ensureOrg` mutation (a write operation) on every page load, even when the org already exists, causing unnecessary database writes on every navigation

1.8 WHEN GitHub OAuth is initiated and GitHub is slow or unresponsive THEN the Auth page provides no loading timeout or retry mechanism, leaving the user stuck with no feedback

1.9 WHEN `organizations.listUserOrgs` is called THEN the system performs N+1 queries by individually querying the organizations table for each membership

1.10 WHEN the OverviewPage loads THEN it fires 3+ heavy analytics queries simultaneously (`overview`, `mttr`, `topVulnerableProjects`), each performing full table scans on the backend, compounding the performance impact

1.11 WHEN the findings table is queried with common filter combinations (orgId + severity, orgId + triageState) THEN the system cannot use indexes because no composite indexes exist for these patterns, falling back to full table scans

### Expected Behavior (Correct)

2.1 WHEN any analytics query is executed THEN the system SHALL use database indexes (e.g., `by_orgId`, composite indexes) to filter data at the database level, avoiding loading entire tables into memory

2.2 WHEN `findings.list()`, `findings.listAdvanced()`, `findings.listForExport()`, or `findings.getAdjacentIds()` is called THEN the system SHALL use appropriate database indexes to filter findings at the query level instead of collecting all records and filtering in JavaScript

2.3 WHEN `scans.list()` is called THEN the system SHALL avoid the N+1 pattern by either batch-loading finding counts or using a pre-computed count, rather than querying findings individually per scan

2.4 WHEN `analytics.topVulnerableProjects` is called THEN the system SHALL use indexed queries scoped to the relevant org and avoid loading all projects, scans, and findings into memory simultaneously

2.5 WHEN `teams.list()` is called THEN the system SHALL require an `orgId` parameter and filter teams using the `by_orgId` index, returning only teams belonging to the specified organization

2.6 WHEN analytics queries are called THEN the system SHALL accept an `orgId` parameter and scope all data retrieval to that organization using database indexes

2.7 WHEN a user navigates to an authenticated dashboard page and already has an org THEN the system SHALL check for existing org membership via a read query first and only call the `ensureOrg` mutation if no membership exists, avoiding unnecessary writes on every page load

2.8 WHEN GitHub OAuth is initiated THEN the Auth page SHALL display a loading timeout indicator (e.g., after 15 seconds) with a retry button and error feedback so the user is never stuck without recourse

2.9 WHEN `organizations.listUserOrgs` is called THEN the system SHALL batch-resolve organization details efficiently instead of performing individual queries per membership

2.10 WHEN the OverviewPage loads THEN the system SHALL ensure backend queries are index-optimized so that concurrent query execution does not compound into excessive full table scans

2.11 WHEN the findings table is queried with common filter combinations THEN the system SHALL have composite indexes (e.g., `by_orgId_severity`, `by_orgId_triageState`, `by_orgId_createdAt`) to support efficient filtered queries

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a query uses an existing single-field index (e.g., `by_findingId`, `by_scanId`, `by_fingerprint`) THEN the system SHALL CONTINUE TO resolve those queries correctly via the existing indexes

3.2 WHEN a user signs in via GitHub OAuth or email/password THEN the system SHALL CONTINUE TO authenticate successfully and redirect to the dashboard

3.3 WHEN a first-time user with no organization loads the dashboard THEN the system SHALL CONTINUE TO auto-create a personal org and admin membership via `ensureOrg`

3.4 WHEN the CLI authenticates via the OAuth Device Flow with PKCE THEN the system SHALL CONTINUE TO complete the device code flow, store tokens in the system keychain, and poll correctly per RFC 8628

3.5 WHEN `findings.triage()` or `findings.bulkTriage()` is called with valid RBAC context THEN the system SHALL CONTINUE TO enforce role-based access control and update findings correctly

3.6 WHEN the dashboard layout renders THEN the system SHALL CONTINUE TO display the sidebar, header, command palette, keyboard shortcuts, and error boundary correctly

3.7 WHEN `scans.insert()` is called with a scan report THEN the system SHALL CONTINUE TO insert the scan record and all associated findings correctly

3.8 WHEN the OrgSwitcher component is used to switch organizations THEN the system SHALL CONTINUE TO persist the active org to localStorage and update the UI accordingly

3.9 WHEN `memberships.list()`, `memberships.create()`, `memberships.update()`, or `memberships.remove()` is called THEN the system SHALL CONTINUE TO enforce admin-only access and manage memberships correctly

3.10 WHEN the device auth flow (`deviceAuth.ts`) creates, approves, or consumes device codes THEN the system SHALL CONTINUE TO manage device code lifecycle correctly with proper expiration and status transitions


---

## Bug Condition Derivation

### Bug Condition Function

```pascal
FUNCTION isBugCondition(X)
  INPUT: X of type QueryRequest
  OUTPUT: boolean

  // The bug triggers when any of these conditions are met:
  // 1. A backend query collects an entire table and filters in JS
  // 2. A query lacks org-scoping, returning cross-tenant data
  // 3. The ensureOrg mutation fires when an org already exists
  // 4. GitHub OAuth has no timeout/retry mechanism
  // 5. N+1 query patterns exist in data resolution

  RETURN (X.queryType IN {analytics, findings.list, findings.listAdvanced,
          findings.listForExport, findings.getAdjacentIds, scans.list,
          teams.list, organizations.listUserOrgs})
      OR (X.isAuthPageLoad AND X.githubOAuthInitiated AND X.noTimeoutMechanism)
      OR (X.isDashboardNavigation AND X.userAlreadyHasOrg AND X.ensureOrgMutationFired)
END FUNCTION
```

### Property Specification — Fix Checking

```pascal
// Property: Fix Checking — Indexed Queries
FOR ALL X WHERE isBugCondition(X) AND X.queryType IN {analytics, findings, scans} DO
  result ← F'(X)
  ASSERT result.usesIndexForFiltering = true
  ASSERT result.doesNotCollectEntireTable = true
  ASSERT result.returnsSameDataAsOriginal(F(X)) = true
END FOR

// Property: Fix Checking — Org Scoping
FOR ALL X WHERE isBugCondition(X) AND X.queryType IN {teams.list, analytics.*} DO
  result ← F'(X)
  ASSERT result.allRecordsBelongToOrg(X.orgId) = true
END FOR

// Property: Fix Checking — Auth Efficiency
FOR ALL X WHERE isBugCondition(X) AND X.isDashboardNavigation AND X.userAlreadyHasOrg DO
  sideEffects ← observeSideEffects(F'(X))
  ASSERT sideEffects.ensureOrgMutationCalled = false
END FOR

// Property: Fix Checking — OAuth Timeout
FOR ALL X WHERE isBugCondition(X) AND X.isAuthPageLoad AND X.githubOAuthInitiated DO
  result ← F'(X)
  ASSERT result.hasTimeoutIndicator = true
  ASSERT result.hasRetryButton = true
END FOR
```

### Preservation Goal

```pascal
// Property: Preservation Checking
FOR ALL X WHERE NOT isBugCondition(X) DO
  ASSERT F(X) = F'(X)
END FOR
```

This ensures that for all non-buggy inputs (e.g., single-record lookups by ID using existing indexes, first-time user org creation, standard auth flows, RBAC enforcement, device auth lifecycle), the fixed code behaves identically to the original.
