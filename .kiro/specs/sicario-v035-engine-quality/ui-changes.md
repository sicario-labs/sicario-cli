# UI Changes — Semgrep-Parity Dashboard Redesign

**Scope:** Frontend-only changes to `sicario-frontend/src/`. No new backend queries required beyond what Requirements 26–33 already specify. All changes are purely presentational or wire up data that already exists in the Convex schema.

**Zero-exfil invariant:** Every change here operates on structured finding metadata already in the DB. No source code is fetched, displayed, or transmitted by any UI change in this document.

---

## 1. Navigation / Sidebar

### Current state
Sidebar has grouped links: Main (Overview, Findings, Projects, Scans), Reports (OWASP, Analytics), System (Settings, Account). No product-level grouping. No "Code" / "Supply Chain" / "Secrets" product tabs.

### Changes

**1a. Rename and regroup sidebar items to match Semgrep's nav structure**

| Current label | New label | Route | Notes |
|---|---|---|---|
| Overview | Overview | `/dashboard` | Keep |
| Findings | Code | `/dashboard/findings` | Rename to match Semgrep's "Code" product label |
| Projects | Projects | `/dashboard/projects` | Keep |
| Scans | Scans | `/dashboard/scans` | Keep, move under Projects section |
| OWASP | OWASP | `/dashboard/owasp` | Keep |
| Analytics | Dashboard | `/dashboard/analytics` | Rename to "Dashboard" — Semgrep calls this the Dashboard page, not Analytics |
| Settings | Settings | `/dashboard/settings` | Keep |
| Account | Account | `/dashboard/account` | Keep |

**1b. Add a "Rules & Policies" nav item** (placeholder, links to `/dashboard/policies`) — renders an empty state with "Coming soon" until the Policies page is built. This establishes the nav slot now so users see the roadmap.

**1c. Sidebar section headers** — add subtle uppercase section labels:
- `SECURITY` → Overview, Code (Findings), Dashboard
- `PROJECTS` → Projects, Scans
- `COMPLIANCE` → OWASP, Rules & Policies
- `WORKSPACE` → Settings, Account

**1d. Active state indicator** — change from a left border accent to a filled pill background (matching Semgrep's style: `bg-accent/10 text-accent` on active item, `text-text-muted hover:text-text-main` on inactive).

**File:** `sicario-frontend/src/components/dashboard/Sidebar.tsx`

---

## 2. Overview Page (Dashboard Home)

### Current state
4 stat cards → severity breakdown → checklist (if empty) or recent findings feed.

### Changes

**2a. Rename page title from "Overview" to "Dashboard"** — matches Semgrep's naming. The route stays `/dashboard`.

**2b. Stat cards — add two new cards and reorder**

Current 4 cards: Total Findings, Critical Issues, Scans Run, Last Scan.

New 6-card layout (2 rows of 3 on desktop, stacked on mobile):

| Card | Value | Delta indicator |
|---|---|---|
| Open Findings | `overview.open_findings` | vs. 7 days ago (↑/↓/→) |
| Critical | `overview.critical_count` | vs. 7 days ago |
| Fixed This Week | `overview.fixed_findings` (filtered to last 7d) | — |
| Avg MTTR | `mttr.overall_mttr_hours` | trend arrow |
| Scans Run | `overview.total_scans` | — |
| Projects | project count | — |

The delta indicators require a second `analytics.overview` query with a `dateFrom` 7 days ago. This is already supported by Requirement 31.

**2c. Backlog Activity chart** — add a new chart section below the stat cards (before the recent findings feed). Uses `analytics.trends` data. Shows a stacked bar chart: new (gray) / fixed (green) / ignored (yellow) per day for the last 14 days. Label: "Backlog Activity — last 14 days". This replaces the current FindingsTrendChart on the Overview page (move FindingsTrendChart to the Analytics/Dashboard page only).

**2d. Top Vulnerable Projects widget** — add a compact table below the Backlog Activity chart showing the top 5 projects by open finding count. Columns: Project name, Critical, High, Medium, Open total. Each row links to `/dashboard/projects/:id`. Data: `analytics.topVulnerableProjects` (already implemented).

**2e. Recent Findings feed** — keep but reduce to 5 items (currently shows more). Add a "Group by Rule" toggle button in the feed header that switches between individual finding cards and a grouped-by-rule view (rule name + count of affected files). The grouped view uses `findings.groupByRule` (Requirement 28).

**2f. Empty state** — keep the existing checklist but add a "See a demo" button that loads the pre-seeded demo project (Requirement 35 AC 8). The button calls the demo seeding mutation and then navigates to `/dashboard/findings`.

**File:** `sicario-frontend/src/pages/dashboard/OverviewPage.tsx`

---

## 3. Findings Page

### Current state
FilterBar → FindingsTable (flat list) → pagination. No grouping. No branch filter. No CWE filter.

### Changes

**3a. "Group by Rule" / "No Grouping" toggle**

Add a toggle button group in the page header (right side, next to the total count badge):

```
[≡ No Grouping]  [⊞ Group by Rule]
```

- **No Grouping** (default): current flat table view, unchanged.
- **Group by Rule**: renders `FindingsGroupedView` component (new). Each rule is a collapsible card showing: rule name, severity badge, CWE badge, open count, affected files list (up to 5, "+ N more" if more). Clicking the card header expands it to show the individual findings for that rule inline. Clicking a finding row navigates to the detail page.

The toggle state is stored in `localStorage` so it persists across page loads.

**3b. Add missing filter chips**

Extend `FilterBar` with three new filter controls:

- **Branch** — text input or dropdown (populated from distinct `branch` values for the org). Requires `branch` field on findings (Requirement 26).
- **CWE** — text input (e.g. "CWE-89"). Filters by `cweId` field. Requires Requirement 28 AC 3.
- **Language** — dropdown (JavaScript, TypeScript, Python, Go, Rust, Java, Ruby, PHP, C#). Filters by file extension. Requires Requirement 28 AC 4.

These are added as optional chips in the FilterBar, collapsed behind a "More filters" disclosure button to avoid cluttering the bar.

**3c. Date range filter**

Add a "Date range" filter chip (collapsed under "More filters") with a simple from/to date picker. Maps to `dateFrom` / `dateTo` params in `listAdvanced` (Requirement 28 AC 5).

**3d. Saved filter presets**

Add a "Save filter" button next to the "Clear all" button. When clicked, prompts for a preset name and saves to `savedFilters` table (Requirement 28 AC 8). A "Saved filters" dropdown shows existing presets; clicking one applies all its filters at once.

**3e. SARIF export button**

Add an "Export" dropdown button in the page header (next to the Group by Rule toggle). Options:
- **Export as JSON** — existing `listForExport` behavior
- **Export as SARIF** — calls `findings.exportSarif` (Requirement 32) and downloads the result as `sicario-findings.sarif`
- **Export as CSV** — generates CSV client-side from the current filtered result set

**3f. Triage state labels**

Update the triage state display values to match the full state machine from Requirement 22:
- `Open` → "Open"
- `Reviewing` → "Reviewing" (yellow badge)
- `ToFix` → "To Fix" (orange badge)
- `Ignored` → "Ignored" (gray badge)
- `AutoIgnored` → "Auto-ignored" (gray badge, italic)
- `Fixed` → "Fixed" (green badge)
- `AutoFixed` → "Auto-fixed" (green badge, italic)
- `Removed` → "Removed" (gray badge, strikethrough)

**File:** `sicario-frontend/src/pages/dashboard/FindingsPage.tsx`, `sicario-frontend/src/components/dashboard/FilterBar.tsx`, new `sicario-frontend/src/components/dashboard/FindingsGroupedView.tsx`

---

## 4. Finding Detail Page

### Current state
2-col layout: left (metadata, snippet, remediation, execution trace, timeline) + right (triage form). No SCM link. No CWE description. No alert box. No branch/commit shown.

### Changes

**4a. Alert box at top of page**

Add a prominent alert banner immediately below the back-navigation row, rendered when any of these conditions are true:
- `finding.severity === "Critical"` → red banner: "Critical severity — immediate attention required"
- `finding.reachable === true` → orange banner: "Reachable — this vulnerability is reachable from an entry point"
- `finding.cloudExposed === true` → red banner: "Cloud-exposed — this service is publicly accessible"

Multiple conditions stack as separate banners. Each has an icon and a dismiss button (dismissed state stored in `sessionStorage` per finding ID).

**4b. SCM deep link**

In the metadata card, add a "View in GitHub/GitLab" link assembled as:
```
{project.repositoryUrl}/blob/{scan.commitSha}/{finding.filePath}#L{finding.line}
```
The SCM type is inferred from `repositoryUrl` (contains `github.com` → GitHub link format, `gitlab.com` → GitLab format). If `commitSha` is unavailable, fall back to the default branch. The link opens in a new tab. Label: "Open in {GitHub|GitLab} →".

This requires fetching the parent scan's `commitSha`. Add a `useQuery(api.scans.getByScanId, { scanId: finding.scan_id })` call — this data is already in the DB.

**4c. CWE and OWASP inline descriptions**

In the metadata card, expand the CWE and OWASP fields:
- CWE: show `CWE-89` as a link to `https://cwe.mitre.org/data/definitions/89.html`, with the CWE name inline from a static lookup table (e.g. "CWE-89: SQL Injection"). The lookup table is a small static JSON file bundled in `src/data/cwe.ts`.
- OWASP: show the category code + name (e.g. "A03:2021 — Injection") from `src/lib/owasp.ts` (already exists).

**4d. Branch and commit shown**

Add two new metadata fields to the metadata card:
- **Branch**: `finding.branch` (Requirement 26)
- **Commit**: `scan.commitSha` (first 8 chars, monospace, links to the commit on the SCM)

**4e. Structured taint trace**

Replace the current `ExecutionAuditTrail` component (which renders `executionTrace: string[]` as a plain list) with a new `TaintTraceVisualization` component that:
- Renders `finding.taintPath` (Requirement 29 AC 2) as a visual chain: `source → [intermediate →] sink`
- Each node shows: role badge (SOURCE/SINK/INTERMEDIATE), file path, line number, node type
- Each node's file path is a link to the SCM deep link for that specific line
- Falls back to the existing `executionTrace` string array rendering if `taintPath` is null

**4f. Activity panel — full event log**

Replace the current stub `getTimeline` rendering (which only shows 2 events: created + triaged) with a full activity log using `findingEvents.list` (Requirement 27 AC 7). Each event shows:
- Event type icon (opened, triaged, reopened, note added, auto-fixed, Jira ticket created)
- State transition: "Open → Reviewing" with colored badges
- Actor name (or "Sicario" for auto events)
- Timestamp (relative + absolute on hover)
- Note text (if any)

Add a "Add note" button at the bottom of the activity panel that opens an inline textarea. Submitting calls `findings.triage` with only the `note` parameter (no state change).

**4g. Ignore reason in triage form**

Extend `TriageForm` to show an `ignoreReason` select when the user picks "Ignored" as the triage state:
- Options: "False positive", "Acceptable risk", "No time to fix"
- Required before the Save button is enabled
- Maps to `ignoreReason: "false_positive" | "acceptable_risk" | "no_time_to_fix"`

**4h. Permalink button**

Add a "Copy link" button in the page header (next to PDF export) that copies the current URL to the clipboard. Uses the existing `CopyButton` component.

**4i. PR comment triage commands footer**

When the finding has `triage_state === "open"` and the org has PR comment triage enabled (org settings toggle), show a collapsible "Triage from PR" section at the bottom of the triage form card:

```
Triage this finding from a PR comment:
  /fp <reason>    — Mark as false positive
  /ar <reason>    — Mark as acceptable risk
  /other <reason> — Deprioritize
  /open <reason>  — Reopen
```

This is informational only — it shows the commands the developer can use in a PR comment. No interaction required.

**Files:** `sicario-frontend/src/pages/dashboard/FindingDetailPage.tsx`, `sicario-frontend/src/components/dashboard/TriageForm.tsx`, `sicario-frontend/src/components/dashboard/TaintTraceVisualization.tsx` (new), `sicario-frontend/src/components/dashboard/ActivityPanel.tsx` (new), `sicario-frontend/src/data/cwe.ts` (new static lookup)

---

## 5. Projects Page

### Current state
Grid of project cards with name, provisioning badge, last scan, open findings count, severity mini-bar, action button.

### Changes

**5a. Scanning / Not Scanning tabs**

Add two tabs at the top of the Projects page:
- **Scanning** (default): projects with `provisioningState === "active"` and at least one completed scan in the last 30 days
- **Not Scanning**: projects with `provisioningState === "pending"` or no recent scan

The tab counts are shown as badges: "Scanning (12)" / "Not Scanning (3)".

**5b. Project tags display**

On each project card, show the project's `tags` array (Requirement 30 AC 1) as small pill badges below the project name. Tags are truncated to 3 visible + "+ N more" tooltip if more than 3.

**5c. Scan type badge on last scan**

Show whether the last scan was "Full" or "Diff-aware" as a small badge next to the last scan timestamp. Uses `scans.scanType` field (Requirement 30 AC 6).

**5d. Sort and filter controls**

Add a sort dropdown (Project name A–Z, Most findings, Last scan) and a tag filter (multi-select dropdown populated from all tags in the org). These are client-side filters over the already-loaded project list.

**5e. Bulk rescan button**

Add a "Scan all" button in the page header (admin only). This is a placeholder that shows a toast: "Trigger a rescan by running `sicario ci --publish` in each project's CI pipeline." (Full bulk rescan requires the Managed CI Config feature to be active.)

**5f. Project card — primary branch display**

Show the `primaryBranch` value (Requirement 30 AC 4) on each project card as a small git branch icon + branch name (e.g. `⎇ main`).

**File:** `sicario-frontend/src/pages/dashboard/ProjectsPage.tsx`

---

## 6. Analytics / Dashboard Page

### Current state
4 summary cards → 4 charts (FindingsTrendChart, SeverityDonutChart, MttrBarChart, ScanFrequencyChart). Empty state if < 2 scans.

### Changes

**6a. Rename page title from "Analytics" to "Dashboard"** — matches Semgrep's naming. The route stays `/dashboard/analytics`.

**6b. Date range filter**

Add a date range selector in the page header (7 days / 30 days / 90 days / Custom). All charts and summary cards re-query with the selected `dateFrom`/`dateTo` when changed. Uses Requirement 31 AC 1–5.

**6c. Backlog Activity chart** (move from Overview)

The stacked bar chart (new/fixed/ignored/net) moves here as the primary chart. On the Overview page it becomes a compact sparkline version.

**6d. Production Backlog trend chart**

New chart: line chart showing total open findings on the primary branch over time. Uses `analytics.trends` with `branchType: "default"` filter (Requirement 31 AC 5). Label: "Production Backlog — open findings on default branch".

**6e. Guardrails Adoption section**

New section below the charts with two metrics displayed as large numbers with labels:
- **Findings shown to developers in PR** — `guardrailsAdoption.findingsSurfacedInPr` / `guardrailsAdoption.findingsTotal` as a fraction + percentage
- **Fixed before reaching production** — `guardrailsAdoption.fixedBeforeBacklog` / `guardrailsAdoption.findingsSurfacedInPr` as a fraction + percentage

Displayed as two stat cards side by side with a brief explanation: "Guardrails adoption measures how many vulnerabilities are caught and fixed during code review before they reach your default branch."

**6f. Median Open Age section**

New section: 4 stat cards (Critical / High / Medium / Low) each showing the median age in days of open findings at that severity. Uses `analytics.medianOpenAge` (Requirement 31 AC 9). Cards use severity colors. Label: "Median age of open findings".

**6g. Fix Rate metric**

Add a "Fix Rate" stat card to the summary row: `fixRate.fixRatePct`% with a trend arrow. Uses `analytics.fixRate` (Requirement 31 AC 6).

**6h. Per-project drill-down**

Add a "Project" dropdown filter in the page header that scopes all charts and metrics to a single project. Uses the `projectId` filter parameter added to all analytics queries in Requirement 31.

**File:** `sicario-frontend/src/pages/dashboard/AnalyticsPage.tsx`

---

## 7. Finding Detail — Jira Integration UI

### Changes (conditional on Jira config being set)

**7a. "Create Jira Ticket" button**

In the right column of the finding detail page, below the triage form, add a "Create Jira Ticket" button. Visible only when `jiraConfigs` is configured for the org. Clicking it:
1. Shows a confirmation modal: "Create a Jira ticket for this finding? The ticket will contain rule name, severity, CWE, file path, and a remediation link. No source code will be included."
2. On confirm, calls the Jira creation mutation (Requirement 33 AC 3).
3. On success, shows the Jira issue key as a link: "Jira: SEC-123 →" in the metadata card.

**7b. Jira issue key display**

If `finding.jiraIssueKey` is set, show it in the metadata card as a link: `[SEC-123 ↗]` linking to `{jiraBaseUrl}/browse/{jiraIssueKey}`.

**File:** `sicario-frontend/src/pages/dashboard/FindingDetailPage.tsx`, `sicario-frontend/src/components/dashboard/TriageForm.tsx`

---

## 8. Onboarding Wizard UI

### Current state
`OnboardingV2Page` exists at `/dashboard/onboarding/v2`. Structure unknown from the context gathered.

### Changes

**8a. Wizard step indicator**

Replace any existing step indicator with a horizontal progress bar showing 4 labeled steps:
```
① About You  ──  ② Connect Your Code  ──  ③ First Scan  ──  ④ See Findings
```
Active step is accent-colored. Completed steps show a checkmark. The bar is sticky at the top of the wizard.

**8b. Step 2 — Connect Your Code layout**

Three option cards in a vertical stack (not tabs):

```
┌─────────────────────────────────────────────────────────┐
│ ★ Scan locally with the CLI          [RECOMMENDED]       │
│   No permissions needed. Your code never leaves your     │
│   machine.                                               │
│   [Get started →]                                        │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│   Set up CI scanning on GitHub                           │
│   Automatically scan all your repos on every PR.         │
│   Requires write access to commit a workflow file.       │
│   [Connect GitHub →]                                     │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│   Set up CI scanning on GitLab                           │
│   [Connect GitLab →]                                     │
└─────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│   Skip — show me a demo                                  │
│   See what Sicario looks like with real findings.        │
│   [Load demo →]                                          │
└─────────────────────────────────────────────────────────┘
```

The CLI card has a `★` star and "RECOMMENDED" badge. The GitHub/GitLab cards show the permission disclosure inline (collapsed, expandable with "What permissions are needed?" link).

**8c. Step 3 — First Scan — real-time polling indicator**

Show a pulsing "Waiting for your first scan..." indicator with a spinner. Poll `analytics.overview` every 5 seconds. When `total_scans > 0`, auto-advance to Step 4 with a success animation (green checkmark, "First scan detected!").

**8d. Step 4 — See Your Findings — mini dashboard preview**

Show a compact summary of the first scan:
- Total findings count (large number)
- Severity breakdown (4 colored pills: Critical N, High N, Medium N, Low N)
- Top 3 findings (rule name, file path, severity badge)
- "Go to Dashboard →" button (calls `userProfiles.completeOnboarding` and navigates to `/dashboard`)

**File:** `sicario-frontend/src/pages/dashboard/OnboardingV2Page.tsx`

---

## 9. Empty State — Getting Started Checklist

### Current state
Checklist with 5 steps: Account ✓, Create project, Install CLI, Run scan, Explore findings.

### Changes

**9a. Add "See a demo" escape hatch**

Add a "See a demo" button below the checklist (not replacing it). Clicking it seeds the demo project and navigates to `/dashboard/findings`. The button is secondary-styled (border, not filled).

**9b. Zero-exfil trust message**

Add a small trust badge below the checklist:
```
🔒 Your source code never leaves your machine.
   Only structured finding metadata is uploaded here.
```
Styled as a subtle bordered box with a lock icon.

**9c. Checklist step — "Set up CI scanning"**

Add a 6th checklist step: "Set up CI scanning" — done when any project has `provisioningState === "active"` and was created via the Managed CI Config flow. Links to the onboarding wizard Step 2.

**File:** `sicario-frontend/src/pages/dashboard/OverviewPage.tsx` (GetStartedChecklist component)

---

## 10. Global UI Polish

### Changes

**10a. Page titles in browser tab**

Update `<title>` tags for each dashboard page:
- Overview → "Dashboard — Sicario"
- Findings → "Code — Sicario"
- Projects → "Projects — Sicario"
- Analytics → "Dashboard — Sicario" (same as Overview, disambiguate with breadcrumb)
- OWASP → "OWASP Compliance — Sicario"
- Settings → "Settings — Sicario"

**10b. Breadcrumb in header**

The existing `Header` component shows a breadcrumb. Extend it to show:
- Findings detail: "Code / {rule_name}"
- Project detail: "Projects / {project_name}"
- Scan detail: "Projects / {project_name} / Scans / {scan_id_short}"

**10c. Keyboard shortcut for Group by Rule toggle**

Add `G R` as a keyboard shortcut that toggles the Group by Rule view on the Findings page. Register it in `DashboardLayout`'s shortcuts map.

**10d. Command palette — add new commands**

Add to the command palette (`commands` array in `DashboardLayout`):
- "Toggle Group by Rule" → toggles the findings grouping
- "Export findings as SARIF" → triggers SARIF export from current filtered view
- "Load demo project" → seeds demo project and navigates to findings
- "Go to Rules & Policies" → navigates to `/dashboard/policies`

**File:** `sicario-frontend/src/pages/dashboard/DashboardLayout.tsx`, `sicario-frontend/src/components/dashboard/Header.tsx`

---

## Implementation Priority

### Phase 1 — High impact, low effort (pure UI, no new queries)
1. Sidebar rename + regroup + active state pill (§1)
2. Alert box on finding detail (§4a)
3. Triage state labels update (§3f)
4. Ignore reason in triage form (§4g)
5. Permalink button (§4h)
6. Zero-exfil trust message in empty state (§9b)
7. Page titles (§10a)

### Phase 2 — Medium effort, requires new queries from Req 26–33
1. Group by Rule toggle + FindingsGroupedView (§3a) — requires `findings.groupByRule`
2. SCM deep link on finding detail (§4b) — requires `branch` field + scan `commitSha`
3. CWE inline descriptions (§4c) — requires static `cwe.ts` lookup table
4. Branch + commit on finding detail (§4d) — requires `branch` field
5. Full activity panel with `findingEvents` (§4f) — requires `findingEvents.list`
6. Scanning / Not Scanning tabs on Projects (§5a) — requires `scanType` field
7. Project tags display (§5b) — requires `tags` field
8. Date range filter on Analytics (§6b) — requires Req 31 analytics params

### Phase 3 — Larger builds
1. Guardrails Adoption section (§6e) — requires `analytics.guardrailsAdoption`
2. Median Open Age section (§6f) — requires `analytics.medianOpenAge`
3. Backlog Activity chart (§2c, §6c) — requires `analytics.trends` with ignored count
4. Taint trace visualization (§4e) — requires `taintPath` structured field
5. Jira integration UI (§7) — requires `jiraConfigs` + Req 33
6. Onboarding wizard redesign (§8) — requires Req 35 backend
7. SARIF export button (§3e) — requires `findings.exportSarif`

---

## 11. Rules & Policies Page (New)

### Route: `/dashboard/policies`

**11a. Page structure — three tabs**

```
[Custom Rules]  [Built-in Rules]  [Policy Modes]
```

**Custom Rules tab (default):**
- Header: "Custom Rules" + badge showing count + `[+ New Rule]` button + `[AI Assist ✨]` button
- Filter row: Language dropdown, Severity dropdown, Policy Mode dropdown, search input
- Table with columns: Rule ID, Name, Language, Severity, CWE, Policy Mode (editable inline dropdown), Status toggle (enabled/disabled), Last Updated, Actions (Edit / Fork / Delete)
- Empty state: "No custom rules yet. Write your first rule or fork a built-in rule to get started." with a `[+ New Rule]` CTA.

**Built-in Rules tab:**
- Read-only table of all embedded rules (fetched from `GET /api/v1/orgs/{org_id}/rules/builtin`)
- Columns: Rule ID, Name, Language, Severity, CWE, Policy Mode (editable), Actions (Fork only)
- Search + Language filter
- "Fork" creates a copy in Custom Rules with `org/` prefix

**Policy Modes tab:**
- Explanation card: what Monitor / Comment / Block / Disabled mean
- Bulk assignment: multi-select rules from either tab → "Change mode" dropdown → Apply

**File:** `sicario-frontend/src/pages/dashboard/PoliciesPage.tsx` (new)

---

## 12. Rule Editor Page (New)

### Route: `/dashboard/policies/rules/new` and `/dashboard/policies/rules/:id/edit`

**12a. Layout — split pane**

Two-column layout (50/50 on desktop, stacked on mobile):
- Left: YAML editor + schema validation + AI Assist
- Right: live test panel + test case results + policy mode selector

**12b. YAML editor**

Use `@uiw/react-codemirror` (already a common choice for this stack) with YAML syntax highlighting and line numbers. Pre-populate with the rule scaffold on new rule creation. On edit, load the existing rule YAML.

The editor fires a debounced validation call (500ms after last keystroke) to `POST /api/v1/rules/validate`. Schema errors appear as:
- Red squiggles on the relevant line in the editor
- A "Schema Validation" panel below the editor listing all errors

**12c. AI Assist panel**

Below the YAML editor, a collapsible "AI Assist ✨" section. Because LLM keys are local-only (BYOK — the cloud never holds API keys), AI Assist works by generating a CLI command the user runs locally. The LLM call happens on the user's machine using their configured provider.

- Text area: "Describe the vulnerability in plain English..."
- Language selector (pre-filled from the rule's `languages` field)
- Severity selector
- `[Generate CLI command]` button — no backend call; generates the command client-side
- Output: a copyable terminal block showing the exact command:
  ```
  sicario rule new --description "..." --lang javascript --severity high
  ```
- Explanatory note: "Run this in your terminal. The rule will be saved to `.sicario/rules/`. Then run `sicario rule push` to sync it here."
- After the user runs the command and pushes, the new rule appears in the Custom Rules table automatically via real-time Convex subscription
- A "Paste YAML" shortcut: if the user already has generated YAML from the CLI, they can paste it directly into the editor instead of using the command flow

**12d. Live test panel**

Right column, top section:
- Label: "Test Code" + language badge
- Code textarea (monospace, syntax-highlighted, no line numbers needed)
- Result display below the textarea:
  - `✓ MATCH — Line {line}, col {col}–{end_col} ({node_type})` in green
  - `✗ No match` in gray
  - `⚠ Query error: {message}` in red
- Updates within 2 seconds of any change to the YAML editor or test code

**12e. Test cases panel**

Right column, middle section:
- Label: "Test Cases" + pass/fail summary badge (e.g. "2/2 passing")
- Each test case from the `test_cases` block rendered as a row:
  - Code snippet (truncated to 1 line, expandable)
  - Expected: `TruePositive` or `TrueNegative` badge
  - Actual: `✓ PASS` (green) or `✗ FAIL` (red)
- "Add test case" button appends a new empty test case to the YAML

**12f. Policy mode + save**

Right column, bottom section:
- Policy Mode selector: Monitor / Comment / Block / Disabled (dropdown)
- Status toggle: Enabled / Disabled
- `[Save Rule]` button (primary, accent color) — validates then saves
- `[Validate]` button (secondary) — runs validation without saving
- `[Cancel]` link — navigates back to Rules & Policies

**12g. Keyboard shortcuts**

- `Cmd/Ctrl+S` — Save Rule
- `Cmd/Ctrl+Enter` — Validate
- `Cmd/Ctrl+Shift+G` — Generate with AI Assist (if description is filled)

**File:** `sicario-frontend/src/pages/dashboard/RuleEditorPage.tsx` (new)

---

## 13. Sidebar Update for Rules & Policies

Add "Rules & Policies" to the COMPLIANCE section in the sidebar (§1c):

```
COMPLIANCE
  OWASP
  Rules & Policies  ← new
```

The nav item links to `/dashboard/policies`. The badge shows the count of custom rules (0 if none, which renders as no badge).

**File:** `sicario-frontend/src/components/dashboard/Sidebar.tsx`

---

## Implementation Notes for Rule Editor

**YAML editor library:** `@uiw/react-codemirror` with `@codemirror/lang-yaml`. This is a well-maintained CodeMirror 6 wrapper for React. Add to `package.json`.

**Debounced validation:** Use a `useEffect` with a 500ms debounce on the YAML + test code state. Cancel the previous request on each new keystroke to avoid race conditions.

**Test code privacy:** The live test panel includes a small notice below the textarea: "Test code is sent to the validation server for pattern matching and is never stored." This is the UI-level disclosure of the zero-exfil behavior documented in Requirement 39 AC 4.

**AI Assist disclosure:** The AI Assist panel includes a note: "Your description is sent to your configured LLM provider ({provider_name}). No source code is transmitted." The provider name is read from the org's LLM config.

**Rule ID namespace:** Custom rules are namespaced with `org/` prefix by convention (e.g. `org/my-sql-check`). The editor enforces this: if the user types an ID without the `org/` prefix, the editor adds it automatically and shows a tooltip explaining the namespace.

**Fork behavior:** Forking a built-in rule copies its YAML, changes the `id` to `org/{original-id}`, and opens the editor with the forked YAML pre-loaded. The user can then modify the pattern, add test cases, and save.
