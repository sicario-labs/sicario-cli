# Sicario Dashboard vs. Semgrep AppSec Platform — Gap Analysis

**Date:** May 2026  
**Purpose:** Exhaustive feature-by-feature comparison. Every gap is zero-exfil compatible unless explicitly noted otherwise.

---

## How to Read This

- ✅ **Have it** — feature exists in the current Convex backend
- ⚠️ **Partial** — scaffolding exists but feature is incomplete
- ❌ **Missing** — not present at all
- 🚫 **Skip** — Semgrep has it but it conflicts with zero-exfil or is out of scope

---

## 1. Findings Page

| Feature | Sicario | Semgrep | Notes |
|---|---|---|---|
| List findings with pagination | ✅ `findings.list`, `findings.listAdvanced` | ✅ | |
| Filter by severity | ✅ | ✅ | |
| Filter by triage state | ✅ | ✅ | |
| Filter by confidence score | ✅ | ✅ | |
| Filter by OWASP category | ✅ | ✅ | |
| Filter by project | ✅ | ✅ | |
| Filter by scan ID | ✅ | ✅ | |
| Full-text search (rule ID, file path, snippet) | ✅ | ✅ | |
| Sort by severity, confidence, file path, date | ✅ | ✅ | |
| Cursor-based pagination | ✅ | ✅ | |
| **Group by Rule view** | ❌ | ✅ | Semgrep groups findings by rule ID, showing a card per rule with a count of affected files. Reduces visual noise dramatically for orgs with many findings from the same rule. |
| **Filter by branch / ref** | ❌ | ✅ | Semgrep shows findings per branch. Sicario has no `branch` field on findings. |
| **Filter by CWE** | ❌ | ✅ | `cweId` exists on findings but no filter endpoint exposes it. |
| **Filter by language** | ❌ | ✅ | No language field on findings. Would need to be derived from file extension or scan metadata. |
| **Filter by committer / author** | ❌ | ✅ | Semgrep tracks who introduced the finding (commit author). Useful for routing to the right dev. |
| **Filter by date introduced** | ❌ | ✅ | `createdAt` exists but no date-range filter in `listAdvanced`. |
| **Saved filter presets** | ❌ | ✅ | Semgrep lets users save named filter combinations (e.g. "Critical open findings in auth service"). |
| **Bulk triage** | ✅ `findings.bulkTriage` | ✅ | Sicario has it. |
| **Bulk triage with ignore reason** | ❌ | ✅ | `bulkTriage` accepts `triageNote` but no structured `ignoreReason` enum. |
| **Triage via PR comment** (`/fp`, `/ar`, `/other`, `/open`) | ❌ | ✅ | Planned in Req 23 but not implemented. |
| **Adjacent finding navigation** (prev/next) | ✅ `findings.getAdjacentIds` | ✅ | |
| **Export findings** (CSV/JSON) | ⚠️ `findings.listForExport` (JSON only) | ✅ CSV + JSON + SARIF | CSV and SARIF export missing. |
| **SARIF export** | ❌ | ✅ | Standard format for GitHub Advanced Security, Azure DevOps. |
| **"No grouping" vs "Group by Rule" toggle** | ❌ | ✅ | |

---

## 2. Finding Detail Page

| Feature | Sicario | Semgrep | Notes |
|---|---|---|---|
| Rule ID, rule name, severity, CWE, OWASP | ✅ | ✅ | |
| File path, line, column, end line/column | ✅ | ✅ | |
| Code snippet | ✅ | ✅ | |
| Confidence score | ✅ | ✅ | |
| Reachability flag | ✅ | ✅ | |
| Triage state + note | ✅ | ✅ | |
| Assigned to | ✅ | ✅ | |
| Created at / updated at | ✅ | ✅ | |
| **Activity / audit trail per finding** | ⚠️ `findings.getTimeline` (only 2 events: created + triaged) | ✅ Full history: opened, triaged, reopened, fixed, notes added, Jira linked | The timeline is a stub. Needs a proper `findingEvents` table with one row per state transition, including who made the change and any note. |
| **Add notes to a finding** | ❌ | ✅ | Semgrep lets any team member add free-text notes to the activity history. Sicario has `triageNote` but it's a single overwritten field, not an append-only log. |
| **Dataflow / taint trace visualization** | ⚠️ `executionTrace` field exists | ✅ Source → intermediate → sink chain with line highlights | The field is stored but there's no structured schema for multi-hop traces. Needs `taintPath: [{file, line, column, nodeType}]` array. |
| **Link to source code in SCM** | ❌ | ✅ | Semgrep generates a direct link to the file+line in GitHub/GitLab. Requires `repositoryUrl + commitSha + filePath + line`. All data is available in Sicario — just not assembled into a link. |
| **CWE tooltip / description** | ❌ | ✅ | Semgrep shows the CWE name and description inline. |
| **OWASP category description** | ❌ | ✅ | |
| **Branch / ref shown on finding** | ❌ | ✅ | Findings don't carry a `branch` field. |
| **Commit SHA shown on finding** | ❌ | ✅ | Available on the scan but not denormalized onto the finding. |
| **Committer name shown on finding** | ❌ | ✅ | Not tracked. |
| **Jira ticket creation / linking** | ❌ | ✅ | Semgrep creates Jira tickets from findings with AI-generated remediation guidance embedded. Zero-exfil compatible: only rule_id, file_path, line, severity, CWE, and a remediation message are sent — no source code. |
| **"Open PR with fix" action** | ⚠️ `autoFixPRs` table exists for SCA | ✅ | SAST autofix PR not wired to the finding detail page. |
| **Ignore with reason enum** | ❌ | ✅ `false_positive`, `acceptable_risk`, `no_time_to_fix` | `triageNote` is free text. Needs a structured `ignoreReason` field. |
| **"Reviewing" and "To Fix" triage states** | ⚠️ `Reviewing` and `ToFix` exist in `deduplicateByRuleAndFile` but not enforced in schema | ✅ | The states exist in code but aren't in the schema's union type. |
| **Alert box for critical triage info** | ❌ | ✅ | Semgrep shows a prominent alert at the top of the detail page if a finding is reachable, validated (secrets), or AI-flagged as FP. |
| **Permalink to finding detail** | ❌ | ✅ | Shareable URL for a specific finding. |

---

## 3. Projects Page

| Feature | Sicario | Semgrep | Notes |
|---|---|---|---|
| List projects | ✅ | ✅ | |
| Create / update / delete project | ✅ | ✅ | |
| Project provisioning state (pending/active/failed) | ✅ | ✅ (Pending/Active/Error) | |
| Project API key per project | ✅ | ✅ | |
| Rotate API key | ✅ | ✅ | |
| Slack alerting config per project | ✅ | ✅ | |
| Severity threshold per project | ✅ | ✅ | |
| Auto-fix enabled toggle | ✅ | ✅ | |
| **Project tags / labels** | ❌ | ✅ | Semgrep lets you tag projects (e.g. `team:payments`, `external-facing`, `tier-1`). Tags are filterable on the Projects page and usable in policy scoping. High value for large orgs. |
| **Primary branch configuration** | ❌ | ✅ | Semgrep lets you set which branch is the "default" for full scans and backlog metrics. Sicario always uses whatever branch the scan was run on. |
| **Path ignores per project** | ❌ | ✅ | Semgrep lets you configure file path patterns to ignore per project from the dashboard (equivalent to `.semgrepignore` but managed centrally). |
| **Scanning tab vs. Not Scanning tab** | ❌ | ✅ | Semgrep separates actively scanned projects from connected-but-not-scanning repos. Useful for tracking coverage gaps. |
| **Bulk rescan** | ❌ | ✅ | Trigger a rescan of multiple projects at once from the Projects page. |
| **Scan details drawer** | ❌ | ✅ | Hover over a scan status to get a drawer with scan logs, duration breakdown, parse errors. |
| **Scan history per project** | ⚠️ `scans.list` with `projectId` filter | ✅ | Data exists but no dedicated project detail page with scan history timeline. |
| **Scan duration trend chart** | ❌ | ✅ | Per-project chart of scan duration over time. Useful for catching performance regressions. |
| **Scan type filter** (full vs. diff-aware) | ❌ | ✅ | Sicario doesn't distinguish full vs. diff-aware scans in the schema. |
| **Permalink to scan details** | ❌ | ✅ | |
| **Framework field** | ✅ | ✅ | |
| **Team assignment** | ✅ | ✅ | |

---

## 4. Dashboard / Analytics Page

| Feature | Sicario | Semgrep | Notes |
|---|---|---|---|
| Total open findings count | ✅ `analytics.overview` | ✅ | |
| Severity breakdown (Critical/High/Medium/Low) | ✅ | ✅ | |
| Total scans count | ✅ | ✅ | |
| Fixed findings count | ✅ | ✅ | |
| Ignored findings count | ✅ | ✅ | |
| MTTR overall + by severity | ✅ `analytics.mttr` | ✅ | |
| Top vulnerable projects | ✅ `analytics.topVulnerableProjects` | ✅ | |
| OWASP compliance breakdown | ✅ `analytics.owaspCompliance` | ✅ | |
| Findings by language | ✅ `analytics.findingsByLanguage` | ✅ | |
| Findings trend over time (new/fixed per day) | ✅ `analytics.trends` | ✅ | |
| **Backlog activity chart** (new/fixed/ignored/net per period) | ❌ | ✅ | `analytics.trends` has new+fixed but not ignored, and no net-change calculation. |
| **Production backlog trend** (open findings on default branch over time) | ❌ | ✅ | Sicario has no concept of "default branch" — all findings are mixed together regardless of branch. |
| **Guardrails adoption rate** (findings shown in PR vs. total; fixed before backlog vs. shown in PR) | ❌ | ✅ | Requires tagging findings with `surfaced_in_pr: bool` at scan time. The `prChecks` table has the data but it's not joined to findings. |
| **Median open age by severity** | ❌ | ✅ | `analytics.mttr` computes mean MTTR for fixed findings. Median age of *open* findings is a different and more useful metric. |
| **Developer engagement metrics** | ❌ | ✅ | Semgrep tracks how many unique developers have interacted with findings (viewed, triaged, commented). |
| **Date range filter on all charts** | ❌ | ✅ | `analytics.trends` has `from`/`to` but `overview`, `mttr`, `topVulnerableProjects`, `owaspCompliance` have no date filter. |
| **Per-project drill-down on dashboard** | ❌ | ✅ | Semgrep lets you filter the entire dashboard to a single project. |
| **Scan type breakdown** (SAST vs. supply-chain vs. secrets) | ❌ | ✅ | All findings are mixed. No `scan_type` field. |
| **Fix rate** (% of findings fixed vs. total detected) | ❌ | ✅ | Derivable from existing data but not exposed as a metric. |

---

## 5. Policies / Rules Page

| Feature | Sicario | Semgrep | Notes |
|---|---|---|---|
| Per-rule policy modes (Monitor/Comment/Block/Disabled) | ⚠️ Planned in Req 19, not implemented | ✅ | |
| Policy fetch by CLI before scan | ⚠️ Planned in Req 19, not implemented | ✅ | |
| **Rules page / rule browser** | ❌ | ✅ | Semgrep has a full Rules & Policies page where you can browse all active rules, see their metadata (CWE, severity, language), and change their mode. Sicario has no rule management UI at all. |
| **Custom rule editor** | ❌ | ✅ | Semgrep has an in-browser rule editor (Playground) where you can write, test, and save custom rules. Zero-exfil compatible: the editor runs locally or sends only the rule YAML + test snippet, not production code. |
| **Rule scoping by project / tag** | ❌ | ✅ | Semgrep's March 2026 update lets you scope each rule to specific projects or tags rather than applying it globally. |
| **Unified policies** (detection policy + remediation policy split) | ❌ | ✅ (beta) | Detection policy = which rules run. Remediation policy = what happens to findings (comment, block, Jira ticket, Slack). More flexible than per-rule modes. |
| **Policy-triggered Jira ticket creation** | ❌ | ✅ | Remediation policy can auto-create a Jira ticket when a finding matches a rule. |
| **Policy-triggered Slack notification** | ⚠️ Slack webhook per project | ✅ | Sicario has per-project Slack webhooks but they're not policy-driven (not tied to rule modes). |

---

## 6. Notifications & Integrations

| Feature | Sicario | Semgrep | Notes |
|---|---|---|---|
| Outbound webhooks | ✅ `webhooks.ts` | ✅ | |
| Webhook delivery log | ✅ `webhookDeliveries` | ✅ | |
| Slack integration | ⚠️ Per-project webhook URL only | ✅ Full Slack app with per-rule filtering | Semgrep's Slack integration is a proper app with configurable notification rules. Sicario's is a raw webhook URL. |
| Email notifications | ✅ `emails.ts` (plan upgrade, invitations) | ✅ Per-finding email alerts | Sicario sends transactional emails but not finding alert emails. |
| **Jira integration** | ❌ | ✅ | Create tickets from findings with AI remediation guidance embedded. Zero-exfil: only metadata sent, no source code. |
| **Email alerts for new findings** | ❌ | ✅ | Semgrep can email on new findings matching a severity threshold. |
| **Notification filtering by rule mode** | ❌ | ✅ | Semgrep only notifies on findings from rules in Comment or Block mode. |
| **Linear / GitHub Issues integration** | ❌ | ❌ | Neither has this. Worth adding — Linear is common in startups. |
| **PagerDuty / OpsGenie integration** | ❌ | ❌ | Neither has this. |

---

## 7. Access Control & Team Management

| Feature | Sicario | Semgrep | Notes |
|---|---|---|---|
| Roles: admin / manager / developer | ✅ `rbac.ts` | ✅ | |
| Team-scoped project access | ✅ | ✅ | |
| Invite members by email | ✅ `invitations.ts` | ✅ | |
| Remove members | ✅ | ✅ | |
| Leave org (with last-admin guard) | ✅ | ✅ | |
| SSO (SAML / OIDC) | ✅ `ssoConfigs` table | ✅ | |
| **Role: viewer (read-only)** | ❌ | ✅ | Semgrep has a read-only viewer role. Sicario's lowest role is `developer` which can triage. |
| **Team-scoped finding visibility** | ❌ | ✅ | Semgrep can restrict which findings a team sees based on project tags. Sicario's team scoping is at the project level but findings aren't filtered by team membership. |
| **API token management** | ⚠️ Per-project API keys only | ✅ Org-level API tokens + per-project | Sicario has no org-level API token for the CLI (`SICARIO_API_KEY`). |
| **Network Broker / private network access** | ❌ | ✅ (enterprise) | Semgrep's Network Broker lets the platform reach self-hosted SCMs. Out of scope for now. |

---

## 8. Scan Management

| Feature | Sicario | Semgrep | Notes |
|---|---|---|---|
| Ingest scan results via API | ✅ `scans.insert` | ✅ | |
| Scan metadata (repo, branch, commit, duration, files, languages) | ✅ | ✅ | |
| Auto-resolve findings absent from latest scan | ✅ | ✅ | |
| Re-open findings that reappear | ✅ | ✅ | |
| PR check tracking | ✅ `prChecks.ts` | ✅ | |
| **Diff-aware scan flag** | ❌ | ✅ | Semgrep distinguishes full scans from diff-aware scans. Sicario treats all scans the same. |
| **Scan type field** (SAST / SCA / secrets) | ❌ | ✅ | |
| **Scan status** (running / completed / error / never finished) | ❌ | ✅ | Sicario has no scan status — scans are inserted as completed. |
| **Scan logs** | ❌ | ✅ | Semgrep stores CI logs per scan for debugging. |
| **Scheduled scans** | ✅ `scheduledScans.ts` | ✅ | |
| **Bulk rescan trigger** | ❌ | ✅ | |
| **Scan permalink** | ❌ | ✅ | |

---

## 9. Billing & Usage

| Feature | Sicario | Semgrep | Notes |
|---|---|---|---|
| Plans: free / pro / team / enterprise | ✅ | ✅ | |
| Seat count tracking | ✅ | ✅ | |
| Usage summary (findings stored, scans submitted, project count) | ✅ | ✅ | |
| Audit log (billing events) | ✅ `auditLog` | ✅ | |
| **Usage dashboard** (visual charts of scan volume, finding volume over time) | ❌ | ✅ | Semgrep shows usage trends in the billing/settings area. |
| **Seat usage breakdown by contributor** | ❌ | ✅ | Semgrep shows which developers are counted as contributors. |

---

## 10. Zero-Exfil Audit (Sicario-Unique)

| Feature | Sicario | Semgrep | Notes |
|---|---|---|---|
| Machine-readable audit log per scan | ✅ (CLI-side, Req 21) | ❌ | Sicario's structural advantage. |
| `sicario audit show` / `sicario audit verify` | ✅ (planned) | ❌ | |
| `code_hash` instead of snippet in publish payload | ✅ (Req 25) | ⚠️ Semgrep sends a one-way hash too, but doesn't expose this as a verifiable guarantee | |
| Air-gap mode (no transmissions when no API key) | ✅ | ❌ | |

---

## Priority Gap List — What to Build Next

Ranked by impact-to-effort ratio, all zero-exfil compatible.

### Tier 1 — High impact, low effort (schema + query changes)

1. **Branch field on findings** — add `branch: string` to the `findings` schema, populated from the scan's `branch` field at insert time. Unlocks branch filtering, production backlog metric, and per-branch triage propagation.

2. **Structured ignore reason** — add `ignoreReason: "false_positive" | "acceptable_risk" | "no_time_to_fix" | null` to the `findings` schema. One field, massive workflow improvement.

3. **`findingEvents` table** — replace the stub `getTimeline` with a proper append-only event log: `{findingId, eventType, fromState, toState, userId, note, timestamp}`. Enables full activity history, notes, and accurate MTTR.

4. **CWE filter in `listAdvanced`** — `cweId` is already on findings. Just add it to the filter logic.

5. **Date-range filter on all analytics queries** — `overview`, `mttr`, `topVulnerableProjects`, `owaspCompliance` all need `from`/`to` params.

6. **`surfaced_in_pr` flag on findings** — boolean set at scan insert time when the finding was surfaced in a PR check. Enables guardrails adoption rate metric.

7. **`scan_type` field on scans** — `"full" | "diff_aware"`. One field, enables production backlog metric and scan type filtering.

8. **`viewer` role in RBAC** — add `viewer: 0` to `ROLE_LEVELS`. Read-only access for stakeholders who need dashboard visibility but shouldn't triage.

### Tier 2 — Medium impact, medium effort

9. **Group by Rule view** — server-side aggregation query: group open findings by `ruleId`, return `{ruleId, ruleName, count, severity, cweId, affectedFiles[]}`. The most impactful UX change for orgs with high finding volume.

10. **SCM deep link on finding detail** — assemble `repositoryUrl + commitSha + filePath + line` into a GitHub/GitLab URL. All data is already in the DB.

11. **SARIF export** — add a `listForExport` variant that outputs SARIF 2.1.0 JSON. Required for GitHub Advanced Security Dashboard integration.

12. **Backlog activity chart data** — extend `analytics.trends` to include `ignored` count and `net_change` per period.

13. **Median open age metric** — new analytics query: for each severity, compute `median(now - createdAt)` across open findings.

14. **Project tags** — add `tags: string[]` to the `projects` schema. Enables policy scoping and project filtering by team/tier.

15. **Primary branch per project** — add `primaryBranch: string` to `projects`. Used to scope production backlog metrics.

16. **Jira integration** — webhook-based: when a finding is triaged as `to_fix`, POST to a configured Jira endpoint with `{summary, description, priority, labels}`. No source code in the payload — only rule_id, file_path, line, severity, CWE, and a remediation message.

### Tier 3 — High impact, high effort

17. **Rules / Policies page** — UI for browsing active rules, changing policy modes (Monitor/Comment/Block/Disabled), and scoping rules to projects/tags. Backend: `policies` table with `{ruleId, mode, projectScope}`.

18. **Per-finding activity notes** — append-only notes on findings (requires `findingEvents` table from item 3).

19. **Taint trace structured schema** — replace `executionTrace: string[]` with `taintPath: [{file, line, column, nodeType, role: "source"|"intermediate"|"sink"}]`. Enables proper dataflow visualization.

20. **Guardrails adoption dashboard section** — requires items 6 (surfaced_in_pr), 7 (scan_type), and 15 (primary branch) to be in place first.

---

## Features to Skip (Zero-Exfil Conflicts or Out of Scope)

| Feature | Reason to Skip |
|---|---|
| Semgrep Managed Scanning (code access) | Requires granting Semgrep read access to source code. Fundamentally incompatible with zero-exfil. Sicario's Managed CI Config (Req 20) is the correct alternative. |
| Semgrep Multimodal AI triage (cloud AI) | Sends code context to Semgrep's AI subprocessors. Sicario's equivalent is `--agent=local` (Ollama) or user-configured LLM with explicit consent. |
| Semgrep Supply Chain reachability (cloud-side) | Semgrep's reachability analysis for SCA requires sending dependency graphs to their platform. Sicario's supply-chain guard runs locally. |
| Semgrep Secrets validation (cloud-side) | Validates secrets by making live API calls from Semgrep's infrastructure. Out of scope. |
| Network Broker | Enterprise-only, complex infrastructure. Future roadmap item. |
| SBOM export | Not a SAST feature. Future roadmap item for supply-chain guard. |
