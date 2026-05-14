# Design Document — Sicario v0.3.5 Engine Quality

## Overview

This document covers the architectural decisions for the features introduced in v0.3.5, with particular focus on the dashboard ↔ CLI integration layer (Requirements 18–25). It is informed by a detailed analysis of Semgrep's AppSec Platform architecture — what to copy, what to improve on, and what to reject outright to preserve the zero-exfiltration model.

---

## Semgrep Research Summary

### What Semgrep Does Well (Worth Copying)

**Finding fingerprinting.** Semgrep uses two fingerprints per finding:
- `match_based_id` = SHA-256 of `(file_path + rule_id + pattern_with_metavar_values_substituted)` + `_<index>` suffix. Stable across line-number shifts. Used for cross-branch triage propagation.
- `syntactic_id` = SHA-256 of `(file_path + rule_id + literal_matched_code + match_index)`. Used only for internal dedup, never transmitted.

Sicario's Requirement 18 already matches this design exactly. The key insight: the `match_based_id` uses the *abstracted pattern with values substituted*, not the raw code. This means the hash is stable even when surrounding lines change, and it reveals nothing about the code to the cloud.

**Policy modes.** Semgrep's Monitor / Comment / Block / Disabled model is the right abstraction. It decouples "does this rule fire?" from "what happens when it fires?" — which is exactly what enterprise AppSec teams need to roll out scanning without immediately blocking every PR.

**Triage lifecycle.** Semgrep's triage states (Open → Reviewing → To Fix → Ignored / Fixed / Removed) map cleanly to real remediation workflows. The `Removed` vs `Fixed` distinction is critical for accurate MTTR: a finding that disappears because the rule was disabled is not a remediation win.

**PR comment triage commands.** `/fp`, `/ar`, `/other`, `/open` — these are a high-leverage DX feature. Developers can dismiss false positives without leaving their code review context. The implementation is a webhook listener that parses comment text.

**Dashboard metrics.** The most useful charts Semgrep shows:
- Backlog activity (new/fixed/ignored/net per period)
- Production backlog trend (open findings on default branch over time)
- Guardrails adoption (findings fixed in PR vs. reaching default branch)
- Median open age by severity (median, not mean — avoids outlier skew)
- MTTR by severity (Fixed findings only)

**Managed scanning onboarding UX.** The `Pending / Active / Error` status model for repo onboarding is clean and maps directly to Sicario's Managed CI Config workflow.

### What Semgrep Does That Sicario Must Not Copy

**Managed scanning code access.** Semgrep's managed scanning requires granting Semgrep read access to source code. Their infrastructure clones the repo, scans it, deletes the clone. This is fundamentally incompatible with zero-exfiltration. Sicario's Managed CI Config (Requirement 20) is the correct alternative: commit a workflow file, run scans on the customer's own CI runners, upload only structured metadata.

**Snippet in publish payload.** Semgrep transmits a one-way hash of the triggering code to the platform. Sicario's original spec included a 100-char truncated snippet. The hash approach (Requirement 25) is strictly better for the zero-exfil story — it's structurally non-reversible rather than just "short enough to be low-risk."

**Metrics telemetry without explicit consent.** Semgrep enables metrics by default when rules are loaded from the registry. Sicario's telemetry model should be opt-in only, consistent with the zero-exfil guarantee.

---

## Architecture: Dashboard ↔ CLI Integration

### Data Flow

```
Developer machine / CI runner
┌─────────────────────────────────────────────────────────────┐
│  sicario ci                                                  │
│  ┌──────────────┐   policy fetch (rule_id → mode map)       │
│  │ Policy Cache │ ◄─────────────────────────────────────────┼── Sicario Cloud
│  └──────────────┘   TTL: 1 hour, stored in                  │
│                     .sicario/cache/policy-<org-id>.json      │
│                                                              │
│  ┌──────────────┐                                            │
│  │ SAST Engine  │  scans source files locally               │
│  └──────┬───────┘                                            │
│         │ findings (in-memory)                               │
│  ┌──────▼───────┐                                            │
│  │ Fingerprinter│  computes match_based_id + syntactic_id   │
│  └──────┬───────┘                                            │
│         │                                                    │
│  ┌──────▼───────┐  applies policy modes                      │
│  │ Policy Filter│  Block → exit 1                            │
│  │              │  Comment → post PR comment via SCM API     │
│  │              │  Monitor → upload only                     │
│  │              │  Disabled → skip                           │
│  └──────┬───────┘                                            │
│         │                                                    │
│  ┌──────▼───────┐  structured metadata only                  │
│  │ Publisher    │ ──────────────────────────────────────────►│ Sicario Cloud
│  │              │  {rule_id, file_path, line, severity,      │
│  │              │   cwe_id, match_based_id, code_hash,       │
│  │              │   triage_state}                            │
│  └──────┬───────┘                                            │
│         │                                                    │
│  ┌──────▼───────┐                                            │
│  │ Audit Logger │  writes .sicario/audit/scan-<ts>.json      │
│  └──────────────┘                                            │
└─────────────────────────────────────────────────────────────┘

Source code never crosses this boundary →
```

### Policy Sync Protocol

The policy fetch is a single GET request:

```
GET /api/v1/orgs/{org_id}/policy
Authorization: Bearer {SICARIO_API_KEY}

Response:
{
  "org_id": "...",
  "fetched_at": "2026-05-07T12:00:00Z",
  "rules": [
    {"rule_id": "js-sql-string-concat", "mode": "block"},
    {"rule_id": "js-hardcoded-secret",  "mode": "comment"},
    {"rule_id": "js-xss-innerhtml",     "mode": "monitor"},
    {"rule_id": "js-eval-injection",    "mode": "disabled"}
  ]
}
```

The response contains only rule IDs and modes — no source code, no finding data, no user data. The CLI caches this to `.sicario/cache/policy-<org-id>.json` with a 1-hour TTL. On cache hit, no network request is made.

### Finding Upload Protocol

The publish payload per finding:

```json
{
  "rule_id": "js-sql-string-concat",
  "file_path": "src/db/queries.js",
  "line": 42,
  "column": 8,
  "severity": "high",
  "cwe_id": "CWE-89",
  "match_based_id": "a3f8c2...d4_0",
  "syntactic_id": null,
  "code_hash": "sha256:e3b0c44298fc1c149afb...",
  "triage_state": "open",
  "scan_id": "scan-2026-05-07T12:00:00Z"
}
```

`syntactic_id` is never included in the upload payload. `code_hash` is a one-way SHA-256 of the matched code text. Raw code is never transmitted unless `--publish-with-snippet` is explicitly provided.

### Triage State Machine

```
                    ┌─────────┐
         ┌──────────►  Open   ◄──────────────────────┐
         │          └────┬────┘                       │
         │ /open         │ manual                     │ /open
         │               ├──────────► Reviewing       │
         │               │            │               │
         │               │ manual     │ manual        │
         │               ├──────────► To Fix          │
         │               │                            │
         │               │ /fp /ar /other             │
         │               └──────────► Ignored ────────┘
         │
         │  (automatic, code changed)
         └── Fixed
         │
         │  (automatic, rule disabled / file deleted)
         └── Removed
```

State transitions:
- `Open → Reviewing / To Fix / Ignored`: manual (dashboard UI or PR comment command)
- `Reviewing / To Fix → Ignored`: manual
- `Ignored → Open`: manual (`/open` command or dashboard)
- `* → Fixed`: automatic, set by scan engine when finding no longer detected and code was modified
- `* → Removed`: automatic, set by scan engine when rule disabled or file deleted/ignored
- `Fixed / Removed` are terminal — they cannot be manually transitioned

### PR Comment Triage Webhook

When `sicario ci` posts a PR comment, it registers a webhook on the SCM for comment events on that PR. The webhook handler:

1. Receives the comment event payload (contains comment text, PR ID, repo ID, commenter identity).
2. Parses the first token of the comment body for a triage command: `/fp`, `/ar`, `/other`, `/open`.
3. Looks up the finding by matching the PR comment ID to the finding record in Sicario Cloud.
4. Validates that the commenter has triage permission for the org.
5. Applies the triage state transition.
6. Propagates the state to all findings with the same `match_based_id` across all branches.
7. Posts a confirmation reply to the PR comment.

The webhook payload contains: comment text, PR metadata, commenter identity. No source code is transmitted.

---

## Architecture: Fingerprinting

### `match_based_id` Computation

```rust
fn compute_match_based_id(
    file_path: &str,       // relative path from project root
    rule_id: &str,
    pattern_with_values: &str,  // rule pattern with metavar values substituted
    match_index: usize,    // 0-indexed count of same pattern matches in file
) -> String {
    let input = format!("{}\x00{}\x00{}", file_path, rule_id, pattern_with_values);
    let hash = sha256(input.as_bytes());
    format!("{}_{}", hex::encode(hash), match_index)
}
```

The `pattern_with_values` is the rule's tree-sitter pattern with all `$VAR` metavariables replaced by their matched values from the AST. This makes the ID stable across line-number shifts (adding/removing lines above the match doesn't change the hash) while still being specific to the actual matched code pattern.

### `syntactic_id` Computation

```rust
fn compute_syntactic_id(
    file_path: &str,
    rule_id: &str,
    matched_code: &str,    // literal matched source text
    match_index: usize,
) -> String {
    let input = format!("{}\x00{}\x00{}\x00{}", file_path, rule_id, matched_code, match_index);
    let hash = sha256(input.as_bytes());
    hex::encode(hash)
}
```

`syntactic_id` is stored in the local scan cache for internal deduplication. It is never transmitted to Sicario Cloud.

### `code_hash` Computation

```rust
fn compute_code_hash(matched_code: &str) -> String {
    let hash = sha256(matched_code.as_bytes());
    format!("sha256:{}", hex::encode(hash))
}
```

This is a one-way hash of the raw matched code text. It is included in the publish payload for deduplication and change detection on the cloud side. It is not reversible without the original text.

---

## Architecture: MTTR and Dashboard Metrics

### Existing Implementation

`sicario-cli/src/reporting/mttr.rs` already implements:
- Per-rule MTTR computation from patch history + baseline timestamps
- Arithmetic mean MTTR per rule (with ≥3 findings threshold)
- Trend indicators (↑ improving / ↓ worsening / → stable, ±10% threshold)
- ASCII table and JSON rendering
- `--since` filter for time-bounded reporting

### Gaps to Fill for v0.3.5

**Median open age.** The existing MTTR module computes mean MTTR for *remediated* findings. We need a separate metric for the median age of *open* findings. This requires access to the finding's `first_detected_at` timestamp, which is stored in the cloud but not currently in the local scan cache.

Design: add `first_detected_at` to the local scan cache entry. On each scan, if a finding's `match_based_id` already exists in the cache, preserve the original `first_detected_at`. If it's new, set `first_detected_at = now`. The median open age is then `median(now - first_detected_at)` across all open findings.

**Fixed vs. Removed distinction.** The current MTTR computation uses all remediated findings from `patch_history.json`. It cannot distinguish between a finding that was fixed (code changed) and one that was removed (rule disabled). 

Design: add a `resolution_type` field to `PatchHistoryEntry` with values `fixed` and `removed`. The MTTR computation filters to `resolution_type == "fixed"` only. The scan engine sets `resolution_type` based on whether the finding disappeared due to a code change (compare file hash before/after) or a rule/ignore change.

**Backlog activity.** The dashboard needs new/fixed/ignored/net counts per time period. This is a cloud-side aggregation over the finding metadata stream. The CLI's `sicario report --dashboard` command fetches pre-aggregated metrics from the cloud API.

**Guardrails adoption rate.** Requires tracking which findings were surfaced in PR comments (Comment/Block mode) vs. which reached the default branch. The scan engine already knows the policy mode per finding — it needs to tag each finding with `surfaced_in_pr: bool` in the upload payload.

### `sicario report --dashboard` Command

```
sicario report --dashboard [--format json] [--since <date>] [--project <name>]
```

Fetches pre-aggregated metrics from Sicario Cloud:

```json
{
  "org_id": "...",
  "period": "last_30_days",
  "backlog_activity": {
    "new": 142,
    "fixed": 87,
    "ignored": 23,
    "net_change": 32
  },
  "production_backlog": {
    "current_open": 318,
    "trend": "increasing"
  },
  "guardrails_adoption": {
    "findings_shown_in_pr": 89,
    "findings_total": 142,
    "adoption_rate_pct": 62.7,
    "fixed_before_backlog": 41,
    "fixed_before_backlog_pct": 46.1
  },
  "median_open_age_days": {
    "critical": 3.2,
    "high": 12.5,
    "medium": 34.1,
    "low": 67.8
  },
  "mttr_hours": {
    "critical": 18.4,
    "high": 72.1,
    "medium": 168.3,
    "low": 312.0
  }
}
```

All values are derived from structured finding metadata. No source code is accessed.

---

## Architecture: Managed CI Config

### Onboarding Flow

```
AppSec team lead (dashboard)
  │
  ├─ 1. Connects GitHub/GitLab org via OAuth app
  │       (read: repo list, branch names; write: files, secrets)
  │
  ├─ 2. Selects repositories to onboard
  │
  ├─ 3. Sicario Cloud generates CI workflow YAML
  │       (no source code read — only repo metadata needed)
  │
  ├─ 4. Commits workflow file to default branch via SCM API
  │       .github/workflows/sicario.yml  (GitHub)
  │       .gitlab-ci.yml addition        (GitLab)
  │
  ├─ 5. Stores SICARIO_API_KEY as repository secret via SCM API
  │
  └─ 6. Dashboard shows repo status: Pending
         → first scan completes → Active
         → scan fails → Error (with error details)
```

### Generated Workflow File (GitHub Actions)

```yaml
# Sicario Security Scan
# Zero-exfiltration notice: This workflow runs entirely on your CI runners.
# Only structured finding metadata (rule_id, file_path, line, severity) is
# uploaded to Sicario Cloud. Source code never leaves your infrastructure.
name: Sicario Security Scan
on:
  pull_request: {}
  schedule:
    - cron: '0 2 * * 1'  # weekly full scan, Monday 02:00 UTC
  push:
    branches: [main, master]

jobs:
  sicario:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # required for diff-aware scans
      - name: Install Sicario
        run: curl -fsSL https://install.sicario.dev | sh
      - name: Run Sicario CI scan
        run: sicario ci --publish
        env:
          SICARIO_API_KEY: ${{ secrets.SICARIO_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The workflow is idempotent: if it already exists, the cloud backend updates it in place via a PUT to the SCM API.

---

## Architecture: Audit Log

### Schema

```json
{
  "schema_version": "1.0",
  "guarantee": "Source code is never transmitted to Sicario Cloud. A one-way SHA-256 hash of matched code is uploaded for deduplication. The hash is not reversible to source code. Raw code excerpts are only transmitted when --publish-with-snippet is explicitly provided.",
  "scan_id": "scan-2026-05-07T12:00:00Z",
  "started_at": "2026-05-07T12:00:00Z",
  "completed_at": "2026-05-07T12:00:47Z",
  "files_scanned": 1247,
  "findings_count": 3,
  "transmissions": [
    {
      "destination": "sicario-cloud",
      "payload_type": "policy_fetch",
      "payload_size_bytes": 412,
      "lines_of_code_transmitted": 0,
      "consent_obtained": true
    },
    {
      "destination": "sicario-cloud",
      "payload_type": "finding_metadata",
      "payload_size_bytes": 1840,
      "lines_of_code_transmitted": 0,
      "consent_obtained": true
    }
  ]
}
```

When `--publish-with-snippet` is active, the `finding_metadata` entry has `lines_of_code_transmitted > 0`. When `--agent=local` is active, a `llm_context` entry appears with `destination: "127.0.0.1:11434"`. When no `--publish` and no `SICARIO_API_KEY`, `transmissions` is an empty array.

### Atomic Write

The audit log is written atomically to prevent corrupt entries on crash:

```rust
let tmp_path = audit_path.with_extension("tmp");
fs::write(&tmp_path, &json_bytes)?;
fs::rename(&tmp_path, &audit_path)?;
```

---

## Competitive Differentiation vs. Semgrep

| Feature | Semgrep | Sicario |
|---|---|---|
| Finding fingerprinting | `match_based_id` + `syntactic_id` | Same — already in Req 18 |
| Cross-branch triage propagation | ✓ | ✓ Req 18 |
| Policy modes | Monitor / Comment / Block / Disabled | Same — Req 19 |
| Triage states | Open / Reviewing / To Fix / Ignored / Fixed / Closed | Open / Reviewing / To Fix / Ignored / Fixed / Removed — Req 22 |
| PR comment triage | `/fp`, `/ar`, `/other`, `/open` | Same — Req 23 |
| Dashboard metrics | Backlog, guardrails, MTTR, median age | Same — Req 24 |
| Managed scanning | Requires code access to Semgrep infra | Zero-exfil: runs on customer CI — Req 20 |
| Publish payload | One-way hash of triggering code | One-way hash (`code_hash`) — Req 25 |
| Audit log | None | Machine-readable, formally verifiable — Req 21 |
| Air-gap mode | Not supported | Full air-gap when no `SICARIO_API_KEY` — Req 21 |

The structural advantage is the audit log + hash-based publish payload. Semgrep's zero-exfil story is contractual ("we promise not to store your code"). Sicario's is structural: the audit log proves what was transmitted, and the `code_hash` approach means even if the cloud were compromised, no source code could be recovered from the finding metadata.

---

## Architecture: Dashboard Gap Closure (Requirements 26–33)

*This section documents the architectural decisions for the features derived from the Semgrep dashboard gap analysis. All features maintain the zero-exfiltration invariant: no source code is stored, processed, or transmitted by Sicario Cloud.*

---

### Schema Changes Summary

The following fields are added to existing Convex tables. All are backward-compatible (optional with defaults).

**`findings` table additions:**

```typescript
branch:        v.optional(v.string()),          // Req 26 — git branch name
ignoreReason:  v.optional(v.string()),          // Req 27 — "false_positive" | "acceptable_risk" | "no_time_to_fix"
committedBy:   v.optional(v.string()),          // Req 28 — git committer name/email
taintPath:     v.optional(v.array(v.object({   // Req 29 — structured dataflow trace
  file:     v.string(),
  line:     v.number(),
  column:   v.number(),
  nodeType: v.string(),
  role:     v.string(),                         // "source" | "intermediate" | "sink"
}))),
surfacedInPr:  v.optional(v.boolean()),         // Req 31 — true when detected in PR + comment/block mode
jiraIssueKey:  v.optional(v.string()),          // Req 33 — e.g. "SEC-123"
```

**`projects` table additions:**

```typescript
tags:          v.optional(v.array(v.string())), // Req 30 — ["team:payments", "tier-1"]
primaryBranch: v.optional(v.string()),          // Req 26/30 — default "main"
pathIgnores:   v.optional(v.array(v.string())), // Req 30 — glob patterns
```

**`scans` table additions:**

```typescript
scanType:   v.optional(v.string()),             // Req 30 — "full" | "diff_aware"
scanStatus: v.optional(v.string()),             // Req 30 — "completed" | "error" | "running"
```

**New `findingEvents` table (Req 27):**

```typescript
findingEvents: defineTable({
  eventId:      v.string(),
  findingId:    v.string(),
  orgId:        v.string(),
  eventType:    v.string(),   // "opened"|"triaged"|"reopened"|"note_added"|"auto_fixed"|"auto_removed"|"jira_ticket_created"
  fromState:    v.optional(v.string()),
  toState:      v.optional(v.string()),
  ignoreReason: v.optional(v.string()),
  userId:       v.optional(v.string()),
  note:         v.optional(v.string()),
  timestamp:    v.string(),
})
  .index("by_findingId", ["findingId"])
  .index("by_orgId_timestamp", ["orgId", "timestamp"])
```

**New `savedFilters` table (Req 28):**

```typescript
savedFilters: defineTable({
  filterId:  v.string(),
  orgId:     v.string(),
  userId:    v.string(),
  name:      v.string(),
  filters:   v.any(),         // serialized filter state object
  createdAt: v.string(),
})
  .index("by_orgId_userId", ["orgId", "userId"])
```

**New `jiraConfigs` table (Req 33):**

```typescript
jiraConfigs: defineTable({
  orgId:          v.string(),
  jiraBaseUrl:    v.string(),
  jiraProjectKey: v.string(),
  jiraIssueType:  v.string(),
  encryptedToken: v.string(),   // AES-256-GCM encrypted Jira API token
  createdAt:      v.string(),
  updatedAt:      v.string(),
})
  .index("by_orgId", ["orgId"])
```

---

### Req 26 — Branch Field and Production Backlog

**Denormalization strategy.** The `branch` field is denormalized from the scan onto every finding at insert time inside `scans.insert`. This avoids a join on every analytics query and keeps the findings table self-contained.

```typescript
// Inside scans.insert, for each finding:
await ctx.db.insert("findings", {
  ...findingFields,
  branch: meta.branch ?? "",          // from scan metadata
  scanType: meta.scan_type ?? "full", // "full" | "diff_aware"
  surfacedInPr: (meta.scan_type === "diff_aware") && isPolicyCommentOrBlock(ruleId, policy),
});
```

**Primary branch scoping.** The `analytics.overview` and `analytics.trends` queries accept `branchType: "default"` which filters to `f.branch === project.primaryBranch`. The `primaryBranch` is resolved per-project from the `projects` table (default `"main"`).

**Cross-branch triage propagation.** When a finding is triaged (any state transition), the `findings.triage` mutation looks up all findings with the same `match_based_id` across all branches of the same project and applies the same triage state. This is the same mechanism as Requirement 18 but now operates on the `branch` field to scope the lookup correctly.

---

### Req 27 — Finding Event Log

**Append-only invariant.** The `findingEvents` table has no `update` or `delete` mutations. Every state change, note, and auto-resolution produces a new row. This makes the audit trail tamper-evident.

**Triage mutation update.** The existing `findings.triage` mutation is extended to:
1. Validate `ignoreReason` is set when `triageState === "Ignored"`.
2. Append a `findingEvents` record before patching the finding.
3. Propagate the triage state to all findings with the same `match_based_id` (cross-branch), appending a `findingEvents` record for each propagated finding with `eventType: "triaged"` and a note indicating it was propagated.

**Auto-resolution events.** The `scans.insert` mutation already auto-resolves absent findings. It is extended to append `findingEvents` records with `eventType: "auto_fixed"` or `"auto_removed"` and `userId: null`.

**Timeline query replacement.** `findings.getTimeline` is deprecated. The new `findingEvents.list` query returns all events for a `findingId` ordered by `timestamp` ascending.

---

### Req 28 — Group by Rule and Missing Filters

**`findings.groupByRule` implementation:**

```typescript
// Pseudo-implementation
const allFindings = await ctx.db.query("findings")
  .withIndex("by_orgId", q => q.eq("orgId", args.orgId))
  .collect();

const filtered = applyFilters(allFindings, args); // same filter logic as listAdvanced

const groups = new Map<string, GroupAccumulator>();
for (const f of filtered) {
  const key = f.ruleId;
  if (!groups.has(key)) groups.set(key, { ruleId: f.ruleId, ruleName: f.ruleName,
    severity: f.severity, cweId: f.cweId, owaspCategory: f.owaspCategory,
    openCount: 0, affectedFiles: new Set(), oldestFindingDate: f.createdAt });
  const g = groups.get(key)!;
  if (f.triageState === "Open" || f.triageState === "Reviewing" || f.triageState === "ToFix") {
    g.openCount++;
    g.affectedFiles.add(f.filePath);
    if (f.createdAt < g.oldestFindingDate) g.oldestFindingDate = f.createdAt;
  }
}

return [...groups.values()].map(g => ({
  ...g,
  affectedFiles: [...g.affectedFiles].slice(0, 10),
})).sort((a, b) => b.openCount - a.openCount);
```

**Language filter.** The `language` filter in `listAdvanced` maps language names to file extensions:

```typescript
const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
  javascript: [".js", ".jsx", ".mjs", ".cjs"],
  typescript: [".ts", ".tsx"],
  python:     [".py"],
  go:         [".go"],
  rust:       [".rs"],
  java:       [".java"],
  ruby:       [".rb"],
  php:        [".php"],
  csharp:     [".cs"],
};
// Filter: LANGUAGE_EXTENSIONS[args.language]?.some(ext => f.filePath.endsWith(ext))
```

---

### Req 29 — Finding Detail: SCM Links, Taint Trace, CWE Descriptions

**SCM deep link assembly.** The link is assembled client-side (dashboard frontend) from fields already in the finding and scan records. No backend change required beyond ensuring `commitSha` is accessible from the finding's parent scan.

```
GitHub:  {repositoryUrl}/blob/{commitSha}/{filePath}#L{line}
GitLab:  {repositoryUrl}/-/blob/{commitSha}/{filePath}#L{line}
```

The SCM type is inferred from `repositoryUrl` (contains `github.com` or `gitlab.com`).

**Taint path migration.** The existing `executionTrace: string[]` field is kept for backward compatibility but deprecated. New findings from CLI v0.3.5+ populate `taintPath` instead. The finding detail page renders `taintPath` if present, falls back to `executionTrace` for older findings.

**CWE and OWASP lookup tables.** These are static JSON files bundled with the dashboard frontend. No API call is needed. The CWE lookup maps `"CWE-89"` → `{name: "SQL Injection", description: "..."}`. The OWASP lookup maps `"A03:2021"` → `{name: "Injection", description: "..."}`.

**Alert box logic.** The finding detail page renders a prominent alert banner when any of these conditions are true:
- `severity === "Critical"`
- `reachable === true`
- `cloudExposed === true`

The banner is purely a frontend rendering decision based on existing fields — no backend change required.

---

### Req 30 — Projects: Tags, Primary Branch, Path Ignores, Scan Metadata

**Path ignores enforcement.** When `scans.insert` processes findings, it checks each finding's `filePath` against the project's `pathIgnores` glob patterns. Matching findings are inserted with `triageState: "AutoIgnored"` and `triageNote: "Auto-ignored: file path matches project ignore pattern."`.

Glob matching uses a simple prefix/suffix/wildcard algorithm (no external dependency):

```typescript
function matchesGlob(filePath: string, pattern: string): boolean {
  // Convert glob to regex: * → [^/]*, ** → .*
  const regex = new RegExp(
    "^" + pattern.replace(/\*\*/g, "§§").replace(/\*/g, "[^/]*")
      .replace(/§§/g, ".*").replace(/\./g, "\\.") + "$"
  );
  return regex.test(filePath);
}
```

**Retroactive path ignore application.** When `projects.update` is called with a new `pathIgnores` value, a background mutation scans all open findings for the project and auto-ignores those matching the new patterns. This is done in batches of 500 to stay within Convex mutation limits.

**`projects.listByOrg` enrichment.** The query is extended to compute `lastScanAt`, `lastScanStatus`, `lastScanType`, and `openFindingsCount` as computed fields. These are derived from the `scans` and `findings` tables in a single pass per project.

**Scanning / Not Scanning tabs.** A project is "Scanning" if it has at least one scan with `scanStatus: "completed"` in the last 30 days. Otherwise it appears in "Not Scanning". This is computed from the `scans` table.

---

### Req 31 — Analytics: Date Range Filters, Fix Rate, Guardrails Adoption

**`surfacedInPr` flag.** Set at `scans.insert` time when:
- `meta.scan_type === "diff_aware"` (PR scan), AND
- The finding's rule has a policy mode of `"comment"` or `"block"` in the cached policy

This requires the policy to be passed into `scans.insert` as an optional parameter. When no policy is available (no API key), `surfacedInPr` defaults to `false`.

**`analytics.guardrailsAdoption` computation:**

```typescript
const allFindings = await ctx.db.query("findings")
  .withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect();

const surfacedInPr = allFindings.filter(f => f.surfacedInPr);
const fixedBeforeBacklog = surfacedInPr.filter(f =>
  (f.triageState === "Fixed" || f.triageState === "AutoFixed") &&
  // Finding was fixed before it appeared on the default branch:
  // i.e., it never had a scan on primaryBranch while open
  !allFindings.some(other =>
    other.findingId !== f.findingId &&
    other.fingerprint === f.fingerprint &&
    other.branch === primaryBranch &&
    other.triageState === "Open"
  )
);

return {
  findingsSurfacedInPr: surfacedInPr.length,
  findingsTotal: allFindings.length,
  adoptionRatePct: allFindings.length > 0
    ? (surfacedInPr.length / allFindings.length) * 100 : 0,
  fixedBeforeBacklog: fixedBeforeBacklog.length,
  fixedBeforeBacklogPct: surfacedInPr.length > 0
    ? (fixedBeforeBacklog.length / surfacedInPr.length) * 100 : 0,
};
```

**`analytics.medianOpenAge` computation:**

```typescript
const openFindings = allFindings.filter(f =>
  f.triageState === "Open" || f.triageState === "Reviewing" || f.triageState === "ToFix"
);
const now = Date.now();
const bySeverity: Record<string, number[]> = {};
for (const f of openFindings) {
  const ageDays = (now - new Date(f.createdAt).getTime()) / (1000 * 60 * 60 * 24);
  if (!bySeverity[f.severity]) bySeverity[f.severity] = [];
  bySeverity[f.severity].push(ageDays);
}
// median = sorted[Math.floor(arr.length / 2)]
return Object.fromEntries(
  Object.entries(bySeverity).map(([sev, ages]) => {
    const sorted = ages.sort((a, b) => a - b);
    return [sev, sorted[Math.floor(sorted.length / 2)] ?? 0];
  })
);
```

---

### Req 32 — SARIF Export

**SARIF 2.1.0 structure:**

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Sicario",
        "version": "0.3.5",
        "informationUri": "https://usesicario.xyz",
        "rules": [
          {
            "id": "js-sql-string-concat",
            "name": "SQL Injection via String Concatenation",
            "shortDescription": { "text": "SQL Injection (CWE-89)" },
            "helpUri": "https://cwe.mitre.org/data/definitions/89.html",
            "properties": { "tags": ["security", "CWE-89", "A03:2021"] }
          }
        ]
      }
    },
    "results": [
      {
        "ruleId": "js-sql-string-concat",
        "message": { "text": "SQL Injection via String Concatenation" },
        "level": "error",
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "src/db/queries.js" },
            "region": { "startLine": 42, "startColumn": 8 }
          }
        }],
        "fingerprints": {
          "matchBasedId/v1": "a3f8c2...d4_0"
        }
      }
    ]
  }]
}
```

**Severity → SARIF level mapping:**

| Sicario severity | SARIF level |
|---|---|
| Critical | `"error"` |
| High | `"error"` |
| Medium | `"warning"` |
| Low | `"note"` |
| Info | `"note"` |

**CLI flag.** `sicario scan --format sarif` outputs SARIF to stdout. This is a new output format alongside the existing `--format json` and `--format text`. The SARIF output does not include `snippet` unless `--publish-with-snippet` is also active.

---

### Req 33 — Jira Integration and Viewer Role

**Jira ticket payload (zero-exfil compliant):**

```json
{
  "fields": {
    "project": { "key": "SEC" },
    "summary": "[Sicario] SQL Injection via String Concatenation in src/db/queries.js:42",
    "description": {
      "type": "doc", "version": 1,
      "content": [{
        "type": "paragraph",
        "content": [{ "type": "text", "text":
          "Rule: js-sql-string-concat\nSeverity: High\nCWE: CWE-89 (SQL Injection)\nOWASP: A03:2021 - Injection\n\nRemediation: Use parameterized queries or prepared statements instead of string concatenation.\n\nFinding permalink: https://app.usesicario.xyz/findings/abc123"
        }]
      }]
    },
    "issuetype": { "name": "Bug" },
    "priority": { "name": "High" },
    "labels": ["sicario", "security", "CWE-89"]
  }
}
```

No `snippet`, no `code_hash`, no file content. Only rule metadata, severity, CWE, OWASP, remediation guidance, and a permalink.

**Token encryption.** The Jira API token is stored encrypted using AES-256-GCM with a key derived from the org's secret. The encrypted token is stored in `jiraConfigs.encryptedToken`. Decryption happens only inside the Convex action that makes the Jira API call — the plaintext token is never stored or logged.

**Viewer role.** The `ROLE_LEVELS` map becomes:

```typescript
const ROLE_LEVELS: Record<string, number> = {
  viewer:    0,
  developer: 1,
  manager:   2,
  admin:     3,
};
```

All existing `requireRole(ctx, userId, orgId, "developer")` calls continue to block viewers. No existing mutation needs to change — the hierarchy enforcement is automatic.

---

### Updated Competitive Differentiation Table

| Feature | Semgrep | Sicario |
|---|---|---|
| Finding fingerprinting | `match_based_id` + `syntactic_id` | Same — Req 18 |
| Cross-branch triage propagation | ✓ | ✓ Req 18, 26 |
| Policy modes | Monitor / Comment / Block / Disabled | Same — Req 19 |
| Triage states | Open / Reviewing / To Fix / Ignored / Fixed / Closed | Open / Reviewing / To Fix / Ignored / Fixed / Removed — Req 22 |
| Structured ignore reasons | ✓ | ✓ Req 27 |
| Append-only finding event log | ✓ | ✓ Req 27 |
| PR comment triage | `/fp`, `/ar`, `/other`, `/open` | Same — Req 23 |
| Branch field on findings | ✓ | ✓ Req 26 |
| Production backlog metric | ✓ | ✓ Req 26, 31 |
| Guardrails adoption rate | ✓ | ✓ Req 31 |
| Median open age by severity | ✓ | ✓ Req 31 |
| Fix rate metric | ✓ | ✓ Req 31 |
| Date-range filter on all analytics | ✓ | ✓ Req 31 |
| Group by Rule view | ✓ | ✓ Req 28, 32 |
| CWE / language / date / committer filters | ✓ | ✓ Req 28 |
| Saved filter presets | ✓ | ✓ Req 28 |
| SCM deep link on finding detail | ✓ | ✓ Req 29 |
| Structured taint trace | ✓ | ✓ Req 29 |
| CWE / OWASP descriptions inline | ✓ | ✓ Req 29 |
| Project tags | ✓ | ✓ Req 30 |
| Primary branch per project | ✓ | ✓ Req 30 |
| Path ignores per project | ✓ | ✓ Req 30 |
| Scan type (full vs. diff-aware) | ✓ | ✓ Req 30 |
| SARIF export | ✓ | ✓ Req 32 |
| Jira integration | ✓ | ✓ Req 33 |
| Viewer role | ✓ | ✓ Req 33 |
| Dashboard metrics | Backlog, guardrails, MTTR, median age | Same — Req 24, 31 |
| Managed scanning | Requires code access to Semgrep infra | Zero-exfil: runs on customer CI — Req 20 |
| Publish payload | One-way hash of triggering code | One-way hash (`code_hash`) — Req 25 |
| Audit log | None | Machine-readable, formally verifiable — Req 21 |
| Air-gap mode | Not supported | Full air-gap when no `SICARIO_API_KEY` — Req 21 |
| Path ignore retroactive enforcement | Dashboard only | Dashboard + retroactive auto-ignore — Req 30 |

---

## Architecture: Signup, Onboarding, and First-Run Experience (Requirements 34–38)

*Modeled on Semgrep's onboarding flow but adapted for zero-exfiltration: no code access is ever requested, the CLI runs locally, and the dashboard receives only structured metadata.*

---

### Semgrep Onboarding — What We're Copying

Semgrep's signup-to-first-scan flow has five key design decisions worth replicating:

1. **OAuth-first, no friction.** GitHub/GitLab OAuth → org name → scan environment choice. Three screens, no forms.
2. **Immediate org creation.** The org is created atomically with the account. The user never sees an "empty account" state.
3. **Scan environment choice at signup.** Semgrep asks "Where do you want to scan?" immediately after org creation: GitHub (managed scan), CLI, or "Don't want to connect yet." This routes the user to the right setup path before they hit the dashboard.
4. **Demo project escape hatch.** Users who don't want to connect anything can see a pre-populated demo (Juice Shop) immediately. This prevents the empty-state abandonment problem.
5. **CLI login via browser.** `semgrep login` opens a browser window. The user clicks Activate. Done. No token copying.

### What We're Doing Differently (Zero-Exfil Constraints)

| Semgrep | Sicario |
|---|---|
| Managed scanning requires granting Semgrep **code read** access | Managed CI Config requests **write-only** SCM access (workflow file + secret). No code read. |
| GitHub OAuth for managed scanning: `repo` scope used to read code | GitHub OAuth for CI Config: `repo` scope used only to write one file and one secret. Explicitly disclosed. |
| `semgrep login` opens a browser window automatically | `sicario login` prints a URL + user code (device auth, works in SSH/headless environments) |
| Demo project uses Juice Shop scanned by Semgrep's infra | Demo project uses pre-seeded finding metadata — no code is scanned by Sicario Cloud |
| Profile questions are optional and used for product analytics | Profile questions are optional and used only to personalize the onboarding UI |
| "Connect GitHub" is the primary onboarding path | CLI is the primary onboarding path — SCM connection is optional and clearly scoped |

---

### Onboarding Flow State Machine

```
New user signs up
        │
        ▼
┌───────────────────┐
│  Account created  │  ← org auto-created, free subscription seeded,
│  (atomic)         │    welcome email sent, pending invitations redeemed
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Onboarding       │  onboardingCompleted=false, onboardingSkipped=false
│  Wizard — Step 1  │  "About You" (role, team size, languages, goals)
│  (optional)       │
└────────┬──────────┘
         │  skip or complete
         ▼
┌────────────────────────────────────────────────────────────┐
│  Step 2 — "Connect Your Code"                              │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ ★ Scan locally with the CLI  [PRIMARY / DEFAULT]     │  │
│  │   No SCM connection. No permissions requested.       │  │
│  │   Your code never leaves your machine.               │  │
│  │   → show install cmd + sicario login (device auth)   │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Set up CI scanning on GitHub  [OPTIONAL / TEAMS]     │  │
│  │   ⚠ Permission disclosure shown first:               │  │
│  │   "We'll request write access to commit one CI       │  │
│  │    workflow file. We will never read your code."     │  │
│  │   Scopes: repo (write: workflow file + secret only)  │  │
│  │   → Managed CI Config flow (Req 20)                  │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Set up CI scanning on GitLab  [OPTIONAL / TEAMS]     │  │
│  │   Same disclosure + scope constraints as GitHub      │  │
│  │   → Managed CI Config flow (Req 20)                  │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ Skip — show me a demo                                │  │
│  │   → seed pre-authored finding metadata, no code      │  │
│  │     scanned, jump to Step 4                          │  │
│  └──────────────────────────────────────────────────────┘  │
└────────┬───────────────────────────────────────────────────┘
         │
         ▼
┌───────────────────┐
│  Step 3           │  "Run Your First Scan"
│  Polling for      │  polls analytics.overview every 5s
│  first scan       │  auto-advances when scans.count > 0
└────────┬──────────┘
         │  first scan detected
         ▼
┌───────────────────┐
│  Step 4           │  "See Your Findings"
│  First scan       │  shows total, severity breakdown, top 3 findings
│  summary          │  "Go to Dashboard" → onboardingCompleted=true
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│  Full Dashboard   │  analytics, findings, projects — all populated
└───────────────────┘

Escape hatches:
  - "Skip setup" at any step → onboardingSkipped=true → empty dashboard + Getting Started banner
  - "See a demo" at Step 2 → seeds demo project → jumps to Step 4
```

---

### Schema Changes for Onboarding (Requirements 34–38)

**`userProfiles` table additions:**

```typescript
// Onboarding email tracking (Req 38)
firstScanNudgeSentAt:          v.optional(v.string()),
dayThreeReengagementSentAt:    v.optional(v.string()),
firstFindingsEmailSentAt:      v.optional(v.string()),
marketingEmailsOptedOut:       v.optional(v.boolean()),
```

The existing `userProfiles` schema already has: `onboardingCompleted`, `onboardingCompletedAt`, `onboardingSkipped`, `role`, `teamSize`, `languages`, `cicdPlatform`, `goals`, `lastNotificationDismissedAt`. No structural changes needed — only the four new fields above.

**`deviceCodes` table** — already present in schema with all required fields: `deviceCode`, `userCode`, `codeChallenge`, `codeChallengeMethod`, `clientId`, `scope`, `userId`, `userName`, `userEmail`, `status`, `expiresAt`, `accessToken`, `createdAt`.

---

### SCM Connection — Exact Permission Model

This is the most important zero-exfil boundary in the onboarding flow. The distinction between "OAuth login" and "SCM integration" must be crystal clear in both the UI and the implementation.

#### Type 1: OAuth Login (identity only)

Used for: signing up and logging in to the Sicario dashboard.

| Provider | Scopes requested | What Sicario receives | What Sicario does NOT receive |
|---|---|---|---|
| GitHub | `read:user`, `user:email` | Name, email, avatar URL, GitHub user ID | Repository list, file contents, org membership, code |
| GitLab | `read_user` | Name, email, avatar URL, GitLab user ID | Repository list, file contents, group membership, code |

This is identical to "Sign in with Google." No code access. No repository access. Zero-exfil safe by construction.

#### Type 2: SCM Integration for Managed CI Config (write-only, optional)

Used for: the "Set up CI scanning on GitHub/GitLab" path in the onboarding wizard. This is **optional** — the CLI path never requires it.

| Provider | Scopes requested | What Sicario uses them for | What Sicario explicitly does NOT do |
|---|---|---|---|
| GitHub | GitHub App installation with `contents: write`, `secrets: write`, `metadata: read` | List repo names + default branch; commit `.github/workflows/sicario.yml`; store `SICARIO_API_KEY` secret | Read file contents, read commit history, read PRs, read issues, clone the repo |
| GitLab | `api` (scoped to selected projects) | List project names + default branch; commit `.gitlab-ci.yml` addition; store CI variable | Read file contents, read MR data, read pipelines, clone the repo |

The GitHub App installation model is preferable to a personal access token because it allows the user to select exactly which repositories the app can access, and the permissions are visible and revocable from GitHub's settings at any time.

**The permission disclosure UI** (shown before the OAuth flow begins):

```
┌─────────────────────────────────────────────────────────────┐
│  Sicario needs limited access to set up CI scanning         │
│                                                             │
│  ✓  Read your repository names and default branch names     │
│  ✓  Write one CI workflow file to each selected repo        │
│  ✓  Store your Sicario API key as a repository secret       │
│                                                             │
│  ✗  Sicario will NEVER read your source code                │
│  ✗  Sicario will NEVER read your commit history             │
│  ✗  Sicario will NEVER clone your repositories              │
│                                                             │
│  You can revoke this access at any time from your           │
│  GitHub/GitLab settings.                                    │
│                                                             │
│  [I understand — continue]    [Cancel]                      │
└─────────────────────────────────────────────────────────────┘
```

This disclosure is shown **before** the OAuth redirect, not after. The user makes an informed decision before any permissions are granted.

#### Why the CLI path needs no SCM connection at all

The CLI path (`sicario login` + `sicario scan . --publish`) requires:
1. A Sicario account (created via OAuth login — Type 1 above)
2. The CLI installed locally
3. An access token stored in `~/.sicario/config.toml` (issued via device auth)

No GitHub/GitLab integration is needed. The CLI scans the local filesystem, computes findings, and POSTs structured metadata to Sicario Cloud. The SCM is never involved. This is the path that 100% of individual developers and security engineers should use.

The SCM integration (Type 2) is only needed when a team wants to automate scanning across many repositories without manually running the CLI in each one's CI pipeline.

---

### Device Auth Flow (`sicario login`) — Req 37

The device auth flow follows [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628) (OAuth 2.0 Device Authorization Grant), adapted for Convex.

```
CLI                          Sicario Cloud                    Browser
 │                                │                               │
 │── POST /api/v1/device/code ───►│                               │
 │   {client_id: "sicario-cli"}   │                               │
 │◄── {device_code, user_code,    │                               │
 │     verification_uri,          │                               │
 │     expires_in: 900} ──────────│                               │
 │                                │                               │
 │  print: "Open: {uri}?code=     │                               │
 │          {user_code}"          │                               │
 │                                │                               │
 │  [poll every 5s]               │                               │
 │── GET /api/v1/device/token ───►│                               │
 │   {device_code}                │                               │
 │◄── {status: "pending"} ────────│                               │
 │                                │                               │
 │                                │◄── GET /device?code=XXXX ─────│
 │                                │    (user opens URL)           │
 │                                │──► render approval page ──────►│
 │                                │                               │
 │                                │◄── POST /device/approve ──────│
 │                                │    {device_code, userId}      │
 │                                │                               │
 │                                │  issue access_token           │
 │                                │  store in deviceCodes         │
 │                                │                               │
 │── GET /api/v1/device/token ───►│                               │
 │   {device_code}                │                               │
 │◄── {status: "approved",        │                               │
 │     access_token: "sic_..."} ──│                               │
 │                                │                               │
 │  store token in                │                               │
 │  ~/.sicario/config.toml        │                               │
 │  print: "✓ Logged in as..."    │                               │
```

**Token format:** `sic_` prefix + 48 hex chars (192 bits of entropy). Stored in `deviceCodes.accessToken`. The CLI sends this token as `Authorization: Bearer sic_...` on all subsequent API calls.

**HTTP endpoints needed** (in `convex/convex/http.ts`):
- `POST /api/v1/device/code` — creates a `deviceCodes` record, returns `{device_code, user_code, verification_uri, expires_in}`
- `GET /api/v1/device/token` — polls for approval status, returns `{status: "pending"|"approved"|"denied"|"expired", access_token?}`
- `POST /api/v1/device/approve` — called by the dashboard when user clicks Approve, sets `deviceCodes.status = "approved"` and generates `accessToken`
- `POST /api/v1/device/deny` — called by the dashboard when user clicks Deny, sets `deviceCodes.status = "denied"`

---

### Demo Project Seeding — Req 35 AC 8, Req 36 AC 5

The demo project is a set of pre-authored finding records based on OWASP Juice Shop vulnerabilities. It is seeded entirely from static data — no code is scanned by Sicario Cloud.

```typescript
// convex/convex/seeds/demoProject.ts
export const DEMO_FINDINGS = [
  {
    ruleId: "js-sql-string-concat",
    ruleName: "SQL Injection via String Concatenation",
    filePath: "routes/login.js",
    line: 42, column: 8,
    severity: "High", cweId: "CWE-89", owaspCategory: "A03:2021",
    confidenceScore: 0.95, reachable: true,
  },
  {
    ruleId: "js-xss-innerhtml",
    ruleName: "Cross-Site Scripting via innerHTML",
    filePath: "frontend/views/search.js",
    line: 17, column: 3,
    severity: "High", cweId: "CWE-79", owaspCategory: "A03:2021",
    confidenceScore: 0.90, reachable: true,
  },
  // ... 8 more representative findings across CWE-89, CWE-79, CWE-22, CWE-798, CWE-918
];
```

The demo project mutation:
1. Creates a project named `[Demo] OWASP Juice Shop` with `framework: "express"`.
2. Creates a scan record with `repository: "demo/juice-shop"`, `branch: "main"`, `scanType: "full"`.
3. Inserts the pre-authored findings.
4. Sets `provisioningState: "active"` immediately.

The demo project is clearly labeled `[Demo]` in all UI surfaces and can be deleted via the standard `projects.deleteProject` mutation.

---

### Getting Started Checklist — Req 36

The checklist completion state is derived entirely from existing data — no separate boolean fields needed:

```typescript
export const getChecklistStatus = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const [pings, scans, projects, invitations, memberships] = await Promise.all([
      ctx.db.query("usagePings").withIndex("by_projectHash", ...).first(),
      ctx.db.query("scans").withIndex("by_orgId", q => q.eq("orgId", args.orgId)).first(),
      ctx.db.query("projects").withIndex("by_orgId", q => q.eq("orgId", args.orgId)).first(),
      ctx.db.query("pendingInvitations").withIndex("by_orgId", q => q.eq("orgId", args.orgId)).first(),
      ctx.db.query("memberships").withIndex("by_orgId", q => q.eq("orgId", args.orgId)).collect(),
    ]);

    // "Invite your team" = org has more than 1 member OR has a pending invitation
    const hasInvitedTeam = memberships.length > 1 || invitations !== null;

    // "Set up CI scanning" = any project was created via Managed CI Config
    // (identified by provisioningState having been "pending" then "active")
    const hasCiSetup = projects !== null && projects.provisioningState === "active"
      && projects.projectApiKey !== null;

    return {
      cliInstalled:    pings !== null,
      loggedIn:        true,  // if we're here, they're logged in
      firstScanDone:   scans !== null,
      projectAdded:    projects !== null,
      teamInvited:     hasInvitedTeam,
      ciSetup:         hasCiSetup,
    };
  },
});
```

---

### Onboarding Email Cron — Req 38

The onboarding email cron runs hourly via Convex's `crons.ts`:

```typescript
// convex/convex/crons.ts addition
crons.interval("onboarding-email-nudges", { hours: 1 }, async (ctx) => {
  const now = new Date();
  const profiles = await ctx.db.query("userProfiles").collect();

  for (const profile of profiles) {
    if (profile.marketingEmailsOptedOut) continue;

    const createdAt = new Date(profile.createdAt);
    const hoursSinceSignup = (now.getTime() - createdAt.getTime()) / (1000 * 60 * 60);

    // Check if user has completed a scan
    const membership = await ctx.db.query("memberships")
      .withIndex("by_userId", q => q.eq("userId", profile.userId)).first();
    if (!membership) continue;

    const hasScan = await ctx.db.query("scans")
      .withIndex("by_orgId", q => q.eq("orgId", membership.orgId)).first();

    // First scan nudge: 24h after signup, no scan yet
    if (hoursSinceSignup >= 24 && !hasScan && !profile.firstScanNudgeSentAt) {
      await sendFirstScanNudgeEmail(profile.userId, membership.orgId);
      await ctx.db.patch(profile._id, { firstScanNudgeSentAt: now.toISOString() });
    }

    // Day-3 re-engagement: 72h after signup, no scan yet, nudge already sent
    if (hoursSinceSignup >= 72 && !hasScan
        && profile.firstScanNudgeSentAt && !profile.dayThreeReengagementSentAt) {
      await sendDayThreeReengagementEmail(profile.userId, membership.orgId);
      await ctx.db.patch(profile._id, { dayThreeReengagementSentAt: now.toISOString() });
    }
  }
});
```

The `scans.insert` mutation is extended to check for first-scan conditions and send the First Findings email:

```typescript
// At the end of scans.insert, after all findings are processed:
if (orgId) {
  const profile = await ctx.db.query("userProfiles")
    .withIndex("by_userId", q => q.eq("userId", callerUserId)).first();

  if (profile && !profile.firstFindingsEmailSentAt && report.findings?.length > 0) {
    await sendFirstFindingsEmail(orgId, scanId);
    await ctx.db.patch(profile._id, {
      firstFindingsEmailSentAt: new Date().toISOString()
    });
  }
}
```

---

### Onboarding vs. Semgrep — Key Differences Summary

| Aspect | Semgrep | Sicario |
|---|---|---|
| Auth methods | GitHub OAuth, GitLab OAuth, SSO | GitHub OAuth, GitLab OAuth, Email/Password |
| Org creation | Manual name entry after OAuth | Automatic (`{name}'s Organization`) |
| Primary onboarding path | GitHub managed scan (requires code read access) | CLI scan — no SCM connection, no permissions needed |
| SCM connection for CI setup | Required for managed scanning; grants code read | Optional; write-only (workflow file + secret); explicit disclosure before OAuth |
| Scan environment choice | At signup: GitHub managed / CLI / skip | In wizard Step 2: CLI (primary) / GitHub CI / GitLab CI / Demo |
| Demo project | Juice Shop scanned by Semgrep infra | Pre-seeded finding metadata, no code scanned |
| CLI login | `semgrep login` opens browser automatically | `sicario login` prints URL + user code (device auth, works headless) |
| Onboarding profile | Not documented publicly | 4 questions: role, team size, languages, goals |
| First scan nudge email | Not documented publicly | 24h nudge + 72h re-engagement, cancelled on first scan |
| Empty state | Not documented publicly | Getting Started checklist derived from real data |
| Zero-exfil messaging | "Code is not uploaded. Only findings are sent." | Shown at signup, in wizard, in permission disclosure, in empty state, in generated CI workflow |

---

## Architecture: Custom Rule Editor (Requirements 39–40)

### Why This Is Better Than Semgrep's Editor

Semgrep's editor at `semgrep.dev/editor` uses Semgrep's own pattern syntax — a custom DSL that abstracts over tree-sitter. It's approachable but limited: you can't express complex structural queries, and the patterns are opaque to anyone who wants to understand what the AST is actually doing.

Sicario's editor exposes **raw tree-sitter queries** directly. This is harder to write by hand, but:
1. The AI Assist layer (NLP → tree-sitter via `RuleCompiler`) handles the hard part for most users.
2. Power users get full expressiveness — any tree-sitter query that works in the CLI works in the editor.
3. The rule format is identical to what the CLI uses — no translation layer, no format mismatch.

The editor is also a **round-trip system**: rules authored in the dashboard sync to the CLI, and rules authored locally sync to the dashboard. Semgrep has this too, but their sync requires their managed scanning infrastructure (code access). Sicario's sync is purely rule metadata — no code access required.

---

### Schema: `customRules` Convex Table

```typescript
customRules: defineTable({
  ruleId:        v.string(),          // e.g. "org/my-sql-injection-check"
  orgId:         v.string(),
  name:          v.string(),
  yaml:          v.string(),          // full rule YAML, validated before storage
  language:      v.string(),          // primary language (for display/filtering)
  severity:      v.string(),          // "Critical" | "High" | "Medium" | "Low"
  cweId:         v.optional(v.string()),
  owaspCategory: v.optional(v.string()),
  isEnabled:     v.boolean(),
  policyMode:    v.string(),          // "monitor" | "comment" | "block" | "disabled"
  createdBy:     v.string(),          // userId
  createdAt:     v.string(),
  updatedAt:     v.string(),
})
  .index("by_orgId", ["orgId"])
  .index("by_orgId_ruleId", ["orgId", "ruleId"])
  .index("by_orgId_language", ["orgId", "language"])
```

The `yaml` field stores the complete rule YAML string. It is validated server-side on every write using the same parser the CLI uses (exposed as a Convex action that shells out to a validation endpoint, or reimplemented in TypeScript for the subset of validation that doesn't require tree-sitter compilation).

---

### Rule Validation Endpoint

The live test panel calls a Convex HTTP action:

```
POST /api/v1/rules/validate
Authorization: Bearer {SICARIO_API_KEY}
Content-Type: application/json

{
  "rule_yaml": "- id: ...\n  pattern:\n    query: ...",
  "test_code": "const x = db.query('SELECT * FROM users WHERE id = ' + userId);",
  "language": "javascript"
}
```

Response:
```json
{
  "valid": true,
  "matched": true,
  "match_locations": [
    {"line": 1, "column": 10, "end_line": 1, "end_column": 65, "node_type": "call_expression"}
  ],
  "schema_errors": [],
  "query_error": null
}
```

**Zero-exfil note on test code:** The test code is ephemeral — it is sent to the validation endpoint, used to run the tree-sitter query, and the result is returned. The test code is **never stored** in Convex or any database. The Convex action processes it in memory and discards it. This is documented in the endpoint's response as `"test_code_stored": false`.

The validation is implemented as a Convex HTTP action that calls a small Rust validation service (the same SAST engine, compiled to a lightweight HTTP server). This avoids reimplementing tree-sitter query compilation in TypeScript.

---

### AI Assist — Why It's a CLI Command Generator, Not a Backend API

The design doc for the monetization/LLM spec is explicit: **"BYOK Always — All LLM provider selection and key management is local-only. The cloud has no visibility into which LLM provider a user has configured."**

This means the dashboard AI Assist **cannot** call a backend endpoint that runs the `RuleCompiler` pipeline, because:
1. Convex cannot reach `localhost:11434` on the user's machine
2. Convex has no LLM API keys — storing them would violate the zero-liability invariant
3. Sending keys from the browser to Convex would be a security regression

**The correct architecture:** AI Assist is a **CLI command generator**. The dashboard generates the exact `sicario rule new` command based on the user's description and language selection. The user runs it locally. The LLM call happens on their machine using their configured provider (Ollama, Claude, GPT-4, anything). The generated rule is saved to `.sicario/rules/` and synced to the dashboard via `sicario rule push`.

```
User types description in dashboard
        │
        ▼
Dashboard generates CLI command (client-side, no API call):
  sicario rule new --description "detect SQL injection via
  string concatenation" --lang javascript --severity high
        │
        ▼
User copies command, runs in terminal
        │
        ▼
CLI calls RuleCompiler pipeline with user's local LLM
  (Ollama / Claude / GPT-4 / whatever is configured)
        │
        ▼
Rule saved to .sicario/rules/org-sql-injection-check.yaml
        │
        ▼
User runs: sicario rule push
        │
        ▼
Rule appears in dashboard Custom Rules table
(via real-time Convex subscription)
```

This is architecturally clean, zero-exfil, zero-liability, and works with any LLM the user has configured. The `POST /api/v1/rules/generate` endpoint described in Task 39.3 is **removed** — it is not needed and would violate the BYOK invariant.

Task 39.3 is updated to: "Remove `POST /api/v1/rules/generate` from the HTTP API. AI Assist is a client-side CLI command generator only."

---

### CLI Sync Protocol

**`sicario rule push`:**
```
1. Read all .yaml files from .sicario/rules/
2. Parse each file to extract rule IDs
3. For each rule:
   a. GET /api/v1/orgs/{org_id}/rules/{rule_id} — check if exists
   b. If exists and --force not set: prompt user
   c. PUT /api/v1/orgs/{org_id}/rules/{rule_id} with rule YAML
4. Print summary: "Pushed N rules to Sicario Cloud"
```

**`sicario rule pull`:**
```
1. GET /api/v1/orgs/{org_id}/rules — fetch all custom rules
2. For each rule:
   a. Check if .sicario/rules/{rule_id}.yaml exists locally
   b. If exists and --force not set: prompt user
   c. Write YAML to .sicario/rules/{rule_id}.yaml
3. Print summary: "Pulled N rules from Sicario Cloud"
```

**Policy sync (inside `sicario ci`):**
```
Existing policy fetch (Req 19):
  GET /api/v1/orgs/{org_id}/policy → {rules: [{rule_id, mode}]}

Extended to also fetch custom rules:
  GET /api/v1/orgs/{org_id}/rules → [{rule_id, yaml, mode}]

Custom rules are written to a temp dir and loaded into the engine
alongside embedded rules. Temp dir is deleted after the scan.
```

---

### Rules & Policies Page Layout

```
/dashboard/policies
├── Custom Rules tab (default)
│   ├── [+ New Rule] button  [AI Assist] button
│   ├── Filter: Language | Severity | Policy Mode | Search
│   └── Table:
│       Rule ID | Name | Language | Severity | CWE | Mode | Status | Updated | Actions
│       org/my-sql-check | SQL Injection Check | JS | High | CWE-89 | Block | ✓ | 2d ago | Edit Fork Delete
│
├── Built-in Rules tab
│   ├── Search + Language filter
│   └── Read-only table of all embedded rules
│       Rule ID | Name | Language | Severity | CWE | Mode | Actions
│       js-sql-string-concat | SQL Injection | JS | High | CWE-89 | Block | Fork
│
└── Policy Modes tab
    ├── Explanation of Monitor/Comment/Block/Disabled
    └── Bulk mode assignment: select rules → change mode
```

---

### Rule Editor Layout

```
/dashboard/policies/rules/new
/dashboard/policies/rules/:id/edit

┌─────────────────────────────────────────────────────────────────────┐
│  ← Rules & Policies    [Rule Editor]    [Save Rule]  [Validate]     │
├──────────────────────────────┬──────────────────────────────────────┤
│  YAML Editor                 │  Live Test Panel                     │
│  ┌────────────────────────┐  │  ┌──────────────────────────────┐   │
│  │ - id: "org/my-rule"    │  │  │ Test Code                    │   │
│  │   name: "..."          │  │  │ ┌──────────────────────────┐ │   │
│  │   severity: High       │  │  │ │ const x = db.query(      │ │   │
│  │   languages:           │  │  │ │   'SELECT * FROM users ' +│ │   │
│  │     - JavaScript       │  │  │ │   userId);               │ │   │
│  │   pattern:             │  │  │ └──────────────────────────┘ │   │
│  │     query: "..."       │  │  │                              │   │
│  │     captures:          │  │  │ Result: ✓ MATCH              │   │
│  │       - "match"        │  │  │ Line 1, col 10–65            │   │
│  │   test_cases:          │  │  │ Node: call_expression        │   │
│  │     - code: "..."      │  │  │                              │   │
│  │       expected: TP     │  │  ├──────────────────────────────┤   │
│  └────────────────────────┘  │  │ Test Cases                   │   │
│                              │  │ ✓ TruePositive — PASS        │   │
│  Schema Validation           │  │ ✓ TrueNegative — PASS        │   │
│  ✓ All fields valid          │  │                              │   │
│                              │  ├──────────────────────────────┤   │
│  [AI Assist ✨]              │  │ Policy Mode: [Block ▼]       │   │
│  Describe the vulnerability  │  │ Languages: JavaScript        │   │
│  in plain English...         │  │ Severity: High               │   │
│  [Generate Rule]             │  └──────────────────────────────┘   │
└──────────────────────────────┴──────────────────────────────────────┘
```

---

### Zero-Exfil Invariant for Rule Editor

| Data | Stored? | Transmitted to? | Notes |
|---|---|---|---|
| Rule YAML (pattern metadata) | Yes, in `customRules` table | Sicario Cloud | Rule patterns are not source code |
| Test code in live test panel | No | Validation endpoint (ephemeral) | Discarded immediately after validation |
| AI Assist description | No | LLM provider (user-configured) | Plain English, not source code |
| Generated rule YAML | No (until user saves) | Browser only | Inserted into editor, not stored |
| `sicario rule push` payload | Yes, in `customRules` | Sicario Cloud | Rule YAML only, no source code |
| `sicario rule pull` payload | Yes, in `.sicario/rules/` | Local filesystem | Downloaded rule YAML |

The test code is the only data that could be considered sensitive. It is explicitly ephemeral: sent to the validation endpoint, used to run the tree-sitter query in memory, and discarded. The validation endpoint response includes `"test_code_stored": false` as a machine-readable confirmation.

---

## Architecture: Rule Editor Share via URL (Requirement 41)

### Three Share Modes — When to Use Each

```
┌─────────────────────────────────────────────────────────────────┐
│  Share modal                                                     │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Copy link                                    [Permalink ○]│   │
│  │ https://app.usesicario.xyz/editor?s=aB3xK9mZ             │   │
│  │ Requires login to view. Valid: [Never ▼]    [Copy ✓]     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Quick share (no login required)                          │   │
│  │ https://app.usesicario.xyz/editor?r=eyJ5YW1sIjoiLS4uLi  │   │
│  │ Encoded in URL. Anyone can view and fork.   [Copy ✓]     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Embed                                                    │   │
│  │ <iframe src="https://app.usesicario.xyz/editor/embed?r=  │   │
│  │ ..." width="800" height="500"></iframe>      [Copy ✓]     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ─────────────────────────────────────────────────────────────  │
│  [Make public]  [Publish to Registry]  [Close]                   │
└─────────────────────────────────────────────────────────────────┘
```

### URL Format Comparison

| Mode | URL format | Auth required | Server storage | Mutable |
|---|---|---|---|---|
| Private link | `?s=aB3xK9mZ` | Yes (org member) | Yes (`sharedRules` table) | Yes (unless permalink) |
| Permalink | `?s=aB3xK9mZ` + frozen | Yes (org member) | Yes (immutable record) | No |
| Quick share | `?r=<base64url>` | No | No (URL-encoded) | N/A (static) |
| Embed | `/embed?r=<base64url>` | No | No (URL-encoded) | N/A (static) |
| Canonical | `/editor/rules/<ruleId>` | Yes (org member) | Yes (customRules table) | Yes |
| Public rule | `/editor/rules/<ruleId>` | No (read-only) | Yes (customRules table) | No (fork to edit) |

### `sharedRules` Convex Table

```typescript
sharedRules: defineTable({
  token:       v.string(),          // 8-12 char base62 token, URL-safe
  orgId:       v.optional(v.string()), // null for public rules
  ruleId:      v.optional(v.string()), // set when sharing a saved rule
  yaml:        v.string(),          // rule YAML at time of share
  testCode:    v.string(),          // test code at time of share
  language:    v.string(),
  isPublic:    v.boolean(),         // false = org members only
  isPermalink: v.boolean(),         // true = frozen, never updated
  expiresAt:   v.optional(v.string()), // ISO-8601, null = never
  createdBy:   v.string(),          // userId
  createdAt:   v.string(),
  viewCount:   v.number(),          // analytics only, no PII
})
  .index("by_token", ["token"])
  .index("by_ruleId", ["ruleId"])
  .index("by_orgId", ["orgId"])
```

### Quick Share URL Encoding (`?r=`)

The `?r=` format encodes the editor state entirely in the URL — no server round-trip, no authentication, works immediately.

```typescript
// Encoding (client-side, in ShareModal.tsx)
function encodeEditorState(yaml: string, code: string, lang: string): string {
  const payload = JSON.stringify({ yaml, code, lang });
  // URL-safe Base64 (RFC 4648 §5): replace + with -, / with _, strip =
  return btoa(payload)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Decoding (client-side, in RuleEditorPage.tsx on mount)
function decodeEditorState(encoded: string): { yaml: string; code: string; lang: string } | null {
  try {
    // Restore standard Base64 padding
    const padded = encoded.replace(/-/g, '+').replace(/_/g, '/');
    const padding = (4 - padded.length % 4) % 4;
    return JSON.parse(atob(padded + '='.repeat(padding)));
  } catch {
    return null;
  }
}
```

**URL length consideration:** A typical rule YAML is ~500 chars and test code is ~200 chars. Base64 overhead is ~33%. Total encoded payload: ~930 chars. Full URL: ~980 chars. Well within the 2048-char safe URL limit for all browsers and link-shorteners.

For larger rules (>1500 chars combined), the client automatically falls back to the server-side `?s=` token format and shows a note: "Rule too large for URL encoding — saved as a private link."

### Embed Mode

The embed URL renders a stripped-down version of the editor:

```
https://app.usesicario.xyz/editor/embed?r=<base64url>
```

The embed page:
- No sidebar, no top nav, no auth gate
- YAML editor (read-only, syntax highlighted)
- Test code panel (editable — visitor can modify test code and re-run)
- Match result display
- Footer: "Open in Sicario Editor →" link that opens the full editor with the same state
- Responsive: works at 600px width minimum

The embed is rendered by a dedicated `EmbedEditorPage.tsx` route that shares the same validation endpoint as the full editor.

### Publish to Registry Flow

```
User clicks "Publish to Registry"
        │
        ▼
Form: description, tags, GitHub handle
        │
        ▼
Dashboard calls POST /api/v1/rules/publish-pr
  {rule_yaml, description, tags, github_handle}
        │
        ▼
Convex action:
  1. Validate rule YAML (same as save validation)
  2. Determine target path: rules/{language}/{rule_id}.yaml
  3. Call GitHub API: create fork of sicario-rules repo (if not exists)
  4. Create branch: community/{github_handle}/{rule_id}
  5. Commit rule YAML file
  6. Open PR against sicario-rules main with pre-populated body:
     - Rule metadata table
     - Link to live editor share URL
     - Checklist: TP test case, TN test case, description, metadata
        │
        ▼
Response: {pr_url: "https://github.com/sicario/sicario-rules/pull/123"}
        │
        ▼
Dashboard shows: "PR opened! Review at github.com/..."
```

The GitHub API call uses a Sicario service token scoped to the `sicario-rules` repository only. No user source code is involved — only the rule YAML the user wrote in the editor.

### Read-Only Playground Mode (Unauthenticated)

When a `?r=` or public `?s=` URL is opened without authentication:

```
┌─────────────────────────────────────────────────────────────────┐
│  ⚡ SICARIO  [Shared Rule — Read Only]  [Fork to my org →]      │
├──────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────┐  ┌──────────────────────────┐  │
│  │ YAML (read-only)            │  │ Test Code (editable)     │  │
│  │ - id: "org/sql-injection"   │  │ const x = db.query(      │  │
│  │   name: "SQL Injection"     │  │   'SELECT * FROM ' +     │  │
│  │   severity: High            │  │   userId);               │  │
│  │   ...                       │  │                          │  │
│  │                             │  │ ✓ MATCH — Line 1, col 10 │  │
│  └─────────────────────────────┘  └──────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ 👋 Want to use this rule in your scans?                  │   │
│  │ Fork it to your org — free to get started.               │   │
│  │ [Sign up free]  [Log in]                                 │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

Key design decisions:
- YAML is read-only (prevents confusion about whether edits are saved)
- Test code IS editable (lets visitors experiment with different inputs)
- Validation endpoint works without auth (rate-limited to 10 req/min per IP)
- "Fork to my org" is the primary CTA — this is a conversion funnel

### Zero-Exfil Note

The test code in the editor is **demonstration code written by the rule author** — it is not production source code from any codebase. The author writes it specifically to show what the rule matches. Sharing it is intentional and expected. The `sharedRules` table stores only this demonstration code, never scan results or production code.

The `?r=` URL format stores the demonstration code in the URL itself, which is visible in browser history and server logs. This is acceptable because the content is intentionally public demonstration code, not sensitive source code.

---

## Architectural Principle: CLI vs. Dashboard Responsibility Split

This principle governs every feature in v0.3.5 and all future releases. Violating it creates either a bloated CLI that tries to be a UI, or a dashboard that tries to access code it shouldn't touch.

### The Rule

**The CLI owns execution. The Dashboard owns configuration, visibility, and coordination.**

```
┌─────────────────────────────────────────────────────────────────────┐
│  DEVELOPER'S MACHINE / CI RUNNER                                    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  sicario CLI                                                 │   │
│  │                                                              │   │
│  │  Owns:                                                       │   │
│  │  • Scanning source code (SAST, secrets, SCA)                │   │
│  │  • Applying fix templates                                    │   │
│  │  • Running the rule engine                                   │   │
│  │  • Pre-commit hooks                                          │   │
│  │  • Local vuln DB queries                                     │   │
│  │  • Taint analysis                                            │   │
│  │  • Benchmark execution                                       │   │
│  │  • Suppression comment parsing                               │   │
│  │  • Git history scanning (--historical)                       │   │
│  │  • Cross-repo search (clones locally)                        │   │
│  │                                                              │   │
│  │  Communicates UP via:                                        │   │
│  │  • --publish: structured finding metadata                    │   │
│  │  • sicario rule push: custom rule YAML                       │   │
│  │  • usagePings: anonymous telemetry                           │   │
│  │                                                              │   │
│  │  Communicates DOWN via:                                      │   │
│  │  • Policy sync: rule modes + custom rules                    │   │
│  │  • sicario rule pull: custom rule YAML                       │   │
│  │  • Triage state: match_based_id → triage_state              │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Source code NEVER crosses this boundary ↑                          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  SICARIO CLOUD (Convex)                                             │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │  Dashboard                                                   │   │
│  │                                                              │   │
│  │  Owns:                                                       │   │
│  │  • Finding triage (states, ignore reasons, notes)            │   │
│  │  • Policy configuration (rule modes, custom rules)           │   │
│  │  • Analytics and metrics (MTTR, backlog, guardrails)         │   │
│  │  • Team management (roles, invitations, orgs)                │   │
│  │  • Onboarding wizard                                         │   │
│  │  • Rule editor (YAML editor, live test panel)                │   │
│  │  • Share via URL                                             │   │
│  │  • Jira integration                                          │   │
│  │  • Notification routing (Slack, email, webhooks)             │   │
│  │  • License policy configuration                              │   │
│  │  • Suppression debt view (org-wide)                          │   │
│  │  • Benchmark trend charts (Rule Quality page)                │   │
│  │  • Vuln DB version status                                    │   │
│  │  • Pre-commit coverage metric                                │   │
│  │  • Code Search (over stored finding metadata)                │   │
│  │                                                              │   │
│  │  Does NOT own:                                               │   │
│  │  • Running scans                                             │   │
│  │  • Accessing source code                                     │   │
│  │  • Cloning repositories                                      │   │
│  │  • Executing the rule engine                                 │   │
│  │  • Storing LLM API keys                                      │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### Feature Assignment Table

Every feature in the spec maps to exactly one primary home:

| Feature | Primary Home | CLI Role | Dashboard Role |
|---|---|---|---|
| SAST scanning | CLI | Runs engine, publishes metadata | Displays findings, triage |
| Secrets detection | CLI | Scans locally, publishes code_hash | Displays findings |
| SCA / dependency scanning | CLI | Queries local vuln DB, publishes metadata | Displays findings, license policy config |
| Taint analysis | CLI | Runs locally, publishes taint_path | Displays dataflow trace |
| Fix templates | CLI | Applies locally, no cloud needed | Shows fix receipt in finding detail |
| Pre-commit hook | CLI | Runs on git commit | Shows pre-commit coverage % |
| Benchmark | CLI | Runs precision/recall/F1 locally | Rule Quality page (trend charts) |
| Suppression comments | CLI | Parses inline, publishes suppression metadata | Suppression debt view |
| Vuln DB updates | CLI | Downloads snapshot locally | Shows DB version + update available badge |
| Policy modes | Dashboard | Fetches + applies before scan | Configures Monitor/Comment/Block/Disabled |
| Custom rules | Dashboard (editor) + CLI (sync) | push/pull sync | YAML editor, live test, fork |
| Triage states | Dashboard | Reads back triage state on scan | Full triage UI |
| Analytics / MTTR | Dashboard | Contributes data via --publish | All charts and metrics |
| Onboarding wizard | Dashboard | Runs first scan, device auth | 4-step wizard |
| Rule share via URL | Dashboard | Generates CLI command for AI Assist | Full share modal, embed, public links |
| Jira integration | Dashboard | Nothing | Creates tickets from findings |
| License policy | Dashboard (config) + CLI (enforcement) | Reads policy from cloud or local file | Visual policy editor |
| Code Search | Dashboard (stored metadata) + CLI (live) | `sicario search --all-projects` | Search over stored findings |
| IDE extensions | Deferred (v0.3.5+) | — | — |
| Monorepo rootPath | Dashboard (config) + CLI (enforcement) | Auto-applies --include from project config | rootPath field in project settings |

### The Communication Contract

**CLI → Cloud (upload):**
```json
{
  "scan_id": "...",
  "findings": [{
    "rule_id": "...", "file_path": "...", "line": 42,
    "severity": "high", "cwe_id": "CWE-89",
    "match_based_id": "...", "code_hash": "sha256:...",
    "triage_state": "open", "suppressed": false,
    "scan_type": "sast|secrets|sca|license",
    "branch": "main", "scan_type": "full|diff_aware",
    "surfaced_in_pr": false
  }],
  "sca_findings": [{ "package": "...", "version": "...", "cve_id": "...", "reachable": true }],
  "suppression_metadata": [{ "file": "...", "line": 42, "rule_id": "...", "committer": "..." }],
  "benchmark_result": null,
  "vuln_db_version": "2026-05-07",
  "hook_installed": true,
  "custom_rules_hash": "sha256:..."
}
```

**Cloud → CLI (download, on `sicario ci`):**
```json
{
  "policy": [{ "rule_id": "...", "mode": "block|comment|monitor|disabled" }],
  "custom_rules": [{ "rule_id": "...", "yaml": "..." }],
  "triage_states": [{ "match_based_id": "...", "triage_state": "ignored", "ignore_reason": "false_positive" }],
  "license_policy": { "allow": ["MIT", "Apache-2.0"], "block": ["GPL-3.0"], "warn": ["MPL-2.0"] },
  "path_ignores": ["**/generated/**", "**/vendor/**"],
  "root_path": "services/payments",
  "vuln_db_latest_version": "2026-05-07"
}
```

This is the complete contract. The CLI never needs to know about Jira, Slack, team management, or analytics. The Dashboard never needs to run code or access files.

### What This Means for the Spec

Several features in the current spec need their home clarified or split:

1. **License policy (Req 47):** The local YAML file is a fallback for air-gap mode. The primary configuration is in the Dashboard (visual policy editor). The CLI downloads the policy as part of the `sicario ci` sync payload. The local file overrides the cloud policy when present.

2. **Benchmark results (Req 5):** Add a `sicario benchmark --publish` flag that uploads benchmark results to Sicario Cloud. The Dashboard gets a new "Rule Quality" page showing precision/recall/F1 trends over time. This is a Dashboard feature that doesn't exist yet in the spec.

3. **Suppression debt (Req 42):** The CLI publishes suppression metadata per scan. The Dashboard aggregates this into an org-wide "Suppression Debt" view: total suppressions, by rule, by committer, trend over time. This is a Dashboard feature that doesn't exist yet in the spec.

4. **Vuln DB status (Req 46):** The CLI includes `vuln_db_version` in the scan payload. The Dashboard shows the current DB version per project and a "Update available" badge when the cloud has a newer snapshot. The CLI checks `vuln_db_latest_version` from the sync payload and prints a notice when an update is available.

5. **Pre-commit coverage (Req 43):** The CLI includes `hook_installed: true` in the scan payload when the pre-commit hook is active. The Dashboard shows a "Pre-commit coverage" metric: % of projects with the hook installed.

6. **IDE extension rule source (Req 44):** The extension fetches the active rule set and triage states from the Dashboard (when `SICARIO_API_KEY` is set), not from a local config file. This ensures all developers on a team see the same rules and the same triage states.
