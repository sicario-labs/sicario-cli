# Tasks - Sicario v0.3.5 Engine Quality

**Coverage:** Requirements 1-40
**Model:** Each numbered task is a parent. Running a parent runs all its subtasks in order.

---

## Group A - CLI Engine Quality (Req 1-17)

### Task 1: Vuln-Sandbox Expansion to 500+ Files

- [x] 1.1 Audit current vuln-sandbox against MANIFEST.md; identify all rules missing TP/TN pairs
- [x] 1.2 Generate TP files for all missing rules across JS, TS, Python, Go, Rust, Java
- [x] 1.3 Generate TN files for all missing rules across JS, TS, Python, Go, Rust, Java
- [x] 1.4 Add TP/TN files for Ruby, PHP, C# after Tasks 6-8 complete
- [x] 1.5 Update MANIFEST.md with every new file: CWE, rule ID, expected outcome
- [x] 1.6 Verify sicario scan vuln-sandbox/ --format json produces exactly 1 finding per TP and 0 per TN
- [x] 1.7 Wire MANIFEST.md validation into CI as a required check

### Task 2: False-Positive Corpus

- [x] 2.1 Clone or reference Express.js, Django, FastAPI, Next.js, Flask, Rails, Laravel, Spring Boot, ASP.NET Core, NestJS
- [x] 2.2 Implement sicario benchmark --fp-corpus subcommand scanning each repo and counting high-confidence findings
- [x] 2.3 Add per-repository FP count table output: repo name, total findings, high-confidence findings, pass/fail
- [x] 2.4 Exit code 1 when any high-confidence finding appears in any FP corpus repo
- [x] 2.5 Wire sicario benchmark --fp-corpus into .github/workflows/ci.yml as a required step

### Task 3: Confidence Metadata Field on Rules

- [x] 3.1 Add confidence field to SecurityRule struct with values high, medium, low; make it required
- [x] 3.2 Update SAST engine to reject rules missing confidence; log warning with rule ID and path
- [x] 3.3 Implement --confidence-threshold <level> flag on sicario scan; filter output accordingly
- [x] 3.4 Add confidence to text, JSON, and SARIF output formats
- [x] 3.5 Backfill all existing built-in YAML rules with appropriate confidence values

### Task 4: Rule Test Harness Wired into CI

- [x] 4.1 Implement sicario rules test: load all YAML rules, extract 	est_cases, run each through SAST engine
- [x] 4.2 Assert TruePositive cases produce at least one matching finding; TrueNegative cases produce zero
- [x] 4.3 Exit 0 with summary N rules tested, M test cases passed; exit 1 on any failure with details
- [x] 4.4 Add performance gate: full rule set completes within 60 seconds on CI runner
- [x] 4.5 Add sicario rules test as a required blocking step in .github/workflows/ci.yml

### Task 5: sicario benchmark Command

- [x] 5.1 Implement sicario benchmark: run SAST engine against Vuln_Sandbox, compute Precision/Recall/F1
- [x] 5.2 Add --target <path> flag for Known_Vulnerable_Apps with bundled ground-truth manifests
- [x] 5.3 Add --format json flag for CI dashboard ingestion
- [x] 5.4 Add --benchmark CI mode with --min-precision threshold and exit code 1 on regression
- [x] 5.5 Add --save-baseline and --compare-baseline <path> flags for delta reporting
- [x] 5.6 Save each run to .sicario/benchmarks/benchmark-<ISO8601>.json
- [x] 5.7 Wire sicario benchmark --benchmark --min-precision 0.80 into CI as a required step

### Task 6: Ruby Language Support

- [x] 6.1 Add tree-sitter-ruby grammar to Cargo.toml and compile into binary
- [x] 6.2 Add Language::Ruby variant to parser and wire into SAST engine
- [x] 6.3 Write YAML rules for CWE-89, CWE-78, CWE-22, CWE-79, CWE-798, CWE-918 in Ruby
- [x] 6.4 Add TP/TN vuln-sandbox files for all 6 Ruby rule classes
- [x] 6.5 Verify Ruby files are scanned automatically without additional flags

### Task 7: PHP Language Support

- [x] 7.1 Add tree-sitter-php grammar to Cargo.toml and compile into binary
- [x] 7.2 Add Language::PHP variant to parser and wire into SAST engine
- [x] 7.3 Write YAML rules for CWE-89, CWE-78, CWE-22, CWE-79, CWE-798, CWE-918 in PHP
- [x] 7.4 Add TP/TN vuln-sandbox files for all 6 PHP rule classes
- [x] 7.5 Verify PHP files are scanned automatically without additional flags

### Task 8: C# Language Support

- [x] 8.1 Add tree-sitter-c-sharp grammar to Cargo.toml and compile into binary
- [x] 8.2 Add Language::CSharp variant to parser and wire into SAST engine
- [x] 8.3 Write YAML rules for CWE-89, CWE-78, CWE-22, CWE-79, CWE-798, CWE-918 in C#
- [x] 8.4 Add TP/TN vuln-sandbox files for all 6 C# rule classes
- [x] 8.5 Verify .cs files are scanned automatically without additional flags

### Task 9: Production Validation Against Known-Vulnerable Apps

- [x] 9.1 Bundle ground-truth manifests for DVWA, WebGoat, Juice Shop, OWASP NodeGoat into the binary
- [x] 9.2 Implement --target flag on sicario benchmark to load the correct manifest for each app
- [x] 9.3 Compute and print per-application Precision/Recall/F1 table
- [x] 9.4 Save Known_Vulnerable_App results to .sicario/benchmarks/benchmark-<app>-<ts>.json
- [x] 9.5 Document benchmark results in CLI docs showing Precision >= 0.80 and Recall >= 0.70

### Task 10: Interprocedural Taint Analysis

- [x] 10.1 Implement Taint_Analyzer: identify taint sources in JS/TS/Python (req.query, os.environ, fs.readFile, etc.)
- [x] 10.2 Implement taint sink detection for CWE-89, CWE-78, CWE-22, CWE-918, CWE-79
- [x] 10.3 Implement 2-hop interprocedural taint tracking across function boundaries within and across files
- [x] 10.4 Add --taint flag to sicario scan; wire Taint_Analyzer into scan pipeline
- [x] 10.5 Add 	aint_path field to JSON output: array of {file, line, column, node_type} per hop
- [x] 10.6 Render taint path as box-drawing chain in text output: source -> [intermediate ->] sink
- [x] 10.7 Cap analysis at 50,000 AST nodes per file; complete 10K SLOC in under 30 seconds
- [x] 10.8 Deduplicate: report each source->sink pair once using shortest path

### Task 11: Taint Analysis Vuln-Sandbox Coverage

- [x] 11.1 Add 1-hop and 2-hop taint test files for SQL injection (JS/TS + Python)
- [x] 11.2 Add 1-hop and 2-hop taint test files for command injection (JS/TS + Python)
- [x] 11.3 Add 1-hop and 2-hop taint test files for path traversal (JS/TS + Python)
- [x] 11.4 Add 1-hop and 2-hop taint test files for SSRF (JS/TS + Python)
- [x] 11.5 Add 1-hop and 2-hop taint test files for XSS (JS/TS + Python)
- [x] 11.6 Verify sicario scan --taint detects all 20 taint test cases with zero false negatives

### Task 12: Benchmark CI Integration

- [x] 12.1 Add --save-baseline flag: save current benchmark as reference baseline
- [x] 12.2 Add --compare-baseline <path> flag: report Precision/Recall/F1 deltas vs. baseline
- [x] 12.3 Add benchmark CI step to .github/workflows/ci.yml with --benchmark --min-precision 0.80
- [x] 12.4 Ensure --format json + --benchmark outputs JSON to stdout and pass/fail to stderr

### Task 13: Universal Autofix Coverage

- [x] 13.1 Add --fix flag to sicario scan: apply all deterministic Fix_Templates in one pass
- [x] 13.2 Create BackupManager backup of each modified file before writing
- [x] 13.3 Print per-finding receipt: rule ID, file, line, template used
- [x] 13.4 Add Fix_Templates for CWE-89, 78, 22, 79, 798, 918, 327, 326, 916, 347, 613, 384, 502, 295
- [x] 13.5 Add --staged flag: apply fixes only to staged files and re-stage after fixing
- [x] 13.6 Add --format json output for fix results: {file, rule_id, line, fixed, template_used}
- [x] 13.7 Update sicario fix <dir> standalone command to match sicario scan <dir> --fix behavior
- [x] 13.8 Run post-fix verification scan and report remaining findings
- [x] 13.9 Validate each Fix_Template against vuln-sandbox: applying template to TP file must pass TN assertion

### Task 14: CI Supply-Chain Guard

- [x] 14.1 Implement sicario guard --ci: scan node_modules/ or site-packages/ with 7 behavioral anomaly rules
- [x] 14.2 Exit 1 on Critical anomaly; print package name, anomaly type, offending snippet to stderr
- [x] 14.3 Add --allowlist <path> flag for YAML allowlist of known-safe packages
- [x] 14.4 Add --format json output for anomaly findings
- [x] 14.5 Add Python site-packages/ support alongside Node.js node_modules/
- [x] 14.6 Implement sicario guard install <package>: wrap npm/pip install, scan new package, block if Critical
- [x] 14.7 Restore pre-installation state when sicario guard install blocks a package
- [x] 14.8 Add supply-chain guard step to .github/workflows/ci.yml after every npm/pip install

### Task 15: Auto-PR Fix Loop

- [x] 15.1 Implement --auto-pr on sicario scan --publish: create branch sicario/autofix-<timestamp>, apply fixes, commit, push
- [x] 15.2 Create GitHub PR via GitHub API with title [Sicario] Auto-fix N security findings and body listing each fix
- [x] 15.3 Create GitLab MR via GitLab API with equivalent title and description
- [x] 15.4 Include zero-exfiltration notice in PR/MR body for deterministic patches
- [x] 15.5 Add --agent=local support: include AI-powered fixes for non-deterministic findings in same PR
- [x] 15.6 Add --auto-pr flag to sicario fix <dir> standalone command
- [x] 15.7 Print PR/MR URL to stdout on success; print descriptive error to stderr on failure (exit 2)
- [x] 15.8 Make branch creation idempotent: append counter suffix if branch already exists

### Task 16: Scan Performance at Scale

- [x] 16.1 Implement incremental scanning: hash file contents, skip unchanged files, return cached results
- [x] 16.2 Store content hash, last-scanned timestamp, and finding fingerprints in .sicario/cache/scan-cache.db
- [x] 16.3 Add --no-cache flag to force full re-scan
- [x] 16.4 Invalidate cache automatically when rule set changes
- [x] 16.5 Verify: 1M SLOC full scan completes in <= 60 seconds on 4-core machine
- [x] 16.6 Verify: unchanged project scan completes in < 1 second; 10 changed files in < 5 seconds
- [x] 16.7 Add --jobs <N> flag to limit parallel worker threads
- [x] 16.8 Add scan throughput to summary output: N files scanned in X.Xs (Y files/s, Z KLOC/s)

### Task 17: Interactive Rule Authoring

- [x] 17.1 Implement sicario rule test <pattern> <file>: print all AST nodes matching pattern with location and matched text
- [x] 17.2 Add --lang <language> flag for ambiguous file extensions
- [x] 17.3 Implement sicario rule validate <rule-file>: run all test_cases, print pass/fail per case
- [x] 17.4 Implement sicario rule test --interactive: REPL loop evaluating patterns in < 500ms
- [x] 17.5 Add match count and matched node kinds to sicario rule test output
- [x] 17.6 Implement sicario rule new: scaffold new YAML rule file with correct schema and empty test_cases
- [x] 17.7 Add --from-finding <finding-id> to sicario rule new: pre-populate scaffold from finding's AST node

---

## Group B - Dashboard / CLI Integration (Req 18-25)

### Task 18: Finding Fingerprinting and Cross-Branch Triage Propagation

- [x] 18.1 Implement compute_match_based_id(file_path, rule_id, pattern_with_values, match_index) in SAST engine
- [x] 18.2 Implement compute_syntactic_id(file_path, rule_id, matched_code, match_index) for internal dedup only
- [x] 18.3 Implement compute_code_hash(matched_code) as SHA-256 for publish payload
- [x] 18.4 Add match_based_id and syntactic_id as top-level fields in JSON output
- [x] 18.5 Verify match_based_id is stable across line-number shifts (add/remove lines above match)
- [x] 18.6 Append _<index> suffix to match_based_id for multiple matches of same pattern in same file

### Task 19: Per-Rule Policy Modes and Cloud Policy Sync

- [x] 19.1 Implement sicario ci subcommand: fetch org policy from GET /api/v1/orgs/{org_id}/policy before scanning
- [x] 19.2 Cache policy to .sicario/cache/policy-<org-id>.json with 1-hour TTL
- [x] 19.3 Apply policy modes: Block -> exit 1, Comment -> post PR comment, Monitor -> upload only, Disabled -> skip rule
- [x] 19.4 Fall back to sicario scan behavior when no SICARIO_API_KEY is present
- [x] 19.5 Add policies Convex table with CRUD mutations and GET /api/v1/orgs/{org_id}/policy HTTP endpoint

### Task 20: Managed CI Config

- [x] 20.1 Build dashboard "Scan new project" workflow: connect GitHub/GitLab org via OAuth, select repos
- [x] 20.2 Implement CI workflow file generator: produce .github/workflows/sicario.yml or .gitlab-ci.yml addition
- [x] 20.3 Commit generated workflow file to repo default branch via SCM API (write-only, no code read)
- [x] 20.4 Store SICARIO_API_KEY as repository secret via SCM API
- [x] 20.5 Display repo onboarding status: Pending / Active / Error
- [x] 20.6 Make workflow commit idempotent: update in place if file already exists
- [x] 20.7 Add "Remove from Sicario" action: delete workflow file and revoke service token
- [x] 20.8 Add zero-exfiltration notice as comment in generated workflow file

### Task 21: Zero-Exfiltration Audit Log

- [x] 21.1 Write audit log entry to .sicario/audit/scan-<ISO8601>.json after every scan
- [x] 21.2 Include 	ransmissions array: each entry has destination, payload_type, payload_size_bytes, lines_of_code_transmitted, consent_obtained
- [x] 21.3 Verify 	ransmissions is empty when no --publish and no SICARIO_API_KEY
- [x] 21.4 Implement sicario audit show: print human-readable summary of most recent audit log
- [x] 21.5 Implement sicario audit verify: assert no unauthorized LLM transmissions across all audit entries
- [x] 21.6 Write audit log atomically via .tmp + rename
- [x] 21.7 Include audit log path in scan summary output
- [x] 21.8 Add guarantee field to every audit log entry with the formal zero-exfil statement

### Task 22: Finding Triage Lifecycle States

- [x] 22.1 Add ignoreReason field to indings Convex schema: alse_positive | acceptable_risk | no_time_to_fix | null
- [x] 22.2 Enforce ignoreReason is non-null when 	riageState === Ignored in indings.triage and indings.bulkTriage
- [x] 22.3 Create indingEvents Convex table: append-only event log (eventId, findingId, orgId, eventType, fromState, toState, ignoreReason, userId, note, timestamp)
- [x] 22.4 Append indingEvents record on every triage mutation and auto-resolution
- [x] 22.5 Implement indingEvents.list query replacing stub indings.getTimeline
- [x] 22.6 Add Fixed vs Removed distinction: auto-set by scan engine based on why finding disappeared
- [x] 22.7 Preserve Reviewing / To Fix state on rescan (do not reset to Open)
- [x] 22.8 Include 	riage_state in CLI JSON output with full state enum

### Task 23: PR Comment Triage Commands

- [x] 23.1 Register SCM webhook for PR comment events when sicario ci posts a finding comment
- [x] 23.2 Implement webhook handler: parse /fp, /ar, /other, /open commands from comment text
- [x] 23.3 Apply triage state transition and propagate via match_based_id across all branches
- [x] 23.4 Post confirmation reply: checkmark Finding marked as [state] (reason: [reason]). - Sicario
- [x] 23.5 Add triage command footer to every PR comment posted by sicario ci
- [x] 23.6 Add org settings toggle to enable/disable PR comment triage
- [x] 23.7 Validate SICARIO_API_KEY on webhook receipt; ignore unauthenticated commands

### Task 24: Dashboard Backlog Activity and Guardrails Adoption Metrics

- [x] 24.1 Add surfacedInPr boolean to indings schema; set at scan insert time when diff-aware + comment/block mode
- [x] 24.2 Implement nalytics.guardrailsAdoption query: findings shown in PR, adoption rate, fixed before backlog
- [x] 24.3 Implement nalytics.medianOpenAge query: median age in days per severity for open findings
- [x] 24.4 Implement nalytics.fixRate query: totalDetected, totalFixed, fixRatePct, ignoreRatePct
- [x] 24.5 Extend nalytics.trends with ignored count and 
et_change per period
- [x] 24.6 Add dateFrom, dateTo, projectId filter params to nalytics.overview, nalytics.mttr, nalytics.topVulnerableProjects, nalytics.owaspCompliance
- [x] 24.7 Implement sicario report --dashboard CLI command: fetch and print dashboard metrics as JSON

### Task 25: Finding Snippet vs. Hash in Publish Payload

- [x] 25.1 Replace snippet field in publish payload with code_hash (SHA-256 of matched code) by default
- [x] 25.2 Add --publish-with-snippet flag: include 100-char truncated snippet when explicitly opted in
- [x] 25.3 Update Audit_Log 	ransmissions entry: set lines_of_code_transmitted > 0 when --publish-with-snippet active
- [x] 25.4 Update guarantee field in audit log to reflect hash-based approach
- [x] 25.5 Update sicario audit verify to assert lines_of_code_transmitted === 0 for inding_metadata entries when snippet not opted in
finding_metadata entries when snippet not opted in


---

## Group C - Dashboard Gap Closure (Req 26-33)

### Task 26: Branch Field on Findings and Production Backlog Scoping

- [x] 26.1 Add `branch` field to `findings` Convex schema; populate from scan metadata at insert time in `scans.insert`
- [x] 26.2 Add `primaryBranch` field to `projects` schema (default `"main"`)
- [x] 26.3 Add `branch` and `branchType` filter params to `findings.listAdvanced`
- [x] 26.4 Scope `analytics.overview` and `analytics.trends` to primary branch when `branchType: "default"` is specified
- [x] 26.5 Propagate triage state across branches using `match_based_id` when a finding is triaged

### Task 27: Structured Ignore Reason and Finding Event Log

- [x] 27.1 Verify `ignoreReason` enforcement from Task 22 covers all triage entry points
- [x] 27.2 Verify `findingEvents` append-only constraint from Task 22 has no update/delete mutations
- [x] 27.3 Extend `findings.triage` to accept `note` param: append `note_added` event without changing triage state
- [x] 27.4 Extend `scans.insert` auto-resolution to append `auto_fixed` / `auto_removed` events with `userId: null`
- [x] 27.5 Implement `findingEvents.list` query returning all events for a `findingId` in chronological order

### Task 28: Findings Page - Group by Rule and Missing Filters

- [x] 28.1 Implement `findings.groupByRule` Convex query: aggregate by ruleId, return openCount, affectedFiles (capped at 10), oldestFindingDate
- [x] 28.2 Add `cweId` filter param to `findings.listAdvanced`
- [x] 28.3 Add `language` filter param to `findings.listAdvanced` (map language name to file extensions)
- [x] 28.4 Add `dateFrom` / `dateTo` ISO-8601 filter params to `findings.listAdvanced`
- [x] 28.5 Add `committedBy` field to `findings` schema; add `committedBy` filter param to `findings.listAdvanced`
- [x] 28.6 Create `savedFilters` Convex table with CRUD mutations for named filter presets per user

### Task 29: Finding Detail - Activity, SCM Links, Structured Taint Trace

- [x] 29.1 Add `taintPath` field to `findings` schema: `[{file, line, column, nodeType, role}]` replacing unstructured `executionTrace`
- [x] 29.2 Add `jiraIssueKey` field to `findings` schema
- [x] 29.3 Expose `scan.commitSha` accessible from finding detail (join or denormalize onto finding)
- [x] 29.4 Add CWE static lookup table to frontend: `src/data/cwe.ts` mapping CWE IDs to names and descriptions

### Task 30: Projects Page - Tags, Primary Branch, Path Ignores, Scan Metadata

- [x] 30.1 Add `tags` field (`string[]`) to `projects` schema; add `tags` filter to `projects.listByOrg`
- [x] 30.2 Add `pathIgnores` field (`string[]`) to `projects` schema; enforce at `scans.insert` time (auto-ignore matching findings)
- [x] 30.3 Add `scanType` field (`"full" | "diff_aware"`) to `scans` schema; populate from CLI scan metadata
- [x] 30.4 Add `scanStatus` field (`"completed" | "error" | "running"`) to `scans` schema
- [x] 30.5 Extend `projects.listByOrg` to return `lastScanAt`, `lastScanStatus`, `lastScanType`, `openFindingsCount` as computed fields
- [x] 30.6 Implement retroactive path ignore: when `projects.update` sets new `pathIgnores`, auto-ignore all matching open findings

### Task 31: Analytics - Date Range Filters, Fix Rate, Guardrails Adoption

- [x] 31.1 Verify `dateFrom`, `dateTo`, `projectId` params are complete on all analytics queries (Task 24 dependency)
- [x] 31.2 Verify `analytics.guardrailsAdoption` is complete (Task 24 dependency)
- [x] 31.3 Verify `analytics.medianOpenAge` is complete (Task 24 dependency)
- [x] 31.4 Verify `analytics.fixRate` is complete (Task 24 dependency)
- [x] 31.5 Add `branchType` param to `analytics.trends` for production backlog scoping

### Task 32: SARIF Export and Group-by-Rule Findings View

- [x] 32.1 Implement `findings.exportSarif` Convex query: return SARIF 2.1.0 JSON for filtered findings
- [x] 32.2 Map Sicario severity to SARIF level: Critical/High -> error, Medium -> warning, Low/Info -> note
- [x] 32.3 Include `fingerprints.matchBasedId` in each SARIF result
- [x] 32.4 Add `sicario scan --format sarif` CLI flag outputting SARIF 2.1.0 to stdout
- [x] 32.5 Verify SARIF output does not include `snippet` unless `--publish-with-snippet` was active

### Task 33: Jira Integration and Viewer Role

- [x] 33.1 Create `jiraConfigs` Convex table: `{orgId, jiraBaseUrl, jiraProjectKey, jiraIssueType, encryptedToken}`
- [x] 33.2 Implement Jira ticket creation Convex action: POST to Jira REST API with rule metadata + remediation link (no source code)
- [x] 33.3 Store Jira issue key on finding record; display as link in finding detail
- [x] 33.4 Append `jira_ticket_created` event to `findingEvents` on ticket creation
- [x] 33.5 Add `viewer` role (level 0) to `ROLE_LEVELS` in `rbac.ts`; block all mutations for viewer role
- [x] 33.6 Accept `"viewer"` as valid role in `memberships.create`

---

## Group D - Signup, Onboarding, and First-Run Experience (Req 34-38)

### Task 34: Signup and Account Creation Flow

- [x] 34.1 Add GitHub OAuth and GitLab OAuth sign-in buttons to the Auth page alongside existing email/password
- [x] 34.2 Auto-populate display name and email from OAuth provider profile; skip extra form fields for OAuth signups
- [x] 34.3 Make `organizations.ensureOrg` atomic: create org + admin membership + free subscription in one operation on first login
- [x] 34.4 Redeem pending invitations at account creation time in `auth.ts` `afterUserCreatedOrUpdated` callback
- [x] 34.5 Add zero-exfiltration trust badge to the Auth page: "Your source code never leaves your machine"
- [x] 34.6 Verify signup-to-dashboard completes in no more than 3 redirects and 10 seconds
- [x] 34.7 When a user signs up via invitation, redirect to the inviting org's dashboard instead of creating a new personal org

### Task 35: Post-Signup Onboarding Wizard

- [x] 35.1 Build 4-step wizard in `OnboardingV2Page.tsx` with sticky progress indicator: About You / Connect Your Code / First Scan / See Findings
- [x] 35.2 Step 1 - About You: collect role, team size, primary languages, primary goal; save to `userProfiles.upsert`; all fields optional
- [x] 35.3 Step 2 - Connect Your Code: render CLI (primary/recommended), GitHub CI, GitLab CI, and Demo option cards
- [x] 35.4 Step 2 - CLI path: show OS-detected install command and `sicario login` device auth command; no SCM connection required
- [x] 35.5 Step 2 - GitHub/GitLab CI path: show permission disclosure modal before OAuth; request write-only scopes (workflow file + secret only)
- [x] 35.6 Step 2 - Demo path: call demo seeding mutation to insert pre-authored Juice Shop finding metadata; jump to Step 4
- [x] 35.7 Step 3 - First Scan: poll `analytics.overview` every 5 seconds; auto-advance to Step 4 when `total_scans > 0`
- [x] 35.8 Step 4 - See Findings: display total findings, severity breakdown, top 3 findings; "Go to Dashboard" calls `userProfiles.completeOnboarding`
- [x] 35.9 Add "Skip setup" link at every step calling `userProfiles.skipOnboarding`; land on empty dashboard with Getting Started banner
- [x] 35.10 Implement demo project seeding mutation: insert pre-authored finding metadata for 10 Juice Shop vulnerabilities; label project `[Demo]`
- [x] 35.11 Add onboarding route guard in `DashboardLayout.tsx`: when authenticated user has `onboardingCompleted === false` AND `onboardingSkipped === false`, redirect to `/dashboard/onboarding/v2` before rendering any dashboard page; guard runs after `ensureOrg` resolves so the userId and orgId are available

### Task 36: Empty State and Getting Started Checklist

- [x] 36.1 Show Getting Started checklist on Overview page when org has zero completed scans; hide analytics charts until first scan
- [x] 36.2 Implement `analytics.getChecklistStatus` query: derive completion state from real data (usagePings, scans, projects, memberships, invitations)
- [x] 36.3 Checklist items: Install CLI, Log in, Run first scan, Add a project, Invite your team, Set up CI scanning
- [x] 36.4 Auto-mark checklist items complete when corresponding data is detected; replace checklist with full dashboard when all 6 complete
- [x] 36.5 Add "See a demo" button below checklist: seeds demo project and navigates to `/dashboard/findings`
- [x] 36.6 Add zero-exfil trust badge in empty state: "Sicario scans run entirely on your machine. Only structured finding metadata is uploaded here."
- [x] 36.7 Add post-scan CLI message when `--publish` is active and it is the user's first scan: "First scan complete. View your findings at https://usesicario.xyz/dashboard"

### Task 37: CLI Device Auth Login Flow

- [x] 37.1 Implement `sicario login` subcommand: generate device code, print URL + user code, poll for approval
- [x] 37.2 Print: "Open this URL in your browser: https://usesicario.xyz/device?code=XXXX-XXXX\nWaiting for authorization..."
- [x] 37.3 Add `POST /api/v1/device/code` HTTP endpoint: create `deviceCodes` record, return `{device_code, user_code, verification_uri, expires_in: 900}`
- [x] 37.4 Add `GET /api/v1/device/token` HTTP endpoint: poll for approval status, return `{status, access_token?}`
- [x] 37.5 Build Device Authorization page at `/auth/device?code=XXXX`: show user code, device name, Approve/Deny buttons; require dashboard login
- [x] 37.6 Add `POST /api/v1/device/approve` and `POST /api/v1/device/deny` HTTP endpoints
- [x] 37.7 On approval: store token in `~/.sicario/config.toml` under `[auth] token`; print "Logged in as {email}. Your scans will now publish to {orgName}."
- [x] 37.8 Expire device code after 15 minutes; print "Login timed out. Run 'sicario login' to try again." and exit 1
- [x] 37.9 Implement `sicario logout`: remove token from config; print "Logged out. Run 'sicario login' to authenticate again."
- [x] 37.10 Skip browser open if valid token already exists; print "Already logged in as {email}."

### Task 38: Onboarding Emails - First Scan Nudge and Re-engagement

- [x] 38.1 Add `firstScanNudgeSentAt`, `dayThreeReengagementSentAt`, `firstFindingsEmailSentAt`, `marketingEmailsOptedOut` fields to `userProfiles` schema
- [x] 38.2 Implement First Scan Nudge email: send 24h after signup if no scan completed; send exactly once per user
- [x] 38.3 Implement Day-3 Re-engagement email: send 72h after signup if no scan and nudge already sent; send exactly once
- [x] 38.4 Implement First Findings email: send when user's first scan completes with at least one finding; send exactly once
- [x] 38.5 Cancel pending nudge/re-engagement emails when first scan is detected
- [x] 38.6 Add one-click unsubscribe link to all onboarding emails; set `marketingEmailsOptedOut: true` on click
- [x] 38.7 Implement idempotent hourly Convex cron in `crons.ts` that checks send criteria and dispatches onboarding emails
- [x] 38.8 Extend `scans.insert` to trigger First Findings email check after inserting findings

---

## Group E - Custom Rule Editor (Req 39-40)

### Task 39: Custom Rule Editor - Dashboard Rule Authoring

- [x] 39.1 Create `customRules` Convex table: `{ruleId, orgId, name, yaml, language, severity, cweId, owaspCategory, isEnabled, policyMode, createdBy, createdAt, updatedAt}`
- [x] 39.2 Add `POST /api/v1/rules/validate` HTTP endpoint: accept `{rule_yaml, test_code, language}`, return `{valid, matched, match_locations, schema_errors, query_error}`; never store test_code
- [x] 39.3 Remove `POST /api/v1/rules/generate` from the HTTP API ? AI Assist is a client-side CLI command generator; no backend LLM call is made (BYOK invariant: cloud never holds LLM keys)
- [x] 39.4 Build `RuleEditorPage.tsx` at `/dashboard/policies/rules/new` and `/dashboard/policies/rules/:id/edit` with split-pane layout
- [x] 39.5 Left pane: YAML editor using `@uiw/react-codemirror` with YAML syntax highlighting, line numbers, and 500ms debounced validation
- [x] 39.6 Left pane: Schema Validation panel showing inline gutter errors and error list below editor
- [x] 39.7 Left pane: AI Assist section ? text area for plain-English description, language selector, severity selector, `[Generate CLI command]` button that produces a copyable `sicario rule new --description "..." --lang ... --severity ...` command client-side (no backend call); include note "Run this locally ? your LLM keys stay on your machine"; add "Paste YAML" shortcut for users who already ran the CLI command
- [x] 39.8 Right pane: Test Code textarea with live match result display (MATCH / No match / Query error) updating within 2 seconds
- [x] 39.9 Right pane: Test Cases panel showing pass/fail for each `test_cases` block entry; "Add test case" button appends to YAML
- [x] 39.10 Right pane: Policy Mode selector (Monitor/Comment/Block/Disabled), Status toggle, Save Rule and Validate buttons
- [x] 39.11 Save Rule: validate server-side before storing; reject invalid YAML or invalid tree-sitter queries with descriptive error
- [x] 39.12 Add `Cmd/Ctrl+S` to save, `Cmd/Ctrl+Enter` to validate, `Cmd/Ctrl+Shift+G` to generate with AI Assist
- [x] 39.13 Build `PoliciesPage.tsx` at `/dashboard/policies` with three tabs: Custom Rules, Built-in Rules, Policy Modes
- [x] 39.14 Custom Rules tab: table with Rule ID, Name, Language, Severity, CWE, Policy Mode (inline editable), Status toggle, Actions (Edit/Fork/Delete)
- [x] 39.15 Built-in Rules tab: read-only table of all embedded rules; Fork action copies YAML with `org/` prefix into Custom Rules
- [x] 39.16 Policy Modes tab: explanation of Monitor/Comment/Block/Disabled; bulk mode assignment for selected rules
- [x] 39.17 Add "Rules & Policies" nav item to sidebar COMPLIANCE section linking to `/dashboard/policies`

### Task 40: Custom Rule Sync - CLI to Dashboard Round-Trip

- [x] 40.1 Implement `sicario rule push` subcommand: read all YAML files from `.sicario/rules/`, upload to `PUT /api/v1/orgs/{org_id}/rules/{rule_id}`
- [x] 40.2 Implement `sicario rule pull` subcommand: fetch all org custom rules from `GET /api/v1/orgs/{org_id}/rules`, write to `.sicario/rules/`
- [x] 40.3 Add `GET /api/v1/orgs/{org_id}/rules` HTTP endpoint: return all custom rules as JSON array
- [x] 40.4 Add `PUT /api/v1/orgs/{org_id}/rules/{rule_id}` HTTP endpoint: create or update custom rule with server-side YAML validation
- [x] 40.5 Add `--force` flag to both `sicario rule push` and `sicario rule pull` to skip overwrite prompts
- [x] 40.6 Implement `sicario rule list` subcommand: display table of all loaded rules (built-in + local) with source column
- [x] 40.7 Extend `sicario ci` policy sync to also download org custom rules and load them into the SAST engine alongside embedded rules
- [x] 40.8 Add `custom_rules_hash` to scan metadata payload; display out-of-sync warning when hash differs from cloud rule set
- [x] 40.9 Require valid `SICARIO_API_KEY` for `sicario rule push` and `sicario rule pull`; print "Not authenticated. Run 'sicario login' first." if absent

---

## Group F - Dashboard UI Changes (ui-changes.md)

### Task 41: Sidebar and Navigation Redesign

- [x] 41.1 Rename "Findings" nav item to "Code" in `Sidebar.tsx`
- [x] 41.2 Rename "Analytics" nav item to "Dashboard" in `Sidebar.tsx`
- [x] 41.3 Add section headers to sidebar: SECURITY, PROJECTS, COMPLIANCE, WORKSPACE
- [x] 41.4 Change active state indicator from left border to filled pill: `bg-accent/10 text-accent` on active, `text-text-muted hover:text-text-main` on inactive
- [x] 41.5 Add "Rules & Policies" placeholder nav item under COMPLIANCE linking to `/dashboard/policies`
- [x] 41.6 Update page `<title>` tags: Overview -> "Dashboard ? Sicario", Findings -> "Code ? Sicario", Analytics -> "Dashboard ? Sicario", etc.

### Task 42: Overview Page Improvements

- [x] 42.1 Rename page title from "Overview" to "Dashboard"
- [x] 42.2 Expand stat cards from 4 to 6: Open Findings, Critical, Fixed This Week, Avg MTTR, Scans Run, Projects; add delta indicators vs. 7 days ago
- [x] 42.3 Add compact Backlog Activity stacked bar chart (new/fixed/ignored per day, last 14 days) below stat cards
- [x] 42.4 Add Top Vulnerable Projects widget: top 5 projects by open finding count with severity columns, linking to project detail
- [x] 42.5 Add "Group by Rule" toggle to Recent Findings feed header; grouped view uses `findings.groupByRule`
- [x] 42.6 Add "See a demo" button to empty state that seeds demo project and navigates to `/dashboard/findings`

### Task 43: Findings Page Improvements

- [x] 43.1 Add "Group by Rule" / "No Grouping" toggle button group in page header; persist choice in `localStorage`
- [x] 43.2 Build `FindingsGroupedView.tsx` component: collapsible rule cards showing rule name, severity, CWE, open count, affected files
- [x] 43.3 Add Branch, CWE, and Language filter chips to `FilterBar.tsx` under a "More filters" disclosure button
- [x] 43.4 Add date range filter chip (from/to date picker) under "More filters"
- [x] 43.5 Add "Save filter" button: prompt for preset name, save to `savedFilters`; add "Saved filters" dropdown to apply presets
- [x] 43.6 Add "Export" dropdown: Export as JSON (existing), Export as SARIF (calls `findings.exportSarif`), Export as CSV (client-side)
- [x] 43.7 Update triage state badge labels and colors for full state machine: Reviewing (yellow), To Fix (orange), Removed (gray strikethrough), Auto-ignored (gray italic), Auto-fixed (green italic)

### Task 44: Finding Detail Page Improvements

- [x] 44.1 Add alert banner at top of page for Critical severity, reachable=true, or cloudExposed=true findings
- [x] 44.2 Add "View in GitHub/GitLab" SCM deep link assembled from `repositoryUrl + commitSha + filePath + line`
- [x] 44.3 Add CWE name and description inline from `src/data/cwe.ts` static lookup; link to cwe.mitre.org
- [x] 44.4 Add OWASP category name inline from existing `src/lib/owasp.ts`
- [x] 44.5 Add `branch` and `commitSha` (first 8 chars) to metadata card
- [x] 44.6 Build `TaintTraceVisualization.tsx`: render `taintPath` as source -> intermediate -> sink chain with role badges and SCM links per node; fall back to `executionTrace` string array if `taintPath` is null
- [x] 44.7 Build `ActivityPanel.tsx`: replace stub `getTimeline` with full `findingEvents.list` rendering; show event type icon, state transition badges, actor, timestamp, note text
- [x] 44.8 Add "Add note" button at bottom of Activity panel: inline textarea calling `findings.triage` with `note` param only
- [x] 44.9 Extend `TriageForm.tsx`: show `ignoreReason` select when triage state is "Ignored"; required before Save is enabled
- [x] 44.10 Add "Copy link" permalink button in page header using existing `CopyButton` component
- [x] 44.11 Add PR comment triage commands footer in triage form card (informational only: `/fp`, `/ar`, `/other`, `/open`)
- [x] 44.12 Add "Create Jira Ticket" button when `jiraConfigs` is configured; show confirmation modal with zero-exfil notice; display Jira issue key as link after creation

### Task 45: Projects Page Improvements

- [x] 45.1 Add Scanning / Not Scanning tabs: Scanning = active projects with recent scan; Not Scanning = pending or no recent scan
- [x] 45.2 Display project `tags` as pill badges on each project card (max 3 visible + tooltip for more)
- [x] 45.3 Show `scanType` badge (Full / Diff-aware) next to last scan timestamp on each project card
- [x] 45.4 Add sort dropdown (Project name A-Z, Most findings, Last scan) and tag filter multi-select
- [x] 45.5 Show `primaryBranch` on each project card as a git branch icon + branch name

### Task 46: Analytics / Dashboard Page Improvements

- [x] 46.1 Rename page title from "Analytics" to "Dashboard"
- [x] 46.2 Add date range selector in page header: 7 days / 30 days / 90 days / Custom; re-query all charts on change
- [x] 46.3 Add Production Backlog trend chart: line chart of open findings on primary branch over time using `analytics.trends` with `branchType: "default"`
- [x] 46.4 Add Guardrails Adoption section: two stat cards showing findings surfaced in PR and fixed before backlog with percentages
- [x] 46.5 Add Median Open Age section: four severity stat cards showing median age in days from `analytics.medianOpenAge`
- [x] 46.6 Add Fix Rate stat card to summary row from `analytics.fixRate`
- [x] 46.7 Add Project dropdown filter in page header to scope all charts to a single project

---

## Group G - Dependency and Cross-Cutting Verification

### Task 47: Schema Migration and Backward Compatibility

- [x] 47.1 Add all new `findings` schema fields as optional with defaults: `branch`, `ignoreReason`, `committedBy`, `taintPath`, `surfacedInPr`, `jiraIssueKey`, `suppressed`, `suppressionComment`
- [x] 47.2 Add all new `projects` schema fields as optional with defaults: `tags`, `primaryBranch`, `pathIgnores`, `rootPath`
- [x] 47.3 Add all new `scans` schema fields as optional with defaults: `scanType`, `scanStatus`, `hookInstalled`, `vulnDbVersion`, `customRulesHash`
- [x] 47.4 Add new tables to schema: `findingEvents`, `savedFilters`, `jiraConfigs`, `customRules`, `sharedRules`, `benchmarkResults`, `suppressions`, `policies`
- [x] 47.5 Add new `userProfiles` fields as optional: `firstScanNudgeSentAt`, `dayThreeReengagementSentAt`, `firstFindingsEmailSentAt`, `marketingEmailsOptedOut`
- [x] 47.6 Add `licensePolicy` JSON field to `organizations` schema: `{allow: string[], block: string[], warn: string[]}`
- [x] 47.7 Verify all existing queries and mutations still work after schema additions (no breaking changes)
- [x] 47.8 Add indexes for all new queryable fields: `findings.by_branch`, `findings.by_suppressed`, `scans.by_scanType`, `suppressions.by_orgId_ruleId`, `policies.by_orgId_ruleId`

### Task 48: CLI Publish Payload Update

- [x] 48.1 Update `convex/telemetry.rs` publish payload to include `match_based_id`, `code_hash`, `branch`, `scan_type`, `surfaced_in_pr`, `suppressed`, `suppression_comment`, `hook_installed`, `vuln_db_version`, `custom_rules_hash`
- [x] 48.2 Remove `snippet` from default payload; only include when `--publish-with-snippet` flag is active
- [x] 48.3 Update `scans.insert` Convex mutation to accept and store all new finding fields from updated payload
- [x] 48.4 Verify audit log `transmissions` entries correctly reflect `lines_of_code_transmitted: 0` for default payload
- [x] 48.5 Implement `--fail-on <severity>` flag on `sicario scan`: exit code 1 when any finding at or above the specified severity is detected (Critical/High/Medium/Low); default behavior unchanged when flag is absent
- [x] 48.6 Implement `--staged` flag on `sicario scan`: scan only files currently staged in git index (`git diff --cached --name-only`); used by pre-commit hook and `--fix --staged`
- [x] 48.7 Implement `--output <file>` flag on `sicario scan`: write findings output to the specified file path instead of stdout; compatible with all `--format` values
- [x] 48.8 Extend `sicario ci` extended sync payload to include `license_policy`, `path_ignores`, `root_path`, `vuln_db_latest_version` from cloud; CLI applies each field appropriately

### Task 49: CI Workflow and End-to-End Verification

- [x] 49.1 Update `.github/workflows/ci.yml` with all new required steps: `sicario rules test`, `sicario benchmark --benchmark`, `sicario guard --ci`
- [x] 49.2 Run full vuln-sandbox scan and verify 0 regressions after all engine changes
- [x] 49.3 Run `sicario benchmark --fp-corpus` against all 10 FP corpus repos and verify 0 high-confidence false positives
- [x] 49.4 Run `sicario scan --taint` against all 20 taint test cases and verify 0 false negatives
- [x] 49.5 Verify `sicario login` -> `sicario scan . --publish` -> dashboard shows findings end-to-end flow works
- [x] 49.6 Verify custom rule push/pull round-trip: author rule in dashboard, pull to CLI, scan detects it, push local rule back to dashboard
- [x] 49.7 Verify `--format json`, `--format sarif`, and `--format text` all correctly include `scan_type`, `taint_path`, `suppressed`, `code_hash` fields for SAST, secrets, and SCA findings
- [x] 49.8 Verify `sicario report --mttr` uses `resolution_type: "fixed"` filter (not "removed") for MTTR computation; update `PatchHistoryEntry` to include `resolution_type` field
- [x] 49.9 Verify `sicario ci` extended sync payload correctly delivers `license_policy`, `path_ignores`, `root_path`, `vuln_db_latest_version` to CLI and CLI applies each correctly

---

## Group H - Rule Editor Share via URL (Req 41)

### Task 50: Share via URL - Backend

- [x] 50.1 Create `sharedRules` Convex table: `{token, orgId, ruleId, yaml, testCode, language, isPublic, isPermalink, expiresAt, createdBy, createdAt, viewCount}`
- [x] 50.2 Add `POST /api/v1/rules/share` HTTP endpoint: generate 8-12 char base62 token, create `sharedRules` record, return `{token, url}`
- [x] 50.3 Add `GET /api/v1/rules/share/:token` HTTP endpoint: look up token, check expiry, check auth for private links, return `{yaml, testCode, language, isPublic, isPermalink}`
- [x] 50.4 Add `PATCH /api/v1/rules/share/:token` HTTP endpoint: update `isPublic` visibility (author only); reject updates to permalink records
- [x] 50.5 Add `DELETE /api/v1/rules/share/:token` HTTP endpoint: delete share record (author only)
- [x] 50.6 Implement token expiry: cron job runs daily and deletes `sharedRules` records where `expiresAt < now`
- [x] 50.7 Add `POST /api/v1/rules/publish-pr` HTTP endpoint: validate rule YAML, create branch in `sicario-rules` repo via GitHub API, commit rule file, open PR with pre-populated body including live editor link
- [x] 50.8 Rate-limit the unauthenticated validation endpoint (`POST /api/v1/rules/validate`) to 10 requests/minute per IP for public/embed access

### Task 51: Share via URL - Frontend

- [x] 51.1 Build `ShareModal.tsx` component with three sections: Copy link (private), Quick share (URL-encoded), Embed; plus Make public and Publish to Registry actions
- [x] 51.2 Implement `encodeEditorState(yaml, code, lang)` client-side: URL-safe Base64 of `{yaml, code, lang}` JSON; auto-fallback to server token when payload > 1500 chars
- [x] 51.3 Implement `decodeEditorState(encoded)` client-side: decode `?r=` param on `RuleEditorPage` mount; populate editor and run validation automatically
- [x] 51.4 Add Share button to Rule Editor top menu bar; wire to `ShareModal`
- [x] 51.5 Add Permalink toggle in Share modal: when enabled, POST to share endpoint with `isPermalink: true`; show note "This link is frozen to the current version"
- [x] 51.6 Add Expiry selector in Share modal: Never / 7 days / 30 days / 90 days; pass `expiresAt` to share endpoint
- [x] 51.7 Add Make public toggle: PATCH share record `isPublic: true`; show warning "Anyone with this link can view and fork this rule"
- [x] 51.8 Add Publish to Registry form: description, tags multi-select, GitHub handle input; POST to `/api/v1/rules/publish-pr`; show PR URL on success
- [x] 51.9 Build `EmbedEditorPage.tsx` at `/editor/embed?r=<base64url>`: stripped layout (no sidebar, no nav), read-only YAML, editable test code, match result, "Open in Sicario Editor" footer link
- [x] 51.10 Add embed `<iframe>` snippet to Share modal Embed tab with copy button
- [x] 51.11 Handle `?s=<token>` URL on `RuleEditorPage` mount: fetch share record from server, populate editor; show "Shared rule" banner with Fork button for non-owners
- [x] 51.12 Render read-only playground mode for unauthenticated visitors: YAML non-editable, test code editable, validation works, "Fork to my org" CTA with sign-up/login prompt
- [x] 51.13 Add canonical rule URL `/editor/rules/<ruleId>` route: load rule from `customRules` by ID; redirect to login if private and unauthenticated
- [x] 51.14 Add "Copy link" button to the Custom Rules table row actions (quick copy of canonical URL without opening Share modal)
- [x] 51.15 Add "Open in Sicario Editor" button to Built-in Rules table: generates `?r=` URL from the built-in rule YAML and opens the editor pre-populated

---

## Group I - Semgrep Parity Nice-to-Haves (Req 42-49)

### Task 52: Inline Suppression Comments (`sicario-ignore`)

- [x] 52.1 Implement `sicario-ignore` inline comment parsing in the SAST_Engine for all supported languages (JS/TS/Python/Go/Rust/Java/Ruby/PHP/C#/JSX)
- [x] 52.2 Support rule-specific suppression: `// sicario-ignore: rule-id` and comma-delimited `// sicario-ignore: rule-id-1, rule-id-2`
- [x] 52.3 Generate finding records for suppressed matches with `triage_state: "ignored"` and `ignoreReason: "inline_suppression"` — do not silently drop them
- [x] 52.4 Add `"suppressed": true` and `"suppression_comment": "..."` fields to JSON output for suppressed findings
- [x] 52.5 Add `--no-ignore-comments` flag to `sicario scan` to disable inline suppression processing for security audits
- [x] 52.6 Implement `sicario audit suppression` subcommand: scan directory for all `sicario-ignore` comments, report file/line/rule/committer
- [x] 52.7 Implement `.sicarioignore` file support following `.gitignore` syntax; respect `.gitignore` by default; add `--no-git-ignore` flag
- [ ] 52.8 Verify suppressed findings are uploaded to Sicario Cloud with correct triage state when `--publish` is active

### Task 53: Pre-Commit Hook Integration

- [x] 53.1 Implement `sicario install-hook` subcommand: write pre-commit hook to `.git/hooks/pre-commit` running `sicario scan --staged --fail-on high`
- [x] 53.2 Implement `sicario uninstall-hook` subcommand: remove the pre-commit hook
- [x] 53.3 Verify pre-commit hook scans only staged files and completes within 10 seconds for up to 50 staged files
- [x] 53.4 Add `.pre-commit-hooks.yaml` to repository root defining a `sicario` hook entry compatible with the `pre-commit` framework
- [x] 53.5 Add overwrite prompt when `sicario install-hook` detects an existing hook
- [x] 53.6 Include secrets detection in default pre-commit hook: `sicario scan --staged --secrets --fail-on medium`

### Task 54: IDE Extension — VS Code *(Deferred — out of scope for v0.3.5)*

### Task 55: IDE Extension — JetBrains *(Deferred — out of scope for v0.3.5)*

### Task 66: IDE Extension Cloud Sync *(Deferred — out of scope for v0.3.5)*

### Task 56: Secrets Detection with Entropy Analysis

- [x] 56.1 Implement `sicario scan --secrets` mode: load secrets rule set targeting credential patterns across all supported languages and config files
- [x] 56.2 Write secrets rules for: AWS keys, GitHub tokens, Stripe keys, Slack tokens, Google API keys, Anthropic/OpenAI keys, Twilio, SendGrid, Cloudflare, DB connection strings, private SSH keys
- [x] 56.3 Implement Shannon entropy analysis: flag strings with entropy > 4.5 bits/char, length 20-100 chars, assigned to credential-named variables
- [x] 56.4 Extend secrets scanning to config files: `.env`, `*.yaml`, `*.yml`, `*.json`, `*.toml`, `*.ini`, Dockerfiles, CI/CD configs
- [x] 56.5 Add `confidence` field to secrets rules: `high` for provider-specific patterns with checksum validation, `medium` for generic patterns, `low` for entropy-only
- [x] 56.6 Implement `sicario scan --secrets --historical` flag: scan full git history for secrets in all commits reachable from HEAD
- [ ] 56.7 Report historical findings with commit SHA, timestamp, and author email (from git log); never transmit commit messages to cloud
- [x] 56.8 Include secrets findings in JSON and SARIF output with `scan_type: "secrets"` field
- [x] 56.9 Publish secrets findings to Sicario Cloud as `code_hash` of matched string — never the actual secret value

### Task 57: Dependency Vulnerability Scanning with Reachability (SCA)

- [x] 57.1 Implement `sicario scan --sca` mode: parse lockfiles for Node.js, Python, Rust, Go, Ruby, PHP, Java
- [x] 57.2 Implement `sicario update --vuln-db` subcommand: download OSV + NVD + GitHub Advisory Database snapshot to `.sicario/cache/vuln_cache.db`
- [x] 57.3 Check identified dependencies against local vulnerability database — no dependency data transmitted to cloud
- [ ] 57.4 Implement reachability analysis: check whether vulnerable function from dependency is called in project source; set `reachable: true/false`
- [x] 57.5 Report each SCA finding with: package name, installed version, fixed version, CVE ID, CVSS score, severity, reachability, call site
- [x] 57.6 Add `--fail-on-reachable` flag: exit 1 only when reachable vulnerabilities are found
- [ ] 57.7 Detect transitive dependencies; flag with `transitive: true`
- [x] 57.8 Include SCA findings in JSON and SARIF output with `scan_type: "sca"` field
- [ ] 57.9 Publish SCA findings to Sicario Cloud as structured metadata (package name, version, CVE ID, reachability) — no lockfile contents beyond package identifiers

### Task 58: License Compliance Scanning

- [x] 58.1 Extend SCA scanner to detect dependency licenses from local vulnerability database
- [x] 58.2 Implement `--license-policy <path>` flag: load YAML policy with `allow`, `block`, `warn` SPDX license lists
- [x] 58.3 Report blocked licenses as Critical findings, warned licenses as Medium, unknown licenses as Low
- [x] 58.4 Exit code 1 when blocked license found and `--fail-on critical` is active
- [ ] 58.5 Display license findings in Sicario Cloud dashboard with `License` scan type badge, filterable separately from SAST/secrets

### Task 59: Cross-Repository Code Search

- [x] 59.1 Build Code Search page at `/dashboard/search`: pattern input, language selector, search button, results table
- [x] 59.2 Dashboard search operates on stored finding metadata only — no repository cloning or code access by the backend
- [x] 59.3 Implement `sicario search --pattern <query> --lang <language> --all-projects` CLI subcommand: fetch project URLs from cloud, clone locally, scan, delete clone, report matches
- [x] 59.4 Add `--project <name>` flag to `sicario search` for single-project search
- [x] 59.5 Display Code Search results: project name, file path, line, snippet (if available), SCM deep link
- [ ] 59.6 Complete dashboard search across 100 projects' stored findings within 5 seconds

### Task 60: Monorepo Support and Path-Scoped Scanning

- [x] 60.1 Add `--include <glob>` flag to `sicario scan`: restrict scanning to matching files
- [x] 60.2 Add `--exclude <glob>` flag to `sicario scan`: exclude matching files from scanning
- [x] 60.3 Add `--max-file-size <bytes>` flag (default 1 MB): skip files larger than threshold
- [x] 60.4 Add `rootPath` field to `projects` Convex schema (default `"."`): defines subdirectory within repo that this project covers
- [ ] 60.5 Auto-apply `--include "{rootPath}/**"` when `sicario ci --publish` detects a project with a non-root `rootPath`
- [ ] 60.6 Scope production backlog metrics to project `rootPath` in analytics queries
- [x] 60.7 Add `--timeout <seconds>` flag to `sicario scan`: max time per file before skipping (default 30s)

---

## Group J - Dashboard Features Revealed by CLI/Dashboard Split (Req 50-53)

### Task 61: Rule Quality Dashboard Page

- [x] 61.1 Add `sicario benchmark --publish` flag: upload benchmark results to `POST /api/v1/orgs/{org_id}/benchmark-results`
- [x] 61.2 Create `benchmarkResults` Convex table: `{orgId, timestamp, precision, recall, f1Score, totalTp, totalFp, totalFn, perLanguage, vulnSandboxSize, cliVersion}`
- [x] 61.3 Build Rule Quality page at `/dashboard/rule-quality`: line chart of Precision/Recall/F1 over time, summary card, per-language breakdown table
- [x] 61.4 Add "Regression detected" alert when latest F1 drops more than 5 percentage points below previous result
- [x] 61.5 Add Rule Quality link to sidebar under COMPLIANCE section

### Task 62: Suppression Debt Dashboard View

- [x] 62.1 Add `suppression_metadata` array to CLI scan publish payload: `{file_path, line, rule_id, committer_email, suppression_comment}` per suppression
- [x] 62.2 Create `suppressions` Convex table: `{orgId, projectId, ruleId, filePath, line, committerEmail, suppressionComment, firstSeenAt, lastSeenAt}`
- [x] 62.3 Build Suppression Debt section on Policies page: total by rule, total by committer, trend chart, full suppression table
- [x] 62.4 Add "Requires review" flag action on suppressions: creates `findingEvents` record and triggers notification

### Task 63: License Policy Dashboard Configuration

- [x] 63.1 Add `licensePolicy` JSON field to `organizations` Convex schema: `{allow: string[], block: string[], warn: string[]}`
- [x] 63.2 Build License Policy configuration page under Settings: visual tag-input UI for allow/block/warn SPDX lists
- [x] 63.3 Include `licensePolicy` in `sicario ci` policy sync payload so CLI applies it during `--sca` scans
- [x] 63.4 Display all detected dependencies with their licenses on the License Policy page so admins can preview policy impact
- [x] 63.5 Ensure local `--license-policy <path>` YAML file overrides cloud policy (air-gap / per-project override)

### Task 64: Pre-Commit Coverage and Vuln DB Status

- [x] 64.1 Add `hook_installed: boolean` and `vuln_db_version: string` to CLI scan publish payload
- [x] 64.2 Store `hookInstalled` and `vulnDbVersion` on `scans` Convex table record
- [x] 64.3 Build Security Coverage section on Projects page: pre-commit hook status (green/red) and vuln DB version per project
- [x] 64.4 Include `vuln_db_latest_version` in `sicario ci` sync payload; CLI prints notice when local DB is more than 7 days behind
- [x] 64.5 Add "Update available" badge on Projects page when project's vuln DB is outdated

---

## Group K - CLI/Dashboard Communication Contract Enforcement

### Task 65: Unified Scan Payload Schema

- [x] 65.1 Define the complete CLI → Cloud upload payload schema as a versioned Rust struct in `sicario-cli/src/publish/payload.rs`: findings, sca_findings, suppression_metadata, benchmark_result, vuln_db_version, hook_installed, custom_rules_hash, scan_type, branch, surfaced_in_pr
- [x] 65.2 Define the complete Cloud → CLI download payload schema as a versioned Rust struct in `sicario-cli/src/publish/policy.rs`: policy rules, custom rules, triage states, license policy, path ignores, root_path, vuln_db_latest_version
- [x] 65.3 Add payload schema version field (`payload_version: "1.0"`) to both upload and download payloads; CLI rejects unknown versions with a descriptive error
- [ ] 65.4 Add integration test: full round-trip from `sicario scan --publish` through Convex to `sicario ci` policy fetch, verifying all fields survive serialization
- [x] 65.5 Document the complete CLI → Dashboard communication contract in `docs/CLI_DASHBOARD_CONTRACT.md` with field descriptions, types, and zero-exfil annotations for every field

### Task 66: IDE Extension Cloud Sync *(Deferred — out of scope for v0.3.5)*

---

## Group L - Gap Closure (Missing Tasks Identified in Audit)

### Task 67: Weekly Digest Email Scheduling

- [x] 67.1 Add weekly digest cron to `crons.ts`: send `sendWeeklyDigestEmail` every Monday at 09:00 UTC to all org admins with at least one completed scan and `marketingEmailsOptedOut !== true`
- [x] 67.2 Compute weekly digest stats server-side: new findings (last 7 days), critical open, high open, fixed this week, scans run, top project by open finding count
- [x] 67.3 Build Notifications settings sub-page under Settings: Slack webhook URL input, alert severity threshold selector, weekly digest opt-in/out toggle, critical findings alert threshold; wire to existing `projects.updateAlertingConfig` mutation

### Task 68: Vuln DB Snapshot Pipeline

- [x] 68.1 Build server-side aggregation job: pull OSV + NVD + GitHub Advisory Database feeds and merge into a single SQLite snapshot at `.sicario/cache/vuln_cache.db` schema
- [ ] 68.2 Host snapshot at `https://cdn.usesicario.xyz/vuln-db/latest.db`; update daily via scheduled job *(deferred — CDN subdomain not available)*
- [x] 68.3 Expose `GET /api/v1/vuln-db/latest` endpoint returning `{version: "2026-05-07", url: "...", checksum: "sha256:..."}` for CLI update checks
- [x] 68.4 Verify `sicario update --vuln-db` downloads the snapshot, verifies checksum, and replaces the local cache atomically

### Task 69: Combined Scan Mode and Text Output for Secrets

- [x] 69.1 Add `--all` flag to `sicario scan`: enables `--secrets`, `--sca`, and `--taint` simultaneously in one pass; deduplicate findings across scan types
- [x] 69.2 Ensure text output for secrets findings never displays the matched string value; show only `rule_id`, `file_path`, `line`, `severity`, and `confidence` level
- [x] 69.3 Add `scan_type` column to text output when multiple scan types are active: prefix each finding line with `[SAST]`, `[SECRETS]`, `[SCA]`, or `[LICENSE]`

### Task 70: Scan Type Detection and Error Reporting

- [x] 70.1 Implement scan type detection in CLI: set `scanType` to `"diff_aware"` when `GITHUB_EVENT_NAME=pull_request` or `GITLAB_CI_MERGE_REQUEST_IID` is set; default to `"full"` otherwise; include in scan metadata payload
- [x] 70.2 Implement `scans.markError` Convex mutation: set `scanStatus` to `"error"` with an error message field; CLI calls this on scan failure before exiting with non-zero code
- [x] 70.3 Extend `sicario config show` to display authenticated user email and org name when a device auth token is present in `~/.sicario/config.toml`

### Task 71: Continuous Watch Mode

- [x] 71.1 Implement `sicario scan --watch` flag: keep process running, monitor target directory for file changes using the `notify` crate
- [x] 71.2 Re-scan only the affected file within 500ms of a Create/Modify/Remove event; debounce 100ms to coalesce rapid saves
- [x] 71.3 Display live-updating severity summary: `[watch] Critical: 0  High: 2  Medium: 5  Low: 1`
- [x] 71.4 Print new findings immediately in standard diagnostic format; print `[resolved] <rule_id> at <file>:<line>` for findings that disappeared
- [x] 71.5 Respect `.sicarioignore` and `.gitignore` patterns in watch mode; exit cleanly with code 0 on Ctrl+C

### Task 72: Glossary and Documentation Updates

- [x] 72.1 Add new glossary terms to requirements.md: `SCA_Scanner`, `Vuln_DB`, `Suppression_Metadata`, `License_Policy`, `Code_Search`, `Pre_Commit_Hook`, `Shared_Rule`, `Device_Auth_Token`, `Demo_Project`
- [x] 72.2 Update the Introduction section of requirements.md to reflect the expanded scope (53 requirements, not 11 outcomes)
- [x] 72.3 Create `docs/CLI_DASHBOARD_CONTRACT.md` documenting the complete CLI → Dashboard communication contract with field descriptions, types, and zero-exfil annotations

---

## Group M - Remaining Gap Closure

### Task 73: Policies Table Backend and CRUD

- [x] 73.1 Create `policies` Convex table: `{policyId, orgId, ruleId, mode, projectScope, updatedBy, updatedAt}` with indexes `by_orgId` and `by_orgId_ruleId`
- [x] 73.2 Add `policies.setMode` mutation: upsert a rule's policy mode for the org; require `manager` role minimum
- [x] 73.3 Add `policies.bulkSetMode` mutation: set mode for multiple rule IDs in one call; used by Policy Modes tab bulk assignment
- [x] 73.4 Add `policies.list` query: return all policy records for an org, joined with built-in rule metadata (name, severity, language, CWE)
- [x] 73.5 Add `GET /api/v1/orgs/{org_id}/policy` HTTP endpoint: return `{rules: [{rule_id, mode}]}` for CLI policy sync; authenticated via `SICARIO_API_KEY`
- [x] 73.6 Seed default policy records for all built-in rules when a new org is created: default mode is `"monitor"` for all rules
- [x] 73.7 Verify `sicario ci` policy fetch correctly reads from the `policies` table and applies modes during scan

### Task 74: MTTR Module Update for Fixed vs. Removed

- [x] 74.1 Add `resolution_type: "fixed" | "removed"` field to `PatchHistoryEntry` in `sicario-cli/src/remediation/backup_manager.rs`
- [x] 74.2 Update `scans.insert` auto-resolution logic: set `resolution_type: "fixed"` when finding disappears due to code change (file hash changed); set `resolution_type: "removed"` when rule disabled or file deleted/ignored
- [x] 74.3 Update `compute_mttr` in `sicario-cli/src/reporting/mttr.rs` to filter to `resolution_type == "fixed"` only; "removed" findings are excluded from MTTR computation
- [x] 74.4 Update `analytics.mttr` Convex query to use `triageState === "Fixed"` (not `"AutoFixed"` or `"Removed"`) for MTTR computation
- [x] 74.5 Add `resolution_type` field to `findingEvents` records for `auto_fixed` and `auto_removed` events so the distinction is auditable

### Task 75: UsagePings and Anonymous Telemetry Update

- [x] 75.1 Extend `usagePings` Convex table with optional fields: `hookInstalled: boolean`, `vulnDbVersion: string`, `cliVersion: string`, `scanType: string`
- [x] 75.2 Update CLI `usagePings` submission to include `hook_installed`, `vuln_db_version`, `cli_version`, and `scan_type` in the ping payload
- [x] 75.3 Update `analytics.getChecklistStatus` to use `usagePings.hookInstalled` for the "Set up CI scanning" checklist item detection (more reliable than `provisioningState`)
- [x] 75.4 Verify `usagePings` records remain anonymous: no user ID, no org ID, no file paths ? only the project hash (already pseudoanonymized)

### Task 76: SARIF Output for SCA and Secrets Findings

- [x] 76.1 Extend `findings.exportSarif` Convex query to include SCA findings: map `package`, `version`, `cve_id`, `reachable` to SARIF `result` with `ruleId: "sca/{cve_id}"` and `level` mapped from CVSS severity
- [x] 76.2 Extend `findings.exportSarif` to include secrets findings: map `rule_id`, `file_path`, `line`, `severity` to SARIF `result`; never include the matched secret value in SARIF output
- [x] 76.3 Add `scan_type` tag to each SARIF result's `properties`: `"sast"`, `"secrets"`, or `"sca"` so consumers can filter by scan type
- [x] 76.4 Extend `sicario scan --format sarif` CLI flag to include SCA and secrets findings in the SARIF output alongside SAST findings
- [x] 76.5 Verify SARIF output passes SARIF 2.1.0 schema validation for all three finding types

### Task 77: Settings Page ? Notifications and Integrations

- [x] 77.1 Build Notifications settings sub-page at `/dashboard/settings?tab=notifications`: Slack webhook URL input, alert severity threshold selector (Critical/High/Medium/Low), weekly digest opt-in/out toggle
- [x] 77.2 Wire Slack webhook URL and threshold to existing `projects.updateAlertingConfig` mutation
- [x] 77.3 Add org-level Slack webhook (not per-project) to `organizations` schema: `slackWebhookUrl`, `slackAlertSeverityThreshold`; used for org-wide critical finding alerts
- [x] 77.4 Build Integrations settings sub-page at `/dashboard/settings?tab=integrations`: Jira configuration form (base URL, project key, issue type, API token); wire to `jiraConfigs` table mutations
- [x] 77.5 Add Settings page tab navigation: General | Notifications | Integrations | Members | Billing | SSO

### Task 78: `sicario scan` Flag Completeness Verification

- [x] 78.1 Verify `--fail-on <severity>` (Task 48.5) works correctly with `--taint`, `--secrets`, and `--sca` modes ? exit code 1 when any finding at or above threshold across all scan types
- [x] 78.2 Verify `--staged` (Task 48.6) correctly resolves staged file paths relative to the project root and handles renamed/deleted staged files gracefully
- [x] 78.3 Verify `--output <file>` (Task 48.7) creates parent directories if they don't exist; exits with code 2 if the file cannot be written
- [x] 78.4 Verify `--no-cache` correctly invalidates the incremental scan cache and forces a full re-scan even when no files have changed
- [x] 78.5 Verify `--confidence-threshold` (Req 3) correctly filters findings from `--taint` and `--secrets` modes, not just SAST
- [x] 78.6 Add `sicario scan --dry-run` flag: run the full scan pipeline but do not write the audit log, do not publish findings, and do not apply fixes; print what would be done. Useful for testing CI configuration.

### Task 79: Pricing Page and Plan Enforcement UI

- [x] 79.1 Verify the Pricing page at `/pricing` correctly reflects the current plan limits (free: 1 project / 500 findings; pro: 10 projects / 5,000 findings; team: unlimited)
- [x] 79.2 Add plan enforcement banners in the dashboard: when org is at 80% of finding storage limit, show a yellow banner; at 100%, show a red banner with upgrade CTA
- [x] 79.3 Add plan enforcement on project creation: when free tier org tries to create a second project, show an upgrade modal instead of the create form
- [x] 79.4 Add `sicario scan --publish` HTTP 402 handling: display the error message from the server and exit with code 0 (non-fatal per Req 4 AC 6 of monetization spec)
- [x] 79.5 Verify the Whop checkout redirect URL includes `?custom_req=<orgId>` so the webhook can associate the purchase with the correct org

### Task 80: `sicario` CLI Help and Documentation

- [x] 80.1 Update `sicario --help` top-level output to list all subcommands including new ones: `login`, `logout`, `ci`, `guard`, `rule`, `audit`, `report`, `search`, `update`, `install-hook`, `uninstall-hook`
- [x] 80.2 Add `--help` text for every new flag added in v0.3.5: `--taint`, `--secrets`, `--sca`, `--all`, `--fail-on`, `--staged`, `--output`, `--dry-run`, `--no-ignore-comments`, `--publish-with-snippet`, `--historical`, `--fail-on-reachable`, `--license-policy`
- [x] 80.3 Add `sicario version` subcommand: print CLI version, build date, target platform, and vuln DB version
- [x] 80.4 Update `README.md` with v0.3.5 feature summary: new languages (Ruby, PHP, C#), taint analysis, secrets detection, SCA, pre-commit hook, device auth login
- [x] 80.5 Update `install.sh` and `install.ps1` to install the latest v0.3.5 binary and verify the checksum before executing

---

## Group N - Sidebar Redesign and New Navigation Pages

### Task 81: Sidebar ? Rich Nested Navigation

- [x] 81.1 Add org switcher dropdown to sidebar header: show current org name, list all orgs user belongs to, [+ Create org] option
- [x] 81.2 Add nested sub-items under **Code** section: "All Findings" (`/dashboard/findings`) and "By Project" (`/dashboard/findings?groupBy=project`)
- [x] 81.3 Add **Secrets** top-level nav item under SECURITY linking to `/dashboard/findings?scanType=secrets`; show badge with open secrets count
- [x] 81.4 Add **Dependencies** top-level nav item under SECURITY linking to `/dashboard/findings?scanType=sca`; show badge with reachable CVE count
- [x] 81.5 Add **Supply Chain Guard** nav item under SECURITY linking to `/dashboard/guard`
- [x] 81.6 Promote **PR Checks** to top-level nav item under PROJECTS (currently buried); show badge with failed check count
- [x] 81.7 Add **Code Search** nav item under OVERVIEW section linking to `/dashboard/search`
- [x] 81.8 Add **License Compliance** nav item under COMPLIANCE section linking to `/dashboard/compliance/licenses`
- [x] 81.9 Move **Rule Quality** nav item under RULES & POLICIES section (currently under COMPLIANCE)
- [x] 81.10 Add **Analytics** as its own section header with Dashboard as the only item (currently grouped under COMPLIANCE)
- [x] 81.11 Add collapse/expand toggle to each sidebar section header; persist collapsed state in `localStorage`
- [x] 81.12 Add unread badge counts to sidebar items: Code (open findings), Secrets (open secrets), Dependencies (reachable CVEs), PR Checks (failed checks)

### Task 82: Secrets Findings Page

- [x] 82.1 Build `/dashboard/findings?scanType=secrets` route: pre-filter `findings.listAdvanced` to `scan_type: "secrets"`; reuse FindingsPage layout
- [x] 82.2 Add Confidence column to findings table for secrets findings (high/medium/low)
- [x] 82.3 Add note banner at top of page: "Matched secret values are never displayed ? only file path, rule, and confidence level"
- [x] 82.4 Add historical scan indicator: badge showing "Includes git history scan" when `--historical` findings are present
- [x] 82.5 Add "Rotate secret" quick action on finding detail for known provider patterns: links to the provider's token revocation page (e.g., GitHub ? `github.com/settings/tokens`, AWS ? AWS console); the link is assembled from the `rule_id` only ? the actual secret value is never stored in Sicario Cloud (only `code_hash`) and is never included in the link

### Task 83: Dependencies (SCA) Findings Page

- [x] 83.1 Build `/dashboard/findings?scanType=sca` route: pre-filter to `scan_type: "sca"`; reuse FindingsPage layout with SCA-specific columns
- [x] 83.2 Add SCA-specific columns to findings table: Package | Version | Fixed Version | CVE | CVSS | Reachable | Transitive
- [x] 83.3 Add "Reachable only" toggle filter: when enabled, show only findings with `reachable: true`
- [x] 83.4 Add "Update available" badge on each finding showing the fixed version
- [x] 83.5 Add vuln DB version indicator in page header: "Vuln DB: 2026-05-07 ? [Update available]" when outdated

### Task 84: Supply Chain Guard Page

- [x] 84.1 Build `/dashboard/guard` page: list guard scan results per project, showing anomaly findings
- [x] 84.2 Guard findings table: Package | Anomaly type | Severity | File | Line | Detected at | Project
- [x] 84.3 Add allowlist management section: view and edit the org-level package allowlist; changes sync to CLI via policy payload
- [x] 84.4 Add "Guard coverage" metric: % of projects with `sicario guard --ci` in their CI workflow (derived from scan metadata)

### Task 85: License Compliance Page

- [x] 85.1 Build `/dashboard/compliance/licenses` page: show all detected dependencies across all projects with their licenses
- [x] 85.2 Dependencies table: Package | Version | License | Status (allowed/blocked/warned/unknown) | Projects using it
- [x] 85.3 Filter by status (allowed/blocked/warned/unknown), license type, project
- [x] 85.4 Show policy summary at top: N blocked, N warned, N unknown licenses detected
- [x] 85.5 Add [Export SBOM] placeholder button (disabled, labeled "Coming soon") for future SBOM export feature

### Task 86: Code Findings ? By Project Grouped View

- [x] 86.1 Build `/dashboard/findings?groupBy=project` view: group findings by project, show per-project severity breakdown
- [x] 86.2 Project group rows: Project name | Critical | High | Medium | Low | Total open | Last scan
- [x] 86.3 Clicking a project row expands it to show the top 5 findings for that project inline
- [x] 86.4 Add "View all findings for this project" link that navigates to `/dashboard/findings?projectId=<id>`

---

## Group O - Settings Page Expansion

### Task 87: Settings ? General Tab

- [x] 87.1 Add **Global Scan Settings** section: toggles for SAST, Secrets, SCA, Supply Chain Guard, Taint analysis, Cross-file analysis; store in `organizations` schema as `scanSettings` JSON field
- [x] 87.2 Add **Global Path Ignores** section: textarea for glob patterns applied to all projects; store in `organizations.globalPathIgnores`; CLI reads from policy sync payload
- [x] 87.3 Add **PR Comment Triage** section: toggle to enable/disable `/fp /ar /other /open` commands org-wide; toggle to require reason text
- [x] 87.4 Move Notifications config from Task 77 into General tab: Slack webhook URL, alert severity threshold, weekly digest toggle, critical findings alert toggle
- [x] 87.5 Add **Organization** section: org name (editable), org slug (read-only), [Save changes] button

### Task 88: Settings ? Access Tab (Users, Teams, Login Methods)

- [x] 88.1 Build **Users** sub-tab: members table with Name | Email | Role | Teams | Joined | Actions; [Invite users] button (up to 20 at once via comma-separated emails)
- [x] 88.2 Add **Default role** selector for new members: Admin / Manager / Developer / Viewer; store in `organizations.defaultMemberRole`
- [x] 88.3 Build **Teams** sub-tab: teams list with sub-teams support; [New team] button; per team: Name | Members count | Projects count | Manager
- [x] 88.4 Implement team creation form: Name, Projects multi-select, Members multi-select, Manager designation
- [x] 88.5 Implement sub-team creation: nested under parent team; sub-team members can be different from parent team
- [x] 88.6 Add team filter to Findings page: "Teams" filter chip that shows findings scoped to the selected team's projects
- [x] 88.7 Build **Login Methods** sub-tab: show connected GitHub OAuth, connected GitLab OAuth, email/password status; [Disconnect] per provider
- [x] 88.8 Add SSO configuration section in Login Methods (Enterprise only): SAML 2.0 and OIDC/OAuth 2.0 setup; wire to existing `ssoConfigs` Convex table
- [x] 88.9 Add `teams` Convex table: `{teamId, orgId, name, parentTeamId, managerUserId, createdAt}`; add `teamIds` to `memberships` (already present); add `teamIds` to `projects` schema

### Task 89: Settings ? Integrations Tab

- [x] 89.1 Build Integrations tab layout: grid of integration cards (Jira, Slack, Email, Webhooks, License Policy); each card shows configured/not configured status
- [x] 89.2 **Jira integration card**: full config form ? subdomain, default project, issue type, API token (encrypted), field mappings table, auto-ticket creation toggles (Critical/High), [Test connection], [Remove]
- [x] 89.3 Add Jira field mappings UI: table of Jira field ? Semgrep field mappings; support short text, paragraph, dropdown, checkbox, labels, components
- [x] 89.4 Add auto-ticket creation config: toggle per severity (Critical/High); toggle per scan type (Code/Secrets/SCA); auto-creates tickets for new findings after each scan
- [x] 89.5 **Slack integration card**: Slack app install button (OAuth flow), default channel input, notify-on selector (Monitor/Comment/Block modes), [Test], [Remove]; Slack notification payload is explicitly constrained to: rule name, severity, file path, line, finding permalink ? never includes `snippet`, `code_hash`, or any code content
- [x] 89.6 **Email notifications card**: recipients list (add/remove emails), severity threshold selector, [Test], [Remove]; email notification payload is explicitly constrained to the same fields as Slack ? no source code content
- [x] 89.7 **Webhooks card**: list of configured webhooks (Name | URL | Events | Status); [Add webhook] form with name, URL, signature secret, event type selector; [Test] per webhook; webhook payload schema is explicitly defined and constrained ? the `payload` field in `webhookDeliveries` must use a typed schema (not `v.any()`) that includes only: `rule_id`, `file_path`, `line`, `severity`, `cwe_id`, `match_based_id`, `triage_state`, `project_name`, `scan_id`, `finding_permalink` ? never `snippet`, `code_hash`, or any code content; add server-side payload sanitization that strips any field not in the allowlist before delivery
- [x] 89.8 **License Policy card**: move from Task 63 into Integrations tab; allow/block/warn SPDX tag inputs; dependency preview table; [Save policy]
- [x] 89.9 Add webhook event types: `scan_completed`, `finding_new`, `finding_triaged`, `pr_check_completed`; store in `webhooks.events` array (already in schema)

### Task 90: Settings ? Deployment Tab

- [x] 90.1 Build **Source Code Managers** section: GitHub connection card (connected org, app installation link, [Disconnect]); GitLab connection card; Bitbucket and Azure DevOps as "Coming soon" placeholders
- [x] 90.2 Build **API Tokens** section: org-level tokens table (Name | Created | Last used | Expiry | [Revoke]); [Create new token] form with name and expiry selector (Never/30d/90d/1y); show token once on creation with copy button
- [x] 90.3 Add `orgApiTokens` Convex table: `{tokenId, orgId, name, tokenHash, expiresAt, lastUsedAt, createdBy, createdAt}`; tokens are hashed before storage, never stored in plaintext
- [x] 90.4 Build **Audit Log** section: event log table (Timestamp | User | Event type | Details); date range filter; event type filter (all/subscription/admin/scan/triage); [Export as JSON] button (Enterprise only)
- [x] 90.5 Extend `auditLog` Convex table to capture triage events: when a finding is triaged via dashboard, append audit log entry with `eventType: "finding.triaged"`, `userId`, `findingId`, `fromState`, `toState`
- [x] 90.6 Add **Managed CI Config** section: list of repos onboarded via Managed CI Config with status (Pending/Active/Error); [Scan new project] button; [Remove from Sicario] per repo

### Task 91: Settings ? Billing Tab

- [x] 91.1 Build Billing tab: current plan display (Free/Pro/Team/Enterprise), plan status badge (Active/Past due/Trialing)
- [x] 91.2 Add usage progress bars: Findings stored (N / plan limit), Projects (N / plan limit); show 80% warning in yellow, 100% in red
- [x] 91.3 Add seat count display: "N contributing developers this period" with explanation tooltip
- [x] 91.4 Add billing cycle and next renewal date display
- [x] 91.5 Add [Upgrade plan] button ? Whop checkout redirect with `?custom_req=<orgId>`
- [x] 91.6 Add [Manage billing] link ? Whop billing portal for invoice history and payment method management
- [x] 91.7 Add plan feature comparison table: show what's included in current plan vs. next tier; highlight locked features with upgrade CTA

### Task 92: Settings Page Navigation and Polish

- [x] 92.1 Build Settings page tab navigation: [General] [Access] [Integrations] [Deployment] [Billing]; active tab highlighted; URL param `?tab=<name>` for deep linking
- [x] 92.2 Add breadcrumb in header for settings sub-pages: "Settings / Access / Teams"
- [x] 92.3 Add unsaved changes warning: when user navigates away from a settings tab with unsaved changes, show confirmation dialog
- [x] 92.4 Add [Save changes] / [Cancel] button pattern consistently across all settings sections; show success toast on save
- [x] 92.5 Add settings search: search input at top of Settings page that filters visible settings sections by keyword

---

## Group P - Hardening Sicario CLI UX

### Task 93: Minimalist Pre-Commit Intercept UX

- [x] 93.1 Add `--hook-mode` boolean flag to `ScanArgs` struct to support minimalist intercepting workflow.
- [x] 93.2 Suppress standard verbose scanning summaries and findings diagnostics when `--hook-mode` is activated.
- [x] 93.3 Intercept pre-commit flow if High or Critical vulnerabilities are detected, prompting user with auto-fix verification: `Apply fix and continue commit? [Y/n]`.
- [x] 93.4 Execute local deterministic remediation templates and automatically stage modified files via `git add` upon confirmation.

### Task 94: Strict Zero-Exfiltration Dashboard Publishing Enforcement

- [x] 94.1 Update `TelemetryFinding` serialization schema to exclusively emit metadata fields and cryptographic `fileHash`.
- [x] 94.2 Strictly strip raw code snippets, execution traces, AST nodes, and developer comments from dashboard publishing payloads.
- [x] 94.3 Update property and unit test suites to validate strict metadata-only schema conformance.