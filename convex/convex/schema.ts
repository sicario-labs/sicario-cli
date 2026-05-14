import { defineSchema, defineTable } from "convex/server";
import { authTables } from "@convex-dev/auth/server";
import { v } from "convex/values";

export default defineSchema({
  ...authTables,

  organizations: defineTable({
    orgId: v.string(),
    name: v.string(),
    createdAt: v.string(),
    // Task 47.6: License policy for SCA license compliance
    licensePolicy: v.optional(v.object({
      allow: v.array(v.string()),
      block: v.array(v.string()),
      warn: v.array(v.string()),
    })),
    // Task 67.3 / 77.3: Notification settings
    slackWebhookUrl: v.optional(v.string()),
    slackAlertSeverityThreshold: v.optional(v.string()),
    weeklyDigestEnabled: v.optional(v.boolean()),
    criticalAlertsEnabled: v.optional(v.boolean()),

    // Group O Extensions
    scanSettings: v.optional(v.any()),
    globalPathIgnores: v.optional(v.string()),
    prCommentTriage: v.optional(v.object({
      enabled: v.boolean(),
      requireReason: v.boolean(),
    })),
    defaultMemberRole: v.optional(v.string()),
    slug: v.optional(v.string()),
  }).index("by_orgId", ["orgId"]),

  teams: defineTable({
    teamId: v.string(),
    name: v.string(),
    orgId: v.string(),
    parentTeamId: v.optional(v.string()),
    managerUserId: v.optional(v.string()),
    createdAt: v.string(),
  })
    .index("by_teamId", ["teamId"])
    .index("by_orgId", ["orgId"]),

  projects: defineTable({
    projectId: v.string(),
    name: v.string(),
    repositoryUrl: v.string(),
    description: v.string(),
    orgId: v.string(),
    teamId: v.optional(v.string()),
    teamIds: v.optional(v.array(v.string())),
    createdAt: v.string(),

    // V2 extensions (all optional for backward compatibility)
    provisioningState: v.optional(v.string()), // "pending" | "active" | "failed"
    framework: v.optional(v.string()),
    projectApiKey: v.optional(v.string()),
    severityThreshold: v.optional(v.string()), // default: "high"
    autoFixEnabled: v.optional(v.boolean()), // default: true
    githubAppInstallationId: v.optional(v.string()), // legacy field — kept for backward compat
    slackWebhookUrl: v.optional(v.string()),
    slackAlertSeverityThreshold: v.optional(v.string()), // "Critical" | "High" | "Medium" | "Low"

    // Req 26: primary branch for production backlog scoping
    primaryBranch: v.optional(v.string()), // default: "main"

    // Req 30: tags, pathIgnores
    tags: v.optional(v.array(v.string())),
    pathIgnores: v.optional(v.array(v.string())),
    rootPath: v.optional(v.string()), // default: "."
  })
    .index("by_projectId", ["projectId"])
    .index("by_teamId", ["teamId"])
    .index("by_orgId", ["orgId"])
    .index("by_projectApiKey", ["projectApiKey"]),

  prChecks: defineTable({
    checkId: v.string(),
    projectId: v.string(),
    orgId: v.string(),
    prNumber: v.number(),
    prTitle: v.string(),
    repositoryUrl: v.string(),
    status: v.string(), // "pending" | "passed" | "failed" | "blocked"
    findingsCount: v.number(),
    criticalCount: v.number(),
    highCount: v.number(),
    scanId: v.optional(v.string()),
    githubCheckRunId: v.optional(v.string()), // legacy field — kept for backward compat with existing documents
    createdAt: v.string(),
    updatedAt: v.string(),
  })
    .index("by_checkId", ["checkId"])
    .index("by_orgId", ["orgId"])
    .index("by_projectId", ["projectId"])
    .index("by_orgId_status", ["orgId", "status"]),

  autoFixPRs: defineTable({
    fixId: v.string(),
    projectId: v.string(),
    orgId: v.string(),
    cveId: v.string(),
    packageName: v.string(),
    fromVersion: v.string(),
    toVersion: v.string(),
    prNumber: v.optional(v.number()),
    prUrl: v.optional(v.string()),
    status: v.string(), // "pending" | "opened" | "merged" | "closed" | "failed"
    createdAt: v.string(),
  })
    .index("by_fixId", ["fixId"])
    .index("by_orgId", ["orgId"])
    .index("by_projectId", ["projectId"])
    .index("by_projectId_cveId", ["projectId", "cveId"]),

  scans: defineTable({
    scanId: v.string(),
    repository: v.string(),
    branch: v.string(),
    commitSha: v.string(),
    timestamp: v.string(),
    durationMs: v.number(),
    rulesLoaded: v.number(),
    filesScanned: v.number(),
    languageBreakdown: v.any(),
    tags: v.array(v.string()),
    orgId: v.optional(v.string()),
    projectId: v.optional(v.string()),
    createdAt: v.string(),

    // Req 30: scan type and status
    scanType: v.optional(v.string()),   // "full" | "diff_aware"
    scanStatus: v.optional(v.string()), // "completed" | "error" | "running"
    hookInstalled: v.optional(v.boolean()),
    vulnDbVersion: v.optional(v.string()),
    customRulesHash: v.optional(v.string()),
  })
    .index("by_scanId", ["scanId"])
    .index("by_repository", ["repository"])
    .index("by_timestamp", ["timestamp"])
    .index("by_orgId", ["orgId"])
    .index("by_projectId", ["projectId"])
    .index("by_scanType", ["scanType"]),

  findings: defineTable({
    findingId: v.string(),
    scanId: v.string(),
    ruleId: v.string(),
    ruleName: v.string(),
    filePath: v.string(),
    line: v.number(),
    column: v.number(),
    endLine: v.optional(v.number()),
    endColumn: v.optional(v.number()),
    snippet: v.string(),
    severity: v.string(),
    confidenceScore: v.number(),
    reachable: v.boolean(),
    cloudExposed: v.optional(v.boolean()),
    cweId: v.optional(v.string()),
    owaspCategory: v.optional(v.string()),
    fingerprint: v.string(),
    executionTrace: v.optional(v.array(v.string())),
    triageState: v.string(),
    triageNote: v.optional(v.string()),
    assignedTo: v.optional(v.string()),

    orgId: v.optional(v.string()),
    projectId: v.optional(v.string()),
    createdAt: v.string(),
    updatedAt: v.string(),

    // Req 22: ignoreReason — required when triageState === "Ignored"
    ignoreReason: v.optional(v.string()), // "false_positive" | "acceptable_risk" | "no_time_to_fix"

    // Req 24: surfacedInPr — set when diff-aware scan + comment/block policy mode
    surfacedInPr: v.optional(v.boolean()),

    // Req 26: branch field for production backlog scoping
    branch: v.optional(v.string()),

    // Req 28: committedBy for filter
    committedBy: v.optional(v.string()),

    // Req 29: structured taint path replacing unstructured executionTrace
    taintPath: v.optional(v.array(v.object({
      file: v.string(),
      line: v.number(),
      column: v.number(),
      nodeType: v.string(),
      role: v.string(), // "source" | "intermediate" | "sink"
    }))),

    // Req 29: Jira issue key
    jiraIssueKey: v.optional(v.string()),

    // Req 29: commit SHA from parent scan (denormalized for finding detail)
    commitSha: v.optional(v.string()),

    // Req 25: match_based_id for cross-branch triage propagation
    matchBasedId: v.optional(v.string()),

    // Req 52: inline suppression
    suppressed: v.optional(v.boolean()),
    suppressionComment: v.optional(v.string()),

    // Task 74: resolutionType ("fixed" | "removed")
    resolutionType: v.optional(v.string()),
  })
    .index("by_findingId", ["findingId"])
    .index("by_scanId", ["scanId"])
    .index("by_severity", ["severity"])
    .index("by_triageState", ["triageState"])
    .index("by_fingerprint", ["fingerprint"])
    .index("by_createdAt", ["createdAt"])
    .index("by_orgId", ["orgId"])
    .index("by_orgId_severity", ["orgId", "severity"])
    .index("by_orgId_triageState", ["orgId", "triageState"])
    .index("by_orgId_createdAt", ["orgId", "createdAt"])
    .index("by_projectId", ["projectId"])
    .index("by_branch", ["branch"])
    .index("by_suppressed", ["suppressed"]),

  webhooks: defineTable({
    webhookId: v.string(),
    orgId: v.string(),
    url: v.string(),
    events: v.array(v.string()),
    deliveryType: v.string(),
    secret: v.optional(v.string()),
    enabled: v.boolean(),
    createdAt: v.string(),
  })
    .index("by_webhookId", ["webhookId"])
    .index("by_orgId", ["orgId"]),

  webhookDeliveries: defineTable({
    deliveryId: v.string(),
    webhookId: v.string(),
    eventType: v.string(),
    payload: v.object({
      rule_id: v.optional(v.string()),
      file_path: v.optional(v.string()),
      line: v.optional(v.number()),
      severity: v.optional(v.string()),
      cwe_id: v.optional(v.string()),
      match_based_id: v.optional(v.string()),
      triage_state: v.optional(v.string()),
      project_name: v.optional(v.string()),
      scan_id: v.optional(v.string()),
      finding_permalink: v.optional(v.string()),
    }),
    status: v.string(),
    responseCode: v.optional(v.number()),
    deliveredAt: v.string(),
  })
    .index("by_webhookId", ["webhookId"])
    .index("by_deliveredAt", ["deliveredAt"]),

  memberships: defineTable({
    userId: v.string(),
    orgId: v.string(),
    role: v.string(), // "admin" | "manager" | "developer"
    teamIds: v.array(v.string()),
    createdAt: v.string(),
  })
    .index("by_userId", ["userId"])
    .index("by_orgId", ["orgId"])
    .index("by_userId_orgId", ["userId", "orgId"]),

  pendingInvitations: defineTable({
    invitationId: v.string(),
    email: v.string(),
    orgId: v.string(),
    role: v.string(),
    teamIds: v.array(v.string()),
    inviterUserId: v.string(),
    createdAt: v.string(),
  })
    .index("by_orgId", ["orgId"])
    .index("by_email", ["email"])
    .index("by_orgId_email", ["orgId", "email"]),

  ssoConfigs: defineTable({
    orgId: v.string(),
    provider: v.string(), // "saml" | "oidc"
    issuerUrl: v.string(),
    clientId: v.string(),
    metadataUrl: v.optional(v.string()),
    enabled: v.boolean(),
    createdAt: v.string(),
  }).index("by_orgId", ["orgId"]),

  deviceCodes: defineTable({
    deviceCode: v.string(),
    userCode: v.string(),
    codeChallenge: v.string(),
    codeChallengeMethod: v.string(),
    clientId: v.string(),
    scope: v.optional(v.string()),
    userId: v.optional(v.string()),
    userName: v.optional(v.string()),
    userEmail: v.optional(v.string()),
    status: v.string(), // "pending" | "approved" | "denied" | "expired"
    expiresAt: v.number(),
    accessToken: v.optional(v.string()),
    createdAt: v.string(),
  })
    .index("by_deviceCode", ["deviceCode"])
    .index("by_userCode", ["userCode"])
    .index("by_accessToken", ["accessToken"]),

  userProfiles: defineTable({
    userId: v.string(),
    onboardingCompleted: v.boolean(),
    onboardingCompletedAt: v.optional(v.string()),
    onboardingSkipped: v.boolean(),
    role: v.optional(v.string()),
    teamSize: v.optional(v.string()),
    languages: v.array(v.string()),
    cicdPlatform: v.optional(v.string()),
    goals: v.array(v.string()),
    lastNotificationDismissedAt: v.optional(v.string()),
    createdAt: v.string(),
    updatedAt: v.string(),

    // Req 38: onboarding email tracking fields
    firstScanNudgeSentAt: v.optional(v.string()),
    dayThreeReengagementSentAt: v.optional(v.string()),
    firstFindingsEmailSentAt: v.optional(v.string()),
    marketingEmailsOptedOut: v.optional(v.boolean()),
  }).index("by_userId", ["userId"]),

  // ── Billing ───────────────────────────────────────────────────────────────
  subscriptions: defineTable({
    orgId:               v.string(),
    plan:                v.union(v.literal("free"), v.literal("pro"), v.literal("team"), v.literal("enterprise")),
    status:              v.union(v.literal("active"), v.literal("trialing"), v.literal("past_due"), v.literal("canceled"), v.literal("paused")),
    billingCycle:        v.union(v.literal("monthly"), v.literal("annual"), v.literal("manual")),
    seatCount:           v.number(),
    currentPeriodStart:  v.string(),
    currentPeriodEnd:    v.string(),
    whopUserId:          v.optional(v.string()),
    whopSubscriptionId:  v.optional(v.string()),
    trialEndsAt:         v.optional(v.string()),
    customRetentionDays: v.optional(v.number()),
    csmIdentifier:       v.optional(v.string()),
    contractStartDate:   v.optional(v.string()),
    createdAt:           v.string(),
    updatedAt:           v.string(),
  }).index("by_orgId", ["orgId"]),

  usageSummary: defineTable({
    orgId:          v.string(),
    periodStart:    v.string(),
    periodEnd:      v.string(),
    findingsStored: v.number(),
    projectCount:   v.number(),
    scansSubmitted: v.number(),
  }).index("by_orgId_periodStart", ["orgId", "periodStart"]),

  auditLog: defineTable({
    orgId:     v.string(),
    userId:    v.optional(v.string()),
    eventType: v.string(),
    payload:   v.any(),
    timestamp: v.string(),
  }).index("by_orgId_timestamp", ["orgId", "timestamp"]),

  // ── Usage telemetry (anonymous, zero-exfiltration) ───────────────────────
  usagePings: defineTable({
    projectHash:  v.string(),
    environment:  v.union(v.literal("ci"), v.literal("local")),
    cliVersion:   v.string(),
    receivedAt:   v.string(),
    // Task 75.1: extended anonymous telemetry fields
    hookInstalled: v.optional(v.boolean()),
    vulnDbVersion: v.optional(v.string()),
    scanType:      v.optional(v.string()),  // "full" | "diff_aware"
  })
    .index("by_projectHash", ["projectHash"])
    .index("by_receivedAt", ["receivedAt"]),

  // ── Dynamic terminal notifications ───────────────────────────────────────
  notifications: defineTable({
    notificationId: v.string(),
    message: v.string(),
    severity: v.union(v.literal("info"), v.literal("warning"), v.literal("critical")),
    minVersion: v.optional(v.string()),
    maxVersion: v.optional(v.string()),
    url: v.optional(v.string()),
    activeFrom: v.string(),
    activeTo: v.optional(v.string()),
    enabled: v.boolean(),
  }).index("by_enabled_activeFrom", ["enabled", "activeFrom"]),

  // ── Release distribution ──────────────────────────────────────────────────
  releases: defineTable({
    version: v.string(),       // e.g. "v0.1.9"
    platform: v.string(),      // "linux-x64-musl" | "linux-x64" | "macos-aarch64" | "macos-x64" | "windows-x64"
    storageId: v.id("_storage"),
    checksum: v.string(),      // SHA-256 hex string
    fileSize: v.optional(v.number()), // bytes
    isActive: v.boolean(),
    createdAt: v.string(),
  })
    .index("by_platform_and_active", ["platform", "isActive"])
    .index("by_version", ["version"]),

  // ── Per-rule policy modes (Req 19) ────────────────────────────────────────
  // Stores per-rule policy modes for an org: Monitor | Comment | Block | Disabled.
  // Fetched by `sicario ci` before scanning via GET /api/v1/orgs/{org_id}/policy.
  policies: defineTable({
    policyId: v.string(),
    orgId: v.string(),
    ruleId: v.string(),
    // "monitor" | "comment" | "block" | "disabled"
    mode: v.string(),
    createdBy: v.optional(v.string()),
    createdAt: v.string(),
    updatedAt: v.string(),
  })
    .index("by_policyId", ["policyId"])
    .index("by_orgId", ["orgId"])
    .index("by_orgId_ruleId", ["orgId", "ruleId"]),

  // ── Finding Events — append-only event log (Req 22, 27) ──────────────────
  findingEvents: defineTable({
    eventId: v.string(),
    findingId: v.string(),
    orgId: v.string(),
    eventType: v.string(), // "opened"|"triaged"|"reopened"|"note_added"|"auto_fixed"|"auto_removed"|"jira_ticket_created"
    fromState: v.optional(v.string()),
    toState: v.optional(v.string()),
    ignoreReason: v.optional(v.string()),
    userId: v.optional(v.string()),
    note: v.optional(v.string()),
    timestamp: v.string(),
    resolutionType: v.optional(v.string()),
  })
    .index("by_findingId", ["findingId"])
    .index("by_orgId_timestamp", ["orgId", "timestamp"]),

  // ── Saved Filters (Req 28) ────────────────────────────────────────────────
  savedFilters: defineTable({
    filterId: v.string(),
    orgId: v.string(),
    userId: v.string(),
    name: v.string(),
    filters: v.any(), // serialized filter state object
    createdAt: v.string(),
  }).index("by_orgId_userId", ["orgId", "userId"]),

  // ── Jira Integration (Req 33) ─────────────────────────────────────────────
  jiraConfigs: defineTable({
    orgId: v.string(),
    jiraBaseUrl: v.string(),
    jiraProjectKey: v.string(),
    jiraIssueType: v.string(),
    encryptedToken: v.string(), // AES-256-GCM encrypted Jira API token
    createdAt: v.string(),
    updatedAt: v.string(),
  }).index("by_orgId", ["orgId"]),

  // ── Custom Rules (Req 39) ─────────────────────────────────────────────────
  customRules: defineTable({
    ruleId: v.string(),
    orgId: v.string(),
    name: v.string(),
    yaml: v.string(),
    language: v.string(),
    severity: v.string(),
    cweId: v.optional(v.string()),
    owaspCategory: v.optional(v.string()),
    isEnabled: v.boolean(),
    policyMode: v.string(), // "monitor" | "comment" | "block" | "disabled"
    createdBy: v.string(),
    createdAt: v.string(),
    updatedAt: v.string(),
  })
    .index("by_ruleId", ["ruleId"])
    .index("by_orgId", ["orgId"]),

  // ── Managed CI Config (Req 20) ────────────────────────────────────────────
  managedRepos: defineTable({
    repoId: v.string(),
    orgId: v.string(),
    repoFullName: v.string(),
    scmProvider: v.string(),
    defaultBranch: v.string(),
    onboardingStatus: v.string(),
    workflowFilePath: v.string(),
    errorMessage: v.optional(v.string()),
    createdAt: v.string(),
    updatedAt: v.string(),
  })
    .index("by_repoId", ["repoId"])
    .index("by_orgId", ["orgId"])
    .index("by_orgId_repoFullName", ["orgId", "repoFullName"]),

  // ── Shared Rules — Rule Editor Share via URL (Task 50, Group H) ──────────
  sharedRules: defineTable({
    token: v.string(),           // 8-12 char base62 token
    orgId: v.optional(v.string()),
    ruleId: v.optional(v.string()),
    yaml: v.string(),
    testCode: v.optional(v.string()),
    language: v.optional(v.string()),
    isPublic: v.boolean(),
    isPermalink: v.boolean(),
    expiresAt: v.optional(v.string()),  // ISO-8601; null = never expires
    createdBy: v.optional(v.string()),
    createdAt: v.string(),
    viewCount: v.number(),
  })
    .index("by_token", ["token"])
    .index("by_orgId", ["orgId"]),

  // ── Benchmark Results (Task 61.2) ────────────────────────────────────────
  benchmarkResults: defineTable({
    orgId: v.optional(v.string()),
    // Task 61.2: renamed fields to match spec
    timestamp: v.optional(v.string()),   // ISO-8601 run timestamp (alias for runAt)
    runAt: v.string(),                   // kept for backward compat
    target: v.string(),                  // "vuln-sandbox" | "dvwa" | "webgoat" | "juiceshop" | "nodegoat"
    precision: v.number(),
    recall: v.number(),
    f1: v.number(),
    f1Score: v.optional(v.number()),     // alias for f1 (spec field name)
    truePositives: v.number(),
    falsePositives: v.number(),
    falseNegatives: v.number(),
    totalTp: v.optional(v.number()),     // alias for truePositives
    totalFp: v.optional(v.number()),     // alias for falsePositives
    totalFn: v.optional(v.number()),     // alias for falseNegatives
    perLanguage: v.optional(v.any()),    // Task 61.2: per-language breakdown
    vulnSandboxSize: v.optional(v.number()), // Task 61.2: number of files in vuln-sandbox
    cliVersion: v.optional(v.string()),  // Task 61.2: CLI version that ran the benchmark
    format: v.optional(v.string()),
    rawJson: v.optional(v.any()),
  })
    .index("by_orgId", ["orgId"])
    .index("by_runAt", ["runAt"]),

  // ── Suppressions (Task 62.2) ──────────────────────────────────────────────
  suppressions: defineTable({
    suppressionId: v.optional(v.string()),  // kept optional for backward compat
    orgId: v.string(),
    projectId: v.optional(v.string()),      // Task 62.2
    ruleId: v.string(),
    filePath: v.optional(v.string()),
    line: v.optional(v.number()),           // Task 62.2
    committerEmail: v.optional(v.string()), // Task 62.2
    suppressionComment: v.optional(v.string()), // Task 62.2
    firstSeenAt: v.optional(v.string()),    // Task 62.2
    lastSeenAt: v.optional(v.string()),     // Task 62.2
    reason: v.optional(v.string()),
    createdBy: v.optional(v.string()),
    createdAt: v.string(),
    expiresAt: v.optional(v.string()),
    requiresReview: v.optional(v.boolean()), // Task 62.4
  })
    .index("by_orgId", ["orgId"])
    .index("by_orgId_ruleId", ["orgId", "ruleId"]),

  // ── Group O: API Tokens ──────────────────────────────────────────────────
  orgApiTokens: defineTable({
    tokenId: v.string(),
    orgId: v.string(),
    name: v.string(),
    tokenHash: v.string(),
    expiresAt: v.optional(v.string()),
    lastUsedAt: v.optional(v.string()),
    createdBy: v.string(),
    createdAt: v.string(),
  })
    .index("by_tokenId", ["tokenId"])
    .index("by_orgId", ["orgId"])
    .index("by_tokenHash", ["tokenHash"]),
});
