import { defineSchema, defineTable } from "convex/server";
import { authTables } from "@convex-dev/auth/server";
import { v } from "convex/values";

export default defineSchema({
  ...authTables,

  organizations: defineTable({
    orgId: v.string(),
    name: v.string(),
    createdAt: v.string(),
  }).index("by_orgId", ["orgId"]),

  teams: defineTable({
    teamId: v.string(),
    name: v.string(),
    orgId: v.string(),
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
  })
    .index("by_scanId", ["scanId"])
    .index("by_repository", ["repository"])
    .index("by_timestamp", ["timestamp"])
    .index("by_orgId", ["orgId"])
    .index("by_projectId", ["projectId"]),

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
    .index("by_projectId", ["projectId"]),

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
    payload: v.any(),
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
});
