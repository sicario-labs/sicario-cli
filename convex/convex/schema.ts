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
  })
    .index("by_projectId", ["projectId"])
    .index("by_teamId", ["teamId"])
    .index("by_orgId", ["orgId"]),

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
    .index("by_orgId", ["orgId"]),

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
    .index("by_orgId_createdAt", ["orgId", "createdAt"]),

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
    status: v.string(), // "pending" | "approved" | "denied" | "expired"
    expiresAt: v.number(),
    accessToken: v.optional(v.string()),
    createdAt: v.string(),
  })
    .index("by_deviceCode", ["deviceCode"])
    .index("by_userCode", ["userCode"])
    .index("by_accessToken", ["accessToken"]),

  providerSettings: defineTable({
    userId: v.string(),
    providerName: v.string(),
    endpoint: v.string(),
    model: v.string(),
    encryptedApiKey: v.optional(v.string()),
    createdAt: v.string(),
    updatedAt: v.string(),
  }).index("by_userId", ["userId"]),

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
    createdAt: v.string(),
    updatedAt: v.string(),
  }).index("by_userId", ["userId"]),
});
