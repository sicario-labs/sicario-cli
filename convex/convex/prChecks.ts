import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const createPrCheck = mutation({
  args: {
    checkId: v.string(),
    projectId: v.string(),
    orgId: v.string(),
    prNumber: v.number(),
    prTitle: v.string(),
    repositoryUrl: v.string(),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();
    await ctx.db.insert("prChecks", {
      checkId: args.checkId,
      projectId: args.projectId,
      orgId: args.orgId,
      prNumber: args.prNumber,
      prTitle: args.prTitle,
      repositoryUrl: args.repositoryUrl,
      status: "pending",
      findingsCount: 0,
      criticalCount: 0,
      highCount: 0,
      createdAt: now,
      updatedAt: now,
    });
    return { checkId: args.checkId };
  },
});

export const updatePrCheck = mutation({
  args: {
    checkId: v.string(),
    status: v.string(),
    findingsCount: v.optional(v.number()),
    criticalCount: v.optional(v.number()),
    highCount: v.optional(v.number()),
    githubCheckRunId: v.optional(v.string()),
    scanId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("prChecks")
      .withIndex("by_checkId", (q) => q.eq("checkId", args.checkId))
      .first();
    if (!record) return null;

    const now = new Date().toISOString();
    const updates: Record<string, unknown> = {
      status: args.status,
      updatedAt: now,
    };
    if (args.findingsCount !== undefined) updates.findingsCount = args.findingsCount;
    if (args.criticalCount !== undefined) updates.criticalCount = args.criticalCount;
    if (args.highCount !== undefined) updates.highCount = args.highCount;
    if (args.githubCheckRunId !== undefined) updates.githubCheckRunId = args.githubCheckRunId;
    if (args.scanId !== undefined) updates.scanId = args.scanId;

    await ctx.db.patch(record._id, updates);
  },
});

export const listByOrg = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const checks = await ctx.db
      .query("prChecks")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .order("desc")
      .collect();
    return checks.map(mapPrCheck);
  },
});

export const listByProject = query({
  args: { projectId: v.string() },
  handler: async (ctx, args) => {
    const checks = await ctx.db
      .query("prChecks")
      .withIndex("by_projectId", (q) => q.eq("projectId", args.projectId))
      .collect();
    return checks.map(mapPrCheck);
  },
});

function mapPrCheck(c: any) {
  return {
    check_id: c.checkId,
    project_id: c.projectId,
    org_id: c.orgId,
    pr_number: c.prNumber,
    pr_title: c.prTitle,
    repository_url: c.repositoryUrl,
    status: c.status,
    findings_count: c.findingsCount,
    critical_count: c.criticalCount,
    high_count: c.highCount,
    github_check_run_id: c.githubCheckRunId ?? null,
    scan_id: c.scanId ?? null,
    created_at: c.createdAt,
    updated_at: c.updatedAt,
  };
}

export const getByCheckId = query({
  args: { checkId: v.string() },
  handler: async (ctx, args) => {
    const check = await ctx.db
      .query("prChecks")
      .withIndex("by_checkId", (q) => q.eq("checkId", args.checkId))
      .first();
    if (!check) return null;

    const mapped = mapPrCheck(check);

    // If a scanId is linked, fetch the associated findings
    if (check.scanId) {
      const findings = await ctx.db
        .query("findings")
        .withIndex("by_scanId", (q) => q.eq("scanId", check.scanId!))
        .collect();
      return {
        ...mapped,
        findings: findings.map((f) => ({
          finding_id: f.findingId,
          rule_id: f.ruleId,
          rule_name: f.ruleName,
          file_path: f.filePath,
          line: f.line,
          column: f.column,
          snippet: f.snippet,
          severity: f.severity,
          cwe_id: f.cweId ?? null,
          owasp_category: f.owaspCategory ?? null,
          fingerprint: f.fingerprint,
          triage_state: f.triageState,
        })),
      };
    }

    return { ...mapped, findings: [] };
  },
});
