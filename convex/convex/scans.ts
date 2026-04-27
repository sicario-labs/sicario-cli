import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const insert = mutation({
  args: {
    scanId: v.string(),
    report: v.any(),
    orgId: v.optional(v.string()),
    projectId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const { scanId, report, orgId, projectId } = args;
    const meta = report.metadata;
    const now = new Date().toISOString();

    // Insert the scan record
    await ctx.db.insert("scans", {
      scanId,
      repository: meta.repository ?? "",
      branch: meta.branch ?? "",
      commitSha: meta.commit_sha ?? "",
      timestamp: meta.timestamp ?? now,
      durationMs: meta.duration_ms ?? 0,
      rulesLoaded: meta.rules_loaded ?? 0,
      filesScanned: meta.files_scanned ?? 0,
      languageBreakdown: meta.language_breakdown ?? {},
      tags: meta.tags ?? [],
      orgId,
      projectId,
      createdAt: now,
    });

    // Insert each finding
    for (const f of report.findings ?? []) {
      await ctx.db.insert("findings", {
        findingId: f.id ?? "",
        scanId,
        ruleId: f.rule_id ?? "",
        ruleName: f.rule_name ?? "",
        filePath: typeof f.file_path === "string" ? f.file_path : "",
        line: f.line ?? 0,
        column: f.column ?? 0,
        endLine: f.end_line ?? undefined,
        endColumn: f.end_column ?? undefined,
        snippet: f.snippet ?? "",
        severity: typeof f.severity === "string" ? f.severity : (f.severity ?? "Info"),
        confidenceScore: f.confidence_score ?? 0,
        reachable: f.reachable ?? false,
        cloudExposed: f.cloud_exposed ?? undefined,
        cweId: f.cwe_id ?? undefined,
        owaspCategory: f.owasp_category ?? undefined,
        fingerprint: f.fingerprint ?? "",
        executionTrace: f.execution_trace ?? undefined,
        orgId,
        projectId,
        triageState: "Open",
        createdAt: now,
        updatedAt: now,
      });
    }

    // Transition project provisioning state from "pending" to "active" on first scan
    if (projectId) {
      const project = await ctx.db
        .query("projects")
        .withIndex("by_projectId", (q) => q.eq("projectId", projectId))
        .first();
      if (project && project.provisioningState === "pending") {
        await ctx.db.patch(project._id, { provisioningState: "active" });
      }
    }

    return { scanId };
  },
});

export const getByScanId = query({
  args: { scanId: v.string() },
  handler: async (ctx, args) => {
    const scan = await ctx.db
      .query("scans")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .first();
    return scan ? { scanId: scan.scanId } : null;
  },
});

export const get = query({
  args: { id: v.string() },
  handler: async (ctx, args) => {
    const scan = await ctx.db
      .query("scans")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.id))
      .first();
    if (!scan) return null;

    // Count findings
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.id))
      .collect();

    const findingsCount = findings.length;
    const criticalCount = findings.filter((f) => f.severity === "Critical").length;
    const highCount = findings.filter((f) => f.severity === "High").length;

    // Resolve project name
    let projectName: string | null = null;
    if (scan.projectId) {
      const project = await ctx.db
        .query("projects")
        .withIndex("by_projectId", (q) => q.eq("projectId", scan.projectId!))
        .first();
      if (project) projectName = project.name;
    }

    // Resolve org name
    let orgName: string | null = null;
    if (scan.orgId) {
      const org = await ctx.db
        .query("organizations")
        .withIndex("by_orgId", (q) => q.eq("orgId", scan.orgId!))
        .first();
      if (org) orgName = org.name;
    }

    return {
      id: scan.scanId,
      repository: scan.repository,
      branch: scan.branch,
      commit_sha: scan.commitSha,
      timestamp: scan.timestamp,
      duration_ms: scan.durationMs,
      rules_loaded: scan.rulesLoaded,
      files_scanned: scan.filesScanned,
      language_breakdown: scan.languageBreakdown,
      tags: scan.tags,
      findings_count: findingsCount,
      critical_count: criticalCount,
      high_count: highCount,
      org_id: scan.orgId ?? null,
      org_name: orgName,
      project_id: scan.projectId ?? null,
      project_name: projectName,
    };
  },
});

export const list = query({
  args: {
    page: v.optional(v.number()),
    perPage: v.optional(v.number()),
    repository: v.optional(v.string()),
    branch: v.optional(v.string()),
    orgId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const page = args.page ?? 1;
    const perPage = args.perPage ?? 20;

    // Use by_orgId index when orgId is provided, otherwise fetch all
    let allScans;
    if (args.orgId) {
      allScans = await ctx.db
        .query("scans")
        .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
        .order("desc")
        .collect();
    } else {
      allScans = await ctx.db.query("scans").order("desc").collect();
    }

    const filtered = allScans.filter((s) => {
      if (args.repository && s.repository !== args.repository) return false;
      if (args.branch && s.branch !== args.branch) return false;
      return true;
    });

    const total = filtered.length;
    const offset = (page - 1) * perPage;
    const paged = filtered.slice(offset, offset + perPage);

    // Batch-load findings counts to avoid N+1 query pattern
    const countByScanId: Record<string, number> = {};
    if (args.orgId) {
      // When orgId is available, load all findings for the org in one query
      const allFindings = await ctx.db
        .query("findings")
        .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
        .collect();
      for (const f of allFindings) {
        countByScanId[f.scanId] = (countByScanId[f.scanId] ?? 0) + 1;
      }
    } else {
      // Fallback: batch-load findings for all scanIds on the current page
      const scanIds = new Set(paged.map((s) => s.scanId));
      const allFindings = await ctx.db.query("findings").collect();
      for (const f of allFindings) {
        if (scanIds.has(f.scanId)) {
          countByScanId[f.scanId] = (countByScanId[f.scanId] ?? 0) + 1;
        }
      }
    }

    const items = paged.map((s) => ({
      id: s.scanId,
      repository: s.repository,
      branch: s.branch,
      commit_sha: s.commitSha,
      timestamp: s.timestamp,
      duration_ms: s.durationMs,
      rules_loaded: s.rulesLoaded,
      files_scanned: s.filesScanned,
      language_breakdown: s.languageBreakdown,
      tags: s.tags,
      findings_count: countByScanId[s.scanId] ?? 0,
    }));

    return { page, per_page: perPage, total, items };
  },
});
