import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireRole } from "./rbac";

export const get = query({
  args: { id: v.string() },
  handler: async (ctx, args) => {
    const finding = await ctx.db
      .query("findings")
      .withIndex("by_findingId", (q) => q.eq("findingId", args.id))
      .first();
    if (!finding) return null;
    return mapFinding(finding);
  },
});

export const list = query({
  args: {
    orgId: v.string(),
    page: v.optional(v.number()),
    perPage: v.optional(v.number()),
    severity: v.optional(v.string()),
    triageState: v.optional(v.string()),
    confidenceMin: v.optional(v.number()),
    scanId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const page = args.page ?? 1;
    const perPage = args.perPage ?? 20;

    // Use composite indexes when a single filter is provided, otherwise base org index
    let baseQuery;
    if (args.severity) {
      baseQuery = ctx.db
        .query("findings")
        .withIndex("by_orgId_severity", (q) =>
          q.eq("orgId", args.orgId).eq("severity", args.severity!)
        );
    } else if (args.triageState) {
      baseQuery = ctx.db
        .query("findings")
        .withIndex("by_orgId_triageState", (q) =>
          q.eq("orgId", args.orgId).eq("triageState", args.triageState!)
        );
    } else {
      baseQuery = ctx.db
        .query("findings")
        .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId));
    }

    const allFindings = await baseQuery.collect();

    // JS-level filtering for confidenceMin and scanId
    const filtered = allFindings.filter((f) => {
      if (args.confidenceMin !== undefined && f.confidenceScore < args.confidenceMin) return false;
      if (args.scanId && f.scanId !== args.scanId) return false;
      return true;
    });

    const total = filtered.length;
    const offset = (page - 1) * perPage;
    const items = filtered.slice(offset, offset + perPage).map(mapFinding);

    return { page, per_page: perPage, total, items };
  },
});

export const triage = mutation({
  args: {
    id: v.string(),
    triageState: v.optional(v.string()),
    triageNote: v.optional(v.string()),
    assignedTo: v.optional(v.string()),
    userId: v.optional(v.string()),
    orgId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId && args.orgId) {
      await requireRole(ctx, args.userId, args.orgId, "developer");
    }

    const finding = await ctx.db
      .query("findings")
      .withIndex("by_findingId", (q) => q.eq("findingId", args.id))
      .first();
    if (!finding) return null;

    const updates: Record<string, string> = {
      updatedAt: new Date().toISOString(),
    };
    if (args.triageState) updates.triageState = args.triageState;
    if (args.triageNote !== undefined) updates.triageNote = args.triageNote;
    if (args.assignedTo !== undefined) updates.assignedTo = args.assignedTo;

    await ctx.db.patch(finding._id, updates);

    return { ...mapFinding(finding), ...updates };
  },
});

export const bulkTriage = mutation({
  args: {
    ids: v.array(v.string()),
    triageState: v.string(),
    triageNote: v.optional(v.string()),
    userId: v.optional(v.string()),
    orgId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId && args.orgId) {
      await requireRole(ctx, args.userId, args.orgId, "developer");
    }

    const now = new Date().toISOString();
    let count = 0;

    for (const id of args.ids) {
      const finding = await ctx.db
        .query("findings")
        .withIndex("by_findingId", (q) => q.eq("findingId", id))
        .first();
      if (finding) {
        const updates: Record<string, string> = {
          triageState: args.triageState,
          updatedAt: now,
        };
        if (args.triageNote) updates.triageNote = args.triageNote;
        await ctx.db.patch(finding._id, updates);
        count++;
      }
    }

    return { updated_count: count };
  },
});

export const listForExport = query({
  args: {
    orgId: v.string(),
    severity: v.optional(v.string()),
    triageState: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Use composite indexes when a single filter is provided, otherwise base org index
    let baseQuery;
    if (args.severity) {
      baseQuery = ctx.db
        .query("findings")
        .withIndex("by_orgId_severity", (q) =>
          q.eq("orgId", args.orgId).eq("severity", args.severity!)
        );
    } else if (args.triageState) {
      baseQuery = ctx.db
        .query("findings")
        .withIndex("by_orgId_triageState", (q) =>
          q.eq("orgId", args.orgId).eq("triageState", args.triageState!)
        );
    } else {
      baseQuery = ctx.db
        .query("findings")
        .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId));
    }

    const allFindings = await baseQuery.collect();

    // JS-level filtering for remaining filters not handled by the index
    return allFindings
      .filter((f) => {
        if (args.severity && f.severity !== args.severity) return false;
        if (args.triageState && f.triageState !== args.triageState) return false;
        return true;
      })
      .map(mapFinding);
  },
});

export const getCriticalForScan = query({
  args: { scanId: v.string() },
  handler: async (ctx, args) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .collect();
    return findings
      .filter((f) => f.severity === "Critical")
      .map(mapFinding);
  },
});

const SEVERITY_ORDER: Record<string, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1,
};

export const listAdvanced = query({
  args: {
    orgId: v.string(),
    severity: v.optional(v.array(v.string())),
    triageState: v.optional(v.array(v.string())),
    search: v.optional(v.string()),
    confidenceMin: v.optional(v.number()),
    confidenceMax: v.optional(v.number()),
    reachable: v.optional(v.boolean()),
    scanId: v.optional(v.string()),
    owaspCategory: v.optional(v.string()),
    sortBy: v.optional(v.string()),
    sortOrder: v.optional(v.string()),
    cursor: v.optional(v.number()),
    perPage: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    // Use composite indexes when a single filter is provided, otherwise base org index
    let baseQuery;
    if (args.severity && args.severity.length === 1) {
      baseQuery = ctx.db
        .query("findings")
        .withIndex("by_orgId_severity", (q) =>
          q.eq("orgId", args.orgId).eq("severity", args.severity![0])
        );
    } else if (args.triageState && args.triageState.length === 1) {
      baseQuery = ctx.db
        .query("findings")
        .withIndex("by_orgId_triageState", (q) =>
          q.eq("orgId", args.orgId).eq("triageState", args.triageState![0])
        );
    } else {
      baseQuery = ctx.db
        .query("findings")
        .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId));
    }

    const allFindings = await baseQuery.collect();

    const filtered = allFindings.filter((f) => {
      if (args.severity && args.severity.length > 0 && !args.severity.includes(f.severity)) return false;
      if (args.triageState && args.triageState.length > 0 && !args.triageState.includes(f.triageState)) return false;
      if (args.confidenceMin !== undefined && f.confidenceScore < args.confidenceMin) return false;
      if (args.confidenceMax !== undefined && f.confidenceScore > args.confidenceMax) return false;
      if (args.reachable !== undefined && f.reachable !== args.reachable) return false;
      if (args.scanId && f.scanId !== args.scanId) return false;
      if (args.owaspCategory && f.owaspCategory !== args.owaspCategory) return false;
      if (args.search) {
        const term = args.search.toLowerCase();
        const inRuleId = f.ruleId.toLowerCase().includes(term);
        const inFilePath = f.filePath.toLowerCase().includes(term);
        const inSnippet = f.snippet.toLowerCase().includes(term);
        if (!inRuleId && !inFilePath && !inSnippet) return false;
      }
      return true;
    });

    const sortBy = args.sortBy ?? "createdAt";
    const sortOrder = args.sortOrder ?? "desc";

    filtered.sort((a: any, b: any) => {
      let aVal: number | string;
      let bVal: number | string;

      if (sortBy === "severity") {
        aVal = SEVERITY_ORDER[a.severity] ?? 0;
        bVal = SEVERITY_ORDER[b.severity] ?? 0;
      } else if (sortBy === "confidenceScore") {
        aVal = a.confidenceScore;
        bVal = b.confidenceScore;
      } else if (sortBy === "filePath") {
        aVal = a.filePath;
        bVal = b.filePath;
      } else if (sortBy === "updatedAt") {
        aVal = a.updatedAt;
        bVal = b.updatedAt;
      } else {
        aVal = a.createdAt;
        bVal = b.createdAt;
      }

      if (aVal < bVal) return sortOrder === "asc" ? -1 : 1;
      if (aVal > bVal) return sortOrder === "asc" ? 1 : -1;
      return 0;
    });

    const total = filtered.length;
    const cursor = args.cursor ?? 0;
    const perPage = args.perPage ?? 20;
    const items = filtered.slice(cursor, cursor + perPage).map(mapFinding);
    const nextCursor = cursor + perPage < total ? cursor + perPage : null;

    return { items, total, nextCursor };
  },
});

export const getTimeline = query({
  args: { id: v.string() },
  handler: async (ctx, args) => {
    const finding = await ctx.db
      .query("findings")
      .withIndex("by_findingId", (q) => q.eq("findingId", args.id))
      .first();
    if (!finding) return null;

    const timeline: { timestamp: string; state: string; action: string }[] = [
      { timestamp: finding.createdAt, state: "Open", action: "created" },
    ];

    if (finding.triageState !== "Open") {
      timeline.push({
        timestamp: finding.updatedAt,
        state: finding.triageState,
        action: "triaged",
      });
    }

    return timeline;
  },
});

export const getAdjacentIds = query({
  args: {
    orgId: v.string(),
    currentId: v.string(),
    severity: v.optional(v.array(v.string())),
    triageState: v.optional(v.array(v.string())),
    search: v.optional(v.string()),
    scanId: v.optional(v.string()),
    sortBy: v.optional(v.string()),
    sortOrder: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const allFindings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();

    const filtered = allFindings.filter((f) => {
      if (args.severity && args.severity.length > 0 && !args.severity.includes(f.severity)) return false;
      if (args.triageState && args.triageState.length > 0 && !args.triageState.includes(f.triageState)) return false;
      if (args.scanId && f.scanId !== args.scanId) return false;
      if (args.search) {
        const term = args.search.toLowerCase();
        const inRuleId = f.ruleId.toLowerCase().includes(term);
        const inFilePath = f.filePath.toLowerCase().includes(term);
        const inSnippet = f.snippet.toLowerCase().includes(term);
        if (!inRuleId && !inFilePath && !inSnippet) return false;
      }
      return true;
    });

    const sortBy = args.sortBy ?? "createdAt";
    const sortOrder = args.sortOrder ?? "desc";

    filtered.sort((a: any, b: any) => {
      let aVal: number | string;
      let bVal: number | string;

      if (sortBy === "severity") {
        aVal = SEVERITY_ORDER[a.severity] ?? 0;
        bVal = SEVERITY_ORDER[b.severity] ?? 0;
      } else if (sortBy === "confidenceScore") {
        aVal = a.confidenceScore;
        bVal = b.confidenceScore;
      } else if (sortBy === "filePath") {
        aVal = a.filePath;
        bVal = b.filePath;
      } else if (sortBy === "updatedAt") {
        aVal = a.updatedAt;
        bVal = b.updatedAt;
      } else {
        aVal = a.createdAt;
        bVal = b.createdAt;
      }

      if (aVal < bVal) return sortOrder === "asc" ? -1 : 1;
      if (aVal > bVal) return sortOrder === "asc" ? 1 : -1;
      return 0;
    });

    const index = filtered.findIndex((f) => f.findingId === args.currentId);
    const previousId = index > 0 ? filtered[index - 1].findingId : null;
    const nextId = index >= 0 && index < filtered.length - 1 ? filtered[index + 1].findingId : null;

    return { previousId, nextId };
  },
});

// Helper to map internal Convex doc to API-compatible shape
function mapFinding(f: any) {
  return {
    id: f.findingId,
    scan_id: f.scanId,
    rule_id: f.ruleId,
    rule_name: f.ruleName,
    file_path: f.filePath,
    line: f.line,
    column: f.column,
    end_line: f.endLine ?? null,
    end_column: f.endColumn ?? null,
    snippet: f.snippet,
    severity: f.severity,
    confidence_score: f.confidenceScore,
    reachable: f.reachable,
    cloud_exposed: f.cloudExposed ?? null,
    cwe_id: f.cweId ?? null,
    owasp_category: f.owaspCategory ?? null,
    fingerprint: f.fingerprint,
    triage_state: f.triageState,
    triage_note: f.triageNote ?? null,
    assigned_to: f.assignedTo ?? null,
    created_at: f.createdAt,
    updated_at: f.updatedAt,
  };
}
