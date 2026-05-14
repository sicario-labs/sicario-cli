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
    ignoreReason: v.optional(v.string()), // Req 22.1: required when triageState === "Ignored"
    note: v.optional(v.string()),         // Req 27.3: note_added event
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

    // Req 22.2: enforce ignoreReason when triageState === "Ignored"
    if (args.triageState === "Ignored" && !args.ignoreReason) {
      throw new Error("ignoreReason is required when triageState is 'Ignored'. Valid values: false_positive, acceptable_risk, no_time_to_fix");
    }

    const now = new Date().toISOString();
    const fromState = finding.triageState;

    // Req 27.3: note_added event without changing triage state
    if (args.note && !args.triageState) {
      await ctx.db.insert("findingEvents", {
        eventId: `evt-${args.id}-${Date.now()}`,
        findingId: args.id,
        orgId: finding.orgId ?? args.orgId ?? "",
        eventType: "note_added",
        fromState,
        toState: fromState,
        userId: args.userId,
        note: args.note,
        timestamp: now,
      });
      await ctx.db.patch(finding._id, { updatedAt: now });
      return mapFinding(finding);
    }

    const updates: Record<string, unknown> = { updatedAt: now };
    if (args.triageState) updates.triageState = args.triageState;
    if (args.triageNote !== undefined) updates.triageNote = args.triageNote;
    if (args.assignedTo !== undefined) updates.assignedTo = args.assignedTo;
    if (args.ignoreReason !== undefined) updates.ignoreReason = args.ignoreReason;

    await ctx.db.patch(finding._id, updates);

    // Req 22.4: append findingEvents record on every triage mutation
    if (args.triageState && args.triageState !== fromState) {
      await ctx.db.insert("findingEvents", {
        eventId: `evt-${args.id}-${Date.now()}`,
        findingId: args.id,
        orgId: finding.orgId ?? args.orgId ?? "",
        eventType: "triaged",
        fromState,
        toState: args.triageState,
        ignoreReason: args.ignoreReason,
        userId: args.userId,
        note: args.triageNote,
        timestamp: now,
      });
    }

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
    projectId: v.optional(v.string()),
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
      if (args.projectId && f.projectId !== args.projectId) return false;
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
    execution_trace: f.executionTrace ?? null,
    triage_state: f.triageState,
    triage_note: f.triageNote ?? null,
    assigned_to: f.assignedTo ?? null,
    created_at: f.createdAt,
    updated_at: f.updatedAt,
    resolution_type: f.resolutionType ?? null,
  };
}

export const listByScanId = query({
  args: { scanId: v.string() },
  handler: async (ctx, args) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .collect();
    return findings.map(mapFinding);
  },
});

/**
 * One-shot migration: mark all existing Low and Info findings as AutoIgnored.
 *
 * This cleans up historical noise from before the telemetry severity gate was
 * introduced. Low/Info findings (e.g. unwrap() in test code) should not appear
 * as open vulnerabilities in the dashboard.
 *
 * Accepts either `orgId` or `projectId` — whichever is available.
 * Safe to call multiple times — already-AutoIgnored findings are skipped.
 * Processes up to `batchSize` documents per call to stay within Convex limits.
 */
export const suppressLowInfoFindings = mutation({
  args: {
    orgId: v.optional(v.string()),
    projectId: v.optional(v.string()),
    batchSize: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const batchSize = args.batchSize ?? 500;
    const now = new Date().toISOString();
    let suppressed = 0;

    for (const severity of ["Low", "Info"]) {
      let findings;

      if (args.orgId) {
        findings = await ctx.db
          .query("findings")
          .withIndex("by_orgId_severity", (q) =>
            q.eq("orgId", args.orgId!).eq("severity", severity)
          )
          .collect();
      } else if (args.projectId) {
        // Fall back to scanning by projectId when orgId is not known
        const allForProject = await ctx.db
          .query("findings")
          .withIndex("by_projectId", (q) => q.eq("projectId", args.projectId!))
          .collect();
        findings = allForProject.filter((f) => f.severity === severity);
      } else {
        // No filter — scan everything (admin use only)
        const all = await ctx.db.query("findings").collect();
        findings = all.filter((f) => f.severity === severity);
      }

      for (const f of findings) {
        if (suppressed >= batchSize) break;
        if (
          f.triageState === "AutoIgnored" ||
          f.triageState === "Ignored" ||
          f.triageState === "Fixed"
        ) {
          continue;
        }
        await ctx.db.patch(f._id, {
          triageState: "AutoIgnored",
          triageNote: "Auto-suppressed: Low/Info severity findings are below the dashboard signal threshold.",
          updatedAt: now,
        });
        suppressed++;
      }
    }

    return { suppressed };
  },
});

/**
 * One-shot deduplication: for each (ruleId, filePath) pair within a project,
 * keep only the most recently updated Open finding and AutoFixed the rest.
 *
 * This cleans up duplicate rows created before the upsert logic was deployed,
 * where the same vulnerability appeared at slightly different line numbers
 * across scans and was treated as a new finding each time.
 */
export const deduplicateByRuleAndFile = mutation({
  args: {
    projectId: v.string(),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();

    const allFindings = await ctx.db
      .query("findings")
      .withIndex("by_projectId", (q) => q.eq("projectId", args.projectId))
      .collect();

    // Group open findings by (ruleId, filePath)
    const groups = new Map<string, typeof allFindings>();
    for (const f of allFindings) {
      if (f.triageState !== "Open" && f.triageState !== "Reviewing" && f.triageState !== "ToFix") {
        continue;
      }
      const key = `${f.ruleId}::${f.filePath}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(f);
    }

    let deduplicated = 0;
    for (const [, dupes] of groups) {
      if (dupes.length <= 1) continue;

      // Keep the most recently updated finding; AutoFixed the rest
      dupes.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
      const [_keep, ...stale] = dupes;

      for (const f of stale) {
        await ctx.db.patch(f._id, {
          triageState: "AutoFixed",
          triageNote: "Auto-resolved: duplicate finding superseded by newer scan result.",
          updatedAt: now,
        });
        deduplicated++;
      }
    }

    return { deduplicated };
  },
});

// ── Task 22.8: triage_state in CLI JSON output (already in mapFinding) ────────

// ── Task 22.6: Fixed vs Removed distinction ───────────────────────────────────
// Auto-set by scans.insert based on why finding disappeared.
// "Fixed" = code changed; "Removed" = rule disabled or file deleted.
// This is handled in scans.ts auto-resolution logic.

// ── Task 22.7: Preserve Reviewing / To Fix state on rescan ───────────────────
// Handled in scans.ts: when auto-resolving, skip findings in Reviewing/ToFix.

// ── Task 28.1: groupByRule ────────────────────────────────────────────────────
export const groupByRule = query({
  args: {
    orgId: v.string(),
    branch: v.optional(v.string()),
    projectId: v.optional(v.string()),
  },
  handler: async (ctx, { orgId, branch, projectId }) => {
    const allFindings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .collect();

    const filtered = allFindings.filter((f) => {
      if (branch && f.branch !== branch) return false;
      if (projectId && f.projectId !== projectId) return false;
      return true;
    });

    const groups = new Map<string, {
      ruleId: string; ruleName: string; severity: string;
      cweId: string | null; owaspCategory: string | null;
      openCount: number; affectedFiles: Set<string>; oldestFindingDate: string;
    }>();

    for (const f of filtered) {
      if (!["Open", "Reviewing", "ToFix"].includes(f.triageState)) continue;
      const key = f.ruleId;
      if (!groups.has(key)) {
        groups.set(key, {
          ruleId: f.ruleId, ruleName: f.ruleName, severity: f.severity,
          cweId: f.cweId ?? null, owaspCategory: f.owaspCategory ?? null,
          openCount: 0, affectedFiles: new Set(), oldestFindingDate: f.createdAt,
        });
      }
      const g = groups.get(key)!;
      g.openCount++;
      g.affectedFiles.add(f.filePath);
      if (f.createdAt < g.oldestFindingDate) g.oldestFindingDate = f.createdAt;
    }

    return [...groups.values()]
      .map((g) => ({ ...g, affectedFiles: [...g.affectedFiles].slice(0, 10) }))
      .sort((a, b) => b.openCount - a.openCount);
  },
});

// ── Task 28.2–28.5: listAdvanced with additional filters ─────────────────────
// (cweId, language, dateFrom/dateTo, committedBy added to existing listAdvanced)
export const listAdvancedV2 = query({
  args: {
    orgId: v.string(),
    severity: v.optional(v.array(v.string())),
    triageState: v.optional(v.array(v.string())),
    cweId: v.optional(v.string()),
    language: v.optional(v.string()),
    dateFrom: v.optional(v.string()),
    dateTo: v.optional(v.string()),
    committedBy: v.optional(v.string()),
    branch: v.optional(v.string()),
    branchType: v.optional(v.string()),
    projectId: v.optional(v.string()),
    search: v.optional(v.string()),
    cursor: v.optional(v.number()),
    perPage: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
      javascript: [".js", ".jsx", ".mjs", ".cjs"],
      typescript: [".ts", ".tsx"],
      python: [".py"],
      go: [".go"],
      rust: [".rs"],
      java: [".java"],
      ruby: [".rb"],
      php: [".php"],
      csharp: [".cs"],
    };

    const allFindings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();

    const filtered = allFindings.filter((f) => {
      if (args.severity?.length && !args.severity.includes(f.severity)) return false;
      if (args.triageState?.length && !args.triageState.includes(f.triageState)) return false;
      if (args.cweId && f.cweId !== args.cweId) return false;
      if (args.language) {
        const exts = LANGUAGE_EXTENSIONS[args.language.toLowerCase()] ?? [];
        if (!exts.some((ext) => f.filePath.endsWith(ext))) return false;
      }
      if (args.dateFrom && f.createdAt < args.dateFrom) return false;
      if (args.dateTo && f.createdAt > args.dateTo) return false;
      if (args.committedBy && f.committedBy !== args.committedBy) return false;
      if (args.branch && f.branch !== args.branch) return false;
      if (args.projectId && f.projectId !== args.projectId) return false;
      if (args.search) {
        const term = args.search.toLowerCase();
        if (!f.ruleId.toLowerCase().includes(term) &&
            !f.filePath.toLowerCase().includes(term) &&
            !f.snippet.toLowerCase().includes(term)) return false;
      }
      return true;
    });

    const total = filtered.length;
    const cursor = args.cursor ?? 0;
    const perPage = args.perPage ?? 20;
    const items = filtered.slice(cursor, cursor + perPage).map(mapFinding);
    const nextCursor = cursor + perPage < total ? cursor + perPage : null;
    return { items, total, nextCursor };
  },
});

// ── Task 28.6: savedFilters CRUD ──────────────────────────────────────────────
export const saveFilter = mutation({
  args: {
    orgId: v.string(),
    userId: v.string(),
    name: v.string(),
    filters: v.any(),
  },
  handler: async (ctx, { orgId, userId, name, filters }) => {
    const now = new Date().toISOString();
    return await ctx.db.insert("savedFilters", {
      filterId: `filter-${orgId}-${Date.now()}`,
      orgId, userId, name, filters, createdAt: now,
    });
  },
});

export const listSavedFilters = query({
  args: { orgId: v.string(), userId: v.string() },
  handler: async (ctx, { orgId, userId }) => {
    return await ctx.db
      .query("savedFilters")
      .withIndex("by_orgId_userId", (q) => q.eq("orgId", orgId).eq("userId", userId))
      .collect();
  },
});

export const deleteSavedFilter = mutation({
  args: { filterId: v.string() },
  handler: async (ctx, { filterId }) => {
    const f = await ctx.db.query("savedFilters")
      .filter((q) => q.eq(q.field("filterId"), filterId)).first();
    if (f) await ctx.db.delete(f._id);
  },
});

// ── Task 32.1–32.3: exportSarif ───────────────────────────────────────────────
export const exportSarif = query({
  args: {
    orgId: v.string(),
    severity: v.optional(v.array(v.string())),
    triageState: v.optional(v.array(v.string())),
    projectId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const allFindings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();

    const filtered = allFindings.filter((f) => {
      if (args.severity?.length && !args.severity.includes(f.severity)) return false;
      if (args.triageState?.length && !args.triageState.includes(f.triageState)) return false;
      if (args.projectId && f.projectId !== args.projectId) return false;
      return true;
    });

    const SEVERITY_TO_SARIF: Record<string, string> = {
      Critical: "error", High: "error",
      Medium: "warning", Low: "note", Info: "note",
    };

    const results = filtered.map((f) => {
      let scanType = "sast";
      if (f.ruleId.startsWith("sca/") || f.filePath.startsWith("<")) {
        scanType = "sca";
      } else if (f.ruleId.startsWith("secrets/") || f.ruleId.includes("secret") || f.ruleId.includes("token") || f.ruleId.includes("key")) {
        scanType = "secrets";
      }

      const cveId = f.cweId ?? f.ruleId.replace(/^sca\//, "");
      const finalRuleId = scanType === "sca" ? (f.ruleId.startsWith("sca/") ? f.ruleId : `sca/${cveId}`) : f.ruleId;

      let scaProps: Record<string, any> = {};
      if (scanType === "sca") {
        const cleanedPath = f.filePath.replace(/^</, "").replace(/>$/, "");
        const parts = cleanedPath.split(":");
        const pkg = (f as any).packageName ?? parts[0] ?? "unknown";
        const ver = (f as any).version ?? parts[1] ?? "unknown";
        scaProps = {
          package: pkg,
          version: ver,
          cve_id: cveId,
          reachable: f.reachable ?? false,
        };
      }

      let secretsProps: Record<string, any> = {};
      if (scanType === "secrets") {
        secretsProps = {
          rule_id: f.ruleId,
          file_path: f.filePath,
          line: f.line,
          severity: f.severity,
        };
      }

      return {
        ruleId: finalRuleId,
        level: SEVERITY_TO_SARIF[f.severity] ?? "note",
        message: { text: f.ruleName },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.filePath },
            region: { startLine: f.line, startColumn: f.column },
          },
        }],
        fingerprints: {
          matchBasedId: f.matchBasedId ?? f.fingerprint,
        },
        properties: {
          scan_type: scanType,
          ...scaProps,
          ...secretsProps,
        },
        // Req 32.5: no snippet unless explicitly opted in
      };
    });

    return {
      version: "2.1.0",
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      runs: [{
        tool: {
          driver: {
            name: "Sicario",
            version: "0.3.5",
            informationUri: "https://usesicario.xyz",
            rules: [],
          },
        },
        results,
      }],
    };
  },
});
