import { query } from "./_generated/server";
import { v } from "convex/values";

export const overview = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const findings = await ctx.db.query("findings").withIndex("by_orgId", (q) => q.eq("orgId", args.orgId)).collect();
    const scans = await ctx.db.query("scans").withIndex("by_orgId", (q) => q.eq("orgId", args.orgId)).collect();

    let total = 0, open = 0, fixed = 0, ignored = 0;
    let critical = 0, high = 0, medium = 0, low = 0, info = 0;

    for (const f of findings) {
      total++;
      const isOpen = f.triageState === "Open" || f.triageState === "Reviewing" || f.triageState === "ToFix";
      const isFixed = f.triageState === "Fixed" || f.triageState === "AutoFixed";
      const isIgnored = f.triageState === "Ignored" || f.triageState === "AutoIgnored";

      if (isOpen) open++;
      else if (isFixed) fixed++;
      else if (isIgnored) ignored++;
      else open++; // unknown state — treat as open

      // Severity breakdown counts only open (actionable) findings.
      // AutoIgnored / Ignored / Fixed findings are excluded so the dashboard
      // reflects the real signal, not historical noise.
      if (!isFixed && !isIgnored) {
        switch (f.severity) {
          case "Critical": critical++; break;
          case "High": high++; break;
          case "Medium": medium++; break;
          case "Low": low++; break;
          case "Info": info++; break;
        }
      }
    }

    const totalScans = scans.length;
    const avgDuration = totalScans > 0
      ? Math.round(scans.reduce((sum, s) => sum + s.durationMs, 0) / totalScans)
      : 0;

    return {
      total_findings: open, // "Vulnerabilities Intercepted" = open (non-ignored, non-fixed) findings
      open_findings: open,
      fixed_findings: fixed,
      ignored_findings: ignored,
      critical_count: critical,
      high_count: high,
      medium_count: medium,
      low_count: low,
      info_count: info,
      total_scans: totalScans,
      avg_scan_duration_ms: avgDuration,
    };
  },
});

export const trends = query({
  args: {
    orgId: v.string(),
    from: v.optional(v.string()),
    to: v.optional(v.string()),
    interval: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const findings = await ctx.db.query("findings").withIndex("by_orgId", (q) => q.eq("orgId", args.orgId)).collect();

    const byDay: Record<string, { open: number; new: number; fixed: number }> = {};

    for (const f of findings) {
      const day = f.createdAt.substring(0, 10); // YYYY-MM-DD
      if (!byDay[day]) byDay[day] = { open: 0, new: 0, fixed: 0 };
      byDay[day].new++;
      switch (f.triageState) {
        case "Open": case "Reviewing": case "ToFix":
          byDay[day].open++; break;
        case "Fixed":
          byDay[day].fixed++; break;
      }
    }

    return Object.entries(byDay)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([day, counts]) => ({
        timestamp: `${day}T00:00:00Z`,
        open_findings: counts.open,
        new_findings: counts.new,
        fixed_findings: counts.fixed,
      }));
  },
});

export const mttr = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const findings = await ctx.db.query("findings").withIndex("by_orgId", (q) => q.eq("orgId", args.orgId)).collect();

    let totalHours = 0;
    let count = 0;
    const bySeverity: Record<string, { hours: number; count: number }> = {};

    for (const f of findings) {
      if (f.triageState === "Fixed") {
        const created = new Date(f.createdAt).getTime();
        const updated = new Date(f.updatedAt).getTime();
        const hours = (updated - created) / (1000 * 60 * 60);
        totalHours += hours;
        count++;

        if (!bySeverity[f.severity]) bySeverity[f.severity] = { hours: 0, count: 0 };
        bySeverity[f.severity].hours += hours;
        bySeverity[f.severity].count++;
      }
    }

    const overall = count > 0 ? totalHours / count : 0;
    const bySev: Record<string, number> = {};
    for (const [sev, data] of Object.entries(bySeverity)) {
      bySev[sev] = data.count > 0 ? data.hours / data.count : 0;
    }

    return {
      overall_mttr_hours: overall,
      by_severity: bySev,
    };
  },
});

export const topVulnerableProjects = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const projects = await ctx.db.query("projects").withIndex("by_orgId", (q) => q.eq("orgId", args.orgId)).collect();
    const findings = await ctx.db.query("findings").withIndex("by_orgId", (q) => q.eq("orgId", args.orgId)).collect();

    // Group open findings by projectId (using f.projectId directly, no scans join needed)
    const openStates = new Set(["Open", "Reviewing", "ToFix"]);
    const projectStats: Record<
      string,
      { openCount: number; criticalCount: number; highCount: number; mediumCount: number; lowCount: number }
    > = {};

    for (const f of findings) {
      const projectId = f.projectId;
      if (!projectId) continue;
      if (!openStates.has(f.triageState)) continue;

      if (!projectStats[projectId]) {
        projectStats[projectId] = { openCount: 0, criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0 };
      }
      projectStats[projectId].openCount++;
      switch (f.severity) {
        case "Critical": projectStats[projectId].criticalCount++; break;
        case "High": projectStats[projectId].highCount++; break;
        case "Medium": projectStats[projectId].mediumCount++; break;
        case "Low": projectStats[projectId].lowCount++; break;
      }
    }

    // Build project lookup
    const projectMap: Record<string, { name: string; repositoryUrl: string }> = {};
    for (const p of projects) {
      projectMap[p.projectId] = { name: p.name, repositoryUrl: p.repositoryUrl };
    }

    // Build result, sort by openCount desc, limit to 10
    const results = Object.entries(projectStats)
      .map(([projectId, stats]) => ({
        projectId,
        name: projectMap[projectId]?.name ?? "Unknown",
        repositoryUrl: projectMap[projectId]?.repositoryUrl ?? "",
        ...stats,
      }))
      .sort((a, b) => b.openCount - a.openCount)
      .slice(0, 10);

    return results;
  },
});

export const owaspCompliance = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const findings = await ctx.db.query("findings").withIndex("by_orgId", (q) => q.eq("orgId", args.orgId)).collect();

    const resolvedStates = new Set(["Fixed", "Ignored", "AutoIgnored"]);
    const openStates = new Set(["Open", "Reviewing", "ToFix"]);

    const categories: Record<
      string,
      {
        total: number;
        resolved: number;
        open: number;
        severityBreakdown: { critical: number; high: number; medium: number; low: number; info: number };
      }
    > = {};

    for (const f of findings) {
      if (!f.owaspCategory) continue;

      const cat = f.owaspCategory;
      if (!categories[cat]) {
        categories[cat] = {
          total: 0,
          resolved: 0,
          open: 0,
          severityBreakdown: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        };
      }

      categories[cat].total++;
      if (resolvedStates.has(f.triageState)) {
        categories[cat].resolved++;
      }
      if (openStates.has(f.triageState)) {
        categories[cat].open++;
      }

      switch (f.severity) {
        case "Critical": categories[cat].severityBreakdown.critical++; break;
        case "High": categories[cat].severityBreakdown.high++; break;
        case "Medium": categories[cat].severityBreakdown.medium++; break;
        case "Low": categories[cat].severityBreakdown.low++; break;
        case "Info": categories[cat].severityBreakdown.info++; break;
      }
    }

    return Object.entries(categories)
      .map(([category, data]) => {
        const complianceScore =
          data.total > 0
            ? Math.round((data.resolved / data.total) * 1000) / 10
            : 100;
        const status =
          complianceScore >= 80 ? "pass" : complianceScore >= 50 ? "warning" : "fail";
        return {
          category,
          total: data.total,
          resolved: data.resolved,
          open: data.open,
          severityBreakdown: data.severityBreakdown,
          complianceScore,
          status,
        };
      })
      .sort((a, b) => a.category.localeCompare(b.category));
  },
});

export const findingsByLanguage = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const scans = await ctx.db.query("scans").withIndex("by_orgId", (q) => q.eq("orgId", args.orgId)).collect();
    const findings = await ctx.db.query("findings").withIndex("by_orgId", (q) => q.eq("orgId", args.orgId)).collect();

    // Group findings by scanId
    const findingsByScan: Record<string, number> = {};
    for (const f of findings) {
      findingsByScan[f.scanId] = (findingsByScan[f.scanId] ?? 0) + 1;
    }

    // For each language, sum finding counts from scans that include that language
    const languageStats: Record<string, { findingCount: number; scanCount: number }> = {};

    for (const scan of scans) {
      const breakdown = scan.languageBreakdown as Record<string, number> | null;
      if (!breakdown) continue;

      const scanFindingCount = findingsByScan[scan.scanId] ?? 0;

      for (const language of Object.keys(breakdown)) {
        if (!languageStats[language]) {
          languageStats[language] = { findingCount: 0, scanCount: 0 };
        }
        languageStats[language].findingCount += scanFindingCount;
        languageStats[language].scanCount++;
      }
    }

    return Object.entries(languageStats)
      .map(([language, stats]) => ({
        language,
        findingCount: stats.findingCount,
        scanCount: stats.scanCount,
      }))
      .sort((a, b) => b.findingCount - a.findingCount);
  },
});

// ── Task 24.2: guardrailsAdoption ────────────────────────────────────────────
export const guardrailsAdoption = query({
  args: {
    orgId: v.string(),
    dateFrom: v.optional(v.string()),
    dateTo: v.optional(v.string()),
    projectId: v.optional(v.string()),
  },
  handler: async (ctx, { orgId, dateFrom, dateTo, projectId }) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .collect();

    const filtered = findings.filter((f) => {
      if (dateFrom && f.createdAt < dateFrom) return false;
      if (dateTo && f.createdAt > dateTo) return false;
      if (projectId && f.projectId !== projectId) return false;
      return true;
    });

    const total = filtered.length;
    const surfacedInPr = filtered.filter((f) => (f as any).surfacedInPr).length;
    const fixedBeforeBacklog = filtered.filter(
      (f) => (f as any).surfacedInPr && (f.triageState === "Fixed" || f.triageState === "AutoFixed")
    ).length;

    return {
      findings_total: total,
      findings_shown_in_pr: surfacedInPr,
      adoption_rate_pct: total > 0 ? Math.round((surfacedInPr / total) * 100 * 10) / 10 : 0,
      fixed_before_backlog: fixedBeforeBacklog,
      fixed_before_backlog_pct: surfacedInPr > 0
        ? Math.round((fixedBeforeBacklog / surfacedInPr) * 100 * 10) / 10 : 0,
    };
  },
});

// ── Task 24.3: medianOpenAge ──────────────────────────────────────────────────
export const medianOpenAge = query({
  args: {
    orgId: v.string(),
    dateFrom: v.optional(v.string()),
    dateTo: v.optional(v.string()),
    projectId: v.optional(v.string()),
  },
  handler: async (ctx, { orgId, dateFrom, dateTo, projectId }) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .collect();

    const now = Date.now();
    const openFindings = findings.filter((f) => {
      if (!["Open", "Reviewing", "ToFix"].includes(f.triageState)) return false;
      if (dateFrom && f.createdAt < dateFrom) return false;
      if (dateTo && f.createdAt > dateTo) return false;
      if (projectId && f.projectId !== projectId) return false;
      return true;
    });

    const medianByGroup = (group: typeof openFindings) => {
      if (group.length === 0) return 0;
      const ages = group
        .map((f) => (now - new Date(f.createdAt).getTime()) / (1000 * 60 * 60 * 24))
        .sort((a, b) => a - b);
      const mid = Math.floor(ages.length / 2);
      return ages.length % 2 === 0
        ? Math.round(((ages[mid - 1] + ages[mid]) / 2) * 10) / 10
        : Math.round(ages[mid] * 10) / 10;
    };

    return {
      critical: medianByGroup(openFindings.filter((f) => f.severity === "Critical")),
      high: medianByGroup(openFindings.filter((f) => f.severity === "High")),
      medium: medianByGroup(openFindings.filter((f) => f.severity === "Medium")),
      low: medianByGroup(openFindings.filter((f) => f.severity === "Low")),
    };
  },
});

// ── Task 24.4: fixRate ────────────────────────────────────────────────────────
export const fixRate = query({
  args: {
    orgId: v.string(),
    dateFrom: v.optional(v.string()),
    dateTo: v.optional(v.string()),
    projectId: v.optional(v.string()),
  },
  handler: async (ctx, { orgId, dateFrom, dateTo, projectId }) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .collect();

    const filtered = findings.filter((f) => {
      if (dateFrom && f.createdAt < dateFrom) return false;
      if (dateTo && f.createdAt > dateTo) return false;
      if (projectId && f.projectId !== projectId) return false;
      return true;
    });

    const total = filtered.length;
    const fixed = filtered.filter((f) => f.triageState === "Fixed" || f.triageState === "AutoFixed").length;
    const ignored = filtered.filter((f) => f.triageState === "Ignored" || f.triageState === "AutoIgnored").length;

    return {
      total_detected: total,
      total_fixed: fixed,
      fix_rate_pct: total > 0 ? Math.round((fixed / total) * 100 * 10) / 10 : 0,
      ignore_rate_pct: total > 0 ? Math.round((ignored / total) * 100 * 10) / 10 : 0,
    };
  },
});

// ── Task 24.5: trends with ignored count and net_change ──────────────────────
// (Extended version of existing trends query — added ignored_count and net_change)
export const trendsV2 = query({
  args: {
    orgId: v.string(),
    periods: v.optional(v.number()),
    branchType: v.optional(v.string()), // Task 31.5
    projectId: v.optional(v.string()),
  },
  handler: async (ctx, { orgId, periods = 7, branchType, projectId }) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .collect();

    const now = new Date();
    const result = [];

    for (let i = periods - 1; i >= 0; i--) {
      const dayStart = new Date(now);
      dayStart.setDate(dayStart.getDate() - i);
      dayStart.setHours(0, 0, 0, 0);
      const dayEnd = new Date(dayStart);
      dayEnd.setHours(23, 59, 59, 999);

      const dayFindings = findings.filter((f) => {
        const created = new Date(f.createdAt);
        if (created < dayStart || created > dayEnd) return false;
        if (projectId && f.projectId !== projectId) return false;
        if (branchType === "default") {
          // Filter to primary branch only (simplified: check branch === "main" or "master")
          const branch = (f as any).branch ?? "";
          if (branch && branch !== "main" && branch !== "master") return false;
        }
        return true;
      });

      const newCount = dayFindings.length;
      const fixedCount = dayFindings.filter((f) => f.triageState === "Fixed" || f.triageState === "AutoFixed").length;
      const ignoredCount = dayFindings.filter((f) => f.triageState === "Ignored" || f.triageState === "AutoIgnored").length;
      const netChange = newCount - fixedCount - ignoredCount;

      result.push({
        date: dayStart.toISOString().split("T")[0],
        new_count: newCount,
        fixed_count: fixedCount,
        ignored_count: ignoredCount,
        net_change: netChange,
      });
    }

    return result;
  },
});

// ── Task 24.7: sicario report --dashboard (CLI fetches this) ─────────────────
export const dashboardMetrics = query({
  args: {
    orgId: v.string(),
    dateFrom: v.optional(v.string()),
    dateTo: v.optional(v.string()),
    projectId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // This query aggregates all dashboard metrics for the CLI `sicario report --dashboard` command
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();

    const filtered = findings.filter((f) => {
      if (args.dateFrom && f.createdAt < args.dateFrom) return false;
      if (args.dateTo && f.createdAt > args.dateTo) return false;
      if (args.projectId && f.projectId !== args.projectId) return false;
      return true;
    });

    const open = filtered.filter((f) => ["Open", "Reviewing", "ToFix"].includes(f.triageState)).length;
    const fixed = filtered.filter((f) => ["Fixed", "AutoFixed"].includes(f.triageState)).length;
    const ignored = filtered.filter((f) => ["Ignored", "AutoIgnored"].includes(f.triageState)).length;
    const surfacedInPr = filtered.filter((f) => (f as any).surfacedInPr).length;

    return {
      org_id: args.orgId,
      period: args.dateFrom ? `${args.dateFrom} to ${args.dateTo ?? "now"}` : "all_time",
      backlog_activity: {
        new: filtered.length,
        fixed,
        ignored,
        net_change: filtered.length - fixed - ignored,
      },
      production_backlog: { current_open: open },
      guardrails_adoption: {
        findings_shown_in_pr: surfacedInPr,
        findings_total: filtered.length,
        adoption_rate_pct: filtered.length > 0
          ? Math.round((surfacedInPr / filtered.length) * 100 * 10) / 10 : 0,
      },
    };
  },
});

// ── Task 42.3: backlogActivity — daily new/fixed/ignored counts for the last N days ──
// Called by BacklogActivityChart in OverviewPage.
export const backlogActivity = query({
  args: {
    orgId: v.string(),
    days: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const windowDays = args.days ?? 14;

    // Build a date bucket map for the last `windowDays` days (ISO date strings)
    const now = new Date();
    const buckets: Record<string, { date: string; new: number; fixed: number; ignored: number }> = {};
    for (let i = windowDays - 1; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const key = d.toISOString().slice(0, 10); // "YYYY-MM-DD"
      buckets[key] = { date: key, new: 0, fixed: 0, ignored: 0 };
    }

    const cutoff = new Date(now);
    cutoff.setDate(cutoff.getDate() - windowDays);
    const cutoffStr = cutoff.toISOString();

    // Fetch all findings for this org created or updated within the window
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();

    for (const f of findings) {
      // Count new findings by createdAt date
      if (f.createdAt >= cutoffStr) {
        const day = f.createdAt.slice(0, 10);
        if (buckets[day]) {
          buckets[day].new++;
        }
      }

      // Count fixed findings by updatedAt date
      const isFixed = f.triageState === "Fixed" || f.triageState === "AutoFixed";
      const isIgnored = f.triageState === "Ignored" || f.triageState === "AutoIgnored";

      if ((isFixed || isIgnored) && f.updatedAt >= cutoffStr) {
        const day = f.updatedAt.slice(0, 10);
        if (buckets[day]) {
          if (isFixed) buckets[day].fixed++;
          else buckets[day].ignored++;
        }
      }
    }

    return Object.values(buckets);
  },
});
