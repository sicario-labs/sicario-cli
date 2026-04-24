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
      switch (f.triageState) {
        case "Open": case "Reviewing": case "ToFix": open++; break;
        case "Fixed": fixed++; break;
        case "Ignored": case "AutoIgnored": ignored++; break;
        default: open++; break;
      }
      switch (f.severity) {
        case "Critical": critical++; break;
        case "High": high++; break;
        case "Medium": medium++; break;
        case "Low": low++; break;
        case "Info": info++; break;
      }
    }

    const totalScans = scans.length;
    const avgDuration = totalScans > 0
      ? Math.round(scans.reduce((sum, s) => sum + s.durationMs, 0) / totalScans)
      : 0;

    return {
      total_findings: total,
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
