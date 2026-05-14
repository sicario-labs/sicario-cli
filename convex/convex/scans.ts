import { mutation, query } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";

/**
 * Deterministic deduplication fingerprint: hash(projectId + ruleId + filePath).
 *
 * Line number is intentionally excluded — lines shift as developers edit code,
 * but the same vulnerability in the same file stays the same finding.
 *
 * Uses a simple djb2-style hash since crypto.subtle is not available in mutations.
 */
function dedupFingerprint(projectId: string, ruleId: string, filePath: string): string {
  const input = `${projectId}::${ruleId}::${filePath}`;
  let hash = 5381;
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) + hash) ^ input.charCodeAt(i);
    hash = hash >>> 0; // keep as unsigned 32-bit
  }
  return `dedup:${hash.toString(16).padStart(8, '0')}`;
}

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
      // Task 47.3 / 48.3: new scan metadata
      scanType: meta.scan_type ?? "full",
      scanStatus: meta.scan_status ?? "completed",
      hookInstalled: meta.hook_installed ?? false,
      vulnDbVersion: meta.vuln_db_version ?? undefined,
      customRulesHash: meta.custom_rules_hash ?? undefined,
    });

    // Track fingerprints seen in this scan payload (for auto-resolve)
    const incomingFingerprints = new Set<string>();

    // Upsert each finding by deduplication fingerprint
    for (const f of report.findings ?? []) {
      const ruleId = f.rule_id ?? "";
      const filePath = typeof f.file_path === "string" ? f.file_path : "";
      const severity = typeof f.severity === "string" ? f.severity : (f.severity ?? "Info");

      // Compute dedup fingerprint: hash(projectId + ruleId + filePath)
      const fp = projectId
        ? dedupFingerprint(projectId, ruleId, filePath)
        : (f.fingerprint ?? "");

      incomingFingerprints.add(fp);

      // Check for an existing finding with this dedup fingerprint in this project
      const existing = fp && projectId
        ? await ctx.db
            .query("findings")
            .withIndex("by_fingerprint", (q) => q.eq("fingerprint", fp))
            .filter((q) => q.eq(q.field("projectId"), projectId))
            .first()
        : null;

      if (existing) {
        // Update: refresh location and scan reference; preserve triage state
        await ctx.db.patch(existing._id, {
          scanId,
          line: f.line ?? existing.line,
          column: f.column ?? existing.column,
          snippet: f.snippet ?? existing.snippet,
          severity,
          updatedAt: now,
          // Task 48.3: update new fields
          branch: meta.branch ?? existing.branch,
          commitSha: meta.commit_sha ?? existing.commitSha,
          matchBasedId: f.match_based_id ?? existing.matchBasedId,
          taintPath: f.taint_path ?? existing.taintPath,
          suppressed: f.suppressed ?? existing.suppressed,
          suppressionComment: f.suppression_comment ?? existing.suppressionComment,
          // Re-open if it was previously auto-resolved (Fixed by absence)
          ...(existing.triageState === "AutoFixed"
            ? { triageState: "Open", triageNote: "Re-opened: finding reappeared in latest scan." }
            : {}),
        });
      } else {
        // Insert new finding
        await ctx.db.insert("findings", {
          findingId: f.id ?? "",
          scanId,
          ruleId,
          ruleName: f.rule_name ?? "",
          filePath,
          line: f.line ?? 0,
          column: f.column ?? 0,
          endLine: f.end_line ?? undefined,
          endColumn: f.end_column ?? undefined,
          snippet: f.snippet ?? "",
          severity,
          confidenceScore: f.confidence_score ?? 0,
          reachable: f.reachable ?? false,
          cloudExposed: f.cloud_exposed ?? undefined,
          cweId: f.cwe_id ?? undefined,
          owaspCategory: f.owasp_category ?? undefined,
          fingerprint: fp,
          executionTrace: f.execution_trace ?? undefined,
          orgId,
          projectId,
          triageState: "Open",
          createdAt: now,
          updatedAt: now,
          // Task 47.1 / 48.3: new finding fields
          branch: meta.branch ?? undefined,
          commitSha: meta.commit_sha ?? undefined,
          matchBasedId: f.match_based_id ?? undefined,
          taintPath: f.taint_path ?? undefined,
          suppressed: f.suppressed ?? false,
          suppressionComment: f.suppression_comment ?? undefined,
          committedBy: f.committed_by ?? undefined,
        });
      }
    }

    // Auto-resolve: mark findings that were NOT in this scan as Fixed
    // (only for AST findings — SCA findings have synthetic file paths starting with '<')
    if (projectId && incomingFingerprints.size > 0) {
      const allProjectFindings = await ctx.db
        .query("findings")
        .withIndex("by_projectId", (q) => q.eq("projectId", projectId))
        .collect();

      for (const existing of allProjectFindings) {
        // Skip already-resolved findings and SCA synthetic entries
        if (
          existing.triageState === "Fixed" ||
          existing.triageState === "AutoFixed" ||
          existing.triageState === "Removed" ||
          existing.triageState === "Ignored" ||
          existing.triageState === "AutoIgnored" ||
          existing.filePath.startsWith("<")
        ) {
          continue;
        }
        // If this finding's fingerprint was not in the incoming scan, auto-resolve it
        if (existing.fingerprint && !incomingFingerprints.has(existing.fingerprint)) {
          let resType = "fixed";
          let nextState = "AutoFixed";
          let note = "Auto-resolved: finding was not present in the latest scan.";
          let eventType = "auto_fixed";

          const currentOrgId = existing.orgId ?? orgId;
          if (currentOrgId) {
            const policy = await ctx.db
              .query("policies")
              .withIndex("by_orgId_ruleId", (q) => q.eq("orgId", currentOrgId).eq("ruleId", existing.ruleId))
              .first();
            if (policy && policy.mode === "disabled") {
              resType = "removed";
              nextState = "Removed";
              note = "Auto-resolved: rule was disabled in the organization policy.";
              eventType = "auto_removed";
            }
          }

          await ctx.db.patch(existing._id, {
            triageState: nextState,
            triageNote: note,
            updatedAt: now,
            resolutionType: resType,
          });

          await ctx.db.insert("findingEvents", {
            eventId: `evt-${existing.findingId}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            findingId: existing.findingId,
            orgId: currentOrgId ?? "",
            eventType,
            fromState: existing.triageState,
            toState: nextState,
            timestamp: now,
            resolutionType: resType,
          });
        }
      }
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

    // Task 38.8: trigger first-findings email check after inserting findings
    if (orgId && (report.findings ?? []).length > 0) {
      const findings = report.findings as any[];
      const criticalCount = findings.filter((f: any) => f.severity === "Critical").length;
      const highCount = findings.filter((f: any) => f.severity === "High").length;
      await ctx.scheduler.runAfter(0, internal.emailJobs.triggerFirstFindingsEmail, {
        orgId,
        projectId: projectId ?? undefined,
        findingsCount: findings.length,
        criticalCount,
        highCount,
      });
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
    startDate: v.optional(v.string()),
    endDate: v.optional(v.string()),
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
      if (args.startDate && s.timestamp < args.startDate) return false;
      if (args.endDate && s.timestamp > args.endDate) return false;
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
      project_id: s.projectId ?? null,
    }));

    return { page, per_page: perPage, total, items };
  },
});

// ── Task 70.2: scans.markError ────────────────────────────────────────────────
// Called by the CLI on scan failure before exiting with non-zero code.
// Sets scanStatus to "error" with an error message field.

export const markError = mutation({
  args: {
    scanId: v.string(),
    errorMessage: v.string(),
  },
  handler: async (ctx, args) => {
    const scan = await ctx.db
      .query("scans")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .first();

    if (!scan) {
      // Scan record may not exist yet if the error occurred before insert.
      // Insert a minimal error record so the dashboard can show the failure.
      const now = new Date().toISOString();
      await ctx.db.insert("scans", {
        scanId: args.scanId,
        repository: "",
        branch: "",
        commitSha: "",
        timestamp: now,
        durationMs: 0,
        rulesLoaded: 0,
        filesScanned: 0,
        languageBreakdown: {},
        tags: [],
        createdAt: now,
        scanStatus: "error",
      });
      return;
    }

    await ctx.db.patch(scan._id, {
      scanStatus: "error",
    });
  },
});
