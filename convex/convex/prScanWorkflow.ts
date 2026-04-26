"use node";

import { action } from "./_generated/server";
import { v } from "convex/values";
import { api } from "./_generated/api";
import {
  requireGitHubAppEnv,
  generateAppJwt,
  getInstallationToken,
} from "./githubAppNode";
import {
  scanFiles,
  detectLanguage,
  evaluateThreshold,
  type FileToScan,
  type ScanFinding,
} from "./prSastEngine";
import { PR_SAST_RULES } from "./prSastRules";

// ── Helper: Build Check Run Summary ─────────────────────────────────────────

export function buildCheckRunSummary(
  totalCount: number,
  criticalCount: number,
  highCount: number,
  threshold: string,
): string {
  const result = totalCount > 0 ? "Issues found" : "No issues found";
  return `## Sicario Security Scan Results

| Metric | Count |
|--------|-------|
| Total Findings | ${totalCount} |
| Critical | ${criticalCount} |
| High | ${highCount} |

**Severity Threshold**: ${threshold}
**Result**: ${result}`;
}

// ── Helper: Build Annotations ───────────────────────────────────────────────

export function buildAnnotations(
  findings: ScanFinding[],
  maxCount = 50,
): Array<{
  path: string;
  start_line: number;
  annotation_level: string;
  message: string;
  title: string;
}> {
  const capped = findings.slice(0, maxCount);
  return capped.map((f) => ({
    path: f.filePath,
    start_line: f.line,
    annotation_level: mapSeverityToAnnotationLevel(f.severity),
    message: `${f.ruleName}: ${f.snippet}`,
    title: `[${f.severity}] ${f.ruleName}`,
  }));
}

function mapSeverityToAnnotationLevel(severity: string): string {
  switch (severity) {
    case "Critical":
    case "High":
      return "failure";
    case "Medium":
      return "warning";
    case "Low":
    case "Info":
    default:
      return "notice";
  }
}

// ── Scan Orchestrator Action ────────────────────────────────────────────────

export const runPrScan = action({
  args: {
    checkId: v.string(),
    repositoryUrl: v.string(),
    prNumber: v.number(),
    projectId: v.string(),
    orgId: v.string(),
    installationId: v.string(),
  },
  handler: async (ctx, args) => {
    const timeoutMs = 120_000;
    const deadline = Date.now() + timeoutMs;

    const [owner, repo] = args.repositoryUrl
      .replace("https://github.com/", "")
      .split("/");

    let checkRunId: number | null = null;

    try {
      // Step 1: Update prCheck status to "running"
      await ctx.runMutation(api.prChecks.updatePrCheck, {
        checkId: args.checkId,
        status: "running",
      });

      if (Date.now() > deadline) {
        throw new Error("Scan timed out");
      }

      // Step 2: Acquire installation token
      const env = requireGitHubAppEnv();
      const jwt = generateAppJwt(env.appId, env.privateKey);
      const installationToken = await getInstallationToken(
        jwt,
        args.installationId,
      );

      const headers = {
        Accept: "application/vnd.github+json",
        "User-Agent": "sicario-security-app",
        Authorization: `Bearer ${installationToken}`,
      };

      if (Date.now() > deadline) {
        throw new Error("Scan timed out");
      }

      // Step 3: Create GitHub Check Run (in_progress)
      try {
        const checkRunRes = await fetch(
          `https://api.github.com/repos/${owner}/${repo}/check-runs`,
          {
            method: "POST",
            headers: { ...headers, "Content-Type": "application/json" },
            body: JSON.stringify({
              name: "Sicario Security Scan",
              head_sha: "HEAD",
              status: "in_progress",
            }),
          },
        );
        if (checkRunRes.ok) {
          const checkRunData = await checkRunRes.json();
          checkRunId = checkRunData.id;
        } else {
          console.error(
            `Failed to create Check Run: ${checkRunRes.status} ${await checkRunRes.text()}`,
          );
        }
      } catch (err) {
        console.error("Check Run creation failed:", err);
      }

      if (Date.now() > deadline) {
        throw new Error("Scan timed out");
      }

      // Step 4: Fetch changed files from PR
      const filesRes = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/pulls/${args.prNumber}/files?per_page=300`,
        { method: "GET", headers },
      );

      if (!filesRes.ok) {
        const body = await filesRes.text();
        throw new Error(
          `GitHub PR Files API error (${filesRes.status}): ${body}`,
        );
      }

      const prFiles: Array<{
        filename: string;
        status: string;
        raw_url: string;
      }> = await filesRes.json();

      const changedFiles = prFiles
        .filter((f) => f.status === "added" || f.status === "modified")
        .slice(0, 300);

      if (Date.now() > deadline) {
        throw new Error("Scan timed out");
      }

      // Step 5: Download raw file contents
      const filesToScan: FileToScan[] = [];
      for (const file of changedFiles) {
        if (Date.now() > deadline) {
          throw new Error("Scan timed out");
        }
        try {
          const contentRes = await fetch(file.raw_url, { headers });
          if (!contentRes.ok) {
            console.error(
              `Skipping file ${file.filename}: ${contentRes.status}`,
            );
            continue;
          }
          const content = await contentRes.text();
          const language = detectLanguage(file.filename);
          if (!language) continue;
          filesToScan.push({
            path: file.filename,
            content,
            language,
          });
        } catch (err) {
          console.error(`Skipping file ${file.filename}:`, err);
          continue;
        }
      }

      if (Date.now() > deadline) {
        throw new Error("Scan timed out");
      }

      // Step 6: Run SAST scan
      const report = scanFiles(filesToScan, PR_SAST_RULES, {
        repository: args.repositoryUrl,
        branch: `pr-${args.prNumber}`,
        commitSha: "HEAD",
      });

      if (Date.now() > deadline) {
        throw new Error("Scan timed out");
      }

      // Step 7: Store scan results
      const scanId = crypto.randomUUID();
      await ctx.runMutation(api.scans.insert, {
        scanId,
        report: {
          metadata: {
            repository: report.metadata.repository,
            branch: report.metadata.branch,
            commit_sha: report.metadata.commitSha,
            timestamp: report.metadata.timestamp,
            duration_ms: report.metadata.durationMs,
            rules_loaded: report.metadata.rulesLoaded,
            files_scanned: report.metadata.filesScanned,
            language_breakdown: report.metadata.languageBreakdown,
            tags: report.metadata.tags,
          },
          findings: report.findings.map((f) => ({
            id: crypto.randomUUID(),
            rule_id: f.ruleId,
            rule_name: f.ruleName,
            file_path: f.filePath,
            line: f.line,
            column: f.column,
            snippet: f.snippet,
            severity: f.severity,
            cwe_id: f.cweId,
            owasp_category: f.owaspCategory,
            fingerprint: f.fingerprint,
          })),
        },
        orgId: args.orgId,
        projectId: args.projectId,
      });

      if (Date.now() > deadline) {
        throw new Error("Scan timed out");
      }

      // Step 8: Evaluate threshold
      const project = await ctx.runQuery(api.projects.get, {
        id: args.projectId,
      });
      const threshold = project?.severity_threshold ?? "high";
      // Capitalize first letter to match severity level keys
      const normalizedThreshold =
        threshold.charAt(0).toUpperCase() + threshold.slice(1).toLowerCase();
      const thresholdResult = evaluateThreshold(
        report.findings,
        normalizedThreshold,
      );

      // Step 9: Update prCheck record
      await ctx.runMutation(api.prChecks.updatePrCheck, {
        checkId: args.checkId,
        status: thresholdResult.passed ? "passed" : "failed",
        findingsCount: thresholdResult.totalCount,
        criticalCount: thresholdResult.criticalCount,
        highCount: thresholdResult.highCount,
        githubCheckRunId: checkRunId ? String(checkRunId) : undefined,
        scanId,
      });

      // Step 10: Update GitHub Check Run with conclusion
      if (checkRunId) {
        try {
          const conclusion = thresholdResult.passed ? "success" : "failure";
          const summary = buildCheckRunSummary(
            thresholdResult.totalCount,
            thresholdResult.criticalCount,
            thresholdResult.highCount,
            normalizedThreshold,
          );
          const annotations = buildAnnotations(report.findings, 50);

          await fetch(
            `https://api.github.com/repos/${owner}/${repo}/check-runs/${checkRunId}`,
            {
              method: "PATCH",
              headers: { ...headers, "Content-Type": "application/json" },
              body: JSON.stringify({
                status: "completed",
                conclusion,
                output: {
                  title: "Sicario Security Scan",
                  summary,
                  annotations,
                },
              }),
            },
          );
        } catch (err) {
          console.error("Failed to update Check Run:", err);
        }
      }
    } catch (error) {
      // On any error, update prCheck to "failed"
      try {
        await ctx.runMutation(api.prChecks.updatePrCheck, {
          checkId: args.checkId,
          status: "failed",
          githubCheckRunId: checkRunId ? String(checkRunId) : undefined,
        });
      } catch (updateErr) {
        console.error("Failed to update prCheck on error:", updateErr);
      }
      console.error("PR scan workflow failed:", error);
    }
  },
});
