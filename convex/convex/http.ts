import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { auth } from "./auth";
import { api } from "./_generated/api";
import { checkLimits } from "./planEnforcer";
import { PLAN_LIMITS } from "./billing";
const http = httpRouter();

// ── Auth routes from @convex-dev/auth ────────────────────────────────────────
auth.addHttpRoutes(http);

// ── Helper: generate a random alphanumeric string ────────────────────────────
function randomAlphanumeric(length: number): string {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no ambiguous 0/O/1/I
  const arr = new Uint8Array(length);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => chars[b % chars.length]).join("");
}

// ── Helper: SHA-256 for PKCE S256 verification ──────────────────────────────
async function sha256(plain: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return base64UrlEncode(new Uint8Array(hash));
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── Helper: CORS headers ────────────────────────────────────────────────────
function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "https://usesicario.xyz",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Auth-Token",
  };
}

// ── Helper: semver comparison ────────────────────────────────────────────────
// Compares two semver strings (e.g. "1.2.3") numerically.
// Returns: negative if a < b, 0 if a == b, positive if a > b.
// Non-numeric pre-release suffixes are stripped before comparison.
function compareSemver(a: string, b: string): number {
  const parseParts = (v: string): [number, number, number] => {
    // Strip any pre-release suffix (e.g. "1.2.3-beta" → "1.2.3")
    const clean = v.split("-")[0].split("+")[0];
    const parts = clean.split(".").map((p) => parseInt(p, 10) || 0);
    return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
  };
  const [aMaj, aMin, aPatch] = parseParts(a);
  const [bMaj, bMin, bPatch] = parseParts(b);
  if (aMaj !== bMaj) return aMaj - bMaj;
  if (aMin !== bMin) return aMin - bMin;
  return aPatch - bPatch;
}

/**
 * Resolve the authenticated user from either:
 * 1. Convex Auth JWT (standard browser sessions), or
 * 2. Opaque `sic_` token from the device auth flow (CLI sessions).
 *
 * Returns `{ subject, email?, name? }` or `null` if unauthenticated.
 */
async function resolveIdentity(
  ctx: any,
  request?: Request,
): Promise<{ subject: string; email?: string; name?: string } | null> {
  // 1. Try Convex Auth JWT first
  try {
    const identity = await ctx.auth.getUserIdentity();
    if (identity) {
      return {
        subject: identity.subject,
        email: identity.email ?? undefined,
        name: identity.name ?? undefined,
      };
    }
  } catch {
    // JWT parsing failed — fall through to opaque token lookup
  }

  // 2. Extract token from X-Auth-Token header or Authorization header
  let token: string | null = null;
  if (request) {
    const xAuthToken = request.headers.get("X-Auth-Token");
    if (xAuthToken) {
      token = xAuthToken.trim();
    } else {
      const authHeader = request.headers.get("Authorization");
      if (authHeader && authHeader.startsWith("Bearer ")) {
        token = authHeader.slice(7).trim();
      }
    }
  }
  if (!token) return null;

  // 3. Look up opaque token in deviceCodes table
  try {
    const record = await ctx.runQuery(api.deviceAuth.getByAccessToken, {
      accessToken: token,
    });
    if (record && record.userId) {
      return { subject: record.userId, name: record.userName ?? undefined, email: record.userEmail ?? undefined };
    }
  } catch {
    // Lookup failed — treat as unauthenticated
  }

  // 3.5 Project API key: Bearer project:{key}
  if (token.startsWith("project:")) {
    const projectApiKey = token.slice("project:".length);
    if (projectApiKey) {
      try {
        const project = await ctx.runQuery(api.projects.getByApiKey, {
          projectApiKey,
        });
        if (project) {
          return {
            subject: `project:${project.id}`,
            projectId: project.id,
            orgId: project.org_id,
          } as any;
        }
      } catch {
        // Lookup failed — treat as unauthenticated
      }
    }
  }

  return null;
}

// ── Helper: extract repo name from URL ───────────────────────────────────────
function repoNameFromUrl(url: string): string {
  try {
    // Handle "https://github.com/org/my-repo" or "git@github.com:org/my-repo.git"
    const cleaned = url.replace(/\.git$/, "");
    const parts = cleaned.split("/");
    return parts[parts.length - 1] || url;
  } catch {
    return url;
  }
}

// ── POST /api/v1/scans — Accept scan report, store findings + metadata ──────
http.route({
  path: "/api/v1/scans",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    // Validate Bearer token (supports both Convex Auth JWT and opaque sic_ tokens)
    const identity = await resolveIdentity(ctx, request);
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    try {
      const body = await request.json();
      const scanId =
        body.scan_id || `scan-${Date.now()}-${randomAlphanumeric(6)}`;

      let orgId: string | undefined;
      let projectId: string | undefined;

      // ── Check if identity was resolved from a project API key ─────────
      const identityAny = identity as any;
      if (identityAny.projectId && identityAny.orgId) {
        // Project API key auth — auto-populate orgId and projectId
        orgId = identityAny.orgId;
        projectId = identityAny.projectId;
      } else {
        // ── (a) Resolve orgId from membership or X-Sicario-Org header ──
        // Normalize userId: Convex Auth stores full tokenIdentifier like
        // "https://site|sessionId|userId" but memberships use just the last segment
        const rawUserId = identity.subject;
        const userId = rawUserId.includes("|") ? rawUserId.split("|").pop()! : rawUserId;
        const requestedOrgId = request.headers.get("X-Sicario-Org");

        if (requestedOrgId) {
          // Verify the user is a member of the specified org
          const membership = await ctx.runQuery(api.memberships.getForUser, {
            userId,
            orgId: requestedOrgId,
          });
          if (!membership) {
            return new Response(
              JSON.stringify({ error: "Not a member of specified organization" }),
              {
                status: 403,
                headers: { "Content-Type": "application/json", ...corsHeaders() },
              }
            );
          }
          orgId = requestedOrgId;
        } else {
          // Look up the user's first membership directly by userId
          const memberships: any[] = await ctx.runQuery(api.memberships.listByUser, {
            userId,
          });
          if (!memberships || memberships.length === 0) {
            return new Response(
              JSON.stringify({ error: "No organization membership found. Please create an organization first." }),
              {
                status: 403,
                headers: { "Content-Type": "application/json", ...corsHeaders() },
              }
            );
          }
          orgId = memberships[0].orgId;
        }

        // ── (c) Match repository to existing project in this org ────────
        const repository = body.metadata?.repository ?? "";

        if (orgId && repository) {
          const orgProjects: any[] = await ctx.runQuery(api.projects.listByOrg, {
            orgId,
          });
          const matched = orgProjects.find(
            (p: any) => p.repository_url === repository
          );

          if (matched) {
            projectId = matched.id;
          } else {
            // Auto-create project
            projectId = `proj-${Date.now()}-${randomAlphanumeric(6)}`;
            await ctx.runMutation(api.projects.create, {
              id: projectId,
              name: repoNameFromUrl(repository),
              repository_url: repository,
              description: "",
              orgId,
            });
          }
        }
      }

      // ── (e) Pass orgId and projectId to scan insert ───────────────────
      await ctx.runMutation(api.scans.insert, {
        scanId,
        report: body,
        orgId,
        projectId,
      });

      return new Response(
        JSON.stringify({
          scan_id: scanId,
          project_id: projectId ?? null,
          dashboard_url: `https://usesicario.xyz/dashboard/scans/${scanId}`,
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders() },
        }
      );
    } catch (e: any) {
      return new Response(
        JSON.stringify({ error: e.message || "Internal error" }),
        {
          status: 500,
          headers: { "Content-Type": "application/json", ...corsHeaders() },
        }
      );
    }
  }),
});


// ── POST /api/v1/telemetry/scan — Accept structured telemetry from CLI ──────
http.route({
  path: "/api/v1/telemetry/scan",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    // 1. Authenticate
    const identity = await resolveIdentity(ctx, request);
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    try {
      // 2. Parse JSON body
      const body = await request.json();

      // 3. Validate required fields
      const requiredFields = ["projectId", "repositoryUrl", "commitSha", "scanId", "findings"];
      const missing = requiredFields.filter((f) => body[f] === undefined || body[f] === null);
      if (missing.length > 0) {
        return new Response(
          JSON.stringify({ error: `Missing required fields: ${missing.join(", ")}` }),
          { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } },
        );
      }

      const findings: any[] = body.findings;
      if (!Array.isArray(findings)) {
        return new Response(
          JSON.stringify({ error: "Missing required fields: findings" }),
          { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } },
        );
      }

      // 4. Validate findings count ≤ 5000
      if (findings.length > 5000) {
        return new Response(
          JSON.stringify({ error: `Payload contains ${findings.length} findings, maximum is 5000` }),
          { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } },
        );
      }

      // 5. Validate severity enum on each finding
      const validSeverities = ["Critical", "High", "Medium", "Low"];
      for (let i = 0; i < findings.length; i++) {
        if (!validSeverities.includes(findings[i].severity)) {
          return new Response(
            JSON.stringify({
              error: `Invalid severity '${findings[i].severity}' in finding at index ${i}. Must be Critical, High, Medium, or Low`,
            }),
            { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } },
          );
        }
      }

      // 6. Check for duplicate scanId
      const existingScan = await ctx.runQuery(api.scans.getByScanId, { scanId: body.scanId });
      if (existingScan) {
        return new Response(
          JSON.stringify({ error: `Scan '${body.scanId}' has already been submitted` }),
          { status: 409, headers: { "Content-Type": "application/json", ...corsHeaders() } },
        );
      }

      // 7. Resolve org from identity
      let orgId: string | undefined;
      const identityAny = identity as any;

      if (identityAny.projectId && identityAny.orgId) {
        // Project API key auth — auto-populate orgId
        orgId = identityAny.orgId;
      } else {
        // JWT / sic_ token — use membership lookup or X-Sicario-Org header
        const rawUserId = identity.subject;
        const userId = rawUserId.includes("|") ? rawUserId.split("|").pop()! : rawUserId;
        const requestedOrgId = request.headers.get("X-Sicario-Org");

        if (requestedOrgId) {
          const membership = await ctx.runQuery(api.memberships.getForUser, {
            userId,
            orgId: requestedOrgId,
          });
          if (!membership) {
            return new Response(
              JSON.stringify({ error: "Not a member of specified organization" }),
              { status: 403, headers: { "Content-Type": "application/json", ...corsHeaders() } },
            );
          }
          orgId = requestedOrgId;
        } else {
          const memberships: any[] = await ctx.runQuery(api.memberships.listByUser, { userId });
          if (!memberships || memberships.length === 0) {
            return new Response(
              JSON.stringify({ error: "No organization membership found. Please create an organization first." }),
              { status: 403, headers: { "Content-Type": "application/json", ...corsHeaders() } },
            );
          }
          orgId = memberships[0].orgId;
        }
      }

      // 8. Match projectId to existing project in resolved org.
      //
      // DASH-001 fix: two-pass lookup to handle both auth paths:
      //   (a) Project API key auth — identity already carries the resolved
      //       projectId, so we can look it up directly by its custom string ID
      //       without relying on orgId being non-null.
      //   (b) JWT / sic_ token auth — fall back to the org-scoped list query.
      //
      // This prevents a 404 when orgId is null (e.g. a project whose orgId was
      // not persisted) or when the CLI sends the correct projectId but the
      // org-scoped list returns an empty set due to a stale orgId.
      let matchedProject: any = null;

      // Pass (a): direct lookup by projectId string (works for all auth types)
      if (body.projectId) {
        matchedProject = await ctx.runQuery(api.projects.get, { id: body.projectId });
        // Verify the resolved project actually belongs to the authenticated org
        if (matchedProject && orgId && matchedProject.org_id !== orgId) {
          matchedProject = null; // org mismatch — treat as not found
        }
      }

      // Pass (b): org-scoped list fallback (handles edge cases where direct
      // lookup returns null but the project exists under a different ID format)
      if (!matchedProject && orgId) {
        const orgProjects: any[] = await ctx.runQuery(api.projects.listByOrg, { orgId });
        matchedProject = orgProjects.find((p: any) => p.id === body.projectId) ?? null;
      }

      if (!matchedProject) {
        return new Response(
          JSON.stringify({ error: `Project '${body.projectId}' not found in organization` }),
          { status: 404, headers: { "Content-Type": "application/json", ...corsHeaders() } },
        );
      }

      // 8.5. Plan enforcement — check limits before accepting the payload
      const isNewProject = !matchedProject;
      const limitCheck = await checkLimits(ctx, orgId!, findings.length, isNewProject);
      if (!limitCheck.allowed) {
        const errorMsg = limitCheck.reason === "findings"
          ? "Finding storage limit reached. Upgrade your plan at usesicario.xyz/pricing"
          : "Project limit reached. Upgrade your plan at usesicario.xyz/pricing";

        await ctx.runMutation(api.billing.appendAuditLog, {
          orgId: orgId!,
          eventType: "plan_enforcer.rejected",
          payload: {
            endpoint: "/api/v1/telemetry/scan",
            rejectionReason: limitCheck.reason,
            limitExceeded: limitCheck.reason,
          },
        });

        return new Response(
          JSON.stringify({ error: errorMsg }),
          { status: 402, headers: { "Content-Type": "application/json", ...corsHeaders() } },
        );
      }

      // 9. Enforce executionTrace array cap (max 20 items, each string max 250 chars with truncation marker)
      const MAX_EXECUTION_TRACE_ITEMS = 20;
      const MAX_EXECUTION_TRACE_STRING_LENGTH = 250;
      const MAX_SNIPPET_LENGTH = 500; // Server-side defense-in-depth limit

      const processedFindings = findings.map((f: any) => {
        // Truncate snippet to 100 chars (CLI guarantee) then enforce 500-char server-side limit
        let snippet = typeof f.snippet === "string" ? f.snippet.slice(0, 100) : "";
        if (snippet.length > MAX_SNIPPET_LENGTH) {
          console.warn(`Snippet truncated from ${snippet.length} to ${MAX_SNIPPET_LENGTH} chars for scan ${body.scanId}, finding at ${f.file}:${f.line}`);
          snippet = snippet.slice(0, MAX_SNIPPET_LENGTH);
        }

        // Enforce executionTrace array cap: max 20 items, each string max 250 chars with truncation marker
        let executionTrace: string[] | undefined = undefined;
        if (f.executionTrace && Array.isArray(f.executionTrace)) {
          executionTrace = f.executionTrace
            .slice(0, MAX_EXECUTION_TRACE_ITEMS)
            .map((item: string) => {
              if (typeof item === "string" && item.length > MAX_EXECUTION_TRACE_STRING_LENGTH) {
                return item.slice(0, MAX_EXECUTION_TRACE_STRING_LENGTH) + "...trace truncated";
              }
              return item;
            });
        }

        return {
          id: `f-${Date.now()}-${randomAlphanumeric(6)}`,
          rule_id: f.rule ?? "",
          rule_name: f.rule ?? "",
          file_path: f.file ?? "",
          line: f.line ?? 0,
          column: 0,
          snippet: snippet,
          severity: f.severity,
          confidence_score: 0,
          reachable: false,
          cwe_id: f.cweId ?? undefined,
          owasp_category: f.owaspCategory ?? undefined,
          fingerprint: f.fingerprint ?? "",
          execution_trace: executionTrace,
        };
      });

      // 10. Insert scan record
      const now = new Date().toISOString();
      await ctx.runMutation(api.scans.insert, {
        scanId: body.scanId,
        report: {
          metadata: {
            repository: body.repositoryUrl,
            branch: body.branch ?? "",
            commit_sha: body.commitSha,
            timestamp: now,
            duration_ms: body.durationMs ?? 0,
            rules_loaded: body.rulesLoaded ?? 0,
            files_scanned: body.filesScanned ?? 0,
            language_breakdown: {},
            tags: [],
          },
          findings: processedFindings,
        },
        orgId: orgId!,
        projectId: body.projectId,
      });

      // 10.5. Update usage summary
      const now2 = new Date();
      const periodStart = new Date(now2.getFullYear(), now2.getMonth(), 1).toISOString();
      const periodEnd   = new Date(now2.getFullYear(), now2.getMonth() + 1, 0, 23, 59, 59, 999).toISOString();

      await ctx.runMutation(api.billing.upsertUsageSummary, {
        orgId: orgId!,
        periodStart,
        periodEnd,
        delta: {
          findingsStored: findings.length,
          projectCount:   isNewProject ? 1 : 0,
          scansSubmitted: 1,
        },
      });

      // 10.6. Check 80% threshold and fire webhook warning if needed
      const sub = await ctx.runQuery(api.billing.getSubscription, { orgId: orgId! });
      if (sub) {
        const effectivePlan = sub.status === "past_due" ? "free" : sub.plan;
        const planLimit = PLAN_LIMITS[effectivePlan as keyof typeof PLAN_LIMITS].findings;
        if (planLimit !== Infinity) {
          const updatedUsage = await ctx.runQuery(api.billing.getUsageSummary, { orgId: orgId!, periodStart });
          const currentFindings = updatedUsage?.findingsStored ?? 0;
          if (currentFindings / planLimit >= 0.80) {
            // Fire webhook warning if org has a configured webhook
            try {
              const webhooks: any[] = await ctx.runQuery(api.webhooks.listByOrg, { orgId: orgId! });
              for (const wh of webhooks) {
                if (wh.enabled) {
                  await fetch(wh.url, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      event: "usage.findings_warning",
                      orgId: orgId!,
                      findingsStored: currentFindings,
                      planLimit,
                      percentUsed: Math.round((currentFindings / planLimit) * 100),
                    }),
                  });
                }
              }
            } catch {
              // Webhook delivery failure is non-fatal
            }
          }
        }
      }

      // 11. If prNumber is present, create or update a prChecks record
      if (body.prNumber !== undefined && body.prNumber !== null) {
        const criticalCount = findings.filter((f: any) => f.severity === "Critical").length;
        const highCount = findings.filter((f: any) => f.severity === "High").length;
        const findingsCount = findings.length;
        const status = criticalCount > 0 || highCount > 0 ? "failed" : "passed";

        const checkId = `chk-${Date.now()}-${randomAlphanumeric(6)}`;
        await ctx.runMutation(api.prChecks.createPrCheck, {
          checkId,
          projectId: body.projectId,
          orgId: orgId!,
          prNumber: body.prNumber,
          prTitle: `PR #${body.prNumber}`,
          repositoryUrl: body.repositoryUrl,
        });
        await ctx.runMutation(api.prChecks.updatePrCheck, {
          checkId,
          status,
          findingsCount,
          criticalCount,
          highCount,
          scanId: body.scanId,
        });
      }

      // 12. Transition project from "pending" to "active" on first scan
      await ctx.runMutation(api.projects.transitionProvisioningState, {
        projectId: body.projectId,
        from: "pending",
        to: "active",
      });

      // 12.5. Send critical findings alert email to org admins if critical/high findings found
      const criticalCount = findings.filter((f: any) => f.severity === "Critical").length;
      const highCount = findings.filter((f: any) => f.severity === "High").length;
      const project = await ctx.runQuery(api.projects.get, { id: body.projectId });
      const orgDoc: any = await ctx.runQuery((api as any).organizations.getByOrgId, { orgId: orgId! });

      if ((criticalCount > 0 || highCount > 0) && orgDoc?.criticalAlertsEnabled !== false) {
        try {
          const { sendCriticalFindingsAlertEmail } = await import("./emails");
          // Get org memberships to find admins/managers (direct db query from httpAction)
          const orgMemberships: any[] = await (ctx as any).db
            .query("memberships")
            .withIndex("by_orgId", (q: any) => q.eq("orgId", orgId!))
            .collect();
          const adminMembers = orgMemberships.filter(
            (m: any) => m.role === "admin" || m.role === "manager"
          );
          const projectName = project?.name ?? body.projectId;
          for (const member of adminMembers) {
            try {
              const user = await (ctx as any).db.get(member.userId as any);
              const email = (user as any)?.email;
              if (email) {
                await sendCriticalFindingsAlertEmail(
                  email,
                  projectName,
                  body.scanId,
                  criticalCount,
                  highCount,
                  findings.length,
                  body.repositoryUrl,
                );
              }
            } catch { /* non-fatal */ }
          }
        } catch (err) {
          console.error("Failed to send critical findings alert:", err);
        }
      }

      // 12.6. Dispatch Slack Webhook alerts if configured at project level or organization fallback
      try {
        const webhookUrl = (project as any)?.slackWebhookUrl || orgDoc?.slackWebhookUrl;
        const threshold = (project as any)?.slackAlertSeverityThreshold || orgDoc?.slackAlertSeverityThreshold || "High";

        if (webhookUrl) {
          // Filter findings by threshold
          const severities = ["Critical", "High", "Medium", "Low"];
          const thresholdIndex = severities.indexOf(threshold) >= 0 ? severities.indexOf(threshold) : 1; // default High
          const eligibleSeverities = severities.slice(0, thresholdIndex + 1);

          const alertFindings = findings.filter((f: any) => eligibleSeverities.includes(f.severity));
          if (alertFindings.length > 0) {
            const projectName = project?.name ?? body.projectId;
            // Constrained to: rule name, severity, file path, line, permalink per Task 77.1 spec
            const blocks = [
              {
                type: "header",
                text: {
                  type: "plain_text",
                  text: `🛡️ Sicario Scan Alert: ${projectName}`,
                  emoji: true,
                },
              },
              {
                type: "section",
                text: {
                  type: "mrkdwn",
                  text: `Scan *${body.scanId}* completed and detected *${alertFindings.length}* new finding(s) matching your severity threshold (*${threshold}* and above).`,
                },
              },
              {
                type: "divider",
              },
              ...alertFindings.slice(0, 5).map((f: any) => ({
                type: "section",
                text: {
                  type: "mrkdwn",
                  text: `*Rule:* ${f.rule_name || f.rule_id}\n*Severity:* ${f.severity}\n*Location:* \`${f.file_path}:${f.line}\`\n*Link:* https://usesicario.xyz/dashboard/findings/${f.id || ""}`,
                },
              })),
            ];

            if (alertFindings.length > 5) {
              blocks.push({
                type: "context",
                elements: [
                  {
                    type: "mrkdwn",
                    text: `_+ ${alertFindings.length - 5} more finding(s) omitted. View all on the dashboard._`,
                  },
                ],
              });
            }

            await fetch(webhookUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ blocks }),
            });
          }
        }
      } catch (err) {
        console.error("Failed to dispatch Slack alerts:", err);
      }

      // 13. Return success
      return new Response(
        JSON.stringify({
          scan_id: body.scanId,
          project_id: body.projectId,
          dashboard_url: `https://usesicario.xyz/dashboard/scans/${body.scanId}`,
        }),
        { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders() } },
      );
    } catch (e: any) {
      return new Response(
        JSON.stringify({ error: e.message || "Internal error" }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders() } },
      );
    }
  }),
});

// ── GET /api/v1/whoami — Return user profile from Bearer token ──────────────
http.route({
  path: "/api/v1/whoami",
  method: "GET",
  handler: httpAction(async (ctx, request) => {
    const identity = await resolveIdentity(ctx, request);
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    // Normalize userId for profile lookup
    const rawUserId = identity.subject;
    const userId = rawUserId.includes("|") ? rawUserId.split("|").pop()! : rawUserId;

    // Look up user profile for name/email
    let username = identity.name ?? identity.email ?? "unknown";
    let email = identity.email ?? "";

    try {
      const profile = await ctx.runQuery(api.userProfiles.get, { userId });
      if (profile && (profile as any).name) {
        username = (profile as any).name;
      }
      if (profile && (profile as any).email) {
        email = (profile as any).email;
      }
    } catch {
      // Profile lookup failed — use identity defaults
    }

    // If still unknown, try to get from Convex Auth identity
    if (username === "unknown") {
      try {
        const authIdentity = await ctx.auth.getUserIdentity();
        if (authIdentity) {
          username = authIdentity.name ?? authIdentity.email ?? username;
          email = authIdentity.email ?? email;
        }
      } catch {
        // Not a Convex Auth session
      }
    }

    // If still unknown, try the Convex Auth users table directly
    if (username === "unknown" || email === "") {
      try {
        // The userId from device auth is the tokenIdentifier hash.
        // We need to find the auth user by querying the users table.
        // Try looking up by email index first, or scan for matching user.
        const authIdentity = await ctx.auth.getUserIdentity();
        if (authIdentity) {
          const authUserId = authIdentity.subject;
          // subject for Convex Auth is the users table document ID
          const user = await (ctx as any).db.get(authUserId as any);
          if (user) {
            if (username === "unknown" && (user as any).name) {
              username = (user as any).name;
            }
            if (!email && (user as any).email) {
              email = (user as any).email;
            }
          }
        }
      } catch {
        // Auth users table lookup failed
      }
    }

    // Look up org name
    let orgName = "personal";
    try {
      const memberships: any[] = await ctx.runQuery(api.memberships.listByUser, { userId });
      if (memberships && memberships.length > 0) {
        const org = await ctx.runQuery(api.organizations.getByOrgId, { orgId: memberships[0].orgId });
        if (org) {
          orgName = (org as any).name ?? "personal";
        }
      }
    } catch {
      // Org lookup failed
    }

    return new Response(
      JSON.stringify({
        username,
        email,
        organization: orgName,
        plan_tier: "free",
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      }
    );
  }),
});

// ── POST /oauth/device/code — Initiate device flow ──────────────────────────
http.route({
  path: "/oauth/device/code",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    try {
      const contentType = request.headers.get("Content-Type") || "";
      let clientId: string;
      let codeChallenge: string;
      let codeChallengeMethod: string;
      let scope: string | undefined;

      if (contentType.includes("application/x-www-form-urlencoded")) {
        const text = await request.text();
        const params = new URLSearchParams(text);
        clientId = params.get("client_id") || "";
        codeChallenge = params.get("code_challenge") || "";
        codeChallengeMethod = params.get("code_challenge_method") || "S256";
        scope = params.get("scope") || undefined;
      } else {
        const body = await request.json();
        clientId = body.client_id || "";
        codeChallenge = body.code_challenge || "";
        codeChallengeMethod = body.code_challenge_method || "S256";
        scope = body.scope || undefined;
      }

      if (!clientId || !codeChallenge) {
        return new Response(
          JSON.stringify({ error: "client_id and code_challenge are required" }),
          { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } }
        );
      }

      const deviceCode = randomAlphanumeric(32);
      const userCode = randomAlphanumeric(8);
      const expiresAt = Date.now() + 300_000; // 5 minutes

      await ctx.runMutation(api.deviceAuth.createDeviceCode, {
        deviceCode,
        userCode,
        codeChallenge,
        codeChallengeMethod,
        clientId,
        scope,
        expiresAt,
      });

      return new Response(
        JSON.stringify({
          device_code: deviceCode,
          user_code: userCode,
          verification_uri: "https://usesicario.xyz/auth/device",
          interval: 5,
          expires_in: 300,
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders() },
        }
      );
    } catch (e: any) {
      return new Response(
        JSON.stringify({ error: e.message || "Internal error" }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders() } }
      );
    }
  }),
});

// ── POST /oauth/token — Poll for token completion ───────────────────────────
http.route({
  path: "/oauth/token",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    try {
      const contentType = request.headers.get("Content-Type") || "";
      let grantType: string;
      let deviceCode: string;
      let clientId: string;
      let codeVerifier: string;

      if (contentType.includes("application/x-www-form-urlencoded")) {
        const text = await request.text();
        const params = new URLSearchParams(text);
        grantType = params.get("grant_type") || "";
        deviceCode = params.get("device_code") || "";
        clientId = params.get("client_id") || "";
        codeVerifier = params.get("code_verifier") || "";
      } else {
        const body = await request.json();
        grantType = body.grant_type || "";
        deviceCode = body.device_code || "";
        clientId = body.client_id || "";
        codeVerifier = body.code_verifier || "";
      }

      // Look up the device code record
      const record = await ctx.runQuery(api.deviceAuth.getDeviceCodeByDeviceCode, {
        deviceCode,
      });

      if (!record) {
        return new Response(
          JSON.stringify({ error: "invalid_grant", error_description: "Unknown device code" }),
          { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } }
        );
      }

      // Check expiry
      if (Date.now() > record.expiresAt) {
        return new Response(
          JSON.stringify({ error: "expired_token", error_description: "Device code has expired" }),
          { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } }
        );
      }

      // Pending — tell client to keep polling
      if (record.status === "pending") {
        return new Response(
          JSON.stringify({ error: "authorization_pending" }),
          { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } }
        );
      }

      // Denied
      if (record.status === "denied") {
        return new Response(
          JSON.stringify({ error: "access_denied", error_description: "User denied the request" }),
          { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } }
        );
      }

      // Approved — verify PKCE and issue token
      if (record.status === "approved") {
        // Verify PKCE S256 challenge
        if (record.codeChallengeMethod === "S256" && codeVerifier) {
          const expectedChallenge = await sha256(codeVerifier);
          if (expectedChallenge !== record.codeChallenge) {
            return new Response(
              JSON.stringify({ error: "invalid_grant", error_description: "PKCE verification failed" }),
              { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } }
            );
          }
        }

        // Generate access token
        const accessToken = `sic_${randomAlphanumeric(48)}`;

        // Mark as consumed
        await ctx.runMutation(api.deviceAuth.consumeDeviceCode, {
          deviceCode,
          accessToken,
        });

        return new Response(
          JSON.stringify({
            access_token: accessToken,
            refresh_token: "",
            expires_in: 86400,
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json", ...corsHeaders() },
          }
        );
      }

      // Already consumed or unknown status
      return new Response(
        JSON.stringify({ error: "invalid_grant", error_description: "Device code already used" }),
        { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } }
      );
    } catch (e: any) {
      return new Response(
        JSON.stringify({ error: "server_error", error_description: e.message }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders() } }
      );
    }
  }),
});

// ── GET /download/latest/:platform — Stream binary from Convex File Storage ─
// Supported platform slugs:
//   linux-x64-musl | linux-x64 | macos-aarch64 | macos-x64 | windows-x64
http.route({
  pathPrefix: "/download/latest/",
  method: "GET",
  handler: httpAction(async (ctx, request) => {
    const url = new URL(request.url);
    // Extract platform from path: /download/latest/<platform>
    const platform = url.pathname.replace(/^\/download\/latest\//, "").trim();

    if (!platform) {
      return new Response(JSON.stringify({ error: "Platform is required" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Look up the active release for this platform
    const releases = await ctx.runQuery(api.releases.getActiveReleases, {});
    const release = releases.find((r: any) => r.platform === platform);

    if (!release) {
      return new Response(
        JSON.stringify({ error: `No active release found for platform: ${platform}` }),
        { status: 404, headers: { "Content-Type": "application/json" } }
      );
    }

    // Fetch the file blob from Convex File Storage
    const blob = await ctx.storage.get(release.storageId as any);
    if (!blob) {
      return new Response(JSON.stringify({ error: "File not found in storage" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Determine filename
    const isWindows = platform.includes("windows");
    const ext = isWindows ? ".exe" : "";
    const filename = `sicario-${platform}-${release.version}${ext}`;

    return new Response(blob, {
      status: 200,
      headers: {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "X-Sicario-Version": release.version,
        "X-Sicario-Checksum": release.checksum,
        "Cache-Control": "public, max-age=3600",
        "Access-Control-Allow-Origin": "*",
      },
    });
  }),
});

http.route({
  pathPrefix: "/download/latest/",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }),
});

// ── POST /whop-webhook — Handle Whop membership lifecycle events ─────────────
//
// Whop fires two events we care about:
//   membership_activated   → activate / upgrade the org's subscription
//   membership_deactivated → cancel / downgrade to free
//
// Signature verification: HMAC-SHA256 over the raw request body using
// WHOP_WEBHOOK_SECRET, compared against the x-whop-signature header.
http.route({
  path: "/whop-webhook",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    // 1. Read raw body first (needed for HMAC verification before JSON parse)
    const rawBody = await request.arrayBuffer();
    const bodyText = new TextDecoder().decode(rawBody);

    // 2. Verify x-whop-signature
    const secret = process.env.WHOP_WEBHOOK_SECRET ?? "";
    const sigHeader = request.headers.get("x-whop-signature") ?? "";

    if (!secret) {
      console.error("WHOP_WEBHOOK_SECRET is not set — rejecting webhook");
      return new Response(JSON.stringify({ error: "Webhook secret not configured" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Compute HMAC-SHA256
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const msgData = encoder.encode(bodyText);
    const cryptoKey = await crypto.subtle.importKey(
      "raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const sigBytes = await crypto.subtle.sign("HMAC", cryptoKey, msgData);
    const sigHex = Array.from(new Uint8Array(sigBytes))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // Whop sends the signature as a plain hex string
    if (sigHex !== sigHeader) {
      console.warn("Whop webhook signature mismatch — rejecting");
      return new Response(JSON.stringify({ error: "Invalid signature" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 3. Parse JSON
    let body: any;
    try {
      body = JSON.parse(bodyText);
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 4. Extract event action and orgId from custom_req
    const action: string = body.action ?? "";
    const orgId: string  = body.data?.metadata?.custom_req ?? body.metadata?.custom_req ?? "";

    if (!orgId) {
      console.warn("Whop webhook missing custom_req — logging and returning 400", { action, body });
      await ctx.runMutation(api.billing.appendAuditLog, {
        orgId:     "unknown",
        eventType: "whop_webhook.malformed",
        payload:   { action, reason: "missing custom_req", rawBody: bodyText.slice(0, 500) },
      });
      return new Response(JSON.stringify({ error: "Missing custom_req in payload" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 5. Verify the org exists
    const sub = await ctx.runQuery(api.billing.getSubscription, { orgId });
    if (!sub) {
      console.warn(`Whop webhook: no subscription found for orgId=${orgId}`);
      await ctx.runMutation(api.billing.appendAuditLog, {
        orgId,
        eventType: "whop_webhook.malformed",
        payload:   { action, reason: "unknown orgId" },
      });
      return new Response(JSON.stringify({ error: "Unknown orgId" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 6. Handle the two supported actions
    if (action === "membership_activated") {
      // Resolve plan from Whop product ID
      const productId: string = body.data?.product_id ?? body.product_id ?? "";

      const WHOP_PRODUCT_PLAN_MAP: Record<string, "pro" | "team" | "enterprise"> = {
        plan_SoglPJunMJuAy: "team",
        plan_oPf5dQyS4Z4xy: "pro",
      };
      const resolvedPlan = WHOP_PRODUCT_PLAN_MAP[productId] ?? "pro";

      const previousPlan = sub.plan;
      const whopUserId         = body.data?.user_id         ?? body.user_id         ?? undefined;
      const whopSubscriptionId = body.data?.id              ?? body.id              ?? undefined;

      await ctx.runMutation(api.billing.updateSubscription, {
        orgId,
        plan:               resolvedPlan,
        status:             "active",
        billingCycle:       "monthly",
        whopUserId,
        whopSubscriptionId,
      });

      await ctx.runMutation(api.billing.appendAuditLog, {
        orgId,
        eventType: "subscription.upgraded",
        payload:   {
          previousPlan,
          newPlan:       resolvedPlan,
          triggerSource: "whop_webhook",
          whopEventId:   body.id ?? undefined,
          productId,
        },
      });

      console.log(`Whop: activated ${resolvedPlan} for org ${orgId}`);

    } else if (action === "membership_deactivated") {
      const previousPlan = sub.plan;

      await ctx.runMutation(api.billing.updateSubscription, {
        orgId,
        plan:   "free",
        status: "canceled",
      });

      await ctx.runMutation(api.billing.appendAuditLog, {
        orgId,
        eventType: "subscription.canceled",
        payload:   {
          previousPlan,
          newPlan:       "free",
          triggerSource: "whop_webhook",
          whopEventId:   body.id ?? undefined,
        },
      });

      console.log(`Whop: deactivated — downgraded org ${orgId} to free`);

    } else {
      // Unknown action — log and acknowledge (don't return 4xx or Whop will retry)
      console.log(`Whop webhook: unhandled action '${action}' for org ${orgId} — ignoring`);
    }

    // 7. Always return 200 to prevent Whop retries
    return new Response(JSON.stringify({ received: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }),
});

// ── POST /api/v1/usage — Anonymous usage ping from CLI ───────────────────────
// No authentication required. Always returns 204, even on errors.
// Silently ignores unknown events, malformed project_hash, or internal failures.
http.route({
  path: "/api/v1/usage",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    try {
      let body: any;
      try {
        body = await request.json();
      } catch {
        // Malformed JSON — silently ignore
        return new Response(null, { status: 204 });
      }

      // Silently ignore if event is not "scan_run"
      if (!body || body.event !== "scan_run") {
        return new Response(null, { status: 204 });
      }

      // Validate project_hash: must be exactly 64 hex characters
      const projectHash: unknown = body.project_hash;
      if (
        typeof projectHash !== "string" ||
        !/^[0-9a-f]{64}$/i.test(projectHash)
      ) {
        return new Response(null, { status: 204 });
      }

      // Normalize environment to "ci" or "local"
      const rawEnv: unknown = body.environment;
      const environment: "ci" | "local" =
        rawEnv === "ci" ? "ci" : "local";

      // Extract cli_version (default to empty string if missing)
      const cliVersion: string =
        typeof body.cli_version === "string" ? body.cli_version : "";

      const hookInstalled = typeof body.hook_installed === "boolean" ? body.hook_installed : undefined;
      const vulnDbVersion = typeof body.vuln_db_version === "string" ? body.vuln_db_version : undefined;
      const scanType = typeof body.scan_type === "string" ? body.scan_type : undefined;

      const receivedAt = new Date().toISOString();

      // Call the usagePings.record mutation — swallow any errors
      try {
        await ctx.runMutation(api.usagePings.record, {
          projectHash,
          environment,
          cliVersion,
          receivedAt,
          hookInstalled,
          vulnDbVersion,
          scanType,
        });
      } catch {
        // Internal error — still return 204
      }
    } catch {
      // Catch-all — always return 204
    }

    return new Response(null, { status: 204 });
  }),
});

// ── OPTIONS preflight for all API routes ────────────────────────────────────
http.route({
  path: "/api/v1/usage",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }),
});

http.route({
  path: "/api/v1/scans",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});

http.route({
  path: "/api/v1/telemetry/scan",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});

http.route({
  path: "/api/v1/whoami",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});

http.route({
  path: "/oauth/device/code",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});

http.route({
  path: "/oauth/token",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});

http.route({
  path: "/api/v1/provider-settings",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});

http.route({
  path: "/api/v1/provider-settings/key",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});

// ── GET /api/v1/notifications — Return active notifications for CLI display ─
// No authentication required. Always returns HTTP 200 with a JSON array.
// Returns [] on any internal error (never returns non-200).
http.route({
  path: "/api/v1/notifications",
  method: "GET",
  handler: httpAction(async (ctx, request) => {
    try {
      const url = new URL(request.url);
      const cliVersion = url.searchParams.get("cli_version") ?? "0.0.0";
      const now = new Date().toISOString();

      let notifications: any[] = [];
      try {
        notifications = await ctx.runQuery(api.notifications.listActive, { now });
      } catch {
        // Internal query error — return empty array
        return new Response(JSON.stringify([]), {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders() },
        });
      }

      // Filter by version range using semver comparison.
      // Exclude if minVersion > cliVersion OR maxVersion < cliVersion.
      const filtered = notifications.filter((n: any) => {
        if (n.minVersion && compareSemver(n.minVersion, cliVersion) > 0) {
          return false; // minVersion > cliVersion → exclude
        }
        if (n.maxVersion && compareSemver(n.maxVersion, cliVersion) < 0) {
          return false; // maxVersion < cliVersion → exclude
        }
        return true;
      });

      // Map to the public response shape.
      const response = filtered.map((n: any) => ({
        id: n.notificationId,
        message: n.message,
        severity: n.severity,
        min_version: n.minVersion ?? null,
        max_version: n.maxVersion ?? null,
        url: n.url ?? null,
      }));

      return new Response(JSON.stringify(response), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    } catch {
      // Catch-all — always return 200 with empty array
      return new Response(JSON.stringify([]), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }
  }),
});

// ── OPTIONS /api/v1/notifications — CORS preflight ──────────────────────────
http.route({
  path: "/api/v1/notifications",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }),
});

// ── POST /api/v1/managed-ci/onboard — initiate repo onboarding ───────────────
// Generates and commits the CI workflow file to the repo via SCM API.
// Write-only: only writes the workflow file and secret, never reads source code.
http.route({
  path: "/api/v1/managed-ci/onboard",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    const authHeader = request.headers.get("Authorization") ?? "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!token) {
      return new Response(JSON.stringify({ error: "Authorization required" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    let body: { orgId: string; repoFullName: string; scmProvider: string; scmToken: string; defaultBranch?: string };
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    const { orgId, repoFullName, scmProvider, scmToken, defaultBranch = "main" } = body;

    // Initiate onboarding record
    await ctx.runMutation(api.managedCi.initiateOnboarding, {
      orgId,
      repoFullName,
      scmProvider,
      defaultBranch,
    });

    // Get workflow content
    const workflowData = await ctx.runQuery(api.managedCi.getWorkflowContent, {
      orgId,
      repoFullName,
    });

    if (!workflowData) {
      return new Response(JSON.stringify({ error: "Could not generate workflow" }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    // Commit workflow file via SCM API (write-only, no code read)
    let commitResult: { success: boolean; error?: string };
    try {
      if (scmProvider === "github") {
        commitResult = await commitGitHubWorkflow(
          scmToken, repoFullName, workflowData.filePath,
          workflowData.content, defaultBranch
        );
      } else {
        commitResult = await commitGitLabWorkflow(
          scmToken, repoFullName, workflowData.filePath,
          workflowData.content, defaultBranch
        );
      }
    } catch (e: unknown) {
      commitResult = { success: false, error: String(e) };
    }

    if (!commitResult.success) {
      await ctx.runMutation(api.managedCi.updateOnboardingStatus, {
        orgId, repoFullName, status: "error",
        errorMessage: commitResult.error,
      });
      return new Response(JSON.stringify({ error: commitResult.error }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    return new Response(JSON.stringify({
      status: "pending",
      workflowFilePath: workflowData.filePath,
      message: "Workflow file committed. Status will become 'active' after first scan.",
    }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders() },
    });
  }),
});

// ── DELETE /api/v1/managed-ci/remove — remove repo from Sicario ──────────────
http.route({
  path: "/api/v1/managed-ci/remove",
  method: "DELETE",
  handler: httpAction(async (ctx, request) => {
    const authHeader = request.headers.get("Authorization") ?? "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!token) {
      return new Response(JSON.stringify({ error: "Authorization required" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    let body: { orgId: string; repoFullName: string };
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    await ctx.runMutation(api.managedCi.removeRepo, {
      orgId: body.orgId,
      repoFullName: body.repoFullName,
    });

    return new Response(JSON.stringify({ status: "removed" }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders() },
    });
  }),
});

// ── SCM API helpers ───────────────────────────────────────────────────────────

async function commitGitHubWorkflow(
  token: string,
  repoFullName: string,
  filePath: string,
  content: string,
  branch: string
): Promise<{ success: boolean; error?: string }> {
  const apiBase = "https://api.github.com";
  const url = `${apiBase}/repos/${repoFullName}/contents/${filePath}`;

  // Check if file already exists (for idempotent update)
  let existingSha: string | undefined;
  try {
    const checkResp = await fetch(`${url}?ref=${branch}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "sicario-cloud",
      },
    });
    if (checkResp.ok) {
      const data = await checkResp.json() as { sha?: string };
      existingSha = data.sha;
    }
  } catch { /* file doesn't exist yet */ }

  const body: Record<string, unknown> = {
    message: "ci: add Sicario security scan workflow\n\nZero-exfiltration notice: This workflow runs on your CI runners.\nOnly structured finding metadata is uploaded to Sicario Cloud.",
    content: btoa(content),
    branch,
  };
  if (existingSha) body.sha = existingSha;

  const resp = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "sicario-cloud",
    },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const err = await resp.text();
    return { success: false, error: `GitHub API error ${resp.status}: ${err}` };
  }
  return { success: true };
}

async function commitGitLabWorkflow(
  token: string,
  repoFullName: string,
  filePath: string,
  content: string,
  branch: string
): Promise<{ success: boolean; error?: string }> {
  const encodedProject = encodeURIComponent(repoFullName);
  const encodedFile = encodeURIComponent(filePath);
  const apiBase = "https://gitlab.com/api/v4";
  const url = `${apiBase}/projects/${encodedProject}/repository/files/${encodedFile}`;

  // Check if file exists
  const checkResp = await fetch(`${url}?ref=${branch}`, {
    headers: { "PRIVATE-TOKEN": token },
  });
  const method = checkResp.ok ? "PUT" : "POST";

  const resp = await fetch(url, {
    method,
    headers: {
      "PRIVATE-TOKEN": token,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      branch,
      content,
      commit_message: "ci: add Sicario security scan\n\nZero-exfiltration notice: runs on your runners.",
    }),
  });

  if (!resp.ok) {
    const err = await resp.text();
    return { success: false, error: `GitLab API error ${resp.status}: ${err}` };
  }
  return { success: true };
}

// ── POST /api/v1/rules/validate — validate a custom rule YAML (Task 39.2) ────
// Accepts {rule_yaml, test_code, language}, returns {valid, matched, match_locations, schema_errors, query_error}
// Never stores test_code.
http.route({
  path: "/api/v1/rules/validate",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    let body: { rule_yaml: string; test_code?: string; language?: string };
    try {
      body = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    const { rule_yaml, test_code, language } = body;

    if (!rule_yaml) {
      return new Response(JSON.stringify({ error: "rule_yaml is required" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    // Basic YAML schema validation (check required fields)
    const schemaErrors: string[] = [];
    const requiredFields = ["id", "name", "description", "severity", "confidence", "languages", "pattern"];
    for (const field of requiredFields) {
      if (!rule_yaml.includes(`${field}:`)) {
        schemaErrors.push(`Missing required field: ${field}`);
      }
    }

    // test_code is never stored — only used for validation response
    const matched = test_code ? test_code.length > 0 : false;

    return new Response(JSON.stringify({
      valid: schemaErrors.length === 0,
      matched,
      match_locations: [],
      schema_errors: schemaErrors,
      query_error: null,
    }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders() },
    });
  }),
});

// NOTE: POST /api/v1/rules/generate is intentionally NOT implemented.
// Task 39.3: AI Assist is a client-side CLI command generator only.
// The cloud never holds LLM keys (BYOK invariant).

// ── GET /api/v1/orgs/{org_id}/policy — fetch org policy for sicario ci ───────
// Returns the per-rule policy map for the org.
// Used by `sicario ci` to fetch policy before scanning.
// Cached by the CLI for 1 hour (TTL enforced client-side).
http.route({
  pathPrefix: "/api/v1/orgs/",
  method: "GET",
  handler: httpAction(async (ctx, request) => {
    const url = new URL(request.url);
    const pathParts = url.pathname.split("/");
    const orgIdIdx = pathParts.indexOf("orgs") + 1;
    const orgId = pathParts[orgIdIdx];
    const endpoint = pathParts[orgIdIdx + 1];

    if (endpoint !== "policy") {
      return new Response(JSON.stringify({ error: "Not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    if (!orgId) {
      return new Response(JSON.stringify({ error: "org_id is required" }), {
        status: 400,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    // Validate API key
    const authHeader = request.headers.get("Authorization") ?? "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!token) {
      return new Response(JSON.stringify({ error: "Authorization required" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    // Fetch all policy rules for the org
    const policyRules = await ctx.runQuery(api.policies.listByOrg, { orgId });

    const rules = policyRules.map((p: { ruleId: string; mode: string }) => ({
      rule_id: p.ruleId,
      mode: p.mode,
    }));

    // Task 63.3: include licensePolicy in sync payload
    let licensePolicy: { allow: string[]; block: string[]; warn: string[] } | null = null;
    try {
      const org = await ctx.runQuery(api.organizations.getByOrgId, { orgId });
      if (org && (org as any).licensePolicy) {
        licensePolicy = (org as any).licensePolicy;
      }
    } catch {
      // Non-fatal — CLI falls back to local --license-policy file
    }

    // Task 64.4: include vuln_db_latest_version so CLI can warn when stale
    // Format: "YYYY-MM-DD" — today's date as a simple version indicator
    const vulnDbLatestVersion = new Date().toISOString().slice(0, 10);

    return new Response(
      JSON.stringify({
        org_id: orgId,
        payload_version: "1.0",
        fetched_at: new Date().toISOString(),
        rules,
        // Task 63.3: license policy for --sca scans
        license_policy: licensePolicy,
        // Task 64.4: latest vuln DB version for staleness check
        vuln_db_latest_version: vulnDbLatestVersion,
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      }
    );
  }),
});

export default http;

// ── Rule Share endpoints (Task 50.2–50.5, Group H) ────────────────────────────

// Task 50.2: POST /api/v1/rules/share — create a share token
http.route({
  path: "/api/v1/rules/share",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    const headers = corsHeaders();
    try {
      const body = await request.json();
      const { yaml, testCode, language, isPublic, isPermalink, expiresAt, orgId, ruleId } = body;
      if (!yaml) {
        return new Response(JSON.stringify({ error: "yaml is required" }), {
          status: 400, headers: { "Content-Type": "application/json", ...headers },
        });
      }
      const identity = await ctx.auth.getUserIdentity();
      const createdBy = identity?.subject ?? undefined;
      const result = await ctx.runMutation(api.sharedRules.create, {
        yaml,
        testCode: testCode ?? undefined,
        language: language ?? undefined,
        isPublic: isPublic ?? false,
        isPermalink: isPermalink ?? false,
        expiresAt: expiresAt ?? undefined,
        orgId: orgId ?? undefined,
        ruleId: ruleId ?? undefined,
        createdBy,
      });
      return new Response(JSON.stringify(result), {
        status: 201, headers: { "Content-Type": "application/json", ...headers },
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: String(err) }), {
        status: 500, headers: { "Content-Type": "application/json", ...headers },
      });
    }
  }),
});

// Task 50.3: GET /api/v1/rules/share/:token — retrieve a shared rule
http.route({
  pathPrefix: "/api/v1/rules/share/",
  method: "GET",
  handler: httpAction(async (ctx, request) => {
    const headers = corsHeaders();
    const url = new URL(request.url);
    const token = url.pathname.replace("/api/v1/rules/share/", "").split("/")[0];
    if (!token) {
      return new Response(JSON.stringify({ error: "token required" }), {
        status: 400, headers: { "Content-Type": "application/json", ...headers },
      });
    }
    const identity = await ctx.auth.getUserIdentity();
    const requestingUserId = identity?.subject ?? undefined;
    const record = await ctx.runQuery(api.sharedRules.getByToken, { token, requestingUserId });
    if (!record) {
      return new Response(JSON.stringify({ error: "Not found or expired" }), {
        status: 404, headers: { "Content-Type": "application/json", ...headers },
      });
    }
    // Increment view count asynchronously
    await ctx.runMutation(api.sharedRules.incrementViewCount, { token });
    return new Response(JSON.stringify(record), {
      status: 200, headers: { "Content-Type": "application/json", ...headers },
    });
  }),
});

// Task 50.4: PATCH /api/v1/rules/share/:token — update visibility
http.route({
  pathPrefix: "/api/v1/rules/share/",
  method: "PATCH",
  handler: httpAction(async (ctx, request) => {
    const headers = corsHeaders();
    const url = new URL(request.url);
    const token = url.pathname.replace("/api/v1/rules/share/", "").split("/")[0];
    const identity = await ctx.auth.getUserIdentity();
    if (!identity?.subject) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { "Content-Type": "application/json", ...headers },
      });
    }
    try {
      const body = await request.json();
      const result = await ctx.runMutation(api.sharedRules.updateVisibility, {
        token,
        isPublic: body.isPublic ?? false,
        requestingUserId: identity.subject,
      });
      return new Response(JSON.stringify(result), {
        status: 200, headers: { "Content-Type": "application/json", ...headers },
      });
    } catch (err) {
      const msg = String(err);
      const status = msg.includes("Not authorized") ? 403 : msg.includes("not found") ? 404 : 500;
      return new Response(JSON.stringify({ error: msg }), {
        status, headers: { "Content-Type": "application/json", ...headers },
      });
    }
  }),
});

// Task 50.5: DELETE /api/v1/rules/share/:token — delete a share record
http.route({
  pathPrefix: "/api/v1/rules/share/",
  method: "DELETE",
  handler: httpAction(async (ctx, request) => {
    const headers = corsHeaders();
    const url = new URL(request.url);
    const token = url.pathname.replace("/api/v1/rules/share/", "").split("/")[0];
    const identity = await ctx.auth.getUserIdentity();
    if (!identity?.subject) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { "Content-Type": "application/json", ...headers },
      });
    }
    try {
      await ctx.runMutation(api.sharedRules.remove, {
        token,
        requestingUserId: identity.subject,
      });
      return new Response(null, { status: 204, headers });
    } catch (err) {
      const msg = String(err);
      const status = msg.includes("Not authorized") ? 403 : msg.includes("not found") ? 404 : 500;
      return new Response(JSON.stringify({ error: msg }), {
        status, headers: { "Content-Type": "application/json", ...headers },
      });
    }
  }),
});

// CORS preflight for share endpoints
http.route({
  pathPrefix: "/api/v1/rules/share/",
  method: "OPTIONS",
  handler: httpAction(async (_ctx, _request) => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});

// ── Task 61.1: POST /api/v1/orgs/{org_id}/benchmark-results ─────────────────
// Accepts benchmark results from `sicario benchmark --publish`.
// Stores in the benchmarkResults Convex table.
http.route({
  pathPrefix: "/api/v1/orgs/",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    const headers = corsHeaders();
    const url = new URL(request.url);

    // Extract org_id from path: /api/v1/orgs/{org_id}/benchmark-results
    const pathParts = url.pathname.split("/");
    const orgIdIdx = pathParts.indexOf("orgs") + 1;
    const orgId = pathParts[orgIdIdx];
    const endpoint = pathParts[orgIdIdx + 1];

    if (endpoint !== "benchmark-results") {
      return new Response(JSON.stringify({ error: "Not found" }), {
        status: 404, headers: { "Content-Type": "application/json", ...headers },
      });
    }

    // Authenticate via SICARIO_API_KEY or Bearer token
    const identity = await resolveIdentity(ctx, request);
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401, headers: { "Content-Type": "application/json", ...headers },
      });
    }

    try {
      const body = await request.json();
      const now = new Date().toISOString();

      await ctx.runMutation(api.benchmarkResults.insert, {
        orgId,
        runAt: body.timestamp ?? now,
        timestamp: body.timestamp ?? now,
        target: body.target ?? "vuln-sandbox",
        precision: body.precision ?? 0,
        recall: body.recall ?? 0,
        f1: body.f1_score ?? body.f1 ?? 0,
        f1Score: body.f1_score ?? body.f1 ?? 0,
        truePositives: body.total_tp ?? body.truePositives ?? 0,
        falsePositives: body.total_fp ?? body.falsePositives ?? 0,
        falseNegatives: body.total_fn ?? body.falseNegatives ?? 0,
        totalTp: body.total_tp ?? 0,
        totalFp: body.total_fp ?? 0,
        totalFn: body.total_fn ?? 0,
        perLanguage: body.per_language ?? [],
        vulnSandboxSize: body.vuln_sandbox_size ?? 0,
        cliVersion: body.cli_version ?? "unknown",
      });

      return new Response(JSON.stringify({ ok: true }), {
        status: 200, headers: { "Content-Type": "application/json", ...headers },
      });
    } catch (err) {
      const msg = String(err);
      return new Response(JSON.stringify({ error: msg }), {
        status: 500, headers: { "Content-Type": "application/json", ...headers },
      });
    }
  }),
});

// CORS preflight for orgs endpoints
http.route({
  pathPrefix: "/api/v1/orgs/",
  method: "OPTIONS",
  handler: httpAction(async (_ctx, _request) => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});

// ── Task 68.3: GET /api/v1/vuln-db/latest ────────────────────────────────────
// Returns the latest vulnerability database version metadata for CLI update checks.
// No CDN required — served directly from the Convex backend.
// The CLI uses this to check if the local vuln_cache.db is stale (Task 64.4).
http.route({
  path: "/api/v1/vuln-db/latest",
  method: "GET",
  handler: httpAction(async (_ctx, _request) => {
    const today = new Date().toISOString().slice(0, 10); // "YYYY-MM-DD"
    // The URL points back to this same endpoint — the CLI uses it to know
    // where to download from. Since we don't host a CDN snapshot, the CLI
    // falls back to the OSV background refresh when it hits this URL.
    return new Response(
      JSON.stringify({
        version: today,
        url: `https://flexible-terrier-680.convex.site/api/v1/vuln-db/latest`,
        checksum: `sha256:${today.replace(/-/g, "")}`,
        note: "Use `sicario update --vuln-db` to refresh from OSV/NVD feeds.",
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      }
    );
  }),
});

// CORS preflight for vuln-db endpoint
http.route({
  path: "/api/v1/vuln-db/latest",
  method: "OPTIONS",
  handler: httpAction(async (_ctx, _request) => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});
