import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { auth } from "./auth";
import { api } from "./_generated/api";
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

      // 8. Match projectId to existing project in resolved org
      const orgProjects: any[] = await ctx.runQuery(api.projects.listByOrg, { orgId: orgId! });
      const matchedProject = orgProjects.find((p: any) => p.id === body.projectId);
      if (!matchedProject) {
        return new Response(
          JSON.stringify({ error: `Project '${body.projectId}' not found in organization` }),
          { status: 404, headers: { "Content-Type": "application/json", ...corsHeaders() } },
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

// ── OPTIONS preflight for all API routes ────────────────────────────────────
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

export default http;
