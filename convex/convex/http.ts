import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { auth } from "./auth";
import { api } from "./_generated/api";
// Lazy-import GitHub App utilities to avoid module-level crashes
// import {
//   requireGitHubAppEnv,
//   generateAppJwt,
//   getInstallationToken,
//   listInstallationRepos,
// } from "./githubApp";

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

// ── Helper: HMAC-SHA256 webhook signature validation ────────────────────────
async function validateWebhookSignature(
  payload: string,
  signature: string,
  secret: string,
): Promise<boolean> {
  try {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));
    const hexDigest = Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const expected = `sha256=${hexDigest}`;
    // Constant-time-ish comparison (both are hex strings of fixed length)
    if (expected.length !== signature.length) return false;
    let mismatch = 0;
    for (let i = 0; i < expected.length; i++) {
      mismatch |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
    }
    return mismatch === 0;
  } catch {
    return false;
  }
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


// ── POST /api/v1/github/webhook — GitHub App webhook handler ────────────────
http.route({
  path: "/api/v1/github/webhook",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    const webhookSecret = process.env.GITHUB_WEBHOOK_SECRET;
    if (!webhookSecret) {
      return new Response(
        JSON.stringify({ error: "Webhook secret not configured" }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders() } },
      );
    }

    // Validate HMAC-SHA256 signature
    const signatureHeader = request.headers.get("X-Hub-Signature-256") ?? "";
    const rawBody = await request.text();

    if (!signatureHeader || !(await validateWebhookSignature(rawBody, signatureHeader, webhookSecret))) {
      return new Response(
        JSON.stringify({ error: "Invalid webhook signature" }),
        { status: 401, headers: { "Content-Type": "application/json", ...corsHeaders() } },
      );
    }

    const eventType = request.headers.get("X-GitHub-Event") ?? "";
    const payload = JSON.parse(rawBody);

    // Only handle pull_request events
    if (eventType !== "pull_request") {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    const action = payload.action; // "opened" | "synchronize" | "closed" etc.
    const repoUrl = payload.repository?.html_url ?? "";
    const prNumber = payload.pull_request?.number ?? 0;
    const prTitle = payload.pull_request?.title ?? "";
    const merged = payload.pull_request?.merged === true;

    // Resolve projectId from repository URL by scanning all projects
    let matchedProject: any = null;
    try {
      matchedProject = await ctx.runQuery(api.projects.getByRepoUrl, {
        repositoryUrl: repoUrl,
      });
    } catch {
      // If project resolution fails, acknowledge and move on
    }

    // No matching project — acknowledge and take no action
    if (!matchedProject) {
      return new Response(JSON.stringify({ ok: true, matched: false }), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    const projectId = matchedProject.id;
    const orgId = matchedProject.org_id;

    try {
      if (action === "opened" || action === "synchronize") {
        // Create a prChecks record with status "pending" and trigger scan workflow
        const checkId = `chk-${Date.now()}-${randomAlphanumeric(6)}`;
        await ctx.runMutation(api.prChecks.createPrCheck, {
          checkId,
          projectId,
          orgId,
          prNumber,
          prTitle,
          repositoryUrl: repoUrl,
        });

        // Schedule the PR scan workflow
        const installationId = matchedProject.github_app_installation_id;
        if (!installationId) {
          await ctx.runMutation(api.prChecks.updatePrCheck, {
            checkId,
            status: "failed",
          });
        } else {
          await ctx.scheduler.runAfter(0, (api as any).prScanWorkflow.runPrScan, {
            checkId,
            repositoryUrl: repoUrl,
            prNumber,
            projectId,
            orgId,
            installationId,
          });
        }
        return new Response(
          JSON.stringify({ ok: true, checkId }),
          { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders() } },
        );
      }

      if (action === "closed" && merged) {
        // Find matching autoFixPRs record by prNumber and update to "merged"
        const autoFixes: any[] = await ctx.runQuery(api.autoFixPRs.listByProject, {
          projectId,
        });
        const matchingFix = autoFixes.find(
          (f: any) => f.pr_number === prNumber && (f.status === "opened" || f.status === "pending"),
        );
        if (matchingFix) {
          await ctx.runMutation(api.autoFixPRs.updateAutoFixStatus, {
            fixId: matchingFix.fix_id,
            status: "merged",
          });
        }

        return new Response(
          JSON.stringify({ ok: true, merged: true }),
          { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders() } },
        );
      }
    } catch (e: any) {
      return new Response(
        JSON.stringify({ error: e.message || "Internal error" }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders() } },
      );
    }

    // Unhandled action — acknowledge
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders() },
    });
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

// ── GET /api/v1/provider-settings — Return provider config for authed user ──
http.route({
  path: "/api/v1/provider-settings",
  method: "GET",
  handler: httpAction(async (ctx, request) => {
    const identity = await resolveIdentity(ctx, request);
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    try {
      const settings = await ctx.runQuery(api.providerSettings.getForUserById, {
        userId: identity.subject,
      });
      if (!settings) {
        return new Response(JSON.stringify({ error: "No provider settings found" }), {
          status: 404,
          headers: { "Content-Type": "application/json", ...corsHeaders() },
        });
      }

      return new Response(
        JSON.stringify({
          provider_name: settings.providerName,
          endpoint: settings.endpoint,
          model: settings.model,
          has_api_key: settings.hasApiKey,
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json", ...corsHeaders() },
        },
      );
    } catch (e: any) {
      return new Response(
        JSON.stringify({ error: e.message || "Internal error" }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders() } },
      );
    }
  }),
});

// ── PUT /api/v1/provider-settings — Create or update provider config ────────
http.route({
  path: "/api/v1/provider-settings",
  method: "PUT",
  handler: httpAction(async (ctx, request) => {
    const identity = await resolveIdentity(ctx, request);
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    try {
      const body = await request.json();
      await ctx.runMutation(api.providerSettings.upsertById, {
        userId: identity.subject,
        providerName: body.provider_name || body.providerName || "",
        endpoint: body.endpoint || "",
        model: body.model || "",
        apiKey: body.api_key || body.apiKey || undefined,
      });

      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    } catch (e: any) {
      return new Response(
        JSON.stringify({ error: e.message || "Internal error" }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders() } },
      );
    }
  }),
});

// ── DELETE /api/v1/provider-settings — Remove provider config ───────────────
http.route({
  path: "/api/v1/provider-settings",
  method: "DELETE",
  handler: httpAction(async (ctx, request) => {
    const identity = await resolveIdentity(ctx, request);
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    try {
      await ctx.runMutation(api.providerSettings.removeById, {
        userId: identity.subject,
      });
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    } catch (e: any) {
      return new Response(
        JSON.stringify({ error: e.message || "Internal error" }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders() } },
      );
    }
  }),
});

// ── GET /api/v1/provider-settings/key — Return decrypted API key (CLI only) ─
http.route({
  path: "/api/v1/provider-settings/key",
  method: "GET",
  handler: httpAction(async (ctx, request) => {
    const identity = await resolveIdentity(ctx, request);
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    try {
      const result = await ctx.runQuery(api.providerSettings.getDecryptedKeyById, {
        userId: identity.subject,
      });
      if (!result) {
        return new Response(JSON.stringify({ error: "No API key stored" }), {
          status: 404,
          headers: { "Content-Type": "application/json", ...corsHeaders() },
        });
      }

      return new Response(JSON.stringify({ api_key: result.apiKey }), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    } catch (e: any) {
      return new Response(
        JSON.stringify({ error: e.message || "Internal error" }),
        { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders() } },
      );
    }
  }),
});

// ── GitHub App utilities (inlined to avoid module import crash) ──────────────

function ghBase64UrlEncode(data: Uint8Array): string {
  const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  let i = 0;
  while (i < data.length) {
    const a = data[i++] ?? 0;
    const b = i < data.length ? data[i++] : 0;
    const c = i < data.length ? data[i++] : 0;
    const triplet = (a << 16) | (b << 8) | c;
    const padding = data.length - (i - (i < data.length ? 0 : (3 - (data.length % 3)) % 3));
    result += base64Chars[(triplet >> 18) & 0x3f];
    result += base64Chars[(triplet >> 12) & 0x3f];
    result += (i - 2 < data.length) ? base64Chars[(triplet >> 6) & 0x3f] : "";
    result += (i - 1 < data.length) ? base64Chars[triplet & 0x3f] : "";
  }
  // Convert to base64url
  return result.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function ghBase64UrlEncodeString(str: string): string {
  return ghBase64UrlEncode(new TextEncoder().encode(str));
}

const GH_REQUIRED_ENV_VARS = [
  "GITHUB_APP_ID",
  "GITHUB_APP_PRIVATE_KEY_BASE64",
  "GITHUB_APP_CLIENT_ID",
  "GITHUB_APP_CLIENT_SECRET",
] as const;

function requireGitHubAppEnv() {
  const missing = GH_REQUIRED_ENV_VARS.filter((v) => !process.env[v]);
  if (missing.length > 0) {
    throw new Error(`Missing GitHub App configuration: ${missing.join(", ")}`);
  }

  // Decode the Base64 string back into the strict multiline PEM format required by OpenSSL
  const formattedPrivateKey = atob(process.env.GITHUB_APP_PRIVATE_KEY_BASE64!);

  return {
    appId: process.env.GITHUB_APP_ID!,
    privateKey: formattedPrivateKey,
    clientId: process.env.GITHUB_APP_CLIENT_ID!,
    clientSecret: process.env.GITHUB_APP_CLIENT_SECRET!,
  };
}

async function generateAppJwt(appId: string, privateKeyPem: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = ghBase64UrlEncodeString(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = ghBase64UrlEncodeString(JSON.stringify({ iss: appId, iat: now - 60, exp: now + 600 }));
  const signingInput = `${header}.${payload}`;

  // Strip PEM headers and whitespace to get raw base64 DER
  const pemBody = privateKeyPem
    .replace(/-----BEGIN (?:RSA )?PRIVATE KEY-----/g, "")
    .replace(/-----END (?:RSA )?PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");

  // Decode base64 to binary without atob (Convex runtime compatibility)
  const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of pemBody) {
    if (ch === "=") break;
    const val = base64Chars.indexOf(ch);
    if (val === -1) continue;
    buffer = (buffer << 6) | val;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  const binaryDer = new Uint8Array(bytes);

  const key = await crypto.subtle.importKey(
    "pkcs8",
    binaryDer.buffer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(signingInput),
  );

  return `${signingInput}.${ghBase64UrlEncode(new Uint8Array(signature))}`;
}

const GH_API_HEADERS = {
  Accept: "application/vnd.github+json",
  "User-Agent": "sicario-security-app",
} as const;

async function getInstallationToken(jwt: string, installationId: string): Promise<string> {
  const url = `https://api.github.com/app/installations/${installationId}/access_tokens`;
  const res = await fetch(url, {
    method: "POST",
    headers: { ...GH_API_HEADERS, Authorization: `Bearer ${jwt}` },
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`GitHub API error (${res.status}): ${body}`);
  }
  const data = await res.json();
  return data.token;
}

async function listInstallationRepos(token: string): Promise<Array<{ name: string; full_name: string; html_url: string }>> {
  const res = await fetch("https://api.github.com/installation/repositories", {
    method: "GET",
    headers: { ...GH_API_HEADERS, Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`Failed to fetch repositories (${res.status}): ${body}`);
  }
  const data = await res.json();
  const repos: any[] = data.repositories ?? [];
  return repos.map((r: any) => ({ name: r.name, full_name: r.full_name, html_url: r.html_url }));
}

// ── GET /api/v1/github/repos — List repos for a GitHub App installation ─────
http.route({
  path: "/api/v1/github/repos",
  method: "GET",
  handler: httpAction(async (ctx, request) => {
    try {
      const url = new URL(request.url);
      const installationId = url.searchParams.get("installation_id");
      if (!installationId) {
        return new Response(
          JSON.stringify({ error: "installation_id query parameter is required" }),
          { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders() } },
        );
      }

      // Delegate to Node.js action for JWT signing + GitHub API calls
      const repos = await ctx.runAction(api.githubAppNode.fetchInstallationRepos, {
        installationId,
      });

      return new Response(JSON.stringify(repos), {
        status: 200,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    } catch (e: any) {
      return new Response(
        JSON.stringify({ error: e.message || "GitHub API error" }),
        { status: 502, headers: { "Content-Type": "application/json", ...corsHeaders() } },
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

http.route({
  path: "/api/v1/github/repos",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});

http.route({
  path: "/api/v1/github/webhook",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }),
});

export default http;
