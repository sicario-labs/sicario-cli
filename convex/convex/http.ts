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
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
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
    // Validate Bearer token
    const identity = await ctx.auth.getUserIdentity();
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

      // ── (a) Resolve orgId from membership or X-Sicario-Org header ──────
      const userId = identity.subject;
      const requestedOrgId = request.headers.get("X-Sicario-Org");

      let orgId: string | undefined;

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
        // Look up the user's first membership
        const userOrgs: any[] = await ctx.runQuery(api.organizations.listUserOrgs);
        if (!userOrgs || userOrgs.length === 0) {
          return new Response(
            JSON.stringify({ error: "No organization membership found. Please create an organization first." }),
            {
              status: 403,
              headers: { "Content-Type": "application/json", ...corsHeaders() },
            }
          );
        }
        orgId = userOrgs[0].orgId;
      }

      // ── (c) Match repository to existing project in this org ───────────
      const repository = body.metadata?.repository ?? "";
      let projectId: string | undefined;

      if (orgId && repository) {
        const orgProjects: any[] = await ctx.runQuery(api.projects.listByOrg, {
          orgId,
        });
        const matched = orgProjects.find(
          (p: any) => p.repository_url === repository
        );

        if (matched) {
          // ── (c) Use existing project ──────────────────────────────────
          projectId = matched.id;
        } else {
          // ── (d) Auto-create project ───────────────────────────────────
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


// ── GET /api/v1/whoami — Return user profile from Bearer token ──────────────
http.route({
  path: "/api/v1/whoami",
  method: "GET",
  handler: httpAction(async (ctx, _request) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    return new Response(
      JSON.stringify({
        username: identity.name ?? identity.email ?? "unknown",
        email: identity.email ?? "",
        organization: "personal",
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
  handler: httpAction(async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    try {
      const settings = await ctx.runQuery(api.providerSettings.getForUser, {});
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
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    try {
      const body = await request.json();
      await ctx.runMutation(api.providerSettings.upsert, {
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
  handler: httpAction(async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    try {
      await ctx.runMutation(api.providerSettings.remove, {});
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
  handler: httpAction(async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json", ...corsHeaders() },
      });
    }

    try {
      const result = await ctx.runQuery(api.providerSettings.getDecryptedKey, {});
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

export default http;
