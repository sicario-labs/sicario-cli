// ── GitHub App utility module ────────────────────────────────────────────────
// Pure async functions for JWT generation and GitHub API interaction.
// Used by HTTP actions in http.ts — the private key never leaves the backend.

// ── Types ───────────────────────────────────────────────────────────────────

export interface GitHubAppEnv {
  appId: string;
  privateKey: string;
  clientId: string;
  clientSecret: string;
}

export interface GitHubRepo {
  name: string;
  full_name: string;
  html_url: string;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function base64UrlEncode(data: Uint8Array): string {
  let binary = "";
  for (const b of data) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncodeString(str: string): string {
  return base64UrlEncode(new TextEncoder().encode(str));
}

// ── requireGitHubAppEnv ─────────────────────────────────────────────────────

const REQUIRED_ENV_VARS = [
  "GITHUB_APP_ID",
  "GITHUB_APP_PRIVATE_KEY_BASE64",
  "GITHUB_APP_CLIENT_ID",
  "GITHUB_APP_CLIENT_SECRET",
] as const;

/**
 * Read and validate all required GitHub App environment variables.
 * Throws with a message listing every missing variable name.
 */
export function requireGitHubAppEnv(): GitHubAppEnv {
  const missing = REQUIRED_ENV_VARS.filter((v) => !process.env[v]);
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

// ── generateAppJwt ──────────────────────────────────────────────────────────

/**
 * Generate an RS256-signed JWT for GitHub App authentication.
 *
 * - Header: { alg: "RS256", typ: "JWT" }
 * - Payload: { iss: appId, iat: now - 60s, exp: now + 600s }
 * - Signs with crypto.subtle using RSASSA-PKCS1-v1_5 / SHA-256
 */
export async function generateAppJwt(
  appId: string,
  privateKeyPem: string,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const header = base64UrlEncodeString(
    JSON.stringify({ alg: "RS256", typ: "JWT" }),
  );
  const payload = base64UrlEncodeString(
    JSON.stringify({ iss: appId, iat: now - 60, exp: now + 600 }),
  );

  const signingInput = `${header}.${payload}`;

  // Strip PEM headers and whitespace to get raw base64 DER
  const pemBody = privateKeyPem
    .replace(/-----BEGIN (?:RSA )?PRIVATE KEY-----/g, "")
    .replace(/-----END (?:RSA )?PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");

  const binaryDer = Uint8Array.from(atob(pemBody), (c) => c.charCodeAt(0));

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

  return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
}

// ── GitHub API headers ──────────────────────────────────────────────────────

const GITHUB_API_HEADERS = {
  Accept: "application/vnd.github+json",
  "User-Agent": "sicario-security-app",
} as const;

// ── getInstallationToken ────────────────────────────────────────────────────

/**
 * Acquire a short-lived installation token from GitHub.
 * POST /app/installations/{installationId}/access_tokens with Bearer JWT.
 */
export async function getInstallationToken(
  jwt: string,
  installationId: string,
): Promise<string> {
  const url = `https://api.github.com/app/installations/${installationId}/access_tokens`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      ...GITHUB_API_HEADERS,
      Authorization: `Bearer ${jwt}`,
    },
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(
      `GitHub API error (${res.status}): ${body}`,
    );
  }

  const data = await res.json();
  return data.token;
}

// ── listInstallationRepos ───────────────────────────────────────────────────

/**
 * Fetch repositories accessible to a GitHub App installation.
 * GET /installation/repositories with Bearer installation token.
 * Returns only { name, full_name, html_url } per repo.
 */
export async function listInstallationRepos(
  token: string,
): Promise<GitHubRepo[]> {
  const res = await fetch(
    "https://api.github.com/installation/repositories",
    {
      method: "GET",
      headers: {
        ...GITHUB_API_HEADERS,
        Authorization: `Bearer ${token}`,
      },
    },
  );

  if (!res.ok) {
    const body = await res.text();
    throw new Error(
      `Failed to fetch repositories (${res.status}): ${body}`,
    );
  }

  const data = await res.json();
  const repos: any[] = data.repositories ?? [];
  return extractRepos(repos);
}

/**
 * Extract only the required fields from GitHub API repo objects.
 * Exported for direct property testing.
 */
export function extractRepos(
  repos: Array<Record<string, unknown>>,
): GitHubRepo[] {
  return repos.map((r) => ({
    name: r.name as string,
    full_name: r.full_name as string,
    html_url: r.html_url as string,
  }));
}
