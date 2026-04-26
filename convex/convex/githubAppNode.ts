"use node";

import { action } from "./_generated/server";
import { v } from "convex/values";
import * as crypto from "crypto";

// ── Types ───────────────────────────────────────────────────────────────────

export interface GitHubAppEnv {
  appId: string;
  privateKey: string;
  clientId: string;
  clientSecret: string;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function base64UrlEncode(data: Buffer): string {
  return data.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ── requireGitHubAppEnv (Node-safe) ─────────────────────────────────────────

const REQUIRED_ENV_VARS = [
  "GITHUB_APP_ID",
  "GITHUB_APP_PRIVATE_KEY_BASE64",
  "GITHUB_APP_CLIENT_ID",
  "GITHUB_APP_CLIENT_SECRET",
] as const;

export function requireGitHubAppEnv(): GitHubAppEnv {
  const missing = REQUIRED_ENV_VARS.filter((v) => !process.env[v]);
  if (missing.length > 0) {
    throw new Error(`Missing GitHub App configuration: ${missing.join(", ")}`);
  }

  const base64Key = process.env.GITHUB_APP_PRIVATE_KEY_BASE64!;
  // Decode the Base64 string back into the strict multiline PEM format required by OpenSSL
  const formattedPrivateKey = Buffer.from(base64Key, "base64").toString("ascii");

  return {
    appId: process.env.GITHUB_APP_ID!,
    privateKey: formattedPrivateKey,
    clientId: process.env.GITHUB_APP_CLIENT_ID!,
    clientSecret: process.env.GITHUB_APP_CLIENT_SECRET!,
  };
}

// ── generateAppJwt (Node crypto — no atob / Web Crypto) ────────────────────

export function generateAppJwt(appId: string, privateKeyPem: string): string {
  const now = Math.floor(Date.now() / 1000);

  const header = base64UrlEncode(
    Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })),
  );
  const payload = base64UrlEncode(
    Buffer.from(JSON.stringify({ iss: appId, iat: now - 60, exp: now + 600 })),
  );

  const signingInput = `${header}.${payload}`;

  const sign = crypto.createSign("RSA-SHA256");
  sign.update(signingInput);
  const signature = sign.sign(privateKeyPem);

  return `${signingInput}.${base64UrlEncode(signature)}`;
}

// ── getInstallationToken (Node-safe) ────────────────────────────────────────

export async function getInstallationToken(
  jwt: string,
  installationId: string,
): Promise<string> {
  const url = `https://api.github.com/app/installations/${installationId}/access_tokens`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "sicario-security-app",
      Authorization: `Bearer ${jwt}`,
    },
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`GitHub API error (${res.status}): ${body}`);
  }

  const data = await res.json();
  return data.token;
}

export const fetchInstallationRepos = action({
  args: { installationId: v.string() },
  handler: async (ctx, args) => {
    const env = requireGitHubAppEnv();
    const jwt = generateAppJwt(env.appId, env.privateKey);
    const installationToken = await getInstallationToken(jwt, args.installationId);

    // Fetch repos
    const reposRes = await fetch(
      "https://api.github.com/installation/repositories",
      {
        method: "GET",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${installationToken}`,
          "User-Agent": "sicario-security-app",
        },
      },
    );

    if (!reposRes.ok) {
      const body = await reposRes.text();
      throw new Error(`Failed to fetch repositories (${reposRes.status}): ${body}`);
    }

    const reposData = await reposRes.json();
    const repos = (reposData.repositories ?? []).map((r: any) => ({
      name: r.name,
      full_name: r.full_name,
      html_url: r.html_url,
    }));

    return repos;
  },
});
