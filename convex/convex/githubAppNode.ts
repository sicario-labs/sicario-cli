"use node";

import { action } from "./_generated/server";
import { v } from "convex/values";
import * as crypto from "crypto";

function base64UrlEncode(data: Buffer): string {
  return data.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function generateJwt(appId: string, privateKeyPem: string): string {
  const now = Math.floor(Date.now() / 1000);

  const header = base64UrlEncode(
    Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })),
  );
  const payload = base64UrlEncode(
    Buffer.from(JSON.stringify({ iss: appId, iat: now - 60, exp: now + 600 })),
  );

  const signingInput = `${header}.${payload}`;

  // Normalize PEM: replace literal \n with real newlines
  const normalizedPem = privateKeyPem.replace(/\\n/g, "\n");

  const sign = crypto.createSign("RSA-SHA256");
  sign.update(signingInput);
  const signature = sign.sign(normalizedPem);

  return `${signingInput}.${base64UrlEncode(signature)}`;
}

export const fetchInstallationRepos = action({
  args: { installationId: v.string() },
  handler: async (ctx, args) => {
    const appId = process.env.GITHUB_APP_ID;
    const privateKey = process.env.GITHUB_APP_PRIVATE_KEY;

    if (!appId || !privateKey) {
      throw new Error("Missing GitHub App configuration: GITHUB_APP_ID or GITHUB_APP_PRIVATE_KEY");
    }

    // Generate JWT
    const jwt = generateJwt(appId, privateKey);

    // Get installation token
    const tokenRes = await fetch(
      `https://api.github.com/app/installations/${args.installationId}/access_tokens`,
      {
        method: "POST",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${jwt}`,
          "User-Agent": "sicario-security-app",
        },
      },
    );

    if (!tokenRes.ok) {
      const body = await tokenRes.text();
      throw new Error(`GitHub API error (${tokenRes.status}): ${body}`);
    }

    const tokenData = await tokenRes.json();
    const installationToken = tokenData.token;

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
