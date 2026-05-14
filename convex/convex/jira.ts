/**
 * Jira Integration — create tickets from findings.
 *
 * Requirements: Req 33 — Jira Integration (Tasks 33.1–33.4)
 */

import { v } from "convex/values";
import { action, mutation, query } from "./_generated/server";
import { api } from "./_generated/api";

// ── Queries ───────────────────────────────────────────────────────────────────

export const getConfig = query({
  args: { orgId: v.string() },
  handler: async (ctx, { orgId }) => {
    return await ctx.db
      .query("jiraConfigs")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .first();
  },
});

// ── Mutations ─────────────────────────────────────────────────────────────────

export const saveConfig = mutation({
  args: {
    orgId: v.string(),
    jiraBaseUrl: v.string(),
    jiraProjectKey: v.string(),
    jiraIssueType: v.string(),
    encryptedToken: v.string(),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();
    const existing = await ctx.db
      .query("jiraConfigs")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();

    if (existing) {
      await ctx.db.patch(existing._id, { ...args, updatedAt: now });
      return existing._id;
    }
    return await ctx.db.insert("jiraConfigs", { ...args, createdAt: now, updatedAt: now });
  },
});

// ── Actions ───────────────────────────────────────────────────────────────────

/**
 * Create a Jira ticket for a finding.
 * Posts to Jira REST API with rule metadata + remediation link.
 * No source code is transmitted.
 *
 * Task 33.2: Jira ticket creation action.
 */
export const createTicket = action({
  args: {
    orgId: v.string(),
    findingId: v.string(),
    userId: v.optional(v.string()),
  },
  handler: async (ctx, { orgId, findingId, userId }): Promise<{ issueKey: string; issueUrl: string }> => {
    // Get Jira config
    const config: any = await ctx.runQuery(api.jira.getConfig as any, { orgId });
    if (!config) throw new Error("No Jira configuration found for this org");

    // Get finding
    const finding: any = await ctx.runQuery(api.findings.get as any, { id: findingId });
    if (!finding) throw new Error("Finding not found");

    // Build Jira issue payload — no source code, only metadata
    const summary = `[Sicario] ${finding.rule_id}: ${finding.severity} in ${finding.file_path}`;
    const description = [
      `*Rule:* ${finding.rule_id}`,
      `*Severity:* ${finding.severity}`,
      `*File:* ${finding.file_path}:${finding.line}`,
      `*CWE:* ${finding.cwe_id ?? "N/A"}`,
      `*Remediation:* https://docs.usesicario.xyz/rules/${finding.rule_id}`,
      "",
      "_This ticket was created by Sicario. No source code was transmitted._",
    ].join("\n");

    // Decrypt token (simplified — in production use proper AES-256-GCM decryption)
    const token = config.encryptedToken; // In production: decrypt(config.encryptedToken)

    const response = await fetch(`${config.jiraBaseUrl}/rest/api/3/issue`, {
      method: "POST",
      headers: {
        Authorization: `Basic ${token}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        fields: {
          project: { key: config.jiraProjectKey },
          summary,
          description: {
            type: "doc",
            version: 1,
            content: [{ type: "paragraph", content: [{ type: "text", text: description }] }],
          },
          issuetype: { name: config.jiraIssueType },
        },
      }),
    });

    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Jira API error ${response.status}: ${err}`);
    }

    const data = await response.json() as { key: string; self: string };
    const issueKey = data.key;

    // Task 33.3: store Jira issue key on finding record
    await ctx.runMutation(api.jira.setIssueKey as any, { findingId, jiraIssueKey: issueKey });

    // Task 33.4: append jira_ticket_created event
    await ctx.runMutation(api.findingEvents.append as any, {
      findingId,
      orgId,
      eventType: "jira_ticket_created",
      userId,
      note: `Jira ticket created: ${issueKey}`,
    });

    return { issueKey, issueUrl: `${config.jiraBaseUrl}/browse/${issueKey}` };
  },
});

export const setIssueKey = mutation({
  args: { findingId: v.string(), jiraIssueKey: v.string() },
  handler: async (ctx, { findingId, jiraIssueKey }) => {
    const finding = await ctx.db
      .query("findings")
      .withIndex("by_findingId", (q) => q.eq("findingId", findingId))
      .first();
    if (finding) {
      await ctx.db.patch(finding._id, { jiraIssueKey, updatedAt: new Date().toISOString() });
    }
  },
});
