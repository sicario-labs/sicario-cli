/**
 * PR Comment Triage Commands — webhook handler for /fp, /ar, /other, /open.
 *
 * When `sicario ci` posts a finding comment on a PR, it registers a webhook
 * for comment events. This handler parses triage commands from comment text
 * and applies state transitions propagated via match_based_id.
 *
 * Requirements: Req 23 — PR Comment Triage Commands (Tasks 23.1–23.7)
 */

import { v } from "convex/values";
import { action, mutation, query } from "./_generated/server";
import { api } from "./_generated/api";

// ── Triage command parser ─────────────────────────────────────────────────────

export type TriageCommand = "fp" | "ar" | "other" | "open";

export function parseTriageCommand(commentText: string): {
  command: TriageCommand | null;
  reason: string | null;
} {
  const text = commentText.trim().toLowerCase();
  if (text.startsWith("/fp")) return { command: "fp", reason: "false_positive" };
  if (text.startsWith("/ar")) return { command: "ar", reason: "acceptable_risk" };
  if (text.startsWith("/other")) return { command: "other", reason: "no_time_to_fix" };
  if (text.startsWith("/open")) return { command: "open", reason: null };
  return { command: null, reason: null };
}

export function commandToTriageState(command: TriageCommand): string {
  switch (command) {
    case "fp": return "Ignored";
    case "ar": return "Ignored";
    case "other": return "Ignored";
    case "open": return "Open";
  }
}

// ── Triage command footer ─────────────────────────────────────────────────────

export const TRIAGE_FOOTER = `
---
*Triage commands (reply with one of):*
- \`/fp\` — Mark as false positive
- \`/ar\` — Mark as acceptable risk
- \`/other\` — Mark as no time to fix
- \`/open\` — Reopen finding
`;

// ── Webhook handler ───────────────────────────────────────────────────────────

/**
 * Handle a PR comment webhook event.
 * Parses the triage command, applies the state transition, and propagates
 * via match_based_id across all branches.
 */
export const handlePrCommentWebhook = action({
  args: {
    orgId: v.string(),
    findingId: v.string(),
    commentText: v.string(),
    commenterId: v.string(),
    apiKey: v.string(),
  },
  handler: async (ctx, { orgId, findingId, commentText, commenterId, apiKey }) => {
    // Task 23.7: validate SICARIO_API_KEY
    const expectedKey = process.env.SICARIO_API_KEY;
    if (expectedKey && apiKey !== expectedKey) {
      return { success: false, error: "Unauthorized" };
    }

    const { command, reason } = parseTriageCommand(commentText);
    if (!command) {
      return { success: false, error: "No triage command found" };
    }

    const newState = commandToTriageState(command);

    // Apply triage state transition
    await ctx.runMutation(api.findings.triage, {
      id: findingId,
      triageState: newState,
      ignoreReason: reason ?? undefined,
      userId: commenterId,
      orgId,
    });

    // Task 23.3: propagate via match_based_id across all branches
    await ctx.runMutation(api.prCommentTriage.propagateByMatchBasedId, {
      orgId,
      sourceFindingId: findingId,
      triageState: newState,
      ignoreReason: reason ?? undefined,
      userId: commenterId,
    });

    const stateLabel = newState === "Ignored"
      ? `Ignored (reason: ${reason ?? "other"})`
      : newState;

    return {
      success: true,
      confirmationMessage: `✅ Finding marked as ${stateLabel}. - Sicario`,
    };
  },
});

/**
 * Propagate triage state to all findings with the same match_based_id.
 * Task 23.3: cross-branch triage propagation.
 */
export const propagateByMatchBasedId = mutation({
  args: {
    orgId: v.string(),
    sourceFindingId: v.string(),
    triageState: v.string(),
    ignoreReason: v.optional(v.string()),
    userId: v.optional(v.string()),
  },
  handler: async (ctx, { orgId, sourceFindingId, triageState, ignoreReason, userId }) => {
    // Get the source finding to find its match_based_id
    const source = await ctx.db
      .query("findings")
      .withIndex("by_findingId", (q) => q.eq("findingId", sourceFindingId))
      .first();

    if (!source?.matchBasedId) return { propagated: 0 };

    // Find all findings with the same match_based_id in this org
    const siblings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .collect();

    const toPropagate = siblings.filter(
      (f) => f.matchBasedId === source.matchBasedId && f.findingId !== sourceFindingId
    );

    const now = new Date().toISOString();
    let propagated = 0;

    for (const f of toPropagate) {
      await ctx.db.patch(f._id, {
        triageState,
        ignoreReason: ignoreReason ?? undefined,
        updatedAt: now,
      });
      // Append event
      await ctx.db.insert("findingEvents", {
        eventId: `evt-${f.findingId}-${Date.now()}-prop`,
        findingId: f.findingId,
        orgId,
        eventType: "triaged",
        fromState: f.triageState,
        toState: triageState,
        ignoreReason,
        userId,
        note: `Propagated from finding ${sourceFindingId} via match_based_id`,
        timestamp: now,
      });
      propagated++;
    }

    return { propagated };
  },
});

// ── Org settings: PR comment triage toggle ────────────────────────────────────
// Task 23.6: stored in organizations table (orgSettings field)
export const getPrTriageEnabled = query({
  args: { orgId: v.string() },
  handler: async (ctx, { orgId }) => {
    const org = await ctx.db
      .query("organizations")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .first();
    return (org as any)?.prCommentTriageEnabled ?? true; // default: enabled
  },
});
