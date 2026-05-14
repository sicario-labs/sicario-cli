/**
 * suppressions — inline suppression comment tracking (Task 62.2).
 *
 * upsert      — insert or update a suppression record from scan publish payload
 * listByOrg   — return all suppressions for an org
 * flagForReview — Task 62.4: mark a suppression as requiring review
 */

import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

/** Upsert a suppression record from the CLI scan publish payload. */
export const upsert = mutation({
  args: {
    orgId: v.string(),
    projectId: v.optional(v.string()),
    ruleId: v.string(),
    filePath: v.optional(v.string()),
    line: v.optional(v.number()),
    committerEmail: v.optional(v.string()),
    suppressionComment: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();

    // Check if a record already exists for this org+rule+file+line
    const existing = await ctx.db
      .query("suppressions")
      .withIndex("by_orgId_ruleId", (q) =>
        q.eq("orgId", args.orgId).eq("ruleId", args.ruleId)
      )
      .filter((q) =>
        q.and(
          q.eq(q.field("filePath"), args.filePath ?? null),
          q.eq(q.field("line"), args.line ?? null)
        )
      )
      .first();

    if (existing) {
      // Update lastSeenAt
      await ctx.db.patch(existing._id, { lastSeenAt: now });
    } else {
      await ctx.db.insert("suppressions", {
        orgId: args.orgId,
        projectId: args.projectId,
        ruleId: args.ruleId,
        filePath: args.filePath,
        line: args.line,
        committerEmail: args.committerEmail,
        suppressionComment: args.suppressionComment,
        firstSeenAt: now,
        lastSeenAt: now,
        createdAt: now,
        requiresReview: false,
      });
    }
  },
});

/** Return all suppressions for an org, newest first. */
export const listByOrg = query({
  args: {
    orgId: v.string(),
    projectId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    let q = ctx.db
      .query("suppressions")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId));

    const results = await q.order("desc").collect();

    if (args.projectId) {
      return results.filter((s) => s.projectId === args.projectId);
    }
    return results;
  },
});

/**
 * Task 62.4: Flag a suppression as requiring review.
 * Creates a findingEvents record and marks the suppression.
 */
export const flagForReview = mutation({
  args: {
    id: v.id("suppressions"),
  },
  handler: async (ctx, args) => {
    const suppression = await ctx.db.get(args.id);
    if (!suppression) throw new Error("Suppression not found");

    await ctx.db.patch(args.id, { requiresReview: true });

    // Append a findingEvents record for audit trail
    const now = new Date().toISOString();
    await ctx.db.insert("findingEvents", {
      eventId: `evt-sup-${Date.now()}`,
      findingId: `suppression:${args.id}`,
      orgId: suppression.orgId,
      eventType: "suppression_flagged",
      fromState: undefined,
      toState: "requires_review",
      ignoreReason: undefined,
      userId: undefined,
      note: `Suppression flagged for review: ${suppression.ruleId} in ${suppression.filePath ?? "unknown"}`,
      timestamp: now,
    });
  },
});
