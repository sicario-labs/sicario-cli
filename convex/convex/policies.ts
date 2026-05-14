/**
 * Per-rule policy modes — CRUD mutations and queries.
 *
 * Policy modes control what happens when a rule fires in `sicario ci`:
 *   - "monitor"  — upload finding to dashboard only (default)
 *   - "comment"  — post a PR/MR comment
 *   - "block"    — exit 1 (fail the CI job)
 *   - "disabled" — skip the rule entirely
 *
 * Requirements: Req 19 — Per-Rule Policy Modes and Cloud Policy Sync (Task 19.5)
 * Task 73: Implement policies table CRUD mutations (setMode, bulkSetMode, listByOrg)
 * Task 73.2: Restrict policy-setting actions to authorized 'manager' roles.
 */

import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireRole } from "./rbac";

// ── Queries ───────────────────────────────────────────────────────────────────

/**
 * List all policy rules for an org.
 * Returns an array of { ruleId, mode } objects.
 */
export const listByOrg = query({
  args: { orgId: v.string() },
  handler: async (ctx, { orgId }) => {
    return await ctx.db
      .query("policies")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .collect();
  },
});

/**
 * Get the policy mode for a specific rule in an org.
 * Returns null if no policy is set (defaults to "monitor").
 */
export const getByRuleId = query({
  args: { orgId: v.string(), ruleId: v.string() },
  handler: async (ctx, { orgId, ruleId }) => {
    return await ctx.db
      .query("policies")
      .withIndex("by_orgId_ruleId", (q) =>
        q.eq("orgId", orgId).eq("ruleId", ruleId)
      )
      .first();
  },
});

// ── Mutations ─────────────────────────────────────────────────────────────────

/**
 * Set the policy mode for a rule in an org.
 * Creates a new policy record or updates the existing one.
 * Restricted to manager/admin roles.
 */
export const setMode = mutation({
  args: {
    orgId: v.string(),
    ruleId: v.string(),
    mode: v.union(
      v.literal("monitor"),
      v.literal("comment"),
      v.literal("block"),
      v.literal("disabled")
    ),
  },
  handler: async (ctx, { orgId, ruleId, mode }) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Unauthorized");
    const userId = identity.subject;

    await requireRole(ctx, userId, orgId, "manager");

    const existing = await ctx.db
      .query("policies")
      .withIndex("by_orgId_ruleId", (q) =>
        q.eq("orgId", orgId).eq("ruleId", ruleId)
      )
      .first();

    const now = new Date().toISOString();

    if (existing) {
      await ctx.db.patch(existing._id, {
        mode,
        updatedAt: now,
      });
      return existing._id;
    } else {
      return await ctx.db.insert("policies", {
        policyId: `policy-${orgId}-${ruleId}-${Date.now()}`,
        orgId,
        ruleId,
        mode,
        createdBy: userId,
        createdAt: now,
        updatedAt: now,
      });
    }
  },
});

/**
 * Alias for setMode for backward compatibility.
 */
export const upsert = setMode;

/**
 * Delete a policy rule (resets to default "monitor" behavior).
 * Restricted to manager/admin roles.
 */
export const remove = mutation({
  args: { orgId: v.string(), ruleId: v.string() },
  handler: async (ctx, { orgId, ruleId }) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Unauthorized");
    const userId = identity.subject;

    await requireRole(ctx, userId, orgId, "manager");

    const existing = await ctx.db
      .query("policies")
      .withIndex("by_orgId_ruleId", (q) =>
        q.eq("orgId", orgId).eq("ruleId", ruleId)
      )
      .first();

    if (existing) {
      await ctx.db.delete(existing._id);
    }
  },
});

/**
 * Bulk set policy modes for multiple rules at once.
 * Restricted to manager/admin roles.
 */
export const bulkSetMode = mutation({
  args: {
    orgId: v.string(),
    rules: v.array(
      v.object({
        ruleId: v.string(),
        mode: v.union(
          v.literal("monitor"),
          v.literal("comment"),
          v.literal("block"),
          v.literal("disabled")
        ),
      })
    ),
  },
  handler: async (ctx, { orgId, rules }) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Unauthorized");
    const userId = identity.subject;

    await requireRole(ctx, userId, orgId, "manager");

    const now = new Date().toISOString();

    for (const { ruleId, mode } of rules) {
      const existing = await ctx.db
        .query("policies")
        .withIndex("by_orgId_ruleId", (q) =>
          q.eq("orgId", orgId).eq("ruleId", ruleId)
        )
        .first();

      if (existing) {
        await ctx.db.patch(existing._id, { mode, updatedAt: now });
      } else {
        await ctx.db.insert("policies", {
          policyId: `policy-${orgId}-${ruleId}-${Date.now()}`,
          orgId,
          ruleId,
          mode,
          createdBy: userId,
          createdAt: now,
          updatedAt: now,
        });
      }
    }
  },
});

/**
 * Alias for bulkSetMode for backward compatibility.
 */
export const bulkUpsert = bulkSetMode;
