import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireRole } from "./rbac";

export const list = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const teams = await ctx.db
      .query("teams")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .order("desc")
      .collect();
    return teams.map(mapTeam);
  },
});

export const create = mutation({
  args: {
    id: v.string(),
    name: v.string(),
    org_id: v.string(),
    userId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId) {
      await requireRole(ctx, args.userId, args.org_id, "admin");
    }

    const now = new Date().toISOString();
    await ctx.db.insert("teams", {
      teamId: args.id,
      name: args.name,
      orgId: args.org_id,
      createdAt: now,
    });
    return { id: args.id };
  },
});

function mapTeam(t: any) {
  return {
    id: t.teamId,
    name: t.name,
    org_id: t.orgId,
    created_at: t.createdAt,
  };
}
