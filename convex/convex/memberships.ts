import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireRole, getUserMembership } from "./rbac";

/**
 * List all memberships for an organization. Admin only.
 */
export const list = query({
  args: {
    orgId: v.string(),
    userId: v.string(),
  },
  handler: async (ctx, args) => {
    // Gracefully return empty if user has no membership (e.g. dev/demo mode)
    const callerMembership = await getUserMembership(ctx, args.userId, args.orgId);
    if (!callerMembership) return [];
    if (callerMembership.role !== "admin") return [];

    const memberships = await ctx.db
      .query("memberships")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();

    // Resolve display names from Convex Auth users table.
    // The membership userId is tokenIdentifier.split("|").pop() which is
    // the Convex Auth users table document ID (as a string).
    return await Promise.all(
      memberships.map(async (m) => {
        let displayName: string | null = null;
        try {
          // Try to use the userId directly as a Convex document ID
          const user = await ctx.db.get(m.userId as any);
          if (user) {
            displayName = (user as any).name ?? (user as any).email ?? null;
          }
        } catch {
          // Not a valid document ID — fall back to scanning
        }

        // If direct lookup failed, scan users table for a match
        if (!displayName) {
          try {
            const allUsers = await ctx.db.query("users").collect();
            for (const user of allUsers) {
              if (user._id.toString() === m.userId) {
                displayName = (user as any).name ?? (user as any).email ?? null;
                break;
              }
            }
          } catch {
            // users table scan failed
          }
        }

        return mapMembership(m, displayName);
      })
    );
  },
});

/**
 * Get a user's membership in an organization.
 */
export const getForUser = query({
  args: {
    userId: v.string(),
    orgId: v.string(),
  },
  handler: async (ctx, args) => {
    const membership = await getUserMembership(ctx, args.userId, args.orgId);
    if (!membership) return null;
    return mapMembership(membership);
  },
});

/**
 * Add a user to an organization with a role. Admin only.
 */
export const create = mutation({
  args: {
    callerUserId: v.string(),
    orgId: v.string(),
    userId: v.string(),
    role: v.string(),
    teamIds: v.optional(v.array(v.string())),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.callerUserId, args.orgId, "admin");

    // Check if membership already exists
    const existing = await getUserMembership(ctx, args.userId, args.orgId);
    if (existing) {
      throw new Error("User is already a member of this organization");
    }

    const now = new Date().toISOString();
    await ctx.db.insert("memberships", {
      userId: args.userId,
      orgId: args.orgId,
      role: args.role,
      teamIds: args.teamIds ?? [],
      createdAt: now,
    });
    return { userId: args.userId, orgId: args.orgId, role: args.role };
  },
});

/**
 * Update a user's role or team assignments. Admin only.
 */
export const update = mutation({
  args: {
    callerUserId: v.string(),
    orgId: v.string(),
    userId: v.string(),
    role: v.optional(v.string()),
    teamIds: v.optional(v.array(v.string())),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.callerUserId, args.orgId, "admin");

    const membership = await ctx.db
      .query("memberships")
      .withIndex("by_userId_orgId", (q) =>
        q.eq("userId", args.userId).eq("orgId", args.orgId)
      )
      .first();
    if (!membership) {
      throw new Error("Membership not found");
    }

    const updates: Record<string, any> = {};
    if (args.role) updates.role = args.role;
    if (args.teamIds) updates.teamIds = args.teamIds;

    await ctx.db.patch(membership._id, updates);
    return { userId: args.userId, orgId: args.orgId };
  },
});

/**
 * Remove a user from an organization. Admin only.
 */
export const remove = mutation({
  args: {
    callerUserId: v.string(),
    orgId: v.string(),
    userId: v.string(),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.callerUserId, args.orgId, "admin");

    const membership = await ctx.db
      .query("memberships")
      .withIndex("by_userId_orgId", (q) =>
        q.eq("userId", args.userId).eq("orgId", args.orgId)
      )
      .first();
    if (!membership) return false;

    await ctx.db.delete(membership._id);
    return true;
  },
});

function mapMembership(m: any, displayName?: string | null) {
  return {
    user_id: m.userId,
    display_name: displayName ?? m.userId,
    org_id: m.orgId,
    role: m.role,
    team_ids: m.teamIds,
    created_at: m.createdAt,
  };
}

/**
 * List all memberships for a user (used by HTTP actions for CLI auth).
 */
export const listByUser = query({
  args: { userId: v.string() },
  handler: async (ctx, args) => {
    const memberships = await ctx.db
      .query("memberships")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .collect();
    return memberships.map((m) => ({ orgId: m.orgId, role: m.role }));
  },
});
