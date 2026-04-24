import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

/**
 * Ensure the authenticated user has an organization and membership.
 * If no membership exists, auto-creates a personal org + admin membership.
 * Idempotent — safe to call on every dashboard load.
 */
export const ensureOrg = mutation({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) {
      throw new Error("Not authenticated");
    }

    const userId =
      identity.tokenIdentifier.split("|").pop() ??
      identity.tokenIdentifier;

    // Check if user already has any membership
    const existing = await ctx.db
      .query("memberships")
      .withIndex("by_userId", (q) => q.eq("userId", userId))
      .first();

    if (existing) {
      return { orgId: existing.orgId, isNew: false };
    }

    // Create a new personal org
    const orgId = crypto.randomUUID();
    const now = new Date().toISOString();
    const displayName = identity.name ?? identity.email ?? userId;

    await ctx.db.insert("organizations", {
      orgId,
      name: `${displayName}'s Organization`,
      createdAt: now,
    });

    // Create admin membership
    await ctx.db.insert("memberships", {
      userId,
      orgId,
      role: "admin",
      teamIds: [],
      createdAt: now,
    });

    return { orgId, isNew: true };
  },
});

/**
 * Create a new organization and assign the authenticated user as admin.
 */
export const createOrg = mutation({
  args: {
    name: v.string(),
  },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) {
      throw new Error("Not authenticated");
    }

    const userId =
      identity.tokenIdentifier.split("|").pop() ??
      identity.tokenIdentifier;

    const orgId = crypto.randomUUID();
    const now = new Date().toISOString();

    await ctx.db.insert("organizations", {
      orgId,
      name: args.name,
      createdAt: now,
    });

    await ctx.db.insert("memberships", {
      userId,
      orgId,
      role: "admin",
      teamIds: [],
      createdAt: now,
    });

    return { orgId };
  },
});

/**
 * Check whether the authenticated user has at least one org membership.
 * Returns a boolean so the frontend can skip the ensureOrg mutation for
 * returning users, avoiding an unnecessary write on every page load.
 */
export const hasOrg = query({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) {
      return false;
    }

    const userId =
      identity.tokenIdentifier.split("|").pop() ??
      identity.tokenIdentifier;

    const membership = await ctx.db
      .query("memberships")
      .withIndex("by_userId", (q) => q.eq("userId", userId))
      .first();

    return membership !== null;
  },
});

/**
 * List all organizations the authenticated user belongs to.
 * Joins memberships → organizations to return org details + user role.
 *
 * N+1 trade-off note: The Promise.all below issues one indexed `.first()`
 * lookup per membership. This is the idiomatic Convex pattern and is
 * acceptable here because N (memberships per user) is bounded and small
 * (typically < 10). Each lookup uses the `by_orgId` index, so individual
 * queries are O(1). Convex does not expose a batch-get API, so this is
 * the most efficient approach available.
 */
export const listUserOrgs = query({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) {
      return [];
    }

    const userId =
      identity.tokenIdentifier.split("|").pop() ??
      identity.tokenIdentifier;

    const memberships = await ctx.db
      .query("memberships")
      .withIndex("by_userId", (q) => q.eq("userId", userId))
      .collect();

    const orgs = await Promise.all(
      memberships.map(async (m) => {
        const org = await ctx.db
          .query("organizations")
          .withIndex("by_orgId", (q) => q.eq("orgId", m.orgId))
          .first();
        if (!org) return null;
        return {
          orgId: org.orgId,
          name: org.name,
          role: m.role,
          createdAt: org.createdAt,
        };
      })
    );

    return orgs.filter((o) => o !== null);
  },
});
