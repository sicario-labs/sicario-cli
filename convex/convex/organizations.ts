import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { getAuthUserId } from "@convex-dev/auth/server";
import { internal } from "./_generated/api";

/**
 * Returns true if the string looks like a raw Convex internal hash:
 * 20+ alphanumeric characters with no spaces.
 */
function looksLikeHash(str: string): boolean {
  return /^[a-z0-9]{20,}$/i.test(str);
}

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

    // Resolve name/email: JWT claims first, then Convex Auth users table fallback
    let resolvedName = identity.name ?? null;
    let resolvedEmail = identity.email ?? null;
    if (!resolvedName || !resolvedEmail) {
      try {
        const authUserId = await getAuthUserId(ctx);
        if (authUserId) {
          const user = await ctx.db.get(authUserId);
          if (user) {
            resolvedName = resolvedName ?? (user as any).name ?? null;
            resolvedEmail = resolvedEmail ?? (user as any).email ?? null;
          }
        }
      } catch {
        // Auth user lookup failed — use JWT defaults
      }
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
      // Self-heal: if the org has a hash-based name and we now have a real name, fix it
      const betterName = resolvedName ?? resolvedEmail ?? null;
      if (betterName) {
        const org = await ctx.db
          .query("organizations")
          .withIndex("by_orgId", (q) => q.eq("orgId", existing.orgId))
          .first();
        if (org) {
          // Check if the org name follows the "<hash>'s Organization" pattern
          const namePrefix = org.name.replace(/'s Organization$/, "");
          if (looksLikeHash(namePrefix)) {
            await ctx.db.patch(org._id, {
              name: `${betterName}'s Organization`,
            });
          }
        }
      }

      // Redeem any pending invitations for this user's email.
      // This handles the case where an existing user was invited to a new org
      // after they already had an account — the auth callback only fires on
      // signup, so we check here on every dashboard load (idempotent).
      if (resolvedEmail) {
        const normalizedEmail = resolvedEmail.toLowerCase();
        const pendingInvitations = await ctx.db
          .query("pendingInvitations")
          .withIndex("by_email", (q: any) => q.eq("email", normalizedEmail))
          .collect();

        const now = new Date().toISOString();
        for (const invitation of pendingInvitations) {
          try {
            // Check for duplicate membership before inserting
            const alreadyMember = await ctx.db
              .query("memberships")
              .withIndex("by_userId", (q) => q.eq("userId", userId))
              .filter((q) => q.eq(q.field("orgId"), invitation.orgId))
              .first();
            if (!alreadyMember) {
              await ctx.db.insert("memberships", {
                userId,
                orgId: invitation.orgId,
                role: invitation.role,
                teamIds: invitation.teamIds,
                createdAt: now,
              });
            }
            await ctx.db.delete(invitation._id);
          } catch (err) {
            console.error(
              `Failed to redeem pending invitation ${invitation.invitationId} ` +
                `for email ${normalizedEmail}:`,
              err
            );
          }
        }
      }

      return { orgId: existing.orgId, isNew: false };
    }

    // Create a new personal org
    const orgId = crypto.randomUUID();
    const now = new Date().toISOString();
    const rawDisplayName = resolvedName ?? resolvedEmail ?? userId;
    const displayName = looksLikeHash(rawDisplayName) ? "User" : rawDisplayName;

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

    // Seed a free subscription for the new org
    await ctx.runMutation(internal.billing.createSubscriptionInternal, { orgId });

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

    // Seed a free subscription for the new org
    await ctx.runMutation(internal.billing.createSubscriptionInternal, { orgId });

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


/**
 * Rename an organization. Only admins of the org may rename it.
 */
export const renameOrg = mutation({
  args: {
    orgId: v.string(),
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

    // Verify the caller is an admin of this org
    const membership = await ctx.db
      .query("memberships")
      .withIndex("by_userId", (q) => q.eq("userId", userId))
      .filter((q) => q.eq(q.field("orgId"), args.orgId))
      .first();

    if (!membership) {
      throw new Error("Not a member of this organization");
    }
    if (membership.role !== "admin") {
      throw new Error("Only admins can rename the organization");
    }

    const trimmed = args.name.trim();
    if (!trimmed) {
      throw new Error("Organization name cannot be empty");
    }
    if (trimmed.length > 64) {
      throw new Error("Organization name must be 64 characters or fewer");
    }

    const org = await ctx.db
      .query("organizations")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();

    if (!org) {
      throw new Error("Organization not found");
    }

    await ctx.db.patch(org._id, { name: trimmed });
    return { success: true };
  },
});

/**
 * Get an organization by its orgId.
 */
export const getByOrgId = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const org = await ctx.db
      .query("organizations")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
    if (!org) return null;
    return {
      ...org,
      orgId: org.orgId,
      name: org.name,
      createdAt: org.createdAt,
    };
  },
});

// ── Task 63.1: updateLicensePolicy ───────────────────────────────────────────
// Updates the licensePolicy JSON field on the organizations table.
// Called from the License Policy settings tab in the dashboard.

export const updateLicensePolicy = mutation({
  args: {
    orgId: v.string(),
    licensePolicy: v.object({
      allow: v.array(v.string()),
      block: v.array(v.string()),
      warn: v.array(v.string()),
    }),
  },
  handler: async (ctx, args) => {
    const org = await ctx.db
      .query("organizations")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
    if (!org) throw new Error("Organization not found");
    await ctx.db.patch(org._id, { licensePolicy: args.licensePolicy });
  },
});

// ── Task 67.3: updateNotificationSettings ────────────────────────────────────
// Updates Slack webhook URL, alert threshold, and email notification toggles.

export const updateNotificationSettings = mutation({
  args: {
    orgId: v.string(),
    slackWebhookUrl: v.optional(v.string()),
    slackAlertSeverityThreshold: v.optional(v.string()),
    weeklyDigestEnabled: v.optional(v.boolean()),
    criticalAlertsEnabled: v.optional(v.boolean()),
  },
  handler: async (ctx, args) => {
    const org = await ctx.db
      .query("organizations")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
    if (!org) throw new Error("Organization not found");

    const updates: Record<string, unknown> = {};
    if (args.slackWebhookUrl !== undefined) updates.slackWebhookUrl = args.slackWebhookUrl;
    if (args.slackAlertSeverityThreshold !== undefined) updates.slackAlertSeverityThreshold = args.slackAlertSeverityThreshold;
    if (args.weeklyDigestEnabled !== undefined) updates.weeklyDigestEnabled = args.weeklyDigestEnabled;
    if (args.criticalAlertsEnabled !== undefined) updates.criticalAlertsEnabled = args.criticalAlertsEnabled;

    await ctx.db.patch(org._id, updates);
  },
});

// ── Group O: updateGeneralSettings ───────────────────────────────────────────
export const updateGeneralSettings = mutation({
  args: {
    orgId: v.string(),
    scanSettings: v.optional(v.any()),
    globalPathIgnores: v.optional(v.string()),
    prCommentTriage: v.optional(v.object({
      enabled: v.boolean(),
      requireReason: v.boolean(),
    })),
    defaultMemberRole: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const org = await ctx.db
      .query("organizations")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
    if (!org) throw new Error("Organization not found");

    const updates: Record<string, unknown> = {};
    if (args.scanSettings !== undefined) updates.scanSettings = args.scanSettings;
    if (args.globalPathIgnores !== undefined) updates.globalPathIgnores = args.globalPathIgnores;
    if (args.prCommentTriage !== undefined) updates.prCommentTriage = args.prCommentTriage;
    if (args.defaultMemberRole !== undefined) updates.defaultMemberRole = args.defaultMemberRole;

    await ctx.db.patch(org._id, updates);
  },
});
