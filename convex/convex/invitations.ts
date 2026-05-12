import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireRole, getUserMembership } from "./rbac";

/**
 * Invite a member by email address.
 *
 * Always creates a pendingInvitation record. The invitation is redeemed
 * automatically in two ways:
 *
 * 1. For users who sign up AFTER being invited: the `afterUserCreatedOrUpdated`
 *    callback in auth.ts fires on registration and redeems all pending
 *    invitations matching their email.
 *
 * 2. For users who ALREADY have an account: `ensureOrg` (called on every
 *    dashboard load) checks for pending invitations and redeems them using
 *    the correct tokenIdentifier-derived userId format.
 *
 * This approach avoids the userId format mismatch that occurred when
 * `invitations.create` tried to create memberships directly using
 * `matchedUser._id.toString()`, which differs from the
 * `tokenIdentifier.split("|").pop()` format used everywhere else.
 */
export const create = mutation({
  args: {
    callerUserId: v.string(),
    orgId: v.string(),
    email: v.string(),
    role: v.string(),
    teamIds: v.optional(v.array(v.string())),
  },
  handler: async (ctx, args) => {
    // RBAC — admin only
    await requireRole(ctx, args.callerUserId, args.orgId, "admin");

    const normalizedEmail = args.email.toLowerCase();

    // Check for duplicate pending invitation
    const existingInvitation = await ctx.db
      .query("pendingInvitations")
      .withIndex("by_orgId_email", (q) =>
        q.eq("orgId", args.orgId).eq("email", normalizedEmail)
      )
      .first();
    if (existingInvitation) {
      throw new Error("An invitation is already pending for this email");
    }

    // Always create a pending invitation.
    // - New users: redeemed by afterUserCreatedOrUpdated in auth.ts on signup.
    // - Existing users: redeemed by ensureOrg on their next dashboard load.
    const now = new Date().toISOString();
    await ctx.db.insert("pendingInvitations", {
      invitationId: crypto.randomUUID(),
      email: normalizedEmail,
      orgId: args.orgId,
      role: args.role,
      teamIds: args.teamIds ?? [],
      inviterUserId: args.callerUserId,
      createdAt: now,
    });

    // Send invitation email (non-fatal)
    try {
      const { sendInvitationEmail } = await import("./emails");
      const org = await ctx.db
        .query("organizations")
        .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
        .first();
      const orgName = org?.name ?? "your organization";
      // Resolve inviter display name from auth users table
      const inviterUser = await ctx.db.get(args.callerUserId as any);
      const inviterName =
        (inviterUser as any)?.name ??
        (inviterUser as any)?.email ??
        "A team member";
      await sendInvitationEmail(normalizedEmail, orgName, args.role, inviterName);
    } catch (err) {
      console.error("Failed to send invitation email:", err);
    }

    return { status: "invited" as const, email: normalizedEmail };
  },
});


/**
 * List all pending invitations for an organization. Admin only.
 */
export const listPending = query({
  args: {
    orgId: v.string(),
    callerUserId: v.string(),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.callerUserId, args.orgId, "admin");

    const invitations = await ctx.db
      .query("pendingInvitations")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();

    return invitations.map((inv) => ({
      invitationId: inv.invitationId,
      email: inv.email,
      role: inv.role,
      teamIds: inv.teamIds,
      createdAt: inv.createdAt,
    }));
  },
});


/**
 * Revoke a pending invitation. Admin only.
 */
export const revoke = mutation({
  args: {
    callerUserId: v.string(),
    orgId: v.string(),
    invitationId: v.string(),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.callerUserId, args.orgId, "admin");

    const invitations = await ctx.db
      .query("pendingInvitations")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();

    const invitation = invitations.find(
      (inv) => inv.invitationId === args.invitationId
    );

    if (!invitation) {
      throw new Error("Invitation not found");
    }

    await ctx.db.delete(invitation._id);
    return true;
  },
});


/**
 * Get memberships created after the user's last notification dismissal.
 * Used to power the "new membership" notification banner.
 */
export const getNewMemberships = query({
  args: {
    userId: v.string(),
  },
  handler: async (ctx, args) => {
    // Look up the user's profile for the dismissal timestamp
    const profile = await ctx.db
      .query("userProfiles")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .first();

    const lastDismissed = profile?.lastNotificationDismissedAt ?? null;

    // Get all memberships for this user
    const memberships = await ctx.db
      .query("memberships")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .collect();

    // Filter to those created after the dismissal timestamp
    const newMemberships = lastDismissed
      ? memberships.filter((m) => m.createdAt > lastDismissed)
      : memberships;

    // Join with organizations to get org names
    const results = await Promise.all(
      newMemberships.map(async (m) => {
        const org = await ctx.db
          .query("organizations")
          .withIndex("by_orgId", (q) => q.eq("orgId", m.orgId))
          .first();
        return {
          orgName: org?.name ?? "Unknown Organization",
          role: m.role,
          createdAt: m.createdAt,
        };
      })
    );

    return results;
  },
});


/**
 * Dismiss the new-membership notification banner.
 * Upserts `lastNotificationDismissedAt` on the user's profile.
 */
export const dismissNotifications = mutation({
  args: {
    userId: v.string(),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();

    const existing = await ctx.db
      .query("userProfiles")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .first();

    if (existing) {
      await ctx.db.patch(existing._id, {
        lastNotificationDismissedAt: now,
        updatedAt: now,
      });
    } else {
      // Create a new profile with default values (upsert pattern from userProfiles.ts)
      await ctx.db.insert("userProfiles", {
        userId: args.userId,
        onboardingCompleted: false,
        onboardingSkipped: false,
        languages: [],
        goals: [],
        lastNotificationDismissedAt: now,
        createdAt: now,
        updatedAt: now,
      });
    }
  },
});
