import GitHub from "@auth/core/providers/github";
import { Password } from "@convex-dev/auth/providers/Password";
import { convexAuth } from "@convex-dev/auth/server";

export const { auth, signIn, signOut, store, isAuthenticated } = convexAuth({
  providers: [GitHub, Password],
  callbacks: {
    async afterUserCreatedOrUpdated(ctx, { userId }) {
      // Look up the user record to get their email
      const user = await ctx.db.get(userId);
      if (!user) return;

      const email = (user as any).email;
      if (!email) return;

      const normalizedEmail = email.toLowerCase();

      // Query pending invitations matching this email
      const pendingInvitations = await (ctx.db
        .query("pendingInvitations") as any)
        .withIndex("by_email", (q: any) => q.eq("email", normalizedEmail))
        .collect();

      if (pendingInvitations.length === 0) return;

      const userIdStr = userId.toString();
      const now = new Date().toISOString();

      // Process each invitation independently so one failure doesn't block others
      for (const invitation of pendingInvitations) {
        try {
          await ctx.db.insert("memberships", {
            userId: userIdStr,
            orgId: invitation.orgId,
            role: invitation.role,
            teamIds: invitation.teamIds,
            createdAt: now,
          });
          await ctx.db.delete(invitation._id);
        } catch (error) {
          // Log the error but retain the pending invitation record
          console.error(
            `Failed to process pending invitation ${invitation.invitationId} ` +
              `for email ${normalizedEmail} in org ${invitation.orgId}:`,
            error
          );
        }
      }
    },
  },
});
