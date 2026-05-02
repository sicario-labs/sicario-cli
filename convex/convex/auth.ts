import GitHub from "@auth/core/providers/github";
import { Password } from "@convex-dev/auth/providers/Password";
import { Email } from "@convex-dev/auth/providers/Email";
import { convexAuth } from "@convex-dev/auth/server";
import { sendPasswordResetEmail, sendWelcomeEmail } from "./emails";

// ── Password reset OTP provider ───────────────────────────────────────────────
// Sends a 6-digit OTP via Resend. Wired into Password({ reset: ... }) so
// flow: "reset" triggers the email and flow: "reset-verification" validates it.

const ResendOTP = Email({
  id: "resend-otp",
  apiKey: process.env.RESEND_API_KEY,
  async sendVerificationRequest({ identifier: email, token }) {
    await sendPasswordResetEmail(email, token);
  },
});

export const { auth, signIn, signOut, store, isAuthenticated } = convexAuth({
  providers: [
    GitHub,
    Password({
      reset: ResendOTP,
      profile(params) {
        return {
          email: params.email as string,
          name: params.name as string | undefined,
        };
      },
    }),
  ],
  callbacks: {
    async afterUserCreatedOrUpdated(ctx, { userId, existingUserId }) {
      const user = await ctx.db.get(userId);
      if (!user) return;

      const email = (user as any).email as string | undefined;
      if (!email) return;

      // ── Welcome email (new users only) ──────────────────────────────────
      if (!existingUserId) {
        try {
          await sendWelcomeEmail(email, (user as any).name ?? undefined);
        } catch (err) {
          // Non-fatal — log but don't block account creation
          console.error("Failed to send welcome email:", err);
        }
      }

      // ── Redeem pending invitations ───────────────────────────────────────
      const normalizedEmail = email.toLowerCase();

      const pendingInvitations = await (ctx.db
        .query("pendingInvitations") as any)
        .withIndex("by_email", (q: any) => q.eq("email", normalizedEmail))
        .collect();

      if (pendingInvitations.length === 0) return;

      const userIdStr = userId.toString();
      const now = new Date().toISOString();

      for (const invitation of pendingInvitations) {
        try {
          const alreadyMember = await (ctx.db
            .query("memberships") as any)
            .withIndex("by_userId", (q: any) => q.eq("userId", userIdStr))
            .filter((q: any) => q.eq(q.field("orgId"), invitation.orgId))
            .first();

          if (!alreadyMember) {
            await ctx.db.insert("memberships", {
              userId: userIdStr,
              orgId: invitation.orgId,
              role: invitation.role,
              teamIds: invitation.teamIds,
              createdAt: now,
            });
          }
          await ctx.db.delete(invitation._id);
        } catch (error) {
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
