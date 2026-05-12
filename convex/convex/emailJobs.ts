import { internalAction, internalMutation, internalQuery } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";

// ── Internal actions ──────────────────────────────────────────────────────────

export const sendWeeklyDigests = internalAction({
  args: {},
  handler: async (ctx) => {
    // Get all orgs
    const orgs: any[] = await ctx.runQuery(internal.emailJobs.getAllOrgs);
    for (const org of orgs) {
      try {
        const stats: any = await ctx.runQuery(internal.emailJobs.getWeeklyStats, { orgId: org.orgId });
        const admins: any[] = await ctx.runQuery(internal.emailJobs.getOrgAdminEmails, { orgId: org.orgId });
        const { sendWeeklyDigestEmail } = await import("./emails");
        for (const admin of admins) {
          if (admin.email) {
            await sendWeeklyDigestEmail(admin.email, org.name, stats);
          }
        }
      } catch (err) {
        console.error(`Weekly digest failed for org ${org.orgId}:`, err);
      }
    }
  },
});

export const sendInactivityNudges = internalAction({
  args: {},
  handler: async (ctx) => {
    const staleUsers: any[] = await ctx.runQuery(internal.emailJobs.getUsersWithNoRecentScan, { thresholdDays: 14 });
    const { sendInactivityNudgeEmail } = await import("./emails");
    for (const u of staleUsers) {
      try {
        if (u.email) {
          await sendInactivityNudgeEmail(u.email, u.name ?? u.email.split("@")[0], u.daysSinceLastScan);
        }
      } catch (err) {
        console.error(`Inactivity nudge failed for ${u.email}:`, err);
      }
    }
  },
});

// ── Internal queries ──────────────────────────────────────────────────────────

export const getAllOrgs = internalQuery({
  args: {},
  handler: async (ctx) => {
    return await ctx.db.query("organizations").collect();
  },
});

export const getWeeklyStats = internalQuery({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const now = Date.now();
    const weekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();
    const scans = await ctx.db
      .query("scans")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();

    const newFindings = findings.filter((f) => f.createdAt >= weekAgo).length;
    const criticalOpen = findings.filter(
      (f) =>
        f.severity === "Critical" &&
        (f.triageState === "Open" || f.triageState === "Reviewing" || f.triageState === "ToFix")
    ).length;
    const highOpen = findings.filter(
      (f) =>
        f.severity === "High" &&
        (f.triageState === "Open" || f.triageState === "Reviewing" || f.triageState === "ToFix")
    ).length;
    const fixed = findings.filter(
      (f) =>
        f.updatedAt >= weekAgo &&
        (f.triageState === "Fixed" || f.triageState === "AutoFixed")
    ).length;
    const scansRun = scans.filter((s) => s.createdAt >= weekAgo).length;

    // Top project by new findings
    const projectCounts: Record<string, number> = {};
    for (const f of findings.filter((f) => f.createdAt >= weekAgo)) {
      if (f.projectId) {
        projectCounts[f.projectId] = (projectCounts[f.projectId] ?? 0) + 1;
      }
    }
    let topProjectId: string | null = null;
    let topCount = 0;
    for (const [pid, count] of Object.entries(projectCounts)) {
      if (count > topCount) {
        topCount = count;
        topProjectId = pid;
      }
    }
    let topProject: string | null = null;
    if (topProjectId) {
      const proj = await ctx.db
        .query("projects")
        .withIndex("by_projectId", (q) => q.eq("projectId", topProjectId!))
        .first();
      topProject = proj?.name ?? null;
    }

    return { newFindings, criticalOpen, highOpen, fixed, scansRun, topProject };
  },
});

export const getOrgAdminEmails = internalQuery({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const memberships = await ctx.db
      .query("memberships")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();
    const admins = memberships.filter((m) => m.role === "admin");
    const result: { email: string | null; name: string | null }[] = [];
    for (const m of admins) {
      try {
        const user = await ctx.db.get(m.userId as any);
        result.push({
          email: (user as any)?.email ?? null,
          name: (user as any)?.name ?? null,
        });
      } catch {
        result.push({ email: null, name: null });
      }
    }
    return result.filter((r) => r.email);
  },
});

export const getUsersWithNoRecentScan = internalQuery({
  args: { thresholdDays: v.number() },
  handler: async (ctx, args) => {
    const threshold = new Date(
      Date.now() - args.thresholdDays * 24 * 60 * 60 * 1000
    ).toISOString();
    const memberships = await ctx.db.query("memberships").collect();
    const result: { email: string; name: string | null; daysSinceLastScan: number }[] = [];
    const seen = new Set<string>();

    for (const m of memberships) {
      if (seen.has(m.userId)) continue;
      seen.add(m.userId);
      try {
        // Get last scan for this org
        const scans = await ctx.db
          .query("scans")
          .withIndex("by_orgId", (q) => q.eq("orgId", m.orgId))
          .collect();
        const lastScan = scans.sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
        if (lastScan && lastScan.createdAt >= threshold) continue; // recent scan exists

        const daysSince = lastScan
          ? Math.floor(
              (Date.now() - new Date(lastScan.createdAt).getTime()) / (1000 * 60 * 60 * 24)
            )
          : args.thresholdDays;

        const user = await ctx.db.get(m.userId as any);
        const email = (user as any)?.email;
        if (email) {
          result.push({
            email,
            name: (user as any)?.name ?? null,
            daysSinceLastScan: daysSince,
          });
        }
      } catch {
        /* skip */
      }
    }
    return result;
  },
});

// ── Onboarding email dispatcher (Task 38.7) ───────────────────────────────────
// Idempotent hourly cron. Checks send criteria for each user and dispatches
// first-scan nudge (24h), day-3 re-engagement (72h), and cancels pending
// nudges when a scan is detected.

export const processOnboardingEmails = internalAction({
  args: {},
  handler: async (ctx) => {
    const users: any[] = await ctx.runQuery(internal.emailJobs.getUsersNeedingOnboardingEmails);

    const {
      sendFirstScanNudgeEmail,
      sendDayThreeReengagementEmail,
    } = await import("./emails");

    for (const u of users) {
      if (!u.email || u.marketingEmailsOptedOut) continue;

      try {
        const signupAge = Date.now() - new Date(u.createdAt).getTime();
        const hours = signupAge / (1000 * 60 * 60);
        const hasScanned = u.hasScanned;

        // Cancel pending nudges if user has now scanned
        if (hasScanned && (u.firstScanNudgeSentAt || u.dayThreeReengagementSentAt)) {
          // Nothing to cancel — emails already sent, but we stop sending more
          continue;
        }

        if (hasScanned) continue;

        // First scan nudge: 24h after signup, not yet sent
        if (hours >= 24 && !u.firstScanNudgeSentAt) {
          await sendFirstScanNudgeEmail(u.email, u.name ?? u.email.split("@")[0]);
          await ctx.runMutation(internal.emailJobs.markNudgeSent, {
            userId: u.userId,
            field: "firstScanNudgeSentAt",
          });
          continue; // one email per user per run
        }

        // Day-3 re-engagement: 72h after signup, nudge already sent, not yet sent
        if (hours >= 72 && u.firstScanNudgeSentAt && !u.dayThreeReengagementSentAt) {
          await sendDayThreeReengagementEmail(u.email, u.name ?? u.email.split("@")[0]);
          await ctx.runMutation(internal.emailJobs.markNudgeSent, {
            userId: u.userId,
            field: "dayThreeReengagementSentAt",
          });
        }
      } catch (err) {
        console.error(`Onboarding email failed for ${u.email}:`, err);
      }
    }
  },
});

export const getUsersNeedingOnboardingEmails = internalQuery({
  args: {},
  handler: async (ctx) => {
    const profiles = await ctx.db.query("userProfiles").collect();
    const result: any[] = [];

    for (const profile of profiles) {
      if (profile.marketingEmailsOptedOut) continue;
      // Only users who haven't completed onboarding
      if (profile.onboardingCompleted) continue;

      // Get the auth user record for email + name
      const user = await ctx.db.get(profile.userId as any);
      const email = (user as any)?.email as string | undefined;
      if (!email) continue;

      // Check if this user has any scans
      const membership = await ctx.db
        .query("memberships")
        .withIndex("by_userId", (q: any) => q.eq("userId", profile.userId))
        .first();

      let hasScanned = false;
      if (membership) {
        const scan = await ctx.db
          .query("scans")
          .withIndex("by_orgId", (q: any) => q.eq("orgId", membership.orgId))
          .first();
        hasScanned = scan !== null;
      }

      result.push({
        userId: profile.userId,
        email,
        name: (user as any)?.name ?? null,
        createdAt: profile.createdAt,
        hasScanned,
        firstScanNudgeSentAt: profile.firstScanNudgeSentAt ?? null,
        dayThreeReengagementSentAt: profile.dayThreeReengagementSentAt ?? null,
        marketingEmailsOptedOut: profile.marketingEmailsOptedOut ?? false,
      });
    }

    return result;
  },
});

export const markNudgeSent = internalMutation({
  args: {
    userId: v.string(),
    field: v.union(
      v.literal("firstScanNudgeSentAt"),
      v.literal("dayThreeReengagementSentAt"),
      v.literal("firstFindingsEmailSentAt")
    ),
  },
  handler: async (ctx, { userId, field }) => {
    const profile = await ctx.db
      .query("userProfiles")
      .withIndex("by_userId", (q) => q.eq("userId", userId))
      .first();
    if (!profile) return;
    await ctx.db.patch(profile._id, {
      [field]: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  },
});

// ── First findings email trigger (Task 38.4, 38.8) ────────────────────────────
// Called from scans.insert after findings are persisted.

export const triggerFirstFindingsEmail = internalAction({
  args: {
    orgId: v.string(),
    projectId: v.optional(v.string()),
    findingsCount: v.number(),
    criticalCount: v.number(),
    highCount: v.number(),
  },
  handler: async (ctx, args) => {
    if (args.findingsCount === 0) return;

    // Get org admins
    const admins: any[] = await ctx.runQuery(internal.emailJobs.getOrgAdminEmails, {
      orgId: args.orgId,
    });

    // Get project name
    let projectName = "your project";
    if (args.projectId) {
      const proj: any = await ctx.runQuery(internal.emailJobs.getProjectName, {
        projectId: args.projectId,
      });
      if (proj) projectName = proj;
    }

    const { sendFirstFindingsEmail } = await import("./emails");

    for (const admin of admins) {
      if (!admin.email) continue;

      // Only send if this user hasn't received a first-findings email yet
      const profile: any = await ctx.runQuery(internal.emailJobs.getUserProfileByEmail, {
        email: admin.email,
      });
      if (!profile || profile.firstFindingsEmailSentAt || profile.marketingEmailsOptedOut) continue;

      try {
        await sendFirstFindingsEmail(
          admin.email,
          admin.name ?? admin.email.split("@")[0],
          args.findingsCount,
          args.criticalCount,
          args.highCount,
          projectName
        );
        await ctx.runMutation(internal.emailJobs.markNudgeSent, {
          userId: profile.userId,
          field: "firstFindingsEmailSentAt",
        });
      } catch (err) {
        console.error(`First findings email failed for ${admin.email}:`, err);
      }
    }
  },
});

export const getProjectName = internalQuery({
  args: { projectId: v.string() },
  handler: async (ctx, { projectId }) => {
    const proj = await ctx.db
      .query("projects")
      .withIndex("by_projectId", (q) => q.eq("projectId", projectId))
      .first();
    return proj?.name ?? null;
  },
});

export const getUserProfileByEmail = internalQuery({
  args: { email: v.string() },
  handler: async (ctx, { email }) => {
    // Find the auth user by email, then look up their profile
    const users = await ctx.db.query("users" as any).collect();
    const user = (users as any[]).find((u: any) => u.email === email);
    if (!user) return null;

    const userId = user._id.toString();
    const profile = await ctx.db
      .query("userProfiles")
      .withIndex("by_userId", (q) => q.eq("userId", userId))
      .first();
    if (!profile) return null;

    return {
      userId,
      firstFindingsEmailSentAt: profile.firstFindingsEmailSentAt ?? null,
      marketingEmailsOptedOut: profile.marketingEmailsOptedOut ?? false,
    };
  },
});
