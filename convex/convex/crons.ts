import { cronJobs } from "convex/server";
import { internal } from "./_generated/api";

const crons = cronJobs();

// Run SCA dependency scan every 24 hours
crons.daily(
  "scheduled-sca-scan",
  { hourUTC: 3, minuteUTC: 0 }, // 3:00 AM UTC daily
  internal.scheduledScans.runScheduledScaScan
);

// Reset seat counts at the start of each billing period (1st of month, 2:00 AM UTC)
crons.monthly(
  "reset-seat-counts",
  { day: 1, hourUTC: 2, minuteUTC: 0 },
  internal.billing.resetAllSeatCounts,
);

// Send weekly digest every Monday at 8:00 AM UTC
crons.weekly(
  "weekly-digest-emails",
  { dayOfWeek: "monday", hourUTC: 8, minuteUTC: 0 },
  internal.emailJobs.sendWeeklyDigests,
);

// Send inactivity nudge every Wednesday at 10:00 AM UTC
crons.weekly(
  "inactivity-nudge-emails",
  { dayOfWeek: "wednesday", hourUTC: 10, minuteUTC: 0 },
  internal.emailJobs.sendInactivityNudges,
);

// Process onboarding emails every hour (Task 38.7)
// Checks first-scan nudge (24h) and day-3 re-engagement (72h) criteria.
crons.hourly(
  "onboarding-emails",
  { minuteUTC: 15 },
  internal.emailJobs.processOnboardingEmails,
);

// Task 50.6: Purge expired shared rule links daily at 04:00 UTC
crons.daily(
  "purge-expired-shared-rules",
  { hourUTC: 4, minuteUTC: 0 },
  internal.sharedRules.purgeExpired,
);

export default crons;
