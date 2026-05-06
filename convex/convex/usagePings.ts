import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

/**
 * Record a new usage ping from the CLI.
 * Called by the HTTP route at POST /api/v1/usage.
 */
export const record = mutation({
  args: {
    projectHash: v.string(),
    environment: v.union(v.literal("ci"), v.literal("local")),
    cliVersion: v.string(),
    receivedAt: v.string(),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert("usagePings", {
      projectHash: args.projectHash,
      environment: args.environment,
      cliVersion: args.cliVersion,
      receivedAt: args.receivedAt,
    });
  },
});

/**
 * Returns the count of distinct project hashes across all usage pings.
 * Used for dashboard display (unique active projects).
 *
 * Convex does not support native COUNT DISTINCT, so we collect all
 * projectHash values and deduplicate in JS.
 */
export const uniqueProjectCount = query({
  args: {},
  handler: async (ctx) => {
    const pings = await ctx.db.query("usagePings").collect();
    const seen = new Set<string>();
    for (const ping of pings) {
      seen.add(ping.projectHash);
    }
    return seen.size;
  },
});

/**
 * Returns ping counts grouped by day (YYYY-MM-DD) for the last 30 days.
 * Used for the recent activity chart on the dashboard.
 */
export const recentActivity = query({
  args: {},
  handler: async (ctx) => {
    const now = new Date();
    const cutoff = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const cutoffStr = cutoff.toISOString();

    // Use the by_receivedAt index to efficiently fetch only recent pings.
    const pings = await ctx.db
      .query("usagePings")
      .withIndex("by_receivedAt", (q) => q.gte("receivedAt", cutoffStr))
      .collect();

    // Group by date string (YYYY-MM-DD).
    const byDay: Record<string, number> = {};
    for (const ping of pings) {
      const day = ping.receivedAt.substring(0, 10);
      byDay[day] = (byDay[day] ?? 0) + 1;
    }

    // Return sorted ascending by date.
    return Object.entries(byDay)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, count]) => ({ date, count }));
  },
});
