/**
 * benchmarkResults — store and query CLI benchmark results (Task 61.2).
 *
 * insert  — store a new benchmark run (called from HTTP endpoint)
 * listByOrg — return all benchmark runs for an org, newest first
 * getLatest — return the most recent run for an org
 */

import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

/** Insert a new benchmark result record. */
export const insert = mutation({
  args: {
    orgId: v.optional(v.string()),
    runAt: v.string(),
    timestamp: v.optional(v.string()),
    target: v.string(),
    precision: v.number(),
    recall: v.number(),
    f1: v.number(),
    f1Score: v.optional(v.number()),
    truePositives: v.number(),
    falsePositives: v.number(),
    falseNegatives: v.number(),
    totalTp: v.optional(v.number()),
    totalFp: v.optional(v.number()),
    totalFn: v.optional(v.number()),
    perLanguage: v.optional(v.any()),
    vulnSandboxSize: v.optional(v.number()),
    cliVersion: v.optional(v.string()),
    format: v.optional(v.string()),
    rawJson: v.optional(v.any()),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert("benchmarkResults", {
      orgId: args.orgId,
      runAt: args.runAt,
      timestamp: args.timestamp ?? args.runAt,
      target: args.target,
      precision: args.precision,
      recall: args.recall,
      f1: args.f1,
      f1Score: args.f1Score ?? args.f1,
      truePositives: args.truePositives,
      falsePositives: args.falsePositives,
      falseNegatives: args.falseNegatives,
      totalTp: args.totalTp ?? args.truePositives,
      totalFp: args.totalFp ?? args.falsePositives,
      totalFn: args.totalFn ?? args.falseNegatives,
      perLanguage: args.perLanguage ?? [],
      vulnSandboxSize: args.vulnSandboxSize ?? 0,
      cliVersion: args.cliVersion ?? "unknown",
      format: args.format,
      rawJson: args.rawJson,
    });
  },
});

/** Return all benchmark runs for an org, newest first (max 100). */
export const listByOrg = query({
  args: {
    orgId: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const limit = args.limit ?? 100;
    const results = await ctx.db
      .query("benchmarkResults")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .order("desc")
      .take(limit);
    return results;
  },
});

/** Return the two most recent benchmark runs for regression detection (Task 61.4). */
export const getLatestTwo = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const results = await ctx.db
      .query("benchmarkResults")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .order("desc")
      .take(2);
    return results;
  },
});
