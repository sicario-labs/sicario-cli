/**
 * Finding Events — append-only event log for finding lifecycle.
 *
 * Every triage mutation, auto-resolution, and note addition appends a record
 * here. No update or delete mutations exist — the log is tamper-evident.
 *
 * Requirements: Req 22 (Tasks 22.3–22.5), Req 27 (Tasks 27.2–27.5)
 */

import { v } from "convex/values";
import { mutation, query } from "./_generated/server";

// ── Queries ───────────────────────────────────────────────────────────────────

/**
 * List all events for a finding in chronological order.
 * Replaces the stub `findings.getTimeline`.
 */
export const list = query({
  args: { findingId: v.string() },
  handler: async (ctx, { findingId }) => {
    const events = await ctx.db
      .query("findingEvents")
      .withIndex("by_findingId", (q) => q.eq("findingId", findingId))
      .collect();
    return events.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  },
});

/**
 * List all events for an org within a time range.
 */
export const listByOrg = query({
  args: {
    orgId: v.string(),
    since: v.optional(v.string()),
  },
  handler: async (ctx, { orgId, since }) => {
    const events = await ctx.db
      .query("findingEvents")
      .withIndex("by_orgId_timestamp", (q) => q.eq("orgId", orgId))
      .collect();
    if (since) {
      return events.filter((e) => e.timestamp >= since);
    }
    return events;
  },
});

// ── Internal helper (used by findings.ts mutations) ───────────────────────────

/**
 * Append a finding event. Called internally by triage mutations.
 * This is the ONLY way to write to findingEvents — no direct insert elsewhere.
 */
export const append = mutation({
  args: {
    findingId: v.string(),
    orgId: v.string(),
    eventType: v.string(),
    fromState: v.optional(v.string()),
    toState: v.optional(v.string()),
    ignoreReason: v.optional(v.string()),
    userId: v.optional(v.string()),
    note: v.optional(v.string()),
    resolutionType: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();
    return await ctx.db.insert("findingEvents", {
      eventId: `evt-${args.findingId}-${Date.now()}`,
      findingId: args.findingId,
      orgId: args.orgId,
      eventType: args.eventType,
      fromState: args.fromState,
      toState: args.toState,
      ignoreReason: args.ignoreReason,
      userId: args.userId,
      note: args.note,
      timestamp: now,
      resolutionType: args.resolutionType,
    });
  },
});
