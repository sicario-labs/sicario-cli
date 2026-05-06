import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

/**
 * Returns all notifications that are currently active:
 *   - enabled == true
 *   - activeFrom <= now (ISO 8601 string comparison)
 *   - activeTo is null OR activeTo >= now
 *
 * Called by the HTTP route at GET /api/v1/notifications.
 */
export const listActive = query({
  args: {
    now: v.string(), // ISO 8601 timestamp, e.g. new Date().toISOString()
  },
  handler: async (ctx, args) => {
    // Use the by_enabled_activeFrom index to efficiently fetch enabled
    // notifications whose activeFrom is at or before `now`.
    const candidates = await ctx.db
      .query("notifications")
      .withIndex("by_enabled_activeFrom", (q) =>
        q.eq("enabled", true).lte("activeFrom", args.now)
      )
      .collect();

    // Post-filter: exclude notifications that have already expired.
    return candidates.filter(
      (n) => n.activeTo === undefined || n.activeTo === null || n.activeTo >= args.now
    );
  },
});

/**
 * Insert a new notification document.
 * Intended for internal/admin use (e.g. seed scripts, dashboard).
 */
export const create = mutation({
  args: {
    notificationId: v.string(),
    message: v.string(),
    severity: v.union(v.literal("info"), v.literal("warning"), v.literal("critical")),
    minVersion: v.optional(v.string()),
    maxVersion: v.optional(v.string()),
    url: v.optional(v.string()),
    activeFrom: v.string(),
    activeTo: v.optional(v.string()),
    enabled: v.boolean(),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert("notifications", {
      notificationId: args.notificationId,
      message: args.message,
      severity: args.severity,
      minVersion: args.minVersion,
      maxVersion: args.maxVersion,
      url: args.url,
      activeFrom: args.activeFrom,
      activeTo: args.activeTo,
      enabled: args.enabled,
    });
  },
});

/**
 * Disable a notification by its notificationId.
 * Sets enabled = false so it no longer appears in listActive results.
 * Intended for internal/admin use.
 */
export const disable = mutation({
  args: {
    notificationId: v.string(),
  },
  handler: async (ctx, args) => {
    // Find the document by notificationId (scan — notifications table is small)
    const docs = await ctx.db
      .query("notifications")
      .collect();

    const doc = docs.find((n) => n.notificationId === args.notificationId);
    if (!doc) {
      throw new Error(`Notification '${args.notificationId}' not found`);
    }

    await ctx.db.patch(doc._id, { enabled: false });
  },
});
