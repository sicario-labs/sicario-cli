/**
 * savedFilters — named filter presets per user (Req 28, Task 28.6)
 *
 * listByUser  — fetch all saved filters for a user
 * create      — save a new named filter preset
 * remove      — delete a saved filter preset
 */

import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

/** Return all saved filter presets for a given user. */
export const listByUser = query({
  args: {
    userId: v.string(),
  },
  handler: async (ctx, args) => {
    // The index is on (orgId, userId); we don't have orgId here so we do a
    // full scan filtered by userId. savedFilters is a small per-user table so
    // this is acceptable.
    const all = await ctx.db.query("savedFilters").collect();
    return all
      .filter((f) => f.userId === args.userId)
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt))
      .map((f) => ({
        _id: f._id,
        filterId: f.filterId,
        name: f.name,
        filters: f.filters as Record<string, unknown>,
        createdAt: f.createdAt,
      }));
  },
});

/** Save a new named filter preset. */
export const create = mutation({
  args: {
    userId: v.string(),
    orgId: v.optional(v.string()),
    name: v.string(),
    filters: v.any(),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();
    const filterId = `filter_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    await ctx.db.insert("savedFilters", {
      filterId,
      orgId: args.orgId ?? "",
      userId: args.userId,
      name: args.name,
      filters: args.filters,
      createdAt: now,
    });
    return { filterId };
  },
});

/** Delete a saved filter preset by its Convex document ID. */
export const remove = mutation({
  args: {
    id: v.id("savedFilters"),
  },
  handler: async (ctx, args) => {
    await ctx.db.delete(args.id);
  },
});
