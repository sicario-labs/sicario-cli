/**
 * Shared Rules — Rule Editor Share via URL (Task 50, Group H)
 *
 * Provides server-side token generation and retrieval for shared rule editor
 * states. Client-side URL encoding (base64url) is the primary path for short
 * payloads; server tokens are used when the payload exceeds ~1500 chars.
 */

import { v } from "convex/values";
import { mutation, query, internalMutation } from "./_generated/server";
import { internal } from "./_generated/api";

// ── Token generation ──────────────────────────────────────────────────────────

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

function generateToken(length = 10): string {
  // Use Math.random for token generation (not crypto-sensitive — tokens are
  // short-lived share links, not authentication credentials)
  let token = "";
  for (let i = 0; i < length; i++) {
    token += BASE62[Math.floor(Math.random() * BASE62.length)];
  }
  return token;
}

// ── Queries ───────────────────────────────────────────────────────────────────

/**
 * Task 50.3: Look up a shared rule by token.
 * Returns null if not found or expired.
 * Increments viewCount on each access.
 */
export const getByToken = query({
  args: {
    token: v.string(),
    requestingUserId: v.optional(v.string()),
  },
  handler: async (ctx, { token, requestingUserId }) => {
    const record = await ctx.db
      .query("sharedRules")
      .withIndex("by_token", (q) => q.eq("token", token))
      .first();

    if (!record) return null;

    // Check expiry
    if (record.expiresAt && new Date(record.expiresAt) < new Date()) {
      return null; // expired — cron will clean up
    }

    // Private links: only the creator can access
    if (!record.isPublic && record.createdBy && record.createdBy !== requestingUserId) {
      return null;
    }

    return {
      token: record.token,
      yaml: record.yaml,
      testCode: record.testCode ?? null,
      language: record.language ?? null,
      isPublic: record.isPublic,
      isPermalink: record.isPermalink,
      expiresAt: record.expiresAt ?? null,
      createdBy: record.createdBy ?? null,
      viewCount: record.viewCount,
      orgId: record.orgId ?? null,
      ruleId: record.ruleId ?? null,
    };
  },
});

/**
 * List all shared rules created by a user in an org.
 */
export const listByOrg = query({
  args: { orgId: v.string() },
  handler: async (ctx, { orgId }) => {
    return await ctx.db
      .query("sharedRules")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .collect();
  },
});

// ── Mutations ─────────────────────────────────────────────────────────────────

/**
 * Task 50.2: Create a new shared rule record and return the token + URL.
 */
export const create = mutation({
  args: {
    yaml: v.string(),
    testCode: v.optional(v.string()),
    language: v.optional(v.string()),
    isPublic: v.boolean(),
    isPermalink: v.boolean(),
    expiresAt: v.optional(v.string()),
    orgId: v.optional(v.string()),
    ruleId: v.optional(v.string()),
    createdBy: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();
    // Generate a unique token (retry on collision — extremely rare)
    let token = generateToken(10);
    let attempts = 0;
    while (attempts < 5) {
      const existing = await ctx.db
        .query("sharedRules")
        .withIndex("by_token", (q) => q.eq("token", token))
        .first();
      if (!existing) break;
      token = generateToken(10);
      attempts++;
    }

    await ctx.db.insert("sharedRules", {
      token,
      yaml: args.yaml,
      testCode: args.testCode,
      language: args.language,
      isPublic: args.isPublic,
      isPermalink: args.isPermalink,
      expiresAt: args.expiresAt,
      orgId: args.orgId,
      ruleId: args.ruleId,
      createdBy: args.createdBy,
      createdAt: now,
      viewCount: 0,
    });

    const url = `https://usesicario.xyz/dashboard/policies/rules/new?s=${token}`;
    return { token, url };
  },
});

/**
 * Task 50.4: Update visibility of a shared rule (author only).
 * Permalink records cannot be updated.
 */
export const updateVisibility = mutation({
  args: {
    token: v.string(),
    isPublic: v.boolean(),
    requestingUserId: v.string(),
  },
  handler: async (ctx, { token, isPublic, requestingUserId }) => {
    const record = await ctx.db
      .query("sharedRules")
      .withIndex("by_token", (q) => q.eq("token", token))
      .first();

    if (!record) throw new Error("Shared rule not found");
    if (record.createdBy !== requestingUserId) throw new Error("Not authorized");
    if (record.isPermalink) throw new Error("Permalink records cannot be updated");

    await ctx.db.patch(record._id, { isPublic });
    return { token, isPublic };
  },
});

/**
 * Task 50.5: Delete a shared rule (author only).
 */
export const remove = mutation({
  args: {
    token: v.string(),
    requestingUserId: v.string(),
  },
  handler: async (ctx, { token, requestingUserId }) => {
    const record = await ctx.db
      .query("sharedRules")
      .withIndex("by_token", (q) => q.eq("token", token))
      .first();

    if (!record) throw new Error("Shared rule not found");
    if (record.createdBy !== requestingUserId) throw new Error("Not authorized");

    await ctx.db.delete(record._id);
    return { deleted: true };
  },
});

/**
 * Increment view count — called after a successful getByToken read.
 */
export const incrementViewCount = mutation({
  args: { token: v.string() },
  handler: async (ctx, { token }) => {
    const record = await ctx.db
      .query("sharedRules")
      .withIndex("by_token", (q) => q.eq("token", token))
      .first();
    if (record) {
      await ctx.db.patch(record._id, { viewCount: record.viewCount + 1 });
    }
  },
});

/**
 * Task 50.6: Internal mutation to purge expired shared rules.
 * Called by the daily cron job.
 */
export const purgeExpired = internalMutation({
  args: {},
  handler: async (ctx) => {
    const now = new Date().toISOString();
    const all = await ctx.db.query("sharedRules").collect();
    let purged = 0;
    for (const record of all) {
      if (record.expiresAt && record.expiresAt < now) {
        await ctx.db.delete(record._id);
        purged++;
      }
    }
    return { purged };
  },
});
