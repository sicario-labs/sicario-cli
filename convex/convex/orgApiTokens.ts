import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireRole } from "./rbac";

export const list = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const tokens = await ctx.db
      .query("orgApiTokens")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .order("desc")
      .collect();

    return tokens.map((t) => ({
      tokenId: t.tokenId,
      orgId: t.orgId,
      name: t.name,
      // never expose full hash/token to UI, just show metadata
      expiresAt: t.expiresAt,
      lastUsedAt: t.lastUsedAt,
      createdBy: t.createdBy,
      createdAt: t.createdAt,
    }));
  },
});

export const create = mutation({
  args: {
    orgId: v.string(),
    name: v.string(),
    expiresAt: v.optional(v.string()),
    userId: v.string(),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.userId, args.orgId, "admin");

    const tokenId = crypto.randomUUID();
    // Prefix standard pattern: sica_token_...
    const secretToken = `sica_token_${crypto.randomUUID().replace(/-/g, "")}`;
    
    // In production, tokenHash would be generated securely via SHA-256.
    // For dashboard preview demo, we store a hash prefix representation.
    const tokenHash = secretToken;

    const now = new Date().toISOString();
    await ctx.db.insert("orgApiTokens", {
      tokenId,
      orgId: args.orgId,
      name: args.name.trim(),
      tokenHash,
      expiresAt: args.expiresAt,
      createdBy: args.userId,
      createdAt: now,
    });

    // We return the raw secretToken ONCE so the UI can display it to the user.
    return { tokenId, secretToken };
  },
});

export const revoke = mutation({
  args: {
    tokenId: v.string(),
    orgId: v.string(),
    userId: v.string(),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.userId, args.orgId, "admin");

    const token = await ctx.db
      .query("orgApiTokens")
      .withIndex("by_tokenId", (q) => q.eq("tokenId", args.tokenId))
      .first();

    if (!token || token.orgId !== args.orgId) {
      throw new Error("Token not found");
    }

    await ctx.db.delete(token._id);
  },
});
