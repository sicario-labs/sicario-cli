import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

/**
 * Insert a new device code record for the OAuth device flow.
 */
export const createDeviceCode = mutation({
  args: {
    deviceCode: v.string(),
    userCode: v.string(),
    codeChallenge: v.string(),
    codeChallengeMethod: v.string(),
    clientId: v.string(),
    scope: v.optional(v.string()),
    expiresAt: v.number(),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();
    await ctx.db.insert("deviceCodes", {
      deviceCode: args.deviceCode,
      userCode: args.userCode,
      codeChallenge: args.codeChallenge,
      codeChallengeMethod: args.codeChallengeMethod,
      clientId: args.clientId,
      scope: args.scope,
      status: "pending",
      expiresAt: args.expiresAt,
      createdAt: now,
    });
    return { deviceCode: args.deviceCode, userCode: args.userCode };
  },
});

/**
 * Look up a device code record by user_code (for the approval page).
 */
export const getDeviceCodeByUserCode = query({
  args: { userCode: v.string() },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("deviceCodes")
      .withIndex("by_userCode", (q) => q.eq("userCode", args.userCode))
      .first();
  },
});

/**
 * Approve a device code — sets status to "approved" and associates the userId.
 */
export const approveDeviceCode = mutation({
  args: {
    userCode: v.string(),
    userId: v.string(),
    userName: v.optional(v.string()),
    userEmail: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    if (!args.userId || args.userId.trim().length === 0) {
      throw new Error("userId must be a non-empty string");
    }
    const record = await ctx.db
      .query("deviceCodes")
      .withIndex("by_userCode", (q) => q.eq("userCode", args.userCode))
      .first();
    if (!record) throw new Error("Device code not found");
    if (record.status !== "pending") throw new Error("Device code is no longer pending");
    if (Date.now() > record.expiresAt) {
      await ctx.db.patch(record._id, { status: "expired" });
      throw new Error("Device code has expired");
    }
    await ctx.db.patch(record._id, {
      status: "approved",
      userId: args.userId,
      userName: args.userName,
      userEmail: args.userEmail,
    });
    return { success: true };
  },
});

/**
 * Look up a device code record by device_code (for token polling).
 * Returns a virtual "expired" status if the code has passed its expiresAt
 * while still marked as "pending", so the CLI receives a clear signal.
 */
export const getDeviceCodeByDeviceCode = query({
  args: { deviceCode: v.string() },
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("deviceCodes")
      .withIndex("by_deviceCode", (q) => q.eq("deviceCode", args.deviceCode))
      .first();
    if (!record) return null;
    // Queries cannot mutate, so surface expiration as a virtual status
    if (record.status === "pending" && Date.now() > record.expiresAt) {
      return { ...record, status: "expired" as const };
    }
    return record;
  },
});

/**
 * Mark a device code as consumed and store the access token.
 * Also checks expiration — if the code has expired, patches status and rejects.
 */
export const consumeDeviceCode = mutation({
  args: {
    deviceCode: v.string(),
    accessToken: v.string(),
  },
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("deviceCodes")
      .withIndex("by_deviceCode", (q) => q.eq("deviceCode", args.deviceCode))
      .first();
    if (!record) throw new Error("Device code not found");
    if (record.status === "pending" && Date.now() > record.expiresAt) {
      await ctx.db.patch(record._id, { status: "expired" });
      throw new Error("Device code has expired");
    }
    if (record.status !== "approved") {
      throw new Error(`Device code is not approved (status: ${record.status})`);
    }
    await ctx.db.patch(record._id, {
      status: "consumed",
      accessToken: args.accessToken,
    });
    return { success: true };
  },
});

/**
 * Look up a consumed device code by its access token.
 * Used by HTTP API endpoints to authenticate CLI requests that send
 * opaque `sic_` tokens instead of Convex Auth JWTs.
 */
export const getByAccessToken = query({
  args: { accessToken: v.string() },
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("deviceCodes")
      .withIndex("by_accessToken", (q) => q.eq("accessToken", args.accessToken))
      .first();
    if (!record) return null;
    if (record.status !== "consumed") return null;
    return { userId: record.userId ?? null, userName: record.userName ?? null, userEmail: record.userEmail ?? null };
  },
});

/**
 * Cleanup mutation that deletes device codes older than 24 hours.
 * Can be called periodically or as a Convex cron to prevent table bloat.
 */
export const cleanupExpiredDeviceCodes = mutation({
  handler: async (ctx) => {
    const twentyFourHoursAgo = Date.now() - 24 * 60 * 60 * 1000;
    const staleRecords = await ctx.db
      .query("deviceCodes")
      .collect();
    let deleted = 0;
    for (const record of staleRecords) {
      if (record.expiresAt < twentyFourHoursAgo) {
        await ctx.db.delete(record._id);
        deleted++;
      }
    }
    return { deleted };
  },
});
