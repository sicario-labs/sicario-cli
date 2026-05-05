/**
 * Release distribution — Convex functions
 *
 * Handles binary release metadata: querying active releases for the
 * download page, and publishing new releases (deactivating old ones).
 */

import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

// ── Queries ───────────────────────────────────────────────────────────────────

/**
 * Return all active releases, one per platform.
 * Used by the frontend download page.
 */
export const getActiveReleases = query({
  args: {},
  handler: async (ctx) => {
    const releases = await ctx.db
      .query("releases")
      .filter((q) => q.eq(q.field("isActive"), true))
      .collect();

    return releases.map((r) => ({
      id: r._id,
      version: r.version,
      platform: r.platform,
      // storageId must be included so the /download/latest/:platform handler
      // can pass a valid string to ctx.storage.get(). Omitting it was the
      // root cause of the "storage.get requires a string but received undefined"
      // error (WEB-002).
      storageId: r.storageId as string,
      checksum: r.checksum,
      fileSize: r.fileSize ?? null,
      createdAt: r.createdAt,
    }));
  },
});

/**
 * Return all releases for a specific version (active or not).
 * Useful for admin views.
 */
export const getReleasesByVersion = query({
  args: { version: v.string() },
  handler: async (ctx, { version }) => {
    return await ctx.db
      .query("releases")
      .withIndex("by_version", (q) => q.eq("version", version))
      .collect();
  },
});

// ── Mutations ─────────────────────────────────────────────────────────────────

/**
 * Publish a new release for a platform.
 *
 * 1. Deactivates any existing active release for the same platform.
 * 2. Inserts the new release as active.
 *
 * Called by the publish_release script after uploading the binary to
 * Convex File Storage.
 */
export const publishRelease = mutation({
  args: {
    version: v.string(),
    platform: v.string(),
    storageId: v.id("_storage"),
    checksum: v.string(),
    fileSize: v.optional(v.number()),
  },
  handler: async (ctx, { version, platform, storageId, checksum, fileSize }) => {
    // Deactivate all existing active releases for this platform
    const existing = await ctx.db
      .query("releases")
      .withIndex("by_platform_and_active", (q) =>
        q.eq("platform", platform).eq("isActive", true)
      )
      .collect();

    for (const r of existing) {
      await ctx.db.patch(r._id, { isActive: false });
    }

    // Insert the new active release
    const id = await ctx.db.insert("releases", {
      version,
      platform,
      storageId,
      checksum,
      fileSize,
      isActive: true,
      createdAt: new Date().toISOString(),
    });

    return { id };
  },
});

/**
 * Generate a short-lived upload URL for Convex File Storage.
 * Called by the publish_release script before uploading a binary.
 */
export const generateUploadUrl = mutation({
  args: {},
  handler: async (ctx) => {
    return await ctx.storage.generateUploadUrl();
  },
});
