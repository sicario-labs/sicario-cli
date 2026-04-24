import { query, mutation } from "./_generated/server";
import { v } from "convex/values";

// ── AES-256-GCM helpers (Web Crypto API) ─────────────────────────────────────

async function getEncryptionKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: encoder.encode("sicario-provider-settings"),
      iterations: 100_000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptApiKey(plaintext: string, secret: string): Promise<string> {
  const key = await getEncryptionKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoded,
  );
  // Store as base64: iv (12 bytes) + ciphertext
  const combined = new Uint8Array(iv.length + new Uint8Array(ciphertext).length);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decryptApiKey(encrypted: string, secret: string): Promise<string> {
  const key = await getEncryptionKey(secret);
  const raw = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0));
  const iv = raw.slice(0, 12);
  const ciphertext = raw.slice(12);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext,
  );
  return new TextDecoder().decode(decrypted);
}

// ── Queries ──────────────────────────────────────────────────────────────────

/**
 * Return provider settings for the authenticated user.
 * Never returns the raw API key — only a boolean `hasApiKey`.
 */
export const getForUser = query({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) return null;

    const userId = identity.subject;
    const row = await ctx.db
      .query("providerSettings")
      .withIndex("by_userId", (q) => q.eq("userId", userId))
      .first();

    if (!row) return null;

    return {
      providerName: row.providerName,
      endpoint: row.endpoint,
      model: row.model,
      hasApiKey: !!row.encryptedApiKey,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  },
});

/**
 * Return the decrypted API key for the authenticated user.
 * Intended for CLI consumption only.
 */
export const getDecryptedKey = query({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) return null;

    const userId = identity.subject;
    const row = await ctx.db
      .query("providerSettings")
      .withIndex("by_userId", (q) => q.eq("userId", userId))
      .first();

    if (!row || !row.encryptedApiKey) return null;

    const secret = process.env.PROVIDER_KEY_ENCRYPTION_SECRET;
    if (!secret) {
      throw new Error("PROVIDER_KEY_ENCRYPTION_SECRET is not configured");
    }

    const apiKey = await decryptApiKey(row.encryptedApiKey, secret);
    return { apiKey };
  },
});

// ── Mutations ────────────────────────────────────────────────────────────────

/**
 * Create or update provider settings for the authenticated user.
 * Encrypts the API key if provided.
 */
export const upsert = mutation({
  args: {
    providerName: v.string(),
    endpoint: v.string(),
    model: v.string(),
    apiKey: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) {
      throw new Error("Unauthorized");
    }

    const userId = identity.subject;
    const now = new Date().toISOString();

    let encryptedApiKey: string | undefined;
    if (args.apiKey) {
      const secret = process.env.PROVIDER_KEY_ENCRYPTION_SECRET;
      if (!secret) {
        throw new Error("PROVIDER_KEY_ENCRYPTION_SECRET is not configured");
      }
      encryptedApiKey = await encryptApiKey(args.apiKey, secret);
    }

    const existing = await ctx.db
      .query("providerSettings")
      .withIndex("by_userId", (q) => q.eq("userId", userId))
      .first();

    if (existing) {
      const updates: Record<string, unknown> = {
        providerName: args.providerName,
        endpoint: args.endpoint,
        model: args.model,
        updatedAt: now,
      };
      if (encryptedApiKey !== undefined) {
        updates.encryptedApiKey = encryptedApiKey;
      }
      await ctx.db.patch(existing._id, updates);
      return existing._id;
    }

    return await ctx.db.insert("providerSettings", {
      userId,
      providerName: args.providerName,
      endpoint: args.endpoint,
      model: args.model,
      encryptedApiKey,
      createdAt: now,
      updatedAt: now,
    });
  },
});

/**
 * Delete provider settings for the authenticated user.
 */
export const remove = mutation({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) {
      throw new Error("Unauthorized");
    }

    const userId = identity.subject;
    const existing = await ctx.db
      .query("providerSettings")
      .withIndex("by_userId", (q) => q.eq("userId", userId))
      .first();

    if (existing) {
      await ctx.db.delete(existing._id);
    }

    return { success: true };
  },
});

// ── ById variants (for HTTP handlers using opaque CLI tokens) ────────────────

/**
 * Return provider settings by explicit userId.
 * Used by HTTP handlers when auth is resolved via opaque token (CLI device flow).
 */
export const getForUserById = query({
  args: { userId: v.string() },
  handler: async (ctx, args) => {
    const row = await ctx.db
      .query("providerSettings")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .first();

    if (!row) return null;

    return {
      providerName: row.providerName,
      endpoint: row.endpoint,
      model: row.model,
      hasApiKey: !!row.encryptedApiKey,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
    };
  },
});

/**
 * Return the decrypted API key by explicit userId.
 * Used by HTTP handlers when auth is resolved via opaque token (CLI device flow).
 */
export const getDecryptedKeyById = query({
  args: { userId: v.string() },
  handler: async (ctx, args) => {
    const row = await ctx.db
      .query("providerSettings")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .first();

    if (!row || !row.encryptedApiKey) return null;

    const secret = process.env.PROVIDER_KEY_ENCRYPTION_SECRET;
    if (!secret) {
      throw new Error("PROVIDER_KEY_ENCRYPTION_SECRET is not configured");
    }

    const apiKey = await decryptApiKey(row.encryptedApiKey, secret);
    return { apiKey };
  },
});

/**
 * Create or update provider settings by explicit userId.
 * Used by HTTP handlers when auth is resolved via opaque token (CLI device flow).
 */
export const upsertById = mutation({
  args: {
    userId: v.string(),
    providerName: v.string(),
    endpoint: v.string(),
    model: v.string(),
    apiKey: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();

    let encryptedApiKey: string | undefined;
    if (args.apiKey) {
      const secret = process.env.PROVIDER_KEY_ENCRYPTION_SECRET;
      if (!secret) {
        throw new Error("PROVIDER_KEY_ENCRYPTION_SECRET is not configured");
      }
      encryptedApiKey = await encryptApiKey(args.apiKey, secret);
    }

    const existing = await ctx.db
      .query("providerSettings")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .first();

    if (existing) {
      const updates: Record<string, unknown> = {
        providerName: args.providerName,
        endpoint: args.endpoint,
        model: args.model,
        updatedAt: now,
      };
      if (encryptedApiKey !== undefined) {
        updates.encryptedApiKey = encryptedApiKey;
      }
      await ctx.db.patch(existing._id, updates);
      return existing._id;
    }

    return await ctx.db.insert("providerSettings", {
      userId: args.userId,
      providerName: args.providerName,
      endpoint: args.endpoint,
      model: args.model,
      encryptedApiKey,
      createdAt: now,
      updatedAt: now,
    });
  },
});

/**
 * Delete provider settings by explicit userId.
 * Used by HTTP handlers when auth is resolved via opaque token (CLI device flow).
 */
export const removeById = mutation({
  args: { userId: v.string() },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("providerSettings")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .first();

    if (existing) {
      await ctx.db.delete(existing._id);
    }

    return { success: true };
  },
});
