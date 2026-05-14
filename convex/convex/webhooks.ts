import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireRole } from "./rbac";

export const list = query({
  args: {},
  handler: async (ctx) => {
    const webhooks = await ctx.db.query("webhooks").collect();
    return webhooks.map(mapWebhook);
  },
});

export const listByOrg = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const webhooks = await ctx.db
      .query("webhooks")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();
    return webhooks.map(mapWebhook);
  },
});

export const create = mutation({
  args: {
    id: v.string(),
    orgId: v.optional(v.string()),
    url: v.string(),
    events: v.array(v.string()),
    deliveryType: v.string(),
    secret: v.optional(v.string()),
    userId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId && args.orgId) {
      await requireRole(ctx, args.userId, args.orgId, "admin");
    }

    // Enforce plan gate — webhooks require pro or above
    if (args.orgId) {
      const subscription = await ctx.db
        .query("subscriptions")
        .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId!))
        .first();
      const plan = subscription?.plan ?? "free";
      const PLAN_RANK: Record<string, number> = { free: 0, pro: 1, team: 2, enterprise: 3 };
      if ((PLAN_RANK[plan] ?? 0) < PLAN_RANK["pro"]) {
        throw new Error("Webhooks require a Pro plan or above. Upgrade at usesicario.xyz/pricing");
      }
    }

    const now = new Date().toISOString();
    await ctx.db.insert("webhooks", {
      webhookId: args.id,
      orgId: args.orgId ?? "",
      url: args.url,
      events: args.events,
      deliveryType: args.deliveryType,
      secret: args.secret,
      enabled: true,
      createdAt: now,
    });
    return { id: args.id };
  },
});

export const update = mutation({
  args: {
    id: v.string(),
    url: v.optional(v.string()),
    events: v.optional(v.array(v.string())),
    deliveryType: v.optional(v.string()),
    secret: v.optional(v.string()),
    enabled: v.optional(v.boolean()),
    userId: v.optional(v.string()),
    orgId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId && args.orgId) {
      await requireRole(ctx, args.userId, args.orgId, "admin");
    }

    const webhook = await ctx.db
      .query("webhooks")
      .withIndex("by_webhookId", (q) => q.eq("webhookId", args.id))
      .first();
    if (!webhook) return null;

    const updates: Record<string, any> = {};
    if (args.url) updates.url = args.url;
    if (args.events) updates.events = args.events;
    if (args.deliveryType) updates.deliveryType = args.deliveryType;
    if (args.secret !== undefined) updates.secret = args.secret;
    if (args.enabled !== undefined) updates.enabled = args.enabled;

    await ctx.db.patch(webhook._id, updates);
    return { id: args.id };
  },
});

export const remove = mutation({
  args: {
    id: v.string(),
    userId: v.optional(v.string()),
    orgId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId && args.orgId) {
      await requireRole(ctx, args.userId, args.orgId, "admin");
    }

    const webhook = await ctx.db
      .query("webhooks")
      .withIndex("by_webhookId", (q) => q.eq("webhookId", args.id))
      .first();
    if (!webhook) return false;
    await ctx.db.delete(webhook._id);
    return true;
  },
});

export const getEnabledForEvent = query({
  args: { event: v.string() },
  handler: async (ctx, args) => {
    const webhooks = await ctx.db.query("webhooks").collect();
    return webhooks
      .filter((w) => w.enabled && w.events.includes(args.event))
      .map(mapWebhook);
  },
});

export const recordDelivery = mutation({
  args: {
    deliveryId: v.string(),
    webhookId: v.string(),
    eventType: v.string(),
    payload: v.any(),
    status: v.string(),
    responseCode: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert("webhookDeliveries", {
      deliveryId: args.deliveryId,
      webhookId: args.webhookId,
      eventType: args.eventType,
      payload: args.payload,
      status: args.status,
      responseCode: args.responseCode,
      deliveredAt: new Date().toISOString(),
    });
  },
});

function mapWebhook(w: any) {
  return {
    id: w.webhookId,
    org_id: w.orgId,
    url: w.url,
    events: w.events,
    delivery_type: w.deliveryType,
    secret: w.secret ?? null,
    enabled: w.enabled,
    created_at: w.createdAt,
  };
}
