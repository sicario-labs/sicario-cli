/**
 * Custom Rule Editor — dashboard rule authoring.
 *
 * Requirements: Req 39 — Custom Rule Editor (Tasks 39.1–39.17)
 * Requirements: Req 40 — Custom Rule Sync (Task 40)
 */

import { v } from "convex/values";
import { mutation, query } from "./_generated/server";

// ── Schema (added to schema.ts separately) ────────────────────────────────────
// customRules table: {ruleId, orgId, name, yaml, language, severity, cweId,
//   owaspCategory, isEnabled, policyMode, createdBy, createdAt, updatedAt}

// ── Queries ───────────────────────────────────────────────────────────────────

export const listByOrg = query({
  args: { orgId: v.string() },
  handler: async (ctx, { orgId }) => {
    return await ctx.db
      .query("customRules")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .collect();
  },
});

export const getById = query({
  args: { ruleId: v.string() },
  handler: async (ctx, { ruleId }) => {
    return await ctx.db
      .query("customRules")
      .withIndex("by_ruleId", (q) => q.eq("ruleId", ruleId))
      .first();
  },
});

// ── Mutations ─────────────────────────────────────────────────────────────────

export const create = mutation({
  args: {
    orgId: v.string(),
    name: v.string(),
    yaml: v.string(),
    language: v.string(),
    severity: v.string(),
    cweId: v.optional(v.string()),
    owaspCategory: v.optional(v.string()),
    isEnabled: v.boolean(),
    policyMode: v.string(), // "monitor" | "comment" | "block" | "disabled"
    createdBy: v.string(),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();
    const ruleId = `org/${args.orgId}/${args.name.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}`;
    return await ctx.db.insert("customRules", {
      ruleId,
      ...args,
      createdAt: now,
      updatedAt: now,
    });
  },
});

export const update = mutation({
  args: {
    ruleId: v.string(),
    name: v.optional(v.string()),
    yaml: v.optional(v.string()),
    language: v.optional(v.string()),
    severity: v.optional(v.string()),
    cweId: v.optional(v.string()),
    owaspCategory: v.optional(v.string()),
    isEnabled: v.optional(v.boolean()),
    policyMode: v.optional(v.string()),
  },
  handler: async (ctx, { ruleId, ...updates }) => {
    const rule = await ctx.db
      .query("customRules")
      .withIndex("by_ruleId", (q) => q.eq("ruleId", ruleId))
      .first();
    if (!rule) throw new Error("Rule not found");
    await ctx.db.patch(rule._id, { ...updates, updatedAt: new Date().toISOString() });
    return rule._id;
  },
});

export const remove = mutation({
  args: { ruleId: v.string() },
  handler: async (ctx, { ruleId }) => {
    const rule = await ctx.db
      .query("customRules")
      .withIndex("by_ruleId", (q) => q.eq("ruleId", ruleId))
      .first();
    if (rule) await ctx.db.delete(rule._id);
  },
});

/**
 * Fork a built-in rule into custom rules with "org/" prefix.
 * Task 39.15: Fork action from Built-in Rules tab.
 */
export const forkBuiltinRule = mutation({
  args: {
    orgId: v.string(),
    builtinRuleId: v.string(),
    yaml: v.string(),
    language: v.string(),
    severity: v.string(),
    createdBy: v.string(),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();
    const ruleId = `org/${args.orgId}/${args.builtinRuleId}`;
    return await ctx.db.insert("customRules", {
      ruleId,
      orgId: args.orgId,
      name: `Fork of ${args.builtinRuleId}`,
      yaml: args.yaml,
      language: args.language,
      severity: args.severity,
      isEnabled: true,
      policyMode: "monitor",
      createdBy: args.createdBy,
      createdAt: now,
      updatedAt: now,
    });
  },
});
