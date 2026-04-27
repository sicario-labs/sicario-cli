import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireRole } from "./rbac";

export const list = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const projects = await ctx.db
      .query("projects")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .order("desc")
      .collect();
    return projects.map(mapProject);
  },
});

export const get = query({
  args: { id: v.string() },
  handler: async (ctx, args) => {
    const project = await ctx.db
      .query("projects")
      .withIndex("by_projectId", (q) => q.eq("projectId", args.id))
      .first();
    if (!project) return null;
    return mapProject(project);
  },
});

export const create = mutation({
  args: {
    id: v.string(),
    name: v.string(),
    repository_url: v.optional(v.string()),
    description: v.optional(v.string()),
    team_id: v.optional(v.string()),
    userId: v.optional(v.string()),
    orgId: v.string(),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId && args.orgId) {
      await requireRole(ctx, args.userId, args.orgId, "manager");
    }

    const now = new Date().toISOString();
    // Always generate a project API key so every project can authenticate CLI telemetry
    const randomPart = Array.from(crypto.getRandomValues(new Uint8Array(24)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const projectApiKey = `sic_proj_${randomPart}`;

    await ctx.db.insert("projects", {
      projectId: args.id,
      name: args.name,
      repositoryUrl: args.repository_url ?? "",
      description: args.description ?? "",
      orgId: args.orgId,
      teamId: args.team_id,
      createdAt: now,
      provisioningState: "pending",
      projectApiKey,
    });
    return { id: args.id, projectApiKey };
  },
});

export const update = mutation({
  args: {
    id: v.string(),
    name: v.optional(v.string()),
    repository_url: v.optional(v.string()),
    description: v.optional(v.string()),
    team_id: v.optional(v.string()),
    userId: v.optional(v.string()),
    orgId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId && args.orgId) {
      await requireRole(ctx, args.userId, args.orgId, "manager");
    }

    const project = await ctx.db
      .query("projects")
      .withIndex("by_projectId", (q) => q.eq("projectId", args.id))
      .first();
    if (!project) return null;

    const updates: Record<string, string> = {};
    if (args.name) updates.name = args.name;
    if (args.repository_url) updates.repositoryUrl = args.repository_url;
    if (args.description) updates.description = args.description;
    if (args.team_id) updates.teamId = args.team_id;

    await ctx.db.patch(project._id, updates);
    return { id: args.id };
  },
});

export const listByOrg = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const projects = await ctx.db
      .query("projects")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();
    return projects.map(mapProject);
  },
});

// ---------------------------------------------------------------------------
// V2 mutations & queries
// ---------------------------------------------------------------------------

/** Find a project by its repository URL (used by webhook handler). */
export const getByRepoUrl = query({
  args: { repositoryUrl: v.string() },
  handler: async (ctx, args) => {
    // No index on repositoryUrl, so we scan all projects.
    // This is acceptable because the projects table is bounded in size.
    const all = await ctx.db.query("projects").collect();
    const project = all.find((p) => p.repositoryUrl === args.repositoryUrl);
    if (!project) return null;
    return mapProject(project);
  },
});

export const createV2 = mutation({
  args: {
    id: v.string(),
    name: v.string(),
    repositoryUrl: v.string(),
    orgId: v.string(),
    framework: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();
    // Generate a proper project API key with prefix
    const randomPart = Array.from(crypto.getRandomValues(new Uint8Array(24)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const projectApiKey = `sic_proj_${randomPart}`;

    await ctx.db.insert("projects", {
      projectId: args.id,
      name: args.name,
      repositoryUrl: args.repositoryUrl,
      description: "",
      orgId: args.orgId,
      createdAt: now,
      provisioningState: "pending",
      framework: args.framework,
      projectApiKey,
    });

    return { id: args.id, projectApiKey };
  },
});

/** Enforce the provisioning state machine. Returns true on success, false on invalid transition. */
export const transitionProvisioningState = mutation({
  args: {
    projectId: v.string(),
    from: v.string(),
    to: v.string(),
  },
  handler: async (ctx, args) => {
    // Reject active → pending
    if (args.from === "active" && args.to === "pending") {
      return false;
    }

    const project = await ctx.db
      .query("projects")
      .withIndex("by_projectId", (q) => q.eq("projectId", args.projectId))
      .first();

    if (!project) return false;

    const currentState = project.provisioningState ?? "active";
    if (currentState !== args.from) return false;

    await ctx.db.patch(project._id, { provisioningState: args.to });
    return true;
  },
});

export const getByApiKey = query({
  args: { projectApiKey: v.string() },
  handler: async (ctx, args) => {
    const project = await ctx.db
      .query("projects")
      .withIndex("by_projectApiKey", (q) =>
        q.eq("projectApiKey", args.projectApiKey)
      )
      .first();
    if (!project) return null;
    return mapProject(project);
  },
});

/** Rotate the project API key. Returns the new key. */
export const regenerateApiKey = mutation({
  args: {
    projectId: v.string(),
    userId: v.string(),
    orgId: v.string(),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.userId, args.orgId, "manager");

    const project = await ctx.db
      .query("projects")
      .withIndex("by_projectId", (q) => q.eq("projectId", args.projectId))
      .first();
    if (!project) throw new Error("Project not found");

    const randomPart = Array.from(crypto.getRandomValues(new Uint8Array(24)))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const projectApiKey = `sic_proj_${randomPart}`;

    await ctx.db.patch(project._id, { projectApiKey });
    return { projectApiKey };
  },
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Pure function — applies read-time defaults for V2 optional fields. */
export function resolveProjectDefaults(p: {
  provisioningState?: string;
  severityThreshold?: string;
  autoFixEnabled?: boolean;
}) {
  return {
    provisioningState: p.provisioningState ?? "active",
    severityThreshold: p.severityThreshold ?? "high",
    autoFixEnabled: p.autoFixEnabled ?? true,
  };
}

function mapProject(p: any) {
  const defaults = resolveProjectDefaults(p);
  return {
    id: p.projectId,
    name: p.name,
    repository_url: p.repositoryUrl,
    description: p.description,
    org_id: p.orgId ?? null,
    team_id: p.teamId ?? null,
    created_at: p.createdAt,
    provisioning_state: defaults.provisioningState,
    framework: p.framework ?? null,
    project_api_key: p.projectApiKey ?? null,
    severity_threshold: defaults.severityThreshold,
    auto_fix_enabled: defaults.autoFixEnabled,
  };
}
