import { QueryCtx, MutationCtx } from "./_generated/server";

/**
 * Role hierarchy: admin > manager > developer > viewer
 * Higher numeric value = more permissions.
 * Task 33.5: viewer role (level 0) — read-only, blocks all mutations.
 */
const ROLE_LEVELS: Record<string, number> = {
  viewer: 0,
  developer: 1,
  manager: 2,
  admin: 3,
};

export type Role = "admin" | "manager" | "developer" | "viewer";

/**
 * Look up a user's membership and role within an organization.
 */
export async function getUserMembership(
  ctx: QueryCtx | MutationCtx,
  userId: string,
  orgId: string
) {
  return await ctx.db
    .query("memberships")
    .withIndex("by_userId_orgId", (q) =>
      q.eq("userId", userId).eq("orgId", orgId)
    )
    .first();
}

/**
 * Throw if the user doesn't have at least the specified role in the org.
 * Role hierarchy: admin > manager > developer.
 */
export async function requireRole(
  ctx: QueryCtx | MutationCtx,
  userId: string,
  orgId: string,
  minimumRole: Role
) {
  const membership = await getUserMembership(ctx, userId, orgId);
  if (!membership) {
    throw new Error("Access denied: user is not a member of this organization");
  }
  const userLevel = ROLE_LEVELS[membership.role] ?? 0;
  const requiredLevel = ROLE_LEVELS[minimumRole] ?? 0;
  if (userLevel < requiredLevel) {
    throw new Error(
      `Access denied: requires '${minimumRole}' role, user has '${membership.role}'`
    );
  }
  return membership;
}

/**
 * Check if a user can access a specific team.
 * Admins can access all teams in the org. Managers/developers can only
 * access teams they are assigned to.
 */
export async function canAccessTeam(
  ctx: QueryCtx | MutationCtx,
  userId: string,
  orgId: string,
  teamId: string
): Promise<boolean> {
  const membership = await getUserMembership(ctx, userId, orgId);
  if (!membership) return false;
  if (membership.role === "admin") return true;
  return membership.teamIds.includes(teamId);
}

/**
 * Check if a user can access a project by looking up the project's teamId
 * and then checking team access.
 */
export async function canAccessProject(
  ctx: QueryCtx | MutationCtx,
  userId: string,
  orgId: string,
  projectId: string
): Promise<boolean> {
  const membership = await getUserMembership(ctx, userId, orgId);
  if (!membership) return false;
  if (membership.role === "admin") return true;

  const project = await ctx.db
    .query("projects")
    .withIndex("by_projectId", (q) => q.eq("projectId", projectId))
    .first();
  if (!project || !project.teamId) return false;
  return membership.teamIds.includes(project.teamId);
}

/**
 * Return the team IDs a user can access.
 * Admins get all teams in the org; others get only their assigned teams.
 */
export async function getAccessibleTeamIds(
  ctx: QueryCtx | MutationCtx,
  userId: string,
  orgId: string
): Promise<string[]> {
  const membership = await getUserMembership(ctx, userId, orgId);
  if (!membership) return [];
  if (membership.role === "admin") {
    const teams = await ctx.db
      .query("teams")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .collect();
    return teams.map((t) => t.teamId);
  }
  return membership.teamIds;
}
