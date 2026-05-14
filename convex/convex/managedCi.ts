/**
 * Managed CI Config — zero-config repo onboarding.
 *
 * Generates and commits CI workflow files to repositories via the SCM API.
 * Source code never leaves the customer's infrastructure — only the workflow
 * file (which runs sicario ci on their own CI runners) is written.
 *
 * Onboarding flow:
 *   1. Connect GitHub/GitLab org via OAuth (write-only scopes: workflow + secret)
 *   2. Select repositories to onboard
 *   3. Generate CI workflow YAML
 *   4. Commit workflow file to repo default branch via SCM API
 *   5. Store SICARIO_API_KEY as repository secret via SCM API
 *   6. Display repo status: Pending → Active → Error
 *
 * Requirements: Req 20 — Managed CI Config (Tasks 20.1–20.8)
 */

import { v } from "convex/values";
import { action, mutation, query } from "./_generated/server";
import { api } from "./_generated/api";

// ── Schema additions (added to schema.ts separately) ─────────────────────────
// managedRepos table tracks onboarding status per repo.

// ── Workflow file generators ──────────────────────────────────────────────────

/**
 * Generate a GitHub Actions workflow file for sicario CI scanning.
 *
 * Zero-exfiltration notice is included as a comment in the generated file.
 * The workflow runs entirely on the customer's CI runners — no source code
 * is transmitted to Sicario Cloud.
 */
export function generateGitHubWorkflow(orgId: string): string {
  return `# Sicario Security Scan
# Zero-exfiltration notice: This workflow runs entirely on your CI runners.
# Only structured finding metadata (rule_id, file_path, line, severity) is
# uploaded to Sicario Cloud. Source code never leaves your infrastructure.
name: Sicario Security Scan
on:
  pull_request: {}
  schedule:
    - cron: '0 2 * * 1'  # weekly full scan, Monday 02:00 UTC
  push:
    branches: [main, master]

jobs:
  sicario:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # required for diff-aware scans
      - name: Install Sicario
        run: curl -fsSL https://install.usesicario.xyz | sh
      - name: Run Sicario CI scan
        run: sicario ci --publish
        env:
          SICARIO_API_KEY: \${{ secrets.SICARIO_API_KEY }}
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
`;
}

/**
 * Generate a GitLab CI configuration addition for sicario CI scanning.
 */
export function generateGitLabCi(orgId: string): string {
  return `# Sicario Security Scan
# Zero-exfiltration notice: This job runs entirely on your GitLab runners.
# Only structured finding metadata is uploaded to Sicario Cloud.
# Source code never leaves your infrastructure.

sicario-security-scan:
  stage: test
  image: ubuntu:22.04
  script:
    - curl -fsSL https://install.usesicario.xyz | sh
    - sicario ci --publish
  variables:
    SICARIO_API_KEY: \$SICARIO_API_KEY
  rules:
    - if: \$CI_PIPELINE_SOURCE == "merge_request_event"
    - if: \$CI_COMMIT_BRANCH == \$CI_DEFAULT_BRANCH
`;
}

// ── Convex mutations ──────────────────────────────────────────────────────────

/**
 * Initiate onboarding for a repository.
 * Creates a managedRepo record with status "pending".
 */
export const initiateOnboarding = mutation({
  args: {
    orgId: v.string(),
    repoFullName: v.string(),   // e.g. "owner/repo"
    scmProvider: v.string(),    // "github" | "gitlab"
    defaultBranch: v.optional(v.string()),
  },
  handler: async (ctx, { orgId, repoFullName, scmProvider, defaultBranch }) => {
    const now = new Date().toISOString();
    const repoId = `repo-${orgId}-${repoFullName.replace("/", "-")}-${Date.now()}`;

    // Check if already onboarded
    const existing = await ctx.db
      .query("managedRepos")
      .withIndex("by_orgId_repoFullName", (q) =>
        q.eq("orgId", orgId).eq("repoFullName", repoFullName)
      )
      .first();

    if (existing) {
      return existing._id;
    }

    return await ctx.db.insert("managedRepos", {
      repoId,
      orgId,
      repoFullName,
      scmProvider,
      defaultBranch: defaultBranch ?? "main",
      onboardingStatus: "pending",
      workflowFilePath: scmProvider === "github"
        ? ".github/workflows/sicario.yml"
        : ".gitlab-ci.yml",
      createdAt: now,
      updatedAt: now,
    });
  },
});

/**
 * Update the onboarding status of a managed repo.
 * Called after workflow file commit succeeds or fails.
 */
export const updateOnboardingStatus = mutation({
  args: {
    orgId: v.string(),
    repoFullName: v.string(),
    status: v.union(
      v.literal("pending"),
      v.literal("active"),
      v.literal("error")
    ),
    errorMessage: v.optional(v.string()),
  },
  handler: async (ctx, { orgId, repoFullName, status, errorMessage }) => {
    const repo = await ctx.db
      .query("managedRepos")
      .withIndex("by_orgId_repoFullName", (q) =>
        q.eq("orgId", orgId).eq("repoFullName", repoFullName)
      )
      .first();

    if (!repo) return null;

    await ctx.db.patch(repo._id, {
      onboardingStatus: status,
      errorMessage: errorMessage ?? undefined,
      updatedAt: new Date().toISOString(),
    });

    return repo._id;
  },
});

/**
 * List all managed repos for an org with their onboarding status.
 */
export const listByOrg = query({
  args: { orgId: v.string() },
  handler: async (ctx, { orgId }) => {
    return await ctx.db
      .query("managedRepos")
      .withIndex("by_orgId", (q) => q.eq("orgId", orgId))
      .collect();
  },
});

/**
 * Remove a repo from Sicario management.
 * Deletes the managedRepo record. The caller is responsible for
 * deleting the workflow file and revoking the service token via SCM API.
 */
export const removeRepo = mutation({
  args: { orgId: v.string(), repoFullName: v.string() },
  handler: async (ctx, { orgId, repoFullName }) => {
    const repo = await ctx.db
      .query("managedRepos")
      .withIndex("by_orgId_repoFullName", (q) =>
        q.eq("orgId", orgId).eq("repoFullName", repoFullName)
      )
      .first();

    if (repo) {
      await ctx.db.delete(repo._id);
    }
  },
});

/**
 * Get the generated workflow file content for a repo.
 * Returns the YAML string ready to commit via SCM API.
 */
export const getWorkflowContent = query({
  args: { orgId: v.string(), repoFullName: v.string() },
  handler: async (ctx, { orgId, repoFullName }) => {
    const repo = await ctx.db
      .query("managedRepos")
      .withIndex("by_orgId_repoFullName", (q) =>
        q.eq("orgId", orgId).eq("repoFullName", repoFullName)
      )
      .first();

    if (!repo) return null;

    const content = repo.scmProvider === "github"
      ? generateGitHubWorkflow(orgId)
      : generateGitLabCi(orgId);

    return {
      filePath: repo.workflowFilePath,
      content,
      scmProvider: repo.scmProvider,
      defaultBranch: repo.defaultBranch,
    };
  },
});
