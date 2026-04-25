/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as analytics from "../analytics.js";
import type * as auth from "../auth.js";
import type * as autoFixPRs from "../autoFixPRs.js";
import type * as crons from "../crons.js";
import type * as deviceAuth from "../deviceAuth.js";
import type * as findings from "../findings.js";
import type * as githubApp from "../githubApp.js";
import type * as githubAppNode from "../githubAppNode.js";
import type * as http from "../http.js";
import type * as invitations from "../invitations.js";
import type * as memberships from "../memberships.js";
import type * as organizations from "../organizations.js";
import type * as prChecks from "../prChecks.js";
import type * as prSastEngine from "../prSastEngine.js";
import type * as prSastRules from "../prSastRules.js";
import type * as prScanWorkflow from "../prScanWorkflow.js";
import type * as projects from "../projects.js";
import type * as providerSettings from "../providerSettings.js";
import type * as rbac from "../rbac.js";
import type * as scans from "../scans.js";
import type * as scheduledScans from "../scheduledScans.js";
import type * as sso from "../sso.js";
import type * as teams from "../teams.js";
import type * as userProfiles from "../userProfiles.js";
import type * as webhooks from "../webhooks.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  analytics: typeof analytics;
  auth: typeof auth;
  autoFixPRs: typeof autoFixPRs;
  crons: typeof crons;
  deviceAuth: typeof deviceAuth;
  findings: typeof findings;
  githubApp: typeof githubApp;
  githubAppNode: typeof githubAppNode;
  http: typeof http;
  invitations: typeof invitations;
  memberships: typeof memberships;
  organizations: typeof organizations;
  prChecks: typeof prChecks;
  prSastEngine: typeof prSastEngine;
  prSastRules: typeof prSastRules;
  prScanWorkflow: typeof prScanWorkflow;
  projects: typeof projects;
  providerSettings: typeof providerSettings;
  rbac: typeof rbac;
  scans: typeof scans;
  scheduledScans: typeof scheduledScans;
  sso: typeof sso;
  teams: typeof teams;
  userProfiles: typeof userProfiles;
  webhooks: typeof webhooks;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};
