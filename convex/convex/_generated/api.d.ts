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
import type * as deviceAuth from "../deviceAuth.js";
import type * as findings from "../findings.js";
import type * as http from "../http.js";
import type * as memberships from "../memberships.js";
import type * as organizations from "../organizations.js";
import type * as projects from "../projects.js";
import type * as providerSettings from "../providerSettings.js";
import type * as rbac from "../rbac.js";
import type * as scans from "../scans.js";
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
  deviceAuth: typeof deviceAuth;
  findings: typeof findings;
  http: typeof http;
  memberships: typeof memberships;
  organizations: typeof organizations;
  projects: typeof projects;
  providerSettings: typeof providerSettings;
  rbac: typeof rbac;
  scans: typeof scans;
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
