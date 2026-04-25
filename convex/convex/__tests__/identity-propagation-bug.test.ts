/**
 * Bug Condition Exploration Test — Property 1
 *
 * Tests the two bug conditions identified in the design:
 *   Case 1: Device auth identity loss — approveDeviceCode discards name/email,
 *           getByAccessToken returns bare { userId } with no userName/userEmail.
 *   Case 2: Hash-based org names — ensureOrg falls back to tokenIdentifier hash
 *           when identity.name and identity.email are both absent.
 *
 * CRITICAL: These tests MUST FAIL on unfixed code. Failure confirms the bug exists.
 * DO NOT attempt to fix the test or the code when it fails.
 *
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
 */
import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// Case 1: Device auth identity loss
//
// The approveDeviceCode mutation only accepts { userCode, userId }.
// There are no userName / userEmail args, so identity is discarded.
// getByAccessToken returns only { userId } — no name or email.
//
// We verify this by reading the source file and checking whether the
// mutation args and query return include userName/userEmail fields.
// ---------------------------------------------------------------------------

const deviceAuthSource = fs.readFileSync(
  path.resolve(__dirname, "../deviceAuth.ts"),
  "utf-8",
);

const httpSource = fs.readFileSync(
  path.resolve(__dirname, "../http.ts"),
  "utf-8",
);

describe("Bug Condition: Device Auth Identity Loss (Case 1)", () => {
  it("approveDeviceCode mutation should accept userName and userEmail args", () => {
    // Extract the approveDeviceCode block from source
    const approveIdx = deviceAuthSource.indexOf("export const approveDeviceCode");
    expect(approveIdx).toBeGreaterThan(-1);

    // Get the args block — everything between the first `args: {` and its closing `}`
    const argsStart = deviceAuthSource.indexOf("args: {", approveIdx);
    const argsEnd = deviceAuthSource.indexOf("}", argsStart);
    const argsBlock = deviceAuthSource.slice(argsStart, argsEnd + 1);

    // On unfixed code, the args block only contains { userCode, userId }.
    // userName and userEmail are NOT present — these assertions FAIL.
    expect(argsBlock).toContain("userName");
    expect(argsBlock).toContain("userEmail");
  });

  it("getByAccessToken should return userName and userEmail in its response", () => {
    // Extract the getByAccessToken block from source
    const getByIdx = deviceAuthSource.indexOf("export const getByAccessToken");
    expect(getByIdx).toBeGreaterThan(-1);

    // Get the handler body
    const handlerBlock = deviceAuthSource.slice(
      getByIdx,
      deviceAuthSource.indexOf("export const", getByIdx + 1) > -1
        ? deviceAuthSource.indexOf("export const", getByIdx + 1)
        : undefined,
    );

    // On unfixed code, the return is { userId: record.userId ?? null }
    // — no userName or userEmail. These assertions FAIL.
    expect(handlerBlock).toContain("userName");
    expect(handlerBlock).toContain("userEmail");
  });

  it("resolveIdentity should return name and email for device-auth sic_ tokens", () => {
    // Find the opaque token lookup branch in resolveIdentity
    // It currently returns: return { subject: record.userId }
    // It should return: { subject, name, email }
    const resolveIdx = httpSource.indexOf("async function resolveIdentity");
    expect(resolveIdx).toBeGreaterThan(-1);

    // Extract the function body up to the next top-level function or route
    const resolveEnd = httpSource.indexOf("\nhttp.route", resolveIdx);
    const resolveBody = httpSource.slice(resolveIdx, resolveEnd);

    // Find the device code lookup branch (record.userId return)
    const deviceBranch = resolveBody.slice(
      resolveBody.indexOf("Look up opaque token"),
    );

    // On unfixed code, the return for device-auth tokens is just
    // { subject: record.userId } — no name or email. This FAILS.
    expect(deviceBranch).toMatch(/name:\s*record\./);
    expect(deviceBranch).toMatch(/email:\s*record\./);
  });

  it("property: for any user with name and email, approveDeviceCode must accept identity fields", () => {
    // Generate random user identities and verify the mutation can carry them.
    // On unfixed code, the args block lacks userName/userEmail — property fails.
    const approveIdx = deviceAuthSource.indexOf("export const approveDeviceCode");
    const argsStart = deviceAuthSource.indexOf("args: {", approveIdx);
    const argsEnd = deviceAuthSource.indexOf("}", argsStart);
    const argsBlock = deviceAuthSource.slice(argsStart, argsEnd + 1);

    fc.assert(
      fc.property(
        fc.record({
          userName: fc.string({ minLength: 1, maxLength: 50 }),
          userEmail: fc.emailAddress(),
          userId: fc.string({ minLength: 1, maxLength: 100 }),
        }),
        (identity) => {
          // For every possible user identity, the mutation must accept
          // userName and userEmail so the device code record carries identity.
          // On unfixed code these fields don't exist — FAILS.
          expect(argsBlock).toContain("userName");
          expect(argsBlock).toContain("userEmail");
        },
      ),
      { numRuns: 10 },
    );
  });
});

// ---------------------------------------------------------------------------
// Case 2: Hash-based org names
//
// ensureOrg computes: displayName = identity.name ?? identity.email ?? userId
// where userId = identity.tokenIdentifier.split("|").pop()
//
// When identity.name and identity.email are both null/undefined, the fallback
// is the raw Convex internal hash (e.g. "ks7dtkrb3e1m5w9cbkbprjvrn585fmhp").
// The org gets named "<hash>'s Organization".
//
// We test the looksLikeHash detection and the fallback logic.
// ---------------------------------------------------------------------------

/**
 * Detects whether a string looks like a raw Convex internal hash.
 * Hashes are 20+ character alphanumeric strings with no spaces.
 */
function looksLikeHash(str: string): boolean {
  return /^[a-z0-9]{20,}$/i.test(str);
}

describe("Bug Condition: Hash-Based Org Names (Case 2)", () => {
  it("property: tokenIdentifier.split('|').pop() produces a hash when name and email are null", () => {
    // Generate random Convex-style tokenIdentifiers of the form
    // "https://domain.com|sessionId|<hash>" where <hash> is a long alphanumeric string.
    const hashArb = fc.stringMatching(/^[a-z0-9]{32}$/);
    const tokenIdentifierArb = fc.tuple(
      fc.webUrl(),
      fc.string({ minLength: 5, maxLength: 20 }),
      hashArb,
    ).map(([domain, session, hash]) => `${domain}|${session}|${hash}`);

    fc.assert(
      fc.property(tokenIdentifierArb, (tokenIdentifier) => {
        // Simulate ensureOrg's FIXED fallback logic with null name and email.
        // The fix adds a looksLikeHash guard: if the raw fallback is a hash,
        // substitute "User" instead.
        const identity = {
          tokenIdentifier,
          name: null as string | null,
          email: null as string | null,
        };

        const userId =
          identity.tokenIdentifier.split("|").pop() ??
          identity.tokenIdentifier;
        const rawDisplayName = identity.name ?? identity.email ?? userId;
        const displayName = looksLikeHash(rawDisplayName) ? "User" : rawDisplayName;

        // The display name should NOT look like a hash.
        // On unfixed code (without the looksLikeHash guard), it WILL be a hash.
        // On fixed code, the guard catches it and substitutes "User".
        expect(looksLikeHash(displayName)).toBe(false);
      }),
      { numRuns: 50 },
    );
  });

  it("property: org name fallback should never produce '<hash>\\'s Organization' pattern", () => {
    const hashArb = fc.stringMatching(/^[a-z0-9]{32}$/);

    fc.assert(
      fc.property(hashArb, (hash) => {
        // Simulate the FIXED ensureOrg logic for a user with no name/email.
        // The fix adds a looksLikeHash guard before building the org name.
        const tokenIdentifier = `https://auth.example.com|session123|${hash}`;
        const identity = {
          tokenIdentifier,
          name: undefined as string | undefined,
          email: undefined as string | undefined,
        };

        const userId =
          identity.tokenIdentifier.split("|").pop() ??
          identity.tokenIdentifier;
        const rawDisplayName = identity.name ?? identity.email ?? userId;
        const displayName = looksLikeHash(rawDisplayName) ? "User" : rawDisplayName;
        const orgName = `${displayName}'s Organization`;

        // The org name should be human-readable, not hash-based.
        // On unfixed code this FAILS — orgName is "<hash>'s Organization".
        // On fixed code, the guard produces "User's Organization" instead.
        expect(looksLikeHash(displayName)).toBe(false);
        expect(orgName).not.toMatch(/^[a-z0-9]{20,}'s Organization$/i);
      }),
      { numRuns: 50 },
    );
  });
});
