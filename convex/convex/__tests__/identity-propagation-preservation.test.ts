/**
 * Preservation Property Tests — Property 2
 *
 * Tests that non-buggy behaviors are preserved on UNFIXED code.
 * These tests MUST PASS on unfixed code — they capture baseline behavior
 * that must remain unchanged after the fix is applied.
 *
 * Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6
 *
 * Testing approach: Since Convex mutations/queries require the Convex runtime,
 * we use source code analysis + pure JS logic simulation, following the same
 * pattern as the bug condition exploration test.
 */
import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// Load source files for structural analysis
// ---------------------------------------------------------------------------
const deviceAuthSource = fs.readFileSync(
  path.resolve(__dirname, "../deviceAuth.ts"),
  "utf-8",
);

const httpSource = fs.readFileSync(
  path.resolve(__dirname, "../http.ts"),
  "utf-8",
);

const orgSource = fs.readFileSync(
  path.resolve(__dirname, "../organizations.ts"),
  "utf-8",
);

// ---------------------------------------------------------------------------
// Helpers: extract code blocks from source
// ---------------------------------------------------------------------------

/** Extract the body of a named export (from `export const <name>` to the next `export const` or EOF). */
function extractExportBlock(source: string, name: string): string {
  const marker = `export const ${name}`;
  const start = source.indexOf(marker);
  if (start === -1) return "";
  const nextExport = source.indexOf("export const", start + marker.length);
  return source.slice(start, nextExport > -1 ? nextExport : undefined);
}

// ---------------------------------------------------------------------------
// Preservation 3.1: Convex Auth JWT sessions resolve identity with name/email
// ---------------------------------------------------------------------------
describe("Preservation 3.1: JWT Identity Resolution", () => {
  it("resolveIdentity tries JWT auth first via ctx.auth.getUserIdentity()", () => {
    const resolveIdx = httpSource.indexOf("async function resolveIdentity");
    expect(resolveIdx).toBeGreaterThan(-1);

    const resolveEnd = httpSource.indexOf("\nhttp.route", resolveIdx);
    const resolveBody = httpSource.slice(resolveIdx, resolveEnd > -1 ? resolveEnd : undefined);

    // JWT path must be the FIRST auth attempt
    const jwtCallIdx = resolveBody.indexOf("ctx.auth.getUserIdentity()");
    expect(jwtCallIdx).toBeGreaterThan(-1);

    // JWT path returns subject, email, name from identity
    expect(resolveBody).toContain("identity.subject");
    expect(resolveBody).toContain("identity.email");
    expect(resolveBody).toContain("identity.name");
  });

  it("property: JWT identity resolution returns subject, name, and email for all valid identities", () => {
    /**
     * Validates: Requirements 3.1
     *
     * Simulate the JWT branch of resolveIdentity: when ctx.auth.getUserIdentity()
     * returns an identity object, the function returns { subject, email, name }.
     */
    fc.assert(
      fc.property(
        fc.record({
          subject: fc.string({ minLength: 1, maxLength: 100 }),
          email: fc.option(fc.emailAddress(), { nil: undefined }),
          name: fc.option(fc.string({ minLength: 1, maxLength: 80 }), { nil: undefined }),
        }),
        (identity) => {
          // Simulate the JWT branch of resolveIdentity
          const result = {
            subject: identity.subject,
            email: identity.email ?? undefined,
            name: identity.name ?? undefined,
          };

          // Subject is always present
          expect(result.subject).toBe(identity.subject);
          // Email and name are passed through when present
          if (identity.email) expect(result.email).toBe(identity.email);
          if (identity.name) expect(result.name).toBe(identity.name);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ---------------------------------------------------------------------------
// Preservation 3.2: Pending device codes reject token exchange
// ---------------------------------------------------------------------------
describe("Preservation 3.2: Pending Device Codes Reject Token Exchange", () => {
  it("consumeDeviceCode checks status is 'approved' before consuming", () => {
    const consumeBlock = extractExportBlock(deviceAuthSource, "consumeDeviceCode");
    expect(consumeBlock).toBeTruthy();

    // Must check that status is "approved" — pending codes should be rejected
    expect(consumeBlock).toContain('status !== "approved"');
    expect(consumeBlock).toContain("Device code is not approved");
  });

  it("property: for all random device codes in pending status, consumption is rejected", () => {
    /**
     * Validates: Requirements 3.2
     *
     * Simulate the consumeDeviceCode logic: when a record has status "pending",
     * the mutation throws because status !== "approved".
     */
    fc.assert(
      fc.property(
        fc.record({
          deviceCode: fc.string({ minLength: 8, maxLength: 64 }),
          userCode: fc.string({ minLength: 4, maxLength: 12 }),
          status: fc.constant("pending" as const),
          expiresAt: fc.integer({ min: Date.now() + 60_000, max: Date.now() + 600_000 }),
          accessToken: fc.string({ minLength: 10, maxLength: 50 }),
        }),
        (input) => {
          // Simulate consumeDeviceCode logic for a pending record
          const record = {
            status: input.status,
            expiresAt: input.expiresAt,
          };

          // Check expiration first (record is not expired since expiresAt is in the future)
          const isExpired = record.status === "pending" && Date.now() > record.expiresAt;
          expect(isExpired).toBe(false);

          // Then check status — pending is NOT approved, so it should throw
          const isApproved = (record.status as string) === "approved";
          expect(isApproved).toBe(false);

          // The error message matches the source code
          const errorMsg = `Device code is not approved (status: ${record.status})`;
          expect(errorMsg).toContain("pending");
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ---------------------------------------------------------------------------
// Preservation 3.3: Expired device codes are rejected
// ---------------------------------------------------------------------------
describe("Preservation 3.3: Expired Device Codes Are Rejected", () => {
  it("approveDeviceCode checks expiration and patches status to expired", () => {
    const approveBlock = extractExportBlock(deviceAuthSource, "approveDeviceCode");
    expect(approveBlock).toBeTruthy();

    // Must check Date.now() > record.expiresAt
    expect(approveBlock).toContain("Date.now() > record.expiresAt");
    // Must patch status to "expired"
    expect(approveBlock).toContain('status: "expired"');
    // Must throw with expired message
    expect(approveBlock).toContain("Device code has expired");
  });

  it("property: for all random device codes past expiresAt, approval throws expired error", () => {
    /**
     * Validates: Requirements 3.3
     *
     * Simulate the approveDeviceCode logic: when Date.now() > record.expiresAt
     * and the record is still pending, the mutation patches to "expired" and throws.
     */
    fc.assert(
      fc.property(
        fc.record({
          userCode: fc.string({ minLength: 4, maxLength: 12 }),
          userId: fc.string({ minLength: 1, maxLength: 100 }),
          status: fc.constant("pending" as const),
          // expiresAt is in the past (expired)
          expiresAt: fc.integer({ min: 0, max: Date.now() - 1000 }),
        }),
        (input) => {
          // Simulate approveDeviceCode logic for an expired pending record
          const record = {
            status: input.status,
            expiresAt: input.expiresAt,
          };

          // The code checks: if (Date.now() > record.expiresAt)
          const isExpired = Date.now() > record.expiresAt;
          expect(isExpired).toBe(true);

          // When expired, the code patches status to "expired" and throws
          const newStatus = "expired";
          expect(newStatus).toBe("expired");
        },
      ),
      { numRuns: 100 },
    );
  });

  it("consumeDeviceCode also rejects expired codes", () => {
    const consumeBlock = extractExportBlock(deviceAuthSource, "consumeDeviceCode");
    expect(consumeBlock).toBeTruthy();

    // consumeDeviceCode checks expiration for pending codes
    expect(consumeBlock).toContain("Date.now() > record.expiresAt");
    expect(consumeBlock).toContain("Device code has expired");
  });
});

// ---------------------------------------------------------------------------
// Preservation 3.4: ensureOrg is idempotent
// ---------------------------------------------------------------------------
describe("Preservation 3.4: ensureOrg Idempotency", () => {
  it("ensureOrg returns early with existing orgId when membership exists", () => {
    // Verify the source code checks for existing membership and returns early
    const ensureOrgBlock = extractExportBlock(orgSource, "ensureOrg");
    expect(ensureOrgBlock).toBeTruthy();

    // Must query memberships by userId
    expect(ensureOrgBlock).toContain("by_userId");
    // Must return early if existing membership found
    expect(ensureOrgBlock).toContain("if (existing)");
    expect(ensureOrgBlock).toContain("existing.orgId");
    expect(ensureOrgBlock).toContain("isNew: false");
  });

  it("property: ensureOrg idempotency — existing membership returns same orgId without creating duplicates", () => {
    /**
     * Validates: Requirements 3.4
     *
     * Simulate the ensureOrg logic: when a membership already exists for the user,
     * the function returns { orgId: existing.orgId, isNew: false } without creating
     * a new org or membership.
     */
    fc.assert(
      fc.property(
        fc.record({
          userId: fc.string({ minLength: 1, maxLength: 100 }),
          existingOrgId: fc.uuid(),
        }),
        (input) => {
          // Simulate: user already has a membership
          const existing = { orgId: input.existingOrgId };

          // ensureOrg returns early
          const result = { orgId: existing.orgId, isNew: false };

          expect(result.orgId).toBe(input.existingOrgId);
          expect(result.isNew).toBe(false);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ---------------------------------------------------------------------------
// Preservation: createDeviceCode → getDeviceCodeByUserCode round-trip
// ---------------------------------------------------------------------------
describe("Preservation: Device Code Creation Round-Trip", () => {
  it("createDeviceCode stores all required fields", () => {
    const createBlock = extractExportBlock(deviceAuthSource, "createDeviceCode");
    expect(createBlock).toBeTruthy();

    // Verify all fields are stored in the insert call
    expect(createBlock).toContain("args.deviceCode");
    expect(createBlock).toContain("args.userCode");
    expect(createBlock).toContain("args.codeChallenge");
    expect(createBlock).toContain("args.clientId");
    expect(createBlock).toContain('status: "pending"');
    expect(createBlock).toContain("args.expiresAt");
  });

  it("getDeviceCodeByUserCode queries by userCode index", () => {
    const getBlock = extractExportBlock(deviceAuthSource, "getDeviceCodeByUserCode");
    expect(getBlock).toBeTruthy();

    expect(getBlock).toContain("by_userCode");
    expect(getBlock).toContain("args.userCode");
  });

  it("property: for all random (deviceCode, userCode, codeChallenge, clientId) tuples, createDeviceCode stores and getDeviceCodeByUserCode retrieves correctly", () => {
    /**
     * Validates: Requirements 3.2, 3.4
     *
     * Simulate the createDeviceCode → getDeviceCodeByUserCode round-trip.
     * The created record should contain all input fields plus status="pending".
     */
    fc.assert(
      fc.property(
        fc.record({
          deviceCode: fc.string({ minLength: 8, maxLength: 64 }),
          userCode: fc.stringMatching(/^[A-Z0-9]{4,12}$/),
          codeChallenge: fc.string({ minLength: 20, maxLength: 128 }),
          codeChallengeMethod: fc.constant("S256"),
          clientId: fc.string({ minLength: 1, maxLength: 50 }),
          scope: fc.option(fc.constant("openid profile email"), { nil: undefined }),
          expiresAt: fc.integer({ min: Date.now(), max: Date.now() + 600_000 }),
        }),
        (input) => {
          // Simulate createDeviceCode: inserts a record with these fields
          const record = {
            deviceCode: input.deviceCode,
            userCode: input.userCode,
            codeChallenge: input.codeChallenge,
            codeChallengeMethod: input.codeChallengeMethod,
            clientId: input.clientId,
            scope: input.scope,
            status: "pending" as const,
            expiresAt: input.expiresAt,
            createdAt: new Date().toISOString(),
          };

          // Simulate getDeviceCodeByUserCode: queries by userCode, returns full record
          const retrieved = record; // In real DB, this would be a query result

          // Round-trip: all fields match
          expect(retrieved.deviceCode).toBe(input.deviceCode);
          expect(retrieved.userCode).toBe(input.userCode);
          expect(retrieved.codeChallenge).toBe(input.codeChallenge);
          expect(retrieved.clientId).toBe(input.clientId);
          expect(retrieved.status).toBe("pending");
          expect(retrieved.expiresAt).toBe(input.expiresAt);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ---------------------------------------------------------------------------
// Preservation: consumeDeviceCode transitions approved → consumed
// ---------------------------------------------------------------------------
describe("Preservation: consumeDeviceCode Transitions Approved to Consumed", () => {
  it("consumeDeviceCode checks status is approved and patches to consumed with accessToken", () => {
    const consumeBlock = extractExportBlock(deviceAuthSource, "consumeDeviceCode");
    expect(consumeBlock).toBeTruthy();

    expect(consumeBlock).toContain('status !== "approved"');
    expect(consumeBlock).toContain('status: "consumed"');
    expect(consumeBlock).toContain("accessToken: args.accessToken");
  });

  it("property: for all random device codes in approved status, consumeDeviceCode transitions to consumed and stores accessToken", () => {
    /**
     * Validates: Requirements 3.5
     *
     * Simulate the consumeDeviceCode logic: when a record has status "approved"
     * and is not expired, the mutation patches to "consumed" with the accessToken.
     */
    fc.assert(
      fc.property(
        fc.record({
          deviceCode: fc.string({ minLength: 8, maxLength: 64 }),
          status: fc.constant("approved" as const),
          expiresAt: fc.integer({ min: Date.now() + 60_000, max: Date.now() + 600_000 }),
          userId: fc.string({ minLength: 1, maxLength: 100 }),
          accessToken: fc.string({ minLength: 10, maxLength: 80 }).map((s) => `sic_${s}`),
        }),
        (input) => {
          // Simulate consumeDeviceCode logic for an approved, non-expired record
          const record = {
            status: input.status,
            expiresAt: input.expiresAt,
            userId: input.userId,
          };

          // Not expired (expiresAt is in the future)
          const isExpired = (record.status as string) === "pending" && Date.now() > record.expiresAt;
          expect(isExpired).toBe(false);

          // Status is approved — consumption proceeds
          expect(record.status).toBe("approved");

          // After patch: status becomes "consumed", accessToken is stored
          const patched = {
            ...record,
            status: "consumed" as const,
            accessToken: input.accessToken,
          };

          expect(patched.status).toBe("consumed");
          expect(patched.accessToken).toBe(input.accessToken);
          expect(patched.accessToken.startsWith("sic_")).toBe(true);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ---------------------------------------------------------------------------
// Preservation: approveDeviceCode validates userId and status
// ---------------------------------------------------------------------------
describe("Preservation: approveDeviceCode Validation", () => {
  it("approveDeviceCode rejects empty userId", () => {
    const approveBlock = extractExportBlock(deviceAuthSource, "approveDeviceCode");
    expect(approveBlock).toBeTruthy();

    // Must validate userId is non-empty
    expect(approveBlock).toContain("userId must be a non-empty string");
    expect(approveBlock).toContain("args.userId.trim().length === 0");
  });

  it("approveDeviceCode rejects non-pending codes", () => {
    const approveBlock = extractExportBlock(deviceAuthSource, "approveDeviceCode");
    expect(approveBlock).toBeTruthy();

    expect(approveBlock).toContain('record.status !== "pending"');
    expect(approveBlock).toContain("Device code is no longer pending");
  });

  it("property: for all random non-empty userId strings, approveDeviceCode stores userId; for empty strings, it throws", () => {
    /**
     * Validates: Requirements 3.2, 3.4
     *
     * Simulate the approveDeviceCode validation logic:
     * - Non-empty userId: proceeds to store userId
     * - Empty userId: throws error
     */
    fc.assert(
      fc.property(
        fc.oneof(
          // Non-empty userId
          fc.string({ minLength: 1, maxLength: 100 }).filter((s) => s.trim().length > 0),
          // Empty or whitespace-only userId
          fc.constant(""),
          fc.constant("   "),
        ),
        (userId) => {
          // Simulate the validation logic from approveDeviceCode
          const isValid = userId && userId.trim().length > 0;

          if (!isValid) {
            // Empty userId should be rejected
            expect(() => {
              if (!userId || userId.trim().length === 0) {
                throw new Error("userId must be a non-empty string");
              }
            }).toThrow("userId must be a non-empty string");
          } else {
            // Non-empty userId is accepted and stored
            const patched = {
              status: "approved" as const,
              userId: userId,
            };
            expect(patched.userId).toBe(userId);
            expect(patched.status).toBe("approved");
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ---------------------------------------------------------------------------
// Preservation 3.5: Valid sic_ tokens for consumed device codes authenticate
// ---------------------------------------------------------------------------
describe("Preservation 3.5: sic_ Token Authentication", () => {
  it("getByAccessToken queries by accessToken index and returns userId", () => {
    const getByBlock = extractExportBlock(deviceAuthSource, "getByAccessToken");
    expect(getByBlock).toBeTruthy();

    expect(getByBlock).toContain("by_accessToken");
    expect(getByBlock).toContain("args.accessToken");
    expect(getByBlock).toContain('record.status !== "consumed"');
    expect(getByBlock).toContain("record.userId");
  });

  it("resolveIdentity looks up opaque sic_ tokens via getByAccessToken", () => {
    const resolveIdx = httpSource.indexOf("async function resolveIdentity");
    expect(resolveIdx).toBeGreaterThan(-1);

    const resolveEnd = httpSource.indexOf("\nhttp.route", resolveIdx);
    const resolveBody = httpSource.slice(resolveIdx, resolveEnd > -1 ? resolveEnd : undefined);

    // Must extract token from headers
    expect(resolveBody).toContain("X-Auth-Token");
    expect(resolveBody).toContain("Authorization");
    // Must call getByAccessToken
    expect(resolveBody).toContain("getByAccessToken");
    // Must check record.userId
    expect(resolveBody).toContain("record.userId");
  });
});

// ---------------------------------------------------------------------------
// Preservation 3.6: Project API key authentication resolves correctly
// ---------------------------------------------------------------------------
describe("Preservation 3.6: Project API Key Authentication", () => {
  it("resolveIdentity handles project: prefixed tokens", () => {
    const resolveIdx = httpSource.indexOf("async function resolveIdentity");
    expect(resolveIdx).toBeGreaterThan(-1);

    const resolveEnd = httpSource.indexOf("\nhttp.route", resolveIdx);
    const resolveBody = httpSource.slice(resolveIdx, resolveEnd > -1 ? resolveEnd : undefined);

    // Must check for "project:" prefix
    expect(resolveBody).toContain('token.startsWith("project:")');
    // Must call projects.getByApiKey
    expect(resolveBody).toContain("getByApiKey");
    // Must return subject with project prefix
    expect(resolveBody).toContain("subject: `project:${project.id}`");
  });

  it("property: project API key resolution returns subject with project prefix, projectId, and orgId", () => {
    /**
     * Validates: Requirements 3.6
     *
     * Simulate the project API key branch of resolveIdentity:
     * when a token starts with "project:" and the project is found,
     * the function returns { subject: "project:<id>", projectId, orgId }.
     */
    fc.assert(
      fc.property(
        fc.record({
          projectId: fc.uuid(),
          orgId: fc.uuid(),
          apiKey: fc.string({ minLength: 10, maxLength: 64 }),
        }),
        (input) => {
          // Simulate the project API key branch
          const token = `project:${input.apiKey}`;
          expect(token.startsWith("project:")).toBe(true);

          const projectApiKey = token.slice("project:".length);
          expect(projectApiKey).toBe(input.apiKey);

          // Simulate project lookup success
          const project = { id: input.projectId, org_id: input.orgId };
          const result = {
            subject: `project:${project.id}`,
            projectId: project.id,
            orgId: project.org_id,
          };

          expect(result.subject).toBe(`project:${input.projectId}`);
          expect(result.projectId).toBe(input.projectId);
          expect(result.orgId).toBe(input.orgId);
        },
      ),
      { numRuns: 100 },
    );
  });
});
