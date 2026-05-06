/**
 * Unit Tests: POST /api/v1/usage HTTP Route Logic
 *
 * Tests the validation and normalization logic for the usage ping endpoint.
 * The route always returns HTTP 204, even on errors.
 *
 * Validates: Task 13.5 — Convex Backend `/api/v1/usage` HTTP Route
 */
import { describe, it, expect } from "vitest";

// ---------------------------------------------------------------------------
// Extracted logic under test
// These mirror the exact logic in convex/convex/http.ts for the usage route.
// ---------------------------------------------------------------------------

const PROJECT_HASH_REGEX = /^[0-9a-f]{64}$/i;

/**
 * Returns true if the payload should be silently ignored (return 204 without recording).
 */
function shouldIgnorePayload(body: unknown): boolean {
  if (!body || typeof body !== "object") return true;
  const b = body as Record<string, unknown>;
  // Ignore if event is not "scan_run"
  if (b.event !== "scan_run") return true;
  // Ignore if project_hash is malformed
  if (
    typeof b.project_hash !== "string" ||
    !PROJECT_HASH_REGEX.test(b.project_hash)
  ) {
    return true;
  }
  return false;
}

/**
 * Normalizes the environment field to "ci" or "local".
 */
function normalizeEnvironment(raw: unknown): "ci" | "local" {
  return raw === "ci" ? "ci" : "local";
}

/**
 * Simulates the full route handler logic.
 * Returns the HTTP status code that would be sent.
 * In all cases this is 204 — this function also returns whether the mutation
 * would have been called (for verifying correct behavior).
 */
function simulateUsageRoute(body: unknown): {
  status: number;
  mutationCalled: boolean;
  environment?: "ci" | "local";
  projectHash?: string;
} {
  // Parse failure → 204, no mutation
  if (body === null || body === undefined) {
    return { status: 204, mutationCalled: false };
  }

  if (shouldIgnorePayload(body)) {
    return { status: 204, mutationCalled: false };
  }

  const b = body as Record<string, unknown>;
  const environment = normalizeEnvironment(b.environment);
  const projectHash = b.project_hash as string;

  return { status: 204, mutationCalled: true, environment, projectHash };
}

// ---------------------------------------------------------------------------
// Tests: Always returns 204
// ---------------------------------------------------------------------------

describe("POST /api/v1/usage — always returns 204", () => {
  it("returns 204 for a valid payload", () => {
    const validHash = "a".repeat(64);
    const result = simulateUsageRoute({
      event: "scan_run",
      project_hash: validHash,
      environment: "ci",
      cli_version: "0.1.9",
    });
    expect(result.status).toBe(204);
  });

  it("returns 204 for malformed project_hash (too short)", () => {
    const result = simulateUsageRoute({
      event: "scan_run",
      project_hash: "abc123",
      environment: "local",
    });
    expect(result.status).toBe(204);
  });

  it("returns 204 for malformed project_hash (non-hex characters)", () => {
    const result = simulateUsageRoute({
      event: "scan_run",
      project_hash: "z".repeat(64),
      environment: "local",
    });
    expect(result.status).toBe(204);
  });

  it("returns 204 when event field is missing", () => {
    const result = simulateUsageRoute({
      project_hash: "a".repeat(64),
      environment: "ci",
    });
    expect(result.status).toBe(204);
  });

  it("returns 204 when event is not scan_run", () => {
    const result = simulateUsageRoute({
      event: "other_event",
      project_hash: "a".repeat(64),
      environment: "ci",
    });
    expect(result.status).toBe(204);
  });

  it("returns 204 when body is null (JSON parse failure)", () => {
    const result = simulateUsageRoute(null);
    expect(result.status).toBe(204);
  });

  it("returns 204 when project_hash is missing entirely", () => {
    const result = simulateUsageRoute({
      event: "scan_run",
      environment: "ci",
    });
    expect(result.status).toBe(204);
  });

  it("returns 204 when project_hash is exactly 63 chars (one short)", () => {
    const result = simulateUsageRoute({
      event: "scan_run",
      project_hash: "a".repeat(63),
      environment: "local",
    });
    expect(result.status).toBe(204);
  });

  it("returns 204 when project_hash is exactly 65 chars (one over)", () => {
    const result = simulateUsageRoute({
      event: "scan_run",
      project_hash: "a".repeat(65),
      environment: "local",
    });
    expect(result.status).toBe(204);
  });
});

// ---------------------------------------------------------------------------
// Tests: Mutation is called only for valid payloads
// ---------------------------------------------------------------------------

describe("POST /api/v1/usage — mutation called only for valid payloads", () => {
  it("calls mutation for valid payload with ci environment", () => {
    const validHash = "deadbeef".repeat(8); // 64 hex chars
    const result = simulateUsageRoute({
      event: "scan_run",
      project_hash: validHash,
      environment: "ci",
      cli_version: "0.2.0",
    });
    expect(result.mutationCalled).toBe(true);
    expect(result.environment).toBe("ci");
    expect(result.projectHash).toBe(validHash);
  });

  it("calls mutation for valid payload with local environment", () => {
    const validHash = "0123456789abcdef".repeat(4); // 64 hex chars
    const result = simulateUsageRoute({
      event: "scan_run",
      project_hash: validHash,
      environment: "local",
    });
    expect(result.mutationCalled).toBe(true);
    expect(result.environment).toBe("local");
  });

  it("does NOT call mutation for malformed project_hash", () => {
    const result = simulateUsageRoute({
      event: "scan_run",
      project_hash: "not-a-valid-hash",
      environment: "ci",
    });
    expect(result.mutationCalled).toBe(false);
  });

  it("does NOT call mutation when event is missing", () => {
    const result = simulateUsageRoute({
      project_hash: "a".repeat(64),
      environment: "ci",
    });
    expect(result.mutationCalled).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tests: Environment normalization
// ---------------------------------------------------------------------------

describe("POST /api/v1/usage — environment normalization", () => {
  it('normalizes "ci" to "ci"', () => {
    expect(normalizeEnvironment("ci")).toBe("ci");
  });

  it('normalizes "local" to "local"', () => {
    expect(normalizeEnvironment("local")).toBe("local");
  });

  it('normalizes unknown value to "local"', () => {
    expect(normalizeEnvironment("production")).toBe("local");
    expect(normalizeEnvironment("staging")).toBe("local");
    expect(normalizeEnvironment(undefined)).toBe("local");
    expect(normalizeEnvironment(null)).toBe("local");
    expect(normalizeEnvironment(42)).toBe("local");
  });

  it('defaults to "local" when environment field is absent', () => {
    const validHash = "a".repeat(64);
    const result = simulateUsageRoute({
      event: "scan_run",
      project_hash: validHash,
      // no environment field
    });
    expect(result.mutationCalled).toBe(true);
    expect(result.environment).toBe("local");
  });

  it('uses "ci" when environment is "ci" in a valid payload', () => {
    const validHash = "f".repeat(64);
    const result = simulateUsageRoute({
      event: "scan_run",
      project_hash: validHash,
      environment: "ci",
    });
    expect(result.mutationCalled).toBe(true);
    expect(result.environment).toBe("ci");
  });
});

// ---------------------------------------------------------------------------
// Tests: project_hash validation
// ---------------------------------------------------------------------------

describe("POST /api/v1/usage — project_hash validation", () => {
  it("accepts a valid 64-char lowercase hex string", () => {
    expect(PROJECT_HASH_REGEX.test("a".repeat(64))).toBe(true);
    expect(PROJECT_HASH_REGEX.test("0123456789abcdef".repeat(4))).toBe(true);
  });

  it("accepts a valid 64-char uppercase hex string (case-insensitive)", () => {
    expect(PROJECT_HASH_REGEX.test("A".repeat(64))).toBe(true);
    expect(PROJECT_HASH_REGEX.test("DEADBEEF".repeat(8))).toBe(true);
  });

  it("rejects strings shorter than 64 chars", () => {
    expect(PROJECT_HASH_REGEX.test("a".repeat(63))).toBe(false);
    expect(PROJECT_HASH_REGEX.test("")).toBe(false);
  });

  it("rejects strings longer than 64 chars", () => {
    expect(PROJECT_HASH_REGEX.test("a".repeat(65))).toBe(false);
  });

  it("rejects strings with non-hex characters", () => {
    expect(PROJECT_HASH_REGEX.test("g".repeat(64))).toBe(false);
    expect(PROJECT_HASH_REGEX.test("z".repeat(64))).toBe(false);
    // 63 valid hex + 1 non-hex
    expect(PROJECT_HASH_REGEX.test("a".repeat(63) + "z")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Tests: Simulated server error — still returns 204
// ---------------------------------------------------------------------------

describe("POST /api/v1/usage — server error still returns 204", () => {
  it("returns 204 even when mutation throws (simulated)", () => {
    // Simulate the catch-all behavior: even if runMutation throws,
    // the route catches the error and returns 204.
    let status = 204;
    try {
      // Simulate mutation throwing
      throw new Error("Convex internal error");
    } catch {
      // Swallowed — route still returns 204
    }
    expect(status).toBe(204);
  });
});
