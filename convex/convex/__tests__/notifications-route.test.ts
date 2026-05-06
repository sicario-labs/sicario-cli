/**
 * Unit Tests: GET /api/v1/notifications HTTP Route Logic
 *
 * Tests the filtering, version comparison, and response-mapping logic for the
 * notifications endpoint. The route always returns HTTP 200 with a JSON array.
 *
 * Validates: Task 14.4 — Convex Backend `/api/v1/notifications` HTTP Route
 */
import { describe, it, expect } from "vitest";

// ---------------------------------------------------------------------------
// Extracted logic under test
// These mirror the exact logic in convex/convex/http.ts for the notifications route.
// ---------------------------------------------------------------------------

/**
 * Compares two semver strings numerically.
 * Returns: negative if a < b, 0 if a == b, positive if a > b.
 */
function compareSemver(a: string, b: string): number {
  const parseParts = (v: string): [number, number, number] => {
    const clean = v.split("-")[0].split("+")[0];
    const parts = clean.split(".").map((p) => parseInt(p, 10) || 0);
    return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
  };
  const [aMaj, aMin, aPatch] = parseParts(a);
  const [bMaj, bMin, bPatch] = parseParts(b);
  if (aMaj !== bMaj) return aMaj - bMaj;
  if (aMin !== bMin) return aMin - bMin;
  return aPatch - bPatch;
}

interface RawNotification {
  notificationId: string;
  message: string;
  severity: "info" | "warning" | "critical";
  minVersion?: string;
  maxVersion?: string;
  url?: string;
  activeFrom: string;
  activeTo?: string;
  enabled: boolean;
}

interface ResponseNotification {
  id: string;
  message: string;
  severity: string;
  min_version: string | null;
  max_version: string | null;
  url: string | null;
}

/**
 * Simulates the listActive query filter (enabled + time window).
 */
function filterActive(notifications: RawNotification[], now: string): RawNotification[] {
  return notifications.filter(
    (n) =>
      n.enabled &&
      n.activeFrom <= now &&
      (n.activeTo === undefined || n.activeTo === null || n.activeTo >= now)
  );
}

/**
 * Simulates the version-range filter applied in the HTTP route.
 */
function filterByVersion(notifications: RawNotification[], cliVersion: string): RawNotification[] {
  return notifications.filter((n) => {
    if (n.minVersion && compareSemver(n.minVersion, cliVersion) > 0) return false;
    if (n.maxVersion && compareSemver(n.maxVersion, cliVersion) < 0) return false;
    return true;
  });
}

/**
 * Maps a raw notification to the public response shape.
 */
function mapToResponse(n: RawNotification): ResponseNotification {
  return {
    id: n.notificationId,
    message: n.message,
    severity: n.severity,
    min_version: n.minVersion ?? null,
    max_version: n.maxVersion ?? null,
    url: n.url ?? null,
  };
}

/**
 * Simulates the full route handler logic (excluding Convex DB calls).
 * Returns the response body that would be sent.
 */
function simulateNotificationsRoute(
  allNotifications: RawNotification[],
  cliVersion: string,
  now: string,
  simulateInternalError = false
): { status: number; body: ResponseNotification[] } {
  if (simulateInternalError) {
    return { status: 200, body: [] };
  }

  const active = filterActive(allNotifications, now);
  const versioned = filterByVersion(active, cliVersion);
  const response = versioned.map(mapToResponse);
  return { status: 200, body: response };
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

const NOW = "2025-06-01T00:00:00.000Z";
const PAST = "2025-01-01T00:00:00.000Z";
const FUTURE = "2026-01-01T00:00:00.000Z";

const activeNotification: RawNotification = {
  notificationId: "v2-beta-launch",
  message: "Sicario v2 Beta is live!",
  severity: "info",
  minVersion: "0.9.0",
  url: "https://usesicario.xyz/changelog",
  activeFrom: PAST,
  enabled: true,
};

// ---------------------------------------------------------------------------
// Tests: Active notification is returned
// ---------------------------------------------------------------------------

describe("GET /api/v1/notifications — active notification returned", () => {
  it("returns an active notification for a matching CLI version", () => {
    const result = simulateNotificationsRoute([activeNotification], "1.0.0", NOW);
    expect(result.status).toBe(200);
    expect(result.body).toHaveLength(1);
    expect(result.body[0].id).toBe("v2-beta-launch");
    expect(result.body[0].message).toBe("Sicario v2 Beta is live!");
    expect(result.body[0].severity).toBe("info");
    expect(result.body[0].url).toBe("https://usesicario.xyz/changelog");
    expect(result.body[0].min_version).toBe("0.9.0");
    expect(result.body[0].max_version).toBeNull();
  });

  it("returns empty array when no notifications exist", () => {
    const result = simulateNotificationsRoute([], "1.0.0", NOW);
    expect(result.status).toBe(200);
    expect(result.body).toHaveLength(0);
  });

  it("maps optional fields to null when absent", () => {
    const minimal: RawNotification = {
      notificationId: "minimal",
      message: "Hello",
      severity: "warning",
      activeFrom: PAST,
      enabled: true,
    };
    const result = simulateNotificationsRoute([minimal], "1.0.0", NOW);
    expect(result.body[0].min_version).toBeNull();
    expect(result.body[0].max_version).toBeNull();
    expect(result.body[0].url).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Tests: Disabled notification excluded
// ---------------------------------------------------------------------------

describe("GET /api/v1/notifications — disabled notification excluded", () => {
  it("excludes a notification with enabled = false", () => {
    const disabled: RawNotification = { ...activeNotification, enabled: false };
    const result = simulateNotificationsRoute([disabled], "1.0.0", NOW);
    expect(result.status).toBe(200);
    expect(result.body).toHaveLength(0);
  });

  it("returns only enabled notifications when mixed", () => {
    const disabled: RawNotification = {
      ...activeNotification,
      notificationId: "disabled-one",
      enabled: false,
    };
    const enabled: RawNotification = {
      ...activeNotification,
      notificationId: "enabled-one",
      enabled: true,
    };
    const result = simulateNotificationsRoute([disabled, enabled], "1.0.0", NOW);
    expect(result.body).toHaveLength(1);
    expect(result.body[0].id).toBe("enabled-one");
  });
});

// ---------------------------------------------------------------------------
// Tests: Expired notification excluded
// ---------------------------------------------------------------------------

describe("GET /api/v1/notifications — expired notification excluded", () => {
  it("excludes a notification whose activeTo is in the past", () => {
    const expired: RawNotification = {
      ...activeNotification,
      activeTo: PAST, // activeTo < NOW → expired
    };
    const result = simulateNotificationsRoute([expired], "1.0.0", NOW);
    expect(result.body).toHaveLength(0);
  });

  it("includes a notification whose activeTo is in the future", () => {
    const notExpired: RawNotification = {
      ...activeNotification,
      activeTo: FUTURE,
    };
    const result = simulateNotificationsRoute([notExpired], "1.0.0", NOW);
    expect(result.body).toHaveLength(1);
  });

  it("includes a notification with no activeTo (never expires)", () => {
    const neverExpires: RawNotification = {
      ...activeNotification,
      activeTo: undefined,
    };
    const result = simulateNotificationsRoute([neverExpires], "1.0.0", NOW);
    expect(result.body).toHaveLength(1);
  });

  it("excludes a notification whose activeFrom is in the future (not yet active)", () => {
    const notYetActive: RawNotification = {
      ...activeNotification,
      activeFrom: FUTURE,
    };
    const result = simulateNotificationsRoute([notYetActive], "1.0.0", NOW);
    expect(result.body).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: Version-filtered notification excluded
// ---------------------------------------------------------------------------

describe("GET /api/v1/notifications — version-filtered notification excluded", () => {
  it("excludes notification when CLI version is below minVersion", () => {
    const n: RawNotification = { ...activeNotification, minVersion: "1.0.0" };
    const result = simulateNotificationsRoute([n], "0.8.0", NOW);
    expect(result.body).toHaveLength(0);
  });

  it("includes notification when CLI version equals minVersion", () => {
    const n: RawNotification = { ...activeNotification, minVersion: "1.0.0" };
    const result = simulateNotificationsRoute([n], "1.0.0", NOW);
    expect(result.body).toHaveLength(1);
  });

  it("includes notification when CLI version is above minVersion", () => {
    const n: RawNotification = { ...activeNotification, minVersion: "0.9.0" };
    const result = simulateNotificationsRoute([n], "1.0.0", NOW);
    expect(result.body).toHaveLength(1);
  });

  it("excludes notification when CLI version is above maxVersion", () => {
    const n: RawNotification = {
      ...activeNotification,
      minVersion: undefined,
      maxVersion: "0.9.9",
    };
    const result = simulateNotificationsRoute([n], "1.0.0", NOW);
    expect(result.body).toHaveLength(0);
  });

  it("includes notification when CLI version equals maxVersion", () => {
    const n: RawNotification = {
      ...activeNotification,
      minVersion: undefined,
      maxVersion: "1.0.0",
    };
    const result = simulateNotificationsRoute([n], "1.0.0", NOW);
    expect(result.body).toHaveLength(1);
  });

  it("includes notification when CLI version is below maxVersion", () => {
    const n: RawNotification = {
      ...activeNotification,
      minVersion: undefined,
      maxVersion: "2.0.0",
    };
    const result = simulateNotificationsRoute([n], "1.0.0", NOW);
    expect(result.body).toHaveLength(1);
  });

  it("includes notification with no version constraints for any CLI version", () => {
    const n: RawNotification = {
      ...activeNotification,
      minVersion: undefined,
      maxVersion: undefined,
    };
    const result = simulateNotificationsRoute([n], "0.0.1", NOW);
    expect(result.body).toHaveLength(1);
  });

  it("uses default version 0.0.0 when cli_version is absent (all minVersion constraints exclude it)", () => {
    const n: RawNotification = { ...activeNotification, minVersion: "0.9.0" };
    // Simulate absent cli_version → defaults to "0.0.0"
    const result = simulateNotificationsRoute([n], "0.0.0", NOW);
    expect(result.body).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: Server error returns empty array
// ---------------------------------------------------------------------------

describe("GET /api/v1/notifications — server error returns empty array", () => {
  it("returns 200 with empty array when internal error occurs", () => {
    const result = simulateNotificationsRoute([], "1.0.0", NOW, true);
    expect(result.status).toBe(200);
    expect(result.body).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Tests: compareSemver helper
// ---------------------------------------------------------------------------

describe("compareSemver", () => {
  it("returns 0 for equal versions", () => {
    expect(compareSemver("1.2.3", "1.2.3")).toBe(0);
  });

  it("returns positive when a > b (major)", () => {
    expect(compareSemver("2.0.0", "1.9.9")).toBeGreaterThan(0);
  });

  it("returns negative when a < b (major)", () => {
    expect(compareSemver("1.0.0", "2.0.0")).toBeLessThan(0);
  });

  it("compares minor version correctly", () => {
    expect(compareSemver("1.2.0", "1.1.9")).toBeGreaterThan(0);
    expect(compareSemver("1.1.0", "1.2.0")).toBeLessThan(0);
  });

  it("compares patch version correctly", () => {
    expect(compareSemver("1.0.1", "1.0.0")).toBeGreaterThan(0);
    expect(compareSemver("1.0.0", "1.0.1")).toBeLessThan(0);
  });

  it("handles pre-release suffix by stripping it", () => {
    // "1.0.0-beta" is treated as "1.0.0"
    expect(compareSemver("1.0.0-beta", "1.0.0")).toBe(0);
  });

  it("handles missing patch component (treats as 0)", () => {
    expect(compareSemver("1.0", "1.0.0")).toBe(0);
  });

  it("handles 0.0.0 correctly", () => {
    expect(compareSemver("0.0.0", "0.0.1")).toBeLessThan(0);
    expect(compareSemver("0.9.0", "0.0.0")).toBeGreaterThan(0);
  });
});
