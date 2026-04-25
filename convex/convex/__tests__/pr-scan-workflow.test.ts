import { describe, it, expect, vi } from "vitest";

// Mock Convex modules so prScanWorkflow.ts can be imported in test context
vi.mock("../_generated/server", () => ({
  action: () => ({}),
}));
vi.mock("convex/values", () => ({
  v: { string: () => ({}), number: () => ({}) },
}));
vi.mock("../_generated/api", () => ({
  api: {},
}));
vi.mock("../githubApp", () => ({
  requireGitHubAppEnv: () => ({}),
  generateAppJwt: async () => "",
  getInstallationToken: async () => "",
}));
vi.mock("../prSastRules", () => ({
  PR_SAST_RULES: [],
}));

import { buildCheckRunSummary, buildAnnotations } from "../prScanWorkflow";
import type { ScanFinding } from "../prSastEngine";

// ── Helpers ─────────────────────────────────────────────────────────────────

function makeFinding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    ruleId: "test-rule",
    ruleName: "Test Rule",
    filePath: "src/app.ts",
    line: 1,
    column: 0,
    snippet: "vulnerable code",
    severity: "High",
    fingerprint: "abc123",
    ...overrides,
  };
}

// ── buildCheckRunSummary ────────────────────────────────────────────────────

describe("buildCheckRunSummary", () => {
  /**
   * Validates: Requirements 7.1, 7.2
   * When zero findings exist, the summary should indicate no issues.
   */
  it('returns "No issues found" when all counts are zero', () => {
    const summary = buildCheckRunSummary(0, 0, 0, "High");
    expect(summary).toContain("No issues found");
    expect(summary).toContain("0");
    expect(summary).toContain("High");
  });

  /**
   * Validates: Requirements 1.3, 7.1
   * When findings exist, the summary should indicate issues were found.
   */
  it('returns "Issues found" when findings exist', () => {
    const summary = buildCheckRunSummary(5, 2, 3, "High");
    expect(summary).toContain("Issues found");
    expect(summary).toContain("5");
    expect(summary).toContain("2");
    expect(summary).toContain("3");
    expect(summary).toContain("High");
  });
});

// ── buildAnnotations ────────────────────────────────────────────────────────

describe("buildAnnotations", () => {
  /**
   * Validates: Requirements 3.4, 7.1
   * Empty findings should produce an empty annotations array.
   */
  it("returns empty array for empty findings", () => {
    const annotations = buildAnnotations([]);
    expect(annotations).toEqual([]);
  });

  /**
   * Validates: Requirements 2.4, 7.2
   * Exactly 50 findings should produce exactly 50 annotations (no truncation).
   */
  it("returns exactly 50 annotations for 50 findings", () => {
    const findings = Array.from({ length: 50 }, (_, i) =>
      makeFinding({ filePath: `src/file${i}.ts`, line: i + 1 }),
    );
    const annotations = buildAnnotations(findings);
    expect(annotations).toHaveLength(50);
  });

  /**
   * Validates: Requirements 2.4, 7.2
   * More than 50 findings should be capped at 50 annotations.
   */
  it("caps annotations at 50 for 100 findings", () => {
    const findings = Array.from({ length: 100 }, (_, i) =>
      makeFinding({ filePath: `src/file${i}.ts`, line: i + 1 }),
    );
    const annotations = buildAnnotations(findings);
    expect(annotations).toHaveLength(50);
  });

  /**
   * Validates: Requirements 7.1
   * Each annotation should have required fields populated.
   */
  it("produces well-formed annotations with required fields", () => {
    const findings = [makeFinding({ severity: "Critical", line: 42 })];
    const annotations = buildAnnotations(findings);

    expect(annotations).toHaveLength(1);
    const ann = annotations[0];
    expect(ann.path).toBe("src/app.ts");
    expect(ann.start_line).toBe(42);
    expect(ann.annotation_level).toBe("failure");
    expect(ann.message).toContain("Test Rule");
    expect(ann.title).toContain("Critical");
  });
});

// ── Severity → annotation_level mapping ─────────────────────────────────────

describe("severity to annotation_level mapping", () => {
  /**
   * Validates: Requirements 1.3, 2.4, 3.4, 7.1, 7.2
   * Each severity level must map to the correct GitHub annotation level.
   */
  it.each([
    ["Critical", "failure"],
    ["High", "failure"],
    ["Medium", "warning"],
    ["Low", "notice"],
    ["Info", "notice"],
  ])("maps %s severity to %s annotation_level", (severity, expected) => {
    const findings = [makeFinding({ severity })];
    const annotations = buildAnnotations(findings);
    expect(annotations[0].annotation_level).toBe(expected);
  });

  /**
   * Validates: Requirements 7.1
   * Unknown severity should default to "notice".
   */
  it('maps unknown severity to "notice" (default)', () => {
    const findings = [makeFinding({ severity: "Unknown" })];
    const annotations = buildAnnotations(findings);
    expect(annotations[0].annotation_level).toBe("notice");
  });
});
