import { describe, it, expect, vi } from "vitest";
import * as fc from "fast-check";

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

// ── Constants ───────────────────────────────────────────────────────────────

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"] as const;
type Severity = (typeof SEVERITIES)[number];

const VALID_ANNOTATION_LEVELS = ["failure", "warning", "notice"];

// ── Generators ──────────────────────────────────────────────────────────────

const arbSeverity: fc.Arbitrary<Severity> = fc.constantFrom(...SEVERITIES);

const arbNonEmptyAlphaNum = fc
  .array(fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789"), {
    minLength: 1,
    maxLength: 12,
  })
  .map((chars) => chars.join(""));

/** Generate a minimal ScanFinding with valid fields. */
const arbScanFinding: fc.Arbitrary<ScanFinding> = fc
  .tuple(
    arbNonEmptyAlphaNum,
    arbNonEmptyAlphaNum,
    arbNonEmptyAlphaNum,
    arbSeverity,
    arbNonEmptyAlphaNum,
    fc.integer({ min: 1, max: 5000 }),
  )
  .map(([ruleId, filePath, snippet, severity, fingerprint, line]) => ({
    ruleId,
    ruleName: `rule-${ruleId}`,
    filePath: `src/${filePath}.ts`,
    line,
    column: 0,
    snippet,
    severity,
    fingerprint,
  }));

// ── Property 6: Check Run summary contains required information ─────────

describe("Feature: pr-scan-workflow, Property 6: Check Run summary contains required information", () => {
  /**
   * **Validates: Requirements 6.3**
   *
   * For any finding counts (total, critical, high) and severity threshold
   * string, the generated Check Run summary string SHALL contain the total
   * count, critical count, high count, and the threshold value.
   */
  it("summary contains totalCount, criticalCount, highCount, and threshold", () => {
    fc.assert(
      fc.property(
        fc.nat({ max: 10000 }),
        fc.nat({ max: 10000 }),
        fc.nat({ max: 10000 }),
        arbSeverity,
        (totalCount, criticalCount, highCount, threshold) => {
          const summary = buildCheckRunSummary(
            totalCount,
            criticalCount,
            highCount,
            threshold,
          );

          expect(summary).toContain(String(totalCount));
          expect(summary).toContain(String(criticalCount));
          expect(summary).toContain(String(highCount));
          expect(summary).toContain(threshold);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ── Property 7: Annotations are capped and well-formed ──────────────────

describe("Feature: pr-scan-workflow, Property 7: Annotations are capped and well-formed", () => {
  /**
   * **Validates: Requirements 6.4**
   *
   * For any list of findings (including lists with more than 50 items),
   * the generated annotations array SHALL contain at most 50 entries, and
   * each annotation SHALL include a non-empty path, a positive start_line,
   * a non-empty annotation_level (one of "failure", "warning", "notice"),
   * and a non-empty message.
   */
  it("annotations are capped at 50 and each entry is well-formed", () => {
    fc.assert(
      fc.property(
        fc.array(arbScanFinding, { minLength: 0, maxLength: 100 }),
        (findings) => {
          const annotations = buildAnnotations(findings);

          // Cap at 50
          expect(annotations.length).toBeLessThanOrEqual(50);

          // Each annotation is well-formed
          for (const ann of annotations) {
            expect(ann.path.length).toBeGreaterThan(0);
            expect(ann.start_line).toBeGreaterThan(0);
            expect(VALID_ANNOTATION_LEVELS).toContain(ann.annotation_level);
            expect(ann.message.length).toBeGreaterThan(0);
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});
