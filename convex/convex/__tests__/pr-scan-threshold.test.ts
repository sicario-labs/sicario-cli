import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { evaluateThreshold, type ScanFinding } from "../prSastEngine";

// ── Constants ───────────────────────────────────────────────────────────────

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"] as const;
type Severity = (typeof SEVERITIES)[number];

const SEVERITY_LEVELS: Record<string, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Info: 0,
};

// ── Generators ──────────────────────────────────────────────────────────────

/** Arbitrary severity string from the valid set. */
const arbSeverity: fc.Arbitrary<Severity> = fc.constantFrom(...SEVERITIES);

/** Arbitrary non-empty alphanumeric string for IDs and paths. */
const arbId = fc
  .array(fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789"), {
    minLength: 1,
    maxLength: 12,
  })
  .map((chars) => chars.join(""));

/** Generate a minimal ScanFinding with an arbitrary severity. */
const arbScanFinding: fc.Arbitrary<ScanFinding> = fc
  .tuple(arbId, arbId, arbId, arbSeverity, arbId)
  .map(([ruleId, filePath, snippet, severity, fingerprint]) => ({
    ruleId,
    ruleName: `rule-${ruleId}`,
    filePath: `src/${filePath}.ts`,
    line: 1,
    column: 0,
    snippet,
    severity,
    fingerprint,
  }));

// ── Property Tests ──────────────────────────────────────────────────────────

describe("Feature: pr-scan-workflow, Property 4: Threshold evaluation correctness", () => {
  /**
   * **Validates: Requirements 5.1, 5.2**
   *
   * For any list of ScanFinding objects and any valid severity threshold,
   * evaluateThreshold SHALL return passed: true if and only if no finding
   * has severity at or above the threshold. Conversely, it SHALL return
   * passed: false if and only if at least one finding has severity at or
   * above the threshold.
   */
  it("passed is true iff no finding has severity >= threshold", () => {
    fc.assert(
      fc.property(
        fc.array(arbScanFinding, { minLength: 0, maxLength: 20 }),
        arbSeverity,
        (findings, threshold) => {
          const result = evaluateThreshold(findings, threshold);
          const thresholdLevel = SEVERITY_LEVELS[threshold];

          const hasViolation = findings.some(
            (f) => (SEVERITY_LEVELS[f.severity] ?? 0) >= thresholdLevel,
          );

          expect(result.passed).toBe(!hasViolation);
        },
      ),
      { numRuns: 200 },
    );
  });
});

describe("Feature: pr-scan-workflow, Property 5: Finding severity counts are accurate", () => {
  /**
   * **Validates: Requirements 5.3**
   *
   * For any list of ScanFinding objects, evaluateThreshold SHALL return
   * criticalCount equal to the number of findings with severity "Critical",
   * highCount equal to the number with severity "High", and totalCount
   * equal to the total number of findings.
   */
  it("criticalCount, highCount, and totalCount match manual counting", () => {
    fc.assert(
      fc.property(
        fc.array(arbScanFinding, { minLength: 0, maxLength: 30 }),
        arbSeverity,
        (findings, threshold) => {
          const result = evaluateThreshold(findings, threshold);

          const expectedCritical = findings.filter(
            (f) => f.severity === "Critical",
          ).length;
          const expectedHigh = findings.filter(
            (f) => f.severity === "High",
          ).length;

          expect(result.criticalCount).toBe(expectedCritical);
          expect(result.highCount).toBe(expectedHigh);
          expect(result.totalCount).toBe(findings.length);
        },
      ),
      { numRuns: 200 },
    );
  });
});
