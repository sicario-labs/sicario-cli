import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { computeFingerprint } from "../prSastEngine";

// ── Generators ──────────────────────────────────────────────────────────────

/** Arbitrary non-empty string suitable for ruleId, filePath, or snippet. */
const arbNonEmptyString = fc.string({ minLength: 1, maxLength: 100 });

// ── Property Tests ──────────────────────────────────────────────────────────

describe("Feature: pr-scan-workflow, Property 3: Fingerprint determinism", () => {
  /**
   * **Validates: Requirements 4.4**
   *
   * For any ruleId, filePath, and snippet strings, calling
   * computeFingerprint(ruleId, filePath, snippet) twice with the same
   * arguments SHALL produce identical results, and calling it with any
   * different argument SHALL produce a different result (collision resistance).
   */

  it("same inputs always produce the same fingerprint (determinism)", () => {
    fc.assert(
      fc.property(
        arbNonEmptyString,
        arbNonEmptyString,
        arbNonEmptyString,
        (ruleId, filePath, snippet) => {
          const first = computeFingerprint(ruleId, filePath, snippet);
          const second = computeFingerprint(ruleId, filePath, snippet);
          expect(first).toBe(second);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("changing any single argument produces a different fingerprint (collision resistance)", () => {
    fc.assert(
      fc.property(
        arbNonEmptyString,
        arbNonEmptyString,
        arbNonEmptyString,
        arbNonEmptyString,
        (ruleId, filePath, snippet, alt) => {
          const baseline = computeFingerprint(ruleId, filePath, snippet);

          // Only test when alt actually differs from the original value
          if (alt !== ruleId) {
            expect(computeFingerprint(alt, filePath, snippet)).not.toBe(baseline);
          }
          if (alt !== filePath) {
            expect(computeFingerprint(ruleId, alt, snippet)).not.toBe(baseline);
          }
          if (alt !== snippet) {
            expect(computeFingerprint(ruleId, filePath, alt)).not.toBe(baseline);
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});
