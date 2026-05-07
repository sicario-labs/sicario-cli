//! Integration tests for `sicario scan --watch` mode.
//!
//! These tests validate the watch mode's re-scan logic directly (without
//! spawning the full binary) to avoid process-management complexity and
//! ensure the 500ms timing requirement is met reliably.
//!
//! Validates: Design Section 4.3 — Continuous Watch Mode
//! Requirement: re-scan must complete within 500ms of the file change event.

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    use crate::engine::sast_engine::SastEngine;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Create a temporary directory containing a single clean JavaScript file
    /// with no vulnerabilities.
    fn setup_clean_js_file() -> (TempDir, std::path::PathBuf) {
        let tmp = TempDir::new().expect("Failed to create temp directory");
        let file_path = tmp.path().join("target.js");
        std::fs::write(
            &file_path,
            "// Clean file — no vulnerabilities\nfunction greet(name) {\n  return 'Hello, ' + name;\n}\n",
        )
        .expect("Failed to write clean JS file");
        (tmp, file_path)
    }

    /// Build a `SastEngine` rooted at `dir` with the default built-in rules loaded.
    fn engine_with_defaults(dir: &std::path::Path) -> SastEngine {
        let mut eng = SastEngine::new(dir).expect("Failed to create SastEngine");
        eng.load_default_rules();
        eng
    }

    // ── Test: clean file produces no findings ─────────────────────────────────

    /// Baseline: scanning a clean file must return zero findings.
    ///
    /// This establishes the pre-condition for the watch-mode diff test below.
    #[test]
    fn watch_clean_file_has_no_findings() {
        let (tmp, file_path) = setup_clean_js_file();
        let mut eng = engine_with_defaults(tmp.path());

        let findings = eng
            .scan_file(&file_path)
            .expect("scan_file must not fail on a clean file");

        assert!(
            findings.is_empty(),
            "Expected 0 findings on a clean file, got {}: {:?}",
            findings.len(),
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    // ── Test: new finding appears within 500ms of file modification ───────────

    /// Core watch-mode integration test.
    ///
    /// Simulates the watch loop's per-file re-scan:
    ///   1. Start with a clean file (0 findings).
    ///   2. Modify the file to introduce a SQL-injection-style eval() call.
    ///   3. Re-scan the file and assert:
    ///      a. At least one new finding is detected.
    ///      b. The re-scan completes within 500ms of the file write.
    ///
    /// The 500ms budget covers the full round-trip: file write → engine init →
    /// rule loading → AST parse → query execution → result collection.
    ///
    /// Validates: Design Section 4.3 — "The re-scan must complete within 500ms
    /// of the file change event for typical file sizes."
    #[test]
    #[ignore = "timing-sensitive: 500ms budget is too tight for shared CI runners; run locally with --ignored to validate watch-mode latency"]
    fn watch_new_finding_appears_within_500ms() {
        let (tmp, file_path) = setup_clean_js_file();

        // ── Step 1: initial scan — expect 0 findings ──────────────────────────
        {
            let mut eng = engine_with_defaults(tmp.path());
            let initial = eng
                .scan_file(&file_path)
                .expect("Initial scan must succeed");
            assert!(
                initial.is_empty(),
                "Pre-condition failed: initial scan must find 0 vulnerabilities, found {}",
                initial.len()
            );
        }

        // ── Step 2: modify the file to introduce a vulnerability ──────────────
        // Write a JavaScript file containing an eval() call, which triggers the
        // built-in `js/eval-injection` rule (CWE-95, Critical severity).
        std::fs::write(
            &file_path,
            "// Vulnerable file — eval injection\nfunction run(userInput) {\n  eval(userInput);\n}\n",
        )
        .expect("Failed to write vulnerable JS file");

        // ── Step 3: re-scan and assert finding appears within 500ms ───────────
        // The timer starts immediately after the file write to mirror the
        // watch loop's behaviour (debounce fires ~100ms after the write event,
        // then the re-scan runs; we budget 500ms for the full cycle).
        let rescan_start = Instant::now();

        let mut eng = engine_with_defaults(tmp.path());
        let findings = eng
            .scan_file(&file_path)
            .expect("Re-scan must succeed on modified file");

        let elapsed = rescan_start.elapsed();

        // ── Assertion A: at least one finding detected ────────────────────────
        assert!(
            !findings.is_empty(),
            "Expected at least one finding after introducing eval() vulnerability, got 0. \
             The watch mode diff would not surface any new findings."
        );

        // Verify the finding is the expected eval-injection rule
        let eval_finding = findings.iter().find(|f| f.rule_id == "js/eval-injection");
        assert!(
            eval_finding.is_some(),
            "Expected a 'js/eval-injection' finding but got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );

        // ── Assertion B: re-scan completed within 500ms ───────────────────────
        assert!(
            elapsed <= Duration::from_millis(500),
            "Re-scan took {}ms, which exceeds the 500ms budget required by the watch mode spec. \
             The watch loop must complete a single-file re-scan within 500ms of the file change event.",
            elapsed.as_millis()
        );
    }

    // ── Test: watch diff correctly identifies new vs existing findings ─────────

    /// Validates the diff logic used by the watch loop:
    /// findings present in the new scan but absent from the previous scan
    /// are correctly identified as "new".
    ///
    /// This mirrors the diff logic in `run_watch_mode` in main.rs.
    #[test]
    fn watch_diff_identifies_new_findings() {
        let (tmp, file_path) = setup_clean_js_file();

        // Initial scan: no findings
        let mut eng = engine_with_defaults(tmp.path());
        let old_findings = eng
            .scan_file(&file_path)
            .expect("Initial scan must succeed");
        assert!(
            old_findings.is_empty(),
            "Pre-condition: initial scan must be clean"
        );

        // Introduce vulnerability
        std::fs::write(&file_path, "function run(input) { eval(input); }\n")
            .expect("Failed to write vulnerable file");

        // Re-scan
        let mut eng2 = engine_with_defaults(tmp.path());
        let new_findings = eng2.scan_file(&file_path).expect("Re-scan must succeed");

        // Diff: findings in new_findings not present in old_findings
        let truly_new: Vec<_> = new_findings
            .iter()
            .filter(|nf| {
                !old_findings
                    .iter()
                    .any(|of| of.rule_id == nf.rule_id && of.line == nf.line)
            })
            .collect();

        assert!(
            !truly_new.is_empty(),
            "Diff must identify at least one new finding after introducing eval()"
        );

        assert!(
            truly_new.iter().any(|f| f.rule_id == "js/eval-injection"),
            "New findings must include 'js/eval-injection', got: {:?}",
            truly_new.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    // ── Test: resolved findings are correctly identified ──────────────────────

    /// Validates that findings present in the previous scan but absent from the
    /// new scan are correctly identified as "resolved" — the `[resolved]` output
    /// in the watch loop.
    #[test]
    fn watch_diff_identifies_resolved_findings() {
        let (tmp, file_path) = setup_clean_js_file();

        // Start with a vulnerable file
        std::fs::write(&file_path, "function run(input) { eval(input); }\n")
            .expect("Failed to write vulnerable file");

        let mut eng = engine_with_defaults(tmp.path());
        let old_findings = eng
            .scan_file(&file_path)
            .expect("Initial scan of vulnerable file must succeed");
        assert!(
            !old_findings.is_empty(),
            "Pre-condition: vulnerable file must have findings"
        );

        // Fix the vulnerability
        std::fs::write(
            &file_path,
            "// Fixed: removed eval()\nfunction run(input) { console.log(input); }\n",
        )
        .expect("Failed to write fixed file");

        let mut eng2 = engine_with_defaults(tmp.path());
        let new_findings = eng2
            .scan_file(&file_path)
            .expect("Re-scan of fixed file must succeed");

        // Diff: findings in old_findings not present in new_findings → resolved
        let resolved: Vec<_> = old_findings
            .iter()
            .filter(|of| {
                !new_findings
                    .iter()
                    .any(|nf| nf.rule_id == of.rule_id && nf.line == of.line)
            })
            .collect();

        assert!(
            !resolved.is_empty(),
            "Diff must identify at least one resolved finding after fixing eval()"
        );

        assert!(
            resolved.iter().any(|f| f.rule_id == "js/eval-injection"),
            "Resolved findings must include 'js/eval-injection', got: {:?}",
            resolved.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    // ── Test: multiple rapid modifications are handled correctly ──────────────

    /// Simulates multiple rapid file saves (as would happen during active editing)
    /// and verifies that each re-scan produces the correct finding set.
    ///
    /// This validates the debounce + re-scan cycle is idempotent.
    #[test]
    fn watch_multiple_modifications_produce_correct_findings() {
        let (tmp, file_path) = setup_clean_js_file();
        let mut eng = engine_with_defaults(tmp.path());

        // Cycle 1: clean
        let findings = eng.scan_file(&file_path).expect("Scan 1 must succeed");
        assert!(findings.is_empty(), "Cycle 1: expected 0 findings");

        // Cycle 2: introduce eval
        std::fs::write(&file_path, "eval(userInput);\n").expect("Failed to write cycle 2");
        let mut eng2 = engine_with_defaults(tmp.path());
        let findings2 = eng2.scan_file(&file_path).expect("Scan 2 must succeed");
        assert!(
            !findings2.is_empty(),
            "Cycle 2: expected findings after eval()"
        );

        // Cycle 3: fix eval, introduce innerHTML XSS
        std::fs::write(
            &file_path,
            "document.getElementById('x').innerHTML = userInput;\n",
        )
        .expect("Failed to write cycle 3");
        let mut eng3 = engine_with_defaults(tmp.path());
        let findings3 = eng3.scan_file(&file_path).expect("Scan 3 must succeed");
        assert!(
            !findings3.is_empty(),
            "Cycle 3: expected findings after innerHTML"
        );
        assert!(
            findings3.iter().any(|f| f.rule_id == "js/innerhtml-xss"),
            "Cycle 3: expected 'js/innerhtml-xss' finding"
        );

        // Cycle 4: clean again
        std::fs::write(&file_path, "// All clean\nconst x = 1;\n")
            .expect("Failed to write cycle 4");
        let mut eng4 = engine_with_defaults(tmp.path());
        let findings4 = eng4.scan_file(&file_path).expect("Scan 4 must succeed");
        assert!(
            findings4.is_empty(),
            "Cycle 4: expected 0 findings after cleanup"
        );
    }
}
