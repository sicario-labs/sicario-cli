//! Property-based tests for exit code threshold correctness.
//!
//! Feature: zero-exfil-edge-scanning, Property 6: Exit Code Threshold Correctness
//!
//! For any list of findings (each with a severity and suppression state) and
//! for any severity threshold, the exit code SHALL be `FindingsDetected` (1)
//! if and only if at least one non-suppressed finding has severity >= threshold.
//! Otherwise the exit code SHALL be `Clean` (0).
//!
//! Validates: Requirements 16.1, 16.2, 16.7

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::cli::exit_code::{ExitCode, FindingSummary};
    use crate::engine::vulnerability::Severity;

    // ── Arbitrary generators ─────────────────────────────────────────────────

    fn arb_severity() -> impl Strategy<Value = Severity> {
        prop_oneof![
            Just(Severity::Info),
            Just(Severity::Low),
            Just(Severity::Medium),
            Just(Severity::High),
            Just(Severity::Critical),
        ]
    }

    fn arb_finding_summary() -> impl Strategy<Value = FindingSummary> {
        (arb_severity(), proptest::bool::ANY).prop_map(|(severity, suppressed)| FindingSummary {
            severity,
            confidence_score: 1.0, // always meets confidence threshold in these tests
            suppressed,
        })
    }

    fn arb_findings() -> impl Strategy<Value = Vec<FindingSummary>> {
        proptest::collection::vec(arb_finding_summary(), 0..=50)
    }

    // ── Helper: reference implementation of the exit code predicate ──────────

    /// Returns true iff at least one non-suppressed finding has severity >= threshold.
    fn should_detect(findings: &[FindingSummary], threshold: Severity) -> bool {
        findings
            .iter()
            .any(|f| !f.suppressed && f.severity >= threshold)
    }

    // ── Property 6: Exit Code Threshold Correctness ──────────────────────────

    proptest! {
        /// P6: For any findings list and threshold, exit code is FindingsDetected (1)
        /// iff at least one non-suppressed finding has severity >= threshold.
        #[test]
        fn p6_exit_code_matches_threshold_predicate(
            findings in arb_findings(),
            threshold in arb_severity(),
        ) {
            let code = ExitCode::from_findings(&findings, threshold, 0.0);
            let expected_detect = should_detect(&findings, threshold);

            if expected_detect {
                prop_assert_eq!(
                    code,
                    ExitCode::FindingsDetected,
                    "Expected FindingsDetected(1) but got Clean(0) for threshold={:?}",
                    threshold
                );
            } else {
                prop_assert_eq!(
                    code,
                    ExitCode::Clean,
                    "Expected Clean(0) but got FindingsDetected(1) for threshold={:?}",
                    threshold
                );
            }
        }

        /// P6 corollary: empty findings list always yields Clean exit code.
        #[test]
        fn p6_empty_findings_always_clean(threshold in arb_severity()) {
            let code = ExitCode::from_findings(&[], threshold, 0.0);
            prop_assert_eq!(code, ExitCode::Clean);
        }

        /// P6 corollary: all-suppressed findings always yield Clean exit code.
        #[test]
        fn p6_all_suppressed_always_clean(
            severities in proptest::collection::vec(arb_severity(), 1..=20),
            threshold in arb_severity(),
        ) {
            let findings: Vec<FindingSummary> = severities
                .into_iter()
                .map(|severity| FindingSummary {
                    severity,
                    confidence_score: 1.0,
                    suppressed: true,
                })
                .collect();
            let code = ExitCode::from_findings(&findings, threshold, 0.0);
            prop_assert_eq!(code, ExitCode::Clean);
        }

        /// P6 corollary: a single non-suppressed Critical finding always triggers
        /// FindingsDetected for any threshold <= Critical.
        #[test]
        fn p6_critical_finding_triggers_detect_for_all_thresholds(
            threshold in arb_severity(),
        ) {
            let findings = vec![FindingSummary {
                severity: Severity::Critical,
                confidence_score: 1.0,
                suppressed: false,
            }];
            // Critical >= every threshold, so always FindingsDetected
            let code = ExitCode::from_findings(&findings, threshold, 0.0);
            prop_assert_eq!(code, ExitCode::FindingsDetected);
        }

        /// P6 corollary: Info-only findings are Clean when threshold is Low or above.
        #[test]
        fn p6_info_findings_clean_above_low_threshold(
            count in 1usize..=20usize,
            threshold in prop_oneof![
                Just(Severity::Low),
                Just(Severity::Medium),
                Just(Severity::High),
                Just(Severity::Critical),
            ],
        ) {
            let findings: Vec<FindingSummary> = (0..count)
                .map(|_| FindingSummary {
                    severity: Severity::Info,
                    confidence_score: 1.0,
                    suppressed: false,
                })
                .collect();
            let code = ExitCode::from_findings(&findings, threshold, 0.0);
            prop_assert_eq!(code, ExitCode::Clean);
        }
    }

    // ── Determinism check ────────────────────────────────────────────────────

    proptest! {
        /// The exit code computation is deterministic: same inputs always produce
        /// the same output.
        #[test]
        fn p6_exit_code_is_deterministic(
            findings in arb_findings(),
            threshold in arb_severity(),
        ) {
            let code1 = ExitCode::from_findings(&findings, threshold, 0.0);
            let code2 = ExitCode::from_findings(&findings, threshold, 0.0);
            prop_assert_eq!(code1, code2);
        }
    }
}
