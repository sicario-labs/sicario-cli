//! Property-based tests for telemetry data integrity.
//!
//! Feature: sicario-cli-core, Property 22: Telemetry data integrity
//!
//! For any detected vulnerability, the telemetry data pushed to Convex should
//! accurately represent all vulnerability attributes including file path,
//! vulnerability type, severity, and timestamp.
//!
//! Validates: Requirements 8.2

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    use crate::convex::telemetry::{TelemetryAction, TelemetryEvent};
    use crate::engine::{OwaspCategory, Severity, Vulnerability};

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

    fn arb_owasp() -> impl Strategy<Value = Option<OwaspCategory>> {
        prop_oneof![
            Just(None),
            Just(Some(OwaspCategory::A01_BrokenAccessControl)),
            Just(Some(OwaspCategory::A02_CryptographicFailures)),
            Just(Some(OwaspCategory::A03_Injection)),
            Just(Some(OwaspCategory::A06_VulnerableComponents)),
            Just(Some(OwaspCategory::A10_ServerSideRequestForgery)),
        ]
    }

    fn arb_action() -> impl Strategy<Value = TelemetryAction> {
        prop_oneof![
            Just(TelemetryAction::Detected),
            Just(TelemetryAction::Dismissed),
            Just(TelemetryAction::Fixed),
        ]
    }

    fn arb_vulnerability() -> impl Strategy<Value = Vulnerability> {
        (
            "[a-z][a-z0-9-]{1,30}",     // rule_id
            "[a-z][a-z0-9/._-]{1,60}",  // file_path
            1usize..=5000usize,         // line
            1usize..=200usize,          // column
            "[a-zA-Z0-9 (){};=]{5,80}", // snippet
            arb_severity(),
            proptest::bool::ANY, // reachable
            arb_owasp(),
        )
            .prop_map(
                |(rule_id, file_path, line, column, snippet, severity, reachable, owasp)| {
                    Vulnerability {
                        id: Uuid::new_v4(),
                        rule_id,
                        file_path: PathBuf::from(file_path),
                        line,
                        column,
                        snippet,
                        severity,
                        reachable,
                        cloud_exposed: None,
                        cwe_id: None,
                        owasp_category: owasp,
                    }
                },
            )
    }

    // ── Property 22: Telemetry data integrity ────────────────────────────────

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// For any vulnerability and action, the resulting TelemetryEvent must
        /// faithfully preserve every attribute of the original vulnerability.
        ///
        /// Feature: sicario-cli-core, Property 22: Telemetry data integrity
        /// Validates: Requirements 8.2
        #[test]
        fn prop_telemetry_preserves_all_vulnerability_attributes(
            vuln in arb_vulnerability(),
            action in arb_action(),
        ) {
            let event = TelemetryEvent::from_vulnerability(&vuln, action.clone());

            // All vulnerability attributes must be faithfully preserved
            prop_assert_eq!(&event.vulnerability_id, &vuln.id.to_string());
            prop_assert_eq!(&event.rule_id, &vuln.rule_id);
            prop_assert_eq!(
                &event.file_path,
                &vuln.file_path.to_string_lossy().to_string()
            );
            prop_assert_eq!(event.line, vuln.line);
            prop_assert_eq!(event.column, vuln.column);
            prop_assert_eq!(&event.snippet, &vuln.snippet);
            prop_assert_eq!(event.severity, vuln.severity);
            prop_assert_eq!(event.reachable, vuln.reachable);
            prop_assert_eq!(event.owasp_category, vuln.owasp_category);
            prop_assert_eq!(event.action, action);
        }

        /// For any vulnerability, the telemetry event must serialise to valid
        /// JSON that can be deserialised back to an equivalent event without
        /// data loss (round-trip property).
        ///
        /// Feature: sicario-cli-core, Property 22: Telemetry data integrity
        /// Validates: Requirements 8.2
        #[test]
        fn prop_telemetry_serialization_round_trip(
            vuln in arb_vulnerability(),
            action in arb_action(),
        ) {
            let event = TelemetryEvent::from_vulnerability(&vuln, action);

            let json = serde_json::to_string(&event)
                .expect("TelemetryEvent must serialise to JSON");
            let back: TelemetryEvent = serde_json::from_str(&json)
                .expect("TelemetryEvent JSON must deserialise back");

            prop_assert_eq!(&back.rule_id, &event.rule_id);
            prop_assert_eq!(&back.file_path, &event.file_path);
            prop_assert_eq!(back.line, event.line);
            prop_assert_eq!(back.column, event.column);
            prop_assert_eq!(back.severity, event.severity);
            prop_assert_eq!(back.reachable, event.reachable);
            prop_assert_eq!(back.owasp_category, event.owasp_category);
            prop_assert_eq!(back.action, event.action);
        }

        /// For any vulnerability, the telemetry JSON payload must contain the
        /// OWASP category field (even when None) to satisfy compliance reporting
        /// requirements (Req 17.4).
        ///
        /// Feature: sicario-cli-core, Property 22: Telemetry data integrity
        /// Validates: Requirements 8.2, 17.4
        #[test]
        fn prop_telemetry_json_always_contains_owasp_field(
            vuln in arb_vulnerability(),
        ) {
            let event = TelemetryEvent::from_vulnerability(&vuln, TelemetryAction::Detected);
            let json = serde_json::to_string(&event).unwrap();
            // The owasp_category key must always be present in the JSON payload
            prop_assert!(
                json.contains("owasp_category"),
                "JSON payload must contain owasp_category field: {}",
                json
            );
        }
    }
}
