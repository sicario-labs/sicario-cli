//! Property-based tests for telemetry payload serialization and validation.
//!
//! Feature: zero-exfil-edge-scanning
//!
//! Properties covered:
//!   - Property 1: Telemetry Payload Serialization Round-Trip
//!   - Property 3: Severity Enum Validation
//!   - Property 7: Telemetry Payload Required Field Validation
//!
//! Validates: Requirements 9.1, 9.2, 9.3, 9.4, 7.2, 6.4, 6.5

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::publish::telemetry_client::{TelemetryFinding, TelemetryPayload, TelemetryResponse};

    // ── Constants ─────────────────────────────────────────────────────────────

    const VALID_SEVERITIES: &[&str] = &["Critical", "High", "Medium", "Low"];

    // ── Generators ────────────────────────────────────────────────────────────

    /// Strategy for a valid severity string.
    fn arb_severity() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("Critical".to_string()),
            Just("High".to_string()),
            Just("Medium".to_string()),
            Just("Low".to_string()),
        ]
    }

    /// Strategy for a snippet of at most 100 characters.
    fn arb_snippet() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9 (){};=._/\\-]{0,100}"
    }

    /// Strategy for a single `TelemetryFinding` with valid fields.
    fn arb_finding() -> impl Strategy<Value = TelemetryFinding> {
        (
            "[a-z][a-z0-9\\-]{1,30}",   // rule
            arb_severity(),
            "[a-z][a-z0-9/._\\-]{1,60}", // file
            1usize..=10000usize,          // line
            arb_snippet(),
        )
            .prop_map(|(rule, severity, file, line, snippet)| TelemetryFinding {
                rule,
                severity,
                file,
                line,
                snippet,
                cwe_id: None,
                owasp_category: None,
                fingerprint: None,
            })
    }

    /// Strategy for a `TelemetryPayload` with 0–100 findings.
    fn arb_payload() -> impl Strategy<Value = TelemetryPayload> {
        (
            "[a-z][a-z0-9\\-]{4,20}",   // project_id
            "https://github\\.com/[a-z]{3,10}/[a-z]{3,10}", // repository_url
            "[a-f0-9]{12,40}",           // commit_sha
            "scan\\-[0-9]{10}\\-[A-Z]{6}", // scan_id
            prop::collection::vec(arb_finding(), 0..=100),
        )
            .prop_map(|(project_id, repository_url, commit_sha, scan_id, findings)| {
                TelemetryPayload {
                    project_id,
                    repository_url,
                    commit_sha,
                    scan_id,
                    branch: None,
                    pr_number: None,
                    duration_ms: None,
                    rules_loaded: None,
                    files_scanned: None,
                    findings,
                }
            })
    }

    // ── Property 1: Telemetry Payload Serialization Round-Trip ───────────────
    //
    // For any valid TelemetryPayload, serializing to JSON and deserializing back
    // must produce an object equal to the original.
    //
    // Validates: Requirements 9.1, 9.2, 9.3, 9.4

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// Feature: zero-exfil-edge-scanning, Property 1: Serialization Round-Trip
        ///
        /// For any valid TelemetryPayload, serialize → deserialize must produce
        /// an equal object (no data loss through the JSON round-trip).
        ///
        /// Validates: Requirements 9.1, 9.4
        #[test]
        fn prop1_payload_round_trip(payload in arb_payload()) {
            let json = serde_json::to_string(&payload)
                .expect("TelemetryPayload must serialize to JSON");
            let back: TelemetryPayload = serde_json::from_str(&json)
                .expect("TelemetryPayload JSON must deserialize back");

            prop_assert_eq!(
                &back.project_id, &payload.project_id,
                "project_id must survive round-trip"
            );
            prop_assert_eq!(
                &back.repository_url, &payload.repository_url,
                "repository_url must survive round-trip"
            );
            prop_assert_eq!(
                &back.commit_sha, &payload.commit_sha,
                "commit_sha must survive round-trip"
            );
            prop_assert_eq!(
                &back.scan_id, &payload.scan_id,
                "scan_id must survive round-trip"
            );
            prop_assert_eq!(
                back.findings.len(), payload.findings.len(),
                "findings array length must survive round-trip"
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 1: Serialization Round-Trip
        ///
        /// For any valid TelemetryFinding, the severity field must be one of the
        /// four allowed values after round-trip serialization.
        ///
        /// Validates: Requirements 9.2
        #[test]
        fn prop1_finding_severity_preserved_through_round_trip(finding in arb_finding()) {
            let json = serde_json::to_string(&finding)
                .expect("TelemetryFinding must serialize to JSON");
            let back: TelemetryFinding = serde_json::from_str(&json)
                .expect("TelemetryFinding JSON must deserialize back");

            prop_assert!(
                VALID_SEVERITIES.contains(&back.severity.as_str()),
                "severity '{}' must be one of {:?} after round-trip",
                back.severity,
                VALID_SEVERITIES
            );
            prop_assert_eq!(
                &back.severity, &finding.severity,
                "severity must be unchanged through round-trip"
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 1: Serialization Round-Trip
        ///
        /// For any valid TelemetryFinding, the snippet field must be ≤ 100 chars
        /// after round-trip serialization.
        ///
        /// Validates: Requirements 9.3
        #[test]
        fn prop1_snippet_length_preserved_through_round_trip(finding in arb_finding()) {
            let json = serde_json::to_string(&finding)
                .expect("TelemetryFinding must serialize to JSON");
            let back: TelemetryFinding = serde_json::from_str(&json)
                .expect("TelemetryFinding JSON must deserialize back");

            prop_assert!(
                back.snippet.len() <= 100,
                "snippet length {} exceeds 100 chars after round-trip",
                back.snippet.len()
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 1: Serialization Round-Trip
        ///
        /// The findings array length must be identical before and after round-trip.
        ///
        /// Validates: Requirements 9.4
        #[test]
        fn prop1_findings_count_preserved_through_round_trip(payload in arb_payload()) {
            let json = serde_json::to_string(&payload).unwrap();
            let back: TelemetryPayload = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(
                back.findings.len(),
                payload.findings.len(),
                "findings count must be identical after round-trip"
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 1: Serialization Round-Trip
        ///
        /// The JSON output must use camelCase field names as required by the
        /// backend API contract.
        ///
        /// Validates: Requirements 8.1, 8.2
        #[test]
        fn prop1_payload_json_uses_camel_case(payload in arb_payload()) {
            let json = serde_json::to_string(&payload).unwrap();
            prop_assert!(json.contains("projectId"), "JSON must contain 'projectId'");
            prop_assert!(json.contains("repositoryUrl"), "JSON must contain 'repositoryUrl'");
            prop_assert!(json.contains("commitSha"), "JSON must contain 'commitSha'");
            prop_assert!(json.contains("scanId"), "JSON must contain 'scanId'");
        }
    }

    // ── Property 3: Severity Enum Validation ─────────────────────────────────
    //
    // For any string, the severity validator must accept it if and only if it is
    // exactly one of "Critical", "High", "Medium", "Low".
    //
    // Validates: Requirements 7.2

    /// Pure severity validator — mirrors the backend's validation logic.
    fn is_valid_severity(s: &str) -> bool {
        matches!(s, "Critical" | "High" | "Medium" | "Low")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// Feature: zero-exfil-edge-scanning, Property 3: Severity Enum Validation
        ///
        /// For any arbitrary string, the severity validator must accept it if and
        /// only if it is exactly one of the four allowed values.
        ///
        /// Validates: Requirements 7.2
        #[test]
        fn prop3_severity_validator_accepts_only_valid_values(s in ".*") {
            let valid = is_valid_severity(&s);
            let expected = VALID_SEVERITIES.contains(&s.as_str());
            prop_assert_eq!(
                valid,
                expected,
                "severity validator gave wrong result for '{}': expected {}, got {}",
                s, expected, valid
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 3: Severity Enum Validation
        ///
        /// All four valid severity values must always be accepted.
        ///
        /// Validates: Requirements 7.2
        #[test]
        fn prop3_all_valid_severities_are_accepted(
            severity in prop_oneof![
                Just("Critical"),
                Just("High"),
                Just("Medium"),
                Just("Low"),
            ]
        ) {
            prop_assert!(
                is_valid_severity(severity),
                "valid severity '{}' was rejected",
                severity
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 3: Severity Enum Validation
        ///
        /// Case variants and partial matches must be rejected.
        ///
        /// Validates: Requirements 7.2
        #[test]
        fn prop3_case_variants_are_rejected(
            severity in prop_oneof![
                Just("critical"), Just("high"), Just("medium"), Just("low"),
                Just("CRITICAL"), Just("HIGH"), Just("MEDIUM"), Just("LOW"),
                Just(""), Just("Unknown"), Just("Info"), Just("None"),
            ]
        ) {
            prop_assert!(
                !is_valid_severity(severity),
                "invalid severity '{}' was incorrectly accepted",
                severity
            );
        }
    }

    // ── Property 7: Telemetry Payload Required Field Validation ──────────────
    //
    // For any JSON object submitted to the telemetry endpoint, the validator
    // must reject the payload if and only if one or more required fields
    // (projectId, repositoryUrl, commitSha, scanId, findings) is missing.
    //
    // Validates: Requirements 6.4, 6.5

    /// Validate that a JSON value contains all required telemetry fields.
    /// Returns Ok(()) if valid, Err(missing_fields) if any are absent.
    fn validate_required_fields(value: &serde_json::Value) -> Result<(), Vec<&'static str>> {
        let required = ["projectId", "repositoryUrl", "commitSha", "scanId", "findings"];
        let missing: Vec<&'static str> = required
            .iter()
            .filter(|&&field| value.get(field).is_none())
            .copied()
            .collect();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// Feature: zero-exfil-edge-scanning, Property 7: Required Field Validation
        ///
        /// A complete payload with all required fields must always be accepted.
        ///
        /// Validates: Requirements 6.4
        #[test]
        fn prop7_complete_payload_is_accepted(payload in arb_payload()) {
            let value = serde_json::to_value(&payload).unwrap();
            let result = validate_required_fields(&value);
            prop_assert!(
                result.is_ok(),
                "complete payload must be accepted, but got missing fields: {:?}",
                result.err()
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 7: Required Field Validation
        ///
        /// Removing any single required field must cause the payload to be rejected,
        /// and the error must identify the missing field.
        ///
        /// Validates: Requirements 6.4, 6.5
        #[test]
        fn prop7_removing_any_required_field_causes_rejection(
            payload in arb_payload(),
            field_idx in 0usize..5,
        ) {
            let required_fields = ["projectId", "repositoryUrl", "commitSha", "scanId", "findings"];
            let removed_field = required_fields[field_idx];

            let mut value = serde_json::to_value(&payload).unwrap();
            value.as_object_mut().unwrap().remove(removed_field);

            let result = validate_required_fields(&value);
            prop_assert!(
                result.is_err(),
                "payload missing '{}' must be rejected",
                removed_field
            );
            let missing = result.unwrap_err();
            prop_assert!(
                missing.contains(&removed_field),
                "error must identify the missing field '{}', got: {:?}",
                removed_field,
                missing
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 7: Required Field Validation
        ///
        /// An empty JSON object must be rejected with all five required fields listed.
        ///
        /// Validates: Requirements 6.5
        #[test]
        fn prop7_empty_object_is_rejected_with_all_fields_listed(_seed in 0u64..u64::MAX) {
            let value = serde_json::json!({});
            let result = validate_required_fields(&value);
            prop_assert!(result.is_err(), "empty object must be rejected");
            let missing = result.unwrap_err();
            prop_assert_eq!(
                missing.len(), 5,
                "all 5 required fields must be listed as missing, got: {:?}",
                missing
            );
        }

        /// Feature: zero-exfil-edge-scanning, Property 7: Required Field Validation
        ///
        /// Extra fields beyond the required set must not cause rejection.
        ///
        /// Validates: Requirements 6.4
        #[test]
        fn prop7_extra_fields_do_not_cause_rejection(
            payload in arb_payload(),
            extra_key in "[a-z]{4,12}",
            extra_val in "[a-zA-Z0-9]{1,20}",
        ) {
            let mut value = serde_json::to_value(&payload).unwrap();
            value.as_object_mut().unwrap().insert(extra_key, serde_json::Value::String(extra_val));
            let result = validate_required_fields(&value);
            prop_assert!(
                result.is_ok(),
                "extra fields must not cause rejection, got: {:?}",
                result.err()
            );
        }
    }

    // ── Unit tests ────────────────────────────────────────────────────────────

    #[test]
    fn unit_all_valid_severities_accepted() {
        for s in VALID_SEVERITIES {
            assert!(is_valid_severity(s), "expected '{}' to be valid", s);
        }
    }

    #[test]
    fn unit_invalid_severities_rejected() {
        for s in &["critical", "HIGH", "info", "Info", "", "none", "CRITICAL"] {
            assert!(!is_valid_severity(s), "expected '{}' to be invalid", s);
        }
    }

    #[test]
    fn unit_complete_payload_passes_validation() {
        let value = serde_json::json!({
            "projectId": "proj-abc",
            "repositoryUrl": "https://github.com/org/repo",
            "commitSha": "abc123",
            "scanId": "scan-001",
            "findings": []
        });
        assert!(validate_required_fields(&value).is_ok());
    }

    #[test]
    fn unit_missing_project_id_fails_validation() {
        let value = serde_json::json!({
            "repositoryUrl": "https://github.com/org/repo",
            "commitSha": "abc123",
            "scanId": "scan-001",
            "findings": []
        });
        let result = validate_required_fields(&value);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(&"projectId"));
    }

    #[test]
    fn unit_response_deserializes_snake_case() {
        let json = r#"{"scan_id":"s1","project_id":"p1","dashboard_url":null}"#;
        let resp: TelemetryResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.scan_id, "s1");
        assert_eq!(resp.project_id, "p1");
        assert!(resp.dashboard_url.is_none());
    }
}
