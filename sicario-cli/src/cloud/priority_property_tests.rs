//! Property-based tests for cloud priority assignment.
//!
//! Feature: sicario-cli-core
//! Property 29 — Priority assignment by exposure
//!
//! Validates: Requirements 11.3, 11.4

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use uuid::Uuid;

    use crate::cloud::exposure::CloudExposureAnalyzer;
    use crate::cloud::interfaces::{ExposureStatus, KubernetesConfig};
    use crate::cloud::priority::assign_cloud_priority;
    use crate::engine::{Severity, Vulnerability};

    // ── Generators ────────────────────────────────────────────────────────────

    fn arb_severity() -> impl Strategy<Value = Severity> {
        prop_oneof![
            Just(Severity::Critical),
            Just(Severity::High),
            Just(Severity::Medium),
            Just(Severity::Low),
            Just(Severity::Info),
        ]
    }

    fn arb_service_name() -> impl Strategy<Value = String> {
        "[a-z]{3,10}"
    }

    fn arb_rule_id() -> impl Strategy<Value = String> {
        "[a-z]{4,8}-[0-9]{3}"
    }

    fn make_vuln(file: &str, severity: Severity) -> Vulnerability {
        Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "test-rule".to_string(),
            file_path: PathBuf::from(file),
            line: 10,
            column: 5,
            snippet: "unsafe_call()".to_string(),
            severity,
            reachable: true,
            cloud_exposed: None,
            cwe_id: None,
            owasp_category: None,
        }
    }

    fn make_k8s_service(name: &str, svc_type: &str) -> KubernetesConfig {
        KubernetesConfig {
            kind: "Service".to_string(),
            namespace: "default".to_string(),
            name: name.to_string(),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            service_type: Some(svc_type.to_string()),
            ports: vec![80],
            has_external_ingress: false,
            source_file: PathBuf::from("k8s/service.yaml"),
        }
    }

    fn demote(s: Severity) -> Severity {
        match s {
            Severity::Critical => Severity::High,
            Severity::High => Severity::Medium,
            Severity::Medium => Severity::Low,
            Severity::Low | Severity::Info => Severity::Info,
        }
    }

    // ── Property 29: Priority assignment by exposure ──────────────────────────
    //
    // Feature: sicario-cli-core, Property 29: Priority assignment by exposure
    // Validates: Requirements 11.3, 11.4
    //
    // For any vulnerability in a publicly exposed service, assign_cloud_priority()
    // must escalate its severity to Critical and set cloud_exposed = Some(true).
    //
    // For any vulnerability in an internal isolated service, assign_cloud_priority()
    // must demote its severity by one level and set cloud_exposed = Some(false).

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// Requirement 11.3: For any vulnerability whose file belongs to a
        /// publicly exposed service (LoadBalancer), severity must be escalated
        /// to Critical and cloud_exposed must be Some(true).
        ///
        /// Feature: sicario-cli-core, Property 29: Priority assignment by exposure
        #[test]
        fn prop29_public_exposure_always_escalates_to_critical(
            service in arb_service_name(),
            initial_severity in arb_severity(),
        ) {
            let mut analyzer = CloudExposureAnalyzer::new();
            analyzer.ingest_kubernetes_configs(vec![
                make_k8s_service(&service, "LoadBalancer"),
            ]);

            let file_path = format!("services/{}/handler.rs", service);
            let mut vulns = vec![make_vuln(&file_path, initial_severity)];

            assign_cloud_priority(&mut vulns, &analyzer);

            prop_assert_eq!(
                vulns[0].severity,
                Severity::Critical,
                "Publicly exposed service must always escalate severity to Critical. \
                 Service: '{}', initial severity: {:?}",
                service, initial_severity
            );
            prop_assert_eq!(
                vulns[0].cloud_exposed,
                Some(true),
                "cloud_exposed must be Some(true) for publicly exposed service. \
                 Service: '{}'",
                service
            );
        }

        /// Requirement 11.4: For any vulnerability whose file belongs to an
        /// internal isolated service (ClusterIP), severity must be demoted by
        /// exactly one level and cloud_exposed must be Some(false).
        ///
        /// Feature: sicario-cli-core, Property 29: Priority assignment by exposure
        #[test]
        fn prop29_internal_service_always_demotes_severity(
            service in arb_service_name(),
            initial_severity in arb_severity(),
        ) {
            let mut analyzer = CloudExposureAnalyzer::new();
            analyzer.ingest_kubernetes_configs(vec![
                make_k8s_service(&service, "ClusterIP"),
            ]);

            let file_path = format!("services/{}/handler.rs", service);
            let mut vulns = vec![make_vuln(&file_path, initial_severity)];

            assign_cloud_priority(&mut vulns, &analyzer);

            let expected = demote(initial_severity);
            prop_assert_eq!(
                vulns[0].severity,
                expected,
                "Internal service must demote severity by one level. \
                 Service: '{}', initial: {:?}, expected: {:?}",
                service, initial_severity, expected
            );
            prop_assert_eq!(
                vulns[0].cloud_exposed,
                Some(false),
                "cloud_exposed must be Some(false) for internal service. \
                 Service: '{}'",
                service
            );
        }

        /// Requirements 11.3 + 11.4: For any pair of identical vulnerabilities
        /// (same rule, same initial severity) where one is in a public service
        /// and the other in an internal service, the public one must always have
        /// higher or equal severity than the internal one after priority assignment.
        ///
        /// Feature: sicario-cli-core, Property 29: Priority assignment by exposure
        #[test]
        fn prop29_public_severity_always_gte_internal_severity(
            public_service in arb_service_name(),
            internal_service in "[a-z]{3,10}worker",
            initial_severity in arb_severity(),
        ) {
            // Ensure the two service names are distinct
            prop_assume!(public_service != internal_service);

            let mut analyzer = CloudExposureAnalyzer::new();
            analyzer.ingest_kubernetes_configs(vec![
                make_k8s_service(&public_service, "LoadBalancer"),
                make_k8s_service(&internal_service, "ClusterIP"),
            ]);

            let public_file = format!("services/{}/handler.rs", public_service);
            let internal_file = format!("services/{}/handler.rs", internal_service);

            let mut vulns = vec![
                make_vuln(&public_file, initial_severity),
                make_vuln(&internal_file, initial_severity),
            ];

            assign_cloud_priority(&mut vulns, &analyzer);

            let public_sev = severity_rank(vulns[0].severity);
            let internal_sev = severity_rank(vulns[1].severity);

            prop_assert!(
                public_sev >= internal_sev,
                "Public service severity ({:?}) must be >= internal service severity ({:?}) \
                 for the same initial severity ({:?})",
                vulns[0].severity, vulns[1].severity, initial_severity
            );
        }

        /// For any vulnerability in a file with no matching service, severity
        /// and cloud_exposed must remain unchanged (Unknown exposure = no-op).
        ///
        /// Feature: sicario-cli-core, Property 29: Priority assignment by exposure
        #[test]
        fn prop29_unknown_exposure_leaves_severity_unchanged(
            initial_severity in arb_severity(),
            file_stem in "[a-z]{4,12}",
        ) {
            // Empty analyzer — no services registered
            let analyzer = CloudExposureAnalyzer::new();

            let file_path = format!("src/{}.rs", file_stem);
            let mut vulns = vec![make_vuln(&file_path, initial_severity)];

            assign_cloud_priority(&mut vulns, &analyzer);

            prop_assert_eq!(
                vulns[0].severity,
                initial_severity,
                "Unknown exposure must leave severity unchanged. \
                 File: '{}', initial: {:?}",
                file_path, initial_severity
            );
            prop_assert_eq!(
                vulns[0].cloud_exposed,
                None,
                "cloud_exposed must remain None for unknown exposure. File: '{}'",
                file_path
            );
        }

        /// For any list of vulnerabilities across multiple services, each
        /// vulnerability must be independently assigned priority based solely
        /// on its own file's exposure status.
        ///
        /// Feature: sicario-cli-core, Property 29: Priority assignment by exposure
        #[test]
        fn prop29_priority_assignment_is_per_vulnerability(
            service_a in "[a-z]{3,8}api",
            service_b in "[a-z]{3,8}db",
            sev_a in arb_severity(),
            sev_b in arb_severity(),
        ) {
            prop_assume!(service_a != service_b);

            let mut analyzer = CloudExposureAnalyzer::new();
            // service_a is public, service_b is internal
            analyzer.ingest_kubernetes_configs(vec![
                make_k8s_service(&service_a, "LoadBalancer"),
                make_k8s_service(&service_b, "ClusterIP"),
            ]);

            let file_a = format!("services/{}/handler.rs", service_a);
            let file_b = format!("services/{}/handler.rs", service_b);

            let mut vulns = vec![
                make_vuln(&file_a, sev_a),
                make_vuln(&file_b, sev_b),
            ];

            assign_cloud_priority(&mut vulns, &analyzer);

            // service_a (public) → Critical
            prop_assert_eq!(
                vulns[0].severity,
                Severity::Critical,
                "Public service vuln must be Critical regardless of other vulns. \
                 Service: '{}', initial: {:?}",
                service_a, sev_a
            );
            prop_assert_eq!(vulns[0].cloud_exposed, Some(true));

            // service_b (internal) → demoted
            let expected_b = demote(sev_b);
            prop_assert_eq!(
                vulns[1].severity,
                expected_b,
                "Internal service vuln must be demoted. \
                 Service: '{}', initial: {:?}, expected: {:?}",
                service_b, sev_b, expected_b
            );
            prop_assert_eq!(vulns[1].cloud_exposed, Some(false));
        }
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    /// Map severity to a numeric rank for ordering comparisons.
    fn severity_rank(s: Severity) -> u8 {
        match s {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }
}
