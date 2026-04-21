//! Priority assignment based on cloud exposure
//!
//! Assigns critical priority to vulnerabilities in publicly exposed services
//! and deprioritises identical vulnerabilities in internal isolated services.
//!
//! Requirements: 11.3, 11.4

use crate::engine::{Severity, Vulnerability};
use super::interfaces::ExposureStatus;
use super::exposure::CloudExposureAnalyzer;

/// Assign cloud-aware priority to a list of vulnerabilities.
///
/// Rules (Requirements 11.3, 11.4):
/// - If the vulnerability's file is in a publicly exposed service → escalate to Critical
/// - If the vulnerability's file is in an internal isolated service → demote one level
/// - If exposure is unknown → leave severity unchanged
///
/// Also sets `vulnerability.cloud_exposed` to reflect the determination.
pub fn assign_cloud_priority(
    vulnerabilities: &mut Vec<Vulnerability>,
    analyzer: &CloudExposureAnalyzer,
) {
    for vuln in vulnerabilities.iter_mut() {
        let exposure = analyzer.exposure_for_file(&vuln.file_path);
        match exposure.exposure {
            ExposureStatus::PubliclyExposed => {
                // Requirement 11.3: escalate to Critical for publicly exposed services
                vuln.severity = Severity::Critical;
                vuln.cloud_exposed = Some(true);
            }
            ExposureStatus::Internal => {
                // Requirement 11.4: deprioritise for internal isolated services
                vuln.severity = demote_severity(vuln.severity);
                vuln.cloud_exposed = Some(false);
            }
            ExposureStatus::Unknown => {
                // Leave severity unchanged; cloud_exposed stays None
            }
        }
    }
}

/// Demote a severity level by one step.
///
/// Critical → High → Medium → Low → Info (floor)
fn demote_severity(severity: Severity) -> Severity {
    match severity {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low | Severity::Info => Severity::Info,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::OwaspCategory;
    use crate::cloud::interfaces::{CloudProvider, CspmFinding, KubernetesConfig};
    use std::collections::HashMap;
    use std::path::PathBuf;
    use uuid::Uuid;

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

    #[test]
    fn test_public_exposure_escalates_to_critical() {
        let mut analyzer = CloudExposureAnalyzer::new();
        analyzer.ingest_kubernetes_configs(vec![make_k8s_service("api", "LoadBalancer")]);

        let mut vulns = vec![make_vuln("services/api/handler.rs", Severity::Medium)];
        assign_cloud_priority(&mut vulns, &analyzer);

        assert_eq!(vulns[0].severity, Severity::Critical);
        assert_eq!(vulns[0].cloud_exposed, Some(true));
    }

    #[test]
    fn test_internal_service_demotes_severity() {
        let mut analyzer = CloudExposureAnalyzer::new();
        analyzer.ingest_kubernetes_configs(vec![make_k8s_service("db", "ClusterIP")]);

        let mut vulns = vec![make_vuln("services/db/queries.rs", Severity::High)];
        assign_cloud_priority(&mut vulns, &analyzer);

        assert_eq!(vulns[0].severity, Severity::Medium);
        assert_eq!(vulns[0].cloud_exposed, Some(false));
    }

    #[test]
    fn test_unknown_exposure_leaves_severity_unchanged() {
        let analyzer = CloudExposureAnalyzer::new();

        let mut vulns = vec![make_vuln("src/utils.rs", Severity::High)];
        assign_cloud_priority(&mut vulns, &analyzer);

        assert_eq!(vulns[0].severity, Severity::High);
        assert_eq!(vulns[0].cloud_exposed, None);
    }

    #[test]
    fn test_demote_severity_chain() {
        assert_eq!(demote_severity(Severity::Critical), Severity::High);
        assert_eq!(demote_severity(Severity::High), Severity::Medium);
        assert_eq!(demote_severity(Severity::Medium), Severity::Low);
        assert_eq!(demote_severity(Severity::Low), Severity::Info);
        assert_eq!(demote_severity(Severity::Info), Severity::Info);
    }

    #[test]
    fn test_identical_vuln_different_exposure() {
        // Requirement 11.3 + 11.4: same rule, one public, one internal
        let mut analyzer = CloudExposureAnalyzer::new();
        analyzer.ingest_kubernetes_configs(vec![
            make_k8s_service("api", "LoadBalancer"),
            make_k8s_service("worker", "ClusterIP"),
        ]);

        let mut vulns = vec![
            make_vuln("services/api/handler.rs", Severity::High),
            make_vuln("services/worker/processor.rs", Severity::High),
        ];
        assign_cloud_priority(&mut vulns, &analyzer);

        // Public service → Critical
        assert_eq!(vulns[0].severity, Severity::Critical);
        assert_eq!(vulns[0].cloud_exposed, Some(true));

        // Internal service → demoted to Medium
        assert_eq!(vulns[1].severity, Severity::Medium);
        assert_eq!(vulns[1].cloud_exposed, Some(false));
    }

    #[test]
    fn test_critical_public_stays_critical() {
        let mut analyzer = CloudExposureAnalyzer::new();
        analyzer.ingest_kubernetes_configs(vec![make_k8s_service("api", "LoadBalancer")]);

        let mut vulns = vec![make_vuln("services/api/handler.rs", Severity::Critical)];
        assign_cloud_priority(&mut vulns, &analyzer);

        // Already Critical — stays Critical
        assert_eq!(vulns[0].severity, Severity::Critical);
    }

    #[test]
    fn test_info_internal_stays_info() {
        let mut analyzer = CloudExposureAnalyzer::new();
        analyzer.ingest_kubernetes_configs(vec![make_k8s_service("db", "ClusterIP")]);

        let mut vulns = vec![make_vuln("services/db/queries.rs", Severity::Info)];
        assign_cloud_priority(&mut vulns, &analyzer);

        // Info is the floor — stays Info
        assert_eq!(vulns[0].severity, Severity::Info);
    }
}
