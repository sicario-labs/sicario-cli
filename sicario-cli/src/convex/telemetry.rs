//! Telemetry event types for the Convex backend.
//!
//! Captures detected, dismissed, and fixed vulnerability events and serialises
//! them for transmission over the WebSocket connection.
//!
//! Requirements: 8.2, 17.4

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::engine::{OwaspCategory, Severity, Vulnerability};

/// The action taken on a vulnerability that triggered this telemetry event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryAction {
    /// Vulnerability was detected during a scan
    Detected,
    /// Developer dismissed the finding (false positive or accepted risk)
    Dismissed,
    /// Developer applied a patch and the vulnerability was fixed
    Fixed,
}

/// A telemetry event pushed to the Convex backend.
///
/// Includes all vulnerability attributes required by Requirements 8.2 and 17.4:
/// file path, vulnerability type (rule_id), severity, timestamp, and OWASP category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// ISO-8601 timestamp of when the event occurred
    pub timestamp: DateTime<Utc>,
    /// Action that triggered this event
    pub action: TelemetryAction,
    /// Unique identifier of the vulnerability (UUID)
    pub vulnerability_id: String,
    /// Security rule that triggered the finding (e.g. "sql-injection")
    pub rule_id: String,
    /// Path of the affected file, relative to the project root
    pub file_path: String,
    /// 1-indexed line number of the finding
    pub line: usize,
    /// 1-indexed column number of the finding
    pub column: usize,
    /// Short code snippet showing the vulnerable code
    pub snippet: String,
    /// Severity level of the finding
    pub severity: Severity,
    /// Whether the vulnerability is reachable from an external taint source
    pub reachable: bool,
    /// Whether the affected service is publicly cloud-exposed (if known)
    pub cloud_exposed: Option<bool>,
    /// CWE identifier, e.g. "CWE-89"
    pub cwe_id: Option<String>,
    /// OWASP Top 10 2021 category (required for compliance reporting, Req 17.4)
    pub owasp_category: Option<OwaspCategory>,
}

impl TelemetryEvent {
    /// Construct a `TelemetryEvent` from a `Vulnerability` and an action.
    pub fn from_vulnerability(vuln: &Vulnerability, action: TelemetryAction) -> Self {
        Self {
            timestamp: Utc::now(),
            action,
            vulnerability_id: vuln.id.to_string(),
            rule_id: vuln.rule_id.clone(),
            file_path: vuln.file_path.to_string_lossy().to_string(),
            line: vuln.line,
            column: vuln.column,
            snippet: vuln.snippet.clone(),
            severity: vuln.severity,
            reachable: vuln.reachable,
            cloud_exposed: vuln.cloud_exposed,
            cwe_id: vuln.cwe_id.clone(),
            owasp_category: vuln.owasp_category,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_vuln() -> Vulnerability {
        Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "sql-injection".to_string(),
            file_path: PathBuf::from("src/db.py"),
            line: 42,
            column: 8,
            snippet: "cursor.execute(query)".to_string(),
            severity: Severity::High,
            reachable: true,
            cloud_exposed: Some(true),
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: Some(OwaspCategory::A03_Injection),
        }
    }

    #[test]
    fn test_telemetry_event_from_vulnerability_detected() {
        let vuln = make_vuln();
        let event = TelemetryEvent::from_vulnerability(&vuln, TelemetryAction::Detected);

        assert_eq!(event.rule_id, "sql-injection");
        assert_eq!(event.file_path, "src/db.py");
        assert_eq!(event.line, 42);
        assert_eq!(event.column, 8);
        assert_eq!(event.severity, Severity::High);
        assert!(event.reachable);
        assert_eq!(event.cloud_exposed, Some(true));
        assert_eq!(event.cwe_id, Some("CWE-89".to_string()));
        assert_eq!(event.owasp_category, Some(OwaspCategory::A03_Injection));
        assert_eq!(event.action, TelemetryAction::Detected);
    }

    #[test]
    fn test_telemetry_event_from_vulnerability_fixed() {
        let vuln = make_vuln();
        let event = TelemetryEvent::from_vulnerability(&vuln, TelemetryAction::Fixed);
        assert_eq!(event.action, TelemetryAction::Fixed);
        assert_eq!(event.vulnerability_id, vuln.id.to_string());
    }

    #[test]
    fn test_telemetry_event_serialization_round_trip() {
        let vuln = make_vuln();
        let event = TelemetryEvent::from_vulnerability(&vuln, TelemetryAction::Dismissed);

        let json = serde_json::to_string(&event).expect("serialization failed");
        let back: TelemetryEvent = serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(back.rule_id, event.rule_id);
        assert_eq!(back.file_path, event.file_path);
        assert_eq!(back.line, event.line);
        assert_eq!(back.severity, event.severity);
        assert_eq!(back.owasp_category, event.owasp_category);
        assert_eq!(back.action, TelemetryAction::Dismissed);
    }

    #[test]
    fn test_telemetry_action_serialization() {
        let detected = serde_json::to_string(&TelemetryAction::Detected).unwrap();
        let dismissed = serde_json::to_string(&TelemetryAction::Dismissed).unwrap();
        let fixed = serde_json::to_string(&TelemetryAction::Fixed).unwrap();

        assert_eq!(detected, r#""detected""#);
        assert_eq!(dismissed, r#""dismissed""#);
        assert_eq!(fixed, r#""fixed""#);
    }

    #[test]
    fn test_telemetry_event_includes_owasp_category() {
        let vuln = make_vuln();
        let event = TelemetryEvent::from_vulnerability(&vuln, TelemetryAction::Detected);
        let json = serde_json::to_string(&event).unwrap();
        // OWASP category must be present in the JSON payload (Req 17.4)
        assert!(json.contains("owasp_category"));
        assert!(json.contains("A03"));
    }

    #[test]
    fn test_telemetry_event_no_owasp_category() {
        let mut vuln = make_vuln();
        vuln.owasp_category = None;
        let event = TelemetryEvent::from_vulnerability(&vuln, TelemetryAction::Detected);
        assert!(event.owasp_category.is_none());
        // Should still serialise cleanly
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("owasp_category"));
    }
}
