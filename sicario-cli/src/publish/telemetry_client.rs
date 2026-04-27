//! Telemetry client for submitting scan results to the zero-exfiltration endpoint.
//!
//! Sends structured scan findings to `POST /api/v1/telemetry/scan` on the
//! Sicario Cloud backend. Telemetry submission is best-effort: network errors
//! and non-200 responses are logged as warnings and never fail the scan.
//!
//! Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 14.5

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{error, warn};

// ── Payload types ─────────────────────────────────────────────────────────────

/// A single finding to include in the telemetry payload.
///
/// All fields use camelCase JSON names to match the backend API contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryFinding {
    /// Rule identifier, e.g. `"sql-injection"`
    pub rule: String,
    /// Severity: one of `"Critical"`, `"High"`, `"Medium"`, `"Low"`
    pub severity: String,
    /// Relative file path
    pub file: String,
    /// 1-indexed line number
    pub line: usize,
    /// Code snippet, pre-truncated to ≤ 100 characters by the CLI
    pub snippet: String,
    /// Optional CWE identifier, e.g. `"CWE-89"`
    #[serde(rename = "cweId", skip_serializing_if = "Option::is_none")]
    pub cwe_id: Option<String>,
    /// Optional OWASP Top 10 category, e.g. `"A03"`
    #[serde(rename = "owaspCategory", skip_serializing_if = "Option::is_none")]
    pub owasp_category: Option<String>,
    /// Optional finding fingerprint for deduplication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Optional execution trace showing how the vulnerability was found
    #[serde(rename = "executionTrace", skip_serializing_if = "Option::is_none")]
    pub execution_trace: Option<Vec<String>>,
}

/// Payload sent by the CLI to `POST /api/v1/telemetry/scan`.
///
/// All fields use camelCase JSON names to match the backend API contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryPayload {
    /// Project identifier in the Sicario dashboard
    #[serde(rename = "projectId")]
    pub project_id: String,
    /// Repository URL, e.g. `"https://github.com/org/repo"`
    #[serde(rename = "repositoryUrl")]
    pub repository_url: String,
    /// Git commit SHA
    #[serde(rename = "commitSha")]
    pub commit_sha: String,
    /// Client-generated unique scan identifier
    #[serde(rename = "scanId")]
    pub scan_id: String,
    /// Optional branch name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Optional pull request number — triggers PR check creation/update
    #[serde(rename = "prNumber", skip_serializing_if = "Option::is_none")]
    pub pr_number: Option<u32>,
    /// Optional scan duration in milliseconds
    #[serde(rename = "durationMs", skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Optional number of rules loaded
    #[serde(rename = "rulesLoaded", skip_serializing_if = "Option::is_none")]
    pub rules_loaded: Option<usize>,
    /// Optional number of files scanned
    #[serde(rename = "filesScanned", skip_serializing_if = "Option::is_none")]
    pub files_scanned: Option<usize>,
    /// Array of findings detected during the scan
    pub findings: Vec<TelemetryFinding>,
}

/// Successful response from `POST /api/v1/telemetry/scan`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TelemetryResponse {
    /// The scan ID echoed back from the backend
    pub scan_id: String,
    /// The project ID echoed back from the backend
    pub project_id: String,
    /// URL to the scan results in the dashboard
    pub dashboard_url: Option<String>,
}

// ── Client ────────────────────────────────────────────────────────────────────

/// HTTP client for submitting telemetry payloads to the Sicario Cloud backend.
pub struct TelemetryClient {
    base_url: String,
    auth_token: String,
    http: reqwest::blocking::Client,
}

impl TelemetryClient {
    /// Create a new telemetry client.
    ///
    /// `base_url` — Sicario Cloud base URL, e.g. `"https://flexible-terrier-680.convex.site"`
    /// `auth_token` — Full `Authorization` header value, e.g. `"Bearer project:{key}"`
    pub fn new(base_url: String, auth_token: String) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        Ok(Self {
            base_url,
            auth_token,
            http,
        })
    }

    /// Submit a telemetry payload to `POST /api/v1/telemetry/scan`.
    ///
    /// - On HTTP 200: returns `Ok(TelemetryResponse)`
    /// - On HTTP 401: logs a descriptive error about the invalid/expired API key
    /// - On other HTTP errors or network failures: logs a warning and returns `Err`
    ///
    /// The caller should treat all errors as non-fatal — telemetry submission
    /// must never cause the scan itself to fail.
    ///
    /// Requirements: 8.3, 8.4, 8.5, 8.6, 14.5
    pub fn submit(&self, payload: &TelemetryPayload) -> Result<TelemetryResponse> {
        let url = format!(
            "{}/api/v1/telemetry/scan",
            self.base_url.trim_end_matches('/')
        );

        let resp = self
            .http
            .post(&url)
            .header("Authorization", &self.auth_token)
            .header("Content-Type", "application/json")
            .json(payload)
            .send();

        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    "Telemetry submission failed (network error): {}. \
                     Scan results were not published to the dashboard.",
                    e
                );
                bail!("Network error submitting telemetry: {}", e);
            }
        };

        let status = resp.status();

        if status == reqwest::StatusCode::UNAUTHORIZED {
            error!(
                "Telemetry submission rejected: API key is invalid or expired. \
                 Regenerate your project API key in the Sicario dashboard and \
                 update SICARIO_API_KEY or .sicario/config.yaml."
            );
            bail!("Telemetry rejected: API key is invalid or expired (HTTP 401)");
        }

        if status == reqwest::StatusCode::OK {
            let telemetry_resp: TelemetryResponse = resp.json().unwrap_or(TelemetryResponse {
                scan_id: payload.scan_id.clone(),
                project_id: payload.project_id.clone(),
                dashboard_url: None,
            });
            return Ok(telemetry_resp);
        }

        // All other non-200 responses
        let body = resp.text().unwrap_or_default();
        warn!(
            "Telemetry submission failed with HTTP {}: {}. \
             Scan results were not published to the dashboard.",
            status, body
        );
        bail!("Telemetry submission failed with HTTP {}: {}", status, body);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_finding() -> TelemetryFinding {
        TelemetryFinding {
            rule: "sql-injection".to_string(),
            severity: "High".to_string(),
            file: "src/db.py".to_string(),
            line: 42,
            snippet: "cursor.execute(query)".to_string(),
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: Some("A03".to_string()),
            fingerprint: None,
        }
    }

    fn sample_payload() -> TelemetryPayload {
        TelemetryPayload {
            project_id: "proj-abc123".to_string(),
            repository_url: "https://github.com/org/repo".to_string(),
            commit_sha: "a1b2c3d4e5f6".to_string(),
            scan_id: "scan-1234567890-ABCDEF".to_string(),
            branch: Some("main".to_string()),
            pr_number: None,
            duration_ms: Some(1500),
            rules_loaded: Some(25),
            files_scanned: Some(100),
            findings: vec![sample_finding()],
        }
    }

    #[test]
    fn test_payload_serializes_to_camel_case() {
        let payload = sample_payload();
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("projectId"), "expected projectId in JSON");
        assert!(json.contains("repositoryUrl"), "expected repositoryUrl in JSON");
        assert!(json.contains("commitSha"), "expected commitSha in JSON");
        assert!(json.contains("scanId"), "expected scanId in JSON");
        assert!(json.contains("durationMs"), "expected durationMs in JSON");
        assert!(json.contains("rulesLoaded"), "expected rulesLoaded in JSON");
        assert!(json.contains("filesScanned"), "expected filesScanned in JSON");
    }

    #[test]
    fn test_finding_serializes_to_camel_case() {
        let finding = sample_finding();
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("cweId"), "expected cweId in JSON");
        assert!(json.contains("owaspCategory"), "expected owaspCategory in JSON");
    }

    #[test]
    fn test_optional_fields_omitted_when_none() {
        let finding = TelemetryFinding {
            rule: "xss".to_string(),
            severity: "Medium".to_string(),
            file: "src/view.js".to_string(),
            line: 10,
            snippet: "innerHTML = input".to_string(),
            cwe_id: None,
            owasp_category: None,
            fingerprint: None,
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(!json.contains("cweId"), "cweId should be omitted when None");
        assert!(!json.contains("owaspCategory"), "owaspCategory should be omitted when None");
        assert!(!json.contains("fingerprint"), "fingerprint should be omitted when None");
    }

    #[test]
    fn test_payload_round_trip() {
        let payload = sample_payload();
        let json = serde_json::to_string(&payload).unwrap();
        let back: TelemetryPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload, back);
    }

    #[test]
    fn test_response_round_trip() {
        let resp = TelemetryResponse {
            scan_id: "scan-abc".to_string(),
            project_id: "proj-xyz".to_string(),
            dashboard_url: Some("https://usesicario.xyz/scans/scan-abc".to_string()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: TelemetryResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn test_telemetry_client_new_succeeds() {
        let client = TelemetryClient::new(
            "https://example.convex.site".to_string(),
            "Bearer project:test-key".to_string(),
        );
        assert!(client.is_ok());
    }
}
