//! Unified CLI → Cloud upload payload schema (Task 65.1).
//!
//! This module defines the versioned Rust structs for all data uploaded from
//! the CLI to Sicario Cloud. The `payload_version` field allows the server to
//! reject payloads from incompatible CLI versions with a descriptive error.
//!
//! Zero-exfiltration guarantee: no field in this struct contains raw source
//! code. Snippets are replaced by `code_hash` (SHA-256). Suppression comments
//! are included as metadata only — they contain no code content.

use serde::{Deserialize, Serialize};

/// Current payload schema version. Increment when breaking changes are made.
pub const PAYLOAD_VERSION: &str = "1.0";

// ── Finding metadata ──────────────────────────────────────────────────────────

/// A single SAST/secrets/SCA finding in the upload payload.
/// Contains no raw source code — only structured metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadFinding {
    pub rule_id: String,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    /// SHA-256 of the matched code text. Never the raw code itself.
    pub code_hash: Option<String>,
    pub severity: String,
    pub confidence: Option<String>,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    /// Stable fingerprint for cross-branch triage propagation.
    pub match_based_id: Option<String>,
    /// Whether this finding was suppressed by an inline directive.
    pub suppressed: bool,
    /// The suppression comment text (e.g. `// sicario-ignore: rule-id`).
    /// Contains no code — only the comment itself.
    pub suppression_comment: Option<String>,
    /// Scan type: "sast" | "secrets" | "sca" | "license"
    pub scan_type: String,
    /// Whether this finding was surfaced in a PR (diff-aware + comment/block mode).
    pub surfaced_in_pr: bool,
    /// Triage state from a previous scan (for cross-branch propagation).
    pub triage_state: Option<String>,
}

// ── SCA finding ───────────────────────────────────────────────────────────────

/// A dependency vulnerability finding from the SCA scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadScaFinding {
    pub package_name: String,
    pub ecosystem: String,
    pub installed_version: String,
    pub fixed_version: Option<String>,
    pub cve_id: Option<String>,
    pub cvss_score: Option<f64>,
    pub severity: String,
    /// Whether the vulnerable function is reachable from project source.
    pub reachable: bool,
    /// Whether this is a transitive (indirect) dependency.
    pub transitive: bool,
    /// Call site in project source where the vulnerable function is called.
    pub call_site: Option<String>,
}

// ── Suppression metadata ──────────────────────────────────────────────────────

/// Metadata about a single inline suppression comment (Task 62.1).
/// Contains no source code — only the comment text and git attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionMetadata {
    pub file_path: String,
    pub line: usize,
    pub rule_id: String,
    /// Author email from git blame. Never the commit message.
    pub committer_email: Option<String>,
    /// The suppression comment text (e.g. `// sicario-ignore: sql-injection`).
    pub suppression_comment: String,
}

// ── Benchmark result ──────────────────────────────────────────────────────────

/// Per-language accuracy breakdown included in benchmark publish payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadLanguageAccuracy {
    pub language: String,
    pub tp: usize,
    pub fp: usize,
    pub fn_count: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

/// Benchmark result for upload to Sicario Cloud (Task 61.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadBenchmarkResult {
    pub timestamp: String,
    pub target: String,
    pub precision: f64,
    pub recall: f64,
    pub f1_score: f64,
    pub total_tp: usize,
    pub total_fp: usize,
    pub total_fn: usize,
    pub per_language: Vec<PayloadLanguageAccuracy>,
    pub vuln_sandbox_size: usize,
    pub cli_version: String,
}

// ── Main upload payload ───────────────────────────────────────────────────────

/// Complete CLI → Cloud upload payload (Task 65.1).
///
/// All fields are optional except `payload_version` and `scan_type` so that
/// partial payloads (e.g. benchmark-only uploads) are valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanUploadPayload {
    /// Schema version — server rejects unknown versions with a descriptive error.
    pub payload_version: String,

    /// SAST + secrets + SCA findings (no raw code).
    #[serde(default)]
    pub findings: Vec<PayloadFinding>,

    /// SCA-specific findings with package metadata.
    #[serde(default)]
    pub sca_findings: Vec<PayloadScaFinding>,

    /// Inline suppression comments with git attribution (Task 62.1).
    #[serde(default)]
    pub suppression_metadata: Vec<SuppressionMetadata>,

    /// Benchmark result, if `--publish` was passed to `sicario benchmark`.
    pub benchmark_result: Option<PayloadBenchmarkResult>,

    /// Local vulnerability database version (e.g. "2026-05-07").
    pub vuln_db_version: Option<String>,

    /// Whether a pre-commit hook is installed in the scanned repository.
    pub hook_installed: bool,

    /// SHA-256 of the custom rules set loaded during this scan.
    /// Used to detect rule drift between scans.
    pub custom_rules_hash: Option<String>,

    /// Scan type: "full" | "diff_aware"
    pub scan_type: String,

    /// Git branch that was scanned.
    pub branch: Option<String>,

    /// Whether any finding was surfaced in a PR (diff-aware + comment/block mode).
    pub surfaced_in_pr: bool,
}

impl ScanUploadPayload {
    /// Create a new payload with the current schema version and sensible defaults.
    pub fn new() -> Self {
        Self {
            payload_version: PAYLOAD_VERSION.to_string(),
            findings: Vec::new(),
            sca_findings: Vec::new(),
            suppression_metadata: Vec::new(),
            benchmark_result: None,
            vuln_db_version: None,
            hook_installed: false,
            custom_rules_hash: None,
            scan_type: "full".to_string(),
            branch: None,
            surfaced_in_pr: false,
        }
    }

    /// Validate that the payload version is supported.
    /// Returns `Err` with a descriptive message if the version is unknown.
    pub fn validate_version(version: &str) -> Result<(), String> {
        if version == PAYLOAD_VERSION {
            Ok(())
        } else {
            Err(format!(
                "Unsupported payload version '{}'. This CLI supports version '{}'. \
                 Please update your Sicario CLI: curl -fsSL https://usesicario.xyz/install.sh | sh",
                version, PAYLOAD_VERSION
            ))
        }
    }
}

impl Default for ScanUploadPayload {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payload_version_validation_accepts_current() {
        assert!(ScanUploadPayload::validate_version(PAYLOAD_VERSION).is_ok());
    }

    #[test]
    fn test_payload_version_validation_rejects_unknown() {
        let result = ScanUploadPayload::validate_version("99.0");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("Unsupported payload version"));
        assert!(msg.contains("99.0"));
        assert!(msg.contains(PAYLOAD_VERSION));
    }

    #[test]
    fn test_payload_serialization_round_trip() {
        let payload = ScanUploadPayload::new();
        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: ScanUploadPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.payload_version, PAYLOAD_VERSION);
        assert_eq!(deserialized.scan_type, "full");
        assert!(!deserialized.hook_installed);
        assert!(!deserialized.surfaced_in_pr);
    }

    #[test]
    fn test_suppression_metadata_serialization() {
        let meta = SuppressionMetadata {
            file_path: "src/db.js".to_string(),
            line: 42,
            rule_id: "js-sql-string-concat".to_string(),
            committer_email: Some("dev@example.com".to_string()),
            suppression_comment: "// sicario-ignore: js-sql-string-concat".to_string(),
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(json.contains("js-sql-string-concat"));
        assert!(json.contains("dev@example.com"));
        // Must NOT contain raw code
        assert!(!json.contains("SELECT"));
    }
}
