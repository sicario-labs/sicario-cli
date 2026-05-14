//! Unified Cloud → CLI download payload schema (Task 65.2).
//!
//! This module defines the versioned Rust structs for all data downloaded from
//! Sicario Cloud to the CLI during `sicario ci` policy sync. The
//! `payload_version` field allows the CLI to reject payloads from incompatible
//! server versions with a descriptive error.

use serde::{Deserialize, Serialize};

/// Current policy payload schema version.
pub const POLICY_PAYLOAD_VERSION: &str = "1.0";

// ── Per-rule policy entry ─────────────────────────────────────────────────────

/// Policy mode for a single rule.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyMode {
    /// Upload finding to dashboard only — no CI impact.
    Monitor,
    /// Post a PR/MR comment when this rule fires.
    Comment,
    /// Exit 1 (fail the CI job) when this rule fires.
    Block,
    /// Skip this rule entirely during scanning.
    Disabled,
}

impl std::fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyMode::Monitor => write!(f, "monitor"),
            PolicyMode::Comment => write!(f, "comment"),
            PolicyMode::Block => write!(f, "block"),
            PolicyMode::Disabled => write!(f, "disabled"),
        }
    }
}

impl Default for PolicyMode {
    fn default() -> Self {
        PolicyMode::Monitor
    }
}

/// Policy entry for a single rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub mode: PolicyMode,
}

// ── Custom rule ───────────────────────────────────────────────────────────────

/// A custom rule synced from Sicario Cloud to the CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudCustomRule {
    pub rule_id: String,
    pub name: String,
    pub yaml: String,
    pub language: String,
    pub severity: String,
    pub cwe_id: Option<String>,
    pub is_enabled: bool,
    pub policy_mode: PolicyMode,
}

// ── License policy ────────────────────────────────────────────────────────────

/// License policy synced from Sicario Cloud (Task 63.3).
/// Local `--license-policy <path>` YAML overrides this (Task 63.5).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LicensePolicy {
    /// SPDX license identifiers that are explicitly allowed.
    #[serde(default)]
    pub allow: Vec<String>,
    /// SPDX license identifiers that are blocked (exit 1 when found).
    #[serde(default)]
    pub block: Vec<String>,
    /// SPDX license identifiers that produce a warning.
    #[serde(default)]
    pub warn: Vec<String>,
}

// ── Triage state entry ────────────────────────────────────────────────────────

/// A triage state for a finding, synced from the cloud for cross-branch propagation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageStateEntry {
    pub match_based_id: String,
    pub triage_state: String,
    pub ignore_reason: Option<String>,
}

// ── Main policy download payload ──────────────────────────────────────────────

/// Complete Cloud → CLI policy download payload (Task 65.2).
///
/// Downloaded by `sicario ci` before scanning. All fields are optional
/// so that partial responses (e.g. no custom rules) are valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDownloadPayload {
    /// Schema version — CLI rejects unknown versions with a descriptive error.
    pub payload_version: String,

    /// Per-rule policy modes (Monitor/Comment/Block/Disabled).
    #[serde(default)]
    pub rules: Vec<PolicyRule>,

    /// Custom rules authored in the dashboard, synced to the CLI.
    #[serde(default)]
    pub custom_rules: Vec<CloudCustomRule>,

    /// Triage states for findings, used for cross-branch propagation.
    #[serde(default)]
    pub triage_states: Vec<TriageStateEntry>,

    /// License policy from the dashboard (Task 63.3).
    pub license_policy: Option<LicensePolicy>,

    /// Glob patterns to ignore during scanning (from project settings).
    #[serde(default)]
    pub path_ignores: Vec<String>,

    /// Root path of the project within the repository (for monorepo support).
    pub root_path: Option<String>,

    /// Latest available vulnerability database version.
    /// CLI prints a notice when local DB is more than 7 days behind (Task 64.4).
    pub vuln_db_latest_version: Option<String>,
}

impl PolicyDownloadPayload {
    /// Create a default policy payload (all rules in Monitor mode, no custom rules).
    pub fn default_policy() -> Self {
        Self {
            payload_version: POLICY_PAYLOAD_VERSION.to_string(),
            rules: Vec::new(),
            custom_rules: Vec::new(),
            triage_states: Vec::new(),
            license_policy: None,
            path_ignores: Vec::new(),
            root_path: None,
            vuln_db_latest_version: None,
        }
    }

    /// Validate that the payload version is supported.
    pub fn validate_version(version: &str) -> Result<(), String> {
        if version == POLICY_PAYLOAD_VERSION {
            Ok(())
        } else {
            Err(format!(
                "Unsupported policy payload version '{}'. Expected '{}'. \
                 Please update your Sicario CLI: curl -fsSL https://usesicario.xyz/install.sh | sh",
                version, POLICY_PAYLOAD_VERSION
            ))
        }
    }

    /// Look up the policy mode for a given rule ID.
    /// Returns `Monitor` if the rule has no explicit policy entry.
    pub fn mode_for_rule(&self, rule_id: &str) -> PolicyMode {
        self.rules
            .iter()
            .find(|r| r.rule_id == rule_id)
            .map(|r| r.mode.clone())
            .unwrap_or_default()
    }

    /// Returns true if the rule should be skipped entirely.
    pub fn is_disabled(&self, rule_id: &str) -> bool {
        self.mode_for_rule(rule_id) == PolicyMode::Disabled
    }

    /// Returns true if the rule should cause CI to exit 1.
    pub fn is_blocking(&self, rule_id: &str) -> bool {
        self.mode_for_rule(rule_id) == PolicyMode::Block
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_version_validation_accepts_current() {
        assert!(PolicyDownloadPayload::validate_version(POLICY_PAYLOAD_VERSION).is_ok());
    }

    #[test]
    fn test_policy_version_validation_rejects_unknown() {
        let result = PolicyDownloadPayload::validate_version("99.0");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported policy payload version"));
    }

    #[test]
    fn test_mode_for_rule_defaults_to_monitor() {
        let payload = PolicyDownloadPayload::default_policy();
        assert_eq!(payload.mode_for_rule("any-rule"), PolicyMode::Monitor);
    }

    #[test]
    fn test_mode_for_rule_returns_configured_mode() {
        let mut payload = PolicyDownloadPayload::default_policy();
        payload.rules.push(PolicyRule {
            rule_id: "js-sql-injection".to_string(),
            mode: PolicyMode::Block,
        });
        assert_eq!(payload.mode_for_rule("js-sql-injection"), PolicyMode::Block);
        assert!(payload.is_blocking("js-sql-injection"));
        assert!(!payload.is_disabled("js-sql-injection"));
    }

    #[test]
    fn test_disabled_rule_detection() {
        let mut payload = PolicyDownloadPayload::default_policy();
        payload.rules.push(PolicyRule {
            rule_id: "noisy-rule".to_string(),
            mode: PolicyMode::Disabled,
        });
        assert!(payload.is_disabled("noisy-rule"));
        assert!(!payload.is_blocking("noisy-rule"));
    }

    #[test]
    fn test_policy_serialization_round_trip() {
        let payload = PolicyDownloadPayload::default_policy();
        let json = serde_json::to_string(&payload).unwrap();
        let deserialized: PolicyDownloadPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.payload_version, POLICY_PAYLOAD_VERSION);
    }

    #[test]
    fn test_license_policy_defaults() {
        let lp = LicensePolicy::default();
        assert!(lp.allow.is_empty());
        assert!(lp.block.is_empty());
        assert!(lp.warn.is_empty());
    }
}
