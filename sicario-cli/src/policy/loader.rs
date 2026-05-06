//! Policy loader for `.sicario/policy.yaml`.
//!
//! Reads the organizational policy file and exposes it as a `PolicyConfig`
//! struct. Returns `None` when no policy file exists so callers can skip
//! enforcement entirely.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Severity level used in policy `fail_on` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyFailOn {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for PolicyFailOn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyFailOn::Critical => write!(f, "Critical"),
            PolicyFailOn::High => write!(f, "High"),
            PolicyFailOn::Medium => write!(f, "Medium"),
            PolicyFailOn::Low => write!(f, "Low"),
        }
    }
}

impl From<&PolicyFailOn> for crate::engine::vulnerability::Severity {
    fn from(level: &PolicyFailOn) -> Self {
        match level {
            PolicyFailOn::Critical => crate::engine::vulnerability::Severity::Critical,
            PolicyFailOn::High => crate::engine::vulnerability::Severity::High,
            PolicyFailOn::Medium => crate::engine::vulnerability::Severity::Medium,
            PolicyFailOn::Low => crate::engine::vulnerability::Severity::Low,
        }
    }
}

/// Organizational policy configuration loaded from `.sicario/policy.yaml`.
///
/// All fields are optional — a minimal policy file may set only `fail_on`
/// without specifying any rule lists.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Overrides `--fail-on` CLI flag. Exit 1 if any finding is at or above
    /// this severity level.
    pub fail_on: Option<PolicyFailOn>,

    /// Rule IDs that cannot be suppressed with `sicario-ignore`. If a
    /// `sicario-ignore` directive targets one of these rules, the scan exits 1
    /// with a policy violation message.
    #[serde(default)]
    pub required_rules: Vec<String>,

    /// Rule IDs whose `sicario-ignore` suppressions are prohibited in staged
    /// commits. The `AutoFixHook` blocks the commit when a staged file contains
    /// a suppression for one of these rules.
    #[serde(default)]
    pub blocked_suppressions: Vec<String>,

    /// Glob patterns restricting which files are in scope for policy
    /// enforcement. An empty list means all files are in scope.
    #[serde(default)]
    pub scope: Vec<String>,

    /// Maximum total finding count. Exit 1 if the scan produces more findings
    /// than this limit.
    pub max_findings: Option<usize>,
}

/// Loads the organizational policy from `.sicario/policy.yaml`.
pub struct PolicyLoader;

impl PolicyLoader {
    /// Load the policy from `<project_root>/.sicario/policy.yaml`.
    ///
    /// Returns `Ok(None)` when the file does not exist (no policy enforcement).
    /// Returns `Ok(Some(config))` when the file exists and parses successfully.
    /// Returns `Err` when the file exists but cannot be parsed.
    pub fn load(project_root: &Path) -> Result<Option<PolicyConfig>> {
        let policy_path = project_root.join(".sicario").join("policy.yaml");

        if !policy_path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(&policy_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to read policy file '{}': {}",
                policy_path.display(),
                e
            )
        })?;

        let config: PolicyConfig = serde_yaml::from_str(&content).map_err(|e| {
            anyhow::anyhow!(
                "Failed to parse policy file '{}': {}",
                policy_path.display(),
                e
            )
        })?;

        Ok(Some(config))
    }
}

/// Check whether any `sicario-ignore` directives in the given source text
/// target a rule that is listed in `required_rules`.
///
/// Returns the first violating rule ID found, or `None` if no violations.
pub fn check_required_rules_suppression(source: &str, required_rules: &[String]) -> Option<String> {
    for line in source.lines() {
        let trimmed = line.trim();
        // Match: sicario-ignore:<rule-id>  or  sicario-ignore: <rule-id>
        if let Some(rest) = trimmed
            .strip_prefix("// sicario-ignore:")
            .or_else(|| trimmed.strip_prefix("# sicario-ignore:"))
            .or_else(|| trimmed.strip_prefix("/* sicario-ignore:"))
        {
            let rule_id = rest.trim().trim_end_matches("*/").trim().to_string();
            if required_rules.iter().any(|r| r == &rule_id) {
                return Some(rule_id);
            }
        }
        // Match bare: sicario-ignore (no rule ID) — check if any required rule
        // is present on the next line context is not available here, so we only
        // flag explicit rule-id suppressions.
    }
    None
}

/// Check whether any `sicario-ignore` directives in the given source text
/// target a rule that is listed in `blocked_suppressions`.
///
/// Returns the first violating rule ID found, or `None` if no violations.
pub fn check_blocked_suppressions(source: &str, blocked: &[String]) -> Option<String> {
    check_required_rules_suppression(source, blocked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_policy(dir: &TempDir, content: &str) {
        let sicario_dir = dir.path().join(".sicario");
        std::fs::create_dir_all(&sicario_dir).unwrap();
        std::fs::write(sicario_dir.join("policy.yaml"), content).unwrap();
    }

    // ── PolicyLoader::load ────────────────────────────────────────────────

    #[test]
    fn no_policy_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let result = PolicyLoader::load(dir.path()).unwrap();
        assert!(result.is_none(), "Expected None when no policy.yaml exists");
    }

    #[test]
    fn policy_fail_on_overrides_cli_fail_on() {
        let dir = TempDir::new().unwrap();
        write_policy(
            &dir,
            "fail_on: Medium\nrequired_rules: []\nblocked_suppressions: []\n",
        );

        let policy = PolicyLoader::load(dir.path()).unwrap().unwrap();
        assert_eq!(policy.fail_on, Some(PolicyFailOn::Medium));

        // Simulate: CLI says High, policy says Medium → policy wins
        let effective_severity: crate::engine::vulnerability::Severity =
            policy.fail_on.as_ref().unwrap().into();
        assert_eq!(
            effective_severity,
            crate::engine::vulnerability::Severity::Medium
        );
    }

    #[test]
    fn required_rules_suppression_detected() {
        let source = r#"
// sicario-ignore:js-sql-string-concat
const q = "SELECT * FROM users WHERE id = " + userId;
"#;
        let required = vec!["js-sql-string-concat".to_string()];
        let violation = check_required_rules_suppression(source, &required);
        assert_eq!(violation, Some("js-sql-string-concat".to_string()));
    }

    #[test]
    fn required_rules_no_violation_when_different_rule() {
        let source = r#"
// sicario-ignore:some-other-rule
const q = "SELECT * FROM users WHERE id = " + userId;
"#;
        let required = vec!["js-sql-string-concat".to_string()];
        let violation = check_required_rules_suppression(source, &required);
        assert!(violation.is_none());
    }

    #[test]
    fn max_findings_exceeded_detection() {
        let dir = TempDir::new().unwrap();
        write_policy(&dir, "max_findings: 5\n");

        let policy = PolicyLoader::load(dir.path()).unwrap().unwrap();
        let finding_count = 10usize;
        let exceeded = policy
            .max_findings
            .map(|limit| finding_count > limit)
            .unwrap_or(false);
        assert!(exceeded, "Expected max_findings to be exceeded");
    }

    #[test]
    fn max_findings_not_exceeded() {
        let dir = TempDir::new().unwrap();
        write_policy(&dir, "max_findings: 100\n");

        let policy = PolicyLoader::load(dir.path()).unwrap().unwrap();
        let finding_count = 5usize;
        let exceeded = policy
            .max_findings
            .map(|limit| finding_count > limit)
            .unwrap_or(false);
        assert!(!exceeded);
    }

    #[test]
    fn full_policy_parses_correctly() {
        let dir = TempDir::new().unwrap();
        write_policy(
            &dir,
            r#"
fail_on: High
required_rules:
  - js-sql-string-concat
  - hardcoded-secret
blocked_suppressions:
  - js-sql-string-concat
scope:
  - "src/**"
max_findings: 100
"#,
        );

        let policy = PolicyLoader::load(dir.path()).unwrap().unwrap();
        assert_eq!(policy.fail_on, Some(PolicyFailOn::High));
        assert_eq!(
            policy.required_rules,
            vec!["js-sql-string-concat", "hardcoded-secret"]
        );
        assert_eq!(policy.blocked_suppressions, vec!["js-sql-string-concat"]);
        assert_eq!(policy.scope, vec!["src/**"]);
        assert_eq!(policy.max_findings, Some(100));
    }

    #[test]
    fn blocked_suppression_detected() {
        let source = "# sicario-ignore:js-sql-string-concat\n";
        let blocked = vec!["js-sql-string-concat".to_string()];
        let violation = check_blocked_suppressions(source, &blocked);
        assert_eq!(violation, Some("js-sql-string-concat".to_string()));
    }
}
