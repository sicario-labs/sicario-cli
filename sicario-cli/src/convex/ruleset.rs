//! Real-time ruleset subscription and update handling.
//!
//! When the Convex backend pushes a `QueryUpdated` message for the `rulesets`
//! subscription, the payload is deserialised into a `RulesetUpdate` and
//! forwarded to the SAST engine so it can reload its rules without restarting.
//!
//! Requirements: 8.4

use serde::{Deserialize, Serialize};

use crate::engine::SecurityRule;

/// A ruleset update received from the Convex backend via WebSocket subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesetUpdate {
    /// Monotonically increasing version number; callers can use this to detect
    /// out-of-order or duplicate updates.
    pub version: u64,
    /// The complete set of organisational security rules.  Replaces the
    /// previously active ruleset in its entirety.
    pub rules: Vec<SecurityRule>,
}

/// Apply a `RulesetUpdate` to a `SastEngine`, replacing its current rules.
///
/// This is called on the main thread whenever a `ClientEvent::RulesetUpdate`
/// is received from the `ConvexClient`.
///
/// Requirements: 8.4
pub fn apply_ruleset_update(
    engine: &mut crate::engine::SastEngine,
    update: &RulesetUpdate,
) -> anyhow::Result<()> {
    use anyhow::Context;

    if update.rules.is_empty() {
        // Nothing to apply — keep existing rules
        return Ok(());
    }

    // Serialise the rules to a temporary YAML file and reload via the engine's
    // existing `load_rules()` path so all validation and query compilation runs.
    let yaml = serde_yaml::to_string(&update.rules)
        .context("Failed to serialise ruleset update to YAML")?;

    // Write to a temp file in the system temp directory
    let tmp_path =
        std::env::temp_dir().join(format!("sicario_ruleset_{}.yaml", uuid::Uuid::new_v4()));
    std::fs::write(&tmp_path, yaml.as_bytes())
        .context("Failed to write ruleset YAML to temp file")?;

    let result = engine
        .load_rules(&tmp_path)
        .context("Failed to load updated ruleset into SAST engine");

    // Clean up temp file regardless of outcome
    let _ = std::fs::remove_file(&tmp_path);

    result
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{QueryPattern, SecurityRule, Severity};
    use crate::parser::Language;

    fn make_rule(id: &str) -> SecurityRule {
        SecurityRule {
            id: id.to_string(),
            name: format!("Rule {}", id),
            description: "Test rule".to_string(),
            severity: Severity::Medium,
            languages: vec![Language::JavaScript],
            pattern: QueryPattern {
                query: "(identifier) @id".to_string(),
                captures: vec!["id".to_string()],
            },
            fix_template: None,
            cwe_id: None,
            owasp_category: None,
            help_uri: None,
            test_cases: None,
        }
    }

    #[test]
    fn test_ruleset_update_serialization_round_trip() {
        let update = RulesetUpdate {
            version: 7,
            rules: vec![make_rule("rule-a"), make_rule("rule-b")],
        };

        let json = serde_json::to_string(&update).expect("serialization failed");
        let back: RulesetUpdate = serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(back.version, 7);
        assert_eq!(back.rules.len(), 2);
        assert_eq!(back.rules[0].id, "rule-a");
        assert_eq!(back.rules[1].id, "rule-b");
    }

    #[test]
    fn test_ruleset_update_empty_rules() {
        let update = RulesetUpdate {
            version: 1,
            rules: vec![],
        };
        let json = serde_json::to_string(&update).unwrap();
        let back: RulesetUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.version, 1);
        assert!(back.rules.is_empty());
    }

    #[test]
    fn test_apply_ruleset_update_empty_is_noop() {
        use tempfile::TempDir;
        let tmp = TempDir::new().unwrap();
        let mut engine = crate::engine::SastEngine::new(tmp.path()).unwrap();

        let update = RulesetUpdate {
            version: 1,
            rules: vec![],
        };

        // Should succeed without modifying the engine
        let result = apply_ruleset_update(&mut engine, &update);
        assert!(result.is_ok());
        assert_eq!(engine.get_rules().len(), 0);
    }

    #[test]
    fn test_apply_ruleset_update_loads_rules() {
        use tempfile::TempDir;
        let tmp = TempDir::new().unwrap();
        let mut engine = crate::engine::SastEngine::new(tmp.path()).unwrap();

        let update = RulesetUpdate {
            version: 2,
            rules: vec![make_rule("injected-rule")],
        };

        let result = apply_ruleset_update(&mut engine, &update);
        assert!(
            result.is_ok(),
            "apply_ruleset_update failed: {:?}",
            result.err()
        );
        assert!(
            engine.get_rule("injected-rule").is_some(),
            "Rule should be loaded into engine"
        );
    }
}
