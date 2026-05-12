//! Security rule definitions

use serde::{Deserialize, Serialize};

use super::{OwaspCategory, Severity};
use crate::parser::Language;

/// Confidence level for a security rule.
///
/// Indicates how likely a match is to be a true positive.
/// Used by `--confidence-threshold` to filter scan output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceLevel {
    /// Low confidence — pattern is broad and may produce false positives.
    Low,
    /// Medium confidence — pattern is reasonably specific.
    Medium,
    /// High confidence — pattern is precise and rarely produces false positives.
    High,
}

impl std::fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfidenceLevel::High => write!(f, "high"),
            ConfidenceLevel::Medium => write!(f, "medium"),
            ConfidenceLevel::Low => write!(f, "low"),
        }
    }
}

/// Expected outcome for a rule test case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TestExpectation {
    TruePositive,
    TrueNegative,
}

/// A test case embedded in a security rule for quality validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTestCase {
    pub code: String,
    pub expected: TestExpectation,
    #[serde(default)]
    pub language: Option<Language>,
}

/// A security rule that can be applied to source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub languages: Vec<Language>,
    pub pattern: QueryPattern,
    pub fix_template: Option<String>,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<OwaspCategory>,
    /// Link to documentation / help page for this rule.
    #[serde(default)]
    pub help_uri: Option<String>,
    /// Embedded TP/TN test cases for rule quality enforcement.
    #[serde(default)]
    pub test_cases: Option<Vec<RuleTestCase>>,
    /// Confidence level for this rule: high, medium, or low.
    /// Required field — rules missing this field are rejected by the SAST engine.
    pub confidence: ConfidenceLevel,
}

/// Tree-sitter query pattern for matching code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryPattern {
    pub query: String,
    pub captures: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_test_case_serde_roundtrip() {
        let tc = RuleTestCase {
            code: "eval(input)".to_string(),
            expected: TestExpectation::TruePositive,
            language: Some(Language::JavaScript),
        };
        let json = serde_json::to_string(&tc).unwrap();
        let deserialized: RuleTestCase = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.expected, TestExpectation::TruePositive);
        assert_eq!(deserialized.language, Some(Language::JavaScript));
    }

    #[test]
    fn test_security_rule_with_test_cases_yaml() {
        let yaml = r#"
id: "test-rule"
name: "Test Rule"
description: "A test rule"
severity: High
confidence: high
languages:
  - JavaScript
pattern:
  query: "(identifier) @id"
  captures:
    - "id"
help_uri: "https://example.com/rules/test-rule"
test_cases:
  - code: "eval(input)"
    expected: TruePositive
    language: JavaScript
  - code: "console.log('safe')"
    expected: TrueNegative
    language: JavaScript
"#;
        let rule: SecurityRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(
            rule.help_uri,
            Some("https://example.com/rules/test-rule".to_string())
        );
        assert_eq!(rule.confidence, ConfidenceLevel::High);
        let cases = rule.test_cases.unwrap();
        assert_eq!(cases.len(), 2);
        assert_eq!(cases[0].expected, TestExpectation::TruePositive);
        assert_eq!(cases[1].expected, TestExpectation::TrueNegative);
    }

    #[test]
    fn test_security_rule_without_optional_fields() {
        let yaml = r#"
id: "basic-rule"
name: "Basic Rule"
description: "No optional fields"
severity: Low
confidence: medium
languages:
  - Python
pattern:
  query: "(identifier) @id"
  captures:
    - "id"
"#;
        let rule: SecurityRule = serde_yaml::from_str(yaml).unwrap();
        assert!(rule.help_uri.is_none());
        assert!(rule.test_cases.is_none());
        assert_eq!(rule.confidence, ConfidenceLevel::Medium);
    }

    #[test]
    fn test_confidence_level_ordering() {
        assert!(ConfidenceLevel::Low < ConfidenceLevel::Medium);
        assert!(ConfidenceLevel::Medium < ConfidenceLevel::High);
        assert!(ConfidenceLevel::Low < ConfidenceLevel::High);
    }

    #[test]
    fn test_confidence_level_display() {
        assert_eq!(ConfidenceLevel::High.to_string(), "high");
        assert_eq!(ConfidenceLevel::Medium.to_string(), "medium");
        assert_eq!(ConfidenceLevel::Low.to_string(), "low");
    }

    #[test]
    fn test_security_rule_missing_confidence_fails_deserialization() {
        let yaml = r#"
id: "no-confidence-rule"
name: "No Confidence Rule"
description: "Missing confidence field"
severity: High
languages:
  - JavaScript
pattern:
  query: "(identifier) @id"
  captures:
    - "id"
"#;
        let result: Result<SecurityRule, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err(), "Rule without confidence should fail deserialization");
    }
}
