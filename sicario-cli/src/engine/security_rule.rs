//! Security rule definitions

use serde::{Deserialize, Serialize};

use super::{OwaspCategory, Severity};
use crate::parser::Language;

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
        assert_eq!(rule.help_uri, Some("https://example.com/rules/test-rule".to_string()));
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
    }
}
