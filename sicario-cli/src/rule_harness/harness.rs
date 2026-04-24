//! Rule quality enforcement — TP/TN test execution and quality reports.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::engine::sast_engine::SastEngine;
use crate::engine::security_rule::{SecurityRule, TestExpectation};

// ── Data models ──────────────────────────────────────────────────────────────

/// Quality report for a single rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleQualityReport {
    pub rule_id: String,
    pub rule_name: String,
    pub tp_count: usize,
    pub tn_count: usize,
    pub tp_passed: usize,
    pub tn_passed: usize,
    pub tp_failed: usize,
    pub tn_failed: usize,
    pub precision: f64,
    pub recall: f64,
    pub fp_rate: f64,
    pub has_minimum_cases: bool,
    pub failures: Vec<TestFailure>,
}

/// A single test case failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestFailure {
    pub code_snippet: String,
    pub expected: String,
    pub actual: String,
}

/// Aggregate quality report across all rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateQualityReport {
    pub total_rules: usize,
    pub rules_with_tests: usize,
    /// Count of rules that don't meet the minimum test case requirement.
    pub invalid_rules: usize,
    pub total_tp_cases: usize,
    pub total_tn_cases: usize,
    pub total_tp_passed: usize,
    pub total_tn_passed: usize,
    pub aggregate_fp_rate: f64,
    pub aggregate_precision: f64,
    pub aggregate_recall: f64,
    pub per_rule: Vec<RuleQualityReport>,
    pub rejected_rules: Vec<String>,
}

/// Validation report for rule syntax and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleValidationReport {
    pub total_rules: usize,
    pub valid_rules: usize,
    /// Count of invalid rules.
    pub invalid_rules: usize,
    pub errors: Vec<RuleValidationError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleValidationError {
    pub rule_id: String,
    pub errors: Vec<String>,
}

// ── Trait ─────────────────────────────────────────────────────────────────────

pub trait RuleQualityValidation {
    fn validate_rule(&self, rule: &SecurityRule) -> Result<RuleQualityReport>;
    fn validate_all(&self, rules: &[SecurityRule]) -> Result<AggregateQualityReport>;
    fn validate_all_syntax(&self, rules: &[SecurityRule]) -> RuleValidationReport;
}

// ── RuleTestHarness ──────────────────────────────────────────────────────────

pub struct RuleTestHarness {
    project_root: PathBuf,
}

impl RuleTestHarness {
    pub fn new(project_root: &Path) -> Self {
        Self {
            project_root: project_root.to_path_buf(),
        }
    }

    /// Execute a single test case: write code to a temp file, scan, check result.
    fn execute_test_case(
        &self,
        rule: &SecurityRule,
        code: &str,
        expected: &TestExpectation,
    ) -> Result<bool> {
        let ext = rule
            .languages
            .first()
            .map(|lang| match lang {
                crate::parser::Language::JavaScript => "js",
                crate::parser::Language::TypeScript => "ts",
                crate::parser::Language::Python => "py",
                crate::parser::Language::Rust => "rs",
                crate::parser::Language::Go => "go",
                crate::parser::Language::Java => "java",
                crate::parser::Language::Ruby => "rb",
                crate::parser::Language::Php => "php",
            })
            .unwrap_or("txt");

        let tmp_dir = tempfile::tempdir()?;
        let test_file = tmp_dir.path().join(format!("test_case.{}", ext));
        fs::write(&test_file, code)?;

        // Serialize just this rule to a temp YAML
        let rule_yaml = serde_yaml::to_string(&vec![rule])?;
        let rule_file = tmp_dir.path().join("test_rule.yaml");
        fs::write(&rule_file, &rule_yaml)?;

        let mut engine = SastEngine::new(tmp_dir.path())?;
        engine.load_rules(&rule_file)?;
        let findings = engine.scan_file(&test_file).unwrap_or_default();

        let has_findings = !findings.is_empty();
        match expected {
            TestExpectation::TruePositive => Ok(has_findings),
            TestExpectation::TrueNegative => Ok(!has_findings),
        }
    }
}

impl RuleQualityValidation for RuleTestHarness {
    fn validate_rule(&self, rule: &SecurityRule) -> Result<RuleQualityReport> {
        let cases = rule.test_cases.as_deref().unwrap_or(&[]);

        let tp_cases: Vec<_> = cases
            .iter()
            .filter(|c| c.expected == TestExpectation::TruePositive)
            .collect();
        let tn_cases: Vec<_> = cases
            .iter()
            .filter(|c| c.expected == TestExpectation::TrueNegative)
            .collect();

        let has_minimum_cases = tp_cases.len() >= 3 && tn_cases.len() >= 3;

        let mut tp_passed = 0usize;
        let mut tp_failed = 0usize;
        let mut tn_passed = 0usize;
        let mut tn_failed = 0usize;
        let mut failures = Vec::new();

        for tc in &tp_cases {
            match self.execute_test_case(rule, &tc.code, &tc.expected) {
                Ok(true) => tp_passed += 1,
                Ok(false) => {
                    tp_failed += 1;
                    failures.push(TestFailure {
                        code_snippet: tc.code.chars().take(120).collect(),
                        expected: "TruePositive (≥1 finding)".to_string(),
                        actual: "0 findings".to_string(),
                    });
                }
                Err(e) => {
                    tp_failed += 1;
                    failures.push(TestFailure {
                        code_snippet: tc.code.chars().take(120).collect(),
                        expected: "TruePositive (≥1 finding)".to_string(),
                        actual: format!("Error: {}", e),
                    });
                }
            }
        }

        for tc in &tn_cases {
            match self.execute_test_case(rule, &tc.code, &tc.expected) {
                Ok(true) => tn_passed += 1,
                Ok(false) => {
                    tn_failed += 1;
                    failures.push(TestFailure {
                        code_snippet: tc.code.chars().take(120).collect(),
                        expected: "TrueNegative (0 findings)".to_string(),
                        actual: "≥1 finding (false positive)".to_string(),
                    });
                }
                Err(e) => {
                    tn_failed += 1;
                    failures.push(TestFailure {
                        code_snippet: tc.code.chars().take(120).collect(),
                        expected: "TrueNegative (0 findings)".to_string(),
                        actual: format!("Error: {}", e),
                    });
                }
            }
        }

        let precision = if tp_passed + tn_failed > 0 {
            tp_passed as f64 / (tp_passed + tn_failed) as f64
        } else {
            1.0
        };
        let recall = if !tp_cases.is_empty() {
            tp_passed as f64 / tp_cases.len() as f64
        } else {
            1.0
        };
        let fp_rate = if !tn_cases.is_empty() {
            tn_failed as f64 / tn_cases.len() as f64
        } else {
            0.0
        };

        Ok(RuleQualityReport {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            tp_count: tp_cases.len(),
            tn_count: tn_cases.len(),
            tp_passed,
            tn_passed,
            tp_failed,
            tn_failed,
            precision,
            recall,
            fp_rate,
            has_minimum_cases,
            failures,
        })
    }

    fn validate_all(&self, rules: &[SecurityRule]) -> Result<AggregateQualityReport> {
        let total_rules = rules.len();
        let mut per_rule = Vec::new();
        let mut rejected_rules = Vec::new();
        let mut rules_with_tests = 0usize;
        let mut invalid_rules = 0usize;
        let mut total_tp = 0usize;
        let mut total_tn = 0usize;
        let mut total_tp_passed = 0usize;
        let mut total_tn_passed = 0usize;

        for rule in rules {
            let report = self.validate_rule(rule)?;

            if !report.has_minimum_cases {
                rejected_rules.push(rule.id.clone());
                invalid_rules += 1;
            } else {
                rules_with_tests += 1;
            }

            total_tp += report.tp_count;
            total_tn += report.tn_count;
            total_tp_passed += report.tp_passed;
            total_tn_passed += report.tn_passed;
            per_rule.push(report);
        }

        let total_tn_failed = total_tn.saturating_sub(total_tn_passed);
        let aggregate_fp_rate = if total_tn > 0 {
            total_tn_failed as f64 / total_tn as f64
        } else {
            0.0
        };
        let aggregate_precision = if total_tp_passed + total_tn_failed > 0 {
            total_tp_passed as f64 / (total_tp_passed + total_tn_failed) as f64
        } else {
            1.0
        };
        let aggregate_recall = if total_tp > 0 {
            total_tp_passed as f64 / total_tp as f64
        } else {
            1.0
        };

        Ok(AggregateQualityReport {
            total_rules,
            rules_with_tests,
            invalid_rules,
            total_tp_cases: total_tp,
            total_tn_cases: total_tn,
            total_tp_passed,
            total_tn_passed,
            aggregate_fp_rate,
            aggregate_precision,
            aggregate_recall,
            per_rule,
            rejected_rules,
        })
    }

    fn validate_all_syntax(&self, rules: &[SecurityRule]) -> RuleValidationReport {
        let total_rules = rules.len();
        let mut valid_rules = 0usize;
        let mut errors = Vec::new();

        for rule in rules {
            let mut rule_errors = Vec::new();

            if rule.id.is_empty() {
                rule_errors.push("Missing rule ID".to_string());
            }
            if rule.name.is_empty() {
                rule_errors.push("Missing rule name".to_string());
            }
            if rule.description.is_empty() {
                rule_errors.push("Missing rule description".to_string());
            }
            if rule.languages.is_empty() {
                rule_errors.push("No target languages specified".to_string());
            }
            if rule.pattern.query.is_empty() {
                rule_errors.push("Empty query pattern".to_string());
            }

            match &rule.test_cases {
                None => {
                    rule_errors
                        .push("No test cases defined (minimum 3 TP + 3 TN required)".to_string());
                }
                Some(cases) => {
                    let tp = cases
                        .iter()
                        .filter(|c| c.expected == TestExpectation::TruePositive)
                        .count();
                    let tn = cases
                        .iter()
                        .filter(|c| c.expected == TestExpectation::TrueNegative)
                        .count();
                    if tp < 3 {
                        rule_errors.push(format!("Insufficient TP test cases: {} (minimum 3)", tp));
                    }
                    if tn < 3 {
                        rule_errors.push(format!("Insufficient TN test cases: {} (minimum 3)", tn));
                    }
                }
            }

            if rule_errors.is_empty() {
                valid_rules += 1;
            } else {
                errors.push(RuleValidationError {
                    rule_id: rule.id.clone(),
                    errors: rule_errors,
                });
            }
        }

        RuleValidationReport {
            total_rules,
            valid_rules,
            invalid_rules: errors.len(),
            errors,
        }
    }
}

// ── Display helpers ──────────────────────────────────────────────────────────

impl AggregateQualityReport {
    pub fn display_text(&self) -> String {
        let mut s = String::new();
        s.push_str("╔══════════════════════════════════════════╗\n");
        s.push_str("║       Rule Quality Report                ║\n");
        s.push_str("╠══════════════════════════════════════════╣\n");
        s.push_str(&format!(
            "║ Total rules:       {:>5}                 ║\n",
            self.total_rules
        ));
        s.push_str(&format!(
            "║ With tests:        {:>5}                 ║\n",
            self.rules_with_tests
        ));
        s.push_str(&format!(
            "║ Missing tests:     {:>5}                 ║\n",
            self.invalid_rules
        ));
        s.push_str(&format!(
            "║ Total TP cases:    {:>5}                 ║\n",
            self.total_tp_cases
        ));
        s.push_str(&format!(
            "║ Total TN cases:    {:>5}                 ║\n",
            self.total_tn_cases
        ));
        s.push_str(&format!(
            "║ TP passed:         {:>5}                 ║\n",
            self.total_tp_passed
        ));
        s.push_str(&format!(
            "║ TN passed:         {:>5}                 ║\n",
            self.total_tn_passed
        ));
        s.push_str(&format!(
            "║ Aggregate FP rate: {:>5.1}%                ║\n",
            self.aggregate_fp_rate * 100.0
        ));
        s.push_str(&format!(
            "║ Precision:         {:>5.1}%                ║\n",
            self.aggregate_precision * 100.0
        ));
        s.push_str(&format!(
            "║ Recall:            {:>5.1}%                ║\n",
            self.aggregate_recall * 100.0
        ));
        s.push_str("╚══════════════════════════════════════════╝\n");

        if !self.rejected_rules.is_empty() {
            s.push_str("\nRejected rules (missing ≥3 TP + ≥3 TN test cases):\n");
            for rule_id in &self.rejected_rules {
                s.push_str(&format!("  ✗ {}\n", rule_id));
            }
        }

        for report in &self.per_rule {
            if !report.failures.is_empty() {
                s.push_str(&format!("\n  {} ({}):\n", report.rule_id, report.rule_name));
                for failure in &report.failures {
                    s.push_str(&format!(
                        "    ✗ Expected: {} | Got: {} | Code: {}\n",
                        failure.expected, failure.actual, failure.code_snippet
                    ));
                }
            }
        }

        if self.aggregate_fp_rate > 0.15 {
            s.push_str(&format!(
                "\n⚠ Aggregate FP rate ({:.1}%) exceeds 15% threshold!\n",
                self.aggregate_fp_rate * 100.0
            ));
        }
        s
    }
}

impl RuleValidationReport {
    pub fn display_text(&self) -> String {
        let mut s = String::new();
        s.push_str("╔══════════════════════════════════════════╗\n");
        s.push_str("║     Rule Validation Report               ║\n");
        s.push_str("╠══════════════════════════════════════════╣\n");
        s.push_str(&format!(
            "║ Total rules:   {:>5}                     ║\n",
            self.total_rules
        ));
        s.push_str(&format!(
            "║ Valid rules:   {:>5}                     ║\n",
            self.valid_rules
        ));
        s.push_str(&format!(
            "║ Invalid rules: {:>5}                     ║\n",
            self.invalid_rules
        ));
        s.push_str("╚══════════════════════════════════════════╝\n");

        for err in &self.errors {
            s.push_str(&format!("\n  ✗ {}:\n", err.rule_id));
            for e in &err.errors {
                s.push_str(&format!("    - {}\n", e));
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregate_report_serde_roundtrip() {
        let report = AggregateQualityReport {
            total_rules: 10,
            rules_with_tests: 8,
            invalid_rules: 2,
            total_tp_cases: 30,
            total_tn_cases: 30,
            total_tp_passed: 28,
            total_tn_passed: 29,
            aggregate_fp_rate: 1.0 / 30.0,
            aggregate_precision: 28.0 / 29.0,
            aggregate_recall: 28.0 / 30.0,
            per_rule: Vec::new(),
            rejected_rules: vec!["bad-rule".to_string()],
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: AggregateQualityReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_rules, 10);
        assert_eq!(deserialized.rejected_rules.len(), 1);
    }

    #[test]
    fn test_validation_report_serde_roundtrip() {
        let report = RuleValidationReport {
            total_rules: 5,
            valid_rules: 3,
            invalid_rules: 2,
            errors: vec![RuleValidationError {
                rule_id: "test-rule".to_string(),
                errors: vec!["Missing test cases".to_string()],
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        let deserialized: RuleValidationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total_rules, 5);
        assert_eq!(deserialized.errors.len(), 1);
    }

    #[test]
    fn test_display_text_not_empty() {
        let report = AggregateQualityReport {
            total_rules: 1,
            rules_with_tests: 1,
            invalid_rules: 0,
            total_tp_cases: 3,
            total_tn_cases: 3,
            total_tp_passed: 3,
            total_tn_passed: 3,
            aggregate_fp_rate: 0.0,
            aggregate_precision: 1.0,
            aggregate_recall: 1.0,
            per_rule: Vec::new(),
            rejected_rules: Vec::new(),
        };
        let text = report.display_text();
        assert!(text.contains("Rule Quality Report"));
    }
}
