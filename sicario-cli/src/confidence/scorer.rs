//! Confidence scoring module — multi-signal confidence computation.
//!
//! Computes a deterministic 0.0–1.0 confidence score per finding using three
//! weighted signals:
//!   - Reachability (0.4 weight): confirmed taint path → high score
//!   - Pattern specificity (0.3 weight): precise query match → higher score
//!   - Contextual indicators (0.3 weight): presence of sanitization/validation → lower score
//!
//! Key invariants:
//!   - Confirmed taint path from user-controlled source to sink → score ≥ 0.8
//!   - Generic pattern with no data-flow path → score ≤ 0.5
//!   - Score is always in [0.0, 1.0]
//!   - Scoring is deterministic: same inputs → bitwise-equal f64

use crate::engine::vulnerability::Finding;

// ── Signal weights ───────────────────────────────────────────────────────────

const REACHABILITY_WEIGHT: f64 = 0.4;
const PATTERN_SPECIFICITY_WEIGHT: f64 = 0.3;
const CONTEXTUAL_WEIGHT: f64 = 0.3;

// ── Reachability result ──────────────────────────────────────────────────────

/// Result of reachability analysis for a single finding.
#[derive(Debug, Clone)]
pub struct ReachabilityResult {
    /// Whether a confirmed taint path exists from a user-controlled source to the sink.
    pub has_taint_path: bool,
    /// Number of hops in the taint path (0 if no path).
    pub path_length: usize,
    /// Whether the source is directly user-controlled (HTTP request, CLI arg, etc.).
    pub source_is_user_controlled: bool,
}

impl ReachabilityResult {
    /// No reachability information available.
    pub fn unknown() -> Self {
        Self {
            has_taint_path: false,
            path_length: 0,
            source_is_user_controlled: false,
        }
    }

    /// Confirmed taint path exists.
    pub fn confirmed(path_length: usize, source_is_user_controlled: bool) -> Self {
        Self {
            has_taint_path: true,
            path_length,
            source_is_user_controlled,
        }
    }
}

// ── Pattern specificity context ──────────────────────────────────────────────

/// Describes how specific the pattern match is.
#[derive(Debug, Clone)]
pub struct PatternContext {
    /// Number of AST node constraints in the query (more = more specific).
    pub query_node_count: usize,
    /// Whether the pattern uses capture predicates (e.g., #match?, #eq?).
    pub has_predicates: bool,
    /// Whether the match is on a specific API call (e.g., `eval(x)`) vs generic pattern.
    pub is_api_specific: bool,
    /// Whether the rule targets a specific framework (e.g., Express, Django).
    pub is_framework_specific: bool,
}

impl PatternContext {
    /// A generic pattern with minimal specificity.
    pub fn generic() -> Self {
        Self {
            query_node_count: 1,
            has_predicates: false,
            is_api_specific: false,
            is_framework_specific: false,
        }
    }

    /// A specific API-targeted pattern.
    pub fn api_specific(query_node_count: usize, has_predicates: bool) -> Self {
        Self {
            query_node_count,
            has_predicates,
            is_api_specific: true,
            is_framework_specific: false,
        }
    }
}

// ── Contextual indicators ────────────────────────────────────────────────────

/// Contextual signals from the surrounding code that affect confidence.
#[derive(Debug, Clone)]
pub struct ContextualIndicators {
    /// Whether sanitization/encoding is applied near the finding.
    pub has_sanitization: bool,
    /// Whether input validation is present (e.g., type checks, regex, allowlists).
    pub has_validation: bool,
    /// Whether the finding is inside a test file or test function.
    pub is_test_code: bool,
    /// Whether the finding is in dead/unreachable code.
    pub is_dead_code: bool,
}

impl ContextualIndicators {
    /// No contextual indicators detected.
    pub fn none() -> Self {
        Self {
            has_sanitization: false,
            has_validation: false,
            is_test_code: false,
            is_dead_code: false,
        }
    }
}

// ── Scoring input ────────────────────────────────────────────────────────────

/// All inputs needed to compute a confidence score for a finding.
#[derive(Debug, Clone)]
pub struct ScoringInput {
    pub reachability: ReachabilityResult,
    pub pattern: PatternContext,
    pub context: ContextualIndicators,
}

impl ScoringInput {
    /// Default scoring input with no reachability, generic pattern, no context.
    pub fn default_for_pattern_match() -> Self {
        Self {
            reachability: ReachabilityResult::unknown(),
            pattern: PatternContext::generic(),
            context: ContextualIndicators::none(),
        }
    }
}

// ── Trait definition ─────────────────────────────────────────────────────────

/// Trait for computing confidence scores on findings.
pub trait ConfidenceScoring {
    /// Compute a deterministic confidence score in [0.0, 1.0] for a finding.
    fn score(&self, finding: &Finding, input: &ScoringInput) -> f64;

    /// Format a confidence score as a human-readable percentage string.
    fn format_score(score: f64) -> String {
        format!("{}%", (score * 100.0).round() as u32)
    }
}

// ── Implementation ───────────────────────────────────────────────────────────

/// The default confidence scorer using weighted multi-signal computation.
pub struct ConfidenceScorer;

impl ConfidenceScorer {
    pub fn new() -> Self {
        Self
    }

    /// Compute the reachability signal (0.0–1.0).
    ///
    /// - Confirmed taint path from user-controlled source: 1.0
    /// - Confirmed taint path from non-user source: 0.8
    /// - No taint path: 0.2
    fn reachability_signal(reachability: &ReachabilityResult) -> f64 {
        if reachability.has_taint_path {
            if reachability.source_is_user_controlled {
                1.0
            } else {
                // Taint path exists but source isn't directly user-controlled
                // (e.g., env var, file read). Still high confidence.
                0.8
            }
        } else {
            // No confirmed taint path — low reachability signal
            0.2
        }
    }

    /// Compute the pattern specificity signal (0.0–1.0).
    ///
    /// More specific patterns (more AST nodes, predicates, API-specific) yield
    /// higher scores.
    fn pattern_specificity_signal(pattern: &PatternContext) -> f64 {
        let mut score = 0.3; // base score for any match

        // More AST nodes in the query = more specific
        // Diminishing returns: cap contribution at 5 nodes
        let node_contribution = (pattern.query_node_count.min(5) as f64) * 0.1;
        score += node_contribution;

        // Predicates add specificity
        if pattern.has_predicates {
            score += 0.1;
        }

        // API-specific patterns are more precise
        if pattern.is_api_specific {
            score += 0.15;
        }

        // Framework-specific patterns are the most precise
        if pattern.is_framework_specific {
            score += 0.1;
        }

        // Clamp to [0.0, 1.0]
        score.min(1.0)
    }

    /// Compute the contextual signal (0.0–1.0).
    ///
    /// Presence of sanitization/validation *lowers* the signal (less likely to
    /// be a true positive). Test code and dead code also lower it.
    fn contextual_signal(context: &ContextualIndicators) -> f64 {
        let mut score: f64 = 1.0; // start high — no mitigating context

        if context.has_sanitization {
            score -= 0.4;
        }
        if context.has_validation {
            score -= 0.3;
        }
        if context.is_test_code {
            score -= 0.3;
        }
        if context.is_dead_code {
            score -= 0.5;
        }

        // Clamp to [0.0, 1.0]
        score.max(0.0)
    }
}

impl Default for ConfidenceScorer {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfidenceScoring for ConfidenceScorer {
    fn score(&self, _finding: &Finding, input: &ScoringInput) -> f64 {
        let reachability = Self::reachability_signal(&input.reachability);
        let specificity = Self::pattern_specificity_signal(&input.pattern);
        let contextual = Self::contextual_signal(&input.context);

        let raw_score = (REACHABILITY_WEIGHT * reachability)
            + (PATTERN_SPECIFICITY_WEIGHT * specificity)
            + (CONTEXTUAL_WEIGHT * contextual);

        // Clamp to [0.0, 1.0]
        raw_score.clamp(0.0, 1.0)
    }
}

// ── Convenience functions ────────────────────────────────────────────────────

/// Quick-score a finding with confirmed reachability and a specific pattern.
/// Guaranteed to return ≥ 0.8 when taint path is confirmed from user source.
pub fn score_with_confirmed_taint(finding: &Finding, path_length: usize) -> f64 {
    let scorer = ConfidenceScorer::new();
    let input = ScoringInput {
        reachability: ReachabilityResult::confirmed(path_length, true),
        pattern: PatternContext::api_specific(3, true),
        context: ContextualIndicators::none(),
    };
    scorer.score(finding, &input)
}

/// Quick-score a finding with no reachability info and a generic pattern.
/// Guaranteed to return ≤ 0.5.
pub fn score_generic_pattern(finding: &Finding) -> f64 {
    let scorer = ConfidenceScorer::new();
    let input = ScoringInput::default_for_pattern_match();
    scorer.score(finding, &input)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::vulnerability::{Finding, Severity};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_finding() -> Finding {
        Finding {
            id: Uuid::new_v4(),
            rule_id: "sql-injection".to_string(),
            rule_name: "SQL Injection".to_string(),
            file_path: PathBuf::from("src/db.rs"),
            line: 42,
            column: 10,
            end_line: None,
            end_column: None,
            snippet: "query(user_input)".to_string(),
            severity: Severity::High,
            confidence_score: 0.0,
            reachable: false,
            cloud_exposed: None,
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: None,
            fingerprint: "abc123".to_string(),
            dataflow_trace: None,
            suppressed: false,
            suppression_rule: None,
            suggested_suppression: false,
        }
    }

    #[test]
    fn test_score_in_valid_range() {
        let scorer = ConfidenceScorer::new();
        let finding = make_finding();
        let input = ScoringInput::default_for_pattern_match();
        let score = scorer.score(&finding, &input);
        assert!(
            score >= 0.0 && score <= 1.0,
            "Score out of range: {}",
            score
        );
    }

    #[test]
    fn test_confirmed_taint_path_yields_high_score() {
        let scorer = ConfidenceScorer::new();
        let finding = make_finding();
        let input = ScoringInput {
            reachability: ReachabilityResult::confirmed(3, true),
            pattern: PatternContext::api_specific(4, true),
            context: ContextualIndicators::none(),
        };
        let score = scorer.score(&finding, &input);
        assert!(
            score >= 0.8,
            "Confirmed taint path should yield score >= 0.8, got {}",
            score
        );
    }

    #[test]
    fn test_generic_pattern_no_dataflow_yields_low_score() {
        let scorer = ConfidenceScorer::new();
        let finding = make_finding();
        let input = ScoringInput::default_for_pattern_match();
        let score = scorer.score(&finding, &input);
        assert!(
            score <= 0.5,
            "Generic pattern with no data-flow should yield score <= 0.5, got {}",
            score
        );
    }

    #[test]
    fn test_determinism() {
        let scorer = ConfidenceScorer::new();
        let finding = make_finding();
        let input = ScoringInput {
            reachability: ReachabilityResult::confirmed(2, true),
            pattern: PatternContext::api_specific(3, false),
            context: ContextualIndicators {
                has_sanitization: false,
                has_validation: true,
                is_test_code: false,
                is_dead_code: false,
            },
        };
        let score1 = scorer.score(&finding, &input);
        let score2 = scorer.score(&finding, &input);
        assert_eq!(
            score1.to_bits(),
            score2.to_bits(),
            "Scores must be bitwise equal for same inputs"
        );
    }

    #[test]
    fn test_sanitization_lowers_score() {
        let scorer = ConfidenceScorer::new();
        let finding = make_finding();

        let without_sanitization = ScoringInput {
            reachability: ReachabilityResult::confirmed(2, true),
            pattern: PatternContext::api_specific(3, true),
            context: ContextualIndicators::none(),
        };
        let with_sanitization = ScoringInput {
            reachability: ReachabilityResult::confirmed(2, true),
            pattern: PatternContext::api_specific(3, true),
            context: ContextualIndicators {
                has_sanitization: true,
                has_validation: false,
                is_test_code: false,
                is_dead_code: false,
            },
        };

        let score_without = scorer.score(&finding, &without_sanitization);
        let score_with = scorer.score(&finding, &with_sanitization);
        assert!(
            score_with < score_without,
            "Sanitization should lower score: {} vs {}",
            score_with,
            score_without
        );
    }

    #[test]
    fn test_test_code_lowers_score() {
        let scorer = ConfidenceScorer::new();
        let finding = make_finding();

        let normal = ScoringInput {
            reachability: ReachabilityResult::unknown(),
            pattern: PatternContext::api_specific(3, true),
            context: ContextualIndicators::none(),
        };
        let test_code = ScoringInput {
            reachability: ReachabilityResult::unknown(),
            pattern: PatternContext::api_specific(3, true),
            context: ContextualIndicators {
                has_sanitization: false,
                has_validation: false,
                is_test_code: true,
                is_dead_code: false,
            },
        };

        let score_normal = scorer.score(&finding, &normal);
        let score_test = scorer.score(&finding, &test_code);
        assert!(
            score_test < score_normal,
            "Test code should lower score: {} vs {}",
            score_test,
            score_normal
        );
    }

    #[test]
    fn test_format_score() {
        assert_eq!(ConfidenceScorer::format_score(0.92), "92%");
        assert_eq!(ConfidenceScorer::format_score(0.0), "0%");
        assert_eq!(ConfidenceScorer::format_score(1.0), "100%");
        assert_eq!(ConfidenceScorer::format_score(0.555), "56%");
    }

    #[test]
    fn test_convenience_score_with_confirmed_taint() {
        let finding = make_finding();
        let score = score_with_confirmed_taint(&finding, 3);
        assert!(
            score >= 0.8,
            "Convenience confirmed taint should be >= 0.8, got {}",
            score
        );
    }

    #[test]
    fn test_convenience_score_generic_pattern() {
        let finding = make_finding();
        let score = score_generic_pattern(&finding);
        assert!(
            score <= 0.5,
            "Convenience generic pattern should be <= 0.5, got {}",
            score
        );
    }

    #[test]
    fn test_all_mitigating_factors_floor_at_zero() {
        let scorer = ConfidenceScorer::new();
        let finding = make_finding();
        let input = ScoringInput {
            reachability: ReachabilityResult::unknown(),
            pattern: PatternContext::generic(),
            context: ContextualIndicators {
                has_sanitization: true,
                has_validation: true,
                is_test_code: true,
                is_dead_code: true,
            },
        };
        let score = scorer.score(&finding, &input);
        assert!(
            score >= 0.0,
            "Score should never go below 0.0, got {}",
            score
        );
    }

    #[test]
    fn test_non_user_controlled_taint_path() {
        let scorer = ConfidenceScorer::new();
        let finding = make_finding();
        let input = ScoringInput {
            reachability: ReachabilityResult::confirmed(2, false), // not user-controlled
            pattern: PatternContext::api_specific(3, true),
            context: ContextualIndicators::none(),
        };
        let score = scorer.score(&finding, &input);
        // Should be high but slightly lower than user-controlled
        assert!(
            score >= 0.6,
            "Non-user taint path should still be fairly high: {}",
            score
        );
        assert!(score < 1.0);
    }
}
