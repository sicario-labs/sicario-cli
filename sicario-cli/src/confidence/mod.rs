//! AI confidence scoring module — multi-signal confidence computation.
//!
//! Provides the `ConfidenceScoring` trait and `ConfidenceScorer` implementation
//! that computes deterministic 0.0–1.0 scores per finding using reachability,
//! pattern specificity, and contextual indicators.

pub mod scorer;

pub use scorer::{
    compute_priority_score, ConfidenceScorer, ConfidenceScoring, ContextualIndicators,
    PatternContext, ReachabilityResult, ScoringInput,
};
