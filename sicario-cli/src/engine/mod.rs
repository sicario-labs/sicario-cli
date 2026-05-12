//! SAST engine module
//!
//! Core static analysis engine that applies security rules to ASTs.

use anyhow::Result;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub mod fingerprint;
pub mod reachability;
pub mod sast_engine;
pub mod sca;
pub mod security_rule;
pub mod taint;
pub mod vulnerability;

pub use fingerprint::{compute_code_hash, compute_match_based_id, compute_syntactic_id};
pub use sast_engine::SastEngine;
pub use sca::{KnownVulnerability, VulnerabilityDatabaseManager};
pub use security_rule::{QueryPattern, RuleTestCase, SecurityRule, TestExpectation};
pub use taint::{TaintAnalyzer, TaintNode, TaintPath};
pub use vulnerability::{Finding, OwaspCategory, Severity, TraceStep, Vulnerability};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_structure() {
        // Verify the Severity enum has the expected variants
        let s = Severity::High;
        assert_eq!(format!("{:?}", s), "High");
    }
}
