//! SAST engine module
//!
//! Core static analysis engine that applies security rules to ASTs.

use anyhow::Result;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub mod sast_engine;
pub mod security_rule;
pub mod vulnerability;
pub mod reachability;
pub mod sca;

pub use sast_engine::SastEngine;
pub use security_rule::{SecurityRule, QueryPattern, RuleTestCase, TestExpectation};
pub use vulnerability::{Vulnerability, Severity, OwaspCategory, Finding, TraceStep};
pub use sca::{KnownVulnerability, VulnerabilityDatabaseManager};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_structure() {
        // Basic module structure test
        assert!(true);
    }
}
