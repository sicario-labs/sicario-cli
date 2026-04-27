//! Code remediation module
//!
//! Generates and applies security patches using AI and AST manipulation.
//! The LLM client is provider-agnostic — any OpenAI-compatible endpoint works.
//!
//! Requirements: 9.1, 9.2, 9.3, 9.4, 11.1–11.10

pub mod backup_manager;
pub mod iteration_guard;
pub mod llm_client;
pub mod patch;
pub mod progress;
pub mod remediation_engine;
pub mod remediation_property_tests;
pub mod templates;

pub use backup_manager::BackupManager;
pub use llm_client::LlmClient;
pub use patch::Patch;
pub use remediation_engine::RemediationEngine;

/// Context for generating a security fix.
///
/// Passed to the LLM to provide all information needed to produce a correct,
/// minimal patch.
#[derive(Debug, Clone)]
pub struct FixContext {
    /// Human-readable description of the vulnerability (rule name + CWE)
    pub vulnerability_description: String,
    /// Code snippet with surrounding context (±10 lines)
    pub code_snippet: String,
    /// Programming language of the file (e.g. "Python", "JavaScript")
    pub file_language: String,
    /// Detected framework, if any (e.g. "Django", "React")
    pub framework: Option<String>,
    /// CWE identifier, if available (e.g. "CWE-89")
    pub cwe_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_structure() {
        let _ctx = FixContext {
            vulnerability_description: "test".to_string(),
            code_snippet: "code".to_string(),
            file_language: "Rust".to_string(),
            framework: None,
            cwe_id: None,
        };
    }
}
