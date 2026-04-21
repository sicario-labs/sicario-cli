//! Secret scanning module
//!
//! Detects and verifies hardcoded credentials in source code and git history.

pub mod secret_patterns;
pub mod secret_scanner;
pub mod suppression_parser;
pub mod verifiers;

pub use secret_patterns::{SecretPattern, SecretType};
pub use secret_scanner::SecretScanner;
pub use suppression_parser::SuppressionParser;
pub use verifiers::SecretVerifier;

/// Represents a detected secret in source code
#[derive(Debug, Clone)]
pub struct DetectedSecret {
    pub secret_type: SecretType,
    pub value: String,
    pub file_path: std::path::PathBuf,
    pub line: usize,
    pub verified: bool,
}
