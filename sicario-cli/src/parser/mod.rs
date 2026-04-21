//! Tree-sitter parsing engine module
//!
//! This module provides ultra-fast AST parsing using tree-sitter compiled to native machine code.
//! It supports multiple languages and implements intelligent file exclusion based on .gitignore
//! and .sicarioignore patterns.

use anyhow::Result;
use std::path::Path;

pub mod tree_sitter_engine;
pub mod exclusion_manager;

pub use tree_sitter_engine::TreeSitterEngine;
pub use exclusion_manager::ExclusionManager;

/// Supported programming languages for parsing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Language {
    JavaScript,
    TypeScript,
    Python,
    Rust,
    Go,
    Java,
}

impl Language {
    /// Detect language from file extension
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| match ext {
                "js" | "jsx" | "mjs" | "cjs" => Some(Language::JavaScript),
                "ts" | "tsx" => Some(Language::TypeScript),
                "py" | "pyw" => Some(Language::Python),
                "rs" => Some(Language::Rust),
                "go" => Some(Language::Go),
                "java" => Some(Language::Java),
                _ => None,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_detection() {
        assert_eq!(
            Language::from_path(Path::new("test.js")),
            Some(Language::JavaScript)
        );
        assert_eq!(
            Language::from_path(Path::new("test.py")),
            Some(Language::Python)
        );
        assert_eq!(
            Language::from_path(Path::new("test.rs")),
            Some(Language::Rust)
        );
        assert_eq!(Language::from_path(Path::new("test.txt")), None);
    }
}
