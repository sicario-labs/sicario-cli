//! CLI arguments for the `sicario rule` command.
//!
//! The `rule` command compiles a natural language description into a validated
//! tree-sitter `SecurityRule` using a local Ollama LLM.
//!
//! Requirements: eta-engine 17.6

use clap::Parser;

/// Severity level for the generated rule.
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum SeverityLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityLevel> for crate::engine::vulnerability::Severity {
    fn from(level: SeverityLevel) -> Self {
        match level {
            SeverityLevel::Info => crate::engine::vulnerability::Severity::Info,
            SeverityLevel::Low => crate::engine::vulnerability::Severity::Low,
            SeverityLevel::Medium => crate::engine::vulnerability::Severity::Medium,
            SeverityLevel::High => crate::engine::vulnerability::Severity::High,
            SeverityLevel::Critical => crate::engine::vulnerability::Severity::Critical,
        }
    }
}

/// Arguments for the `sicario rule` command.
#[derive(Parser, Debug)]
pub struct RuleArgs {
    /// Natural language description of the rule to compile (max 200 characters).
    ///
    /// Example: "Detect dangerous eval() calls in JavaScript"
    pub description: String,

    /// Target language for the rule (default: auto-detect from project files).
    ///
    /// Valid values: javascript, typescript, python, rust, go, java, ruby, php
    #[arg(long, short = 'l')]
    pub lang: Option<String>,

    /// Severity level for the generated rule (default: high).
    #[arg(long, short = 's', value_enum, default_value = "high")]
    pub severity: SeverityLevel,

    /// Generate and print the query without saving to disk.
    #[arg(long)]
    pub dry_run: bool,
}
