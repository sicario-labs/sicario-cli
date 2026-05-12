//! CLI arguments for the `sicario rule` command.
//!
//! Subcommands:
//!   - `sicario rule <description>` — compile a natural language description into a rule (LLM)
//!   - `sicario rule test <pattern> <file>` — print all AST nodes matching pattern
//!   - `sicario rule validate <rule-file>` — run all test_cases, print pass/fail
//!   - `sicario rule new` — scaffold a new YAML rule file
//!
//! Requirements: Req 17 — Interactive Rule Authoring (Tasks 17.1–17.7)

use clap::{Parser, Subcommand};

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

/// Top-level `sicario rule` command.
///
/// Without a subcommand, compiles a natural language description into a rule.
/// With a subcommand, performs interactive rule authoring operations.
#[derive(Parser, Debug)]
pub struct RuleCommand {
    #[command(subcommand)]
    pub action: Option<RuleAction>,

    /// Natural language description of the rule to compile (max 200 characters).
    /// Used when no subcommand is given.
    #[arg(value_name = "DESCRIPTION", required = false)]
    pub description: Option<String>,

    /// Target language for the rule (default: auto-detect from project files).
    #[arg(long, short = 'l')]
    pub lang: Option<String>,

    /// Severity level for the generated rule (default: high).
    #[arg(long, short = 's', value_enum, default_value = "high")]
    pub severity: SeverityLevel,

    /// Generate and print the query without saving to disk.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Subcommand, Debug)]
pub enum RuleAction {
    /// Print all AST nodes matching a tree-sitter pattern in a file.
    ///
    /// Example: sicario rule test "(call_expression) @call" src/app.js
    Test(RuleTestArgs),
    /// Run all test_cases in a YAML rule file and print pass/fail per case.
    Validate(RuleValidateArgs),
    /// Scaffold a new YAML rule file with correct schema and empty test_cases.
    New(RuleNewArgs),
    /// Push all YAML rules from .sicario/rules/ to Sicario Cloud.
    /// Requires SICARIO_API_KEY. Use --force to skip overwrite prompts.
    Push(RulePushArgs),
    /// Pull all org custom rules from Sicario Cloud to .sicario/rules/.
    /// Requires SICARIO_API_KEY. Use --force to skip overwrite prompts.
    Pull(RulePullArgs),
    /// List all loaded rules (built-in + local) with source column.
    List(RuleListArgs),
}

/// Arguments for `sicario rule test <pattern> <file>`
#[derive(Parser, Debug)]
pub struct RuleTestArgs {
    /// Tree-sitter pattern to match (e.g. "(call_expression) @call")
    pub pattern: String,

    /// Source file to match against
    pub file: String,

    /// Language override for ambiguous file extensions (e.g. --lang javascript)
    #[arg(long)]
    pub lang: Option<String>,

    /// Enter interactive REPL mode: evaluate patterns in < 500ms
    #[arg(long)]
    pub interactive: bool,
}

/// Arguments for `sicario rule validate <rule-file>`
#[derive(Parser, Debug)]
pub struct RuleValidateArgs {
    /// Path to the YAML rule file to validate
    pub rule_file: String,
}

/// Arguments for `sicario rule new`
#[derive(Parser, Debug)]
pub struct RuleNewArgs {
    /// Output file path for the new rule (default: new-rule.yaml)
    #[arg(long, default_value = "new-rule.yaml")]
    pub output: String,

    /// Rule ID for the new rule
    #[arg(long)]
    pub id: Option<String>,

    /// Language for the new rule
    #[arg(long, short = 'l')]
    pub lang: Option<String>,

    /// Severity for the new rule
    #[arg(long, short = 's', value_enum, default_value = "high")]
    pub severity: SeverityLevel,

    /// Pre-populate scaffold from a finding ID (--from-finding <id>)
    #[arg(long)]
    pub from_finding: Option<String>,

    /// Plain-English description for AI Assist CLI command generation
    #[arg(long)]
    pub description: Option<String>,
}

/// Legacy flat args for backward compatibility (used when no subcommand given).
#[derive(Parser, Debug)]
pub struct RuleArgs {
    /// Natural language description of the rule to compile (max 200 characters).
    pub description: String,

    /// Target language for the rule.
    #[arg(long, short = 'l')]
    pub lang: Option<String>,

    /// Severity level for the generated rule (default: high).
    #[arg(long, short = 's', value_enum, default_value = "high")]
    pub severity: SeverityLevel,

    /// Generate and print the query without saving to disk.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments for `sicario rule push`
#[derive(Parser, Debug)]
pub struct RulePushArgs {
    /// Directory containing YAML rule files (default: .sicario/rules/)
    #[arg(long, default_value = ".sicario/rules")]
    pub dir: String,

    /// Skip overwrite prompts — push all rules without confirmation
    #[arg(long)]
    pub force: bool,

    /// Organization ID (overrides SICARIO_ORG_ID env var)
    #[arg(long)]
    pub org: Option<String>,
}

/// Arguments for `sicario rule pull`
#[derive(Parser, Debug)]
pub struct RulePullArgs {
    /// Directory to write pulled rules (default: .sicario/rules/)
    #[arg(long, default_value = ".sicario/rules")]
    pub dir: String,

    /// Skip overwrite prompts — overwrite existing files without confirmation
    #[arg(long)]
    pub force: bool,

    /// Organization ID (overrides SICARIO_ORG_ID env var)
    #[arg(long)]
    pub org: Option<String>,
}

/// Arguments for `sicario rule list`
#[derive(Parser, Debug)]
pub struct RuleListArgs {
    /// Show only built-in rules
    #[arg(long)]
    pub builtin_only: bool,

    /// Show only local/custom rules
    #[arg(long)]
    pub local_only: bool,
}
