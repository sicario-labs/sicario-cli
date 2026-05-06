//! Suppressions subcommand arguments.

use clap::{Parser, Subcommand, ValueEnum};

/// Manage inline suppressions.
#[derive(Parser, Debug)]
pub struct SuppressionsCommand {
    #[command(subcommand)]
    pub action: SuppressionsAction,
}

#[derive(Subcommand, Debug)]
pub enum SuppressionsAction {
    /// List all active suppressions
    List,
    /// Reset learned suppression patterns
    Reset,
    /// Audit suppression directives with git attribution
    Audit(SuppressionAuditArgs),
}

/// Arguments for the `suppressions audit` subcommand.
#[derive(Parser, Debug)]
pub struct SuppressionAuditArgs {
    /// Output format (json or csv)
    #[arg(long, value_enum, default_value = "json")]
    pub format: AuditOutputFormat,

    /// Filter by commit date (ISO 8601 format, e.g. 2024-01-01 or 2024-01-01T00:00:00Z)
    #[arg(long)]
    pub since: Option<String>,

    /// Filter by author email
    #[arg(long)]
    pub author: Option<String>,

    /// Output file path (appends to existing file rather than overwriting)
    #[arg(long)]
    pub output: Option<String>,
}

/// Output format for suppression audit.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum AuditOutputFormat {
    Json,
    Csv,
}
