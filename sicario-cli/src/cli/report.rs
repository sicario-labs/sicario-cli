//! CLI definitions for the `sicario report` subcommand.
//!
//! Provides `ReportArgs` and `ReportAction` with `compliance` and `mttr`
//! subcommands.

use clap::{Parser, Subcommand};

/// Arguments for the `sicario report` command.
#[derive(Parser, Debug)]
pub struct ReportArgs {
    #[command(subcommand)]
    pub action: ReportAction,
}

/// Subcommands available under `sicario report`.
#[derive(Subcommand, Debug)]
pub enum ReportAction {
    /// Generate a compliance evidence report (remediation log, suppression audit,
    /// baseline history, MTTR).
    Compliance(ComplianceArgs),
    /// Display per-rule MTTR (Mean Time To Remediate) metrics.
    Mttr(MttrArgs),
}

/// Arguments for `sicario report compliance`.
#[derive(Parser, Debug)]
pub struct ComplianceArgs {
    /// Project root directory (defaults to current directory).
    #[arg(long, default_value = ".")]
    pub dir: String,

    /// Output format: `json` (default) or `sarif`.
    #[arg(long, default_value = "json")]
    pub format: String,
}

/// Arguments for `sicario report mttr`.
#[derive(Parser, Debug)]
pub struct MttrArgs {
    /// Project root directory (defaults to current directory).
    #[arg(long, default_value = ".")]
    pub dir: String,

    /// Output format: `table` (default) or `json`.
    #[arg(long, default_value = "table")]
    pub format: String,

    /// Restrict computation to findings detected after this ISO 8601 date.
    #[arg(long)]
    pub since: Option<String>,
}
