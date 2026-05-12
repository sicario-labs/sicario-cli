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
    /// Fetch and print dashboard metrics as JSON from Sicario Cloud.
    /// Requires SICARIO_API_KEY and SICARIO_ORG_ID.
    Dashboard(DashboardArgs),
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

/// Arguments for `sicario report dashboard`.
#[derive(Parser, Debug)]
pub struct DashboardArgs {
    /// Organization ID (overrides SICARIO_ORG_ID env var)
    #[arg(long)]
    pub org: Option<String>,

    /// Date range start (ISO-8601, e.g. 2026-01-01)
    #[arg(long)]
    pub since: Option<String>,

    /// Project ID to scope metrics
    #[arg(long)]
    pub project: Option<String>,
}
