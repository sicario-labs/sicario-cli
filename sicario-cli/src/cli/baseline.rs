//! Baseline subcommand arguments.

use crate::cli::scan::SeverityLevel;
use clap::{Parser, Subcommand};

/// Manage security debt baselines.
#[derive(Parser, Debug)]
pub struct BaselineCommand {
    #[command(subcommand)]
    pub action: BaselineAction,
}

#[derive(Subcommand, Debug)]
pub enum BaselineAction {
    /// Save current scan results as a baseline snapshot
    Save(BaselineSaveArgs),
    /// Compare current scan against a saved baseline
    Compare(BaselineCompareArgs),
    /// Show finding count trends across baselines
    Trend(BaselineTrendArgs),
    /// Diff current scan against a baseline (CI-friendly)
    Diff(BaselineDiffArgs),
}

/// Arguments for `baseline save`.
#[derive(Parser, Debug)]
pub struct BaselineSaveArgs {
    /// Tag for this baseline snapshot
    #[arg(long)]
    pub tag: Option<String>,

    /// Output format
    #[arg(long, default_value = "json")]
    pub format: String,
}

/// Arguments for `baseline compare`.
#[derive(Parser, Debug)]
pub struct BaselineCompareArgs {
    /// Tag or timestamp of the baseline to compare against
    pub reference: String,

    /// Output format
    #[arg(long, default_value = "json")]
    pub format: String,
}

/// Arguments for `baseline trend`.
#[derive(Parser, Debug)]
pub struct BaselineTrendArgs {
    /// Output format
    #[arg(long, default_value = "json")]
    pub format: String,
}

/// Arguments for `baseline diff`.
#[derive(Parser, Debug)]
pub struct BaselineDiffArgs {
    /// Tag or timestamp of the baseline to compare against (optional; uses most recent if omitted)
    pub reference: Option<String>,

    /// Exit with code 1 on new findings above threshold (for CI use)
    #[arg(long)]
    pub ci: bool,

    /// Minimum severity for CI blocking (default: high)
    #[arg(long, value_enum, default_value = "high")]
    pub threshold: SeverityLevel,

    /// Tag of a named baseline to compare against
    #[arg(long)]
    pub tag: Option<String>,
}
