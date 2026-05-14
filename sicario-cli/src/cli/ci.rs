//! CLI arguments for the `sicario ci` subcommand.
//!
//! `sicario ci` fetches org policy from Sicario Cloud before scanning,
//! applies policy modes (Block/Comment/Monitor/Disabled), and falls back
//! to `sicario scan` behavior when no SICARIO_API_KEY is present.
//!
//! Requirements: Req 19 — Per-Rule Policy Modes and Cloud Policy Sync

use clap::Parser;

/// Arguments for the `sicario ci` subcommand.
#[derive(Parser, Debug)]
pub struct CiArgs {
    /// Directory to scan (default: current directory)
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: String,

    /// Output format: text (default), json, or sarif
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Organization ID (overrides SICARIO_ORG_ID env var)
    #[arg(long)]
    pub org: Option<String>,

    /// Publish findings to Sicario Cloud after scanning
    #[arg(long)]
    pub publish: bool,

    /// Minimum severity to report (default: low)
    #[arg(long, default_value = "low")]
    pub min_severity: String,

    /// Disable reading from the scan cache
    #[arg(long)]
    pub no_cache: bool,
}
