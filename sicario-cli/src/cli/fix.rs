//! Fix subcommand arguments.

use clap::Parser;

/// Arguments for the `fix` subcommand.
#[derive(Parser, Debug)]
pub struct FixArgs {
    /// File path to fix
    pub file: String,

    /// Specific rule ID to fix (optional)
    #[arg(long)]
    pub rule: Option<String>,

    /// Revert a previously applied patch by ID
    #[arg(long)]
    pub revert: Option<String>,

    /// Skip post-fix verification scan
    #[arg(long)]
    pub no_verify: bool,

    /// Apply all fixes without prompting for confirmation (batch mode).
    /// `--auto` is an alias for `--yes`.
    #[arg(long, alias = "auto")]
    pub yes: bool,
}
