//! Hook subcommand arguments.

use clap::{Parser, Subcommand};

/// Manage Git pre-commit hooks.
#[derive(Parser, Debug)]
pub struct HookCommand {
    #[command(subcommand)]
    pub action: HookAction,
}

#[derive(Subcommand, Debug)]
pub enum HookAction {
    /// Install the Sicario pre-commit hook
    Install,
    /// Uninstall the Sicario pre-commit hook
    Uninstall,
    /// Show current hook status
    Status,
}
