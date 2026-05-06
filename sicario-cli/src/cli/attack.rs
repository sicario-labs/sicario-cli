//! CLI arguments for the `sicario attack` command.

use clap::Parser;

/// Arguments for the `attack` subcommand.
#[derive(Parser, Debug)]
pub struct AttackArgs {
    /// Target URL to attack (must be localhost or 127.0.0.1)
    #[arg(long, default_value = "http://localhost:3000")]
    pub target: String,

    /// Per-request timeout in seconds
    #[arg(long, default_value = "10")]
    pub timeout: u64,

    /// Extract routes and generate payloads without firing any HTTP requests
    #[arg(long)]
    pub dry_run: bool,

    /// Skip the confirmation prompt
    #[arg(long)]
    pub yes: bool,
}
