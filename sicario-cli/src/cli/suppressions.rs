//! Suppressions subcommand arguments.

use clap::{Parser, Subcommand};

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
}
