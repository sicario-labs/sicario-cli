//! Cache subcommand arguments.

use clap::{Parser, Subcommand};

/// Manage the scan cache.
#[derive(Parser, Debug)]
pub struct CacheCommand {
    #[command(subcommand)]
    pub action: CacheAction,
}

#[derive(Subcommand, Debug)]
pub enum CacheAction {
    /// Clear all cached scan results
    Clear,
    /// Show cache statistics
    Stats,
}
