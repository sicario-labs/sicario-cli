//! CLI definitions for the `sicario guard` command.

use clap::{Args, Subcommand};

/// Poison-Pill Interceptor — monitors package installations for malicious behavior.
#[derive(Subcommand, Debug)]
pub enum GuardCommand {
    /// Watch a package cache directory for new packages (persistent mode)
    Watch(GuardWatchArgs),
    /// Scan an existing node_modules directory for behavioral anomalies (one-shot)
    Scan(GuardScanArgs),
    /// List all quarantined packages
    List,
    /// Restore a quarantined package (rename back to original)
    Restore(GuardRestoreArgs),
}

/// Arguments for `sicario guard watch`
#[derive(Args, Debug)]
pub struct GuardWatchArgs {
    /// Package manager to watch (npm, pip, cargo)
    #[arg(long, default_value = "npm")]
    pub pm: String,

    /// Project root directory to watch
    #[arg(long, default_value = ".")]
    pub project: String,

    /// Automatically rename suspicious packages to <name>.sicario-quarantined
    #[arg(long)]
    pub auto_quarantine: bool,
}

/// Arguments for `sicario guard scan`
#[derive(Args, Debug)]
pub struct GuardScanArgs {
    /// Directory to scan (default: ./node_modules)
    #[arg(long, default_value = "./node_modules")]
    pub dir: String,

    /// Automatically rename suspicious packages to <name>.sicario-quarantined
    #[arg(long)]
    pub auto_quarantine: bool,
}

/// Arguments for `sicario guard restore`
#[derive(Args, Debug)]
pub struct GuardRestoreArgs {
    /// Name of the package to restore
    pub package_name: String,
}
