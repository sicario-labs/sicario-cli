//! CLI definitions for the `sicario guard` command.

use clap::{Args, Subcommand};

/// Poison-Pill Interceptor — monitors package installations for malicious behavior.
#[derive(Subcommand, Debug)]
pub enum GuardCommand {
    /// Watch a package cache directory for new packages (persistent mode)
    Watch(GuardWatchArgs),
    /// Scan an existing node_modules/ or site-packages/ directory for behavioral anomalies (one-shot)
    Scan(GuardScanArgs),
    /// CI mode: scan node_modules/ and site-packages/ with 7 behavioral anomaly rules.
    /// Exits 1 on any Critical anomaly. Use after npm/pip install in CI pipelines.
    Ci(GuardCiArgs),
    /// Wrap npm/pip install, scan the new package, and block if Critical anomaly found.
    Install(GuardInstallArgs),
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

    /// Path to YAML allowlist of known-safe packages (skip scanning these)
    #[arg(long)]
    pub allowlist: Option<String>,

    /// Output format: text (default) or json
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// Arguments for `sicario guard --ci`
///
/// Scans node_modules/ and site-packages/ with 7 behavioral anomaly rules.
/// Exits 1 on any Critical anomaly.
#[derive(Args, Debug)]
pub struct GuardCiArgs {
    /// Project root directory (default: current directory)
    #[arg(long, default_value = ".")]
    pub dir: String,

    /// Path to YAML allowlist of known-safe packages
    #[arg(long)]
    pub allowlist: Option<String>,

    /// Output format: text (default) or json
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// Arguments for `sicario guard install <package>`
///
/// Wraps npm/pip install, scans the new package, and blocks if Critical anomaly found.
/// Restores pre-installation state when a package is blocked.
#[derive(Args, Debug)]
pub struct GuardInstallArgs {
    /// Package name to install (e.g. "lodash" or "requests==2.28.0")
    pub package: String,

    /// Package manager to use: npm (default) or pip
    #[arg(long, default_value = "npm")]
    pub pm: String,

    /// Project root directory (default: current directory)
    #[arg(long, default_value = ".")]
    pub dir: String,

    /// Path to YAML allowlist of known-safe packages
    #[arg(long)]
    pub allowlist: Option<String>,
}

/// Arguments for `sicario guard restore`
#[derive(Args, Debug)]
pub struct GuardRestoreArgs {
    /// Name of the package to restore
    pub package_name: String,
}
