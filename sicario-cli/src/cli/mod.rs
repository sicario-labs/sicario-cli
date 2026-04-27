//! Clap-based CLI definitions for Sicario.

pub mod baseline;
pub mod benchmark;
pub mod cache;
pub mod config;
pub mod exit_code;
pub mod exit_code_property_tests;
pub mod fix;
pub mod hook;
pub mod link;
pub mod lsp;
pub mod rules;
pub mod scan;
pub mod suppressions;

use clap::{Parser, Subcommand};

use self::baseline::BaselineCommand;
use self::benchmark::BenchmarkArgs;
use self::cache::CacheCommand;
use self::config::ConfigCommand;
use self::fix::FixArgs;
use self::hook::HookCommand;
use self::link::LinkArgs;
use self::lsp::LspArgs;
use self::rules::RulesCommand;
use self::scan::ScanArgs;
use self::suppressions::SuppressionsCommand;

/// Next-gen SAST security scanner
#[derive(Parser, Debug)]
#[command(name = "sicario", version, about = "Next-gen SAST security scanner")]
pub struct SicarioCli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run a security scan on a directory
    Scan(Box<ScanArgs>),
    /// Initialize a new Sicario project configuration
    Init,
    /// Generate compliance reports
    Report(ReportArgs),
    /// Apply AI-powered fixes to vulnerabilities
    Fix(FixArgs),
    /// Manage security debt baselines
    Baseline(BaselineCommand),
    /// Manage Sicario configuration and API keys
    Config(ConfigCommand),
    /// Manage inline suppressions
    Suppressions(SuppressionsCommand),
    /// Generate shell completion scripts
    Completions(CompletionsArgs),
    /// Log in to Sicario Cloud
    Login,
    /// Log out of Sicario Cloud
    Logout,
    /// Publish scan results to Sicario Cloud
    Publish(PublishArgs),
    /// Show current authenticated user
    Whoami,
    /// Launch the interactive TUI
    Tui(TuiArgs),
    /// Manage Git pre-commit hooks
    Hook(HookCommand),
    /// Start the Language Server Protocol server
    Lsp(LspArgs),
    /// Run performance benchmarks
    Benchmark(BenchmarkArgs),
    /// Test and validate security rules
    Rules(RulesCommand),
    /// Manage the scan cache
    Cache(CacheCommand),
    /// Link the current project to a Sicario Cloud project
    Link(LinkArgs),
}

/// Arguments for the `report` subcommand.
#[derive(Parser, Debug)]
pub struct ReportArgs {
    /// Directory to scan
    #[arg(long, default_value = ".")]
    pub dir: String,

    /// Output directory for reports
    #[arg(long)]
    pub output: Option<String>,

    /// Report format
    #[arg(long, default_value = "owasp")]
    pub format: String,
}

/// Arguments for the `completions` subcommand.
#[derive(Parser, Debug)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Arguments for the `tui` subcommand.
#[derive(Parser, Debug)]
pub struct TuiArgs {
    /// Directory to scan
    #[arg(long, default_value = ".")]
    pub dir: String,
}

/// Arguments for the `publish` subcommand.
#[derive(Parser, Debug)]
pub struct PublishArgs {
    /// Organization ID to publish scan results under
    #[arg(long)]
    pub org: Option<String>,
}
