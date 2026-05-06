//! Clap-based CLI definitions for Sicario.

pub mod attack;
pub mod baseline;
pub mod benchmark;
pub mod cache;
pub mod config;
pub mod exit_code;
pub mod exit_code_property_tests;
pub mod exorcise;
pub mod fix;
pub mod guard;
pub mod hook;
pub mod link;
pub mod lsp;
pub mod policy;
pub mod report;
pub mod rule;
pub mod rules;
pub mod scan;
pub mod suppressions;

#[cfg(test)]
pub mod watch_integration_tests;

#[cfg(test)]
pub mod fix_staged_tests;

use clap::{Parser, Subcommand};

use self::attack::AttackArgs;
use self::baseline::BaselineCommand;
use self::benchmark::BenchmarkArgs;
use self::cache::CacheCommand;
use self::config::ConfigCommand;
use self::exorcise::ExorciseArgs;
use self::fix::FixArgs;
use self::hook::HookCommand;
use self::link::LinkArgs;
use self::lsp::LspArgs;
use self::policy::PolicyCommand;
use self::report::ReportArgs;
use self::rule::RuleArgs;
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
    Login(LoginArgs),
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
    /// Manage and enforce organizational security policies
    Policy(PolicyCommand),
    /// Run performance benchmarks
    Benchmark(BenchmarkArgs),
    /// Test and validate security rules
    Rules(RulesCommand),
    /// Manage the scan cache
    Cache(CacheCommand),
    /// Link the current project to a Sicario Cloud project
    Link(LinkArgs),
    /// Start the Kiro Power MCP server (stdio JSON-RPC 2.0)
    Mcp,
    /// Rewrite local git history to remove hardcoded secrets
    Exorcise(ExorciseArgs),
    /// Compile a natural language description into a security rule
    Rule(RuleArgs),
    /// Run the Shadow Pen-Tester against a local target
    Attack(AttackArgs),
    /// Monitor package installations for behavioral anomalies (Poison-Pill Interceptor)
    Guard {
        #[command(subcommand)]
        command: guard::GuardCommand,
    },
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

/// Arguments for the `login` subcommand.
#[derive(Parser, Debug)]
pub struct LoginArgs {
    /// Authenticate using a project API token directly (non-interactive).
    /// Useful in CI environments where browser-based OAuth is not available.
    /// Example: sicario login --token=sic_proj_...
    #[arg(long)]
    pub token: Option<String>,
}
