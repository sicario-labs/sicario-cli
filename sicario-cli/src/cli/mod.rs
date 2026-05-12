//! Clap-based CLI definitions for Sicario.

pub mod attack;
pub mod baseline;
pub mod benchmark;
pub mod cache;
pub mod ci;
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
pub mod triage;
pub mod zero_exfil_audit;

#[cfg(test)]
pub mod watch_integration_tests;

#[cfg(test)]
pub mod fix_staged_tests;

use clap::{Parser, Subcommand};

use self::attack::AttackArgs;
use self::zero_exfil_audit::AuditCommand;
use self::baseline::BaselineCommand;
use self::benchmark::BenchmarkArgs;
use self::cache::CacheCommand;
use self::ci::CiArgs;
use self::config::ConfigCommand;
use self::exorcise::ExorciseArgs;
use self::fix::FixArgs;
use self::hook::HookCommand;
use self::link::LinkArgs;
use self::lsp::LspArgs;
use self::policy::PolicyCommand;
use self::report::ReportArgs;
use self::rule::RuleArgs;
use self::rule::RuleCommand;
use self::rules::RulesCommand;
use self::scan::ScanArgs;
use self::suppressions::SuppressionsCommand;
use self::triage::TriageArgs;

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
    /// Run a CI scan: fetch org policy, scan, apply policy modes (Block/Comment/Monitor/Disabled)
    Ci(CiArgs),
    /// View and verify the zero-exfiltration audit log
    Audit(AuditCommand),
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
    /// Launch the interactive CLI triage wizard
    Triage(TriageArgs),
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
    /// Compile a natural language description into a security rule, or use subcommands for interactive rule authoring
    Rule(RuleCommand),
    /// Run the Shadow Pen-Tester against a local target
    Attack(AttackArgs),
    /// Monitor package installations for behavioral anomalies (Poison-Pill Interceptor)
    Guard {
        #[command(subcommand)]
        command: guard::GuardCommand,
    },
    /// Install the Sicario pre-commit hook (alias for `sicario hook install`)
    InstallHook(InstallHookArgs),
    /// Uninstall the Sicario pre-commit hook (alias for `sicario hook uninstall`)
    UninstallHook,
    /// Search for security patterns across projects
    Search(SearchArgs),
    /// Update the local vulnerability database
    Update(UpdateArgs),
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

/// Arguments for the `install-hook` subcommand.
#[derive(Parser, Debug)]
pub struct InstallHookArgs {
    /// Install the auto-fix hook (Ghost Fix mode) instead of the standard scan hook.
    #[arg(long)]
    pub auto_fix: bool,

    /// Overwrite an existing hook without prompting.
    #[arg(long)]
    pub force: bool,
}

/// Arguments for the `search` subcommand.
#[derive(Parser, Debug)]
pub struct SearchArgs {
    /// Pattern to search for (tree-sitter query or plain text)
    #[arg(long)]
    pub pattern: String,

    /// Language to search in
    #[arg(long)]
    pub lang: Option<String>,

    /// Search across all projects (fetches project list from Sicario Cloud)
    #[arg(long)]
    pub all_projects: bool,

    /// Search within a specific project by name
    #[arg(long)]
    pub project: Option<String>,

    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    pub format: crate::cli::scan::OutputFormat,
}

/// Arguments for the `update` subcommand.
#[derive(Parser, Debug)]
pub struct UpdateArgs {
    /// Download the latest vulnerability database snapshot
    #[arg(long = "vuln-db")]
    pub vuln_db: bool,
}
