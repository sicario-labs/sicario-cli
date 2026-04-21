//! Scan subcommand arguments.

use crate::engine::vulnerability::Severity;
use clap::{ArgGroup, Parser, ValueEnum};

/// Output format for scan results.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Sarif,
}

/// Wrapper so clap can parse Severity from the CLI.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SeverityLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<SeverityLevel> for Severity {
    fn from(level: SeverityLevel) -> Self {
        match level {
            SeverityLevel::Info => Severity::Info,
            SeverityLevel::Low => Severity::Low,
            SeverityLevel::Medium => Severity::Medium,
            SeverityLevel::High => Severity::High,
            SeverityLevel::Critical => Severity::Critical,
        }
    }
}

/// Arguments for the `scan` subcommand.
#[derive(Parser, Debug)]
#[command(group(ArgGroup::new("verbosity").args(["quiet", "verbose"]).multiple(false)))]
pub struct ScanArgs {
    /// Directory to scan
    #[arg(long, default_value = ".")]
    pub dir: String,

    /// Rule files to load (can be specified multiple times)
    #[arg(long)]
    pub rules: Vec<String>,

    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,

    /// Minimum severity to report (default: low)
    #[arg(long, value_enum, default_value = "low")]
    pub severity_threshold: SeverityLevel,

    /// Only show findings on lines changed since this Git ref
    #[arg(long)]
    pub diff: Option<String>,

    /// Minimum confidence score to report (0.0–1.0)
    #[arg(long, default_value = "0.0")]
    pub confidence_threshold: f64,

    /// Suppress all output except final results
    #[arg(long)]
    pub quiet: bool,

    /// Print detailed progress and diagnostics
    #[arg(long)]
    pub verbose: bool,

    /// Glob patterns to exclude from scanning
    #[arg(long)]
    pub exclude: Vec<String>,

    /// Glob patterns to include in scanning
    #[arg(long)]
    pub include: Vec<String>,

    /// Number of parallel scan threads
    #[arg(long)]
    pub jobs: Option<usize>,

    /// Per-file scan timeout in seconds
    #[arg(long)]
    pub timeout: Option<u64>,

    /// Max snippet lines per finding in text output
    #[arg(long, default_value = "5")]
    pub max_lines_per_finding: usize,

    /// Max characters per line in text output (truncates longer lines)
    #[arg(long, default_value = "160")]
    pub max_chars_per_line: usize,

    /// Only scan staged files (for pre-commit hooks)
    #[arg(long)]
    pub staged: bool,

    /// Include dataflow traces in output
    #[arg(long)]
    pub dataflow_traces: bool,

    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,

    /// Force colored output even when not a TTY
    #[arg(long)]
    pub force_color: bool,

    /// Rule IDs to exclude from scanning
    #[arg(long)]
    pub exclude_rule: Vec<String>,

    /// Write JSON results to this file
    #[arg(long)]
    pub json_output: Option<String>,

    /// Write SARIF results to this file
    #[arg(long)]
    pub sarif_output: Option<String>,

    /// Write text results to this file
    #[arg(long)]
    pub text_output: Option<String>,

    /// Print timing information
    #[arg(long)]
    pub time: bool,

    /// Disable reading from the scan cache
    #[arg(long)]
    pub no_cache: bool,

    /// Disable writing to the scan cache
    #[arg(long)]
    pub no_cache_write: bool,

    /// Automatically suppress findings matching learned patterns
    #[arg(long)]
    pub auto_suppress: bool,

    /// Publish results to Sicario Cloud after scanning
    #[arg(long)]
    pub publish: bool,
}
