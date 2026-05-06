//! Scan subcommand arguments.

use crate::engine::vulnerability::Severity;
use clap::{ArgGroup, Parser, ValueEnum};

/// Severity level for the `--fail-on` CI/CD exit code gate.
/// Only Critical, High, Medium, and Low are valid (no Info).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOnLevel {
    Critical,
    High,
    Medium,
    Low,
}

impl From<FailOnLevel> for Severity {
    fn from(level: FailOnLevel) -> Self {
        match level {
            FailOnLevel::Critical => Severity::Critical,
            FailOnLevel::High => Severity::High,
            FailOnLevel::Medium => Severity::Medium,
            FailOnLevel::Low => Severity::Low,
        }
    }
}

impl std::fmt::Display for FailOnLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailOnLevel::Critical => write!(f, "Critical"),
            FailOnLevel::High => write!(f, "High"),
            FailOnLevel::Medium => write!(f, "Medium"),
            FailOnLevel::Low => write!(f, "Low"),
        }
    }
}

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
    /// Directory to scan (positional, defaults to current directory)
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: String,

    /// Directory to scan (named flag, overrides positional PATH if both provided)
    #[arg(long, hide = true)]
    pub dir: Option<String>,

    /// Rule files to load (can be specified multiple times)
    #[arg(long)]
    pub rules: Vec<String>,

    /// Directory containing custom YAML rule files to load.
    /// User rules take precedence over built-in rules on ID conflicts.
    /// If the path doesn't exist or has no valid YAML files, a warning is printed
    /// and scanning continues with built-in rules only.
    #[arg(long)]
    pub rules_dir: Option<String>,

    /// Watch mode: continuously re-scan on file changes.
    /// Debounces events by 100ms. Press Ctrl+C to exit cleanly.
    #[arg(long)]
    pub watch: bool,

    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,

    /// Minimum severity to report (default: low)
    #[arg(long, value_enum, default_value = "low")]
    pub severity_threshold: SeverityLevel,

    /// Minimum severity to display in output (default: low).
    /// Findings below this level are silently dropped from all output and the summary.
    /// Alias: -s
    /// Example: --min-severity medium  (hides Low and Info findings)
    #[arg(long = "min-severity", short = 's', value_enum, default_value = "low")]
    pub min_severity: SeverityLevel,

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

    /// Trace taint paths from external input sources to each finding.
    /// Prints a box-drawing call chain for each finding above the severity threshold.
    /// Output goes to stderr to avoid contaminating --format json.
    #[arg(long)]
    pub trace: bool,

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

    /// Publish ALL findings to Sicario Cloud, including Low and Info severity.
    /// By default, --publish only sends Medium and above to reduce dashboard noise.
    /// Use this flag to override that filter and send the complete finding set.
    #[arg(long = "publish-all", requires = "publish")]
    pub publish_all: bool,

    /// Disable automatic cloud exposure analysis (K8s manifest detection)
    #[arg(long)]
    pub no_cloud: bool,

    /// Organization ID to publish scan results under (used with --publish)
    #[arg(long)]
    pub org: Option<String>,

    /// Severity threshold for CI/CD exit code gating (default: High).
    /// Exit code 1 if any non-suppressed finding is at or above this level.
    /// Overrides SICARIO_FAIL_ON env var.
    #[arg(long, value_enum)]
    pub fail_on: Option<FailOnLevel>,

    /// Number of surrounding context lines to include in each finding snippet (default: 3, min: 0, max: 10).
    /// Overrides SICARIO_SNIPPET_CONTEXT env var.
    #[arg(long)]
    pub snippet_context: Option<u8>,

    /// Suppress the patch receipt output in watch mode (for clean CI logs).
    ///
    /// By default, a zero-exfiltration receipt is printed after every
    /// `[resolved]` event in watch mode. Use this flag to suppress it.
    #[arg(long)]
    pub no_receipt: bool,

    /// Generate and display proof-of-concept exploit payloads for confirmed findings.
    ///
    /// For each finding above the severity threshold, a consent prompt is shown
    /// before any payload is printed. With `--format json`, the consent prompt
    /// is suppressed and a `poc` field is included in each finding object.
    ///
    /// WARNING: Only run against safe, local development environments.
    #[arg(long)]
    pub prove: bool,

    /// Scan dependencies for license risk and append a license risk table to output.
    ///
    /// Checks npm and PyPI packages against known license risk tiers:
    ///   HIGH:   GPL-2.0, GPL-3.0, AGPL-3.0, SSPL-1.0, EUPL-1.2
    ///   MEDIUM: LGPL-2.1, LGPL-3.0, MPL-2.0, CDDL-1.0
    ///   LOW:    MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, 0BSD
    ///
    /// With `--format json`, a `license_findings` array is included alongside
    /// `security_findings`. Packages in `.sicario/license-allowlist.txt` are
    /// reported but do not affect the exit code.
    #[arg(long)]
    pub licenses: bool,

    /// Exit with code 1 if any dependency has a license at or above this risk tier.
    ///
    /// Valid values: `high` (exit 1 on HIGH-tier only) or `medium` (exit 1 on
    /// HIGH or MEDIUM tier). Requires `--licenses` to be set.
    /// Allowlisted packages (`.sicario/license-allowlist.txt`) are excluded.
    #[arg(long, value_name = "TIER")]
    pub fail_on_license: Option<String>,

    /// Record suppression patterns for findings that have inline `sicario-ignore` directives.
    ///
    /// After the scan, for each suppressed finding, the pattern is recorded in
    /// `.sicario/learned_suppressions.json`. Once a pattern has been recorded 3+
    /// times, `--auto-suppress` will automatically exclude matching findings.
    #[arg(long)]
    pub learn_suppressions: bool,
}

impl Default for ScanArgs {
    fn default() -> Self {
        Self {
            path: ".".to_string(),
            dir: None,
            rules: Vec::new(),
            rules_dir: None,
            watch: false,
            format: OutputFormat::Text,
            severity_threshold: SeverityLevel::Low,
            min_severity: SeverityLevel::Low,
            diff: None,
            confidence_threshold: 0.0,
            quiet: false,
            verbose: false,
            exclude: Vec::new(),
            include: Vec::new(),
            jobs: None,
            timeout: None,
            max_lines_per_finding: 5,
            max_chars_per_line: 160,
            staged: false,
            dataflow_traces: false,
            trace: false,
            no_color: false,
            force_color: false,
            exclude_rule: Vec::new(),
            json_output: None,
            sarif_output: None,
            text_output: None,
            time: false,
            no_cache: false,
            no_cache_write: false,
            auto_suppress: false,
            publish: false,
            publish_all: false,
            no_cloud: false,
            org: None,
            fail_on: None,
            snippet_context: None,
            no_receipt: false,
            prove: false,
            licenses: false,
            fail_on_license: None,
            learn_suppressions: false,
        }
    }
}

impl ScanArgs {
    /// Resolve the effective scan directory.
    ///
    /// `--dir` (named flag) takes precedence over the positional `PATH` argument
    /// for backward compatibility with scripts that use `--dir`.
    pub fn resolved_dir(&self) -> &str {
        self.dir.as_deref().unwrap_or(&self.path)
    }

    /// Resolve the `--fail-on` severity threshold.
    ///
    /// Priority: `--fail-on` flag > `SICARIO_FAIL_ON` env var > default (`High`).
    /// Returns `Err` with exit-code-2 message if the env var contains an invalid value.
    pub fn resolve_fail_on(&self) -> Result<Severity, String> {
        if let Some(level) = self.fail_on {
            return Ok(level.into());
        }
        if let Ok(val) = std::env::var("SICARIO_FAIL_ON") {
            return parse_fail_on_str(&val);
        }
        Ok(Severity::High)
    }

    /// Resolve the `--snippet-context` value.
    ///
    /// Priority: `--snippet-context` flag > `SICARIO_SNIPPET_CONTEXT` env var > default (3).
    /// Returns `Err` with exit-code-2 message if the value is out of range [0, 10].
    pub fn resolve_snippet_context(&self) -> Result<usize, String> {
        if let Some(n) = self.snippet_context {
            let n = n as usize;
            if n > 10 {
                return Err(format!(
                    "Invalid --snippet-context value '{n}'. Must be between 0 and 10."
                ));
            }
            return Ok(n);
        }
        if let Ok(val) = std::env::var("SICARIO_SNIPPET_CONTEXT") {
            let n: usize = val.trim().parse().map_err(|_| {
                format!(
                    "Invalid SICARIO_SNIPPET_CONTEXT value '{val}'. Must be an integer between 0 and 10."
                )
            })?;
            if n > 10 {
                return Err(format!(
                    "Invalid SICARIO_SNIPPET_CONTEXT value '{n}'. Must be between 0 and 10."
                ));
            }
            return Ok(n);
        }
        Ok(3)
    }
}

/// Parse a `--fail-on` / `SICARIO_FAIL_ON` string into a `Severity`.
pub fn parse_fail_on_str(s: &str) -> Result<Severity, String> {
    match s.trim() {
        "Critical" => Ok(Severity::Critical),
        "High" => Ok(Severity::High),
        "Medium" => Ok(Severity::Medium),
        "Low" => Ok(Severity::Low),
        other => Err(format!(
            "Invalid severity '{other}'. Valid values: Critical, High, Medium, Low"
        )),
    }
}
