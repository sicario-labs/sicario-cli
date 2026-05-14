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

/// Confidence threshold level for the `--confidence-threshold` flag.
/// Controls which findings are included based on the rule's confidence level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ConfidenceThresholdLevel {
    /// Include only high-confidence findings.
    High,
    /// Include high and medium confidence findings.
    Medium,
    /// Include all findings regardless of confidence (default).
    Low,
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

    /// Minimum numeric confidence score to report (0.0–1.0). Internal use.
    #[arg(long = "confidence-score", default_value = "0.0", hide = true)]
    pub confidence_threshold: f64,

    /// Filter findings by rule confidence level.
    /// `high` → only high-confidence findings.
    /// `medium` → high + medium confidence findings.
    /// `low` (default) → all findings regardless of confidence.
    #[arg(long = "confidence-threshold", value_enum, default_value = "low")]
    pub confidence_level: ConfidenceThresholdLevel,

    /// Suppress all output except final results
    #[arg(long)]
    pub quiet: bool,

    /// Print detailed progress and diagnostics
    #[arg(long)]
    pub verbose: bool,

    /// Show only the top N highest-priority findings (default: show all).
    /// Findings are ranked by a composite risk score combining severity,
    /// confidence, reachability, and cloud exposure.
    /// Example: sicario scan . --top 5
    #[arg(long)]
    pub top: Option<usize>,

    /// Focus mode: show only Critical and High findings, grouped by file,
    /// with inline fix commands. Designed for first-time users.
    /// Equivalent to: --min-severity high --top 10 with grouped output.
    #[arg(long)]
    pub focus: bool,

    /// Display a compact summary table of findings instead of full diagnostic output.
    #[arg(long)]
    pub summary: bool,

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

    /// Execute minimalist hook mode: pauses commit with an auto-fix prompt on High/Critical findings
    #[arg(long)]
    pub hook_mode: bool,

    /// Include dataflow traces in output
    #[arg(long)]
    pub dataflow_traces: bool,

    /// Trace taint paths from external input sources to each finding.
    /// Prints a box-drawing call chain for each finding above the severity threshold.
    /// Output goes to stderr to avoid contaminating --format json.
    #[arg(long)]
    pub trace: bool,

    /// Enable interprocedural taint analysis (2-hop source-to-sink tracking).
    /// Identifies taint sources (req.query, os.environ, fs.readFile, etc.) and
    /// tracks data flow to sinks (SQL queries, shell commands, file paths, HTTP
    /// requests, HTML rendering). Adds `taint_path` field to JSON output.
    #[arg(long)]
    pub taint: bool,

    /// Apply all deterministic Fix_Templates to findings in a single pass after scanning.
    /// Creates a backup of each modified file before writing.
    /// Prints a per-finding receipt: rule ID, file, line, template used.
    /// Skips findings where no deterministic template exists.
    #[arg(long)]
    pub fix: bool,

    /// With --fix: apply fixes only to staged files and re-stage after fixing.
    /// Requires a git repository.
    #[arg(long, requires = "fix")]
    pub fix_staged: bool,

    /// After scanning and applying fixes (requires --publish), create a branch
    /// `sicario/autofix-<timestamp>`, commit all fixes, push, and open a PR/MR.
    /// Prints the PR/MR URL to stdout on success.
    #[arg(long, requires = "publish")]
    pub auto_pr: bool,

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

    /// Write results in the selected --format to this file
    #[arg(long)]
    pub output: Option<String>,

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

    /// Include 100-char truncated code snippets in the publish payload.
    /// By default, only a one-way SHA-256 hash of matched code is uploaded.
    /// Use this flag to explicitly opt in to snippet transmission.
    /// When active, lines_of_code_transmitted > 0 in the audit log.
    #[arg(long = "publish-with-snippet", requires = "publish")]
    pub publish_with_snippet: bool,

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

    // ── Group I: Semgrep Parity flags (Tasks 52–60) ───────────────────────────

    /// Enable secrets detection mode (Task 56.1).
    /// Scans for credential patterns: API keys, tokens, connection strings, SSH keys.
    /// Matched secret values are never transmitted — only a one-way SHA-256 hash.
    #[arg(long)]
    pub secrets: bool,

    /// Enable SCA (Software Composition Analysis) mode (Task 57.1).
    /// Parses lockfiles and checks dependencies against the local vulnerability database.
    #[arg(long)]
    pub sca: bool,

    /// Enable all scan modes in one pass: --secrets, --sca, and --taint (Task 69.1).
    /// Deduplicates findings across scan types.
    #[arg(long)]
    pub all: bool,

    /// Scan full git history for secrets in all commits reachable from HEAD (Task 56.6).
    /// Reports historical findings with commit SHA, timestamp, and author email.
    /// Requires --secrets to be active.
    #[arg(long, requires = "secrets")]
    pub historical: bool,

    /// Disable inline `sicario-ignore` comment processing (Task 52.5).
    /// Use for security audits where suppression bypass must be prevented.
    #[arg(long)]
    pub no_ignore_comments: bool,

    /// Disable automatic .gitignore pattern application (Task 52.7).
    /// By default, files matching .gitignore patterns are excluded from scanning.
    #[arg(long)]
    pub no_git_ignore: bool,

    /// Maximum file size in bytes to scan (default: 1 MB) (Task 60.3).
    /// Files larger than this threshold are skipped with a warning.
    #[arg(long, default_value = "1048576")]
    pub max_file_size: u64,

    /// Dry run: execute the full scan pipeline but do not write the audit log,
    /// do not publish findings, and do not apply fixes (Task 78.6).
    /// Prints what would be done. Useful for testing CI configuration.
    #[arg(long)]
    pub dry_run: bool,

    /// Exit code 1 only when reachable SCA vulnerabilities are found (Task 57.6).
    /// Requires --sca to be active.
    #[arg(long, requires = "sca")]
    pub fail_on_reachable: bool,
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
            confidence_level: ConfidenceThresholdLevel::Low,
            quiet: false,
            verbose: false,
            top: None,
            focus: false,
            summary: false,
            exclude: Vec::new(),
            include: Vec::new(),
            jobs: None,
            timeout: None,
            max_lines_per_finding: 5,
            max_chars_per_line: 160,
            staged: false,
            hook_mode: false,
            dataflow_traces: false,
            trace: false,
            taint: false,
            fix: false,
            fix_staged: false,
            auto_pr: false,
            no_color: false,
            force_color: false,
            exclude_rule: Vec::new(),
            json_output: None,
            sarif_output: None,
            text_output: None,
            output: None,
            time: false,
            no_cache: false,
            no_cache_write: false,
            auto_suppress: false,
            publish: false,
            publish_all: false,
            publish_with_snippet: false,
            no_cloud: false,
            org: None,
            fail_on: None,
            snippet_context: None,
            no_receipt: false,
            prove: false,
            licenses: false,
            fail_on_license: None,
            learn_suppressions: false,
            secrets: false,
            sca: false,
            all: false,
            historical: false,
            no_ignore_comments: false,
            no_git_ignore: false,
            max_file_size: 1_048_576,
            dry_run: false,
            fail_on_reachable: false,
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
