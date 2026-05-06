//! Fix subcommand arguments.

use clap::{Parser, ValueEnum};

/// Default maximum LLM fix iterations.
pub const DEFAULT_MAX_ITERATIONS: u32 = 3;

/// Output format for fix results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FixOutputFormat {
    Text,
    Json,
}

/// Arguments for the `fix` subcommand.
#[derive(Parser, Debug)]
pub struct FixArgs {
    /// File path to fix (ignored when --staged is set)
    #[arg(default_value = "")]
    pub file: String,

    /// Specific rule ID to fix (optional)
    #[arg(long)]
    pub rule: Option<String>,

    /// Revert a previously applied patch by ID
    #[arg(long)]
    pub revert: Option<String>,

    /// Skip post-fix verification scan
    #[arg(long)]
    pub no_verify: bool,

    /// Apply all fixes without prompting for confirmation (batch mode).
    /// `--auto` is an alias for `--yes`.
    #[arg(long, alias = "auto")]
    pub yes: bool,

    /// Maximum number of LLM fix iterations before giving up (default: 3).
    /// Overrides the SICARIO_MAX_ITERATIONS environment variable.
    #[arg(long, env = "SICARIO_MAX_ITERATIONS", default_value_t = DEFAULT_MAX_ITERATIONS)]
    pub max_iterations: u32,

    /// Pre-approve AI Fallback without the interactive prompt (for CI use).
    ///
    /// When set, Sicario will transmit file context to the LLM without asking
    /// for consent. A one-line notice is printed before each LLM call.
    /// Without this flag, Sicario halts and prompts the user when no
    /// deterministic template is found (zero-exfiltration by default).
    #[arg(long)]
    pub allow_ai: bool,

    /// Suppress the patch receipt output (for clean CI logs).
    ///
    /// By default, a zero-exfiltration receipt is printed after every
    /// successful patch. Use this flag to suppress it.
    #[arg(long)]
    pub no_receipt: bool,

    /// Select the remediation agent.
    ///
    /// Valid values:
    ///   - `local`            — use the local Ollama instance (auto-selects model)
    ///   - `local-<model>`    — use the local Ollama instance with a specific model
    ///   - `cloud`            — use the configured cloud LLM provider
    ///
    /// When `local` or `local-<model>` is specified, AI consent is granted
    /// implicitly — no interactive prompt is shown for localhost calls.
    #[arg(long)]
    pub agent: Option<String>,

    /// Fix only the files currently staged in git (`git diff --cached --name-only`).
    ///
    /// When set:
    ///   - Enumerates staged files via `git diff --cached --name-only`.
    ///   - Applies fixes automatically (no interactive diff prompt).
    ///   - Uses only deterministic templates — no LLM fallback.
    ///   - With `--format json`, outputs a JSON array of fix result objects.
    ///   - Exits non-zero if run outside a Git repository.
    #[arg(long)]
    pub staged: bool,

    /// Output format for fix results (default: text).
    ///
    /// With `--staged --format json`, outputs a JSON array:
    /// `[{ "file", "rule_id", "line", "fixed", "template_used" }, ...]`
    #[arg(long, value_enum, default_value = "text")]
    pub format: FixOutputFormat,

    /// After a successful patch application, open a pull request (GitHub) or
    /// merge request (GitLab) with the fix.
    ///
    /// Requires `GITHUB_TOKEN` (for GitHub) or `GITLAB_TOKEN` (for GitLab) to
    /// be set in the environment. The provider is auto-detected from the
    /// `git remote get-url origin` output.
    #[arg(long)]
    pub pr: bool,
}

impl FixArgs {
    /// Resolve the effective max-iterations value.
    ///
    /// The `--max-iterations` flag (or `SICARIO_MAX_ITERATIONS` env var) takes
    /// precedence. Returns an error string if the value is 0.
    pub fn resolve_max_iterations(&self) -> Result<u32, String> {
        if self.max_iterations == 0 {
            return Err("Invalid --max-iterations value: must be at least 1".to_string());
        }
        Ok(self.max_iterations)
    }
}
