//! Fix subcommand arguments.

use clap::Parser;

/// Default maximum LLM fix iterations.
pub const DEFAULT_MAX_ITERATIONS: u32 = 3;

/// Arguments for the `fix` subcommand.
#[derive(Parser, Debug)]
pub struct FixArgs {
    /// File path to fix
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
}

impl FixArgs {
    /// Resolve the effective max-iterations value.
    ///
    /// The `--max-iterations` flag (or `SICARIO_MAX_ITERATIONS` env var) takes
    /// precedence. Returns an error string if the value is 0.
    pub fn resolve_max_iterations(&self) -> Result<u32, String> {
        if self.max_iterations == 0 {
            return Err(
                "Invalid --max-iterations value: must be at least 1".to_string(),
            );
        }
        Ok(self.max_iterations)
    }
}
