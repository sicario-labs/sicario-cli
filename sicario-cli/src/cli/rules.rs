//! Rules subcommand arguments.

use clap::{Parser, Subcommand};

/// Test and validate security rules.
#[derive(Parser, Debug)]
pub struct RulesCommand {
    #[command(subcommand)]
    pub action: RulesAction,
}

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// Run test cases for all loaded rules
    Test(RulesTestArgs),
    /// Validate rule YAML syntax and query compilation
    Validate(RulesValidateArgs),
}

/// Arguments for `rules test`.
#[derive(Parser, Debug)]
pub struct RulesTestArgs {
    /// Generate a quality report
    #[arg(long)]
    pub report: bool,
}

/// Arguments for `rules validate`.
#[derive(Parser, Debug)]
pub struct RulesValidateArgs {
    /// Generate a validation report
    #[arg(long)]
    pub report: bool,
}
