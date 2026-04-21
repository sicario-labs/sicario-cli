//! Benchmark subcommand arguments.

use clap::Parser;

/// Arguments for the `benchmark` subcommand.
#[derive(Parser, Debug)]
pub struct BenchmarkArgs {
    /// Output format
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Compare against a saved baseline
    #[arg(long)]
    pub compare_baseline: Option<String>,
}
