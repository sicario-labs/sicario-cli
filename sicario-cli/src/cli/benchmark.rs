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

    /// Run the false-positive corpus scan: clone (or reuse) the 10 canonical
    /// open-source repos and assert zero high-confidence findings.
    #[arg(long)]
    pub fp_corpus: bool,

    /// Directory where FP corpus repos are cached (default: .sicario/fp-corpus/).
    /// Useful in CI to point at a pre-populated volume.
    #[arg(long)]
    pub corpus_dir: Option<String>,

    /// Target directory to benchmark against (default: vuln-sandbox/).
    /// When pointing at a Known_Vulnerable_App directory, the bundled
    /// ground-truth manifest for that app is used as the source of truth.
    #[arg(long)]
    pub target: Option<String>,

    /// Enable CI mode: exit 1 if Precision drops below --min-precision.
    #[arg(long)]
    pub benchmark: bool,

    /// Minimum precision threshold for CI mode (default: 0.80).
    /// Only used when --benchmark is active.
    #[arg(long, default_value = "0.80")]
    pub min_precision: f64,

    /// Save the current benchmark result as the reference baseline.
    /// Saves to .sicario/benchmarks/baseline.json.
    #[arg(long)]
    pub save_baseline: bool,

    /// Task 61.1: Publish benchmark results to Sicario Cloud.
    /// Uploads to POST /api/v1/orgs/{org_id}/benchmark-results.
    /// Requires SICARIO_API_KEY to be set.
    #[arg(long)]
    pub publish: bool,
}
