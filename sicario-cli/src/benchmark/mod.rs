//! Performance benchmarking module — timing, memory, per-language breakdown,
//! false-positive corpus definitions, and corpus clone management.

pub mod accuracy;
pub mod corpus_manager;
pub mod fp_corpus;
pub mod runner;

pub use accuracy::{AccuracyBenchmark, AccuracyResult};
pub use corpus_manager::{
    print_preparation_summary, CorpusManager, CorpusRepoResult, CorpusRepoStatus,
};
pub use fp_corpus::{load_fp_corpus, FpCorpusRepo, FP_CORPUS_REPOS};
pub use runner::{BenchmarkComparison, BenchmarkResult, BenchmarkRunner, LanguageBenchmark};
