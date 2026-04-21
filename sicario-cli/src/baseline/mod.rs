//! Baseline tracking module — security debt snapshots and delta computation.
//!
//! Provides the `BaselineManager` for saving scan results as timestamped JSON
//! baselines, computing deltas between scans, and reporting trends over time.

pub mod manager;

pub use manager::{
    Baseline, BaselineDelta, BaselineFinding, BaselineManagement, BaselineManager, BaselineSummary,
};
