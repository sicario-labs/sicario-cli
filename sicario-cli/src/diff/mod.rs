//! Diff-aware scanning module — git2-based changed-line computation.

pub mod diff_scanner;

pub use diff_scanner::{filter_findings_by_diff, DiffScanner, DiffScanning};
