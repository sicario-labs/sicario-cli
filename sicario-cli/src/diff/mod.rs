//! Diff-aware scanning module — git2-based changed-line computation.

pub mod diff_scanner;

pub use diff_scanner::{DiffScanner, DiffScanning, filter_findings_by_diff};
