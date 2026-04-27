//! Iteration guard for LLM-based auto-remediation.
//!
//! Enforces a hard cap on the number of fix attempts per vulnerability,
//! preventing runaway LLM loops in CI pipelines. On limit exhaustion the
//! guard logs a structured diagnostic to `.sicario/trace.log` and signals
//! the caller to exit with code 1.
//!
//! Requirements: 14.1, 14.2, 14.3, 14.4 (zero-exfil spec)

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ── IterationRecord ───────────────────────────────────────────────────────────

/// Diagnostic record for a single failed fix attempt.
#[derive(Debug, Clone)]
pub struct IterationRecord {
    /// 1-indexed attempt number.
    pub attempt: u32,
    /// Human-readable reason the attempt failed.
    pub reason: String,
}

// ── IterationGuard ────────────────────────────────────────────────────────────

/// Tracks fix attempts for a single vulnerability and enforces the iteration cap.
///
/// # Usage
///
/// ```rust,ignore
/// let mut guard = IterationGuard::new(3, &project_root);
/// for _ in 0..max {
///     match try_fix() {
///         Ok(_) => break,
///         Err(e) => {
///             if guard.record_failure(e.to_string()).is_err() {
///                 // limit reached — caller should exit 1
///                 guard.flush_trace_log("sql-injection", "src/db.rs")?;
///                 return Err(anyhow!("iteration limit reached"));
///             }
///         }
///     }
/// }
/// ```
pub struct IterationGuard {
    max_iterations: u32,
    records: Vec<IterationRecord>,
    trace_log_path: PathBuf,
}

impl IterationGuard {
    /// Create a new guard with the given cap, writing traces to
    /// `<project_root>/.sicario/trace.log`.
    pub fn new(max_iterations: u32, project_root: &Path) -> Self {
        let trace_log_path = project_root.join(".sicario").join("trace.log");
        Self {
            max_iterations,
            records: Vec::new(),
            trace_log_path,
        }
    }

    /// Record a failed attempt.
    ///
    /// Returns `Ok(attempt_number)` if more attempts remain, or
    /// `Err(())` when the cap has been reached.
    pub fn record_failure(&mut self, reason: impl Into<String>) -> Result<u32, ()> {
        let attempt = self.records.len() as u32 + 1;
        self.records.push(IterationRecord {
            attempt,
            reason: reason.into(),
        });
        if attempt >= self.max_iterations {
            Err(())
        } else {
            Ok(attempt)
        }
    }

    /// Returns `true` if the iteration cap has been reached.
    pub fn is_exhausted(&self) -> bool {
        self.records.len() as u32 >= self.max_iterations
    }

    /// Number of attempts recorded so far.
    pub fn attempts(&self) -> u32 {
        self.records.len() as u32
    }

    /// Write a structured diagnostic entry to `.sicario/trace.log`.
    ///
    /// The log is append-only so multiple runs accumulate history.
    /// Each entry is separated by a blank line for readability.
    pub fn flush_trace_log(&self, rule_id: &str, file_path: &str) -> std::io::Result<()> {
        // Ensure the .sicario directory exists
        if let Some(parent) = self.trace_log_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.trace_log_path)?;

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        writeln!(file, "=== sicario fix trace ===")?;
        writeln!(file, "timestamp: {ts}")?;
        writeln!(file, "rule_id:   {rule_id}")?;
        writeln!(file, "file:      {file_path}")?;
        writeln!(
            file,
            "result:    FAILED — iteration limit ({}) reached",
            self.max_iterations
        )?;
        writeln!(file, "attempts:")?;
        for rec in &self.records {
            writeln!(file, "  [{}] {}", rec.attempt, rec.reason)?;
        }
        writeln!(file)?; // blank separator

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_guard(max: u32) -> (TempDir, IterationGuard) {
        let dir = TempDir::new().unwrap();
        let guard = IterationGuard::new(max, dir.path());
        (dir, guard)
    }

    #[test]
    fn test_first_failure_returns_ok_when_cap_not_reached() {
        let (_dir, mut guard) = make_guard(3);
        assert_eq!(guard.record_failure("llm timeout"), Ok(1));
        assert!(!guard.is_exhausted());
    }

    #[test]
    fn test_second_failure_still_ok_for_cap_3() {
        let (_dir, mut guard) = make_guard(3);
        let _ = guard.record_failure("attempt 1");
        assert_eq!(guard.record_failure("attempt 2"), Ok(2));
        assert!(!guard.is_exhausted());
    }

    #[test]
    fn test_cap_reached_returns_err() {
        let (_dir, mut guard) = make_guard(3);
        let _ = guard.record_failure("a1");
        let _ = guard.record_failure("a2");
        assert_eq!(guard.record_failure("a3"), Err(()));
        assert!(guard.is_exhausted());
    }

    #[test]
    fn test_cap_of_one_exhausted_on_first_failure() {
        let (_dir, mut guard) = make_guard(1);
        assert_eq!(guard.record_failure("immediate fail"), Err(()));
        assert!(guard.is_exhausted());
    }

    #[test]
    fn test_flush_trace_log_creates_file() {
        let (dir, mut guard) = make_guard(2);
        let _ = guard.record_failure("syntax error");
        let _ = guard.record_failure("invalid patch");
        guard
            .flush_trace_log("sql-injection", "src/db.rs")
            .unwrap();

        let log_path = dir.path().join(".sicario").join("trace.log");
        assert!(log_path.exists());
        let content = fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("sql-injection"));
        assert!(content.contains("src/db.rs"));
        assert!(content.contains("iteration limit (2) reached"));
        assert!(content.contains("[1] syntax error"));
        assert!(content.contains("[2] invalid patch"));
    }

    #[test]
    fn test_flush_trace_log_appends_on_multiple_calls() {
        let (dir, mut guard) = make_guard(1);
        let _ = guard.record_failure("fail");
        guard.flush_trace_log("xss", "src/view.js").unwrap();
        guard.flush_trace_log("xss", "src/view.js").unwrap();

        let log_path = dir.path().join(".sicario").join("trace.log");
        let content = fs::read_to_string(&log_path).unwrap();
        // Two entries appended
        assert_eq!(content.matches("=== sicario fix trace ===").count(), 2);
    }

    #[test]
    fn test_attempts_counter() {
        let (_dir, mut guard) = make_guard(5);
        assert_eq!(guard.attempts(), 0);
        let _ = guard.record_failure("a");
        assert_eq!(guard.attempts(), 1);
        let _ = guard.record_failure("b");
        assert_eq!(guard.attempts(), 2);
    }
}
