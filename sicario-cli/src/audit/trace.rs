//! Execution trace capture for auditability.
//!
//! Captures the steps the SAST engine takes during analysis and bundles them
//! into the telemetry payload. This proves deterministic execution to the
//! cloud dashboard.
//!
//! Requirements: 15.1, 15.2

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// A single step in the execution trace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceStep {
    /// Duration since the trace started (in seconds with 3 decimal places)
    pub elapsed: String,
    /// Description of the action taken
    pub action: String,
}

impl TraceStep {
    /// Create a new trace step with the given action.
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            elapsed: "0.000".to_string(),
            action: action.into(),
        }
    }

    /// Create a trace step with a specific elapsed time.
    pub fn with_elapsed(action: impl Into<String>, elapsed: Duration) -> Self {
        let secs = elapsed.as_secs_f64();
        Self {
            elapsed: format!("{:.3}", secs),
            action: action.into(),
        }
    }
}

/// A collection of trace steps captured during scan execution.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionTrace {
    /// Steps captured during the scan
    steps: Vec<TraceStep>,
    /// When the trace started
    start_time: Instant,
}

impl ExecutionTrace {
    /// Create a new execution trace.
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            start_time: Instant::now(),
        }
    }

    /// Record a new step in the execution trace.
    pub fn record(&mut self, action: impl Into<String>) {
        let elapsed = self.start_time.elapsed();
        self.steps.push(TraceStep::with_elapsed(action, elapsed));
    }

    /// Record a step with a custom elapsed time (for testing).
    pub fn record_with_elapsed(&mut self, action: impl Into<String>, elapsed: Duration) {
        self.steps.push(TraceStep::with_elapsed(action, elapsed));
    }

    /// Return the trace steps as a vector of strings for the telemetry payload.
    /// Each string is formatted as "0.01s: Parsed CST for db.js".
    pub fn as_strings(&self) -> Vec<String> {
        self.steps
            .iter()
            .map(|s| format!("{}s: {}", s.elapsed, s.action))
            .collect()
    }

    /// Return the number of steps in the trace.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Check if the trace is empty.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Clear all steps from the trace.
    pub fn clear(&mut self) {
        self.steps.clear();
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_step_serialization() {
        let step = TraceStep::new("Parsed CST for db.js");
        let json = serde_json::to_string(&step).unwrap();
        assert!(json.contains("Parsed CST for db.js"));
    }

    #[test]
    fn test_execution_trace_records_steps() {
        let mut trace = ExecutionTrace::new();
        trace.record("Parsed CST for db.js");
        trace.record("Traced untrusted input to Line 8");
        trace.record("Flagged CWE-89");

        assert_eq!(trace.len(), 3);
        let strings = trace.as_strings();
        assert!(strings[0].starts_with("0."));
        assert!(strings[0].ends_with(": Parsed CST for db.js"));
        assert!(strings[1].ends_with(": Traced untrusted input to Line 8"));
        assert!(strings[2].ends_with(": Flagged CWE-89"));
    }

    #[test]
    fn test_execution_trace_clear() {
        let mut trace = ExecutionTrace::new();
        trace.record("Step 1");
        trace.record("Step 2");
        assert_eq!(trace.len(), 2);

        trace.clear();
        assert!(trace.is_empty());
    }

    #[test]
    fn test_execution_trace_elapsed_format() {
        let mut trace = ExecutionTrace::new();
        // Simulate some elapsed time by recording with custom duration
        trace.record_with_elapsed("Test action", Duration::from_millis(123));
        
        let strings = trace.as_strings();
        assert!(strings[0].starts_with("0.12"));
        assert!(strings[0].ends_with(": Test action"));
    }
}
