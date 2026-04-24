//! Progress indicator for LLM API calls
//!
//! Displays a terminal spinner while the LLM generates a security fix,
//! so the user knows the CLI has not frozen.
//!
//! Requirements: 2.1, 2.2, 2.3, 2.4

use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// A terminal spinner shown during LLM fix generation.
pub struct LlmProgressSpinner {
    bar: ProgressBar,
}

impl LlmProgressSpinner {
    /// Start a new spinner with the given status message.
    ///
    /// The spinner ticks every 80 ms and uses a cyan style.
    pub fn start(message: &str) -> Self {
        let bar = ProgressBar::new_spinner();
        bar.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .expect("valid spinner template"),
        );
        bar.set_message(message.to_string());
        bar.enable_steady_tick(Duration::from_millis(80));
        Self { bar }
    }

    /// Stop the spinner with a success message.
    pub fn finish_success(&self, message: &str) {
        self.bar.finish_with_message(format!("✓ {}", message));
    }

    /// Stop the spinner with an error message.
    pub fn finish_error(&self, message: &str) {
        self.bar.finish_with_message(format!("✗ {}", message));
    }

    /// Stop the spinner with a timeout message.
    pub fn finish_timeout(&self) {
        self.bar
            .finish_with_message("✗ LLM request timed out — using template fix");
    }
}
