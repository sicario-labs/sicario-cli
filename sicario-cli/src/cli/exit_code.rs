//! Structured exit codes for CI/CD integration.

use crate::engine::vulnerability::Severity;

/// Exit codes returned by the Sicario CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    /// Scan completed with no findings above threshold.
    Clean = 0,
    /// Scan completed with findings above threshold.
    FindingsDetected = 1,
    /// An internal error occurred.
    InternalError = 2,
}

/// A minimal finding representation used for exit code computation.
/// This decouples exit code logic from the full `Vulnerability` struct.
pub struct FindingSummary {
    pub severity: Severity,
    pub confidence_score: f64,
    pub suppressed: bool,
}

impl ExitCode {
    /// Determine the exit code from a list of findings, a severity threshold,
    /// and a confidence threshold.
    ///
    /// Returns `Clean` (0) if no findings meet all three criteria:
    ///   - severity >= severity_threshold
    ///   - confidence_score >= confidence_threshold
    ///   - not suppressed
    ///
    /// Returns `FindingsDetected` (1) otherwise.
    pub fn from_findings(
        findings: &[FindingSummary],
        severity_threshold: Severity,
        confidence_threshold: f64,
    ) -> Self {
        let actionable = findings.iter().any(|f| {
            !f.suppressed
                && f.severity >= severity_threshold
                && f.confidence_score >= confidence_threshold
        });

        if actionable {
            ExitCode::FindingsDetected
        } else {
            ExitCode::Clean
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_when_no_findings() {
        let code = ExitCode::from_findings(&[], Severity::Low, 0.0);
        assert_eq!(code, ExitCode::Clean);
    }

    #[test]
    fn clean_when_all_below_threshold() {
        let findings = vec![FindingSummary {
            severity: Severity::Low,
            confidence_score: 0.9,
            suppressed: false,
        }];
        let code = ExitCode::from_findings(&findings, Severity::High, 0.0);
        assert_eq!(code, ExitCode::Clean);
    }

    #[test]
    fn findings_detected_when_above_threshold() {
        let findings = vec![FindingSummary {
            severity: Severity::High,
            confidence_score: 0.9,
            suppressed: false,
        }];
        let code = ExitCode::from_findings(&findings, Severity::Low, 0.0);
        assert_eq!(code, ExitCode::FindingsDetected);
    }

    #[test]
    fn clean_when_suppressed() {
        let findings = vec![FindingSummary {
            severity: Severity::Critical,
            confidence_score: 1.0,
            suppressed: true,
        }];
        let code = ExitCode::from_findings(&findings, Severity::Low, 0.0);
        assert_eq!(code, ExitCode::Clean);
    }

    #[test]
    fn clean_when_below_confidence_threshold() {
        let findings = vec![FindingSummary {
            severity: Severity::Critical,
            confidence_score: 0.3,
            suppressed: false,
        }];
        let code = ExitCode::from_findings(&findings, Severity::Low, 0.5);
        assert_eq!(code, ExitCode::Clean);
    }
}
