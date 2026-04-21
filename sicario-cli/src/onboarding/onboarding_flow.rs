//! Orchestrates the zero-configuration onboarding flow.
//!
//! Sequence:
//!   1. Auto-detect languages, package managers, and frameworks
//!   2. Configure optimal rule subsets
//!   3. Send `OnboardingDetected` to TUI (shows detection results)
//!   4. Run initial scan with progress updates
//!   5. Send `OnboardingComplete` with first actionable fix
//!   6. On user approval, apply first patch and send `OnboardingPatchApplied`
//!
//! Requirements: 10.1, 10.2, 10.3, 10.4, 10.5

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::mpsc::Sender;

use crate::tui::app::TuiMessage;
use super::detector::TechDetector;
use super::rule_configurator::RuleConfigurator;

/// Drives the zero-configuration onboarding experience.
pub struct OnboardingFlow {
    /// Root directory of the project being onboarded
    project_root: PathBuf,
    /// Optional directory containing YAML rule files
    rules_dir: Option<PathBuf>,
}

impl OnboardingFlow {
    /// Create a new onboarding flow for the given project root.
    pub fn new(project_root: &Path) -> Self {
        Self {
            project_root: project_root.to_path_buf(),
            rules_dir: None,
        }
    }

    /// Override the rules directory (useful for testing).
    pub fn with_rules_dir(mut self, rules_dir: &Path) -> Self {
        self.rules_dir = Some(rules_dir.to_path_buf());
        self
    }

    /// Run the full onboarding flow on a background thread, sending TUI messages
    /// over `tx` as each phase completes.
    ///
    /// This method is designed to be called from `std::thread::spawn`.
    pub fn run(self, tx: Sender<TuiMessage>) -> Result<()> {
        // ── Phase 1: Auto-detect technologies ────────────────────────────────
        let tech = TechDetector::detect(&self.project_root)?;

        // ── Phase 2: Configure rule subsets ──────────────────────────────────
        let rules_dir = self
            .rules_dir
            .clone()
            .unwrap_or_else(|| self.project_root.join(".sicario").join("rules"));

        let config = RuleConfigurator::configure(&tech, &rules_dir);

        // Estimate rule count (use actual count if rules exist, otherwise estimate)
        let rules_configured = if config.rule_count > 0 {
            config.rule_count
        } else {
            RuleConfigurator::estimate_default_rule_count(&tech)
        };

        // ── Phase 3: Notify TUI of detection results ──────────────────────────
        let _ = tx.send(TuiMessage::OnboardingDetected {
            languages: tech.languages.clone(),
            package_managers: tech.package_managers.clone(),
            frameworks: tech.frameworks.clone(),
            rules_configured,
        });

        // ── Phase 4: Run initial scan ─────────────────────────────────────────
        let _ = tx.send(TuiMessage::ScanProgress {
            files_scanned: 0,
            total: 0,
        });

        let vulnerabilities = self.run_scan(&config.rule_files)?;

        // ── Phase 5: Present first actionable fix ─────────────────────────────
        let _ = tx.send(TuiMessage::OnboardingComplete {
            vulnerabilities,
        });

        Ok(())
    }

    /// Spawn the onboarding flow on a background thread.
    pub fn spawn(self, tx: Sender<TuiMessage>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            if let Err(e) = self.run(tx.clone()) {
                let _ = tx.send(TuiMessage::Error(format!("Onboarding failed: {}", e)));
            }
        })
    }

    /// Run the SAST scan and return found vulnerabilities.
    fn run_scan(&self, rule_files: &[PathBuf]) -> Result<Vec<crate::engine::Vulnerability>> {
        use crate::engine::sast_engine::SastEngine;

        let mut engine = SastEngine::new(&self.project_root)?;

        for rule_file in rule_files {
            if let Err(e) = engine.load_rules(rule_file) {
                // Log but don't abort — partial rule loading is acceptable
                eprintln!("Warning: failed to load rule file {:?}: {}", rule_file, e);
            }
        }

        engine.scan_directory(&self.project_root)
    }
}

/// Apply the first patch from the onboarding scan and send the "Magic Moment"
/// message to the TUI.
///
/// Called after the user presses Enter/y in the PatchPreview state during
/// onboarding.
pub fn apply_onboarding_patch(
    vulnerability: &crate::engine::Vulnerability,
    patch_content: &str,
    tx: &Sender<TuiMessage>,
) {
    use crate::remediation::{Patch, RemediationEngine};

    let project_root = vulnerability
        .file_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    match RemediationEngine::new(&project_root) {
        Ok(engine) => {
            let original = std::fs::read_to_string(&vulnerability.file_path).unwrap_or_default();
            let backup = engine
                .backup_manager()
                .backup_file(&vulnerability.file_path)
                .unwrap_or_else(|_| vulnerability.file_path.clone());

            let patch = Patch::new(
                vulnerability.file_path.clone(),
                original,
                patch_content.to_string(),
                String::new(),
                backup,
            );

            match engine.apply_patch(&patch) {
                Ok(_) => {
                    let _ = tx.send(TuiMessage::OnboardingPatchApplied {
                        file_path: vulnerability.file_path.clone(),
                        vulnerabilities_fixed: 1,
                    });
                }
                Err(e) => {
                    let _ = tx.send(TuiMessage::PatchFailed(e.to_string()));
                }
            }
        }
        Err(e) => {
            let _ = tx.send(TuiMessage::PatchFailed(e.to_string()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::mpsc;
    use tempfile::TempDir;

    fn write_rule_file(dir: &Path) -> PathBuf {
        let content = r#"
- id: "test-rule"
  name: "Test Rule"
  description: "Matches identifiers"
  severity: Medium
  languages:
    - JavaScript
  pattern:
    query: "(identifier) @id"
    captures:
      - "id"
"#;
        let path = dir.join("javascript.yaml");
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_onboarding_flow_sends_detected_message() {
        let dir = TempDir::new().unwrap();
        // Create a package.json so detection finds something
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"react":"^18.0.0"}}"#,
        )
        .unwrap();
        // Create a rules dir with a JS rule
        let rules_dir = dir.path().join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        write_rule_file(&rules_dir);

        let (tx, rx) = mpsc::channel();
        let flow = OnboardingFlow::new(dir.path()).with_rules_dir(&rules_dir);
        let handle = flow.spawn(tx);
        handle.join().unwrap();

        let messages: Vec<TuiMessage> = rx.try_iter().collect();
        let detected = messages.iter().find(|m| matches!(m, TuiMessage::OnboardingDetected { .. }));
        assert!(detected.is_some(), "Should send OnboardingDetected message");

        if let Some(TuiMessage::OnboardingDetected { languages, .. }) = detected {
            assert!(languages.contains(&"JavaScript".to_string()));
        }
    }

    #[test]
    fn test_onboarding_flow_sends_complete_message() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"test"}"#).unwrap();
        fs::write(dir.path().join("app.js"), "const x = 1;").unwrap();

        let rules_dir = dir.path().join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        write_rule_file(&rules_dir);

        let (tx, rx) = mpsc::channel();
        let flow = OnboardingFlow::new(dir.path()).with_rules_dir(&rules_dir);
        let handle = flow.spawn(tx);
        handle.join().unwrap();

        let messages: Vec<TuiMessage> = rx.try_iter().collect();
        let complete = messages.iter().find(|m| matches!(m, TuiMessage::OnboardingComplete { .. }));
        assert!(complete.is_some(), "Should send OnboardingComplete message");
    }

    #[test]
    fn test_onboarding_flow_empty_project() {
        let dir = TempDir::new().unwrap();
        let rules_dir = dir.path().join("rules");
        fs::create_dir_all(&rules_dir).unwrap();

        let (tx, rx) = mpsc::channel();
        let flow = OnboardingFlow::new(dir.path()).with_rules_dir(&rules_dir);
        let handle = flow.spawn(tx);
        handle.join().unwrap();

        let messages: Vec<TuiMessage> = rx.try_iter().collect();
        // Should not error on empty project
        let has_error = messages.iter().any(|m| matches!(m, TuiMessage::Error(_)));
        assert!(!has_error, "Should not error on empty project");
    }

    #[test]
    fn test_onboarding_flow_message_order() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("package.json"), r#"{"name":"test"}"#).unwrap();

        let rules_dir = dir.path().join("rules");
        fs::create_dir_all(&rules_dir).unwrap();

        let (tx, rx) = mpsc::channel();
        let flow = OnboardingFlow::new(dir.path()).with_rules_dir(&rules_dir);
        let handle = flow.spawn(tx);
        handle.join().unwrap();

        let messages: Vec<TuiMessage> = rx.try_iter().collect();

        // OnboardingDetected must come before OnboardingComplete
        let detected_idx = messages.iter().position(|m| matches!(m, TuiMessage::OnboardingDetected { .. }));
        let complete_idx = messages.iter().position(|m| matches!(m, TuiMessage::OnboardingComplete { .. }));

        assert!(detected_idx.is_some(), "OnboardingDetected must be sent");
        assert!(complete_idx.is_some(), "OnboardingComplete must be sent");
        assert!(
            detected_idx.unwrap() < complete_idx.unwrap(),
            "OnboardingDetected must come before OnboardingComplete"
        );
    }
}
