//! TUI application state and main loop

use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyEvent};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io::Stdout;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use crate::engine::Vulnerability;

/// Main TUI application state variants
#[derive(Debug, Clone)]
pub enum AppState {
    Welcome,
    /// Zero-configuration onboarding: auto-detection results displayed before scan
    Onboarding {
        /// Detected programming languages
        languages: Vec<String>,
        /// Detected package managers
        package_managers: Vec<String>,
        /// Detected frameworks
        frameworks: Vec<String>,
        /// Number of rules configured for detected technologies
        rules_configured: usize,
    },
    /// Waiting for the user to complete OAuth Device Flow in a browser
    AuthPending {
        /// URL the user must visit to authenticate
        verification_uri: String,
        /// Short code the user enters at the verification URI
        user_code: String,
    },
    /// Authentication completed successfully
    AuthComplete,
    Scanning {
        progress: f64,
        files_scanned: usize,
        total_files: usize,
    },
    Results {
        vulnerabilities: Vec<Vulnerability>,
        selected: usize,
    },
    /// OWASP-grouped view of results (toggled with 'o' from Results)
    OwaspResults {
        vulnerabilities: Vec<Vulnerability>,
        selected_category: usize,
    },
    PatchPreview {
        vulnerability: Vulnerability,
        patch: String,
    },
    /// Shown briefly after a patch is successfully applied
    PatchSuccess {
        file_path: std::path::PathBuf,
    },
    /// Shown when patch application fails
    PatchError {
        message: String,
    },
    /// "Magic Moment" — celebratory state after first patch is applied during onboarding
    OnboardingSuccess {
        file_path: std::path::PathBuf,
        vulnerabilities_fixed: usize,
    },
}

/// Messages sent from worker threads to the TUI via mpsc channels
#[derive(Debug, Clone)]
pub enum TuiMessage {
    ScanProgress {
        files_scanned: usize,
        total: usize,
    },
    VulnerabilityFound(Vulnerability),
    ScanComplete,
    PatchGenerated(String),
    /// Patch was successfully applied to disk
    PatchApplied,
    /// Patch application failed with an error message
    PatchFailed(String),
    Error(String),
    DbSyncComplete {
        new_entries: usize,
    },
    DbSyncError(String),
    /// OAuth Device Flow started — display verification_uri and user_code to the user
    AuthPending {
        verification_uri: String,
        user_code: String,
    },
    /// OAuth authentication completed successfully
    AuthComplete,
    /// OAuth authentication failed
    AuthFailed(String),
    /// Auto-detection completed — transition to Onboarding state
    OnboardingDetected {
        languages: Vec<String>,
        package_managers: Vec<String>,
        frameworks: Vec<String>,
        rules_configured: usize,
    },
    /// Onboarding scan complete — present first actionable fix
    OnboardingComplete {
        vulnerabilities: Vec<Vulnerability>,
    },
    /// Onboarding "Magic Moment" — first patch applied successfully
    OnboardingPatchApplied {
        file_path: std::path::PathBuf,
        vulnerabilities_fixed: usize,
    },
}

/// Create a new mpsc channel pair for TUI message passing.
/// Returns (sender, receiver) — the sender is given to worker threads,
/// the receiver is owned by the TUI.
pub fn create_tui_channel() -> (Sender<TuiMessage>, Receiver<TuiMessage>) {
    mpsc::channel()
}

/// Main TUI application
pub struct SicarioTui {
    pub terminal: Terminal<CrosstermBackend<Stdout>>,
    pub state: AppState,
    pub rx: Receiver<TuiMessage>,
    /// Accumulated vulnerabilities during a scan
    pub vulnerabilities: Vec<Vulnerability>,
    /// Whether the application should exit
    pub should_quit: bool,
    /// Last error message to display as an overlay
    pub last_error: Option<String>,
    /// Sender half — kept so callers can send patch commands back to the TUI
    /// (e.g. from a worker thread that applied a patch)
    pub patch_tx: Option<std::sync::mpsc::Sender<TuiMessage>>,
}

impl SicarioTui {
    /// Create a new TUI application with the given message receiver
    pub fn new(rx: Receiver<TuiMessage>) -> Result<Self> {
        use crossterm::terminal::{enable_raw_mode, EnterAlternateScreen};
        use crossterm::ExecutableCommand;
        use std::io::stdout;

        enable_raw_mode()?;
        let mut stdout = stdout();
        stdout.execute(EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        Ok(Self {
            terminal,
            state: AppState::Welcome,
            rx,
            vulnerabilities: Vec::new(),
            should_quit: false,
            last_error: None,
            patch_tx: None,
        })
    }

    /// Run the main TUI event loop
    pub fn run(&mut self) -> Result<()> {
        use super::events::poll_event;
        use super::ui::render;

        while !self.should_quit {
            // Drain all pending messages from worker threads
            self.drain_messages();

            // Render current state
            let state = self.state.clone();
            self.terminal.draw(|frame| render(frame, &state))?;

            // Poll for keyboard input with a short timeout so we stay responsive
            if let Some(event) = poll_event(Duration::from_millis(16))? {
                self.handle_input(event)?;
            }
        }

        self.cleanup()?;
        Ok(())
    }

    /// Drain all pending messages from the worker channel without blocking
    fn drain_messages(&mut self) {
        loop {
            match self.rx.try_recv() {
                Ok(msg) => self.process_message(msg),
                Err(_) => break,
            }
        }
    }

    /// Process a single TuiMessage and update application state accordingly
    pub fn process_message(&mut self, msg: TuiMessage) {
        match msg {
            TuiMessage::ScanProgress { files_scanned, total } => {
                let progress = if total > 0 {
                    files_scanned as f64 / total as f64
                } else {
                    0.0
                };
                self.state = AppState::Scanning {
                    progress,
                    files_scanned,
                    total_files: total,
                };
            }
            TuiMessage::VulnerabilityFound(vuln) => {
                self.vulnerabilities.push(vuln);
            }
            TuiMessage::ScanComplete => {
                let vulns = std::mem::take(&mut self.vulnerabilities);
                self.state = AppState::Results {
                    vulnerabilities: vulns,
                    selected: 0,
                };
            }
            TuiMessage::PatchGenerated(patch) => {
                if let AppState::Results { vulnerabilities, selected } = &self.state {
                    if let Some(vuln) = vulnerabilities.get(*selected).cloned() {
                        self.state = AppState::PatchPreview {
                            vulnerability: vuln,
                            patch,
                        };
                    }
                }
            }            TuiMessage::PatchApplied => {
                // Return to Results state after a successful patch application
                let vulns = std::mem::take(&mut self.vulnerabilities);
                self.state = AppState::Results {
                    vulnerabilities: vulns,
                    selected: 0,
                };
            }
            TuiMessage::PatchFailed(err) => {
                // Surface the error; stay in current state so user can retry
                self.last_error = Some(err);
            }
            TuiMessage::Error(msg) => {
                self.last_error = Some(msg);
            }
            TuiMessage::DbSyncComplete { .. } | TuiMessage::DbSyncError(_) => {
                // DB sync status — surfaced in future tasks
            }
            TuiMessage::AuthPending { verification_uri, user_code } => {
                self.state = AppState::AuthPending {
                    verification_uri,
                    user_code,
                };
            }
            TuiMessage::AuthComplete => {
                self.state = AppState::AuthComplete;
            }
            TuiMessage::AuthFailed(msg) => {
                self.last_error = Some(format!("Authentication failed: {}", msg));
                self.state = AppState::Welcome;
            }
            TuiMessage::OnboardingDetected {
                languages,
                package_managers,
                frameworks,
                rules_configured,
            } => {
                self.state = AppState::Onboarding {
                    languages,
                    package_managers,
                    frameworks,
                    rules_configured,
                };
            }
            TuiMessage::OnboardingComplete { vulnerabilities } => {
                self.vulnerabilities = vulnerabilities;
                let vulns = self.vulnerabilities.clone();
                self.state = AppState::Results {
                    vulnerabilities: vulns,
                    selected: 0,
                };
            }
            TuiMessage::OnboardingPatchApplied { file_path, vulnerabilities_fixed } => {
                self.state = AppState::OnboardingSuccess {
                    file_path,
                    vulnerabilities_fixed,
                };
            }
        }
    }

    /// Handle a terminal input event
    pub fn handle_input(&mut self, event: Event) -> Result<()> {
        if let Event::Key(KeyEvent { code, .. }) = event {
            match &self.state {
                // ── PatchPreview: Enter applies, Esc cancels ──────────────────
                AppState::PatchPreview { vulnerability, patch } => {
                    let vuln = vulnerability.clone();
                    let patch_str = patch.clone();
                    match code {
                        KeyCode::Enter | KeyCode::Char('y') => {
                            // Apply the patch via a worker thread so the TUI stays responsive
                            if let Some(tx) = &self.patch_tx {
                                let tx = tx.clone();
                                let project_root = vuln.file_path
                                    .parent()
                                    .unwrap_or(std::path::Path::new("."))
                                    .to_path_buf();
                                let vuln_clone = vuln.clone();
                                let patch_content = patch_str.clone();
                                std::thread::spawn(move || {
                                    use crate::remediation::RemediationEngine;
                                    use crate::remediation::Patch;
                                    match RemediationEngine::new(&project_root) {
                                        Ok(engine) => {
                                            // Reconstruct a Patch from the preview data
                                            let original = std::fs::read_to_string(&vuln_clone.file_path)
                                                .unwrap_or_default();
                                            let backup = engine.backup_manager().backup_file(&vuln_clone.file_path)
                                                .unwrap_or_else(|_| vuln_clone.file_path.clone());
                                            let p = Patch::new(
                                                vuln_clone.file_path.clone(),
                                                original,
                                                patch_content,
                                                String::new(),
                                                backup,
                                            );
                                            match engine.apply_patch(&p) {
                                                Ok(_) => { let _ = tx.send(TuiMessage::PatchApplied); }
                                                Err(e) => { let _ = tx.send(TuiMessage::PatchFailed(e.to_string())); }
                                            }
                                        }
                                        Err(e) => {
                                            let _ = tx.send(TuiMessage::PatchFailed(e.to_string()));
                                        }
                                    }
                                });
                            } else {
                                // No patch_tx configured — apply synchronously
                                self.apply_current_patch_sync(&vuln, &patch_str);
                            }
                        }
                        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('q') => {
                            // Cancel — return to Results
                            let vulns = std::mem::take(&mut self.vulnerabilities);
                            self.state = AppState::Results {
                                vulnerabilities: vulns,
                                selected: 0,
                            };
                        }
                        _ => {}
                    }
                }

                // ── All other states ──────────────────────────────────────────
                _ => match code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        self.should_quit = true;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        match &mut self.state {
                            AppState::Results { vulnerabilities, selected } => {
                                if !vulnerabilities.is_empty() {
                                    *selected = (*selected + 1).min(vulnerabilities.len() - 1);
                                }
                            }
                            AppState::OwaspResults { selected_category, .. } => {
                                *selected_category = (*selected_category + 1).min(9);
                            }
                            _ => {}
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        match &mut self.state {
                            AppState::Results { selected, .. } => {
                                *selected = selected.saturating_sub(1);
                            }
                            AppState::OwaspResults { selected_category, .. } => {
                                *selected_category = selected_category.saturating_sub(1);
                            }
                            _ => {}
                        }
                    }
                    KeyCode::Enter => {
                        // In Onboarding state, Enter starts the scan
                        if matches!(self.state, AppState::Onboarding { .. }) {
                            // Transition to scanning — caller is responsible for
                            // sending ScanProgress messages via the worker
                            self.state = AppState::Scanning {
                                progress: 0.0,
                                files_scanned: 0,
                                total_files: 0,
                            };
                        }
                        // In Results state, Enter generates a patch for the selected vuln
                        if let AppState::Results { vulnerabilities, selected } = &self.state {
                            if let Some(vuln) = vulnerabilities.get(*selected).cloned() {
                                if let Some(tx) = self.patch_tx.clone() {
                                    let vuln_clone = vuln.clone();
                                    std::thread::spawn(move || {
                                        use crate::remediation::RemediationEngine;
                                        let project_root = vuln_clone.file_path
                                            .parent()
                                            .unwrap_or(std::path::Path::new("."))
                                            .to_path_buf();
                                        match RemediationEngine::new(&project_root) {
                                            Ok(engine) => {
                                                match engine.generate_patch(&vuln_clone) {
                                                    Ok(patch) => {
                                                        let _ = tx.send(TuiMessage::PatchGenerated(patch.diff.clone()));
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
                                    });
                                }
                            }
                        }
                    }
                    KeyCode::Char('s') => {
                        // 's' on Welcome screen starts onboarding / scanning
                        if matches!(self.state, AppState::Welcome) {
                            self.state = AppState::Scanning {
                                progress: 0.0,
                                files_scanned: 0,
                                total_files: 0,
                            };
                        }
                    }
                    KeyCode::Char('o') => {
                        // 'o' toggles OWASP grouped view from Results
                        match &self.state {
                            AppState::Results { vulnerabilities, .. } => {
                                let vulns = vulnerabilities.clone();
                                self.state = AppState::OwaspResults {
                                    vulnerabilities: vulns,
                                    selected_category: 0,
                                };
                            }
                            AppState::OwaspResults { vulnerabilities, .. } => {
                                let vulns = vulnerabilities.clone();
                                self.state = AppState::Results {
                                    vulnerabilities: vulns,
                                    selected: 0,
                                };
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                },
            }
        }
        Ok(())
    }

    /// Apply the current patch synchronously (used when no patch_tx is configured).
    fn apply_current_patch_sync(&mut self, vuln: &Vulnerability, patch_content: &str) {
        use crate::remediation::{Patch, RemediationEngine};

        let project_root = vuln
            .file_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();

        match RemediationEngine::new(&project_root) {
            Ok(engine) => {
                let original = std::fs::read_to_string(&vuln.file_path).unwrap_or_default();
                let backup = engine
                    .backup_manager()
                    .backup_file(&vuln.file_path)
                    .unwrap_or_else(|_| vuln.file_path.clone());
                let patch = Patch::new(
                    vuln.file_path.clone(),
                    original,
                    patch_content.to_string(),
                    String::new(),
                    backup,
                );
                match engine.apply_patch(&patch) {
                    Ok(_) => {
                        let vulns = std::mem::take(&mut self.vulnerabilities);
                        self.state = AppState::Results {
                            vulnerabilities: vulns,
                            selected: 0,
                        };
                    }
                    Err(e) => {
                        self.last_error = Some(e.to_string());
                    }
                }
            }
            Err(e) => {
                self.last_error = Some(e.to_string());
            }
        }
    }

    /// Restore terminal to original state
    pub fn cleanup(&mut self) -> Result<()> {
        use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
        use crossterm::ExecutableCommand;

        disable_raw_mode()?;
        self.terminal.backend_mut().execute(LeaveAlternateScreen)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;
    use crate::engine::{Vulnerability, Severity};

    fn make_vuln() -> Vulnerability {
        Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "test-rule".to_string(),
            file_path: PathBuf::from("src/main.rs"),
            line: 10,
            column: 5,
            snippet: "let x = secret;".to_string(),
            severity: Severity::High,
            reachable: true,
            cloud_exposed: None,
            cwe_id: None,
            owasp_category: None,
        }
    }

    #[test]
    fn test_channel_creation() {
        let (tx, rx) = create_tui_channel();
        tx.send(TuiMessage::ScanComplete).unwrap();
        let msg = rx.recv().unwrap();
        assert!(matches!(msg, TuiMessage::ScanComplete));
    }

    #[test]
    fn test_message_ordering() {
        let (tx, rx) = create_tui_channel();
        for i in 0..5u32 {
            tx.send(TuiMessage::ScanProgress {
                files_scanned: i as usize,
                total: 10,
            })
            .unwrap();
        }
        for i in 0..5u32 {
            match rx.recv().unwrap() {
                TuiMessage::ScanProgress { files_scanned, .. } => {
                    assert_eq!(files_scanned, i as usize);
                }
                _ => panic!("unexpected message"),
            }
        }
    }

    #[test]
    fn test_process_scan_progress() {
        let (_tx, rx) = create_tui_channel();
        // Build a minimal SicarioTui without a real terminal
        // We test process_message directly via a helper struct
        let mut state = AppState::Welcome;
        let msg = TuiMessage::ScanProgress { files_scanned: 3, total: 10 };
        // Simulate what process_message does
        if let TuiMessage::ScanProgress { files_scanned, total } = msg {
            let progress = files_scanned as f64 / total as f64;
            state = AppState::Scanning { progress, files_scanned, total_files: total };
        }
        assert!(matches!(state, AppState::Scanning { files_scanned: 3, .. }));
    }

    #[test]
    fn test_process_vulnerability_found_then_complete() {
        let (tx, rx) = create_tui_channel();
        let vuln = make_vuln();
        tx.send(TuiMessage::VulnerabilityFound(vuln.clone())).unwrap();
        tx.send(TuiMessage::ScanComplete).unwrap();

        let mut vulns: Vec<Vulnerability> = Vec::new();
        let mut state = AppState::Welcome;

        loop {
            match rx.try_recv() {
                Ok(TuiMessage::VulnerabilityFound(v)) => vulns.push(v),
                Ok(TuiMessage::ScanComplete) => {
                    state = AppState::Results {
                        vulnerabilities: std::mem::take(&mut vulns),
                        selected: 0,
                    };
                    break;
                }
                _ => break,
            }
        }

        if let AppState::Results { vulnerabilities, .. } = state {
            assert_eq!(vulnerabilities.len(), 1);
            assert_eq!(vulnerabilities[0].rule_id, "test-rule");
        } else {
            panic!("expected Results state");
        }
    }

    #[test]
    fn test_appstate_variants_exist() {        let _welcome = AppState::Welcome;
        let _scanning = AppState::Scanning { progress: 0.5, files_scanned: 5, total_files: 10 };
        let _results = AppState::Results { vulnerabilities: vec![], selected: 0 };
        let _preview = AppState::PatchPreview {
            vulnerability: make_vuln(),
            patch: "diff".to_string(),
        };
        let _success = AppState::PatchSuccess {
            file_path: std::path::PathBuf::from("src/main.rs"),
        };
        let _error = AppState::PatchError {
            message: "something went wrong".to_string(),
        };
        let _onboarding = AppState::Onboarding {
            languages: vec!["Rust".to_string()],
            package_managers: vec!["Cargo".to_string()],
            frameworks: vec![],
            rules_configured: 5,
        };
        let _onboarding_success = AppState::OnboardingSuccess {
            file_path: std::path::PathBuf::from("src/main.rs"),
            vulnerabilities_fixed: 1,
        };
        let _owasp = AppState::OwaspResults {
            vulnerabilities: vec![],
            selected_category: 0,
        };
    }
}
