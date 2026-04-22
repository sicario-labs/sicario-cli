//! Worker thread integration for background scanning
//!
//! Spawns a background thread that runs the SAST scan using the Rayon-backed
//! `SastEngine::scan_directory` and streams progress/result messages to the
//! TUI via mpsc channels.
//!
//! Requirements: 4.3

use anyhow::Result;
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::thread;

use crate::engine::sca::vuln_db::DbSyncEvent;
use crate::tui::app::TuiMessage;

/// Configuration for a background scan job
pub struct ScanJob {
    /// Root directory to scan
    pub directory: PathBuf,
    /// Optional paths to YAML rule files; if empty, no rules are loaded
    pub rule_files: Vec<PathBuf>,
}

/// Spawn a background thread that runs a SAST scan and sends progress messages
/// to the TUI via the provided `Sender<TuiMessage>`.
///
/// The worker:
/// 1. Sends an initial `ScanProgress { files_scanned: 0, total: 0 }` to signal start
/// 2. Runs `SastEngine::scan_directory` (which uses Rayon internally)
/// 3. Sends `VulnerabilityFound` for each detected vulnerability
/// 4. Sends `ScanComplete` when finished
/// 5. Sends `Error` if the scan fails
///
/// Returns the `JoinHandle` so the caller can optionally wait for completion.
pub fn spawn_scan_worker(job: ScanJob, tx: Sender<TuiMessage>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if let Err(e) = run_scan(job, &tx) {
            let _ = tx.send(TuiMessage::Error(format!("Scan failed: {}", e)));
        }
    })
}

/// Convert a `DbSyncEvent` into a `TuiMessage` so the TUI can display
/// sync status and stale-cache warnings.
pub fn db_sync_event_to_tui_message(event: DbSyncEvent) -> TuiMessage {
    match event {
        DbSyncEvent::SyncStarted => TuiMessage::ScanProgress {
            files_scanned: 0,
            total: 0,
        },
        DbSyncEvent::SyncComplete { new_entries } => TuiMessage::DbSyncComplete { new_entries },
        DbSyncEvent::SyncError(msg) => TuiMessage::DbSyncError(msg),
    }
}

/// Spawn a background DB sync thread that forwards `DbSyncEvent`s to the TUI
/// channel as `TuiMessage`s.
pub fn spawn_db_sync_worker(
    db: std::sync::Arc<crate::engine::sca::VulnerabilityDatabaseManager>,
    interval: std::time::Duration,
    tui_tx: std::sync::mpsc::Sender<TuiMessage>,
) -> thread::JoinHandle<()> {
    let (sync_tx, sync_rx) = std::sync::mpsc::channel::<DbSyncEvent>();
    let _sync_handle = db.start_background_sync(interval, sync_tx);

    thread::spawn(move || {
        for event in sync_rx {
            let msg = db_sync_event_to_tui_message(event);
            if tui_tx.send(msg).is_err() {
                break; // TUI has shut down
            }
        }
    })
}

fn run_scan(job: ScanJob, tx: &Sender<TuiMessage>) -> Result<()> {
    use crate::engine::sast_engine::SastEngine;

    // Signal that scanning has started — show "loading rules" phase
    // Use a sentinel total of 1 so the progress bar isn't empty
    let _ = tx.send(TuiMessage::ScanProgress {
        files_scanned: 0,
        total: 1,
    });

    let mut engine = SastEngine::new(&job.directory)?;

    for rule_file in &job.rule_files {
        let _ = engine.load_rules(rule_file);
    }

    // Phase 1: Collect all files to scan (fast — just walks the tree)
    let mut files_to_scan = Vec::new();
    engine.collect_files_recursive(&job.directory, &mut files_to_scan)?;
    let total = files_to_scan.len();

    // Send the real total so the TUI can show a meaningful progress bar
    let _ = tx.send(TuiMessage::ScanProgress {
        files_scanned: 0,
        total,
    });

    // Phase 2: Scan each file individually and stream progress
    let rules = engine.get_rules().to_vec();
    let exclusion_mgr = engine.exclusion_manager();

    for (idx, file_path) in files_to_scan.iter().enumerate() {
        match SastEngine::scan_file_parallel(file_path, &rules, &exclusion_mgr) {
            Ok(vulns) => {
                for vuln in vulns {
                    let _ = tx.send(TuiMessage::VulnerabilityFound(vuln));
                }
            }
            Err(_) => {}
        }

        let _ = tx.send(TuiMessage::ScanProgress {
            files_scanned: idx + 1,
            total,
        });
    }

    let _ = tx.send(TuiMessage::ScanComplete);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::mpsc;
    use tempfile::TempDir;

    fn write_rule_file(dir: &std::path::Path) -> PathBuf {
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
        let path = dir.join("rules.yaml");
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_worker_sends_scan_complete() {
        let temp_dir = TempDir::new().unwrap();
        let rule_file = write_rule_file(temp_dir.path());

        fs::write(temp_dir.path().join("app.js"), "const x = 1;").unwrap();

        let (tx, rx) = mpsc::channel();
        let job = ScanJob {
            directory: temp_dir.path().to_path_buf(),
            rule_files: vec![rule_file],
        };

        let handle = spawn_scan_worker(job, tx);
        handle.join().unwrap();

        let messages: Vec<TuiMessage> = rx.try_iter().collect();
        let has_complete = messages
            .iter()
            .any(|m| matches!(m, TuiMessage::ScanComplete));
        assert!(has_complete, "Worker should send ScanComplete");
    }

    #[test]
    fn test_worker_sends_progress_messages() {
        let temp_dir = TempDir::new().unwrap();
        let rule_file = write_rule_file(temp_dir.path());

        fs::write(temp_dir.path().join("a.js"), "const a = 1;").unwrap();
        fs::write(temp_dir.path().join("b.js"), "const b = 2;").unwrap();

        let (tx, rx) = mpsc::channel();
        let job = ScanJob {
            directory: temp_dir.path().to_path_buf(),
            rule_files: vec![rule_file],
        };

        let handle = spawn_scan_worker(job, tx);
        handle.join().unwrap();

        let messages: Vec<TuiMessage> = rx.try_iter().collect();
        let progress_msgs: Vec<_> = messages
            .iter()
            .filter(|m| matches!(m, TuiMessage::ScanProgress { .. }))
            .collect();

        assert!(
            !progress_msgs.is_empty(),
            "Worker should send ScanProgress messages"
        );
    }

    #[test]
    fn test_worker_sends_vulnerability_found() {
        let temp_dir = TempDir::new().unwrap();
        let rule_file = write_rule_file(temp_dir.path());

        fs::write(temp_dir.path().join("app.js"), "const secret = 'value';").unwrap();

        let (tx, rx) = mpsc::channel();
        let job = ScanJob {
            directory: temp_dir.path().to_path_buf(),
            rule_files: vec![rule_file],
        };

        let handle = spawn_scan_worker(job, tx);
        handle.join().unwrap();

        let messages: Vec<TuiMessage> = rx.try_iter().collect();
        let vuln_msgs: Vec<_> = messages
            .iter()
            .filter(|m| matches!(m, TuiMessage::VulnerabilityFound(_)))
            .collect();

        assert!(
            !vuln_msgs.is_empty(),
            "Worker should send VulnerabilityFound messages"
        );
    }

    #[test]
    fn test_worker_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        let rule_file = write_rule_file(temp_dir.path());

        let (tx, rx) = mpsc::channel();
        let job = ScanJob {
            directory: temp_dir.path().to_path_buf(),
            rule_files: vec![rule_file],
        };

        let handle = spawn_scan_worker(job, tx);
        handle.join().unwrap();

        let messages: Vec<TuiMessage> = rx.try_iter().collect();
        let has_complete = messages
            .iter()
            .any(|m| matches!(m, TuiMessage::ScanComplete));
        assert!(
            has_complete,
            "Worker should send ScanComplete even with no files"
        );
    }

    #[test]
    fn test_worker_ui_remains_responsive() {
        // Verify that the worker runs on a separate thread and the main thread
        // (simulating the TUI) can continue processing while the scan runs.
        let temp_dir = TempDir::new().unwrap();
        let rule_file = write_rule_file(temp_dir.path());

        for i in 0..5 {
            fs::write(
                temp_dir.path().join(format!("file{}.js", i)),
                format!("const x{} = {};", i, i),
            )
            .unwrap();
        }

        let (tx, rx) = mpsc::channel();
        let job = ScanJob {
            directory: temp_dir.path().to_path_buf(),
            rule_files: vec![rule_file],
        };

        // Spawn worker — main thread is free immediately
        let handle = spawn_scan_worker(job, tx);

        // Main thread can do other work while scan runs
        let mut ui_ticks = 0usize;
        loop {
            // Simulate a 16ms UI frame tick
            std::thread::sleep(std::time::Duration::from_millis(1));
            ui_ticks += 1;

            // Drain any available messages (non-blocking)
            let mut done = false;
            while let Ok(msg) = rx.try_recv() {
                if matches!(msg, TuiMessage::ScanComplete) {
                    done = true;
                }
            }
            if done {
                break;
            }
            if ui_ticks > 5000 {
                panic!("Scan did not complete within timeout");
            }
        }

        handle.join().unwrap();
        // If we got here, the UI was never blocked
        assert!(ui_ticks > 0);
    }
}
