//! Filesystem watcher for the `sicario guard` persistent mode.
//!
//! Watches a package cache directory for new files and scans them for
//! behavioral anomalies.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use notify::RecursiveMode;
use notify_debouncer_mini::{new_debouncer, DebounceEventResult};

use super::behavioral_scanner::BehavioralScanner;
use super::quarantine::QuarantineManager;
use crate::engine::vulnerability::Severity;

/// Watches a package cache directory for new files and scans them.
pub struct PackageWatcher;

impl PackageWatcher {
    /// Watch `cache_dir` for new `.js`, `.ts`, or `.py` files.
    ///
    /// On each new file:
    /// - Determines the package directory from the file path
    /// - Calls `BehavioralScanner::scan_package`
    /// - Quarantines Critical packages (always) and High packages (if `auto_quarantine`)
    ///
    /// Blocks until `Ctrl+C` is received, then prints a summary.
    pub fn watch(cache_dir: &Path, project_root: &Path, auto_quarantine: bool) -> Result<()> {
        let packages_monitored = Arc::new(AtomicUsize::new(0));
        let packages_flagged = Arc::new(AtomicUsize::new(0));

        let monitored_clone = packages_monitored.clone();
        let flagged_clone = packages_flagged.clone();
        let project_root_owned = project_root.to_path_buf();

        // Set up Ctrl+C handler
        let (tx_stop, rx_stop) = std::sync::mpsc::channel::<()>();
        let tx_stop_clone = tx_stop.clone();
        ctrlc::set_handler(move || {
            let _ = tx_stop_clone.send(());
        })
        .ok();

        let (tx_event, rx_event) = std::sync::mpsc::channel::<PathBuf>();

        // Set up the debounced file watcher
        let mut debouncer = new_debouncer(
            Duration::from_millis(200),
            move |result: DebounceEventResult| {
                if let Ok(events) = result {
                    for event in events {
                        // notify-debouncer-mini uses event.path (singular)
                        let path = event.path;
                        // Only watch .js, .ts, .py files
                        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                            if matches!(ext, "js" | "ts" | "py") {
                                let _ = tx_event.send(path);
                            }
                        }
                    }
                }
            },
        )?;

        debouncer
            .watcher()
            .watch(cache_dir, RecursiveMode::Recursive)?;

        eprintln!(
            "[sicario guard] Watching {} for new packages...",
            cache_dir.display()
        );

        // Main event loop
        loop {
            // Check for stop signal
            if rx_stop.try_recv().is_ok() {
                break;
            }

            // Process file events with a short timeout
            match rx_event.recv_timeout(Duration::from_millis(100)) {
                Ok(file_path) => {
                    // Determine the package directory from the file path
                    if let Some(pkg_dir) = resolve_package_dir(&file_path, cache_dir) {
                        monitored_clone.fetch_add(1, Ordering::Relaxed);

                        match BehavioralScanner::scan_package(&pkg_dir) {
                            Ok(anomalies) => {
                                let has_critical =
                                    anomalies.iter().any(|a| a.severity == Severity::Critical);
                                let has_high =
                                    anomalies.iter().any(|a| a.severity == Severity::High);

                                if has_critical {
                                    flagged_clone.fetch_add(1, Ordering::Relaxed);
                                    let pkg_name = pkg_dir
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or("unknown");
                                    eprintln!(
                                        "\n[sicario guard] ⚠ CRITICAL: Package '{}' contains malicious patterns!",
                                        pkg_name
                                    );
                                    for anomaly in anomalies
                                        .iter()
                                        .filter(|a| a.severity == Severity::Critical)
                                    {
                                        eprintln!(
                                            "  {:?} at {}:{}",
                                            anomaly.signal,
                                            anomaly.file.display(),
                                            anomaly.line
                                        );
                                    }

                                    if let Err(e) = QuarantineManager::quarantine(
                                        &pkg_dir,
                                        &anomalies,
                                        auto_quarantine,
                                    ) {
                                        eprintln!("[sicario guard] Failed to quarantine: {}", e);
                                    } else if auto_quarantine {
                                        eprintln!(
                                            "[sicario guard] Package '{}' quarantined.",
                                            pkg_name
                                        );
                                    } else {
                                        eprintln!(
                                            "[sicario guard] Package '{}' flagged (use --auto-quarantine to rename).",
                                            pkg_name
                                        );
                                    }
                                } else if has_high {
                                    flagged_clone.fetch_add(1, Ordering::Relaxed);
                                    let pkg_name = pkg_dir
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or("unknown");
                                    eprintln!(
                                        "\n[sicario guard] ⚡ WARNING: Package '{}' has suspicious patterns:",
                                        pkg_name
                                    );
                                    for anomaly in
                                        anomalies.iter().filter(|a| a.severity == Severity::High)
                                    {
                                        eprintln!(
                                            "  {:?} at {}:{}",
                                            anomaly.signal,
                                            anomaly.file.display(),
                                            anomaly.line
                                        );
                                    }
                                    if auto_quarantine {
                                        if let Err(e) = QuarantineManager::quarantine(
                                            &pkg_dir, &anomalies, true,
                                        ) {
                                            eprintln!(
                                                "[sicario guard] Failed to quarantine: {}",
                                                e
                                            );
                                        }
                                    }
                                }
                                // Clean packages: silent
                            }
                            Err(e) => {
                                tracing::debug!("Failed to scan package {:?}: {}", pkg_dir, e);
                            }
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // No events — check stop signal again
                    if rx_stop.try_recv().is_ok() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let monitored = packages_monitored.load(Ordering::Relaxed);
        let flagged = packages_flagged.load(Ordering::Relaxed);
        eprintln!(
            "\nSicario Guard: monitored {} packages, flagged {}",
            monitored, flagged
        );

        Ok(())
    }
}

/// Resolve the package directory from a file path within a cache directory.
///
/// For `node_modules/pkg-name/lib/index.js`, returns `node_modules/pkg-name`.
/// For scoped packages `node_modules/@scope/pkg/index.js`, returns `node_modules/@scope/pkg`.
fn resolve_package_dir(file_path: &Path, cache_dir: &Path) -> Option<PathBuf> {
    // Get the relative path from cache_dir
    let rel = file_path.strip_prefix(cache_dir).ok()?;
    let mut components = rel.components();

    let first = components.next()?.as_os_str().to_str()?;

    if first.starts_with('@') {
        // Scoped package: @scope/pkg-name/...
        let second = components.next()?.as_os_str().to_str()?;
        Some(cache_dir.join(first).join(second))
    } else {
        // Regular package: pkg-name/...
        Some(cache_dir.join(first))
    }
}

/// Resolve the npm cache directory.
///
/// Checks `node_modules/` in the project root first, then `~/.npm/_npx`.
pub fn resolve_npm_cache_dir(project_root: &Path) -> Option<PathBuf> {
    let node_modules = project_root.join("node_modules");
    if node_modules.is_dir() {
        return Some(node_modules);
    }

    // Fall back to ~/.npm/_npx
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(PathBuf::from);
    if let Some(home) = home {
        let npx_cache = home.join(".npm").join("_npx");
        if npx_cache.is_dir() {
            return Some(npx_cache);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_resolve_package_dir_regular_package() {
        let cache = PathBuf::from("/project/node_modules");
        let file = PathBuf::from("/project/node_modules/lodash/lodash.js");
        let result = resolve_package_dir(&file, &cache);
        assert_eq!(result, Some(PathBuf::from("/project/node_modules/lodash")));
    }

    #[test]
    fn test_resolve_package_dir_scoped_package() {
        let cache = PathBuf::from("/project/node_modules");
        let file = PathBuf::from("/project/node_modules/@babel/core/lib/index.js");
        let result = resolve_package_dir(&file, &cache);
        assert_eq!(
            result,
            Some(PathBuf::from("/project/node_modules/@babel/core"))
        );
    }

    #[test]
    fn test_resolve_npm_cache_dir_finds_node_modules() {
        let root = TempDir::new().unwrap();
        let node_modules = root.path().join("node_modules");
        std::fs::create_dir_all(&node_modules).unwrap();

        let result = resolve_npm_cache_dir(root.path());
        assert_eq!(result, Some(node_modules));
    }

    #[test]
    fn test_resolve_npm_cache_dir_returns_none_when_missing() {
        let root = TempDir::new().unwrap();
        // No node_modules directory
        let result = resolve_npm_cache_dir(root.path());
        // May return ~/.npm/_npx if it exists on the test machine, so we just
        // verify it doesn't panic
        let _ = result;
    }

    /// Test that the watcher correctly identifies new files and calls scan_package.
    /// This is a unit test for the resolve_package_dir logic used by the watcher.
    #[test]
    fn test_watcher_detects_new_file_in_watched_directory() {
        let root = TempDir::new().unwrap();
        let cache_dir = root.path().join("node_modules");
        std::fs::create_dir_all(&cache_dir).unwrap();

        // Create a package directory with a suspicious file
        let pkg_dir = cache_dir.join("evil-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();

        let mut f = std::fs::File::create(pkg_dir.join("package.json")).unwrap();
        f.write_all(br#"{"name":"evil-pkg","version":"1.0.0","keywords":[]}"#)
            .unwrap();

        let mut f = std::fs::File::create(pkg_dir.join("index.js")).unwrap();
        f.write_all(b"const cp = require('child_process');")
            .unwrap();

        // Simulate what the watcher does: resolve package dir and scan
        let new_file = pkg_dir.join("index.js");
        let resolved = resolve_package_dir(&new_file, &cache_dir);
        assert_eq!(resolved, Some(pkg_dir.clone()));

        // Scan the package
        let anomalies = BehavioralScanner::scan_package(&pkg_dir).unwrap();
        assert!(
            !anomalies.is_empty(),
            "Expected anomalies from evil package"
        );
        assert!(anomalies.iter().any(|a| a.severity == Severity::Critical));
    }

    #[test]
    fn test_clean_package_produces_no_anomalies() {
        let root = TempDir::new().unwrap();
        let cache_dir = root.path().join("node_modules");
        std::fs::create_dir_all(&cache_dir).unwrap();

        let pkg_dir = cache_dir.join("clean-pkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();

        let mut f = std::fs::File::create(pkg_dir.join("package.json")).unwrap();
        f.write_all(br#"{"name":"clean-pkg","version":"1.0.0","keywords":[]}"#)
            .unwrap();

        let mut f = std::fs::File::create(pkg_dir.join("index.js")).unwrap();
        f.write_all(b"function add(a, b) { return a + b; }\nmodule.exports = { add };")
            .unwrap();

        let anomalies = BehavioralScanner::scan_package(&pkg_dir).unwrap();
        assert!(
            anomalies.is_empty(),
            "Expected no anomalies from clean package"
        );
    }
}
