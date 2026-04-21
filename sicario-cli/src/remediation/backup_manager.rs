//! Backup management for safe patch application
//!
//! Creates timestamped backups of files before modification and maintains a
//! patch history log. Provides automatic cleanup of old backups.
//!
//! Requirements: 14.1, 14.2, 14.5

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

// ── Patch history log entry ───────────────────────────────────────────────────

/// A single entry in the patch history log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchHistoryEntry {
    /// Unique patch identifier (matches `Patch::id`)
    pub patch_id: String,
    /// Timestamp when the patch was applied (RFC 3339)
    pub applied_at: String,
    /// Path of the file that was patched
    pub file_path: PathBuf,
    /// Path where the original file was backed up
    pub backup_path: PathBuf,
}

// ── BackupManager ─────────────────────────────────────────────────────────────

/// Manages file backups before applying patches.
///
/// Backups are stored under `<project_root>/.sicario/backups/<timestamp>/`.
/// A JSON patch history log is maintained at
/// `<project_root>/.sicario/patch_history.json`.
pub struct BackupManager {
    /// Root backup directory: `<project_root>/.sicario/backups/`
    backup_dir: PathBuf,
    /// Path to the patch history log file
    history_path: PathBuf,
}

impl BackupManager {
    /// Create a new `BackupManager` rooted at `project_root`.
    ///
    /// Creates the `.sicario/backups/` directory if it does not exist.
    pub fn new(project_root: &Path) -> Result<Self> {
        let sicario_dir = project_root.join(".sicario");
        let backup_dir = sicario_dir.join("backups");
        fs::create_dir_all(&backup_dir)
            .with_context(|| format!("Failed to create backup directory: {}", backup_dir.display()))?;

        let history_path = sicario_dir.join("patch_history.json");

        Ok(Self {
            backup_dir,
            history_path,
        })
    }

    /// Create a timestamped backup of `file_path`.
    ///
    /// The backup is placed at
    /// `.sicario/backups/<YYYYMMDD_HHMMSS_nanoseconds>/<filename>`.
    /// Returns the path of the created backup file.
    pub fn backup_file(&self, file_path: &Path) -> Result<PathBuf> {
        // Use nanoseconds to avoid collisions when multiple files are backed up
        // in the same second.
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let subdir_name = format!("{}_{}", timestamp, nanos);
        let backup_subdir = self.backup_dir.join(&subdir_name);
        fs::create_dir_all(&backup_subdir)
            .with_context(|| format!("Failed to create backup subdir: {}", backup_subdir.display()))?;

        // Preserve the relative path structure inside the backup directory so
        // that multiple files from the same patch can coexist.
        let file_name = file_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid file path: {}", file_path.display()))?;
        let backup_path = backup_subdir.join(file_name);

        fs::copy(file_path, &backup_path)
            .with_context(|| {
                format!(
                    "Failed to copy {} to {}",
                    file_path.display(),
                    backup_path.display()
                )
            })?;

        Ok(backup_path)
    }

    /// Restore `original_path` from `backup_path`.
    pub fn restore_file(&self, backup_path: &Path, original_path: &Path) -> Result<()> {
        fs::copy(backup_path, original_path).with_context(|| {
            format!(
                "Failed to restore {} from {}",
                original_path.display(),
                backup_path.display()
            )
        })?;
        Ok(())
    }

    /// Append an entry to the patch history log.
    ///
    /// The log is a JSON array stored at `.sicario/patch_history.json`.
    /// If the file does not exist it is created.
    pub fn record_patch(&self, entry: PatchHistoryEntry) -> Result<()> {
        let mut entries = self.load_history()?;
        entries.push(entry);
        let json = serde_json::to_string_pretty(&entries)
            .context("Failed to serialize patch history")?;
        fs::write(&self.history_path, json)
            .with_context(|| format!("Failed to write patch history: {}", self.history_path.display()))?;
        Ok(())
    }

    /// Return the root backup directory path.
    pub fn backup_dir(&self) -> &Path {
        &self.backup_dir
    }

    /// Load all patch history entries from disk.
    ///
    /// Returns an empty `Vec` if the history file does not exist yet.
    pub fn load_history(&self) -> Result<Vec<PatchHistoryEntry>> {        if !self.history_path.exists() {
            return Ok(Vec::new());
        }
        let json = fs::read_to_string(&self.history_path)
            .with_context(|| format!("Failed to read patch history: {}", self.history_path.display()))?;
        serde_json::from_str(&json).context("Failed to parse patch history JSON")
    }

    /// Remove backup directories older than `days` days.
    ///
    /// Only removes entries inside the `.sicario/backups/` directory.
    pub fn cleanup_old_backups(&self, days: u64) -> Result<()> {
        let cutoff = Utc::now() - chrono::Duration::days(days as i64);

        if !self.backup_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&self.backup_dir)
            .with_context(|| format!("Failed to read backup dir: {}", self.backup_dir.display()))?
        {
            let entry = entry?;
            let metadata = entry.metadata()?;

            if let Ok(modified) = metadata.modified() {
                let modified_time: chrono::DateTime<Utc> = modified.into();
                if modified_time < cutoff {
                    let path = entry.path();
                    if path.is_dir() {
                        fs::remove_dir_all(&path).with_context(|| {
                            format!("Failed to remove old backup dir: {}", path.display())
                        })?;
                    } else {
                        fs::remove_file(&path).with_context(|| {
                            format!("Failed to remove old backup file: {}", path.display())
                        })?;
                    }
                }
            }
        }

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, BackupManager) {
        let dir = TempDir::new().unwrap();
        let mgr = BackupManager::new(dir.path()).unwrap();
        (dir, mgr)
    }

    #[test]
    fn test_backup_creates_copy() {
        let (dir, mgr) = setup();
        let original = dir.path().join("secret.rs");
        fs::write(&original, "let key = \"abc\";").unwrap();

        let backup_path = mgr.backup_file(&original).unwrap();
        assert!(backup_path.exists());
        assert_eq!(
            fs::read_to_string(&backup_path).unwrap(),
            "let key = \"abc\";"
        );
    }

    #[test]
    fn test_backup_does_not_modify_original() {
        let (dir, mgr) = setup();
        let original = dir.path().join("file.rs");
        fs::write(&original, "original content").unwrap();

        mgr.backup_file(&original).unwrap();

        assert_eq!(fs::read_to_string(&original).unwrap(), "original content");
    }

    #[test]
    fn test_restore_file() {
        let (dir, mgr) = setup();
        let original = dir.path().join("file.rs");
        fs::write(&original, "original").unwrap();

        let backup = mgr.backup_file(&original).unwrap();

        // Overwrite original
        fs::write(&original, "modified").unwrap();
        assert_eq!(fs::read_to_string(&original).unwrap(), "modified");

        // Restore
        mgr.restore_file(&backup, &original).unwrap();
        assert_eq!(fs::read_to_string(&original).unwrap(), "original");
    }

    #[test]
    fn test_record_and_load_history() {
        let (dir, mgr) = setup();
        let entry = PatchHistoryEntry {
            patch_id: "patch-1".to_string(),
            applied_at: Utc::now().to_rfc3339(),
            file_path: PathBuf::from("src/main.rs"),
            backup_path: PathBuf::from(".sicario/backups/20240101_000000/main.rs"),
        };

        mgr.record_patch(entry.clone()).unwrap();
        let history = mgr.load_history().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].patch_id, "patch-1");
    }

    #[test]
    fn test_load_history_empty_when_no_file() {
        let (dir, mgr) = setup();
        let history = mgr.load_history().unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn test_multiple_backups_do_not_collide() {
        let (dir, mgr) = setup();
        let original = dir.path().join("file.rs");
        fs::write(&original, "v1").unwrap();
        let b1 = mgr.backup_file(&original).unwrap();

        fs::write(&original, "v2").unwrap();
        let b2 = mgr.backup_file(&original).unwrap();

        assert_ne!(b1, b2);
        assert!(b1.exists());
        assert!(b2.exists());
    }

    #[test]
    fn test_cleanup_old_backups_removes_nothing_recent() {
        let (dir, mgr) = setup();
        let original = dir.path().join("file.rs");
        fs::write(&original, "content").unwrap();
        mgr.backup_file(&original).unwrap();

        // Cleanup with 30-day threshold — recent backup should survive
        mgr.cleanup_old_backups(30).unwrap();

        let entries: Vec<_> = fs::read_dir(&mgr.backup_dir)
            .unwrap()
            .collect();
        assert!(!entries.is_empty(), "Recent backup should not be removed");
    }
}
