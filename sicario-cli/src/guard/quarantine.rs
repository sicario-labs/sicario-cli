//! Quarantine mechanism for suspicious packages.
//!
//! Manages the quarantine of packages that exhibit behavioral anomalies.
//! Records are stored in `.sicario/quarantine.json` in an append-only fashion.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::BehavioralAnomaly;

/// The action taken when a package is quarantined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineAction {
    /// The package directory was renamed to `<name>.sicario-quarantined`
    Renamed,
    /// The package was flagged but not renamed (auto-quarantine was disabled)
    Flagged,
}

/// A record of a quarantined package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// ISO 8601 timestamp of when the package was quarantined
    pub quarantined_at: String,
    pub package_name: String,
    pub version: String,
    pub ecosystem: String,
    pub anomalies: Vec<BehavioralAnomaly>,
    pub action: QuarantineAction,
}

/// Manages the quarantine of suspicious packages.
pub struct QuarantineManager;

impl QuarantineManager {
    /// Quarantine a package directory.
    ///
    /// If `auto_quarantine` is `true`, the package directory is renamed to
    /// `{package_dir}.sicario-quarantined`. In both cases, a `QuarantineRecord`
    /// is appended to `.sicario/quarantine.json`.
    pub fn quarantine(
        package_dir: &Path,
        anomalies: &[BehavioralAnomaly],
        auto_quarantine: bool,
    ) -> Result<QuarantineRecord> {
        // Read package metadata
        let (name, version) = read_package_metadata(package_dir);

        let action = if auto_quarantine {
            // Rename the directory
            let quarantined_path = PathBuf::from(format!(
                "{}.sicario-quarantined",
                package_dir.to_string_lossy()
            ));
            std::fs::rename(package_dir, &quarantined_path).with_context(|| {
                format!(
                    "Failed to rename package directory {:?} to {:?}",
                    package_dir, quarantined_path
                )
            })?;
            QuarantineAction::Renamed
        } else {
            QuarantineAction::Flagged
        };

        let record = QuarantineRecord {
            quarantined_at: chrono::Utc::now().to_rfc3339(),
            package_name: name,
            version,
            ecosystem: "npm".to_string(),
            anomalies: anomalies.to_vec(),
            action,
        };

        // Find the project root by walking up from package_dir
        // The quarantine.json is stored in <project_root>/.sicario/quarantine.json
        // We look for the .sicario directory walking up from package_dir
        let project_root = find_project_root(package_dir);
        append_quarantine_record(&project_root, &record)?;

        Ok(record)
    }

    /// List all quarantined packages from `.sicario/quarantine.json`.
    pub fn list(project_root: &Path) -> Result<Vec<QuarantineRecord>> {
        let quarantine_path = project_root.join(".sicario").join("quarantine.json");
        if !quarantine_path.exists() {
            return Ok(vec![]);
        }

        let content = std::fs::read_to_string(&quarantine_path)
            .with_context(|| format!("Failed to read {:?}", quarantine_path))?;

        // The file is a JSON array of records
        let records: Vec<QuarantineRecord> = serde_json::from_str(&content).with_context(|| {
            format!(
                "Failed to parse quarantine records from {:?}",
                quarantine_path
            )
        })?;

        Ok(records)
    }
}

/// Read `name` and `version` from `package.json` in the given directory.
fn read_package_metadata(package_dir: &Path) -> (String, String) {
    // If the directory was already renamed, try the quarantined path too
    let pkg_path = package_dir.join("package.json");
    let quarantined_path = PathBuf::from(format!(
        "{}.sicario-quarantined",
        package_dir.to_string_lossy()
    ))
    .join("package.json");

    let content = std::fs::read_to_string(&pkg_path)
        .or_else(|_| std::fs::read_to_string(&quarantined_path))
        .unwrap_or_default();

    if content.is_empty() {
        // Fall back to directory name
        let dir_name = package_dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        return (dir_name, "unknown".to_string());
    }

    let json: serde_json::Value = serde_json::from_str(&content).unwrap_or_default();
    let name = json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    (name, version)
}

/// Find the project root by walking up from `start` looking for a `.sicario` dir
/// or a `node_modules` parent. Falls back to the parent of `node_modules`.
fn find_project_root(start: &Path) -> PathBuf {
    let mut current = start.to_path_buf();
    loop {
        // If we find a .sicario directory, this is the project root
        if current.join(".sicario").is_dir() {
            return current;
        }
        // If we find node_modules as a sibling, the parent is the project root
        if current.file_name().and_then(|n| n.to_str()) == Some("node_modules") {
            if let Some(parent) = current.parent() {
                return parent.to_path_buf();
            }
        }
        match current.parent() {
            Some(p) => current = p.to_path_buf(),
            None => return start.to_path_buf(),
        }
    }
}

/// Append a `QuarantineRecord` to `.sicario/quarantine.json`.
///
/// The file is a JSON array. If it doesn't exist, it is created with a
/// single-element array. If it exists, the record is appended to the array.
/// This is append-only — existing records are never overwritten.
fn append_quarantine_record(project_root: &Path, record: &QuarantineRecord) -> Result<()> {
    let sicario_dir = project_root.join(".sicario");
    std::fs::create_dir_all(&sicario_dir)
        .with_context(|| format!("Failed to create .sicario directory at {:?}", sicario_dir))?;

    let quarantine_path = sicario_dir.join("quarantine.json");

    let mut records: Vec<QuarantineRecord> = if quarantine_path.exists() {
        let content = std::fs::read_to_string(&quarantine_path)
            .with_context(|| format!("Failed to read {:?}", quarantine_path))?;
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        vec![]
    };

    records.push(record.clone());

    let json =
        serde_json::to_string_pretty(&records).context("Failed to serialize quarantine records")?;
    std::fs::write(&quarantine_path, json)
        .with_context(|| format!("Failed to write {:?}", quarantine_path))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::vulnerability::Severity;
    use crate::guard::{AnomalySignal, BehavioralAnomaly};
    use std::io::Write;
    use tempfile::TempDir;

    fn make_anomaly() -> BehavioralAnomaly {
        BehavioralAnomaly {
            signal: AnomalySignal::UnexpectedChildProcess,
            severity: Severity::Critical,
            file: PathBuf::from("index.js"),
            line: 1,
            snippet: "require('child_process')".to_string(),
            description: "test".to_string(),
        }
    }

    fn create_package_dir(parent: &TempDir, name: &str) -> PathBuf {
        let pkg_dir = parent.path().join("node_modules").join(name);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        let pkg_json = format!(r#"{{"name":"{}","version":"1.0.0"}}"#, name);
        let mut f = std::fs::File::create(pkg_dir.join("package.json")).unwrap();
        f.write_all(pkg_json.as_bytes()).unwrap();
        pkg_dir
    }

    #[test]
    fn test_quarantine_auto_renames_directory() {
        let root = TempDir::new().unwrap();
        let pkg_dir = create_package_dir(&root, "evil-pkg");

        let anomalies = vec![make_anomaly()];
        let record = QuarantineManager::quarantine(&pkg_dir, &anomalies, true).unwrap();

        assert_eq!(record.action, QuarantineAction::Renamed);
        assert!(!pkg_dir.exists(), "Original directory should be renamed");
        let quarantined = PathBuf::from(format!("{}.sicario-quarantined", pkg_dir.display()));
        assert!(quarantined.exists(), "Quarantined directory should exist");
    }

    #[test]
    fn test_quarantine_flagged_does_not_rename() {
        let root = TempDir::new().unwrap();
        let pkg_dir = create_package_dir(&root, "suspicious-pkg");

        let anomalies = vec![make_anomaly()];
        let record = QuarantineManager::quarantine(&pkg_dir, &anomalies, false).unwrap();

        assert_eq!(record.action, QuarantineAction::Flagged);
        assert!(
            pkg_dir.exists(),
            "Directory should NOT be renamed when auto_quarantine=false"
        );
    }

    #[test]
    fn test_quarantine_record_written() {
        let root = TempDir::new().unwrap();
        let pkg_dir = create_package_dir(&root, "test-pkg");

        let anomalies = vec![make_anomaly()];
        QuarantineManager::quarantine(&pkg_dir, &anomalies, false).unwrap();

        let records = QuarantineManager::list(root.path()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].package_name, "test-pkg");
    }

    #[test]
    fn test_list_returns_all_records() {
        let root = TempDir::new().unwrap();
        let pkg1 = create_package_dir(&root, "pkg-one");
        let pkg2 = create_package_dir(&root, "pkg-two");

        let anomalies = vec![make_anomaly()];
        QuarantineManager::quarantine(&pkg1, &anomalies, false).unwrap();
        QuarantineManager::quarantine(&pkg2, &anomalies, false).unwrap();

        let records = QuarantineManager::list(root.path()).unwrap();
        assert_eq!(records.len(), 2, "Expected 2 records");
    }

    #[test]
    fn test_append_only_two_calls_produce_two_records() {
        let root = TempDir::new().unwrap();
        let pkg1 = create_package_dir(&root, "pkg-a");
        let pkg2 = create_package_dir(&root, "pkg-b");

        let anomalies = vec![make_anomaly()];
        QuarantineManager::quarantine(&pkg1, &anomalies, false).unwrap();
        QuarantineManager::quarantine(&pkg2, &anomalies, false).unwrap();

        let records = QuarantineManager::list(root.path()).unwrap();
        assert_eq!(
            records.len(),
            2,
            "Append-only: should have 2 records, not 1"
        );
    }

    #[test]
    fn test_list_empty_when_no_quarantine_file() {
        let root = TempDir::new().unwrap();
        let records = QuarantineManager::list(root.path()).unwrap();
        assert!(records.is_empty());
    }
}
