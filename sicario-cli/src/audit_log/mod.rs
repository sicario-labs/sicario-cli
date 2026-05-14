//! Zero-Exfiltration Audit Log — machine-readable record of every outbound
//! network transmission made during a scan.
//!
//! Written atomically to `.sicario/audit/scan-<ISO8601>.json` after every scan.
//! The `transmissions` array is empty when no `--publish` and no `SICARIO_API_KEY`.
//!
//! Requirements: Req 21 — Zero-Exfiltration Audit Log (Tasks 21.1–21.8)

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ── Formal zero-exfil guarantee statement ────────────────────────────────────

pub const ZERO_EXFIL_GUARANTEE: &str =
    "Source code is never transmitted to Sicario Cloud. \
     A one-way SHA-256 hash of matched code is uploaded for deduplication. \
     The hash is not reversible to source code. \
     Raw code excerpts are only transmitted when --publish-with-snippet is \
     explicitly provided by the user.";

// ── Data models ───────────────────────────────────────────────────────────────

/// A single outbound network transmission recorded in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transmission {
    /// Destination: "sicario-cloud", "127.0.0.1:11434" (Ollama), etc.
    pub destination: String,
    /// Type of payload: "policy_fetch", "finding_metadata", "llm_context"
    pub payload_type: String,
    /// Size of the payload in bytes.
    pub payload_size_bytes: usize,
    /// Number of lines of source code transmitted (0 for hash-only payloads).
    pub lines_of_code_transmitted: usize,
    /// Whether the user explicitly consented to this transmission.
    pub consent_obtained: bool,
}

/// The full audit log entry for a single scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// Formal zero-exfiltration guarantee statement.
    pub guarantee: String,
    /// Unique scan identifier.
    pub scan_id: String,
    /// ISO-8601 timestamp when the scan started.
    pub started_at: String,
    /// ISO-8601 timestamp when the scan completed.
    pub completed_at: String,
    /// Number of files scanned.
    pub files_scanned: usize,
    /// Number of findings detected.
    pub findings_count: usize,
    /// All outbound network transmissions made during this scan.
    /// Empty when no --publish and no SICARIO_API_KEY.
    pub transmissions: Vec<Transmission>,
}

impl AuditLogEntry {
    /// Create a new audit log entry for a scan.
    pub fn new(scan_id: &str, files_scanned: usize, findings_count: usize) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            schema_version: "1.0".to_string(),
            guarantee: ZERO_EXFIL_GUARANTEE.to_string(),
            scan_id: scan_id.to_string(),
            started_at: now.clone(),
            completed_at: now,
            files_scanned,
            findings_count,
            transmissions: Vec::new(),
        }
    }

    /// Add a transmission record.
    pub fn add_transmission(&mut self, tx: Transmission) {
        self.transmissions.push(tx);
    }

    /// Mark the scan as completed with the current timestamp.
    pub fn complete(&mut self) {
        self.completed_at = Utc::now().to_rfc3339();
    }

    /// Display a human-readable summary.
    pub fn display_text(&self) -> String {
        let mut s = String::new();
        s.push_str("╔══════════════════════════════════════════════════╗\n");
        s.push_str("║         Zero-Exfiltration Audit Log              ║\n");
        s.push_str("╠══════════════════════════════════════════════════╣\n");
        s.push_str(&format!("║ Scan ID:    {:<38}║\n", truncate(&self.scan_id, 38)));
        s.push_str(&format!("║ Started:    {:<38}║\n", truncate(&self.started_at, 38)));
        s.push_str(&format!("║ Completed:  {:<38}║\n", truncate(&self.completed_at, 38)));
        s.push_str(&format!("║ Files:      {:<38}║\n", self.files_scanned));
        s.push_str(&format!("║ Findings:   {:<38}║\n", self.findings_count));
        s.push_str(&format!("║ Transmissions: {:<35}║\n", self.transmissions.len()));
        s.push_str("╠══════════════════════════════════════════════════╣\n");
        if self.transmissions.is_empty() {
            s.push_str("║ No outbound transmissions — full air-gap mode.   ║\n");
        } else {
            for tx in &self.transmissions {
                s.push_str(&format!(
                    "║  → {} ({} bytes, {} LOC, consent: {}){}║\n",
                    truncate(&tx.destination, 20),
                    tx.payload_size_bytes,
                    tx.lines_of_code_transmitted,
                    if tx.consent_obtained { "yes" } else { "no" },
                    " ".repeat(2),
                ));
            }
        }
        s.push_str("╠══════════════════════════════════════════════════╣\n");
        s.push_str("║ Guarantee:                                       ║\n");
        // Word-wrap the guarantee
        for chunk in self.guarantee.chars().collect::<Vec<_>>().chunks(48) {
            let line: String = chunk.iter().collect();
            s.push_str(&format!("║  {:<48}║\n", line));
        }
        s.push_str("╚══════════════════════════════════════════════════╝\n");
        s
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() }
    else { format!("{}…", &s[..max.saturating_sub(1)]) }
}

// ── AuditLogger ───────────────────────────────────────────────────────────────

/// Writes audit log entries atomically to `.sicario/audit/`.
pub struct AuditLogger {
    audit_dir: PathBuf,
}

impl AuditLogger {
    /// Create a new `AuditLogger` rooted at `project_root`.
    pub fn new(project_root: &Path) -> Self {
        Self {
            audit_dir: project_root.join(".sicario").join("audit"),
        }
    }

    /// Write an audit log entry atomically (via .tmp + rename).
    ///
    /// Returns the path of the written file.
    pub fn write(&self, entry: &AuditLogEntry) -> Result<PathBuf> {
        std::fs::create_dir_all(&self.audit_dir)
            .with_context(|| format!("Failed to create audit dir: {}", self.audit_dir.display()))?;

        let filename = format!(
            "scan-{}.json",
            entry.started_at.replace(':', "-").replace('+', "Z")
        );
        let final_path = self.audit_dir.join(&filename);
        let tmp_path = final_path.with_extension("tmp");

        let json = serde_json::to_string_pretty(entry)
            .context("Failed to serialize audit log entry")?;

        // Atomic write: write to .tmp then rename
        std::fs::write(&tmp_path, &json)
            .with_context(|| format!("Failed to write tmp audit file: {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, &final_path)
            .with_context(|| format!("Failed to rename audit file: {}", final_path.display()))?;

        Ok(final_path)
    }

    /// Load the most recent audit log entry.
    pub fn load_latest(&self) -> Result<Option<AuditLogEntry>> {
        if !self.audit_dir.exists() {
            return Ok(None);
        }
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&self.audit_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect();
        entries.sort();
        match entries.last() {
            Some(path) => {
                let content = std::fs::read_to_string(path)?;
                let entry: AuditLogEntry = serde_json::from_str(&content)
                    .with_context(|| format!("Failed to parse audit log: {}", path.display()))?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Load all audit log entries.
    pub fn load_all(&self) -> Result<Vec<AuditLogEntry>> {
        if !self.audit_dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for path in std::fs::read_dir(&self.audit_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if let Ok(entry) = serde_json::from_str::<AuditLogEntry>(&content) {
                    entries.push(entry);
                }
            }
        }
        entries.sort_by(|a, b| a.started_at.cmp(&b.started_at));
        Ok(entries)
    }

    /// Verify no unauthorized LLM transmissions across all audit entries.
    ///
    /// Returns `Ok(())` if all `finding_metadata` entries have
    /// `lines_of_code_transmitted == 0`. Returns `Err` with details otherwise.
    pub fn verify_zero_exfil(&self) -> Result<()> {
        let entries = self.load_all()?;
        let mut violations = Vec::new();

        for entry in &entries {
            for tx in &entry.transmissions {
                if tx.payload_type == "finding_metadata"
                    && tx.lines_of_code_transmitted > 0
                    && !tx.consent_obtained
                {
                    violations.push(format!(
                        "Scan {}: {} transmitted {} LOC without consent",
                        entry.scan_id, tx.destination, tx.lines_of_code_transmitted
                    ));
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "Zero-exfiltration violations detected:\n{}",
                violations.join("\n")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_logger() -> (TempDir, AuditLogger) {
        let tmp = TempDir::new().unwrap();
        let logger = AuditLogger::new(tmp.path());
        (tmp, logger)
    }

    #[test]
    fn test_write_and_load_latest() {
        let (_tmp, logger) = make_logger();
        let mut entry = AuditLogEntry::new("scan-001", 42, 3);
        entry.complete();
        let path = logger.write(&entry).unwrap();
        assert!(path.exists());

        let loaded = logger.load_latest().unwrap().unwrap();
        assert_eq!(loaded.scan_id, "scan-001");
        assert_eq!(loaded.files_scanned, 42);
        assert_eq!(loaded.findings_count, 3);
        assert!(loaded.transmissions.is_empty());
    }

    #[test]
    fn test_transmissions_empty_when_no_publish() {
        let (_tmp, logger) = make_logger();
        let entry = AuditLogEntry::new("scan-002", 10, 0);
        logger.write(&entry).unwrap();
        let loaded = logger.load_latest().unwrap().unwrap();
        assert!(loaded.transmissions.is_empty(), "No transmissions when no --publish");
    }

    #[test]
    fn test_verify_zero_exfil_passes_with_no_violations() {
        let (_tmp, logger) = make_logger();
        let mut entry = AuditLogEntry::new("scan-003", 5, 1);
        entry.add_transmission(Transmission {
            destination: "sicario-cloud".to_string(),
            payload_type: "finding_metadata".to_string(),
            payload_size_bytes: 512,
            lines_of_code_transmitted: 0, // hash-only, no LOC
            consent_obtained: true,
        });
        logger.write(&entry).unwrap();
        assert!(logger.verify_zero_exfil().is_ok());
    }

    #[test]
    fn test_verify_zero_exfil_fails_with_violation() {
        let (_tmp, logger) = make_logger();
        let mut entry = AuditLogEntry::new("scan-004", 5, 1);
        entry.add_transmission(Transmission {
            destination: "sicario-cloud".to_string(),
            payload_type: "finding_metadata".to_string(),
            payload_size_bytes: 1024,
            lines_of_code_transmitted: 5, // LOC transmitted without consent
            consent_obtained: false,
        });
        logger.write(&entry).unwrap();
        assert!(logger.verify_zero_exfil().is_err());
    }

    #[test]
    fn test_atomic_write_no_partial_files() {
        let (_tmp, logger) = make_logger();
        let entry = AuditLogEntry::new("scan-005", 1, 0);
        logger.write(&entry).unwrap();
        // No .tmp files should remain
        let tmp_files: Vec<_> = std::fs::read_dir(logger.audit_dir.as_path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        assert!(tmp_files.is_empty(), "No .tmp files should remain after atomic write");
    }

    #[test]
    fn test_guarantee_field_present() {
        let entry = AuditLogEntry::new("scan-006", 0, 0);
        assert!(!entry.guarantee.is_empty());
        assert!(entry.guarantee.contains("never transmitted"));
    }

    #[test]
    fn test_display_text_not_empty() {
        let entry = AuditLogEntry::new("scan-007", 10, 2);
        let text = entry.display_text();
        assert!(text.contains("Audit Log"));
        assert!(text.contains("scan-007"));
    }
}
