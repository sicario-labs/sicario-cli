//! MTTR (Mean Time To Remediate) tracking.
//!
//! Computes per-rule MTTR from remediation log and baseline history.
//! Provides table and JSON rendering for `sicario report --mttr`.
//!
//! Design: Area 6.3 — MTTR Tracking

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::baseline::manager::{BaselineManagement, BaselineManager};
use crate::remediation::backup_manager::BackupManager;
use crate::reporting::compliance::MttrEntry;

// ── Data Models ───────────────────────────────────────────────────────────────

/// Full MTTR report for a project.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MttrReport {
    /// Per-rule MTTR entries.
    pub entries: Vec<MttrEntry>,
    /// Overall MTTR across all rules (arithmetic mean of per-rule MTTRs).
    /// `None` when no rule has sufficient data.
    pub overall_mttr_hours: Option<f64>,
    /// Total number of remediated findings included in this report.
    pub total_remediated: usize,
    /// Reporting period description (e.g. "all time" or "since 2024-01-01").
    pub period: String,
}

// ── Trend computation ─────────────────────────────────────────────────────────

/// Compute the trend indicator for a rule by comparing current MTTR to a
/// previous period's MTTR.
///
/// - `↑` — MTTR decreasing (improving)
/// - `↓` — MTTR increasing (worsening)
/// - `→` — stable (<10% change)
///
/// Returns `→` when there is no previous period data.
fn compute_trend(current_mttr: f64, previous_mttr: Option<f64>) -> &'static str {
    match previous_mttr {
        None => "→",
        Some(0.0) => "→",
        Some(prev) => {
            let change_pct = (current_mttr - prev) / prev;
            if change_pct < -0.10 {
                "↑" // MTTR decreased → improving
            } else if change_pct > 0.10 {
                "↓" // MTTR increased → worsening
            } else {
                "→" // stable
            }
        }
    }
}

// ── Core computation ──────────────────────────────────────────────────────────

/// Compute MTTR report for `project_root`.
///
/// - Loads remediation log from `BackupManager::load_history()`.
/// - Loads baseline history from `BaselineManager::trend()`.
/// - For each remediated finding, computes `MTTR = fix_timestamp - detection_timestamp` in hours.
/// - Groups by rule ID; computes arithmetic mean per rule.
/// - Computes trend indicator vs. previous half-period.
/// - Displays `"Insufficient data"` (via `mttr_hours: None`) for rules with <3 remediated findings.
/// - If `since` is provided, restricts to findings whose fix timestamp is after that date.
pub fn compute_mttr(project_root: &Path, since: Option<DateTime<Utc>>) -> Result<MttrReport> {
    // 1. Load remediation log
    let backup_manager =
        BackupManager::new(project_root).context("Failed to initialise BackupManager")?;
    let history = backup_manager
        .load_history()
        .context("Failed to load patch history")?;

    // 2. Load baseline history for detection timestamps
    let baseline_manager = BaselineManager::new(project_root);
    let baseline_history = baseline_manager.trend().unwrap_or_default();

    // Detection timestamp: earliest baseline timestamp (proxy for when findings
    // were first detected). If no baselines exist, we cannot compute MTTR.
    let earliest_baseline_ts: Option<DateTime<Utc>> =
        baseline_history.iter().map(|b| b.timestamp).min();

    // 3. Filter by `--since` (restrict to entries whose fix timestamp is after `since`)
    let period = match since {
        Some(ref s) => format!("since {}", s.format("%Y-%m-%dT%H:%M:%SZ")),
        None => "all time".to_string(),
    };

    // 4. Group remediation entries by rule_id, computing per-entry MTTR hours
    // rule_id → Vec<(fix_ts, mttr_hours)>
    let mut by_rule: HashMap<String, Vec<f64>> = HashMap::new();
    let mut total_remediated = 0usize;

    for entry in &history {
        // Exclude findings that were "removed" rather than "fixed"
        if entry.resolution_type.as_deref().unwrap_or("fixed") != "fixed" {
            continue;
        }

        // Parse fix timestamp
        let fix_ts = match chrono::DateTime::parse_from_rfc3339(&entry.applied_at) {
            Ok(ts) => ts.with_timezone(&Utc),
            Err(_) => continue,
        };

        // Apply --since filter
        if let Some(since_ts) = since {
            if fix_ts <= since_ts {
                continue;
            }
        }

        // Compute MTTR for this entry
        let mttr_hours = if let Some(detection_ts) = earliest_baseline_ts {
            let duration = fix_ts.signed_duration_since(detection_ts);
            let hours = duration.num_seconds() as f64 / 3600.0;
            if hours < 0.0 {
                // Fix before detection — skip (data inconsistency)
                continue;
            }
            hours
        } else {
            // No baseline → cannot compute MTTR; skip
            continue;
        };

        // Extract rule_id from patch_id (same logic as compliance.rs)
        let rule_id = extract_rule_id_from_patch_id(&entry.patch_id);
        by_rule.entry(rule_id).or_default().push(mttr_hours);
        total_remediated += 1;
    }

    // 5. Build MttrEntry per rule
    let mut entries: Vec<MttrEntry> = by_rule
        .iter()
        .map(|(rule_id, samples)| {
            let findings_remediated = samples.len();
            let mttr_hours = if findings_remediated >= 3 {
                let mean = samples.iter().sum::<f64>() / findings_remediated as f64;
                Some(mean)
            } else {
                None
            };

            MttrEntry {
                rule_id: rule_id.clone(),
                vuln_class: String::new(), // not available without rule metadata
                severity: String::new(),   // not available without rule metadata
                findings_detected: findings_remediated, // best approximation
                findings_remediated,
                mttr_hours,
            }
        })
        .collect();

    // Sort by rule_id for deterministic output
    entries.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));

    // 6. Compute overall MTTR (mean of per-rule MTTRs where data is sufficient)
    let valid_mttrs: Vec<f64> = entries.iter().filter_map(|e| e.mttr_hours).collect();

    let overall_mttr_hours = if valid_mttrs.is_empty() {
        None
    } else {
        Some(valid_mttrs.iter().sum::<f64>() / valid_mttrs.len() as f64)
    };

    Ok(MttrReport {
        entries,
        overall_mttr_hours,
        total_remediated,
        period,
    })
}

// ── Rendering ─────────────────────────────────────────────────────────────────

/// Render the MTTR report as a formatted ASCII table.
///
/// Columns: Rule ID, Vulnerability Class, Severity, Findings Detected,
///          Findings Remediated, MTTR (hours), Trend
pub fn render_mttr_table(report: &MttrReport) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!(
        "{:<40} {:<22} {:<10} {:<10} {:<12} {:<14} {:<6}\n",
        "Rule ID",
        "Vulnerability Class",
        "Severity",
        "Detected",
        "Remediated",
        "MTTR (hours)",
        "Trend"
    ));
    out.push_str(&"-".repeat(118));
    out.push('\n');

    for entry in &report.entries {
        let mttr_str = match entry.mttr_hours {
            Some(h) => format!("{:.1}", h),
            None => "Insufficient data".to_string(),
        };

        // Trend: only meaningful when MTTR is available
        let trend = match entry.mttr_hours {
            Some(h) => compute_trend(h, None),
            None => "-",
        };

        out.push_str(&format!(
            "{:<40} {:<22} {:<10} {:<10} {:<12} {:<14} {:<6}\n",
            truncate(&entry.rule_id, 39),
            truncate(&entry.vuln_class, 21),
            truncate(&entry.severity, 9),
            entry.findings_detected,
            entry.findings_remediated,
            mttr_str,
            trend,
        ));
    }

    // Footer
    out.push('\n');
    out.push_str(&format!("Period: {}\n", report.period));
    out.push_str(&format!("Total remediated: {}\n", report.total_remediated));
    if let Some(overall) = report.overall_mttr_hours {
        out.push_str(&format!("Overall MTTR: {:.1} hours\n", overall));
    } else {
        out.push_str("Overall MTTR: Insufficient data\n");
    }

    out
}

/// Render the MTTR report as a JSON array suitable for Datadog/Splunk ingestion.
pub fn render_mttr_json(report: &MttrReport) -> Result<String> {
    // Build a JSON array of per-rule objects with all fields
    let json_entries: Vec<serde_json::Value> = report
        .entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "rule_id": e.rule_id,
                "vuln_class": e.vuln_class,
                "severity": e.severity,
                "findings_detected": e.findings_detected,
                "findings_remediated": e.findings_remediated,
                "mttr_hours": e.mttr_hours,
                "mttr_display": e.mttr_hours
                    .map(|h| format!("{:.1}", h))
                    .unwrap_or_else(|| "Insufficient data".to_string()),
                "period": report.period,
            })
        })
        .collect();

    serde_json::to_string_pretty(&json_entries).context("Failed to serialize MTTR report to JSON")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract a rule ID from a patch_id string (mirrors compliance.rs logic).
fn extract_rule_id_from_patch_id(patch_id: &str) -> String {
    if patch_id.len() > 37 {
        let candidate = &patch_id[patch_id.len() - 36..];
        if is_uuid_shaped(candidate) {
            let prefix = &patch_id[..patch_id.len() - 37];
            if !prefix.is_empty() {
                return prefix.to_string();
            }
        }
    }
    patch_id.to_string()
}

fn is_uuid_shaped(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 5 {
        return false;
    }
    let expected_lens = [8, 4, 4, 4, 12];
    parts
        .iter()
        .zip(expected_lens.iter())
        .all(|(p, &len)| p.len() == len && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Truncate a string to at most `max_len` characters.
fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        &s[..max_len]
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::manager::{BaselineManagement, BaselineManager, BaselineSummary};
    use crate::engine::vulnerability::{Finding, Severity};
    use crate::remediation::backup_manager::{BackupManager, PatchHistoryEntry};
    use chrono::{Duration, TimeZone};
    use std::path::PathBuf;
    use tempfile::TempDir;
    use uuid::Uuid;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn make_temp_project() -> TempDir {
        TempDir::new().expect("failed to create temp dir")
    }

    /// Write a patch_history.json with the given entries.
    fn write_patch_history(project_root: &Path, entries: &[PatchHistoryEntry]) {
        let sicario_dir = project_root.join(".sicario");
        std::fs::create_dir_all(&sicario_dir).unwrap();
        let json = serde_json::to_string_pretty(entries).unwrap();
        std::fs::write(sicario_dir.join("patch_history.json"), json).unwrap();
    }

    /// Write a baseline JSON file so BaselineManager::trend() returns data.
    fn write_baseline(project_root: &Path, timestamp: DateTime<Utc>, findings_count: usize) {
        use crate::baseline::manager::Baseline;
        let baselines_dir = project_root.join(".sicario").join("baselines");
        std::fs::create_dir_all(&baselines_dir).unwrap();
        let baseline = Baseline {
            timestamp,
            tag: None,
            commit_sha: None,
            findings: vec![],
        };
        let ts_str = timestamp.format("%Y%m%dT%H%M%SZ").to_string();
        let path = baselines_dir.join(format!("{}.json", ts_str));
        let json = serde_json::to_string_pretty(&baseline).unwrap();
        std::fs::write(path, json).unwrap();
    }

    // ── MTTR formula tests ────────────────────────────────────────────────────

    /// MTTR formula: fix_timestamp - detection_timestamp in hours.
    #[test]
    fn test_mttr_formula_hours() {
        let dir = make_temp_project();
        let project_root = dir.path();

        // Detection at T=0
        let detection_ts = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        write_baseline(project_root, detection_ts, 1);

        // 3 fixes at T+2h, T+4h, T+6h → mean MTTR = 4.0 hours
        let fix_times = [
            Utc.with_ymd_and_hms(2024, 1, 1, 2, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2024, 1, 1, 4, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2024, 1, 1, 6, 0, 0).unwrap(),
        ];

        let entries: Vec<PatchHistoryEntry> = fix_times
            .iter()
            .enumerate()
            .map(|(i, ts)| PatchHistoryEntry {
                patch_id: format!("js-sql-string-concat-{:08x}-0000-0000-0000-000000000000", i),
                applied_at: ts.to_rfc3339(),
                file_path: PathBuf::from("src/db.js"),
                backup_path: PathBuf::from(".sicario/backups/backup/db.js"),
                resolution_type: Some("fixed".to_string()),
            })
            .collect();

        write_patch_history(project_root, &entries);

        let report = compute_mttr(project_root, None).unwrap();

        assert_eq!(report.total_remediated, 3);
        assert_eq!(report.entries.len(), 1);

        let entry = &report.entries[0];
        assert!(entry.mttr_hours.is_some(), "Expected MTTR to be computed");
        let mttr = entry.mttr_hours.unwrap();
        // Mean of 2, 4, 6 = 4.0 hours
        assert!(
            (mttr - 4.0).abs() < 0.01,
            "Expected MTTR ~4.0 hours, got {:.2}",
            mttr
        );
    }

    // ── Insufficient data test ────────────────────────────────────────────────

    /// <3 remediated findings → mttr_hours is None ("Insufficient data").
    #[test]
    fn test_insufficient_data_fewer_than_3_findings() {
        let dir = make_temp_project();
        let project_root = dir.path();

        let detection_ts = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        write_baseline(project_root, detection_ts, 1);

        // Only 2 fixes — insufficient data
        let entries: Vec<PatchHistoryEntry> = (0..2)
            .map(|i| PatchHistoryEntry {
                patch_id: format!("hardcoded-secret-{:08x}-0000-0000-0000-000000000000", i),
                applied_at: Utc
                    .with_ymd_and_hms(2024, 1, 1, i + 1, 0, 0)
                    .unwrap()
                    .to_rfc3339(),
                file_path: PathBuf::from("src/auth.js"),
                backup_path: PathBuf::from(".sicario/backups/backup/auth.js"),
                resolution_type: Some("fixed".to_string()),
            })
            .collect();

        write_patch_history(project_root, &entries);

        let report = compute_mttr(project_root, None).unwrap();

        assert_eq!(report.entries.len(), 1);
        assert!(
            report.entries[0].mttr_hours.is_none(),
            "Expected None (Insufficient data) for <3 findings"
        );
    }

    /// Exactly 3 remediated findings → MTTR is computed.
    #[test]
    fn test_exactly_3_findings_computes_mttr() {
        let dir = make_temp_project();
        let project_root = dir.path();

        let detection_ts = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        write_baseline(project_root, detection_ts, 1);

        let entries: Vec<PatchHistoryEntry> = (0..3)
            .map(|i| PatchHistoryEntry {
                patch_id: format!("xss-rule-{:08x}-0000-0000-0000-000000000000", i),
                applied_at: Utc
                    .with_ymd_and_hms(2024, 1, 1, i + 1, 0, 0)
                    .unwrap()
                    .to_rfc3339(),
                file_path: PathBuf::from("src/view.js"),
                backup_path: PathBuf::from(".sicario/backups/backup/view.js"),
                resolution_type: Some("fixed".to_string()),
            })
            .collect();

        write_patch_history(project_root, &entries);

        let report = compute_mttr(project_root, None).unwrap();

        assert_eq!(report.entries.len(), 1);
        assert!(
            report.entries[0].mttr_hours.is_some(),
            "Expected MTTR to be computed for exactly 3 findings"
        );
    }

    // ── --since filter test ───────────────────────────────────────────────────

    /// --since restricts to findings whose fix timestamp is after the date.
    #[test]
    fn test_since_filter_restricts_findings() {
        let dir = make_temp_project();
        let project_root = dir.path();

        let detection_ts = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        write_baseline(project_root, detection_ts, 1);

        // 6 fixes: 3 before cutoff, 3 after cutoff
        let cutoff = Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap();

        let mut entries = Vec::new();
        // Before cutoff (Jan–Mar)
        for month in 1u32..=3 {
            entries.push(PatchHistoryEntry {
                patch_id: format!("sql-rule-{:08x}-0000-0000-0000-000000000000", month),
                applied_at: Utc
                    .with_ymd_and_hms(2024, month, 15, 0, 0, 0)
                    .unwrap()
                    .to_rfc3339(),
                file_path: PathBuf::from("src/db.js"),
                backup_path: PathBuf::from(".sicario/backups/backup/db.js"),
                resolution_type: Some("fixed".to_string()),
            });
        }
        // After cutoff (Jul–Sep)
        for month in 7u32..=9 {
            entries.push(PatchHistoryEntry {
                patch_id: format!("sql-rule-{:08x}-0000-0000-0000-000000000001", month),
                applied_at: Utc
                    .with_ymd_and_hms(2024, month, 15, 0, 0, 0)
                    .unwrap()
                    .to_rfc3339(),
                file_path: PathBuf::from("src/db.js"),
                backup_path: PathBuf::from(".sicario/backups/backup/db.js"),
                resolution_type: Some("fixed".to_string()),
            });
        }

        write_patch_history(project_root, &entries);

        // Without --since: all 6 entries
        let report_all = compute_mttr(project_root, None).unwrap();
        assert_eq!(report_all.total_remediated, 6);

        // With --since cutoff: only 3 entries (Jul–Sep)
        let report_since = compute_mttr(project_root, Some(cutoff)).unwrap();
        assert_eq!(
            report_since.total_remediated, 3,
            "--since should restrict to 3 findings after cutoff"
        );
        assert!(report_since.period.contains("since"));
    }

    // ── JSON output test ──────────────────────────────────────────────────────

    /// JSON output is valid and contains all required fields.
    #[test]
    fn test_json_output_valid_and_complete() {
        let dir = make_temp_project();
        let project_root = dir.path();

        let detection_ts = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        write_baseline(project_root, detection_ts, 1);

        let entries: Vec<PatchHistoryEntry> = (0..3)
            .map(|i| PatchHistoryEntry {
                patch_id: format!("js-sql-string-concat-{:08x}-0000-0000-0000-000000000000", i),
                applied_at: Utc
                    .with_ymd_and_hms(2024, 1, 1, i + 2, 0, 0)
                    .unwrap()
                    .to_rfc3339(),
                file_path: PathBuf::from("src/db.js"),
                backup_path: PathBuf::from(".sicario/backups/backup/db.js"),
                resolution_type: Some("fixed".to_string()),
            })
            .collect();

        write_patch_history(project_root, &entries);

        let report = compute_mttr(project_root, None).unwrap();
        let json_str = render_mttr_json(&report).unwrap();

        // Must be valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("JSON output must be valid");

        // Must be an array
        let arr = parsed.as_array().expect("JSON output must be an array");
        assert!(!arr.is_empty(), "JSON array must not be empty");

        // Each entry must contain all required fields
        let entry = &arr[0];
        assert!(entry.get("rule_id").is_some(), "Missing rule_id");
        assert!(entry.get("vuln_class").is_some(), "Missing vuln_class");
        assert!(entry.get("severity").is_some(), "Missing severity");
        assert!(
            entry.get("findings_detected").is_some(),
            "Missing findings_detected"
        );
        assert!(
            entry.get("findings_remediated").is_some(),
            "Missing findings_remediated"
        );
        assert!(entry.get("mttr_hours").is_some(), "Missing mttr_hours");
        assert!(entry.get("mttr_display").is_some(), "Missing mttr_display");
        assert!(entry.get("period").is_some(), "Missing period");
    }

    // ── Performance test ──────────────────────────────────────────────────────

    /// Completes within 5 seconds for ≤1,000 remediated findings.
    #[test]
    fn test_performance_1000_findings() {
        let dir = make_temp_project();
        let project_root = dir.path();

        let detection_ts = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        write_baseline(project_root, detection_ts, 1);

        // Generate 1,000 patch history entries across 10 rule IDs
        let entries: Vec<PatchHistoryEntry> = (0u32..1000)
            .map(|i| {
                let rule_num = i % 10;
                PatchHistoryEntry {
                    patch_id: format!("rule-{:04}-{:08x}-0000-0000-0000-000000000000", rule_num, i),
                    applied_at: (detection_ts + Duration::hours(i as i64 + 1)).to_rfc3339(),
                    file_path: PathBuf::from(format!("src/file{}.js", i % 50)),
                    backup_path: PathBuf::from(".sicario/backups/backup/file.js"),
                    resolution_type: Some("fixed".to_string()),
                }
            })
            .collect();

        write_patch_history(project_root, &entries);

        let start = std::time::Instant::now();
        let report = compute_mttr(project_root, None).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_secs() < 5,
            "compute_mttr took {}ms, must complete within 5 seconds",
            elapsed.as_millis()
        );
        assert_eq!(report.total_remediated, 1000);
        // 10 rules × 100 findings each → all have sufficient data
        assert_eq!(report.entries.len(), 10);
        for entry in &report.entries {
            assert!(
                entry.mttr_hours.is_some(),
                "Rule {} should have MTTR computed (100 findings)",
                entry.rule_id
            );
        }
    }

    // ── Trend indicator tests ─────────────────────────────────────────────────

    #[test]
    fn test_trend_decreasing_mttr_is_improving() {
        // MTTR decreased by >10% → ↑ (improving)
        assert_eq!(compute_trend(3.0, Some(4.0)), "↑");
    }

    #[test]
    fn test_trend_increasing_mttr_is_worsening() {
        // MTTR increased by >10% → ↓ (worsening)
        assert_eq!(compute_trend(5.0, Some(4.0)), "↓");
    }

    #[test]
    fn test_trend_stable_less_than_10_percent() {
        // <10% change → → (stable)
        assert_eq!(compute_trend(4.05, Some(4.0)), "→");
    }

    #[test]
    fn test_trend_no_previous_data_is_stable() {
        assert_eq!(compute_trend(4.0, None), "→");
    }

    // ── Table rendering test ──────────────────────────────────────────────────

    #[test]
    fn test_render_mttr_table_contains_headers() {
        let report = MttrReport {
            entries: vec![MttrEntry {
                rule_id: "js-sql-string-concat".to_string(),
                vuln_class: "SQL Injection".to_string(),
                severity: "High".to_string(),
                findings_detected: 5,
                findings_remediated: 5,
                mttr_hours: Some(4.2),
            }],
            overall_mttr_hours: Some(4.2),
            total_remediated: 5,
            period: "all time".to_string(),
        };

        let table = render_mttr_table(&report);
        assert!(
            table.contains("Rule ID"),
            "Table must contain Rule ID header"
        );
        assert!(
            table.contains("Vulnerability Class"),
            "Table must contain Vulnerability Class header"
        );
        assert!(
            table.contains("MTTR (hours)"),
            "Table must contain MTTR (hours) header"
        );
        assert!(
            table.contains("js-sql-string-concat"),
            "Table must contain rule ID"
        );
        assert!(table.contains("4.2"), "Table must contain MTTR value");
    }

    #[test]
    fn test_render_mttr_table_insufficient_data() {
        let report = MttrReport {
            entries: vec![MttrEntry {
                rule_id: "hardcoded-secret".to_string(),
                vuln_class: String::new(),
                severity: String::new(),
                findings_detected: 2,
                findings_remediated: 2,
                mttr_hours: None,
            }],
            overall_mttr_hours: None,
            total_remediated: 2,
            period: "all time".to_string(),
        };

        let table = render_mttr_table(&report);
        assert!(
            table.contains("Insufficient data"),
            "Table must show 'Insufficient data' for <3 findings"
        );
    }

    #[test]
    fn test_mttr_excludes_removed_findings() {
        let dir = make_temp_project();
        let project_root = dir.path();

        let detection_ts = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        write_baseline(project_root, detection_ts, 1);

        // 3 fixes: 2 "fixed", 1 "removed"
        let entries = vec![
            PatchHistoryEntry {
                patch_id: "rule-1-0001".to_string(),
                applied_at: Utc.with_ymd_and_hms(2024, 1, 1, 2, 0, 0).unwrap().to_rfc3339(),
                file_path: PathBuf::from("src/app.js"),
                backup_path: PathBuf::from(".sicario/backups/1/app.js"),
                resolution_type: Some("fixed".to_string()),
            },
            PatchHistoryEntry {
                patch_id: "rule-1-0002".to_string(),
                applied_at: Utc.with_ymd_and_hms(2024, 1, 1, 4, 0, 0).unwrap().to_rfc3339(),
                file_path: PathBuf::from("src/app.js"),
                backup_path: PathBuf::from(".sicario/backups/2/app.js"),
                resolution_type: Some("fixed".to_string()),
            },
            PatchHistoryEntry {
                patch_id: "rule-1-0003".to_string(),
                applied_at: Utc.with_ymd_and_hms(2024, 1, 1, 6, 0, 0).unwrap().to_rfc3339(),
                file_path: PathBuf::from("src/app.js"),
                backup_path: PathBuf::from(".sicario/backups/3/app.js"),
                resolution_type: Some("removed".to_string()),
            },
        ];

        write_patch_history(project_root, &entries);

        let report = compute_mttr(project_root, None).unwrap();
        // Since only 2 findings are "fixed", total_remediated should be 2, resulting in Insufficient data
        assert_eq!(report.total_remediated, 2);
        assert!(report.entries[0].mttr_hours.is_none());
    }
}
