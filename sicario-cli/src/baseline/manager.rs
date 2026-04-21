//! Baseline management — persist scan snapshots and compute deltas.
//!
//! Baselines are stored as timestamped JSON files in `.sicario/baselines/`.
//! Finding identity uses a stable fingerprint: SHA-256(rule_id + file_path + snippet_hash),
//! so line/column changes do NOT affect identity across baselines.

use crate::engine::vulnerability::{Finding, Severity};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

// ── Data Models ──────────────────────────────────────────────────────────────

/// A persisted baseline snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub timestamp: DateTime<Utc>,
    pub tag: Option<String>,
    pub commit_sha: Option<String>,
    pub findings: Vec<BaselineFinding>,
}

/// A finding as stored in a baseline (minimal fields for identity + metadata).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineFinding {
    pub fingerprint: String,
    pub rule_id: String,
    pub file_path: PathBuf,
    pub line: usize,
    pub severity: Severity,
    pub confidence_score: f64,
    pub snippet_hash: String,
}

/// Delta between two baselines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineDelta {
    pub new_findings: Vec<BaselineFinding>,
    pub resolved_findings: Vec<BaselineFinding>,
    pub unchanged_findings: Vec<BaselineFinding>,
}

/// Summary of a single baseline for trend reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSummary {
    pub timestamp: DateTime<Utc>,
    pub tag: Option<String>,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

// ── Trait ────────────────────────────────────────────────────────────────────

/// Trait defining baseline management operations.
pub trait BaselineManagement {
    /// Save current findings as a timestamped baseline snapshot.
    /// Returns the path to the saved baseline file.
    fn save(&self, findings: &[Finding], tag: Option<&str>) -> Result<PathBuf>;

    /// Compare current findings against a saved baseline identified by tag or timestamp.
    /// Returns the delta: new, resolved, and unchanged findings.
    fn compare(&self, reference: &str, current_findings: &[Finding]) -> Result<BaselineDelta>;

    /// Summarize finding counts across all saved baselines for trend analysis.
    fn trend(&self) -> Result<Vec<BaselineSummary>>;
}

// ── Implementation ───────────────────────────────────────────────────────────

/// Baseline manager that persists baselines in `.sicario/baselines/`.
pub struct BaselineManager {
    /// Root directory of the project (where `.sicario/` lives).
    project_root: PathBuf,
}

impl BaselineManager {
    /// Create a new BaselineManager for the given project root.
    pub fn new(project_root: impl Into<PathBuf>) -> Self {
        Self {
            project_root: project_root.into(),
        }
    }

    /// Get the baselines directory path, creating it if needed.
    fn baselines_dir(&self) -> Result<PathBuf> {
        let dir = self.project_root.join(".sicario").join("baselines");
        if !dir.exists() {
            fs::create_dir_all(&dir).with_context(|| {
                format!("Failed to create baselines directory: {}", dir.display())
            })?;
        }
        Ok(dir)
    }

    /// Convert a Finding to a BaselineFinding for storage.
    fn to_baseline_finding(finding: &Finding) -> BaselineFinding {
        let snippet_hash = {
            let mut hasher = Sha256::new();
            hasher.update(finding.snippet.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        BaselineFinding {
            fingerprint: finding.fingerprint.clone(),
            rule_id: finding.rule_id.clone(),
            file_path: finding.file_path.clone(),
            line: finding.line,
            severity: finding.severity,
            confidence_score: finding.confidence_score,
            snippet_hash,
        }
    }

    /// Generate a filename for a baseline: `{timestamp}_{tag}.json` or `{timestamp}.json`.
    fn baseline_filename(timestamp: &DateTime<Utc>, tag: Option<&str>) -> String {
        let ts = timestamp.format("%Y%m%dT%H%M%SZ").to_string();
        match tag {
            Some(t) => format!("{}_{}.json", ts, sanitize_tag(t)),
            None => format!("{}.json", ts),
        }
    }

    /// Load all baselines from disk, sorted by timestamp (oldest first).
    fn load_all_baselines(&self) -> Result<Vec<Baseline>> {
        let dir = self.baselines_dir()?;
        let mut baselines = Vec::new();

        if !dir.exists() {
            return Ok(baselines);
        }

        for entry in fs::read_dir(&dir)
            .with_context(|| format!("Failed to read baselines directory: {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let content = fs::read_to_string(&path)
                    .with_context(|| format!("Failed to read baseline: {}", path.display()))?;
                match serde_json::from_str::<Baseline>(&content) {
                    Ok(baseline) => baselines.push(baseline),
                    Err(e) => {
                        tracing::warn!("Skipping malformed baseline {}: {}", path.display(), e);
                    }
                }
            }
        }

        baselines.sort_by_key(|b| b.timestamp);
        Ok(baselines)
    }

    /// Find a baseline by tag or timestamp prefix.
    fn find_baseline(&self, reference: &str) -> Result<Baseline> {
        let baselines = self.load_all_baselines()?;

        // Try matching by tag first
        if let Some(b) = baselines
            .iter()
            .find(|b| b.tag.as_deref() == Some(reference))
        {
            return Ok(b.clone());
        }

        // Try matching by timestamp prefix (e.g., "20240101" or full "20240101T120000Z")
        if let Some(b) = baselines.iter().rev().find(|b| {
            let ts = b.timestamp.format("%Y%m%dT%H%M%SZ").to_string();
            ts.starts_with(reference)
        }) {
            return Ok(b.clone());
        }

        anyhow::bail!(
            "No baseline found matching '{}'. Use `sicario baseline trend` to list available baselines.",
            reference
        )
    }
}

impl BaselineManagement for BaselineManager {
    fn save(&self, findings: &[Finding], tag: Option<&str>) -> Result<PathBuf> {
        let dir = self.baselines_dir()?;
        let now = Utc::now();

        let baseline = Baseline {
            timestamp: now,
            tag: tag.map(|t| t.to_string()),
            commit_sha: detect_current_commit(&self.project_root),
            findings: findings.iter().map(Self::to_baseline_finding).collect(),
        };

        let filename = Self::baseline_filename(&now, tag);
        let path = dir.join(&filename);

        let json =
            serde_json::to_string_pretty(&baseline).context("Failed to serialize baseline")?;
        fs::write(&path, json)
            .with_context(|| format!("Failed to write baseline: {}", path.display()))?;

        Ok(path)
    }

    fn compare(&self, reference: &str, current_findings: &[Finding]) -> Result<BaselineDelta> {
        let old_baseline = self.find_baseline(reference)?;

        let old_fingerprints: HashSet<&str> = old_baseline
            .findings
            .iter()
            .map(|f| f.fingerprint.as_str())
            .collect();

        let current_baseline_findings: Vec<BaselineFinding> = current_findings
            .iter()
            .map(Self::to_baseline_finding)
            .collect();

        let current_fingerprints: HashSet<&str> = current_baseline_findings
            .iter()
            .map(|f| f.fingerprint.as_str())
            .collect();

        // New: in current but not in old
        let new_findings: Vec<BaselineFinding> = current_baseline_findings
            .iter()
            .filter(|f| !old_fingerprints.contains(f.fingerprint.as_str()))
            .cloned()
            .collect();

        // Resolved: in old but not in current
        let resolved_findings: Vec<BaselineFinding> = old_baseline
            .findings
            .iter()
            .filter(|f| !current_fingerprints.contains(f.fingerprint.as_str()))
            .cloned()
            .collect();

        // Unchanged: in both
        let unchanged_findings: Vec<BaselineFinding> = current_baseline_findings
            .iter()
            .filter(|f| old_fingerprints.contains(f.fingerprint.as_str()))
            .cloned()
            .collect();

        Ok(BaselineDelta {
            new_findings,
            resolved_findings,
            unchanged_findings,
        })
    }

    fn trend(&self) -> Result<Vec<BaselineSummary>> {
        let baselines = self.load_all_baselines()?;

        let summaries = baselines
            .into_iter()
            .map(|b| {
                let total = b.findings.len();
                let critical_count = b
                    .findings
                    .iter()
                    .filter(|f| f.severity == Severity::Critical)
                    .count();
                let high_count = b
                    .findings
                    .iter()
                    .filter(|f| f.severity == Severity::High)
                    .count();
                let medium_count = b
                    .findings
                    .iter()
                    .filter(|f| f.severity == Severity::Medium)
                    .count();
                let low_count = b
                    .findings
                    .iter()
                    .filter(|f| f.severity == Severity::Low)
                    .count();
                let info_count = b
                    .findings
                    .iter()
                    .filter(|f| f.severity == Severity::Info)
                    .count();

                BaselineSummary {
                    timestamp: b.timestamp,
                    tag: b.tag,
                    total_findings: total,
                    critical_count,
                    high_count,
                    medium_count,
                    low_count,
                    info_count,
                }
            })
            .collect();

        Ok(summaries)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Sanitize a tag for use in filenames (replace non-alphanumeric with dashes).
fn sanitize_tag(tag: &str) -> String {
    tag.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Attempt to detect the current git commit SHA. Returns None if not in a git repo.
fn detect_current_commit(project_root: &Path) -> Option<String> {
    let repo = git2::Repository::discover(project_root).ok()?;
    let head = repo.head().ok()?;
    let oid = head.target()?;
    Some(oid.to_string())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::vulnerability::Finding;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn make_finding(rule_id: &str, file: &str, snippet: &str) -> Finding {
        let fingerprint = Finding::compute_fingerprint(rule_id, Path::new(file), snippet);
        Finding {
            id: Uuid::new_v4(),
            rule_id: rule_id.to_string(),
            rule_name: format!("{} rule", rule_id),
            file_path: PathBuf::from(file),
            line: 10,
            column: 5,
            end_line: None,
            end_column: None,
            snippet: snippet.to_string(),
            severity: Severity::High,
            confidence_score: 0.85,
            reachable: true,
            cloud_exposed: None,
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: None,
            fingerprint,
            dataflow_trace: None,
            suppressed: false,
            suppression_rule: None,
            suggested_suppression: false,
        }
    }

    #[test]
    fn test_save_creates_baseline_file() {
        let tmp = TempDir::new().unwrap();
        let mgr = BaselineManager::new(tmp.path());

        let findings = vec![make_finding("sql-injection", "src/db.rs", "query(input)")];

        let path = mgr.save(&findings, Some("v1-release")).unwrap();
        assert!(path.exists());
        assert!(path.to_string_lossy().contains("v1-release"));

        let content = fs::read_to_string(&path).unwrap();
        let baseline: Baseline = serde_json::from_str(&content).unwrap();
        assert_eq!(baseline.findings.len(), 1);
        assert_eq!(baseline.tag.as_deref(), Some("v1-release"));
    }

    #[test]
    fn test_save_without_tag() {
        let tmp = TempDir::new().unwrap();
        let mgr = BaselineManager::new(tmp.path());

        let findings = vec![make_finding("xss", "src/view.js", "innerHTML = data")];

        let path = mgr.save(&findings, None).unwrap();
        assert!(path.exists());
        // No tag in filename
        let filename = path.file_name().unwrap().to_string_lossy();
        assert!(!filename.contains('_'));
    }

    #[test]
    fn test_compare_computes_correct_delta() {
        let tmp = TempDir::new().unwrap();
        let mgr = BaselineManager::new(tmp.path());

        // Save a baseline with findings A and B
        let finding_a = make_finding("sql-injection", "src/db.rs", "query(input)");
        let finding_b = make_finding("xss", "src/view.js", "innerHTML = data");
        mgr.save(&[finding_a.clone(), finding_b.clone()], Some("baseline1"))
            .unwrap();

        // Current scan has findings A and C (B resolved, C is new)
        let finding_c = make_finding("cmd-injection", "src/exec.rs", "Command::new(user_input)");
        let current = vec![finding_a.clone(), finding_c.clone()];

        let delta = mgr.compare("baseline1", &current).unwrap();

        // A is unchanged
        assert_eq!(delta.unchanged_findings.len(), 1);
        assert_eq!(
            delta.unchanged_findings[0].fingerprint,
            finding_a.fingerprint
        );

        // B is resolved
        assert_eq!(delta.resolved_findings.len(), 1);
        assert_eq!(
            delta.resolved_findings[0].fingerprint,
            finding_b.fingerprint
        );

        // C is new
        assert_eq!(delta.new_findings.len(), 1);
        assert_eq!(delta.new_findings[0].fingerprint, finding_c.fingerprint);
    }

    #[test]
    fn test_delta_sets_are_disjoint() {
        let tmp = TempDir::new().unwrap();
        let mgr = BaselineManager::new(tmp.path());

        let finding_a = make_finding("rule-a", "a.rs", "snippet_a");
        let finding_b = make_finding("rule-b", "b.rs", "snippet_b");
        let finding_c = make_finding("rule-c", "c.rs", "snippet_c");

        mgr.save(&[finding_a.clone(), finding_b.clone()], Some("old"))
            .unwrap();

        let current = vec![finding_b.clone(), finding_c.clone()];
        let delta = mgr.compare("old", &current).unwrap();

        let new_fps: HashSet<&str> = delta
            .new_findings
            .iter()
            .map(|f| f.fingerprint.as_str())
            .collect();
        let resolved_fps: HashSet<&str> = delta
            .resolved_findings
            .iter()
            .map(|f| f.fingerprint.as_str())
            .collect();
        let unchanged_fps: HashSet<&str> = delta
            .unchanged_findings
            .iter()
            .map(|f| f.fingerprint.as_str())
            .collect();

        // Disjoint check
        assert!(new_fps.is_disjoint(&resolved_fps));
        assert!(new_fps.is_disjoint(&unchanged_fps));
        assert!(resolved_fps.is_disjoint(&unchanged_fps));

        // Union equals union of old and new fingerprints
        let old_fps: HashSet<&str> = [&finding_a, &finding_b]
            .iter()
            .map(|f| f.fingerprint.as_str())
            .collect();
        let cur_fps: HashSet<&str> = [&finding_b, &finding_c]
            .iter()
            .map(|f| f.fingerprint.as_str())
            .collect();
        let all_fps: HashSet<&str> = old_fps.union(&cur_fps).copied().collect();
        let delta_union: HashSet<&str> = new_fps
            .union(&resolved_fps)
            .copied()
            .chain(unchanged_fps.iter().copied())
            .collect();
        assert_eq!(all_fps, delta_union);
    }

    #[test]
    fn test_trend_returns_summaries_sorted_by_time() {
        let tmp = TempDir::new().unwrap();
        let mgr = BaselineManager::new(tmp.path());

        let f1 = make_finding("rule-a", "a.rs", "snippet_a");
        let mut f2 = make_finding("rule-b", "b.rs", "snippet_b");
        f2.severity = Severity::Critical;

        mgr.save(&[f1.clone()], Some("first")).unwrap();
        // Small delay to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(10));
        mgr.save(&[f1.clone(), f2.clone()], Some("second")).unwrap();

        let summaries = mgr.trend().unwrap();
        assert_eq!(summaries.len(), 2);
        assert!(summaries[0].timestamp <= summaries[1].timestamp);
        assert_eq!(summaries[0].total_findings, 1);
        assert_eq!(summaries[1].total_findings, 2);
        assert_eq!(summaries[1].critical_count, 1);
    }

    #[test]
    fn test_baseline_round_trip() {
        let tmp = TempDir::new().unwrap();
        let mgr = BaselineManager::new(tmp.path());

        let findings = vec![
            make_finding("sql-injection", "src/db.rs", "query(input)"),
            make_finding("xss", "src/view.js", "innerHTML = data"),
        ];

        let path = mgr.save(&findings, Some("roundtrip")).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        let loaded: Baseline = serde_json::from_str(&content).unwrap();

        assert_eq!(loaded.findings.len(), 2);
        assert_eq!(loaded.tag.as_deref(), Some("roundtrip"));
        assert_eq!(loaded.findings[0].fingerprint, findings[0].fingerprint);
        assert_eq!(loaded.findings[1].fingerprint, findings[1].fingerprint);
    }

    #[test]
    fn test_fingerprint_stability_line_change() {
        // Changing line/column should NOT change the fingerprint
        let fp1 =
            Finding::compute_fingerprint("sql-injection", Path::new("src/db.rs"), "query(input)");
        let fp2 =
            Finding::compute_fingerprint("sql-injection", Path::new("src/db.rs"), "query(input)");
        assert_eq!(fp1, fp2);
        // The fingerprint is based on rule_id + file_path + snippet_hash, not line/column
    }

    #[test]
    fn test_find_baseline_by_tag() {
        let tmp = TempDir::new().unwrap();
        let mgr = BaselineManager::new(tmp.path());

        let findings = vec![make_finding("rule-a", "a.rs", "snippet")];
        mgr.save(&findings, Some("release-1.0")).unwrap();

        let found = mgr.find_baseline("release-1.0").unwrap();
        assert_eq!(found.tag.as_deref(), Some("release-1.0"));
    }

    #[test]
    fn test_find_baseline_not_found() {
        let tmp = TempDir::new().unwrap();
        let mgr = BaselineManager::new(tmp.path());

        let result = mgr.find_baseline("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_tag() {
        assert_eq!(sanitize_tag("v1.0-beta"), "v1-0-beta");
        assert_eq!(sanitize_tag("release/2024"), "release-2024");
        assert_eq!(sanitize_tag("simple_tag"), "simple_tag");
    }
}
