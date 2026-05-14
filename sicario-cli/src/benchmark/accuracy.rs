//! Accuracy benchmarking — Precision, Recall, F1 against MANIFEST.md ground truth.
//!
//! Reads the vuln-sandbox MANIFEST.md (or a bundled Known_Vulnerable_App manifest),
//! runs the SAST engine against the target directory, and computes:
//!   - True Positives (TP): TP files that produced ≥1 finding for the expected rule
//!   - False Positives (FP): TN files that produced ≥1 finding for the expected rule
//!   - False Negatives (FN): TP files that produced 0 findings for the expected rule
//!
//! Precision = TP / (TP + FP)
//! Recall    = TP / (TP + FN)
//! F1        = 2 * (Precision * Recall) / (Precision + Recall)
//!
//! Requirements: Req 5 — sicario benchmark command (Tasks 5.1–5.6)

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::engine::sast_engine::SastEngine;

// ── Data models ──────────────────────────────────────────────────────────────

/// A single entry from the ground-truth manifest.
#[derive(Debug, Clone)]
pub struct ManifestEntry {
    /// Relative file path from the target directory root.
    pub file_path: String,
    /// Expected rule ID that should (or should not) fire.
    pub rule_id: String,
    /// Whether this file is a true positive or true negative.
    pub expected: ManifestOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestOutcome {
    TruePositive,
    TrueNegative,
}

/// Per-language accuracy breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageAccuracy {
    pub language: String,
    pub tp: usize,
    pub fp: usize,
    pub fn_count: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

/// Full accuracy benchmark result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccuracyResult {
    pub timestamp: String,
    pub target_dir: String,
    pub total_tp: usize,
    pub total_fp: usize,
    pub total_fn: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub per_language: Vec<LanguageAccuracy>,
    /// Files that were expected to produce a finding but didn't (false negatives).
    pub false_negatives: Vec<String>,
    /// Files that were expected to produce no finding but did (false positives).
    pub false_positives: Vec<String>,
}

impl AccuracyResult {
    pub fn display_text(&self) -> String {
        let mut s = String::new();
        s.push_str("╔══════════════════════════════════════════════════╗\n");
        s.push_str("║         Sicario Accuracy Benchmark               ║\n");
        s.push_str("╠══════════════════════════════════════════════════╣\n");
        s.push_str(&format!(
            "║ Target:    {:<38}║\n",
            truncate(&self.target_dir, 38)
        ));
        s.push_str(&format!("║ TP:        {:>5}                                  ║\n", self.total_tp));
        s.push_str(&format!("║ FP:        {:>5}                                  ║\n", self.total_fp));
        s.push_str(&format!("║ FN:        {:>5}                                  ║\n", self.total_fn));
        s.push_str(&format!(
            "║ Precision: {:>6.1}%                                ║\n",
            self.precision * 100.0
        ));
        s.push_str(&format!(
            "║ Recall:    {:>6.1}%                                ║\n",
            self.recall * 100.0
        ));
        s.push_str(&format!(
            "║ F1:        {:>6.1}%                                ║\n",
            self.f1 * 100.0
        ));
        s.push_str("╠══════════════════════════════════════════════════╣\n");
        s.push_str("║ Per-language breakdown:                          ║\n");
        for lang in &self.per_language {
            s.push_str(&format!(
                "║  {:<12} P:{:>5.1}% R:{:>5.1}% F1:{:>5.1}%          ║\n",
                lang.language,
                lang.precision * 100.0,
                lang.recall * 100.0,
                lang.f1 * 100.0
            ));
        }
        s.push_str("╚══════════════════════════════════════════════════╝\n");

        if !self.false_negatives.is_empty() {
            s.push_str("\nFalse Negatives (missed vulnerabilities):\n");
            for f in &self.false_negatives {
                s.push_str(&format!("  ✗ {}\n", f));
            }
        }
        if !self.false_positives.is_empty() {
            s.push_str("\nFalse Positives (noise in clean files):\n");
            for f in &self.false_positives {
                s.push_str(&format!("  ✗ {}\n", f));
            }
        }
        s
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("...{}", &s[s.len().saturating_sub(max - 3)..])
    }
}

// ── Manifest parser ───────────────────────────────────────────────────────────

/// Parse a MANIFEST.md file and return all ground-truth entries.
///
/// Expects table rows in the format:
/// `| path/to/file.js | CWE-XX | rule-id | TruePositive | ... |`
pub fn parse_manifest(manifest_path: &Path) -> Result<Vec<ManifestEntry>> {
    let content = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("Failed to read manifest: {}", manifest_path.display()))?;

    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Only process table rows (start and end with |)
        if !line.starts_with('|') || !line.ends_with('|') {
            continue;
        }
        let cols: Vec<&str> = line
            .split('|')
            .map(|c| c.trim())
            .filter(|c| !c.is_empty())
            .collect();

        // Expect at least 4 columns: file, CWE, rule_id, outcome
        if cols.len() < 4 {
            continue;
        }

        // Skip header rows
        let file_col = cols[0];
        if file_col == "File" || file_col.starts_with('-') || file_col.starts_with('*') {
            continue;
        }

        // Strip backtick formatting from file path
        let file_path = file_col.trim_matches('`').to_string();
        if file_path.is_empty() || file_path.starts_with('-') {
            continue;
        }

        let rule_id = cols[2].trim_matches('`').to_string();
        let outcome_str = cols[3];

        let expected = if outcome_str.contains("TruePositive") {
            ManifestOutcome::TruePositive
        } else if outcome_str.contains("TrueNegative") {
            ManifestOutcome::TrueNegative
        } else {
            continue; // skip rows without a clear outcome
        };

        entries.push(ManifestEntry {
            file_path,
            rule_id,
            expected,
        });
    }

    Ok(entries)
}

// ── AccuracyBenchmark ─────────────────────────────────────────────────────────

pub struct AccuracyBenchmark {
    project_root: PathBuf,
}

impl AccuracyBenchmark {
    pub fn new(project_root: &Path) -> Self {
        Self {
            project_root: project_root.to_path_buf(),
        }
    }

    /// Run an accuracy benchmark against `target_dir` using `manifest_path` as ground truth.
    /// The `engine` should already have rules loaded.
    pub fn run_with_engine(
        &self,
        target_dir: &Path,
        manifest_path: &Path,
        engine: &mut SastEngine,
    ) -> Result<AccuracyResult> {
        let entries = parse_manifest(manifest_path)?;

        if entries.is_empty() {
            anyhow::bail!(
                "No ground-truth entries found in manifest: {}",
                manifest_path.display()
            );
        }

        // Scan the target directory
        let all_findings = engine.scan_directory(target_dir)?;

        // Build a lookup: file_path (relative) → set of rule_ids that fired
        let mut findings_by_file: HashMap<String, std::collections::HashSet<String>> =
            HashMap::new();
        for finding in &all_findings {
            let rel_path = finding
                .file_path
                .strip_prefix(target_dir)
                .unwrap_or(&finding.file_path)
                .to_string_lossy()
                .replace('\\', "/")
                .trim_start_matches('/')
                .to_string();
            findings_by_file
                .entry(rel_path)
                .or_default()
                .insert(finding.rule_id.clone());
        }

        // Evaluate each manifest entry
        let mut tp = 0usize;
        let mut fp = 0usize;
        let mut fn_count = 0usize;
        let mut false_negatives = Vec::new();
        let mut false_positives = Vec::new();

        // Per-language tracking: language → (tp, fp, fn)
        let mut lang_stats: HashMap<String, (usize, usize, usize)> = HashMap::new();

        for entry in &entries {
            let lang = detect_language_from_path(&entry.file_path);
            let stat = lang_stats.entry(lang).or_insert((0, 0, 0));

            let fired = findings_by_file
                .get(&entry.file_path)
                .map(|rules| rules.contains(&entry.rule_id))
                .unwrap_or(false);

            match entry.expected {
                ManifestOutcome::TruePositive => {
                    if fired {
                        tp += 1;
                        stat.0 += 1;
                    } else {
                        fn_count += 1;
                        stat.2 += 1;
                        false_negatives.push(format!("{} (rule: {})", entry.file_path, entry.rule_id));
                    }
                }
                ManifestOutcome::TrueNegative => {
                    if fired {
                        fp += 1;
                        stat.1 += 1;
                        false_positives.push(format!("{} (rule: {})", entry.file_path, entry.rule_id));
                    }
                    // TN that correctly produced no finding: not counted in TP/FP/FN
                }
            }
        }

        let precision = compute_precision(tp, fp);
        let recall = compute_recall(tp, fn_count);
        let f1 = compute_f1(precision, recall);

        let per_language = lang_stats
            .into_iter()
            .map(|(lang, (l_tp, l_fp, l_fn))| {
                let p = compute_precision(l_tp, l_fp);
                let r = compute_recall(l_tp, l_fn);
                LanguageAccuracy {
                    language: lang,
                    tp: l_tp,
                    fp: l_fp,
                    fn_count: l_fn,
                    precision: p,
                    recall: r,
                    f1: compute_f1(p, r),
                }
            })
            .collect();

        Ok(AccuracyResult {
            timestamp: Utc::now().to_rfc3339(),
            target_dir: target_dir.to_string_lossy().to_string(),
            total_tp: tp,
            total_fp: fp,
            total_fn: fn_count,
            precision,
            recall,
            f1,
            per_language,
            false_negatives,
            false_positives,
        })
    }

    /// Save an accuracy result to `.sicario/benchmarks/benchmark-<ISO8601>.json`.
    pub fn save(&self, result: &AccuracyResult, app_name: Option<&str>) -> Result<PathBuf> {
        let benchmarks_dir = self.project_root.join(".sicario").join("benchmarks");
        std::fs::create_dir_all(&benchmarks_dir)?;

        let ts = Utc::now().format("%Y%m%dT%H%M%S");
        let filename = match app_name {
            Some(name) => format!("benchmark-{}-{}.json", name, ts),
            None => format!("benchmark-{}.json", ts),
        };
        let path = benchmarks_dir.join(&filename);
        let json = serde_json::to_string_pretty(result)?;
        std::fs::write(&path, json)?;
        Ok(path)
    }

    /// Save as the named baseline file.
    pub fn save_baseline(&self, result: &AccuracyResult) -> Result<PathBuf> {
        let benchmarks_dir = self.project_root.join(".sicario").join("benchmarks");
        std::fs::create_dir_all(&benchmarks_dir)?;
        let path = benchmarks_dir.join("baseline.json");
        let json = serde_json::to_string_pretty(result)?;
        std::fs::write(&path, json)?;
        Ok(path)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn compute_precision(tp: usize, fp: usize) -> f64 {
    if tp + fp == 0 {
        1.0
    } else {
        tp as f64 / (tp + fp) as f64
    }
}

fn compute_recall(tp: usize, fn_count: usize) -> f64 {
    if tp + fn_count == 0 {
        1.0
    } else {
        tp as f64 / (tp + fn_count) as f64
    }
}

fn compute_f1(precision: f64, recall: f64) -> f64 {
    if precision + recall == 0.0 {
        0.0
    } else {
        2.0 * (precision * recall) / (precision + recall)
    }
}

fn detect_language_from_path(path: &str) -> String {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    match ext {
        "js" | "mjs" | "cjs" => "JavaScript".to_string(),
        "ts" | "tsx" => "TypeScript".to_string(),
        "py" => "Python".to_string(),
        "go" => "Go".to_string(),
        "rs" => "Rust".to_string(),
        "java" => "Java".to_string(),
        "rb" => "Ruby".to_string(),
        "php" => "PHP".to_string(),
        "cs" => "CSharp".to_string(),
        _ => "Other".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_precision() {
        assert_eq!(compute_precision(8, 2), 0.8);
        assert_eq!(compute_precision(0, 0), 1.0);
        assert_eq!(compute_precision(10, 0), 1.0);
    }

    #[test]
    fn test_compute_recall() {
        assert_eq!(compute_recall(7, 3), 0.7);
        assert_eq!(compute_recall(0, 0), 1.0);
    }

    #[test]
    fn test_compute_f1() {
        let p = compute_precision(8, 2);
        let r = compute_recall(7, 3);
        let f1 = compute_f1(p, r);
        assert!((f1 - 2.0 * p * r / (p + r)).abs() < 1e-9);
    }

    #[test]
    fn test_detect_language_from_path() {
        assert_eq!(detect_language_from_path("src/app.js"), "JavaScript");
        assert_eq!(detect_language_from_path("src/app.ts"), "TypeScript");
        assert_eq!(detect_language_from_path("app.py"), "Python");
        assert_eq!(detect_language_from_path("main.go"), "Go");
        assert_eq!(detect_language_from_path("lib.rs"), "Rust");
    }

    #[test]
    fn test_parse_manifest_table_row() {
        let manifest_content = r#"
# Test Manifest

| File | CWE | Rule ID | Expected Outcome | Severity |
|------|-----|---------|-----------------|----------|
| `node/cwe-89/sql-injection.js` | CWE-89 | js-sql-string-concat | TruePositive | HIGH |
| `node/cwe-89/sql-injection-safe.js` | CWE-89 | js-sql-string-concat | TrueNegative | — |
"#;
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), manifest_content).unwrap();
        let entries = parse_manifest(tmp.path()).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].file_path, "node/cwe-89/sql-injection.js");
        assert_eq!(entries[0].rule_id, "js-sql-string-concat");
        assert_eq!(entries[0].expected, ManifestOutcome::TruePositive);
        assert_eq!(entries[1].expected, ManifestOutcome::TrueNegative);
    }

    #[test]
    fn test_accuracy_result_display_text() {
        let result = AccuracyResult {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            target_dir: "/tmp/vuln-sandbox".to_string(),
            total_tp: 80,
            total_fp: 5,
            total_fn: 10,
            precision: 80.0 / 85.0,
            recall: 80.0 / 90.0,
            f1: 0.85,
            per_language: vec![],
            false_negatives: vec![],
            false_positives: vec![],
        };
        let text = result.display_text();
        assert!(text.contains("Accuracy Benchmark"));
        assert!(text.contains("Precision"));
        assert!(text.contains("Recall"));
    }
}
