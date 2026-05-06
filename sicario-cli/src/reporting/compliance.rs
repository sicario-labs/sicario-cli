//! Enterprise compliance evidence export.
//!
//! Generates a structured compliance report from patch history, suppression
//! directives, baseline trend data, and computed MTTR metrics.
//!
//! Design: Area 6.1 — Compliance Evidence Export

use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::baseline::manager::{BaselineManagement, BaselineManager, BaselineSummary};
use crate::remediation::backup_manager::{BackupManager, PatchHistoryEntry};

// ── Data Models ───────────────────────────────────────────────────────────────

/// Lightweight scan summary embedded in the compliance report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ComplianceScanSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

/// A single entry in the remediation log, derived from `PatchHistoryEntry`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RemediationEntry {
    /// Unique patch identifier.
    pub patch_id: String,
    /// RFC 3339 timestamp when the patch was applied.
    pub applied_at: String,
    /// Path of the file that was patched.
    pub file_path: PathBuf,
    /// Rule ID that triggered the patch (derived from patch_id prefix when available).
    pub rule_id: String,
    /// Template or agent used to generate the patch.
    pub template_used: String,
}

impl From<&PatchHistoryEntry> for RemediationEntry {
    fn from(entry: &PatchHistoryEntry) -> Self {
        // patch_id format is typically "<rule_id>-<uuid>" or just "<uuid>".
        // We extract the rule_id as the portion before the last '-' segment if
        // it looks like a UUID suffix; otherwise use the full patch_id.
        let rule_id = extract_rule_id_from_patch_id(&entry.patch_id);
        Self {
            patch_id: entry.patch_id.clone(),
            applied_at: entry.applied_at.clone(),
            file_path: entry.file_path.clone(),
            rule_id,
            template_used: String::new(), // PatchHistoryEntry does not carry template info
        }
    }
}

/// A single entry in the suppression audit log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SuppressionEntry {
    /// Source file containing the suppression directive.
    pub file: String,
    /// 1-indexed line number of the suppression comment.
    pub line: usize,
    /// Rule ID being suppressed (`"all"` for blanket suppressions).
    pub rule_id: String,
    /// Full text of the suppression comment.
    pub comment_text: String,
    /// Author email from git history, or `"untracked"` if unavailable.
    pub author_email: String,
    /// Commit SHA from git history, or `"untracked"` if unavailable.
    pub commit_sha: String,
    /// ISO 8601 commit timestamp, or `"untracked"` if unavailable.
    pub committed_at: String,
}

/// Per-rule MTTR (Mean Time To Remediate) entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MttrEntry {
    /// Rule ID.
    pub rule_id: String,
    /// Vulnerability class description (e.g. "SQL Injection").
    pub vuln_class: String,
    /// Severity level as a string.
    pub severity: String,
    /// Total number of findings detected for this rule.
    pub findings_detected: usize,
    /// Number of findings that have been remediated.
    pub findings_remediated: usize,
    /// Mean time to remediate in hours. `None` when fewer than 3 findings
    /// have been remediated (insufficient data).
    pub mttr_hours: Option<f64>,
}

/// Full enterprise compliance report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceReport {
    /// ISO 8601 timestamp when this report was generated.
    pub generated_at: String,
    /// Sicario version string.
    pub sicario_version: String,
    /// Lightweight scan summary (populated from baseline history when available).
    pub scan_summary: ComplianceScanSummary,
    /// Ordered list of applied patches.
    pub remediation_log: Vec<RemediationEntry>,
    /// Ordered list of suppression directives found in source files.
    pub suppression_log: Vec<SuppressionEntry>,
    /// Baseline trend history (one entry per saved baseline).
    pub baseline_history: Vec<BaselineSummary>,
    /// Per-rule MTTR metrics.
    pub mttr_by_rule: Vec<MttrEntry>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract a rule ID from a patch_id string.
///
/// Patch IDs are typically `<rule_id>-<uuid>` or just `<uuid>`. We detect the
/// UUID suffix (8-4-4-4-12 hex groups) and strip it, returning the prefix as
/// the rule ID. If no UUID suffix is found, the full patch_id is returned.
fn extract_rule_id_from_patch_id(patch_id: &str) -> String {
    // UUID v4 pattern: 8-4-4-4-12 hex chars separated by '-'
    // We look for the last 36-character UUID-shaped suffix.
    if patch_id.len() > 37 {
        let candidate = &patch_id[patch_id.len() - 36..];
        if is_uuid_shaped(candidate) {
            // Strip the trailing '-<uuid>'
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

// ── Suppression scanning ──────────────────────────────────────────────────────

/// Check whether `project_root` is inside a git repository.
///
/// This is called once before the recursive walk to avoid spawning a subprocess
/// per file when git is not available.
fn is_git_repo(project_root: &Path) -> bool {
    std::process::Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(project_root)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Scan `project_root` recursively for source files containing `sicario-ignore`
/// directives and return a `SuppressionEntry` for each occurrence.
///
/// Git attribution is attempted via `git log -S "sicario-ignore" --follow
/// --format="%ae %H %aI" -- <file>` once per file (not per line). If git is
/// unavailable or the file is untracked, the git fields are set to
/// `"untracked"`.
fn scan_suppression_log(project_root: &Path) -> Vec<SuppressionEntry> {
    // Check git availability once upfront to avoid spawning a subprocess per file.
    let in_git_repo = is_git_repo(project_root);
    let mut entries = Vec::new();
    collect_suppressions_recursive(project_root, project_root, in_git_repo, &mut entries);
    entries
}

/// Recursively walk `dir` and collect suppression entries into `out`.
///
/// `in_git_repo` is pre-computed to avoid repeated git subprocess spawning.
fn collect_suppressions_recursive(
    project_root: &Path,
    dir: &Path,
    in_git_repo: bool,
    out: &mut Vec<SuppressionEntry>,
) {
    let source_extensions = [
        "js", "ts", "jsx", "tsx", "py", "rb", "go", "java", "kt", "rs", "cs", "php", "c", "cpp",
        "h", "hpp", "swift", "scala", "sh", "bash",
    ];

    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };

    for entry in read_dir.filter_map(|e| e.ok()) {
        let path = entry.path();

        if path.is_dir() {
            // Skip well-known non-source directories
            if let Some(
                "node_modules" | ".git" | "target" | "dist" | "build" | "__pycache__" | ".venv"
                | "venv" | ".sicario",
            ) = path.file_name().and_then(|n| n.to_str())
            {
                continue;
            }
            collect_suppressions_recursive(project_root, &path, in_git_repo, out);
        } else if path.is_file() {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if !source_extensions.contains(&ext.as_str()) {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // Collect all suppression lines in this file first (avoids per-line git calls)
            let suppression_lines: Vec<(usize, String, String)> = content
                .lines()
                .enumerate()
                .filter(|(_, line)| line.contains("sicario-ignore"))
                .map(|(idx, line)| {
                    let line_number = idx + 1; // 1-indexed
                    let rule_id = extract_suppression_rule_id(line);
                    let comment_text = line.trim().to_string();
                    (line_number, rule_id, comment_text)
                })
                .collect();

            if suppression_lines.is_empty() {
                continue;
            }

            // Run git attribution once per file (not per line) for performance
            let (author_email, commit_sha, committed_at) = if in_git_repo {
                git_blame_line(project_root, &path, suppression_lines[0].0)
            } else {
                (
                    "untracked".to_string(),
                    "untracked".to_string(),
                    "untracked".to_string(),
                )
            };

            let relative_path = path
                .strip_prefix(project_root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");

            for (line_number, rule_id, comment_text) in suppression_lines {
                out.push(SuppressionEntry {
                    file: relative_path.clone(),
                    line: line_number,
                    rule_id,
                    comment_text,
                    author_email: author_email.clone(),
                    commit_sha: commit_sha.clone(),
                    committed_at: committed_at.clone(),
                });
            }
        }
    }
}

/// Extract the rule ID from a `sicario-ignore` comment.
///
/// Formats:
/// - `// sicario-ignore: js-sql-string-concat` → `"js-sql-string-concat"`
/// - `// sicario-ignore` (no rule) → `"all"`
fn extract_suppression_rule_id(line: &str) -> String {
    if let Some(pos) = line.find("sicario-ignore") {
        let after = &line[pos + "sicario-ignore".len()..];
        let after = after.trim_start_matches([':', ' ', '\t']);
        if after.is_empty() {
            return "all".to_string();
        }
        // Take the first whitespace-delimited token
        let token = after.split_whitespace().next().unwrap_or("all");
        if token.is_empty() {
            "all".to_string()
        } else {
            token.to_string()
        }
    } else {
        "all".to_string()
    }
}

/// Attempt to get git blame information for a specific line in a file.
///
/// Runs `git log -S "sicario-ignore" --follow --format="%ae %H %aI" -- <file>`
/// and returns `(author_email, commit_sha, committed_at)`.
/// Returns `("untracked", "untracked", "untracked")` on any failure.
fn git_blame_line(project_root: &Path, file_path: &Path, _line: usize) -> (String, String, String) {
    let untracked = || {
        (
            "untracked".to_string(),
            "untracked".to_string(),
            "untracked".to_string(),
        )
    };

    let output = std::process::Command::new("git")
        .args([
            "log",
            "-S",
            "sicario-ignore",
            "--follow",
            "--format=%ae %H %aI",
            "--",
            &file_path.to_string_lossy(),
        ])
        .current_dir(project_root)
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return untracked(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Take the most recent (first) log entry
    let first_line = stdout.lines().next().unwrap_or("").trim();
    if first_line.is_empty() {
        return untracked();
    }

    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return untracked();
    }

    (
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
    )
}

// ── MTTR computation ──────────────────────────────────────────────────────────

/// Compute per-rule MTTR from baseline history and remediation log.
///
/// Detection timestamp = earliest baseline in which a rule_id appears.
/// Fix timestamp = `applied_at` from the remediation log entry.
/// MTTR = mean of (fix_time - detection_time) in hours across all remediated
/// findings for a rule. Requires ≥ 3 remediated findings; otherwise
/// `mttr_hours` is `None`.
fn compute_mttr(
    baseline_history: &[BaselineSummary],
    remediation_log: &[RemediationEntry],
) -> Vec<MttrEntry> {
    use std::collections::HashMap;

    // Build a map of rule_id → earliest detection timestamp from baseline history.
    // BaselineSummary doesn't carry per-rule timestamps, so we use the baseline
    // timestamp as a proxy for when findings in that snapshot were first detected.
    // We approximate: for each rule_id in the remediation log, the detection time
    // is the timestamp of the oldest baseline (if any baselines exist).
    let earliest_baseline_ts: Option<chrono::DateTime<Utc>> =
        baseline_history.iter().map(|b| b.timestamp).min();

    // Group remediation entries by rule_id
    let mut by_rule: HashMap<String, Vec<&RemediationEntry>> = HashMap::new();
    for entry in remediation_log {
        by_rule
            .entry(entry.rule_id.clone())
            .or_default()
            .push(entry);
    }

    let mut result = Vec::new();

    for (rule_id, entries) in &by_rule {
        let findings_remediated = entries.len();

        // Compute MTTR hours for each remediated finding
        let mut mttr_samples: Vec<f64> = Vec::new();

        if let Some(detection_ts) = earliest_baseline_ts {
            for entry in entries {
                if let Ok(fix_ts) = chrono::DateTime::parse_from_rfc3339(&entry.applied_at) {
                    let fix_ts_utc: chrono::DateTime<Utc> = fix_ts.into();
                    let duration = fix_ts_utc.signed_duration_since(detection_ts);
                    let hours = duration.num_seconds() as f64 / 3600.0;
                    if hours >= 0.0 {
                        mttr_samples.push(hours);
                    }
                }
            }
        }

        let mttr_hours = if mttr_samples.len() >= 3 {
            let mean = mttr_samples.iter().sum::<f64>() / mttr_samples.len() as f64;
            Some(mean)
        } else {
            None
        };

        result.push(MttrEntry {
            rule_id: rule_id.clone(),
            vuln_class: String::new(), // not available without rule metadata
            severity: String::new(),   // not available without rule metadata
            findings_detected: findings_remediated, // best approximation
            findings_remediated,
            mttr_hours,
        });
    }

    // Sort by rule_id for deterministic output
    result.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    result
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate a full enterprise compliance report for `project_root`.
///
/// - Reads patch history from `.sicario/patch_history.json`.
/// - Scans source files for `sicario-ignore` directives.
/// - Loads baseline trend data from `.sicario/baselines/`.
/// - Computes per-rule MTTR.
/// - Writes the report to `.sicario/compliance-report-<timestamp>.json`.
///
/// Returns the populated `ComplianceReport`.
pub fn generate_compliance_report(project_root: &Path) -> Result<ComplianceReport> {
    let sicario_dir = project_root.join(".sicario");
    std::fs::create_dir_all(&sicario_dir)
        .with_context(|| format!("Failed to create .sicario dir: {}", sicario_dir.display()))?;

    // 1. Remediation log from BackupManager
    let backup_manager = BackupManager::new(project_root)?;
    let history = backup_manager.load_history()?;
    let remediation_log: Vec<RemediationEntry> =
        history.iter().map(RemediationEntry::from).collect();

    // 2. Suppression log from source file scan
    let suppression_log = scan_suppression_log(project_root);

    // 3. Baseline history from BaselineManager::trend()
    let baseline_manager = BaselineManager::new(project_root);
    let baseline_history = baseline_manager.trend().unwrap_or_default();

    // 4. Compute scan summary from most recent baseline (if available)
    let scan_summary = baseline_history
        .last()
        .map(|b| ComplianceScanSummary {
            total_findings: b.total_findings,
            critical_count: b.critical_count,
            high_count: b.high_count,
            medium_count: b.medium_count,
            low_count: b.low_count,
            info_count: b.info_count,
        })
        .unwrap_or_default();

    // 5. Compute MTTR
    let mttr_by_rule = compute_mttr(&baseline_history, &remediation_log);

    let report = ComplianceReport {
        generated_at: Utc::now().to_rfc3339(),
        sicario_version: env!("CARGO_PKG_VERSION").to_string(),
        scan_summary,
        remediation_log,
        suppression_log,
        baseline_history,
        mttr_by_rule,
    };

    // 6. Write JSON report
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let report_path = sicario_dir.join(format!("compliance-report-{}.json", timestamp));
    let json =
        serde_json::to_string_pretty(&report).context("Failed to serialize compliance report")?;
    std::fs::write(&report_path, &json).with_context(|| {
        format!(
            "Failed to write compliance report: {}",
            report_path.display()
        )
    })?;

    Ok(report)
}

/// Generate a compliance report and also write a SARIF file.
///
/// The SARIF file is written to `.sicario/compliance-report-<timestamp>.sarif`.
/// Since the compliance report does not carry live `Vulnerability` objects, the
/// SARIF output is generated from an empty findings list (structural compliance
/// evidence only). Callers that need finding-level SARIF should use
/// `output::sarif::emit_sarif` directly.
pub fn generate_compliance_report_with_sarif(project_root: &Path) -> Result<ComplianceReport> {
    let report = generate_compliance_report(project_root)?;

    let sicario_dir = project_root.join(".sicario");
    let timestamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let sarif_path = sicario_dir.join(format!("compliance-report-{}.sarif", timestamp));

    // Build a minimal SARIF document representing the compliance report metadata.
    use crate::output::sarif::emit_sarif;
    let sarif_doc = emit_sarif(&[], env!("CARGO_PKG_VERSION"));
    let sarif_json = serde_json::to_string_pretty(&sarif_doc)
        .context("Failed to serialize SARIF compliance report")?;
    std::fs::write(&sarif_path, &sarif_json)
        .with_context(|| format!("Failed to write SARIF report: {}", sarif_path.display()))?;

    Ok(report)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_temp_project() -> TempDir {
        TempDir::new().expect("failed to create temp dir")
    }

    // ── JSON round-trip ───────────────────────────────────────────────────────

    /// `ComplianceReport` JSON round-trip produces equivalent report with no data loss.
    #[test]
    fn test_compliance_report_json_round_trip() {
        let report = ComplianceReport {
            generated_at: "2024-01-01T00:00:00Z".to_string(),
            sicario_version: "1.0.0".to_string(),
            scan_summary: ComplianceScanSummary {
                total_findings: 5,
                critical_count: 1,
                high_count: 2,
                medium_count: 1,
                low_count: 1,
                info_count: 0,
            },
            remediation_log: vec![RemediationEntry {
                patch_id: "js-sql-string-concat-abc123".to_string(),
                applied_at: "2024-01-02T10:00:00Z".to_string(),
                file_path: PathBuf::from("src/db.js"),
                rule_id: "js-sql-string-concat".to_string(),
                template_used: "SqlAstRewriteTemplate".to_string(),
            }],
            suppression_log: vec![SuppressionEntry {
                file: "src/auth.js".to_string(),
                line: 42,
                rule_id: "hardcoded-secret".to_string(),
                comment_text: "// sicario-ignore: hardcoded-secret".to_string(),
                author_email: "dev@example.com".to_string(),
                commit_sha: "abc123def456".to_string(),
                committed_at: "2024-01-01T09:00:00Z".to_string(),
            }],
            baseline_history: vec![],
            mttr_by_rule: vec![MttrEntry {
                rule_id: "js-sql-string-concat".to_string(),
                vuln_class: "SQL Injection".to_string(),
                severity: "High".to_string(),
                findings_detected: 3,
                findings_remediated: 3,
                mttr_hours: Some(4.5),
            }],
        };

        let json = serde_json::to_string_pretty(&report).expect("serialize failed");
        let deserialized: ComplianceReport =
            serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(
            report, deserialized,
            "round-trip must produce identical report"
        );

        // Verify no data loss: all fields present in JSON
        assert!(json.contains("generated_at"));
        assert!(json.contains("sicario_version"));
        assert!(json.contains("scan_summary"));
        assert!(json.contains("remediation_log"));
        assert!(json.contains("suppression_log"));
        assert!(json.contains("baseline_history"));
        assert!(json.contains("mttr_by_rule"));
        assert!(json.contains("js-sql-string-concat"));
        assert!(json.contains("hardcoded-secret"));
        assert!(json.contains("dev@example.com"));
    }

    // ── Suppression log: untracked files ─────────────────────────────────────

    /// `suppression_log` records `"untracked"` for files with no git history.
    #[test]
    fn test_suppression_log_untracked_for_no_git_history() {
        let dir = make_temp_project();
        let project_root = dir.path();

        // Create a JS file with a sicario-ignore comment (outside any git repo)
        let src_dir = project_root.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(
            src_dir.join("auth.js"),
            "// sicario-ignore: hardcoded-secret\nconst secret = 'abc';\n",
        )
        .unwrap();

        let entries = scan_suppression_log(project_root);

        assert_eq!(entries.len(), 1, "should find exactly one suppression");
        let entry = &entries[0];
        assert_eq!(entry.rule_id, "hardcoded-secret");
        assert_eq!(entry.line, 1);
        // Since this is not a git repo, all git fields must be "untracked"
        assert_eq!(
            entry.author_email, "untracked",
            "author_email must be 'untracked' for non-git files"
        );
        assert_eq!(
            entry.commit_sha, "untracked",
            "commit_sha must be 'untracked' for non-git files"
        );
        assert_eq!(
            entry.committed_at, "untracked",
            "committed_at must be 'untracked' for non-git files"
        );
    }

    /// Blanket `sicario-ignore` (no rule ID) is recorded with rule_id `"all"`.
    #[test]
    fn test_suppression_log_blanket_suppression() {
        let dir = make_temp_project();
        let project_root = dir.path();

        let src_dir = project_root.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::write(
            src_dir.join("main.js"),
            "// sicario-ignore\nconst x = eval(input);\n",
        )
        .unwrap();

        let entries = scan_suppression_log(project_root);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rule_id, "all");
    }

    // ── Performance assertion ─────────────────────────────────────────────────

    /// Report generation completes within 10 seconds for ≤500 findings.
    ///
    /// This test creates a project with 500 suppression comments across 50 files
    /// and verifies the scan completes within the time budget.
    #[test]
    fn test_report_performance_500_findings() {
        let dir = make_temp_project();
        let project_root = dir.path();

        // Create .sicario dir
        std::fs::create_dir_all(project_root.join(".sicario")).unwrap();

        // Create 50 JS files each with 10 sicario-ignore comments
        let src_dir = project_root.join("src");
        std::fs::create_dir_all(&src_dir).unwrap();
        for i in 0..50 {
            let mut content = String::new();
            for j in 0..10 {
                content.push_str(&format!(
                    "// sicario-ignore: rule-{}\nconst x{} = {};\n",
                    j, j, j
                ));
            }
            std::fs::write(src_dir.join(format!("file{}.js", i)), &content).unwrap();
        }

        let start = std::time::Instant::now();
        let report = generate_compliance_report(project_root).expect("report generation failed");
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_secs() < 10,
            "report generation took {}s, must complete within 10s",
            elapsed.as_secs()
        );
        assert_eq!(
            report.suppression_log.len(),
            500,
            "should find 500 suppression entries"
        );
    }

    // ── Helper unit tests ─────────────────────────────────────────────────────

    #[test]
    fn test_extract_rule_id_from_patch_id_with_uuid_suffix() {
        let patch_id = "js-sql-string-concat-550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            extract_rule_id_from_patch_id(patch_id),
            "js-sql-string-concat"
        );
    }

    #[test]
    fn test_extract_rule_id_from_patch_id_plain_uuid() {
        let patch_id = "550e8400-e29b-41d4-a716-446655440000";
        // No prefix → returns full patch_id
        assert_eq!(extract_rule_id_from_patch_id(patch_id), patch_id);
    }

    #[test]
    fn test_extract_suppression_rule_id_with_colon() {
        assert_eq!(
            extract_suppression_rule_id("// sicario-ignore: hardcoded-secret"),
            "hardcoded-secret"
        );
    }

    #[test]
    fn test_extract_suppression_rule_id_blanket() {
        assert_eq!(extract_suppression_rule_id("// sicario-ignore"), "all");
    }

    #[test]
    fn test_extract_suppression_rule_id_with_trailing_comment() {
        assert_eq!(
            extract_suppression_rule_id("// sicario-ignore: sql-injection -- reviewed by security"),
            "sql-injection"
        );
    }
}
