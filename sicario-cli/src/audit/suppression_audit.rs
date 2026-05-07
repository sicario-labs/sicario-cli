//! Suppression audit log.
//!
//! Scans all source files for sicario-ignore directives and attributes each
//! one to a git commit using `git blame --porcelain`.
//!
//! Design: Area 6.4  Suppression Audit Log

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

//  Data Model

/// A single suppression directive found in a source file, with git attribution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SuppressionAuditEntry {
    /// Relative path to the source file.
    pub file: String,
    /// 1-indexed line number of the suppression comment.
    pub line: usize,
    /// Rule ID being suppressed (`"all"` for blanket suppressions).
    pub rule_id: String,
    /// Full text of the suppression comment line.
    pub comment_text: String,
    /// Author email from git blame, or `"untracked"` if no git history.
    pub author_email: String,
    /// Commit SHA from git blame, or `"untracked"` if no git history.
    pub commit_sha: String,
    /// ISO 8601 commit timestamp, or `"untracked"` if no git history.
    pub committed_at: String,
}

//  Source file extensions to scan

const SOURCE_EXTENSIONS: &[&str] = &[
    "js", "ts", "jsx", "tsx", "py", "rb", "go", "java", "kt", "rs", "cs", "php", "c", "cpp", "h",
    "hpp", "swift", "scala", "sh", "bash",
];

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    "target",
    "dist",
    "build",
    "__pycache__",
    ".venv",
    "venv",
    ".sicario",
];

//  Git helpers

/// Check whether `project_root` is inside a git repository.
fn is_git_repo(project_root: &Path) -> bool {
    std::process::Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .current_dir(project_root)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `git blame --porcelain -L <line>,<line> <file>` and extract
/// `(author_email, commit_sha, committed_at)`.
///
/// Returns `("untracked", "untracked", "untracked")` on any failure.
fn git_blame_porcelain(
    project_root: &Path,
    file_path: &Path,
    line: usize,
) -> (String, String, String) {
    let untracked = || {
        (
            "untracked".to_string(),
            "untracked".to_string(),
            "untracked".to_string(),
        )
    };

    let line_range = format!("{},{}", line, line);
    let file_str = file_path.to_string_lossy();

    let output = std::process::Command::new("git")
        .args(["blame", "--porcelain", "-L", &line_range, &file_str])
        .current_dir(project_root)
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return untracked(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_porcelain_blame(&stdout)
}

/// Parse the output of `git blame --porcelain` and extract
/// `(author_email, commit_sha, committed_at)`.
///
/// Porcelain format (first block):
/// ```text
/// <commit-sha> <orig-line> <final-line> <num-lines>
/// author <name>
/// author-mail <email>
/// author-time <unix-timestamp>
/// author-tz <tz>
/// committer <name>
/// committer-mail <email>
/// committer-time <unix-timestamp>
/// committer-tz <tz>
/// summary <message>
/// ...
/// ```
fn parse_porcelain_blame(output: &str) -> (String, String, String) {
    let untracked = || {
        (
            "untracked".to_string(),
            "untracked".to_string(),
            "untracked".to_string(),
        )
    };

    let mut lines = output.lines();

    // First line: "<sha> <orig-line> <final-line> [<num-lines>]"
    let first = match lines.next() {
        Some(l) => l,
        None => return untracked(),
    };
    let commit_sha = match first.split_whitespace().next() {
        Some(sha) if sha.len() >= 7 => sha.to_string(),
        _ => return untracked(),
    };

    // Check for "not committed yet" (all-zeros SHA)
    if commit_sha.chars().all(|c| c == '0') {
        return untracked();
    }

    let mut author_email = String::new();
    let mut author_time: Option<i64> = None;
    let mut author_tz = String::new();

    for line in lines {
        if let Some(email) = line.strip_prefix("author-mail ") {
            // Strip angle brackets: <email@example.com>  email@example.com
            author_email = email
                .trim()
                .trim_start_matches('<')
                .trim_end_matches('>')
                .to_string();
        } else if let Some(ts) = line.strip_prefix("author-time ") {
            author_time = ts.trim().parse::<i64>().ok();
        } else if let Some(tz) = line.strip_prefix("author-tz ") {
            author_tz = tz.trim().to_string();
        }
    }

    if author_email.is_empty() {
        return untracked();
    }

    // Convert unix timestamp + tz to ISO 8601
    let committed_at = if let Some(ts) = author_time {
        use chrono::TimeZone;
        let dt = chrono::Utc.timestamp_opt(ts, 0).single();
        match dt {
            Some(dt) => {
                // Apply timezone offset if available (e.g. "+0200")
                if author_tz.len() == 5 {
                    let sign = if author_tz.starts_with('-') {
                        -1i64
                    } else {
                        1i64
                    };
                    let hours: i64 = author_tz[1..3].parse().unwrap_or(0);
                    let mins: i64 = author_tz[3..5].parse().unwrap_or(0);
                    let offset_secs = sign * (hours * 3600 + mins * 60);
                    let local_ts = ts + offset_secs;
                    let local_dt = chrono::Utc.timestamp_opt(local_ts, 0).single();
                    match local_dt {
                        Some(ldt) => ldt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                        None => dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                    }
                } else {
                    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
                }
            }
            None => "untracked".to_string(),
        }
    } else {
        "untracked".to_string()
    };

    (author_email, commit_sha, committed_at)
}

//  Suppression directive extraction

/// Extract the rule ID from a line containing a `sicario-ignore` directive.
///
/// - `// sicario-ignore: js-sql-string-concat`  `"js-sql-string-concat"`
/// - `// sicario-ignore-next-line`  `"all"`
/// - `// sicario-ignore`  `"all"`
fn extract_rule_id(line: &str) -> String {
    // Rule-specific: sicario-ignore:<rule-id>
    if let Some(pos) = line.find("sicario-ignore:") {
        let after = &line[pos + "sicario-ignore:".len()..];
        let token = after.split_whitespace().next().unwrap_or("").trim();
        if !token.is_empty() {
            return token.to_string();
        }
    }
    // sicario-ignore-next-line  blanket
    if line.contains("sicario-ignore-next-line") {
        return "all".to_string();
    }
    // sicario-ignore (blanket, but not sicario-ignore-secret)
    if line.contains("sicario-ignore") && !line.contains("sicario-ignore-secret") {
        return "all".to_string();
    }
    "all".to_string()
}

/// Check whether a line contains a SAST suppression directive (not the legacy
/// secret-scanner directive).
fn is_suppression_line(line: &str) -> bool {
    (line.contains("sicario-ignore") || line.contains("sicario-ignore-next-line"))
        && !line.contains("sicario-ignore-secret")
}

//  Core collection

/// Scan all source files under `project_root` for suppression directives and
/// return a `SuppressionAuditEntry` for each one, with git attribution.
pub fn collect_suppression_audit(project_root: &Path) -> Result<Vec<SuppressionAuditEntry>> {
    let in_git_repo = is_git_repo(project_root);
    let mut entries = Vec::new();
    collect_recursive(project_root, project_root, in_git_repo, &mut entries);
    Ok(entries)
}

fn collect_recursive(
    project_root: &Path,
    dir: &Path,
    in_git_repo: bool,
    out: &mut Vec<SuppressionAuditEntry>,
) {
    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };

    for entry in read_dir.filter_map(|e| e.ok()) {
        let path = entry.path();

        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if SKIP_DIRS.contains(&name) {
                    continue;
                }
            }
            collect_recursive(project_root, &path, in_git_repo, out);
        } else if path.is_file() {
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();
            if !SOURCE_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let relative_path = path
                .strip_prefix(project_root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");

            for (idx, line) in content.lines().enumerate() {
                if !is_suppression_line(line) {
                    continue;
                }

                let line_number = idx + 1; // 1-indexed
                let rule_id = extract_rule_id(line);
                let comment_text = line.trim().to_string();

                let (author_email, commit_sha, committed_at) = if in_git_repo {
                    git_blame_porcelain(project_root, &path, line_number)
                } else {
                    (
                        "untracked".to_string(),
                        "untracked".to_string(),
                        "untracked".to_string(),
                    )
                };

                out.push(SuppressionAuditEntry {
                    file: relative_path.clone(),
                    line: line_number,
                    rule_id,
                    comment_text,
                    author_email,
                    commit_sha,
                    committed_at,
                });
            }
        }
    }
}

//  Filtering

/// Filter entries by `--since` (committed_at after date) and `--author`
/// (author_email matches).
///
/// `since` is an ISO 8601 date string (e.g. `"2024-01-01"` or
/// `"2024-01-01T00:00:00Z"`). Entries with `committed_at == "untracked"` are
/// excluded when a `--since` filter is active.
pub fn filter_entries(
    entries: Vec<SuppressionAuditEntry>,
    since: Option<&str>,
    author: Option<&str>,
) -> Vec<SuppressionAuditEntry> {
    let since_dt: Option<chrono::DateTime<chrono::Utc>> = since.and_then(|s| {
        // Try RFC 3339 first
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
            return Some(dt.with_timezone(&chrono::Utc));
        }
        // Try date-only (YYYY-MM-DD)
        if let Ok(date) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
            use chrono::TimeZone;
            return Some(chrono::Utc.from_utc_datetime(&date.and_hms_opt(0, 0, 0).unwrap()));
        }
        None
    });

    entries
        .into_iter()
        .filter(|e| {
            // --since filter
            if let Some(ref cutoff) = since_dt {
                if e.committed_at == "untracked" {
                    return false;
                }
                match chrono::DateTime::parse_from_rfc3339(&e.committed_at) {
                    Ok(dt) => {
                        if dt.with_timezone(&chrono::Utc) <= *cutoff {
                            return false;
                        }
                    }
                    Err(_) => return false,
                }
            }
            // --author filter
            if let Some(email) = author {
                if !e.author_email.eq_ignore_ascii_case(email) {
                    return false;
                }
            }
            true
        })
        .collect()
}

//  Output rendering

/// Render entries as a JSON array string.
pub fn render_json(entries: &[SuppressionAuditEntry]) -> Result<String> {
    serde_json::to_string_pretty(entries).context("Failed to serialize suppression audit to JSON")
}

/// Render entries as CSV with headers.
///
/// Headers: `file,line,rule_id,comment,author_email,commit_sha,committed_at`
pub fn render_csv(entries: &[SuppressionAuditEntry]) -> String {
    let mut out = String::from("file,line,rule_id,comment,author_email,commit_sha,committed_at\n");
    for e in entries {
        // Escape fields that may contain commas or quotes
        out.push_str(&csv_field(&e.file));
        out.push(',');
        out.push_str(&e.line.to_string());
        out.push(',');
        out.push_str(&csv_field(&e.rule_id));
        out.push(',');
        out.push_str(&csv_field(&e.comment_text));
        out.push(',');
        out.push_str(&csv_field(&e.author_email));
        out.push(',');
        out.push_str(&csv_field(&e.commit_sha));
        out.push(',');
        out.push_str(&csv_field(&e.committed_at));
        out.push('\n');
    }
    out
}

/// Wrap a CSV field in double quotes if it contains commas, quotes, or newlines.
fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Write output to a file, appending if it already exists.
pub fn write_output(path: &str, content: &str) -> Result<()> {
    use std::fs::OpenOptions;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("Failed to open output file: {}", path))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("Failed to write to output file: {}", path))?;
    Ok(())
}

//  Tests

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn make_temp_project() -> TempDir {
        TempDir::new().expect("failed to create temp dir")
    }

    fn write_file(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    //  Directive detection

    /// Detects all three suppression directive forms.
    #[test]
    fn test_detects_all_three_directive_forms() {
        let dir = make_temp_project();
        let root = dir.path();

        write_file(
            root,
            "src/test.js",
            "// sicario-ignore\nconst a = 1;\n\
             // sicario-ignore-next-line\nconst b = 2;\n\
             // sicario-ignore:sql-injection\nconst c = 3;\n",
        );

        let entries = collect_suppression_audit(root).unwrap();
        assert_eq!(entries.len(), 3, "should detect all three directive forms");

        let rule_ids: Vec<&str> = entries.iter().map(|e| e.rule_id.as_str()).collect();
        assert!(
            rule_ids.contains(&"all"),
            "blanket sicario-ignore should have rule_id 'all'"
        );
        assert!(
            rule_ids.contains(&"sql-injection"),
            "rule-specific directive should have correct rule_id"
        );
        // sicario-ignore-next-line is also "all"
        assert_eq!(rule_ids.iter().filter(|&&r| r == "all").count(), 2);
    }

    /// `"untracked"` for files with no git history.
    #[test]
    fn test_untracked_for_no_git_history() {
        let dir = make_temp_project();
        let root = dir.path();

        write_file(
            root,
            "src/auth.js",
            "// sicario-ignore: hardcoded-secret\nconst secret = 'abc';\n",
        );

        let entries = collect_suppression_audit(root).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.author_email, "untracked");
        assert_eq!(e.commit_sha, "untracked");
        assert_eq!(e.committed_at, "untracked");
    }

    //  Filtering

    /// `--since` filter works correctly.
    #[test]
    fn test_since_filter() {
        let entries = vec![
            SuppressionAuditEntry {
                file: "a.js".to_string(),
                line: 1,
                rule_id: "all".to_string(),
                comment_text: "// sicario-ignore".to_string(),
                author_email: "dev@example.com".to_string(),
                commit_sha: "abc123".to_string(),
                committed_at: "2024-06-01T00:00:00Z".to_string(),
            },
            SuppressionAuditEntry {
                file: "b.js".to_string(),
                line: 1,
                rule_id: "all".to_string(),
                comment_text: "// sicario-ignore".to_string(),
                author_email: "dev@example.com".to_string(),
                commit_sha: "def456".to_string(),
                committed_at: "2024-01-01T00:00:00Z".to_string(),
            },
            SuppressionAuditEntry {
                file: "c.js".to_string(),
                line: 1,
                rule_id: "all".to_string(),
                comment_text: "// sicario-ignore".to_string(),
                author_email: "dev@example.com".to_string(),
                commit_sha: "ghi789".to_string(),
                committed_at: "untracked".to_string(),
            },
        ];

        // Filter: only entries after 2024-03-01
        let filtered = filter_entries(entries, Some("2024-03-01"), None);
        assert_eq!(
            filtered.len(),
            1,
            "only the June entry should pass the since filter"
        );
        assert_eq!(filtered[0].file, "a.js");
    }

    /// `--author` filter works correctly.
    #[test]
    fn test_author_filter() {
        let entries = vec![
            SuppressionAuditEntry {
                file: "a.js".to_string(),
                line: 1,
                rule_id: "all".to_string(),
                comment_text: "// sicario-ignore".to_string(),
                author_email: "alice@example.com".to_string(),
                commit_sha: "abc123".to_string(),
                committed_at: "2024-06-01T00:00:00Z".to_string(),
            },
            SuppressionAuditEntry {
                file: "b.js".to_string(),
                line: 1,
                rule_id: "all".to_string(),
                comment_text: "// sicario-ignore".to_string(),
                author_email: "bob@example.com".to_string(),
                commit_sha: "def456".to_string(),
                committed_at: "2024-06-02T00:00:00Z".to_string(),
            },
        ];

        let filtered = filter_entries(entries, None, Some("alice@example.com"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].file, "a.js");
    }

    //  Output: append mode

    /// `--output` appends to existing file.
    #[test]
    fn test_output_appends_to_existing_file() {
        let dir = make_temp_project();
        let output_path = dir.path().join("audit.csv");

        // Write initial content
        std::fs::write(&output_path, "existing content\n").unwrap();

        let new_content = "new line\n";
        write_output(output_path.to_str().unwrap(), new_content).unwrap();

        let result = std::fs::read_to_string(&output_path).unwrap();
        assert!(
            result.starts_with("existing content\n"),
            "original content must be preserved"
        );
        assert!(
            result.ends_with("new line\n"),
            "new content must be appended"
        );
        assert_eq!(result, "existing content\nnew line\n");
    }

    //  Performance assertion

    /// Completes within 10 seconds for 500 suppressions.
    #[test]
    fn test_performance_500_suppressions() {
        let dir = make_temp_project();
        let root = dir.path();
        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();

        // 50 files  10 suppressions = 500 total
        for i in 0..50 {
            let mut content = String::new();
            for j in 0..10 {
                content.push_str(&format!(
                    "// sicario-ignore: rule-{}\nconst x{} = {};\n",
                    j, j, j
                ));
            }
            std::fs::write(src.join(format!("file{}.js", i)), &content).unwrap();
        }

        let start = std::time::Instant::now();
        let entries = collect_suppression_audit(root).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(entries.len(), 500, "should find 500 suppression entries");
        assert!(
            elapsed.as_secs() < 10,
            "audit took {}s, must complete within 10s",
            elapsed.as_secs()
        );
    }

    //  CSV rendering

    #[test]
    fn test_csv_has_correct_headers() {
        let entries: Vec<SuppressionAuditEntry> = vec![];
        let csv = render_csv(&entries);
        assert!(csv.starts_with("file,line,rule_id,comment,author_email,commit_sha,committed_at\n"));
    }

    #[test]
    fn test_csv_renders_entry() {
        let entries = vec![SuppressionAuditEntry {
            file: "src/db.js".to_string(),
            line: 42,
            rule_id: "sql-injection".to_string(),
            comment_text: "// sicario-ignore:sql-injection".to_string(),
            author_email: "dev@example.com".to_string(),
            commit_sha: "abc123".to_string(),
            committed_at: "2024-01-01T00:00:00Z".to_string(),
        }];
        let csv = render_csv(&entries);
        assert!(csv.contains("src/db.js"));
        assert!(csv.contains("42"));
        assert!(csv.contains("sql-injection"));
        assert!(csv.contains("dev@example.com"));
    }

    //  JSON rendering

    #[test]
    fn test_json_round_trip() {
        let entries = vec![SuppressionAuditEntry {
            file: "src/db.js".to_string(),
            line: 42,
            rule_id: "sql-injection".to_string(),
            comment_text: "// sicario-ignore:sql-injection".to_string(),
            author_email: "dev@example.com".to_string(),
            commit_sha: "abc123".to_string(),
            committed_at: "2024-01-01T00:00:00Z".to_string(),
        }];
        let json = render_json(&entries).unwrap();
        let deserialized: Vec<SuppressionAuditEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(entries, deserialized);
    }

    //  Porcelain blame parser

    #[test]
    fn test_parse_porcelain_blame_valid() {
        let output = "abc123def456abc123def456abc123def456abc1 1 1 1\n\
                      author Test User\n\
                      author-mail <test@example.com>\n\
                      author-time 1704067200\n\
                      author-tz +0000\n\
                      committer Test User\n\
                      committer-mail <test@example.com>\n\
                      committer-time 1704067200\n\
                      committer-tz +0000\n\
                      summary Initial commit\n";
        let (email, sha, ts) = parse_porcelain_blame(output);
        assert_eq!(email, "test@example.com");
        assert_eq!(sha, "abc123def456abc123def456abc123def456abc1");
        assert!(!ts.is_empty());
        assert_ne!(ts, "untracked");
    }

    #[test]
    fn test_parse_porcelain_blame_untracked_zeros() {
        let output = "0000000000000000000000000000000000000000 1 1 1\n\
                      author Not Committed Yet\n\
                      author-mail <not.committed.yet>\n";
        let (email, sha, ts) = parse_porcelain_blame(output);
        assert_eq!(email, "untracked");
        assert_eq!(sha, "untracked");
        assert_eq!(ts, "untracked");
    }

    #[test]
    fn test_parse_porcelain_blame_empty() {
        let (email, sha, ts) = parse_porcelain_blame("");
        assert_eq!(email, "untracked");
        assert_eq!(sha, "untracked");
        assert_eq!(ts, "untracked");
    }
}
