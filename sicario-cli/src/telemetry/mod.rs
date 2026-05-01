//! Telemetry helpers — local computation of contributor metrics.
//!
//! All data computed here is aggregated before transmission. No author names,
//! email addresses, or commit messages are included in any return value or
//! telemetry payload field.
//!
//! Requirements: 1.3 (per-contributing-developer seat counting)

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

/// Count the number of unique contributing developers in the last 90 days.
///
/// Runs `git log --since="90 days ago" --format=%ae` in `repo_path` and
/// counts distinct email addresses using a `HashSet`. Only the integer count
/// is returned — no author names, emails, or commit messages are exposed.
///
/// Returns `1` as a safe default when:
/// - `repo_path` is not a Git repository
/// - `git` is not installed or not on `PATH`
/// - The command exits with a non-zero status
///
/// Returns `0` when the repository exists but has no commits in the last 90 days.
pub fn count_contributors(repo_path: &Path) -> u32 {
    let output = Command::new("git")
        .args(["log", "--since=90 days ago", "--format=%ae"])
        .current_dir(repo_path)
        .output();

    match output {
        Err(_) => {
            // git not found or could not be spawned
            1
        }
        Ok(out) if !out.status.success() => {
            // Non-zero exit — check if this is an empty repo (no commits yet)
            // vs. a directory that is not a git repository at all.
            // `git log` in an empty repo exits 128 with a message like
            // "does not have any commits yet", whereas a non-repo exits 128
            // with "not a git repository".
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("does not have any commits") {
                // Empty repo — 0 contributors, not the fallback
                0
            } else {
                // Not a git repo or other git error — safe default
                1
            }
        }
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let unique: HashSet<&str> = stdout
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect();
            unique.len() as u32
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The current workspace is a real Git repository with recent commits, so
    /// `count_contributors` should return at least 1.
    #[test]
    fn test_count_contributors_real_repo() {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let count = count_contributors(&workspace_root);
        // We can't assert an exact number, but a real repo must return >= 1.
        assert!(
            count >= 1,
            "expected at least 1 contributor in the workspace repo, got {count}"
        );
    }

    /// A non-git directory (e.g. /tmp) should return the safe default of 1.
    #[test]
    fn test_count_contributors_non_git_directory() {
        let tmp = std::env::temp_dir();
        let count = count_contributors(&tmp);
        // /tmp is not a git repo, so we expect the fallback value of 1.
        assert_eq!(
            count, 1,
            "expected fallback value 1 for non-git directory, got {count}"
        );
    }

    /// A freshly-initialised empty git repo has no commits, so the 90-day
    /// window returns 0 unique contributors.
    #[test]
    fn test_count_contributors_empty_repo() {
        use std::fs;

        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let repo_path = tmp.path();

        // Initialise a bare git repo with no commits.
        let init_status = Command::new("git")
            .args(["init"])
            .current_dir(repo_path)
            .output();

        match init_status {
            Err(_) => {
                // git not available in this environment — skip the test.
                return;
            }
            Ok(out) if !out.status.success() => {
                // git init failed — skip.
                return;
            }
            Ok(_) => {}
        }

        let count = count_contributors(repo_path);
        // No commits → 0 unique contributors (not the fallback 1, because git
        // ran successfully and returned an empty log).
        assert_eq!(
            count, 0,
            "expected 0 contributors in an empty repo, got {count}"
        );
    }
}
