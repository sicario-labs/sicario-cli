//! Diff-aware scanning — git2-based changed-line computation.
//!
//! Uses `git2` to compute which lines changed between the working tree and a
//! Git reference (commit, branch, tag). Also supports listing staged files for
//! the `--staged` flag.

use anyhow::{Context, Result};
use git2::{DiffOptions, Repository, StatusOptions};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Trait for diff-aware scanning operations.
pub trait DiffScanning {
    /// Compute the set of changed (added/modified) lines between the working
    /// tree and the given Git reference. Returns a map of file path → set of
    /// 1-indexed line numbers.
    fn changed_lines(&self, reference: &str) -> Result<HashMap<PathBuf, HashSet<usize>>>;

    /// List files that are currently staged in the Git index.
    fn staged_files(&self) -> Result<Vec<PathBuf>>;
}

/// Git2-backed implementation of [`DiffScanning`].
pub struct DiffScanner {
    repo: Repository,
}

impl DiffScanner {
    /// Open the Git repository that contains `working_dir`.
    ///
    /// Returns exit-code-2-style error if the path is not inside a Git repo.
    pub fn open(working_dir: &Path) -> Result<Self> {
        let repo = Repository::discover(working_dir).with_context(|| {
            format!(
                "Not a git repository (or any parent): {}. Exit code 2.",
                working_dir.display()
            )
        })?;
        Ok(Self { repo })
    }

    /// Resolve a reference string (branch name, tag, or commit SHA) to a
    /// `git2::Object` (commit). Branch names are resolved to their HEAD commit.
    fn resolve_reference(&self, reference: &str) -> Result<git2::Object<'_>> {
        // Try as a direct revision first (SHA, tag, branch)
        self.repo
            .revparse_single(reference)
            .with_context(|| format!("Git reference '{}' does not exist. Exit code 2.", reference))
    }
}

impl DiffScanning for DiffScanner {
    fn changed_lines(&self, reference: &str) -> Result<HashMap<PathBuf, HashSet<usize>>> {
        let obj = self.resolve_reference(reference)?;
        let commit = obj
            .peel_to_commit()
            .with_context(|| format!("Reference '{}' does not point to a commit", reference))?;
        let old_tree = commit.tree()?;

        let mut diff_opts = DiffOptions::new();
        diff_opts.include_untracked(false);

        // Diff: old_tree (reference) vs working directory
        let diff = self
            .repo
            .diff_tree_to_workdir_with_index(Some(&old_tree), Some(&mut diff_opts))?;

        let mut result: HashMap<PathBuf, HashSet<usize>> = HashMap::new();

        diff.foreach(
            &mut |_delta, _progress| true,
            None, // binary callback
            None, // hunk callback
            Some(&mut |delta, _hunk, line| {
                // We only care about added/modified lines in the new file
                if line.origin() == '+' {
                    if let Some(new_file) = delta.new_file().path() {
                        let path = PathBuf::from(new_file);
                        let line_no = line.new_lineno().unwrap_or(0) as usize;
                        if line_no > 0 {
                            result.entry(path).or_default().insert(line_no);
                        }
                    }
                }
                true
            }),
        )?;

        Ok(result)
    }

    fn staged_files(&self) -> Result<Vec<PathBuf>> {
        let mut status_opts = StatusOptions::new();
        status_opts.include_untracked(false);
        status_opts.include_ignored(false);

        let statuses = self.repo.statuses(Some(&mut status_opts))?;
        let mut files = Vec::new();

        for entry in statuses.iter() {
            let status = entry.status();
            // Include files that are staged (index changes)
            let is_staged = status.intersects(
                git2::Status::INDEX_NEW
                    | git2::Status::INDEX_MODIFIED
                    | git2::Status::INDEX_RENAMED
                    | git2::Status::INDEX_TYPECHANGE,
            );
            if is_staged {
                if let Some(path) = entry.path() {
                    files.push(PathBuf::from(path));
                }
            }
        }

        Ok(files)
    }
}

/// Filter a set of findings to only those on changed lines.
///
/// `changed` maps file paths to sets of 1-indexed line numbers that were
/// added or modified. Any finding whose `(file_path, line)` is not in the map
/// is excluded.
pub fn filter_findings_by_diff<F, P, L>(
    findings: Vec<F>,
    changed: &HashMap<PathBuf, HashSet<usize>>,
    file_path: P,
    line: L,
) -> Vec<F>
where
    P: Fn(&F) -> &PathBuf,
    L: Fn(&F) -> usize,
{
    findings
        .into_iter()
        .filter(|f| {
            changed
                .get(file_path(f))
                .is_some_and(|lines| lines.contains(&line(f)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_findings_by_diff_keeps_matching() {
        let mut changed = HashMap::new();
        changed.insert(PathBuf::from("src/main.rs"), {
            let mut s = HashSet::new();
            s.insert(10);
            s.insert(20);
            s
        });

        struct FakeFinding {
            path: PathBuf,
            line: usize,
        }

        let findings = vec![
            FakeFinding {
                path: PathBuf::from("src/main.rs"),
                line: 10,
            },
            FakeFinding {
                path: PathBuf::from("src/main.rs"),
                line: 15,
            },
            FakeFinding {
                path: PathBuf::from("src/main.rs"),
                line: 20,
            },
            FakeFinding {
                path: PathBuf::from("src/other.rs"),
                line: 10,
            },
        ];

        let filtered = filter_findings_by_diff(findings, &changed, |f| &f.path, |f| f.line);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].line, 10);
        assert_eq!(filtered[1].line, 20);
    }

    #[test]
    fn test_filter_findings_empty_changed() {
        let changed: HashMap<PathBuf, HashSet<usize>> = HashMap::new();

        struct FakeFinding {
            path: PathBuf,
            line: usize,
        }

        let findings = vec![FakeFinding {
            path: PathBuf::from("src/main.rs"),
            line: 10,
        }];

        let filtered = filter_findings_by_diff(findings, &changed, |f| &f.path, |f| f.line);
        assert!(filtered.is_empty());
    }
}
