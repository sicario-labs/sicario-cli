//! FP Corpus Manager — clone or reference the 10 false-positive corpus
//! repositories to a local cache directory for scanning.
//!
//! Repositories are shallow-cloned (depth 1) to `.sicario/fp-corpus/<name>/`
//! inside the project root. If a clone already exists it is reused without
//! re-fetching, making repeated runs fast and idempotent.
//!
//! Requirement: Req 2 — False-Positive Corpus (Task 2.1)

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use super::fp_corpus::{FpCorpusRepo, FP_CORPUS_REPOS};

// ── Status types ─────────────────────────────────────────────────────────────

/// The outcome of a single corpus repo preparation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusRepoStatus {
    /// Repository was freshly cloned from GitHub.
    Cloned,
    /// Repository already existed locally; clone was skipped.
    AlreadyPresent,
    /// Clone failed; the error message is included.
    Failed(String),
}

/// Result of preparing a single FP corpus repository.
#[derive(Debug, Clone)]
pub struct CorpusRepoResult {
    pub repo: &'static FpCorpusRepo,
    pub local_path: PathBuf,
    pub status: CorpusRepoStatus,
}

impl CorpusRepoResult {
    /// Returns `true` when the repo is available for scanning (cloned or
    /// already present).
    pub fn is_available(&self) -> bool {
        matches!(
            self.status,
            CorpusRepoStatus::Cloned | CorpusRepoStatus::AlreadyPresent
        )
    }
}

// ── CorpusManager ─────────────────────────────────────────────────────────────

/// Manages the local cache of FP corpus repositories.
///
/// The cache lives at `<project_root>/.sicario/fp-corpus/`.  Each repository
/// is stored in a subdirectory named after its `FpCorpusRepo::name` field
/// (e.g. `express`, `django`, `next.js`).
pub struct CorpusManager {
    /// Root directory of the project (parent of `.sicario/`).
    project_root: PathBuf,
}

impl CorpusManager {
    /// Create a new `CorpusManager` rooted at `project_root`.
    pub fn new(project_root: &Path) -> Self {
        Self {
            project_root: project_root.to_path_buf(),
        }
    }

    /// Returns the base directory where all corpus repos are cached.
    ///
    /// `<project_root>/.sicario/fp-corpus/`
    pub fn corpus_base_dir(&self) -> PathBuf {
        self.project_root.join(".sicario").join("fp-corpus")
    }

    /// Returns the expected local path for a single corpus repo.
    pub fn repo_local_path(&self, repo: &FpCorpusRepo) -> PathBuf {
        self.corpus_base_dir().join(repo.name)
    }

    /// Prepare all 10 FP corpus repositories.
    ///
    /// For each repo:
    /// - If the local directory already contains a `.git` folder, it is
    ///   considered present and the clone is skipped.
    /// - Otherwise a shallow clone (`depth = 1`) is attempted via `git2`.
    ///
    /// Returns one `CorpusRepoResult` per repo.  Failures are recorded but do
    /// not abort the remaining repos.
    pub fn prepare_all(&self) -> Vec<CorpusRepoResult> {
        let base = self.corpus_base_dir();
        if let Err(e) = std::fs::create_dir_all(&base) {
            // If we can't even create the base dir, mark everything as failed.
            return FP_CORPUS_REPOS
                .iter()
                .map(|repo| CorpusRepoResult {
                    repo,
                    local_path: base.join(repo.name),
                    status: CorpusRepoStatus::Failed(format!(
                        "could not create corpus base dir: {e}"
                    )),
                })
                .collect();
        }

        FP_CORPUS_REPOS
            .iter()
            .map(|repo| self.prepare_one(repo))
            .collect()
    }

    /// Prepare a single FP corpus repository.
    ///
    /// Returns immediately with `AlreadyPresent` if the repo directory already
    /// contains a `.git` folder.  Otherwise performs a shallow clone.
    pub fn prepare_one(&self, repo: &'static FpCorpusRepo) -> CorpusRepoResult {
        let local_path = self.repo_local_path(repo);

        // Already present — skip clone.
        if local_path.join(".git").exists() {
            return CorpusRepoResult {
                repo,
                local_path,
                status: CorpusRepoStatus::AlreadyPresent,
            };
        }

        // Attempt shallow clone.
        match self.shallow_clone(repo, &local_path) {
            Ok(()) => CorpusRepoResult {
                repo,
                local_path,
                status: CorpusRepoStatus::Cloned,
            },
            Err(e) => CorpusRepoResult {
                repo,
                local_path,
                status: CorpusRepoStatus::Failed(e.to_string()),
            },
        }
    }

    /// Perform a shallow clone (depth 1) of `repo` into `dest`.
    ///
    /// Tries `git2::build::RepoBuilder` first for zero-dependency operation.
    /// If that fails (common on Windows where libgit2 shallow clone support
    /// has known issues with certain large repos), falls back to the system
    /// `git` CLI which handles these correctly.
    fn shallow_clone(&self, repo: &FpCorpusRepo, dest: &Path) -> Result<()> {
        // Ensure the parent directory exists.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent dir for {}", dest.display()))?;
        }

        // Remove a partial/corrupt clone directory if it exists but has no .git.
        if dest.exists() && !dest.join(".git").exists() {
            std::fs::remove_dir_all(dest)
                .with_context(|| format!("remove partial clone at {}", dest.display()))?;
        }

        // ── Try 1: git2 (libgit2) ────────────────────────────────────────────
        let git2_result = self.shallow_clone_git2(repo, dest);
        if git2_result.is_ok() {
            return Ok(());
        }

        // Clean up any partial git2 attempt before falling back.
        if dest.exists() {
            let _ = std::fs::remove_dir_all(dest);
        }

        // ── Try 2: system git CLI fallback ───────────────────────────────────
        eprintln!(
            "\r[fp-corpus] git2 failed for {}, trying system git…",
            repo.display_name
        );
        self.shallow_clone_cli(repo, dest)
    }

    /// Shallow clone via git2 (libgit2).
    fn shallow_clone_git2(&self, repo: &FpCorpusRepo, dest: &Path) -> Result<()> {
        use git2::build::RepoBuilder;
        use git2::{FetchOptions, RemoteCallbacks};

        let mut callbacks = RemoteCallbacks::new();
        // Progress callback — prints to stderr so CI logs show activity.
        callbacks.transfer_progress(|stats| {
            if stats.received_objects() == stats.total_objects() {
                eprint!(
                    "\r[fp-corpus] Resolving deltas {}/{}…",
                    stats.indexed_deltas(),
                    stats.total_deltas()
                );
            } else if stats.total_objects() > 0 {
                eprint!(
                    "\r[fp-corpus] Receiving objects: {}% ({}/{})…",
                    (100 * stats.received_objects()) / stats.total_objects(),
                    stats.received_objects(),
                    stats.total_objects()
                );
            }
            true
        });

        let mut fetch_opts = FetchOptions::new();
        fetch_opts.remote_callbacks(callbacks);
        // Shallow clone: depth 1 — only the latest commit on the default branch.
        fetch_opts.depth(1);

        RepoBuilder::new()
            .fetch_options(fetch_opts)
            .clone(repo.url, dest)
            .with_context(|| {
                format!(
                    "shallow clone of '{}' ({}) into '{}' failed",
                    repo.display_name,
                    repo.url,
                    dest.display()
                )
            })?;

        eprintln!(); // newline after progress output
        Ok(())
    }

    /// Shallow clone via the system `git` binary.
    ///
    /// Falls back here when git2 fails (e.g. libgit2 shallow-clone bugs on
    /// Windows). Requires `git` to be on PATH.
    fn shallow_clone_cli(&self, repo: &FpCorpusRepo, dest: &Path) -> Result<()> {
        let status = std::process::Command::new("git")
            .args([
                "clone",
                "--depth",
                "1",
                "--single-branch",
                repo.url,
                &dest.to_string_lossy(),
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .status()
            .with_context(|| {
                format!(
                    "failed to run `git clone` for '{}' — is git installed?",
                    repo.display_name
                )
            })?;

        // Git writes progress to stderr (which we inherit), and exits 0 on
        // success. Exit code 128 is common for auth/network/path issues.
        if !status.success() {
            // Double-check: maybe git succeeded but returned non-zero due to
            // a warning. If .git exists in dest, treat it as success.
            if dest.join(".git").exists() {
                return Ok(());
            }
            anyhow::bail!(
                "git clone --depth 1 of '{}' ({}) into '{}' failed with exit code {:?}",
                repo.display_name,
                repo.url,
                dest.display(),
                status.code()
            );
        }

        Ok(())
    }

    /// Returns the local paths of all repos that are currently available
    /// (already cloned).  Does not attempt any network operations.
    pub fn available_repos(&self) -> Vec<(&FpCorpusRepo, PathBuf)> {
        FP_CORPUS_REPOS
            .iter()
            .filter_map(|repo| {
                let path = self.repo_local_path(repo);
                if path.join(".git").exists() {
                    Some((repo, path))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns `true` if all 10 corpus repos are present locally.
    pub fn all_present(&self) -> bool {
        FP_CORPUS_REPOS
            .iter()
            .all(|repo| self.repo_local_path(repo).join(".git").exists())
    }
}

// ── Display helpers ───────────────────────────────────────────────────────────

/// Print a human-readable preparation summary to stderr.
pub fn print_preparation_summary(results: &[CorpusRepoResult]) {
    let cloned: Vec<_> = results
        .iter()
        .filter(|r| r.status == CorpusRepoStatus::Cloned)
        .collect();
    let present: Vec<_> = results
        .iter()
        .filter(|r| r.status == CorpusRepoStatus::AlreadyPresent)
        .collect();
    let failed: Vec<_> = results
        .iter()
        .filter(|r| matches!(r.status, CorpusRepoStatus::Failed(_)))
        .collect();

    eprintln!(
        "[fp-corpus] {} cloned, {} already present, {} failed",
        cloned.len(),
        present.len(),
        failed.len()
    );

    for r in &cloned {
        eprintln!("  ✓ cloned   {}", r.repo.display_name);
    }
    for r in &present {
        eprintln!("  ✓ present  {}", r.repo.display_name);
    }
    for r in &failed {
        if let CorpusRepoStatus::Failed(ref msg) = r.status {
            eprintln!("  ✗ failed   {} — {}", r.repo.display_name, msg);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_manager() -> (CorpusManager, TempDir) {
        let tmp = TempDir::new().unwrap();
        let mgr = CorpusManager::new(tmp.path());
        (mgr, tmp)
    }

    #[test]
    fn corpus_base_dir_is_under_sicario() {
        let (mgr, tmp) = make_manager();
        let base = mgr.corpus_base_dir();
        assert!(base.starts_with(tmp.path()));
        // The last two components should be ".sicario" and "fp-corpus"
        let mut components = base.components().rev();
        assert_eq!(components.next().unwrap().as_os_str(), "fp-corpus");
        assert_eq!(components.next().unwrap().as_os_str(), ".sicario");
    }

    #[test]
    fn repo_local_path_uses_repo_name() {
        let (mgr, _tmp) = make_manager();
        let repo = &FP_CORPUS_REPOS[0]; // express
        let path = mgr.repo_local_path(repo);
        assert_eq!(path.file_name().unwrap(), "express");
    }

    #[test]
    fn available_repos_empty_when_nothing_cloned() {
        let (mgr, _tmp) = make_manager();
        assert!(mgr.available_repos().is_empty());
    }

    #[test]
    fn all_present_false_when_nothing_cloned() {
        let (mgr, _tmp) = make_manager();
        assert!(!mgr.all_present());
    }

    #[test]
    fn prepare_one_already_present_when_git_dir_exists() {
        let (mgr, _tmp) = make_manager();
        let repo = &FP_CORPUS_REPOS[0]; // express
        let local = mgr.repo_local_path(repo);
        std::fs::create_dir_all(local.join(".git")).unwrap();

        let result = mgr.prepare_one(repo);
        assert_eq!(result.status, CorpusRepoStatus::AlreadyPresent);
        assert!(result.is_available());
        assert_eq!(result.local_path, local);
    }

    #[test]
    fn prepare_one_already_present_django() {
        let (mgr, _tmp) = make_manager();
        let repo = &FP_CORPUS_REPOS[1]; // django
        let local = mgr.repo_local_path(repo);
        std::fs::create_dir_all(local.join(".git")).unwrap();

        let result = mgr.prepare_one(repo);
        assert_eq!(result.status, CorpusRepoStatus::AlreadyPresent);
        assert!(result.is_available());
    }

    #[test]
    fn prepare_all_returns_ten_results() {
        // Seed all 10 repos as already-present so no network calls are made.
        let (mgr, _tmp) = make_manager();
        for repo in FP_CORPUS_REPOS {
            let local = mgr.repo_local_path(repo);
            std::fs::create_dir_all(local.join(".git")).unwrap();
        }

        let results = mgr.prepare_all();
        assert_eq!(results.len(), 10);
        assert!(results.iter().all(|r| r.is_available()));
    }

    #[test]
    fn all_present_true_when_all_git_dirs_exist() {
        let (mgr, _tmp) = make_manager();
        for repo in FP_CORPUS_REPOS {
            let local = mgr.repo_local_path(repo);
            std::fs::create_dir_all(local.join(".git")).unwrap();
        }
        assert!(mgr.all_present());
    }

    #[test]
    fn available_repos_returns_only_present_repos() {
        let (mgr, _tmp) = make_manager();
        // Seed only the first 3 repos.
        for repo in &FP_CORPUS_REPOS[..3] {
            let local = mgr.repo_local_path(repo);
            std::fs::create_dir_all(local.join(".git")).unwrap();
        }
        let available = mgr.available_repos();
        assert_eq!(available.len(), 3);
    }

    #[test]
    fn corpus_repo_result_is_available_for_cloned_and_present() {
        let tmp = TempDir::new().unwrap();
        let repo = &FP_CORPUS_REPOS[0];
        let path = tmp.path().join(repo.name);

        let cloned = CorpusRepoResult {
            repo,
            local_path: path.clone(),
            status: CorpusRepoStatus::Cloned,
        };
        assert!(cloned.is_available());

        let present = CorpusRepoResult {
            repo,
            local_path: path.clone(),
            status: CorpusRepoStatus::AlreadyPresent,
        };
        assert!(present.is_available());

        let failed = CorpusRepoResult {
            repo,
            local_path: path,
            status: CorpusRepoStatus::Failed("network error".to_string()),
        };
        assert!(!failed.is_available());
    }

    #[test]
    fn prepare_all_fails_gracefully_when_base_dir_cannot_be_created() {
        // Point the project root at a non-existent deeply nested path that
        // cannot be created (simulate by using a file as a path component).
        let tmp = TempDir::new().unwrap();
        // Create a file where we'd want a directory — this blocks dir creation.
        let blocker = tmp.path().join("blocker");
        std::fs::write(&blocker, b"not a dir").unwrap();
        // Use the file as if it were a directory — create_dir_all will fail.
        let mgr = CorpusManager::new(&blocker);
        // The base dir would be blocker/.sicario/fp-corpus — can't create it.
        let results = mgr.prepare_all();
        // All 10 results should be Failed.
        assert_eq!(results.len(), 10);
        assert!(results
            .iter()
            .all(|r| matches!(r.status, CorpusRepoStatus::Failed(_))));
    }
}
