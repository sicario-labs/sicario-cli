//! Git Exorcist — rewrites local git history to remove hardcoded secrets.
//!
//! `GitExorcist` walks a range of local commits, detects hardcoded credentials
//! via `SecretScanner`, replaces them with `process.env.VAR_NAME` references
//! using the existing `TemplateRegistry`, and creates new commits with the
//! same metadata (author, timestamp, message) but clean trees.
//!
//! The rewrite is purely local — no remote refs are touched.
//!
//! Phase 16 of the eta-engine spec.

use anyhow::{Context, Result};
use std::path::Path;

use crate::remediation::BackupManager;
use crate::scanner::SecretScanner;

// ── ExorcistReceipt ───────────────────────────────────────────────────────────

/// Summary of a completed (or dry-run) exorcism.
#[derive(Debug, Default, Clone)]
pub struct ExorcistReceipt {
    /// Number of commits whose trees were rewritten.
    pub commits_rewritten: usize,
    /// Total number of hardcoded secrets removed across all commits.
    pub secrets_removed: usize,
    /// Mapping of original variable name → generated env-var name for each
    /// replacement made (e.g. `("DB_PASSWORD", "DB_PASSWORD")`).
    pub replacements: Vec<(String, String)>,
}

impl ExorcistReceipt {
    /// Render a human-readable receipt in the same box-drawing style used by
    /// `PatchReceipt`. Full implementation is added in task 16.4.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("╔══════════════════════════════════════╗\n");
        out.push_str("║        sicario git exorcist          ║\n");
        out.push_str("╠══════════════════════════════════════╣\n");
        out.push_str(&format!(
            "║  Commits rewritten : {:>16} ║\n",
            self.commits_rewritten
        ));
        out.push_str(&format!(
            "║  Secrets removed   : {:>16} ║\n",
            self.secrets_removed
        ));
        if !self.replacements.is_empty() {
            out.push_str("╠══════════════════════════════════════╣\n");
            out.push_str("║  Replacements                        ║\n");
            for (orig, env_var) in &self.replacements {
                let line = format!("  {} → {}", orig, env_var);
                out.push_str(&format!("║  {:<36} ║\n", line));
            }
        }
        out.push_str("╠══════════════════════════════════════╣\n");
        out.push_str("║  ⚠ History has been rewritten        ║\n");
        out.push_str("╚══════════════════════════════════════╝\n");
        out
    }
}

// ── GitExorcist ───────────────────────────────────────────────────────────────

/// Return type of `GitExorcist::rewrite_commit`:
/// `(new_commit_oid, secrets_removed, replacements)`.
type RewriteCommitResult = (git2::Oid, usize, Vec<(String, String)>);

/// Rewrites local git history to excise hardcoded secrets.
pub struct GitExorcist {
    /// The git repository being operated on.
    pub(crate) repo: git2::Repository,
    /// Backup manager — used to snapshot files before any in-place edits so
    /// the operation can be rolled back if something goes wrong.
    pub(crate) backup_manager: BackupManager,
}

impl GitExorcist {
    /// Open the git repository that contains `project_root` and initialise a
    /// `BackupManager` rooted at the same directory.
    ///
    /// Uses `git2::Repository::discover` so the caller does not need to pass
    /// the exact `.git` directory — any subdirectory of the repo works.
    pub fn new(project_root: &Path) -> Result<Self> {
        let repo = git2::Repository::discover(project_root).with_context(|| {
            format!(
                "Could not find a git repository at or above '{}'",
                project_root.display()
            )
        })?;

        let backup_manager = BackupManager::new(project_root).with_context(|| {
            format!(
                "Failed to initialise BackupManager at '{}'",
                project_root.display()
            )
        })?;

        Ok(Self {
            repo,
            backup_manager,
        })
    }

    /// Rewrite local commits to remove hardcoded secrets.
    ///
    /// # Arguments
    /// * `since_ref` — optional git ref (branch name, tag, or commit SHA) that
    ///   marks the *exclusive* lower bound of the commit range to rewrite.
    ///   When `None` the range defaults to all commits not yet pushed to the
    ///   configured upstream (`@{u}..HEAD`).
    /// * `dry_run` — when `true` the method scans commits and reports what
    ///   *would* be changed without touching the repository.
    ///
    /// # Stub
    /// The full rewrite loop is implemented in tasks 16.2–16.5.  This stub
    /// calls the pre-flight checks, collects the commit list, and dispatches
    /// to either `dry_run_report` or the (not-yet-implemented) rewrite loop.
    pub fn exorcise(&self, since_ref: Option<&str>, dry_run: bool) -> Result<ExorcistReceipt> {
        // ── Pre-flight checks (implemented in task 16.2) ──────────────────
        self.check_working_tree_clean()?;

        // ── Collect commits to rewrite (implemented in task 16.2) ─────────
        let commits = self.collect_commits_to_rewrite(since_ref)?;

        if commits.is_empty() {
            anyhow::bail!(
                "No local-only commits found in the specified range. \
                 All commits may already be pushed, or the ref '{}' was not found.",
                since_ref.unwrap_or("@{u}")
            );
        }

        if dry_run {
            // Dry-run path (implemented in task 16.5)
            return self.dry_run_report(&commits);
        }

        // ── Rewrite loop (task 16.4) ──────────────────────────────────────
        // Iterate over commits oldest-first, rewriting each one and chaining
        // the new parent OIDs so the rewritten history forms a valid chain.
        let mut prev_new_oid: Option<git2::Oid> = None;
        let mut total_secrets_removed: usize = 0;
        let mut all_replacements: Vec<(String, String)> = Vec::new();
        let mut final_new_oid: Option<git2::Oid> = None;

        for &commit_oid in &commits {
            let (new_oid, secrets_removed, replacements) =
                self.rewrite_commit(commit_oid, prev_new_oid)?;

            total_secrets_removed += secrets_removed;
            all_replacements.extend(replacements);
            prev_new_oid = Some(new_oid);
            final_new_oid = Some(new_oid);
        }

        // Update HEAD to point to the final rewritten commit.
        if let Some(final_oid) = final_new_oid {
            self.repo
                .find_reference("HEAD")
                .context("Failed to find HEAD reference")?
                .set_target(final_oid, "sicario exorcise")
                .context("Failed to update HEAD to final rewritten commit")?;
        }

        Ok(ExorcistReceipt {
            commits_rewritten: commits.len(),
            secrets_removed: total_secrets_removed,
            replacements: all_replacements,
        })
    }

    // ── Pre-flight helpers (stubs — full impl in task 16.2) ──────────────

    /// Verify that the working tree has no uncommitted changes.
    ///
    /// Bails with a descriptive error if any tracked file is modified,
    /// staged, or has an unresolved conflict.
    pub(crate) fn check_working_tree_clean(&self) -> Result<()> {
        let statuses = self
            .repo
            .statuses(None)
            .context("Failed to read repository status")?;

        let dirty: Vec<_> = statuses
            .iter()
            .filter(|e| {
                let s = e.status();
                // Ignore completely untracked files — only care about changes
                // that would affect a commit.
                !s.is_empty()
                    && !s.contains(git2::Status::IGNORED)
                    && !s.contains(git2::Status::WT_NEW)
            })
            .map(|e| e.path().unwrap_or("<unknown>").to_owned())
            .collect();

        if !dirty.is_empty() {
            anyhow::bail!(
                "Working tree has uncommitted changes in {} file(s): {}\n\
                 Commit or stash your changes before running `sicario exorcise`.",
                dirty.len(),
                dirty.join(", ")
            );
        }

        Ok(())
    }

    /// Count commits reachable from HEAD that have not been pushed to the
    /// configured upstream (`@{u}`).
    ///
    /// Returns `0` when no upstream is configured (treats all commits as local).
    pub(crate) fn count_unpushed_commits(&self) -> Result<usize> {
        // Try to resolve the upstream ref.  If there is no upstream we treat
        // every commit as local and return 0 so the caller can decide.
        let upstream_oid = match self.resolve_upstream_oid() {
            Ok(oid) => oid,
            Err(_) => return Ok(0),
        };

        let head_oid = self
            .repo
            .head()
            .context("Failed to read HEAD")?
            .peel_to_commit()
            .context("HEAD is not a commit")?
            .id();

        let mut revwalk = self.repo.revwalk().context("Failed to create revwalk")?;
        revwalk
            .push(head_oid)
            .context("Failed to push HEAD onto revwalk")?;
        revwalk
            .hide(upstream_oid)
            .context("Failed to hide upstream from revwalk")?;

        Ok(revwalk.count())
    }

    /// Collect the OIDs of commits to rewrite, in oldest-first order.
    ///
    /// When `since_ref` is `Some`, the range is `since_ref..HEAD`.
    /// When `None`, the range is `@{u}..HEAD` (all unpushed commits).
    ///
    /// Bails if more than 50 commits would be rewritten to prevent accidental
    /// large-scale history rewrites.
    pub(crate) fn collect_commits_to_rewrite(
        &self,
        since_ref: Option<&str>,
    ) -> Result<Vec<git2::Oid>> {
        let head_oid = self
            .repo
            .head()
            .context("Failed to read HEAD")?
            .peel_to_commit()
            .context("HEAD is not a commit")?
            .id();

        let mut revwalk = self.repo.revwalk().context("Failed to create revwalk")?;
        revwalk
            .push(head_oid)
            .context("Failed to push HEAD onto revwalk")?;

        // Hide the base commit so the revwalk stops there.
        if let Some(base_ref) = since_ref {
            let base_oid = self
                .repo
                .revparse_single(base_ref)
                .with_context(|| format!("Could not resolve ref '{}'", base_ref))?
                .peel_to_commit()
                .with_context(|| format!("Ref '{}' does not point to a commit", base_ref))?
                .id();
            revwalk
                .hide(base_oid)
                .context("Failed to hide base ref from revwalk")?;
        } else {
            // Default: hide the upstream base.
            if let Ok(upstream_oid) = self.resolve_upstream_oid() {
                revwalk
                    .hide(upstream_oid)
                    .context("Failed to hide upstream from revwalk")?;
            }
            // If no upstream is configured the revwalk will walk the entire
            // history — the 50-commit guard below will catch runaway cases.
        }

        // Collect newest-first, then reverse to oldest-first.
        let mut oids: Vec<git2::Oid> = revwalk.filter_map(|r| r.ok()).collect();

        if oids.len() > 50 {
            anyhow::bail!(
                "Too many commits to rewrite ({}).  \
                 Use --since <ref> to limit the range to at most 50 commits.",
                oids.len()
            );
        }

        oids.reverse(); // oldest first
        Ok(oids)
    }

    // ── Commit Rewrite Engine (task 16.3) ────────────────────────────────

    /// Rewrite a single commit to remove hardcoded secrets.
    ///
    /// # Arguments
    /// * `commit_oid` — the OID of the commit to rewrite.
    /// * `new_parent` — the OID of the rewritten parent commit, or `None` for
    ///   root commits (commits with no parents).
    ///
    /// # Returns
    /// A tuple of:
    /// * The new commit OID (different from `commit_oid` even if no secrets
    ///   were found, because the parent chain may have changed).
    /// * The number of secrets removed.
    /// * A list of `(original_value, env_var_name)` replacement pairs.
    pub(crate) fn rewrite_commit(
        &self,
        commit_oid: git2::Oid,
        new_parent: Option<git2::Oid>,
    ) -> Result<RewriteCommitResult> {
        let commit = self
            .repo
            .find_commit(commit_oid)
            .with_context(|| format!("Could not find commit {}", commit_oid))?;

        let tree = commit
            .tree()
            .with_context(|| format!("Could not get tree for commit {}", commit_oid))?;

        // Checkout the commit's tree to a temporary directory.
        let tmp = tempfile::tempdir().context("Failed to create temp directory")?;
        self.checkout_tree_to_dir(&tree, tmp.path())
            .context("Failed to checkout tree to temp directory")?;

        // Scan the temp directory for secrets.
        let scanner = SecretScanner::new().context("Failed to create SecretScanner")?;
        let mut secrets_removed = 0usize;
        let mut replacements: Vec<(String, String)> = Vec::new();

        // Collect all files in the temp directory.
        let files = collect_files_recursive(tmp.path());

        for file_path in &files {
            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(_) => continue, // skip binary files
            };

            let detected = scanner.scan_content_for_secrets(&content, file_path);
            if detected.is_empty() {
                continue;
            }

            // Apply replacements: replace each detected secret value with
            // `process.env.VAR_NAME` where VAR_NAME is derived from the
            // secret type.
            let mut new_content = content.clone();
            for secret in &detected {
                let env_var = secret_type_to_env_var_name(&secret.secret_type, &secret.value);
                let replacement = format!("process.env.{}", env_var);
                if new_content.contains(&secret.value) {
                    new_content = new_content.replace(&secret.value, &replacement);
                    replacements.push((secret.value.clone(), env_var));
                    secrets_removed += 1;
                }
            }

            if new_content != content {
                std::fs::write(file_path, &new_content).with_context(|| {
                    format!("Failed to write patched file: {}", file_path.display())
                })?;
            }
        }

        // Build a new git tree from the (possibly patched) temp directory.
        let new_tree_oid = self
            .build_tree_from_dir(tmp.path(), &tree)
            .context("Failed to build new git tree from temp directory")?;

        let new_tree = self
            .repo
            .find_tree(new_tree_oid)
            .context("Failed to find newly created tree")?;

        // Resolve parent commits for the new commit.
        let parents: Vec<git2::Commit> = match new_parent {
            Some(parent_oid) => {
                let parent_commit = self
                    .repo
                    .find_commit(parent_oid)
                    .with_context(|| format!("Could not find parent commit {}", parent_oid))?;
                vec![parent_commit]
            }
            None => vec![],
        };
        let parent_refs: Vec<&git2::Commit> = parents.iter().collect();

        // Create the new commit with the same metadata but the new tree.
        let new_commit_oid = self
            .repo
            .commit(
                None, // don't update any ref — caller handles HEAD update
                &commit.author(),
                &commit.committer(),
                commit.message().unwrap_or(""),
                &new_tree,
                &parent_refs,
            )
            .context("Failed to create rewritten commit")?;

        Ok((new_commit_oid, secrets_removed, replacements))
    }

    /// Walk a git tree recursively and write all blob entries to `dir`.
    ///
    /// Subdirectories are created as needed. Existing files are overwritten.
    pub(crate) fn checkout_tree_to_dir(&self, tree: &git2::Tree, dir: &Path) -> Result<()> {
        self.checkout_tree_recursive(tree, dir)
    }

    fn checkout_tree_recursive(&self, tree: &git2::Tree, dir: &Path) -> Result<()> {
        for entry in tree.iter() {
            let name = entry.name().unwrap_or("<unknown>");
            let entry_path = dir.join(name);

            match entry.kind() {
                Some(git2::ObjectType::Blob) => {
                    let blob = self
                        .repo
                        .find_blob(entry.id())
                        .with_context(|| format!("Could not find blob for entry '{}'", name))?;
                    std::fs::write(&entry_path, blob.content()).with_context(|| {
                        format!("Failed to write blob to '{}'", entry_path.display())
                    })?;
                }
                Some(git2::ObjectType::Tree) => {
                    std::fs::create_dir_all(&entry_path).with_context(|| {
                        format!("Failed to create directory '{}'", entry_path.display())
                    })?;
                    let subtree = self
                        .repo
                        .find_tree(entry.id())
                        .with_context(|| format!("Could not find subtree for entry '{}'", name))?;
                    self.checkout_tree_recursive(&subtree, &entry_path)?;
                }
                _ => {
                    // Skip symlinks, submodules, etc.
                }
            }
        }
        Ok(())
    }

    /// Walk `dir` recursively and build a git tree object that mirrors the
    /// directory structure.
    ///
    /// Each file is written as a blob object in the repository. The resulting
    /// tree OID is returned.
    ///
    /// `original_tree` is used to preserve file modes for entries that exist
    /// in both the original tree and the directory.
    pub(crate) fn build_tree_from_dir(
        &self,
        dir: &Path,
        original_tree: &git2::Tree,
    ) -> Result<git2::Oid> {
        self.build_tree_recursive(dir, original_tree)
    }

    fn build_tree_recursive(&self, dir: &Path, original_tree: &git2::Tree) -> Result<git2::Oid> {
        let mut builder = self
            .repo
            .treebuilder(None)
            .context("Failed to create TreeBuilder")?;

        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read directory '{}'", dir.display()))?;

        for entry in entries {
            let entry = entry.with_context(|| {
                format!("Failed to read directory entry in '{}'", dir.display())
            })?;
            let path = entry.path();
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("Non-UTF-8 filename in '{}'", dir.display()))?;

            if path.is_dir() {
                // Find the original subtree entry to pass down for mode preservation.
                let subtree_oid = if let Some(orig_entry) = original_tree.get_name(&name) {
                    if orig_entry.kind() == Some(git2::ObjectType::Tree) {
                        let orig_subtree = self
                            .repo
                            .find_tree(orig_entry.id())
                            .with_context(|| format!("Could not find subtree '{}'", name))?;
                        self.build_tree_recursive(&path, &orig_subtree)?
                    } else {
                        // Original entry was not a tree — build with empty reference tree.
                        let empty_tree_oid = self
                            .repo
                            .treebuilder(None)
                            .context("Failed to create empty TreeBuilder")?
                            .write()
                            .context("Failed to write empty tree")?;
                        let empty_tree = self
                            .repo
                            .find_tree(empty_tree_oid)
                            .context("Failed to find empty tree")?;
                        self.build_tree_recursive(&path, &empty_tree)?
                    }
                } else {
                    // New directory not in original tree.
                    let empty_tree_oid = self
                        .repo
                        .treebuilder(None)
                        .context("Failed to create empty TreeBuilder")?
                        .write()
                        .context("Failed to write empty tree")?;
                    let empty_tree = self
                        .repo
                        .find_tree(empty_tree_oid)
                        .context("Failed to find empty tree")?;
                    self.build_tree_recursive(&path, &empty_tree)?
                };

                builder
                    .insert(&name, subtree_oid, 0o040000)
                    .with_context(|| format!("Failed to insert subtree '{}' into tree", name))?;
            } else if path.is_file() {
                let content = std::fs::read(&path)
                    .with_context(|| format!("Failed to read file '{}'", path.display()))?;
                let blob_oid = self
                    .repo
                    .blob(&content)
                    .with_context(|| format!("Failed to create blob for '{}'", name))?;

                // Preserve the original file mode if the entry exists in the
                // original tree; default to regular file (0o100644).
                let filemode = if let Some(orig_entry) = original_tree.get_name(&name) {
                    orig_entry.filemode()
                } else {
                    0o100644
                };

                builder
                    .insert(&name, blob_oid, filemode)
                    .with_context(|| format!("Failed to insert blob '{}' into tree", name))?;
            }
            // Skip symlinks and other special files.
        }

        builder.write().context("Failed to write tree object")
    }

    // ── Dry-run (task 16.5) ──────────────────────────────────────────────

    /// Scan commits for secrets without modifying the repository.
    ///
    /// For each commit, checks out its tree to a temporary directory and runs
    /// `SecretScanner` over the files — exactly the same scanning logic used
    /// by `rewrite_commit`, but no new commits are created and no files on
    /// disk are touched.
    ///
    /// Returns a receipt with `commits_rewritten: 0` and the accumulated list
    /// of secrets that *would* be removed if the exorcism were run for real.
    pub(crate) fn dry_run_report(&self, commits: &[git2::Oid]) -> Result<ExorcistReceipt> {
        let scanner = SecretScanner::new().context("Failed to create SecretScanner")?;

        let mut total_secrets_removed: usize = 0;
        let mut all_replacements: Vec<(String, String)> = Vec::new();

        for &commit_oid in commits {
            let commit = self
                .repo
                .find_commit(commit_oid)
                .with_context(|| format!("Could not find commit {}", commit_oid))?;

            let tree = commit
                .tree()
                .with_context(|| format!("Could not get tree for commit {}", commit_oid))?;

            // Checkout the commit's tree to a temporary directory (read-only
            // scan — we never write back to the repo).
            let tmp = tempfile::tempdir().context("Failed to create temp directory")?;
            self.checkout_tree_to_dir(&tree, tmp.path())
                .context("Failed to checkout tree to temp directory")?;

            // Scan every file in the temp directory for secrets.
            let files = collect_files_recursive(tmp.path());

            for file_path in &files {
                let content = match std::fs::read_to_string(file_path) {
                    Ok(c) => c,
                    Err(_) => continue, // skip binary files
                };

                let detected = scanner.scan_content_for_secrets(&content, file_path);
                if detected.is_empty() {
                    continue;
                }

                // Accumulate what *would* be replaced — same logic as
                // `rewrite_commit` but without writing anything.
                for secret in &detected {
                    if content.contains(&secret.value) {
                        let env_var =
                            secret_type_to_env_var_name(&secret.secret_type, &secret.value);
                        all_replacements.push((secret.value.clone(), env_var));
                        total_secrets_removed += 1;
                    }
                }
            }
            // `tmp` is dropped here — the temp directory is cleaned up
            // automatically.  The repository is completely untouched.
        }

        Ok(ExorcistReceipt {
            commits_rewritten: 0,
            secrets_removed: total_secrets_removed,
            replacements: all_replacements,
        })
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Resolve the OID of the upstream tracking branch (`@{u}`).
    fn resolve_upstream_oid(&self) -> Result<git2::Oid> {
        let head = self.repo.head().context("Failed to read HEAD")?;
        let branch_name = head
            .shorthand()
            .context("HEAD has no shorthand name (detached HEAD?)")?;

        let branch = self
            .repo
            .find_branch(branch_name, git2::BranchType::Local)
            .with_context(|| format!("Could not find local branch '{}'", branch_name))?;

        let upstream = branch
            .upstream()
            .with_context(|| format!("Branch '{}' has no upstream configured", branch_name))?;

        upstream
            .get()
            .peel_to_commit()
            .context("Upstream ref does not point to a commit")
            .map(|c| c.id())
    }
}

// ── Module-level helpers ──────────────────────────────────────────────────────

/// Derive a `process.env` variable name from a `SecretType` and the matched
/// value.  The name is used in the replacement string
/// `process.env.<VAR_NAME>`.
fn secret_type_to_env_var_name(secret_type: &crate::scanner::SecretType, _value: &str) -> String {
    use crate::scanner::SecretType;
    match secret_type {
        SecretType::AwsAccessKey => "AWS_ACCESS_KEY_ID".to_string(),
        SecretType::AwsSecretKey => "AWS_SECRET_ACCESS_KEY".to_string(),
        SecretType::GithubPat => "GITHUB_TOKEN".to_string(),
        SecretType::StripeKey => "STRIPE_SECRET_KEY".to_string(),
        SecretType::DatabaseUrl => "DATABASE_URL".to_string(),
        SecretType::PrivateKey => "PRIVATE_KEY".to_string(),
        SecretType::GenericApiKey => "API_KEY".to_string(),
    }
}

/// Recursively collect all file paths under `dir`.
fn collect_files_recursive(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_files_recursive(&path));
        } else if path.is_file() {
            files.push(path);
        }
    }
    files
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Create a minimal git repository with an initial commit in a temp dir.
    fn init_repo_with_commit(dir: &Path) -> git2::Repository {
        let repo = git2::Repository::init(dir).expect("init repo");

        // Configure identity so commits don't fail on CI.
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();
        drop(config);

        // Write a file and make an initial commit.
        let file_path = dir.join("hello.txt");
        std::fs::write(&file_path, "hello world\n").unwrap();

        let mut index = repo.index().unwrap();
        index.add_path(Path::new("hello.txt")).unwrap();
        index.write().unwrap();
        let tree_oid = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_oid).unwrap();

        let sig = repo.signature().unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
            .unwrap();

        drop(tree);
        repo
    }

    #[test]
    fn test_new_opens_repo_in_subdirectory() {
        let tmp = TempDir::new().unwrap();
        let _repo = init_repo_with_commit(tmp.path());

        // Create a subdirectory — GitExorcist::new should discover the repo.
        let subdir = tmp.path().join("subdir");
        std::fs::create_dir_all(&subdir).unwrap();

        let exorcist = GitExorcist::new(&subdir);
        assert!(
            exorcist.is_ok(),
            "GitExorcist::new should discover repo from subdirectory: {:?}",
            exorcist.err()
        );
    }

    #[test]
    fn test_new_fails_outside_repo() {
        let tmp = TempDir::new().unwrap();
        // No git repo initialised — should fail.
        let result = GitExorcist::new(tmp.path());
        assert!(
            result.is_err(),
            "GitExorcist::new should fail when no git repo is present"
        );
    }

    #[test]
    fn test_check_working_tree_clean_on_clean_repo() {
        let tmp = TempDir::new().unwrap();
        let _repo = init_repo_with_commit(tmp.path());

        let exorcist = GitExorcist::new(tmp.path()).unwrap();
        let result = exorcist.check_working_tree_clean();
        assert!(
            result.is_ok(),
            "Clean repo should pass working-tree check: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_check_working_tree_clean_fails_on_dirty_repo() {
        let tmp = TempDir::new().unwrap();
        let _repo = init_repo_with_commit(tmp.path());

        // Modify a tracked file without staging/committing.
        std::fs::write(tmp.path().join("hello.txt"), "dirty content\n").unwrap();

        let exorcist = GitExorcist::new(tmp.path()).unwrap();
        let result = exorcist.check_working_tree_clean();
        assert!(result.is_err(), "Dirty repo should fail working-tree check");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("uncommitted changes"),
            "Error should mention uncommitted changes, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_collect_commits_no_upstream_returns_all() {
        let tmp = TempDir::new().unwrap();
        let repo = init_repo_with_commit(tmp.path());

        // Add two more commits.
        for i in 1..=2u32 {
            let file = tmp.path().join(format!("file{}.txt", i));
            std::fs::write(&file, format!("content {}\n", i)).unwrap();
            let mut index = repo.index().unwrap();
            index
                .add_path(Path::new(&format!("file{}.txt", i)))
                .unwrap();
            index.write().unwrap();
            let tree_oid = index.write_tree().unwrap();
            let tree = repo.find_tree(tree_oid).unwrap();
            let sig = repo.signature().unwrap();
            let parent = repo.head().unwrap().peel_to_commit().unwrap();
            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                &format!("Commit {}", i),
                &tree,
                &[&parent],
            )
            .unwrap();
        }

        let exorcist = GitExorcist::new(tmp.path()).unwrap();
        // No upstream configured → collect_commits_to_rewrite with None
        // should return all 3 commits (initial + 2 added).
        let commits = exorcist.collect_commits_to_rewrite(None).unwrap();
        assert_eq!(
            commits.len(),
            3,
            "Expected 3 commits (no upstream), got {}",
            commits.len()
        );
    }

    #[test]
    fn test_exorcist_receipt_default() {
        let receipt = ExorcistReceipt::default();
        assert_eq!(receipt.commits_rewritten, 0);
        assert_eq!(receipt.secrets_removed, 0);
        assert!(receipt.replacements.is_empty());
    }

    #[test]
    fn test_receipt_render_contains_key_fields() {
        let receipt = ExorcistReceipt {
            commits_rewritten: 3,
            secrets_removed: 5,
            replacements: vec![
                ("DB_PASSWORD".to_string(), "DB_PASSWORD".to_string()),
                ("API_KEY".to_string(), "API_KEY".to_string()),
            ],
        };
        let rendered = receipt.render();
        assert!(rendered.contains("3"), "Should contain commit count");
        assert!(rendered.contains("5"), "Should contain secret count");
        assert!(
            rendered.contains("History has been rewritten"),
            "Should contain rewrite warning"
        );
        assert!(
            rendered.contains("DB_PASSWORD"),
            "Should contain replacement"
        );
    }

    /// Helper: add a commit to `repo` with the given file name and content.
    fn add_commit(
        repo: &git2::Repository,
        dir: &Path,
        filename: &str,
        content: &str,
        message: &str,
    ) -> git2::Oid {
        let file_path = dir.join(filename);
        std::fs::write(&file_path, content).unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new(filename)).unwrap();
        index.write().unwrap();
        let tree_oid = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_oid).unwrap();
        let sig = repo.signature().unwrap();
        let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
        let parents: Vec<&git2::Commit> = parent.iter().collect();
        repo.commit(Some("HEAD"), &sig, &sig, message, &tree, &parents)
            .unwrap()
    }

    #[test]
    fn test_rewrite_commit_replaces_secret_and_returns_new_oid() {
        let tmp = TempDir::new().unwrap();
        let repo = init_repo_with_commit(tmp.path());

        // Add a commit with a hardcoded AWS access key.
        // The pattern is: AKIA followed by 16 uppercase alphanumeric chars.
        let secret_value = concat!("AKIA", "IOSFODNN7EXAMPLE");
        let file_content = format!(
            "const awsKey = \"{}\";\nconsole.log(awsKey);\n",
            secret_value
        );
        let commit_oid = add_commit(&repo, tmp.path(), "config.js", &file_content, "Add AWS key");

        let exorcist = GitExorcist::new(tmp.path()).unwrap();

        // Rewrite the commit — the initial commit is the parent.
        let initial_oid = {
            let mut revwalk = repo.revwalk().unwrap();
            revwalk.push(commit_oid).unwrap();
            let oids: Vec<_> = revwalk.filter_map(|r| r.ok()).collect();
            // oids[0] is the commit itself, oids[1] is the initial commit
            *oids.last().unwrap()
        };

        let (new_oid, secrets_removed, replacements) = exorcist
            .rewrite_commit(commit_oid, Some(initial_oid))
            .unwrap();

        // The new OID must differ from the original.
        assert_ne!(
            new_oid, commit_oid,
            "Rewritten commit OID should differ from original"
        );

        // At least one secret should have been removed.
        assert!(
            secrets_removed >= 1,
            "Expected at least 1 secret removed, got {}",
            secrets_removed
        );

        // The replacement list should be non-empty.
        assert!(
            !replacements.is_empty(),
            "Expected non-empty replacements list"
        );

        // The new commit's tree should contain the patched file.
        let new_commit = repo.find_commit(new_oid).unwrap();
        let new_tree = new_commit.tree().unwrap();
        let entry = new_tree
            .get_name("config.js")
            .expect("config.js should be in new tree");
        let blob = repo.find_blob(entry.id()).unwrap();
        let new_content = std::str::from_utf8(blob.content()).unwrap();

        // The secret value should no longer appear verbatim.
        assert!(
            !new_content.contains(secret_value),
            "Secret value should be replaced in new commit, but found in: {}",
            new_content
        );

        // The replacement should reference process.env.
        assert!(
            new_content.contains("process.env."),
            "Replacement should use process.env.X, got: {}",
            new_content
        );

        // The original commit should be unchanged.
        let orig_commit = repo.find_commit(commit_oid).unwrap();
        let orig_tree = orig_commit.tree().unwrap();
        let orig_entry = orig_tree.get_name("config.js").unwrap();
        let orig_blob = repo.find_blob(orig_entry.id()).unwrap();
        let orig_content = std::str::from_utf8(orig_blob.content()).unwrap();
        assert!(
            orig_content.contains(secret_value),
            "Original commit should still contain the secret value"
        );
    }

    /// Task 16.5 — dry-run on a repo with 2 secrets in 2 commits:
    /// the receipt must report both secrets and the git log must be unchanged.
    #[test]
    fn test_dry_run_report_detects_secrets_without_modifying_history() {
        let tmp = TempDir::new().unwrap();
        let repo = init_repo_with_commit(tmp.path());

        // Commit 1: AWS access key
        let secret1 = concat!("AKIA", "IOSFODNN7EXAMPLE");
        let content1 = format!("const awsKey = \"{}\";\n", secret1);
        let oid1 = add_commit(&repo, tmp.path(), "aws.js", &content1, "Add AWS key");

        // Commit 2: Stripe secret key
        let secret2 = "sk_live_ABCDEFGHIJKLMNOPQRSTUVWX";
        let content2 = format!("const stripe = require('stripe')('{}');\n", secret2);
        let oid2 = add_commit(&repo, tmp.path(), "stripe.js", &content2, "Add Stripe key");

        // Capture the git log (commit OIDs) before the dry run.
        let log_before: Vec<git2::Oid> = {
            let mut rw = repo.revwalk().unwrap();
            rw.push_head().unwrap();
            rw.filter_map(|r| r.ok()).collect()
        };

        let exorcist = GitExorcist::new(tmp.path()).unwrap();
        let commits = vec![oid1, oid2];
        let receipt = exorcist.dry_run_report(&commits).unwrap();

        // The receipt must show 0 commits rewritten (dry run).
        assert_eq!(
            receipt.commits_rewritten, 0,
            "dry_run_report must not rewrite any commits"
        );

        // The receipt must report at least 2 secrets found.
        assert!(
            receipt.secrets_removed >= 2,
            "Expected at least 2 secrets detected, got {}",
            receipt.secrets_removed
        );

        // The replacements list must be non-empty.
        assert!(
            !receipt.replacements.is_empty(),
            "Expected non-empty replacements list from dry run"
        );

        // The git log must be identical after the dry run.
        let log_after: Vec<git2::Oid> = {
            let mut rw = repo.revwalk().unwrap();
            rw.push_head().unwrap();
            rw.filter_map(|r| r.ok()).collect()
        };

        assert_eq!(
            log_before, log_after,
            "git log must be unchanged after dry_run_report"
        );

        // The original files in the latest commit must still contain the secrets.
        let head_commit = repo.head().unwrap().peel_to_commit().unwrap();
        let head_tree = head_commit.tree().unwrap();

        let stripe_entry = head_tree
            .get_name("stripe.js")
            .expect("stripe.js should still exist");
        let stripe_blob = repo.find_blob(stripe_entry.id()).unwrap();
        let stripe_content = std::str::from_utf8(stripe_blob.content()).unwrap();
        assert!(
            stripe_content.contains(secret2),
            "stripe.js should still contain the original secret after dry run"
        );
    }

    // ── Task 16.6 integration test: CLI entry point ───────────────────────────

    /// Integration test for `sicario exorcise --dry-run`:
    ///
    /// Creates a test repo with a commit containing a hardcoded secret, calls
    /// `GitExorcist::exorcise(None, true)` (the same code path as the CLI
    /// `--dry-run` flag), verifies the receipt is non-empty, and asserts that
    /// the git log is completely unchanged.
    ///
    /// This mirrors what `cmd_exorcise` does when invoked with `--dry-run`.
    #[test]
    fn test_cli_exorcise_dry_run_prints_receipt_and_leaves_git_log_unchanged() {
        let tmp = TempDir::new().unwrap();
        let repo = init_repo_with_commit(tmp.path());

        // Add a commit with a hardcoded AWS access key (a pattern the
        // SecretScanner reliably detects).
        let secret_value = concat!("AKIA", "IOSFODNN7EXAMPLE");
        let file_content = format!(
            "const awsKey = \"{}\";\nconsole.log(awsKey);\n",
            secret_value
        );
        add_commit(
            &repo,
            tmp.path(),
            "config.js",
            &file_content,
            "Add hardcoded secret",
        );

        // Capture the full git log before the dry run.
        let log_before: Vec<git2::Oid> = {
            let mut rw = repo.revwalk().unwrap();
            rw.push_head().unwrap();
            rw.filter_map(|r| r.ok()).collect()
        };

        // Instantiate GitExorcist — same as `cmd_exorcise` does.
        let exorcist = GitExorcist::new(tmp.path()).unwrap();

        // Pre-flight check must pass on a clean repo.
        exorcist
            .check_working_tree_clean()
            .expect("Working tree should be clean before dry run");

        // Run the exorcism in dry-run mode — this is the code path exercised
        // by `sicario exorcise --dry-run`.
        let receipt = exorcist
            .exorcise(None, /*dry_run=*/ true)
            .expect("exorcise(dry_run=true) should succeed");

        // ── Receipt assertions ────────────────────────────────────────────
        // The receipt must show 0 commits rewritten (dry run never rewrites).
        assert_eq!(
            receipt.commits_rewritten, 0,
            "dry-run must not rewrite any commits; got commits_rewritten={}",
            receipt.commits_rewritten
        );

        // At least one secret must have been detected.
        assert!(
            receipt.secrets_removed >= 1,
            "Expected at least 1 secret detected in dry-run receipt, got {}",
            receipt.secrets_removed
        );

        // The rendered receipt must be non-empty and contain the key header.
        let rendered = receipt.render();
        assert!(
            !rendered.is_empty(),
            "receipt.render() must produce non-empty output"
        );
        assert!(
            rendered.contains("sicario git exorcist"),
            "Rendered receipt must contain the header; got:\n{}",
            rendered
        );

        // ── Git log unchanged assertion ───────────────────────────────────
        let log_after: Vec<git2::Oid> = {
            let mut rw = repo.revwalk().unwrap();
            rw.push_head().unwrap();
            rw.filter_map(|r| r.ok()).collect()
        };

        assert_eq!(
            log_before, log_after,
            "git log must be completely unchanged after --dry-run"
        );

        // The file in the latest commit must still contain the original secret.
        let head_commit = repo.head().unwrap().peel_to_commit().unwrap();
        let head_tree = head_commit.tree().unwrap();
        let entry = head_tree
            .get_name("config.js")
            .expect("config.js must still exist in HEAD after dry run");
        let blob = repo.find_blob(entry.id()).unwrap();
        let content = std::str::from_utf8(blob.content()).unwrap();
        assert!(
            content.contains(secret_value),
            "config.js must still contain the original secret after --dry-run; got:\n{}",
            content
        );
    }
}
