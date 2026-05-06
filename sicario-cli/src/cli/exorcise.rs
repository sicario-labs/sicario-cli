//! CLI argument definitions for the `sicario exorcise` subcommand.
//!
//! `sicario exorcise` rewrites local git history to remove hardcoded secrets
//! from commits that have not yet been pushed to a remote.

use clap::Parser;

/// Rewrite local git history to remove hardcoded secrets.
///
/// Walks unpushed commits (or the range specified by `--since`), detects
/// hardcoded credentials, replaces them with `process.env.VAR_NAME`
/// references, and creates new commits with the same metadata but clean trees.
///
/// **Warning:** This rewrites local git history. Force-push will be required
/// if any of the affected commits have already been shared with collaborators.
#[derive(Parser, Debug)]
pub struct ExorciseArgs {
    /// Scan and report what would be changed without rewriting git history.
    ///
    /// Prints the exorcism receipt showing which secrets would be removed,
    /// but leaves the repository completely untouched.
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,

    /// Limit the rewrite to commits after this git ref (branch, tag, or SHA).
    ///
    /// When omitted, defaults to all commits not yet pushed to the configured
    /// upstream (`@{u}..HEAD`).
    #[arg(long, value_name = "REF")]
    pub since: Option<String>,

    /// Skip the confirmation prompt and proceed immediately.
    ///
    /// Implied by `--dry-run` (no confirmation needed for a read-only scan).
    #[arg(long, default_value_t = false)]
    pub yes: bool,
}
