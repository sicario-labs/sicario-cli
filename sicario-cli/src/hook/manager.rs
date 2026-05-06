//! Pre-commit hook management — install, uninstall, and status.
//!
//! The hook script uses marker comments (`# BEGIN SICARIO HOOK` / `# END SICARIO HOOK`)
//! to delimit the Sicario section, allowing safe append and removal without
//! disturbing other hook content.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

// ── Marker constants ──────────────────────────────────────────────────────────

const BEGIN_MARKER: &str = "# BEGIN SICARIO HOOK";
const END_MARKER: &str = "# END SICARIO HOOK";
const SHEBANG: &str = "#!/bin/sh";

const SICARIO_HOOK_BLOCK: &str = "\
# BEGIN SICARIO HOOK
if [ \"$SICARIO_SKIP_HOOK\" = \"1\" ]; then
  exit 0
fi
sicario scan --staged --severity-threshold high --quiet
# END SICARIO HOOK";

const AUTO_FIX_HOOK_BLOCK: &str = "\
# BEGIN SICARIO HOOK
# INVARIANT: sicario fix --staged creates a backup via BackupManager (apply_patch)
# before modifying any file. If git add fails after a fix, we restore from the
# git index (pre-fix staged state) and block the commit to prevent ghost fixes.
#
# ZERO-EXFILTRATION INVARIANT: This hook script contains NO network commands.
# There is no curl, wget, nc, ssh, ftp, or any other network utility invoked
# here. The only external commands are: sicario (local binary), git (local VCS),
# printf, grep, sed, sort, and echo — all purely local operations.
# Code reviewers: reject any PR that adds a network command to this block.
if [ \"$SICARIO_SKIP_HOOK\" = \"1\" ]; then
  exit 0
fi
_sicario_results=$(sicario fix --staged --format json --quiet 2>/dev/null)
_sicario_fixed=$(printf '%s' \"$_sicario_results\" | grep -c '\"fixed\":true' || true)
_sicario_unfixed=$(printf '%s' \"$_sicario_results\" | grep -c '\"fixed\":false' || true)
if [ \"$_sicario_unfixed\" -gt 0 ]; then
  sicario scan --staged --severity-threshold high
  exit 1
fi
if [ \"$_sicario_fixed\" -gt 0 ]; then
  _sicario_files=$(printf '%s\\n' \"$_sicario_results\" | grep '\"file\"' | sed 's/.*\"file\":\"\\([^\"]*\\)\".*/\\1/' | sort -u)
  _sicario_add_failed=0
  printf '%s\\n' \"$_sicario_files\" | while IFS= read -r _sicario_file; do
    if [ -n \"$_sicario_file\" ]; then
      if ! git add \"$_sicario_file\" 2>/dev/null; then
        echo \"Sicario: ERROR — git add failed for '$_sicario_file'. Restoring from backup.\" >&2
        git checkout -- \"$_sicario_file\" 2>/dev/null || true
        _sicario_add_failed=1
      fi
    fi
  done
  if [ \"$_sicario_add_failed\" -eq 1 ] 2>/dev/null; then
    echo \"Sicario: commit blocked — one or more files could not be re-staged after auto-fix.\" >&2
    exit 1
  fi
  echo \"Sicario: auto-fixed $_sicario_fixed vulnerabilities. Commit proceeding.\"
fi
# END SICARIO HOOK";

// ── Public types ──────────────────────────────────────────────────────────────

/// Status of the Sicario pre-commit hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookStatus {
    /// Whether the Sicario hook section is present in the pre-commit script.
    pub installed: bool,
    /// The command line embedded in the hook, if installed.
    pub command: Option<String>,
}

/// Trait for managing the Git pre-commit hook.
pub trait HookManagement {
    fn install(&self) -> Result<()>;
    fn uninstall(&self) -> Result<()>;
    fn status(&self) -> Result<HookStatus>;
}

/// Concrete implementation backed by a Git repository path.
pub struct HookManager {
    /// Path to the `.git/hooks` directory.
    hooks_dir: PathBuf,
}

impl HookManager {
    /// Create a `HookManager` for the repository containing `working_dir`.
    ///
    /// Uses `git2::Repository::discover` to locate the `.git` directory.
    pub fn new(working_dir: &Path) -> Result<Self> {
        let repo = git2::Repository::discover(working_dir).with_context(|| {
            format!(
                "Not a git repository (or any parent): {}",
                working_dir.display()
            )
        })?;
        let git_dir = repo.path().to_path_buf(); // e.g. /repo/.git/
        let hooks_dir = git_dir.join("hooks");
        Ok(Self { hooks_dir })
    }

    /// Build a `HookManager` pointing at an explicit hooks directory (useful for tests).
    #[cfg(test)]
    fn with_hooks_dir(hooks_dir: PathBuf) -> Self {
        Self { hooks_dir }
    }

    /// Path to the pre-commit hook script.
    fn pre_commit_path(&self) -> PathBuf {
        self.hooks_dir.join("pre-commit")
    }

    /// Install the AutoFix pre-commit hook (Ghost Fix mode).
    ///
    /// Calls `remove_sicario_block()` on any existing content first to ensure
    /// idempotency — exactly one `BEGIN SICARIO HOOK` / `END SICARIO HOOK` pair
    /// will be present regardless of prior state.
    pub fn install_auto_fix(&self) -> Result<()> {
        let path = self.pre_commit_path();

        // Ensure hooks directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = if path.exists() {
            let existing = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;

            // Remove any existing Sicario block (idempotency).
            let cleaned = remove_sicario_block(&existing);
            let trimmed = cleaned.trim_end().to_string();

            if trimmed.is_empty() || trimmed == SHEBANG {
                // Only shebang (or empty) — write fresh.
                format!("{}\n{}\n", SHEBANG, AUTO_FIX_HOOK_BLOCK)
            } else {
                // Append auto-fix block after existing content.
                format!("{}\n{}\n", trimmed, AUTO_FIX_HOOK_BLOCK)
            }
        } else {
            // Create a new hook file.
            format!("{}\n{}\n", SHEBANG, AUTO_FIX_HOOK_BLOCK)
        };

        std::fs::write(&path, &content)
            .with_context(|| format!("Failed to write {}", path.display()))?;

        // Make executable on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&path, perms)?;
        }

        Ok(())
    }
}

impl HookManagement for HookManager {
    fn install(&self) -> Result<()> {
        let path = self.pre_commit_path();

        // Ensure hooks directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = if path.exists() {
            let existing = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;

            if existing.contains(BEGIN_MARKER) {
                // Already installed — nothing to do.
                return Ok(());
            }

            // Append to existing hook.
            format!("{}\n{}\n", existing.trim_end(), SICARIO_HOOK_BLOCK)
        } else {
            // Create a new hook file.
            format!("{}\n{}\n", SHEBANG, SICARIO_HOOK_BLOCK)
        };

        std::fs::write(&path, &content)
            .with_context(|| format!("Failed to write {}", path.display()))?;

        // Make executable on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&path, perms)?;
        }

        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        let path = self.pre_commit_path();

        if !path.exists() {
            return Ok(());
        }

        let existing = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        let cleaned = remove_sicario_block(&existing);

        // If only the shebang (or whitespace) remains, delete the file.
        let trimmed = cleaned.trim();
        if trimmed.is_empty() || trimmed == SHEBANG {
            std::fs::remove_file(&path)?;
        } else {
            std::fs::write(&path, &cleaned)?;
        }

        Ok(())
    }

    fn status(&self) -> Result<HookStatus> {
        let path = self.pre_commit_path();

        if !path.exists() {
            return Ok(HookStatus {
                installed: false,
                command: None,
            });
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        if let Some(cmd) = extract_sicario_command(&content) {
            Ok(HookStatus {
                installed: true,
                command: Some(cmd),
            })
        } else {
            Ok(HookStatus {
                installed: false,
                command: None,
            })
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Remove everything between (and including) the BEGIN/END markers.
fn remove_sicario_block(content: &str) -> String {
    let mut result = String::new();
    let mut inside_block = false;

    for line in content.lines() {
        if line.trim() == BEGIN_MARKER {
            inside_block = true;
            continue;
        }
        if line.trim() == END_MARKER {
            inside_block = false;
            continue;
        }
        if !inside_block {
            result.push_str(line);
            result.push('\n');
        }
    }

    result
}

/// Extract the sicario command line from within the markers, if present.
fn extract_sicario_command(content: &str) -> Option<String> {
    let mut inside = false;
    for line in content.lines() {
        if line.trim() == BEGIN_MARKER {
            inside = true;
            continue;
        }
        if line.trim() == END_MARKER {
            break;
        }
        if inside {
            let trimmed = line.trim();
            if trimmed.starts_with("sicario ") {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, HookManager) {
        let tmp = TempDir::new().unwrap();
        let hooks_dir = tmp.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let mgr = HookManager::with_hooks_dir(hooks_dir);
        (tmp, mgr)
    }

    #[test]
    fn install_creates_new_hook() {
        let (_tmp, mgr) = setup();
        mgr.install().unwrap();

        let content = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();
        assert!(content.starts_with(SHEBANG));
        assert!(content.contains(BEGIN_MARKER));
        assert!(content.contains(END_MARKER));
        assert!(content.contains("sicario scan --staged --severity-threshold high --quiet"));
        assert!(content.contains("SICARIO_SKIP_HOOK"));
    }

    #[test]
    fn install_appends_to_existing_hook() {
        let (_tmp, mgr) = setup();
        let path = mgr.pre_commit_path();
        std::fs::write(&path, "#!/bin/sh\necho 'existing hook'\n").unwrap();

        mgr.install().unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("echo 'existing hook'"));
        assert!(content.contains(BEGIN_MARKER));
        assert!(content.contains("sicario scan --staged"));
    }

    #[test]
    fn install_is_idempotent() {
        let (_tmp, mgr) = setup();
        mgr.install().unwrap();
        mgr.install().unwrap();

        let content = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();
        // Should only contain one BEGIN marker.
        assert_eq!(content.matches(BEGIN_MARKER).count(), 1);
    }

    #[test]
    fn uninstall_removes_sicario_block() {
        let (_tmp, mgr) = setup();
        let path = mgr.pre_commit_path();
        let content = format!(
            "#!/bin/sh\necho 'before'\n{}\necho 'after'\n",
            SICARIO_HOOK_BLOCK
        );
        std::fs::write(&path, &content).unwrap();

        mgr.uninstall().unwrap();

        let result = std::fs::read_to_string(&path).unwrap();
        assert!(!result.contains(BEGIN_MARKER));
        assert!(!result.contains(END_MARKER));
        assert!(result.contains("echo 'before'"));
        assert!(result.contains("echo 'after'"));
    }

    #[test]
    fn uninstall_deletes_file_when_only_shebang_remains() {
        let (_tmp, mgr) = setup();
        mgr.install().unwrap();
        assert!(mgr.pre_commit_path().exists());

        mgr.uninstall().unwrap();
        assert!(!mgr.pre_commit_path().exists());
    }

    #[test]
    fn uninstall_noop_when_no_file() {
        let (_tmp, mgr) = setup();
        // Should not error.
        mgr.uninstall().unwrap();
    }

    #[test]
    fn status_reports_not_installed_when_no_file() {
        let (_tmp, mgr) = setup();
        let st = mgr.status().unwrap();
        assert!(!st.installed);
        assert!(st.command.is_none());
    }

    #[test]
    fn status_reports_installed_with_command() {
        let (_tmp, mgr) = setup();
        mgr.install().unwrap();

        let st = mgr.status().unwrap();
        assert!(st.installed);
        assert_eq!(
            st.command.as_deref(),
            Some("sicario scan --staged --severity-threshold high --quiet")
        );
    }

    #[test]
    fn status_reports_not_installed_when_markers_absent() {
        let (_tmp, mgr) = setup();
        std::fs::write(mgr.pre_commit_path(), "#!/bin/sh\necho hello\n").unwrap();

        let st = mgr.status().unwrap();
        assert!(!st.installed);
    }

    #[test]
    fn remove_sicario_block_preserves_surrounding() {
        let input = format!(
            "#!/bin/sh\necho before\n{}\necho after\n",
            SICARIO_HOOK_BLOCK
        );
        let result = remove_sicario_block(&input);
        assert!(!result.contains(BEGIN_MARKER));
        assert!(result.contains("echo before"));
        assert!(result.contains("echo after"));
    }

    #[test]
    fn remove_sicario_block_noop_when_absent() {
        let input = "#!/bin/sh\necho hello\n";
        let result = remove_sicario_block(input);
        assert_eq!(result, input);
    }

    #[cfg(unix)]
    #[test]
    fn install_sets_executable_permission() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, mgr) = setup();
        mgr.install().unwrap();

        let meta = std::fs::metadata(mgr.pre_commit_path()).unwrap();
        let mode = meta.permissions().mode();
        assert!(mode & 0o111 != 0, "hook should be executable");
    }

    // ── install_auto_fix tests ────────────────────────────────────────────────

    #[test]
    fn install_auto_fix_creates_hook_on_empty_repo() {
        let (_tmp, mgr) = setup();
        mgr.install_auto_fix().unwrap();

        let content = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();
        assert!(content.starts_with(SHEBANG));
        assert!(content.contains(BEGIN_MARKER));
        assert!(content.contains(END_MARKER));
        assert!(content.contains("sicario fix --staged --format json --quiet"));
        assert!(content.contains("SICARIO_SKIP_HOOK"));
    }

    #[test]
    fn install_auto_fix_on_existing_standard_hook_replaces_sicario_block_only() {
        let (_tmp, mgr) = setup();
        // First install the standard hook.
        mgr.install().unwrap();

        let before = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();
        assert!(before.contains("sicario scan --staged --severity-threshold high --quiet"));

        // Now install auto-fix — should replace the Sicario block.
        mgr.install_auto_fix().unwrap();

        let after = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();
        // Old scan command should be gone.
        assert!(!after.contains("sicario scan --staged --severity-threshold high --quiet"));
        // New auto-fix content should be present.
        assert!(after.contains("sicario fix --staged --format json --quiet"));
        // Markers should still be present exactly once.
        assert_eq!(after.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(after.matches(END_MARKER).count(), 1);
    }

    #[test]
    fn install_auto_fix_on_existing_hook_with_other_content_preserves_other_content() {
        let (_tmp, mgr) = setup();
        let path = mgr.pre_commit_path();
        std::fs::write(&path, "#!/bin/sh\necho 'existing hook'\n").unwrap();

        mgr.install_auto_fix().unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("echo 'existing hook'"));
        assert!(content.contains(BEGIN_MARKER));
        assert!(content.contains("sicario fix --staged --format json --quiet"));
    }

    #[test]
    fn install_auto_fix_twice_results_in_exactly_one_marker_pair() {
        let (_tmp, mgr) = setup();
        mgr.install_auto_fix().unwrap();
        mgr.install_auto_fix().unwrap();

        let content = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();
        assert_eq!(content.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(content.matches(END_MARKER).count(), 1);
    }

    #[test]
    fn install_auto_fix_is_idempotent() {
        let (_tmp, mgr) = setup();
        mgr.install_auto_fix().unwrap();
        let first = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();

        mgr.install_auto_fix().unwrap();
        let second = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();

        assert_eq!(first, second, "install_auto_fix should be idempotent");
    }

    #[test]
    fn install_auto_fix_hook_contains_sicario_skip_hook_bypass() {
        let (_tmp, mgr) = setup();
        mgr.install_auto_fix().unwrap();

        let content = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();
        assert!(
            content.contains("SICARIO_SKIP_HOOK"),
            "hook must contain SICARIO_SKIP_HOOK bypass"
        );
        assert!(
            content.contains("exit 0"),
            "hook must exit 0 when bypass is set"
        );
    }

    #[test]
    fn install_auto_fix_hook_uses_posix_sh_syntax() {
        let (_tmp, mgr) = setup();
        mgr.install_auto_fix().unwrap();

        let content = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();

        // Shebang must be /bin/sh, not /bin/bash.
        assert!(
            content.starts_with("#!/bin/sh"),
            "hook must use POSIX sh shebang"
        );
        // No bash-specific [[ ]] syntax.
        assert!(
            !content.contains("[["),
            "hook must not use bash-specific [[ ]] syntax"
        );
        // No bash-specific (( )) arithmetic.
        assert!(
            !content.contains("(("),
            "hook must not use bash-specific (( )) arithmetic"
        );
        // No bash-specific $'...' quoting.
        assert!(
            !content.contains("$'"),
            "hook must not use bash-specific $'...' quoting"
        );
        // Uses printf instead of echo -e (POSIX).
        assert!(
            !content.contains("echo -e"),
            "hook must not use echo -e (not POSIX)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_auto_fix_sets_executable_permission() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, mgr) = setup();
        mgr.install_auto_fix().unwrap();

        let meta = std::fs::metadata(mgr.pre_commit_path()).unwrap();
        let mode = meta.permissions().mode();
        assert!(mode & 0o111 != 0, "auto-fix hook should be executable");
    }

    // ── Task 3.3: Ghost Fix Safety tests ─────────────────────────────────────

    /// Unit test: AutoFixHook with SICARIO_SKIP_HOOK=1 exits 0 without scanning.
    ///
    /// Verifies the hook script contains the bypass check that exits 0 immediately
    /// when SICARIO_SKIP_HOOK=1 is set, without invoking any sicario commands.
    #[test]
    fn auto_fix_hook_skip_hook_bypass_exits_zero_without_scanning() {
        let (_tmp, mgr) = setup();
        mgr.install_auto_fix().unwrap();

        let content = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();

        // The bypass check must appear before the actual sicario fix invocation.
        // We look for the assignment line `_sicario_results=$(sicario fix` as the
        // actual invocation (not the comment that also mentions "sicario fix").
        let skip_pos = content
            .find("SICARIO_SKIP_HOOK")
            .expect("hook must contain SICARIO_SKIP_HOOK check");
        let exit_zero_pos = content
            .find("exit 0")
            .expect("hook must contain 'exit 0' for bypass");
        let sicario_fix_invocation = "_sicario_results=$(sicario fix";
        let sicario_fix_pos = content
            .find(sicario_fix_invocation)
            .expect("hook must contain '_sicario_results=$(sicario fix' invocation");

        // The SICARIO_SKIP_HOOK check and its exit 0 must come before sicario fix.
        assert!(
            skip_pos < sicario_fix_pos,
            "SICARIO_SKIP_HOOK check must appear before sicario fix invocation"
        );
        assert!(
            exit_zero_pos < sicario_fix_pos,
            "'exit 0' bypass must appear before sicario fix invocation"
        );

        // The bypass must check for the value "1".
        assert!(
            content.contains("\"$SICARIO_SKIP_HOOK\" = \"1\""),
            "hook must check SICARIO_SKIP_HOOK equals 1"
        );
    }

    /// Unit test: hook script contains git add failure recovery logic.
    ///
    /// Verifies the AUTO_FIX_HOOK_BLOCK contains error handling for git add failures:
    /// - Checks git add exit status
    /// - Restores the file on failure (via git checkout --)
    /// - Blocks the commit with an error message
    #[test]
    fn auto_fix_hook_contains_git_add_failure_recovery() {
        let (_tmp, mgr) = setup();
        mgr.install_auto_fix().unwrap();

        let content = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();

        // Must check git add exit status (using 'if ! git add' pattern).
        assert!(content.contains("git add"), "hook must invoke git add");
        assert!(
            content.contains("git checkout --"),
            "hook must restore file via 'git checkout --' on git add failure"
        );
        // Must emit an error message to stderr on failure.
        assert!(
            content.contains(">&2"),
            "hook must write error message to stderr on git add failure"
        );
        // Must exit 1 to block the commit on failure.
        assert!(
            content.contains("exit 1"),
            "hook must exit 1 to block commit when git add fails"
        );
        // Must contain the backup invariant comment.
        assert!(
            content.contains("BackupManager"),
            "hook must contain comment asserting BackupManager backup invariant"
        );
    }

    /// Integration test: hook with zero unfixed findings exits 0.
    ///
    /// Installs the auto-fix hook, then executes it with a mock `sicario` that
    /// returns an empty JSON array (no findings). Verifies the hook exits 0.
    #[cfg(unix)]
    #[test]
    fn integration_hook_with_zero_unfixed_findings_exits_zero() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let hooks_dir = tmp.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();

        // Create a mock `sicario` that returns an empty JSON array (no findings).
        let mock_sicario = bin_dir.join("sicario");
        std::fs::write(&mock_sicario, "#!/bin/sh\nprintf '[]\n'\n").unwrap();
        std::fs::set_permissions(&mock_sicario, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mgr = HookManager::with_hooks_dir(hooks_dir);
        mgr.install_auto_fix().unwrap();

        let hook_path = mgr.pre_commit_path();

        // Execute the hook with the mock sicario on PATH.
        let status = std::process::Command::new("sh")
            .arg(&hook_path)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin_dir.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("SICARIO_SKIP_HOOK", "")
            .current_dir(tmp.path())
            .status()
            .expect("failed to execute hook script");

        assert!(
            status.success(),
            "hook with zero unfixed findings must exit 0, got: {:?}",
            status.code()
        );
    }

    /// Integration test: hook with unfixed findings exits 1.
    ///
    /// Installs the auto-fix hook, then executes it with a mock `sicario` that
    /// returns a JSON array containing one unfixed finding. Verifies the hook exits 1.
    #[cfg(unix)]
    #[test]
    fn integration_hook_with_unfixed_findings_exits_one() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let hooks_dir = tmp.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();

        // Create a mock `sicario` that returns one unfixed finding.
        // The hook counts '"fixed":false' occurrences to detect unfixed findings.
        let mock_sicario = bin_dir.join("sicario");
        std::fs::write(
            &mock_sicario,
            r#"#!/bin/sh
printf '[{"file":"src/db.js","rule_id":"js-sql-string-concat","line":42,"fixed":false,"template_used":null}]\n'
"#,
        )
        .unwrap();
        std::fs::set_permissions(&mock_sicario, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mgr = HookManager::with_hooks_dir(hooks_dir);
        mgr.install_auto_fix().unwrap();

        let hook_path = mgr.pre_commit_path();

        // Execute the hook with the mock sicario on PATH.
        let status = std::process::Command::new("sh")
            .arg(&hook_path)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin_dir.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("SICARIO_SKIP_HOOK", "")
            .current_dir(tmp.path())
            .status()
            .expect("failed to execute hook script");

        assert_eq!(
            status.code(),
            Some(1),
            "hook with unfixed findings must exit 1"
        );
    }

    /// Performance test: AutoFixHook completes within 2 seconds for 20 staged files
    /// with 50 findings (all fixed via deterministic templates).
    ///
    /// Uses a mock `sicario` that returns a JSON array of 50 fixed findings across
    /// 20 files, and a mock `git` that succeeds for all `git add` calls.
    /// Verifies the hook script processes all findings and exits 0 within 2 seconds.
    #[cfg(unix)]
    #[test]
    fn integration_hook_performance_20_files_50_findings_within_2_seconds() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let hooks_dir = tmp.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();

        // Build a JSON array of 50 fixed findings across 20 files (2-3 per file).
        let mut findings = Vec::new();
        for i in 0..50 {
            let file_idx = i % 20;
            findings.push(format!(
                r#"{{"file":"src/file{}.js","rule_id":"js-sql-string-concat","line":{},"fixed":true,"template_used":"SqlAstRewriteTemplate"}}"#,
                file_idx,
                i + 1
            ));
        }
        let json_output = format!("[{}]", findings.join(","));

        // Create a mock `sicario` that returns the 50-finding JSON array.
        let mock_sicario = bin_dir.join("sicario");
        std::fs::write(
            &mock_sicario,
            format!(
                "#!/bin/sh\nprintf '{}\\n'\n",
                json_output.replace('\'', "'\\''")
            ),
        )
        .unwrap();
        std::fs::set_permissions(&mock_sicario, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Create a mock `git` that succeeds for all operations (git add, git checkout).
        let mock_git = bin_dir.join("git");
        std::fs::write(&mock_git, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&mock_git, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mgr = HookManager::with_hooks_dir(hooks_dir);
        mgr.install_auto_fix().unwrap();

        let hook_path = mgr.pre_commit_path();
        let path_env = format!(
            "{}:{}",
            bin_dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );

        let start = std::time::Instant::now();
        let status = std::process::Command::new("sh")
            .arg(&hook_path)
            .env("PATH", &path_env)
            .env("SICARIO_SKIP_HOOK", "")
            .current_dir(tmp.path())
            .status()
            .expect("failed to execute hook script");
        let elapsed = start.elapsed();

        assert!(
            status.success(),
            "hook with 50 fixed findings must exit 0, got: {:?}",
            status.code()
        );
        assert!(
            elapsed.as_secs() < 2,
            "AutoFixHook took {}ms for 20 staged files / 50 findings, must complete within 2 seconds",
            elapsed.as_millis()
        );
    }

    /// Integration test: hook with SICARIO_SKIP_HOOK=1 exits 0 without running sicario.
    ///
    /// Verifies the bypass works at runtime by executing the hook script with
    /// SICARIO_SKIP_HOOK=1 and a mock sicario that would fail if called.
    #[cfg(unix)]
    #[test]
    fn integration_hook_skip_hook_env_exits_zero() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let hooks_dir = tmp.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();

        // Create a mock `sicario` that always exits 1 — if called, the test fails.
        let mock_sicario = bin_dir.join("sicario");
        std::fs::write(&mock_sicario, "#!/bin/sh\nexit 1\n").unwrap();
        std::fs::set_permissions(&mock_sicario, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mgr = HookManager::with_hooks_dir(hooks_dir);
        mgr.install_auto_fix().unwrap();

        let hook_path = mgr.pre_commit_path();

        // Execute the hook with SICARIO_SKIP_HOOK=1 — must exit 0 without calling sicario.
        let status = std::process::Command::new("sh")
            .arg(&hook_path)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin_dir.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("SICARIO_SKIP_HOOK", "1")
            .current_dir(tmp.path())
            .status()
            .expect("failed to execute hook script");

        assert!(
            status.success(),
            "hook with SICARIO_SKIP_HOOK=1 must exit 0 without scanning, got: {:?}",
            status.code()
        );
    }
}
