//! Unit tests for `sicario fix --staged` command.
//!
//! These tests verify the staged fix behavior without requiring a real LLM
//! connection. They use the compiled binary to test end-to-end behavior.

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Command;
    use tempfile::TempDir;

    // ── Helper: get the path to the compiled sicario binary ──────────────────

    fn binary_path() -> PathBuf {
        // Cargo sets this env-var for integration tests at runtime
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_sicario") {
            return PathBuf::from(p);
        }

        // Fallback: derive from CARGO_MANIFEST_DIR
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let workspace_root = PathBuf::from(&manifest_dir)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        let debug_bin = workspace_root
            .join("target")
            .join("debug")
            .join(if cfg!(windows) {
                "sicario.exe"
            } else {
                "sicario"
            });
        let release_bin = workspace_root
            .join("target")
            .join("release")
            .join(if cfg!(windows) {
                "sicario.exe"
            } else {
                "sicario"
            });

        if release_bin.exists() {
            release_bin
        } else {
            debug_bin
        }
    }

    // ── Helper: initialize a git repo in a temp dir ───────────────────────────

    fn init_git_repo(dir: &std::path::Path) {
        Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .expect("git init failed");
        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(dir)
            .output()
            .expect("git config email failed");
        Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(dir)
            .output()
            .expect("git config name failed");
    }

    fn stage_file(dir: &std::path::Path, file: &str) {
        Command::new("git")
            .args(["add", file])
            .current_dir(dir)
            .output()
            .expect("git add failed");
    }

    // ── Test: --staged outside git repo exits non-zero ────────────────────────

    /// `--staged` outside a Git repository must print a descriptive error and
    /// exit non-zero.
    #[test]
    fn staged_outside_git_repo_exits_nonzero_with_descriptive_error() {
        let bin = binary_path();
        if !bin.exists() {
            eprintln!("Skipping test: binary not found at {}", bin.display());
            return;
        }

        let tmp = TempDir::new().unwrap();
        // tmp is NOT a git repo

        let output = Command::new(&bin)
            .args(["fix", "--staged"])
            .current_dir(tmp.path())
            .output()
            .expect("failed to run sicario");

        assert!(
            !output.status.success(),
            "sicario fix --staged should exit non-zero outside a git repo"
        );

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Git repository")
                || stderr.contains("git repository")
                || stderr.contains("not inside a Git")
                || stderr.contains("git command failed")
                || stderr.contains("git"),
            "stderr should contain a descriptive error about git, got: {stderr}"
        );
    }

    // ── Test: --staged only fixes files in git diff --cached output ───────────

    /// `--staged` must only attempt to fix files that appear in
    /// `git diff --cached --name-only`. Files not staged must be ignored.
    #[test]
    fn staged_only_fixes_staged_files() {
        let bin = binary_path();
        if !bin.exists() {
            eprintln!("Skipping test: binary not found at {}", bin.display());
            return;
        }

        let tmp = TempDir::new().unwrap();
        init_git_repo(tmp.path());

        // Create two files — only one will be staged
        let staged_file = tmp.path().join("staged.js");
        let unstaged_file = tmp.path().join("unstaged.js");

        std::fs::write(
            &staged_file,
            "const query = db.query(\"SELECT * FROM users WHERE id = \" + userId);\n",
        )
        .unwrap();
        std::fs::write(
            &unstaged_file,
            "const query = db.query(\"SELECT * FROM users WHERE id = \" + userId);\n",
        )
        .unwrap();

        // Stage only the first file
        stage_file(tmp.path(), "staged.js");

        let output = Command::new(&bin)
            .args(["fix", "--staged", "--format", "json"])
            .current_dir(tmp.path())
            .output()
            .expect("failed to run sicario");

        let stdout = String::from_utf8_lossy(&output.stdout);

        // The JSON output should only reference staged.js, not unstaged.js
        if !stdout.trim().is_empty() && stdout.trim() != "[]" {
            assert!(
                !stdout.contains("unstaged.js"),
                "--staged should not process unstaged files, got: {stdout}"
            );
        }
    }

    // ── Test: --staged with --format json produces correct JSON array ─────────

    /// `--staged --format json` must output a valid JSON array.
    /// Each element must have the fields: file, rule_id, line, fixed, template_used.
    #[test]
    fn staged_with_format_json_produces_valid_json_array() {
        let bin = binary_path();
        if !bin.exists() {
            eprintln!("Skipping test: binary not found at {}", bin.display());
            return;
        }

        let tmp = TempDir::new().unwrap();
        init_git_repo(tmp.path());

        // Create a file with no vulnerabilities so we get an empty array
        let clean_file = tmp.path().join("clean.js");
        std::fs::write(&clean_file, "const x = 1;\n").unwrap();
        stage_file(tmp.path(), "clean.js");

        let output = Command::new(&bin)
            .args(["fix", "--staged", "--format", "json"])
            .current_dir(tmp.path())
            .output()
            .expect("failed to run sicario");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();

        // Must be valid JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(trimmed);
        assert!(
            parsed.is_ok(),
            "--staged --format json must produce valid JSON, got: {trimmed}"
        );

        // Must be an array
        let value = parsed.unwrap();
        assert!(
            value.is_array(),
            "--staged --format json must produce a JSON array, got: {value}"
        );
    }

    /// `--staged --format json` with findings must produce objects with the
    /// correct fields: file, rule_id, line, fixed, template_used.
    #[test]
    fn staged_json_output_has_correct_fields() {
        let bin = binary_path();
        if !bin.exists() {
            eprintln!("Skipping test: binary not found at {}", bin.display());
            return;
        }

        let tmp = TempDir::new().unwrap();
        init_git_repo(tmp.path());

        // Create a file with a known vulnerability pattern
        let vuln_file = tmp.path().join("vuln.js");
        std::fs::write(
            &vuln_file,
            "const query = db.query(\"SELECT * FROM users WHERE id = \" + userId);\n",
        )
        .unwrap();
        stage_file(tmp.path(), "vuln.js");

        let output = Command::new(&bin)
            .args(["fix", "--staged", "--format", "json"])
            .current_dir(tmp.path())
            .output()
            .expect("failed to run sicario");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();

        let parsed: serde_json::Value = serde_json::from_str(trimmed).expect("must be valid JSON");
        let arr = parsed.as_array().expect("must be a JSON array");

        // If there are findings, verify the field structure
        for item in arr {
            assert!(
                item.get("file").is_some(),
                "each result must have a 'file' field"
            );
            assert!(
                item.get("rule_id").is_some(),
                "each result must have a 'rule_id' field"
            );
            assert!(
                item.get("line").is_some(),
                "each result must have a 'line' field"
            );
            assert!(
                item.get("fixed").is_some(),
                "each result must have a 'fixed' field"
            );
            assert!(
                item.get("template_used").is_some(),
                "each result must have a 'template_used' field (may be null)"
            );
        }
    }

    // ── Test: --staged does not invoke LLM fallback ───────────────────────────

    /// `--staged` must not invoke LLM fallback. We verify this by checking that
    /// the command completes quickly (no LLM timeout) and does not print any
    /// LLM-related messages.
    #[test]
    fn staged_does_not_invoke_llm_fallback() {
        let bin = binary_path();
        if !bin.exists() {
            eprintln!("Skipping test: binary not found at {}", bin.display());
            return;
        }

        let tmp = TempDir::new().unwrap();
        init_git_repo(tmp.path());

        // Create a file with a vulnerability that has no deterministic template
        // (so LLM would normally be invoked in non-staged mode)
        let vuln_file = tmp.path().join("no_template.js");
        std::fs::write(
            &vuln_file,
            "// Some code with a hypothetical unfixable pattern\nconst x = eval(userInput);\n",
        )
        .unwrap();
        stage_file(tmp.path(), "no_template.js");

        let start = std::time::Instant::now();
        let output = Command::new(&bin)
            .args(["fix", "--staged", "--format", "json"])
            .current_dir(tmp.path())
            .output()
            .expect("failed to run sicario");
        let elapsed = start.elapsed();

        // Should complete quickly — no LLM timeout (LLM calls can take 30+ seconds)
        assert!(
            elapsed.as_secs() < 60,
            "--staged should complete quickly without LLM calls, took: {:?}",
            elapsed
        );

        let stderr = String::from_utf8_lossy(&output.stderr);

        // Should not contain LLM-related messages
        assert!(
            !stderr.contains("Generating fix") && !stderr.contains("LLM"),
            "--staged should not invoke LLM, stderr: {stderr}"
        );

        // If there are results, fixed=false for unfixable patterns (no LLM fallback)
        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();
        if !trimmed.is_empty() && trimmed != "[]" {
            if let Ok(serde_json::Value::Array(arr)) =
                serde_json::from_str::<serde_json::Value>(trimmed)
            {
                for item in &arr {
                    // If a finding has no deterministic template, fixed must be false
                    // (not fixed via LLM)
                    if item
                        .get("template_used")
                        .and_then(|v| v.as_null())
                        .is_some()
                    {
                        assert_eq!(
                            item.get("fixed").and_then(|v| v.as_bool()),
                            Some(false),
                            "unfixable findings (no template) must have fixed=false, not LLM-fixed"
                        );
                    }
                }
            }
        }
    }

    // ── Test: --staged with no staged files returns empty array ──────────────

    /// When no files are staged, `--staged --format json` must output `[]`.
    #[test]
    fn staged_with_no_staged_files_returns_empty_array() {
        let bin = binary_path();
        if !bin.exists() {
            eprintln!("Skipping test: binary not found at {}", bin.display());
            return;
        }

        let tmp = TempDir::new().unwrap();
        init_git_repo(tmp.path());

        // Create a file but don't stage it
        let file = tmp.path().join("unstaged.js");
        std::fs::write(&file, "const x = 1;\n").unwrap();
        // Do NOT call stage_file

        let output = Command::new(&bin)
            .args(["fix", "--staged", "--format", "json"])
            .current_dir(tmp.path())
            .output()
            .expect("failed to run sicario");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();

        assert_eq!(
            trimmed, "[]",
            "--staged with no staged files should output [], got: {trimmed}"
        );
        assert!(
            output.status.success(),
            "--staged with no staged files should exit 0"
        );
    }
}
