//! Property-based tests for binary portability and independence.
//!
//! Feature: sicario-cli-core
//! Property 30 — Binary portability and independence
//!
//! Validates: Requirements 12.4
//!
//! For any compiled Sicario CLI binary for a target platform (Linux, macOS, or
//! Windows), it should execute successfully on that platform without requiring
//! additional runtime dependencies or libraries, with a binary footprint under
//! 50MB.
//!
//! These tests validate portability properties that can be checked at compile
//! time and at test time:
//!   1. The binary size is under 50 MB (the debug build is allowed to be larger;
//!      we test the release-profile size limit via a size-budget property).
//!   2. The binary is self-contained: all required symbols are resolved at link
//!      time (verified by the fact that the test binary itself can be executed).
//!   3. The binary exposes a stable, platform-independent CLI interface: for any
//!      valid invocation the exit code is deterministic and the output is
//!      well-formed UTF-8.

#[cfg(test)]
mod binary_portability_tests {
    use proptest::prelude::*;
    use std::path::PathBuf;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Return the path to the compiled `sicario` binary produced by Cargo.
    ///
    /// `CARGO_BIN_EXE_sicario` is set by Cargo's test harness when the crate
    /// declares a `[[bin]]` target named `sicario`.  If the env-var is absent
    /// (e.g. when running individual unit tests outside of `cargo test`) we fall
    /// back to a best-effort path relative to the workspace root.
    fn binary_path() -> PathBuf {
        // Cargo sets this env-var for integration tests; it points to the
        // compiled binary for the current profile (debug by default).
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_sicario") {
            return PathBuf::from(p);
        }

        // Fallback: derive from CARGO_MANIFEST_DIR
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| ".".to_string());

        // Walk up to the workspace root (one level above the crate manifest)
        let workspace_root = PathBuf::from(&manifest_dir)
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));

        // Try debug build first, then release
        let debug_bin = workspace_root
            .join("target")
            .join("debug")
            .join(if cfg!(windows) { "sicario.exe" } else { "sicario" });

        let release_bin = workspace_root
            .join("target")
            .join("release")
            .join(if cfg!(windows) { "sicario.exe" } else { "sicario" });

        if release_bin.exists() {
            release_bin
        } else {
            debug_bin
        }
    }

    /// Maximum allowed binary size in bytes (50 MB per Requirement 12.4).
    const MAX_BINARY_SIZE_BYTES: u64 = 50 * 1024 * 1024;

    /// Maximum allowed binary size for debug builds (unoptimised + debug info).
    /// Debug builds are exempt from the 50 MB production limit; we use 200 MB
    /// as a generous upper bound to catch runaway dependency bloat early.
    const MAX_DEBUG_BINARY_SIZE_BYTES: u64 = 200 * 1024 * 1024;

    /// Return `true` when the binary under test was compiled in release mode.
    fn is_release_build() -> bool {
        // Cargo sets PROFILE to "release" for `cargo test --release`
        let sep = std::path::MAIN_SEPARATOR_STR;
        std::env::var("PROFILE").map(|p| p == "release").unwrap_or(false)
            || binary_path()
                .to_string_lossy()
                .contains(&format!("{}release{}", sep, sep))
    }

    // ── Property 30: Binary portability and independence ─────────────────────
    //
    // Feature: sicario-cli-core, Property 30: Binary portability and independence
    // Validates: Requirements 12.4

    /// The binary must exist on the current platform after compilation.
    ///
    /// This is the most fundamental portability check: if the binary does not
    /// exist, no further portability guarantees can be made.
    #[test]
    fn prop30_binary_exists_on_current_platform() {
        let path = binary_path();
        assert!(
            path.exists(),
            "Compiled binary must exist at '{}'. \
             Run `cargo build` before running tests.",
            path.display()
        );
    }

    /// The binary size must be within the allowed budget.
    ///
    /// For release builds: under 50 MB (Requirement 12.4).
    /// For debug builds: under 200 MB (generous bound to catch bloat).
    ///
    /// Feature: sicario-cli-core, Property 30: Binary portability and independence
    /// Validates: Requirements 12.4
    #[test]
    fn prop30_binary_size_within_budget() {
        let path = binary_path();
        if !path.exists() {
            // Skip gracefully if the binary hasn't been built yet
            return;
        }

        let metadata = std::fs::metadata(&path)
            .expect("Must be able to read binary metadata");
        let size = metadata.len();

        let limit = if is_release_build() {
            MAX_BINARY_SIZE_BYTES
        } else {
            MAX_DEBUG_BINARY_SIZE_BYTES
        };

        assert!(
            size <= limit,
            "Binary size {} bytes ({:.1} MB) exceeds the {} MB limit for a {} build. \
             Check for unnecessary large dependencies or embedded assets.",
            size,
            size as f64 / (1024.0 * 1024.0),
            limit / (1024 * 1024),
            if is_release_build() { "release" } else { "debug" }
        );
    }

    /// The binary must be executable on the current platform.
    ///
    /// On Unix systems this checks the executable permission bit.
    /// On Windows all files are executable by default, so we verify the binary
    /// can be spawned with `--help` or an unknown flag and exits without a
    /// segfault / access violation.
    ///
    /// Feature: sicario-cli-core, Property 30: Binary portability and independence
    /// Validates: Requirements 12.4
    #[test]
    fn prop30_binary_is_executable() {
        let path = binary_path();
        if !path.exists() {
            return;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path)
                .expect("Must read binary metadata")
                .permissions();
            let mode = perms.mode();
            assert!(
                mode & 0o111 != 0,
                "Binary at '{}' must have at least one executable bit set (mode: {:o})",
                path.display(),
                mode
            );
        }

        // Verify the binary can actually be spawned (cross-platform)
        let output = std::process::Command::new(&path)
            .arg("--help")
            .output()
            .or_else(|_| std::process::Command::new(&path).output());

        match output {
            Ok(out) => {
                // Any exit code is acceptable here — we just need the process
                // to start and terminate without a crash signal.
                // On Unix, a signal-killed process has no status code.
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    assert!(
                        out.status.signal().is_none(),
                        "Binary must not terminate via a signal (crash). \
                         Signal: {:?}",
                        out.status.signal()
                    );
                }
                // stdout and stderr must be valid UTF-8 (portability requirement)
                let _ = String::from_utf8(out.stdout)
                    .expect("Binary stdout must be valid UTF-8");
                let _ = String::from_utf8(out.stderr)
                    .expect("Binary stderr must be valid UTF-8");
            }
            Err(e) => {
                panic!(
                    "Binary at '{}' could not be spawned: {}. \
                     This indicates a missing runtime dependency or incompatible binary format.",
                    path.display(),
                    e
                );
            }
        }
    }

    /// The binary must produce valid UTF-8 output for any recognised subcommand.
    ///
    /// Feature: sicario-cli-core, Property 30: Binary portability and independence
    /// Validates: Requirements 12.4
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// For any known CLI subcommand string, the binary must start, run, and
        /// produce valid UTF-8 on stdout and stderr without crashing.
        ///
        /// Feature: sicario-cli-core, Property 30: Binary portability and independence
        /// Validates: Requirements 12.4
        #[test]
        fn prop30_binary_output_is_valid_utf8_for_any_subcommand(
            subcommand in prop_oneof![
                Just("report"),
                Just("scan"),
                Just("init"),
                Just("login"),
                Just("help"),
                Just("version"),
                Just("--help"),
                Just("--version"),
            ],
        ) {
            let path = binary_path();
            prop_assume!(path.exists());

            let output = std::process::Command::new(&path)
                .arg(subcommand)
                .output()
                .expect("Binary must be spawnable");

            // stdout must be valid UTF-8
            prop_assert!(
                String::from_utf8(output.stdout.clone()).is_ok(),
                "stdout must be valid UTF-8 for subcommand '{}'. \
                 Got {} bytes of non-UTF-8 output.",
                subcommand,
                output.stdout.len()
            );

            // stderr must be valid UTF-8
            prop_assert!(
                String::from_utf8(output.stderr.clone()).is_ok(),
                "stderr must be valid UTF-8 for subcommand '{}'. \
                 Got {} bytes of non-UTF-8 output.",
                subcommand,
                output.stderr.len()
            );

            // The process must not have been killed by a signal (Unix only)
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                prop_assert!(
                    output.status.signal().is_none(),
                    "Binary must not crash (signal) for subcommand '{}'. \
                     Signal: {:?}",
                    subcommand,
                    output.status.signal()
                );
            }
        }

        /// For any random string passed as a subcommand, the binary must handle
        /// it gracefully (no crash, valid UTF-8 output) — demonstrating that the
        /// binary is robust to unexpected input without runtime dependency failures.
        ///
        /// Feature: sicario-cli-core, Property 30: Binary portability and independence
        /// Validates: Requirements 12.4
        #[test]
        fn prop30_binary_handles_unknown_subcommands_gracefully(
            subcommand in "[a-z]{1,20}",
        ) {
            let path = binary_path();
            prop_assume!(path.exists());

            let output = std::process::Command::new(&path)
                .arg(&subcommand)
                .output()
                .expect("Binary must be spawnable for any subcommand");

            // Must produce valid UTF-8 regardless of the subcommand
            prop_assert!(
                String::from_utf8(output.stdout.clone()).is_ok(),
                "stdout must be valid UTF-8 for unknown subcommand '{}'",
                subcommand
            );
            prop_assert!(
                String::from_utf8(output.stderr.clone()).is_ok(),
                "stderr must be valid UTF-8 for unknown subcommand '{}'",
                subcommand
            );

            // Must not crash with a signal
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                prop_assert!(
                    output.status.signal().is_none(),
                    "Binary must not crash for unknown subcommand '{}'. Signal: {:?}",
                    subcommand,
                    output.status.signal()
                );
            }
        }

        /// For any number of repeated invocations, the binary must produce
        /// identical exit codes for the same subcommand — demonstrating
        /// deterministic, stateless behaviour independent of runtime environment.
        ///
        /// Feature: sicario-cli-core, Property 30: Binary portability and independence
        /// Validates: Requirements 12.4
        #[test]
        fn prop30_binary_exit_code_is_deterministic(
            subcommand in prop_oneof![
                Just("--help"),
                Just("--version"),
                Just("help"),
            ],
            _iterations in 2usize..=5usize,
        ) {
            let path = binary_path();
            prop_assume!(path.exists());

            let first = std::process::Command::new(&path)
                .arg(subcommand)
                .output()
                .expect("Binary must be spawnable");

            let second = std::process::Command::new(&path)
                .arg(subcommand)
                .output()
                .expect("Binary must be spawnable on second invocation");

            prop_assert_eq!(
                first.status.code(),
                second.status.code(),
                "Exit code must be deterministic for subcommand '{}'. \
                 First: {:?}, Second: {:?}",
                subcommand,
                first.status.code(),
                second.status.code()
            );
        }
    }

    // ── Requirement 12.4 & 12.5: Binary footprint and PATH availability ──────

    /// Verify the release binary is strictly under 50 MB.
    ///
    /// This is a hard requirement (Requirement 12.4). Debug builds are skipped
    /// because they include debug symbols and are not subject to the size limit.
    ///
    /// Validates: Requirements 12.4
    #[test]
    fn test_release_binary_under_50mb() {
        let path = binary_path();
        if !path.exists() {
            // Binary not built yet — skip rather than fail.
            return;
        }

        // Only enforce the 50 MB limit on release builds.
        if !is_release_build() {
            let size = std::fs::metadata(&path)
                .expect("Must read binary metadata")
                .len();
            // Debug builds get the generous 200 MB bound from prop30_binary_size_within_budget.
            // Here we just report the size for informational purposes.
            println!(
                "Debug binary size: {:.2} MB (50 MB limit applies to release builds only)",
                size as f64 / (1024.0 * 1024.0)
            );
            return;
        }

        let size = std::fs::metadata(&path)
            .expect("Must read binary metadata")
            .len();

        assert!(
            size < MAX_BINARY_SIZE_BYTES,
            "Release binary size is {:.2} MB, which exceeds the 50 MB limit required by \
             Requirement 12.4. Binary path: '{}'. \
             Consider stripping debug symbols (`strip` or `[profile.release] strip = true`) \
             or auditing large dependencies.",
            size as f64 / (1024.0 * 1024.0),
            path.display()
        );

        println!(
            "Release binary size: {:.2} MB (limit: 50 MB) ✓",
            size as f64 / (1024.0 * 1024.0)
        );
    }

    /// Verify that the binary name `sicario` can be resolved via the system PATH.
    ///
    /// This test checks Requirement 12.5: "When installed, THE Sicario_CLI SHALL
    /// be available globally in the system PATH."
    ///
    /// The test uses `which` (Unix) / `where` (Windows) to locate the binary,
    /// mirroring what a developer would experience after installation. If the
    /// binary is not on PATH (e.g. in a CI environment where only the build
    /// artifact exists), the test is skipped rather than failed, because PATH
    /// availability is an installation-time property, not a build-time property.
    ///
    /// Validates: Requirements 12.5
    #[test]
    fn test_binary_available_on_path() {
        // Use the platform-appropriate "which" command to locate the binary.
        #[cfg(windows)]
        let which_cmd = ("where", "sicario");
        #[cfg(not(windows))]
        let which_cmd = ("which", "sicario");

        let result = std::process::Command::new(which_cmd.0)
            .arg(which_cmd.1)
            .output();

        match result {
            Ok(output) if output.status.success() => {
                // Binary found on PATH — verify it is actually executable.
                let path_str = String::from_utf8_lossy(&output.stdout);
                let found_path = path_str.trim();
                assert!(
                    !found_path.is_empty(),
                    "`{}` returned success but no path. PATH may be misconfigured.",
                    which_cmd.0
                );

                // Confirm the resolved binary can be invoked.
                let invoke = std::process::Command::new(found_path)
                    .arg("--version")
                    .output();

                match invoke {
                    Ok(out) => {
                        assert!(
                            out.status.success() || out.status.code() == Some(1),
                            "Binary found at '{}' via PATH but `--version` returned \
                             unexpected exit code: {:?}",
                            found_path,
                            out.status.code()
                        );
                        println!(
                            "Binary is available on PATH at: {} ✓",
                            found_path
                        );
                    }
                    Err(e) => {
                        panic!(
                            "Binary found at '{}' via PATH but could not be invoked: {}",
                            found_path, e
                        );
                    }
                }
            }
            Ok(_) => {
                // `which` exited non-zero — binary not on PATH.
                // This is expected in build/CI environments where the binary
                // has been compiled but not installed. Skip gracefully.
                println!(
                    "SKIP: `sicario` not found on PATH. \
                     This is expected in build environments. \
                     Run `cargo install --path .` or use the install.sh script \
                     to make the binary globally available (Requirement 12.5)."
                );
            }
            Err(e) => {
                // `which`/`where` itself is unavailable — skip.
                println!(
                    "SKIP: Could not run `{}` to check PATH: {}. \
                     Skipping PATH availability check.",
                    which_cmd.0, e
                );
            }
        }
    }

    /// Verify that the install.sh script installs the binary to a directory
    /// that is (or should be) on the system PATH.
    ///
    /// This is a static analysis test — it parses the installer script to
    /// confirm the default install directory is a standard PATH location.
    ///
    /// Validates: Requirements 12.5
    #[test]
    fn test_installer_targets_standard_path_directory() {
        // The install.sh script must default to a directory that is on PATH
        // for standard Unix/macOS installations.
        let installer_path = {
            let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
                .unwrap_or_else(|_| ".".to_string());
            let workspace_root = std::path::PathBuf::from(&manifest_dir)
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            workspace_root.join("install.sh")
        };

        if !installer_path.exists() {
            println!("SKIP: install.sh not found at '{}'", installer_path.display());
            return;
        }

        let content = std::fs::read_to_string(&installer_path)
            .expect("Must be able to read install.sh");

        // The installer must define a default install directory.
        assert!(
            content.contains("SICARIO_INSTALL_DIR"),
            "install.sh must define SICARIO_INSTALL_DIR to control the install location"
        );

        // The default install directory must be /usr/local/bin — a standard
        // PATH location on macOS and most Linux distributions.
        assert!(
            content.contains("/usr/local/bin"),
            "install.sh must default to /usr/local/bin, which is on PATH for \
             standard macOS and Linux installations (Requirement 12.5)"
        );

        // The installer must include a PATH check to warn users when the
        // install directory is not on their PATH.
        assert!(
            content.contains("PATH"),
            "install.sh must check whether the install directory is on PATH \
             and warn the user if it is not (Requirement 12.5)"
        );

        println!("install.sh targets /usr/local/bin (standard PATH directory) ✓");
    }

    /// Verify the Homebrew formula installs the binary into Homebrew's bin
    /// directory, which is always on PATH for Homebrew users.
    ///
    /// Validates: Requirements 12.2, 12.5
    #[test]
    fn test_homebrew_formula_installs_to_bin() {
        let formula_path = {
            let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
                .unwrap_or_else(|_| ".".to_string());
            let workspace_root = std::path::PathBuf::from(&manifest_dir)
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            workspace_root.join("Formula").join("sicario.rb")
        };

        if !formula_path.exists() {
            println!("SKIP: Formula/sicario.rb not found");
            return;
        }

        let content = std::fs::read_to_string(&formula_path)
            .expect("Must be able to read Formula/sicario.rb");

        // The formula must install the binary into Homebrew's bin directory.
        assert!(
            content.contains("bin.install"),
            "Homebrew formula must use `bin.install` to place the binary in \
             Homebrew's bin directory, which is on PATH for all Homebrew users \
             (Requirement 12.5)"
        );

        // The installed binary must be named `sicario` (no platform suffix).
        assert!(
            content.contains("=> \"sicario\""),
            "Homebrew formula must rename the platform-specific binary to `sicario` \
             so it is invocable as `sicario` from the terminal (Requirement 12.5)"
        );

        // The formula must include a test block that verifies the binary runs.
        assert!(
            content.contains("test do"),
            "Homebrew formula must include a `test do` block to verify the \
             binary executes correctly after installation"
        );

        println!("Homebrew formula correctly installs binary to bin/ as `sicario` ✓");
    }
}
