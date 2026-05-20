//! File exclusion management
//!
//! Handles .gitignore and .sicarioignore patterns to filter files during scanning.

use anyhow::Result;
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::{Path, PathBuf};

/// Manages file exclusion patterns from .gitignore and .sicarioignore
#[derive(Clone)]
pub struct ExclusionManager {
    gitignore_patterns: GlobSet,
    sicarioignore_patterns: GlobSet,
    default_excludes: GlobSet,
    extra_excludes: GlobSet,
}

impl ExclusionManager {
    /// Create a new ExclusionManager for the given project root
    pub fn new(project_root: &Path) -> Result<Self> {
        let mut manager = Self {
            gitignore_patterns: GlobSet::empty(),
            sicarioignore_patterns: GlobSet::empty(),
            default_excludes: Self::build_default_excludes()?,
            extra_excludes: GlobSet::empty(),
        };

        // Load .gitignore if it exists
        let gitignore_path = project_root.join(".gitignore");
        if gitignore_path.exists() {
            manager.load_gitignore(&gitignore_path)?;
        }

        // Load .sicarioignore if it exists
        let sicarioignore_path = project_root.join(".sicarioignore");
        if sicarioignore_path.exists() {
            manager.load_sicarioignore(&sicarioignore_path)?;
        }

        Ok(manager)
    }

    /// Create an ExclusionManager with no patterns at all — not even the
    /// built-in default excludes. Used by `BehavioralScanner` to scan inside
    /// `node_modules` without any exclusion filtering.
    pub fn new_empty() -> Self {
        Self {
            gitignore_patterns: GlobSet::empty(),
            sicarioignore_patterns: GlobSet::empty(),
            default_excludes: GlobSet::empty(),
            extra_excludes: GlobSet::empty(),
        }
    }

    /// Create an ExclusionManager with only the built-in default excludes and
    /// no patterns loaded from `.gitignore` or `.sicarioignore`.
    ///
    /// Used as a fallback when the watched directory cannot be read (e.g. the
    /// path does not exist yet at startup).  The default excludes (node_modules,
    /// target, dist, …) are still applied so the watcher never scans build
    /// artefacts even in the fallback case.
    pub fn empty() -> Self {
        Self {
            gitignore_patterns: GlobSet::empty(),
            sicarioignore_patterns: GlobSet::empty(),
            default_excludes: Self::build_default_excludes().unwrap_or_else(|_| GlobSet::empty()),
            extra_excludes: GlobSet::empty(),
        }
    }

    /// Build default exclusion patterns
    fn build_default_excludes() -> Result<GlobSet> {
        let mut builder = GlobSetBuilder::new();

        // ── Build artefacts & package managers ───────────────────────────
        let defaults = vec![
            "**/node_modules/**",
            "**/dist/**",
            "**/build/**",
            "**/target/**",
            "**/.git/**",
            "**/*.min.js",
            "**/*.bundle.js",
            "**/*.map",
            "**/__pycache__/**",
            "**/*.pyc",
            "**/.venv/**",
            "**/venv/**",
            "**/.sicario/backups/**",
            "**/.sicario/cache/**",
            // ── Smart default exclusions: test & fixture directories ──────
            // These directories contain intentional test code where patterns
            // like unwrap(), eval(), and hardcoded values are expected and safe.
            // Scanning them produces high-volume Low-severity noise with no
            // actionable signal for enterprise CI/CD pipelines.
            "**/tests/**",
            "**/test/**",
            "**/mocks/**",
            "**/fixtures/**",
            "**/testdata/**",
            "**/test-data/**",
            // ── Smart default exclusions: test file patterns ──────────────
            "**/*_test.rs",
            "**/*_test.js",
            "**/*_test.ts",
            "**/*_test.py",
            "**/*.spec.ts",
            "**/*.spec.js",
            "**/*.test.ts",
            "**/*.test.tsx",
            "**/*.test.js",
            "**/*.test.jsx",
        ];

        for pattern in defaults {
            builder.add(Glob::new(pattern)?);
        }

        Ok(builder.build()?)
    }

    /// Load patterns from .gitignore
    fn load_gitignore(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        let mut builder = GlobSetBuilder::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle negation patterns (lines starting with !)
            if line.starts_with('!') {
                // Negation patterns are not directly supported in globset
                // For now, we skip them (could be enhanced later)
                continue;
            }

            // Convert gitignore pattern to glob pattern
            let pattern = if line.ends_with('/') {
                // Directory pattern
                format!("{}**", line)
            } else if !line.contains('/') {
                // Match anywhere in tree
                format!("**/{}", line)
            } else {
                // Relative path pattern
                line.to_string()
            };

            if let Ok(glob) = Glob::new(&pattern) {
                builder.add(glob);
            }
        }

        self.gitignore_patterns = builder.build()?;
        Ok(())
    }

    /// Load patterns from .sicarioignore
    pub fn load_sicarioignore(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        let mut builder = GlobSetBuilder::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Handle negation patterns (lines starting with !)
            if line.starts_with('!') {
                continue;
            }

            // Normalize to forward slashes for cross-platform consistency
            let line = &line.replace('\\', "/");

            // Convert pattern to glob pattern
            let pattern = if line.ends_with('/') {
                // Directory pattern — match everything inside at any depth
                format!("**/{}**", line)
            } else if let Some(stripped) = line.strip_prefix('/') {
                // Rooted pattern — strip leading slash, match from scan root
                stripped.to_string()
            } else if !line.contains('/') {
                // Bare filename — match anywhere in tree
                format!("**/{}", line)
            } else {
                // Relative path like `src/pages/Home.tsx` — add **/ prefix so it
                // matches regardless of how the path is rooted (absolute, `./`, etc.)
                format!("**/{}", line)
            };

            if let Ok(glob) = Glob::new(&pattern) {
                builder.add(glob);
            }
        }

        self.sicarioignore_patterns = builder.build()?;
        Ok(())
    }

    /// Check if a path should be excluded from scanning
    pub fn is_excluded(&self, path: &Path) -> bool {
        // Normalize to forward-slash string for cross-platform glob matching.
        // globset patterns always use `/`; Windows paths use `\`.
        let normalized = path.to_string_lossy().replace('\\', "/");
        let normalized_path = Path::new(&normalized);

        self.default_excludes.is_match(normalized_path)
            || self.gitignore_patterns.is_match(normalized_path)
            || self.sicarioignore_patterns.is_match(normalized_path)
            || self.extra_excludes.is_match(normalized_path)
    }

    /// Disable .gitignore pattern matching (Task 52.7: --no-git-ignore flag).
    /// After calling this, `.gitignore` patterns are no longer applied.
    /// `.sicarioignore` patterns and default excludes are still active.
    pub fn disable_gitignore(&mut self) {
        self.gitignore_patterns = GlobSet::empty();
    }

    /// Add extra exclude glob patterns (Task 60.2: --exclude flag).
    /// Patterns are added on top of existing exclusions without overwriting
    /// `.sicarioignore` patterns.
    pub fn add_exclude_patterns(&mut self, patterns: &[String]) -> Result<()> {
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            if let Ok(glob) = Glob::new(pattern) {
                builder.add(glob);
            }
        }
        self.extra_excludes = builder.build()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_default_exclusions() {
        let temp_dir = std::env::temp_dir();
        let manager = ExclusionManager::new(&temp_dir).unwrap();

        assert!(manager.is_excluded(Path::new("node_modules/package/index.js")));
        assert!(manager.is_excluded(Path::new("dist/bundle.js")));
        assert!(manager.is_excluded(Path::new("target/debug/app")));
        assert!(!manager.is_excluded(Path::new("src/main.rs")));
    }

    #[test]
    fn test_gitignore_loading() {
        let temp_dir = std::env::temp_dir().join("sicario_gitignore_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create a .gitignore file
        let gitignore_path = temp_dir.join(".gitignore");
        fs::write(&gitignore_path, "*.log\ntemp/\n# Comment\n\nbuild/**/*.o").unwrap();

        let manager = ExclusionManager::new(&temp_dir).unwrap();

        // Test patterns from .gitignore
        assert!(manager.is_excluded(Path::new("debug.log")));
        assert!(manager.is_excluded(Path::new("src/debug.log")));
        assert!(manager.is_excluded(Path::new("temp/file.txt")));
        assert!(manager.is_excluded(Path::new("build/src/main.o")));
        assert!(!manager.is_excluded(Path::new("src/main.rs")));

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_sicarioignore_loading() {
        let temp_dir = std::env::temp_dir().join("sicario_sicarioignore_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create a .sicarioignore file
        let sicarioignore_path = temp_dir.join(".sicarioignore");
        fs::write(
            &sicarioignore_path,
            "*.test.js\nfixtures/\n# Test comment\n\nvendor/**",
        )
        .unwrap();

        let manager = ExclusionManager::new(&temp_dir).unwrap();

        // Test patterns from .sicarioignore
        assert!(manager.is_excluded(Path::new("app.test.js")));
        assert!(manager.is_excluded(Path::new("src/app.test.js")));
        assert!(manager.is_excluded(Path::new("fixtures/data.json")));
        assert!(manager.is_excluded(Path::new("vendor/lib/module.js")));
        assert!(!manager.is_excluded(Path::new("src/app.js")));

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_combined_exclusions() {
        let temp_dir = std::env::temp_dir().join("sicario_combined_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create both .gitignore and .sicarioignore
        let gitignore_path = temp_dir.join(".gitignore");
        fs::write(&gitignore_path, "*.log").unwrap();

        let sicarioignore_path = temp_dir.join(".sicarioignore");
        fs::write(&sicarioignore_path, "*.test.js").unwrap();

        let manager = ExclusionManager::new(&temp_dir).unwrap();

        // Test patterns from both files
        assert!(manager.is_excluded(Path::new("debug.log")));
        assert!(manager.is_excluded(Path::new("app.test.js")));
        assert!(manager.is_excluded(Path::new("node_modules/lib.js"))); // default
        assert!(!manager.is_excluded(Path::new("src/app.js")));

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_directory_patterns() {
        let temp_dir = std::env::temp_dir().join("sicario_dir_test");
        fs::create_dir_all(&temp_dir).unwrap();

        let gitignore_path = temp_dir.join(".gitignore");
        fs::write(&gitignore_path, "cache/\nlogs/").unwrap();

        let manager = ExclusionManager::new(&temp_dir).unwrap();

        assert!(manager.is_excluded(Path::new("cache/data.db")));
        assert!(manager.is_excluded(Path::new("cache/subdir/file.txt")));
        assert!(manager.is_excluded(Path::new("logs/app.log")));
        assert!(!manager.is_excluded(Path::new("src/cache.rs")));

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_empty_ignore_files() {
        let temp_dir = std::env::temp_dir().join("sicario_empty_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Create empty .gitignore
        let gitignore_path = temp_dir.join(".gitignore");
        fs::write(&gitignore_path, "").unwrap();

        let manager = ExclusionManager::new(&temp_dir).unwrap();

        // Should still have default exclusions
        assert!(manager.is_excluded(Path::new("node_modules/lib.js")));
        assert!(!manager.is_excluded(Path::new("src/main.rs")));

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_comments_and_empty_lines() {
        let temp_dir = std::env::temp_dir().join("sicario_comments_test");
        fs::create_dir_all(&temp_dir).unwrap();

        let gitignore_path = temp_dir.join(".gitignore");
        fs::write(
            &gitignore_path,
            "# This is a comment\n\n*.log\n\n# Another comment\n*.tmp",
        )
        .unwrap();

        let manager = ExclusionManager::new(&temp_dir).unwrap();

        assert!(manager.is_excluded(Path::new("debug.log")));
        assert!(manager.is_excluded(Path::new("temp.tmp")));
        assert!(!manager.is_excluded(Path::new("src/main.rs")));

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_no_ignore_files() {
        let temp_dir = std::env::temp_dir().join("sicario_no_ignore_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Don't create any ignore files
        let manager = ExclusionManager::new(&temp_dir).unwrap();

        // Should only have default exclusions
        assert!(manager.is_excluded(Path::new("node_modules/lib.js")));
        assert!(manager.is_excluded(Path::new("dist/bundle.js")));
        assert!(!manager.is_excluded(Path::new("src/main.rs")));

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    /// Validates that the `empty()` fallback constructor still applies default
    /// excludes (node_modules, target, dist, …) even when no ignore files are
    /// present.  This is the path taken by `run_watch_mode` when the watched
    /// directory cannot be read at startup.
    #[test]
    fn test_empty_constructor_applies_default_excludes() {
        let manager = ExclusionManager::empty();

        // Default excludes must still be active
        assert!(manager.is_excluded(Path::new("node_modules/lib.js")));
        assert!(manager.is_excluded(Path::new("dist/bundle.js")));
        assert!(manager.is_excluded(Path::new("target/debug/app")));

        // Regular source files must not be excluded
        assert!(!manager.is_excluded(Path::new("src/main.rs")));
        assert!(!manager.is_excluded(Path::new("src/app.js")));
    }

    /// Validates the watch-mode exclusion path (Req 18.6):
    /// files matching `.gitignore` or `.sicarioignore` patterns must be
    /// identified as excluded so the watcher can skip them silently.
    #[test]
    fn test_watch_mode_exclusion_check() {
        let temp_dir = std::env::temp_dir().join("sicario_watch_excl_test");
        fs::create_dir_all(&temp_dir).unwrap();

        // Simulate a project with both ignore files
        let gitignore_path = temp_dir.join(".gitignore");
        fs::write(&gitignore_path, "*.generated.ts\nvendor/").unwrap();

        let sicarioignore_path = temp_dir.join(".sicarioignore");
        fs::write(&sicarioignore_path, "vuln-sandbox/\nlegacy/").unwrap();

        let manager = ExclusionManager::new(&temp_dir).unwrap();

        // Files matching .gitignore patterns must be excluded
        assert!(manager.is_excluded(Path::new("src/api.generated.ts")));
        assert!(manager.is_excluded(Path::new("vendor/lib/index.js")));

        // Files matching .sicarioignore patterns must be excluded
        assert!(manager.is_excluded(Path::new("vuln-sandbox/node/sql-injection.js")));
        assert!(manager.is_excluded(Path::new("legacy/auth.py")));

        // Regular source files must not be excluded
        assert!(!manager.is_excluded(Path::new("src/auth.ts")));
        assert!(!manager.is_excluded(Path::new("src/main.py")));

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use std::fs;

    // Feature: sicario-cli-core, Property 34: Exclusion pattern effectiveness
    // Validates: Requirements 15.1, 15.2, 15.3, 15.4
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        #[test]
        fn test_exclusion_pattern_effectiveness(
            pattern_count in 1usize..10,
            file_count in 5usize..20
        ) {
            let temp_dir = std::env::temp_dir().join(format!("sicario_excl_prop_{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&temp_dir).unwrap();

            // Generate random exclusion patterns
            let patterns = generate_exclusion_patterns(pattern_count);

            // Create .sicarioignore with generated patterns
            let sicarioignore_path = temp_dir.join(".sicarioignore");
            fs::write(&sicarioignore_path, patterns.join("\n")).unwrap();

            let manager = ExclusionManager::new(&temp_dir).unwrap();

            // Generate test file paths
            let test_files = generate_test_file_paths(file_count);

            // Test that patterns are applied correctly
            for file_path in &test_files {
                let is_excluded = manager.is_excluded(Path::new(file_path));

                // Verify exclusion logic
                let should_be_excluded = should_match_patterns(file_path, &patterns);

                // Allow for default exclusions to also match
                if should_be_excluded {
                    prop_assert!(is_excluded, "File {} should be excluded by pattern", file_path);
                }
                // Note: We don't assert !is_excluded when should_be_excluded is false
                // because default patterns might also match
            }

            // Test default exclusions are always applied
            prop_assert!(manager.is_excluded(Path::new("node_modules/lib.js")));
            prop_assert!(manager.is_excluded(Path::new("dist/bundle.js")));
            prop_assert!(manager.is_excluded(Path::new("target/debug/app")));

            // Cleanup
            fs::remove_dir_all(&temp_dir).ok();
        }
    }

    // Helper function to generate random exclusion patterns
    fn generate_exclusion_patterns(count: usize) -> Vec<String> {
        let mut patterns = Vec::new();
        let extensions = ["log", "tmp", "bak", "cache"];
        let dirs = ["temp", "cache", "logs", "backup"];

        for i in 0..count {
            if i % 2 == 0 {
                // File extension pattern
                patterns.push(format!("*.{}", extensions[i % extensions.len()]));
            } else {
                // Directory pattern
                patterns.push(format!("{}/", dirs[i % dirs.len()]));
            }
        }

        patterns
    }

    // Helper function to generate test file paths
    fn generate_test_file_paths(count: usize) -> Vec<String> {
        let mut paths = Vec::new();
        let extensions = ["js", "rs", "py", "log", "tmp", "bak"];
        let dirs = ["src", "lib", "temp", "cache", "logs"];

        for i in 0..count {
            let dir = &dirs[i % dirs.len()];
            let ext = &extensions[i % extensions.len()];
            paths.push(format!("{}/file{}.{}", dir, i, ext));
        }

        paths
    }

    // Helper function to check if a file should match given patterns
    fn should_match_patterns(file_path: &str, patterns: &[String]) -> bool {
        for pattern in patterns {
            if pattern.ends_with('/') {
                // Directory pattern
                let dir_name = pattern.trim_end_matches('/');
                if file_path.starts_with(&format!("{}/", dir_name))
                    || file_path.contains(&format!("/{}/", dir_name))
                {
                    return true;
                }
            } else if pattern.starts_with("*.") {
                // Extension pattern
                let ext = pattern.trim_start_matches("*.");
                if file_path.ends_with(&format!(".{}", ext)) {
                    return true;
                }
            } else if file_path.contains(pattern) {
                // General pattern match
                return true;
            }
        }
        false
    }
}
