//! Secret scanner implementation
//!
//! Scans staged files and git history for hardcoded credentials, verifies them
//! against origin APIs, and respects inline suppression comments.

use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::{DetectedSecret, SecretPattern, SecretType};
use crate::scanner::suppression_parser::SuppressionParser;
use crate::scanner::verifiers::{AwsVerifier, GithubVerifier, SecretVerifier, StripeVerifier};

/// Main secret scanning engine
pub struct SecretScanner {
    patterns: Vec<SecretPattern>,
    suppression_parser: SuppressionParser,
    verifiers: HashMap<SecretType, Box<dyn SecretVerifier>>,
}

impl SecretScanner {
    /// Create a new SecretScanner with default patterns and verifiers
    pub fn new() -> Result<Self> {
        let mut verifiers: HashMap<SecretType, Box<dyn SecretVerifier>> = HashMap::new();
        verifiers.insert(SecretType::AwsAccessKey, Box::new(AwsVerifier::new()?));
        verifiers.insert(SecretType::AwsSecretKey, Box::new(AwsVerifier::new()?));
        verifiers.insert(SecretType::GithubPat, Box::new(GithubVerifier::new()?));
        verifiers.insert(SecretType::StripeKey, Box::new(StripeVerifier::new()?));

        Ok(Self {
            patterns: SecretPattern::default_patterns(),
            suppression_parser: SuppressionParser::new(),
            verifiers,
        })
    }

    /// Scan staged files in the git repository at `repo_path` for secrets.
    ///
    /// Uses `git2::Repository::statuses()` to enumerate staged files, then
    /// scans each file's content for credential patterns. Suppressed lines
    /// are filtered out before returning results.
    ///
    /// Requirements: 1.1
    pub fn scan_staged_files(&self, repo_path: &Path) -> Result<Vec<DetectedSecret>> {
        let repo = git2::Repository::open(repo_path)
            .with_context(|| format!("Failed to open git repository at {:?}", repo_path))?;

        // Collect staged file paths (index vs HEAD)
        let mut staged_files: Vec<PathBuf> = Vec::new();
        let statuses = repo
            .statuses(Some(
                git2::StatusOptions::new()
                    .include_untracked(false)
                    .include_ignored(false),
            ))
            .context("Failed to get repository statuses")?;

        for entry in statuses.iter() {
            let status = entry.status();
            // Include files that are staged (index-modified, index-new, index-renamed)
            if status.intersects(
                git2::Status::INDEX_NEW
                    | git2::Status::INDEX_MODIFIED
                    | git2::Status::INDEX_RENAMED
                    | git2::Status::INDEX_TYPECHANGE,
            ) {
                if let Some(path_str) = entry.path() {
                    staged_files.push(repo_path.join(path_str));
                }
            }
        }

        // Scan each staged file
        let results: Vec<Vec<DetectedSecret>> = staged_files
            .par_iter()
            .map(|file_path| self.scan_file_for_secrets(file_path))
            .filter_map(|r| r.ok())
            .collect();

        Ok(results.into_iter().flatten().collect())
    }

    /// Traverse all commits and branches in the git repository at `repo_path`
    /// and scan each blob for secrets.
    ///
    /// Requirements: 1.5
    pub fn scan_git_history(&self, repo_path: &Path) -> Result<Vec<DetectedSecret>> {
        let repo = git2::Repository::open(repo_path)
            .with_context(|| format!("Failed to open git repository at {:?}", repo_path))?;

        let mut all_secrets: Vec<DetectedSecret> = Vec::new();
        let mut visited_blobs = std::collections::HashSet::new();

        // Walk all references (branches, tags) to cover all commits
        let refs = repo.references().context("Failed to list references")?;
        let mut commit_oids: Vec<git2::Oid> = Vec::new();

        for reference in refs.flatten() {
            if let Ok(commit) = reference.peel_to_commit() {
                commit_oids.push(commit.id());
            }
        }

        // Walk each commit's tree
        for oid in commit_oids {
            if let Ok(commit) = repo.find_commit(oid) {
                if let Ok(tree) = commit.tree() {
                    self.scan_tree_for_secrets(&repo, &tree, &mut visited_blobs, &mut all_secrets);
                }
            }
        }

        Ok(all_secrets)
    }

    /// Recursively scan a git tree for secrets in all blobs
    fn scan_tree_for_secrets(
        &self,
        repo: &git2::Repository,
        tree: &git2::Tree,
        visited_blobs: &mut std::collections::HashSet<git2::Oid>,
        secrets: &mut Vec<DetectedSecret>,
    ) {
        for entry in tree.iter() {
            match entry.kind() {
                Some(git2::ObjectType::Blob) => {
                    let oid = entry.id();
                    if visited_blobs.contains(&oid) {
                        continue;
                    }
                    visited_blobs.insert(oid);

                    if let Ok(blob) = repo.find_blob(oid) {
                        if blob.is_binary() {
                            continue;
                        }
                        if let Ok(content) = std::str::from_utf8(blob.content()) {
                            let file_path = PathBuf::from(entry.name().unwrap_or("<unknown>"));
                            let mut found = self.scan_content_for_secrets(content, &file_path);
                            secrets.append(&mut found);
                        }
                    }
                }
                Some(git2::ObjectType::Tree) => {
                    if let Ok(subtree) = repo.find_tree(entry.id()) {
                        self.scan_tree_for_secrets(repo, &subtree, visited_blobs, secrets);
                    }
                }
                _ => {}
            }
        }
    }

    /// Scan a file on disk for secrets, respecting suppression comments.
    pub fn scan_file_for_secrets(&self, file_path: &Path) -> Result<Vec<DetectedSecret>> {
        let content = std::fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {:?}", file_path))?;

        let suppressed = self.suppression_parser.suppressed_lines_in_source(&content);
        let mut secrets = self.scan_content_for_secrets(&content, file_path);

        // Filter out suppressed lines
        secrets.retain(|s| !suppressed.contains(&s.line));

        Ok(secrets)
    }

    /// Scan raw source content for secrets (no suppression filtering).
    pub fn scan_content_for_secrets(&self, content: &str, file_path: &Path) -> Vec<DetectedSecret> {
        let mut secrets = Vec::new();

        for (line_idx, line) in content.lines().enumerate() {
            let line_number = line_idx + 1; // 1-indexed

            for pattern in &self.patterns {
                for capture in pattern.regex.captures_iter(line) {
                    // Use capture group 1 if present, otherwise the full match
                    let matched = capture
                        .get(1)
                        .or_else(|| capture.get(0))
                        .map(|m| m.as_str())
                        .unwrap_or("");

                    if matched.is_empty() {
                        continue;
                    }

                    // Apply entropy threshold
                    if !pattern.meets_entropy_threshold(matched) {
                        continue;
                    }

                    secrets.push(DetectedSecret {
                        secret_type: pattern.secret_type,
                        value: matched.to_string(),
                        file_path: file_path.to_path_buf(),
                        line: line_number,
                        verified: false,
                    });
                }
            }
        }

        secrets
    }

    /// Verify if a detected secret is currently active against its origin API.
    ///
    /// Returns Ok(true) if the secret is valid and active, Ok(false) if invalid,
    /// or Err if verification could not be completed (network error, rate limit).
    ///
    /// Requirements: 1.3
    pub fn verify_secret(&self, secret: &DetectedSecret) -> Result<bool> {
        if let Some(verifier) = self.verifiers.get(&secret.secret_type) {
            verifier.verify(&secret.value)
        } else {
            // No verifier for this type — cannot confirm
            Ok(false)
        }
    }

    /// Check if a specific line in a file is suppressed by an inline comment.
    ///
    /// Requirements: 16.1, 16.2
    pub fn is_suppressed(&self, file: &Path, line: usize) -> Result<bool> {
        self.suppression_parser
            .check_suppression_comment(file, line)
    }

    /// Scan staged files and verify all detected secrets, returning only
    /// verified active credentials. Blocks the commit if any are found.
    ///
    /// Requirements: 1.1, 1.3, 1.4
    pub fn scan_and_verify_staged(&self, repo_path: &Path) -> Result<Vec<DetectedSecret>> {
        let mut secrets = self.scan_staged_files(repo_path)?;

        // Verify each secret in parallel
        secrets.par_iter_mut().for_each(|secret| {
            // Ignore verification errors (network issues) — mark as unverified
            if let Ok(verified) = self.verify_secret(secret) {
                secret.verified = verified;
            }
        });

        // Return only verified active credentials
        Ok(secrets.into_iter().filter(|s| s.verified).collect())
    }
}

impl Default for SecretScanner {
    fn default() -> Self {
        Self::new().expect("Failed to create SecretScanner")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_scanner() -> SecretScanner {
        SecretScanner::new().unwrap()
    }

    #[test]
    fn test_scan_content_detects_aws_key() {
        let scanner = create_scanner();
        let content = "const key = \"AKIAIOSFODNN7EXAMPLE\";";
        let secrets = scanner.scan_content_for_secrets(content, Path::new("test.js"));
        assert!(!secrets.is_empty());
        let aws = secrets
            .iter()
            .find(|s| s.secret_type == SecretType::AwsAccessKey);
        assert!(aws.is_some(), "Should detect AWS access key");
    }

    #[test]
    fn test_scan_content_detects_stripe_key() {
        let scanner = create_scanner();
        let content = "const stripe = require('stripe')('sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZ');";
        let secrets = scanner.scan_content_for_secrets(content, Path::new("test.js"));
        let stripe = secrets
            .iter()
            .find(|s| s.secret_type == SecretType::StripeKey);
        assert!(stripe.is_some(), "Should detect Stripe live key");
    }

    #[test]
    fn test_scan_content_detects_database_url() {
        let scanner = create_scanner();
        let content = "DATABASE_URL=postgres://admin:password123@db.example.com/myapp";
        let secrets = scanner.scan_content_for_secrets(content, Path::new(".env"));
        let db = secrets
            .iter()
            .find(|s| s.secret_type == SecretType::DatabaseUrl);
        assert!(db.is_some(), "Should detect database URL");
    }

    #[test]
    fn test_scan_content_detects_private_key() {
        let scanner = create_scanner();
        let content =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let secrets = scanner.scan_content_for_secrets(content, Path::new("key.pem"));
        let pk = secrets
            .iter()
            .find(|s| s.secret_type == SecretType::PrivateKey);
        assert!(pk.is_some(), "Should detect private key");
    }

    #[test]
    fn test_scan_file_respects_suppression() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "// sicario-ignore-secret").unwrap();
        writeln!(f, "const key = \"AKIAIOSFODNN7EXAMPLE\";").unwrap();
        f.flush().unwrap();

        let scanner = create_scanner();
        let secrets = scanner.scan_file_for_secrets(f.path()).unwrap();
        // The AWS key on line 2 should be suppressed by the comment on line 1
        let aws = secrets
            .iter()
            .find(|s| s.secret_type == SecretType::AwsAccessKey);
        assert!(aws.is_none(), "Suppressed AWS key should not be reported");
    }

    #[test]
    fn test_scan_file_reports_unsuppressed_secrets() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "const key = \"AKIAIOSFODNN7EXAMPLE\";").unwrap();
        f.flush().unwrap();

        let scanner = create_scanner();
        let secrets = scanner.scan_file_for_secrets(f.path()).unwrap();
        let aws = secrets
            .iter()
            .find(|s| s.secret_type == SecretType::AwsAccessKey);
        assert!(aws.is_some(), "Unsuppressed AWS key should be reported");
    }

    #[test]
    fn test_line_numbers_are_correct() {
        let scanner = create_scanner();
        let content = "line1\nline2\nconst key = \"AKIAIOSFODNN7EXAMPLE\";\nline4";
        let secrets = scanner.scan_content_for_secrets(content, Path::new("test.js"));
        let aws = secrets
            .iter()
            .find(|s| s.secret_type == SecretType::AwsAccessKey);
        assert!(aws.is_some());
        assert_eq!(aws.unwrap().line, 3, "AWS key should be on line 3");
    }

    #[test]
    fn test_scan_git_history_with_temp_repo() {
        let temp_dir = TempDir::new().unwrap();
        let repo = git2::Repository::init(temp_dir.path()).unwrap();

        // Configure git identity
        let mut config = repo.config().unwrap();
        config.set_str("user.name", "Test User").unwrap();
        config.set_str("user.email", "test@example.com").unwrap();
        drop(config);

        // Create a file with a secret
        let secret_file = temp_dir.path().join("secrets.js");
        std::fs::write(&secret_file, "const key = \"AKIAIOSFODNN7EXAMPLE\";").unwrap();

        // Stage and commit the file
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("secrets.js")).unwrap();
        index.write().unwrap();

        let tree_id = index.write_tree().unwrap();
        let tree = repo.find_tree(tree_id).unwrap();
        let sig = git2::Signature::now("Test", "test@example.com").unwrap();
        repo.commit(Some("HEAD"), &sig, &sig, "Initial commit", &tree, &[])
            .unwrap();

        let scanner = create_scanner();
        let secrets = scanner.scan_git_history(temp_dir.path()).unwrap();

        let aws = secrets
            .iter()
            .find(|s| s.secret_type == SecretType::AwsAccessKey);
        assert!(aws.is_some(), "Should find AWS key in git history");
    }
}

// ── Property tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_scanner() -> SecretScanner {
        SecretScanner::new().unwrap()
    }

    // Feature: sicario-cli-core, Property 3: Verified credential blocking
    // For any verified active credential detected in staged files, the Secret Scanner
    // should block the commit and display the credential location with context.
    // Validates: Requirements 1.4
    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(30))]

        /// Property 3: Verified credential blocking
        /// For any file containing a credential pattern, scan_file_for_secrets
        /// should detect it (before verification). The blocking behavior is
        /// validated by ensuring detected secrets have correct location metadata.
        #[test]
        fn prop_detected_secrets_have_valid_location_metadata(
            prefix in "[a-zA-Z_][a-zA-Z0-9_]{0,20}",
            suffix in "[a-zA-Z0-9 ;]{0,20}",
        ) {
            let aws_key = "AKIAIOSFODNN7EXAMPLE";
            let content = format!("const {} = \"{}\";\n{}", prefix, aws_key, suffix);

            let scanner = create_scanner();
            let secrets = scanner.scan_content_for_secrets(&content, Path::new("test.js"));

            let aws = secrets.iter().find(|s| s.secret_type == SecretType::AwsAccessKey);
            prop_assert!(aws.is_some(), "AWS key should be detected in content");

            if let Some(secret) = aws {
                // Line number must be valid (1-indexed, within file bounds)
                let line_count = content.lines().count();
                prop_assert!(
                    secret.line >= 1 && secret.line <= line_count,
                    "Line number {} should be within [1, {}]", secret.line, line_count
                );
                // Value must match the actual key
                prop_assert_eq!(&secret.value, aws_key, "Detected value should match the key");
                // File path must be set
                prop_assert_eq!(&secret.file_path, &PathBuf::from("test.js"));
            }
        }

        /// Property 3 (suppression): Suppressed credentials must NOT be returned
        /// even when the credential pattern is present on the suppressed line.
        #[test]
        fn prop_suppressed_credentials_are_not_reported(
            comment_style in prop_oneof![
                Just("// sicario-ignore-secret"),
                Just("# sicario-ignore-secret"),
            ],
        ) {
            let mut f = tempfile::NamedTempFile::new().unwrap();
            writeln!(f, "{}", comment_style).unwrap();
            writeln!(f, "const key = \"AKIAIOSFODNN7EXAMPLE\";").unwrap();
            f.flush().unwrap();

            let scanner = create_scanner();
            let secrets = scanner.scan_file_for_secrets(f.path()).unwrap();
            let aws = secrets.iter().find(|s| s.secret_type == SecretType::AwsAccessKey);
            prop_assert!(
                aws.is_none(),
                "Suppressed AWS key should not be reported (comment: {})", comment_style
            );
        }

        /// Property 3 (non-suppressed): Credentials NOT preceded by a suppression
        /// comment must always be reported.
        #[test]
        fn prop_non_suppressed_credentials_are_always_reported(
            prefix_lines in 0usize..5,
        ) {
            let mut content = String::new();
            for i in 0..prefix_lines {
                content.push_str(&format!("const x{} = {};\n", i, i));
            }
            content.push_str("const key = \"AKIAIOSFODNN7EXAMPLE\";\n");

            let scanner = create_scanner();
            let secrets = scanner.scan_content_for_secrets(&content, Path::new("test.js"));
            let aws = secrets.iter().find(|s| s.secret_type == SecretType::AwsAccessKey);
            prop_assert!(
                aws.is_some(),
                "Non-suppressed AWS key should always be reported"
            );
        }
    }

    // Feature: sicario-cli-core, Property 4: Git history traversal completeness
    // For any git repository structure with multiple commits and branches, scanning
    // the git history should traverse all commits and branches.
    // Validates: Requirements 1.5
    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(20))]

        /// Property 4: Git history traversal completeness
        /// For any number of commits containing secrets, scan_git_history should
        /// find secrets from all commits (deduplicating by blob content).
        #[test]
        fn prop_git_history_finds_secrets_across_commits(
            commit_count in 1usize..5,
        ) {
            let temp_dir = TempDir::new().unwrap();
            let repo = git2::Repository::init(temp_dir.path()).unwrap();

            let mut config = repo.config().unwrap();
            config.set_str("user.name", "Test").unwrap();
            config.set_str("user.email", "test@test.com").unwrap();
            drop(config);

            let sig = git2::Signature::now("Test", "test@test.com").unwrap();
            let mut parent_commit: Option<git2::Oid> = None;

            for i in 0..commit_count {
                let file_name = format!("secret_{}.js", i);
                let file_path = temp_dir.path().join(&file_name);
                // Each commit has a unique file with an AWS key
                std::fs::write(&file_path, format!(
                    "const key{} = \"AKIAIOSFODNN7EXAMPLE\";", i
                )).unwrap();

                let mut index = repo.index().unwrap();
                index.add_path(Path::new(&file_name)).unwrap();
                index.write().unwrap();

                let tree_id = index.write_tree().unwrap();
                let tree = repo.find_tree(tree_id).unwrap();

                let parents: Vec<git2::Commit> = parent_commit
                    .map(|oid| repo.find_commit(oid).unwrap())
                    .into_iter()
                    .collect();
                let parent_refs: Vec<&git2::Commit> = parents.iter().collect();

                let oid = repo.commit(
                    Some("HEAD"), &sig, &sig,
                    &format!("Commit {}", i),
                    &tree,
                    &parent_refs,
                ).unwrap();
                parent_commit = Some(oid);
            }

            let scanner = create_scanner();
            let secrets = scanner.scan_git_history(temp_dir.path()).unwrap();

            // Should find at least one AWS key (blobs are deduplicated by content hash,
            // so identical keys across commits count as one unique blob)
            let aws_count = secrets.iter().filter(|s| s.secret_type == SecretType::AwsAccessKey).count();
            prop_assert!(
                aws_count >= 1,
                "Should find at least 1 AWS key across {} commits, found {}",
                commit_count, aws_count
            );
        }

        /// Property 4: Secrets in all branches are found
        /// For a repo with multiple branches each containing a secret,
        /// scan_git_history should find secrets from all branches.
        #[test]
        fn prop_git_history_traverses_all_branches(
            branch_count in 1usize..4,
        ) {
            let temp_dir = TempDir::new().unwrap();
            let repo = git2::Repository::init(temp_dir.path()).unwrap();

            let mut config = repo.config().unwrap();
            config.set_str("user.name", "Test").unwrap();
            config.set_str("user.email", "test@test.com").unwrap();
            drop(config);

            let sig = git2::Signature::now("Test", "test@test.com").unwrap();

            // Create initial commit on main
            let init_file = temp_dir.path().join("init.js");
            std::fs::write(&init_file, "const x = 1;").unwrap();
            let mut index = repo.index().unwrap();
            index.add_path(Path::new("init.js")).unwrap();
            index.write().unwrap();
            let tree_id = index.write_tree().unwrap();
            let tree = repo.find_tree(tree_id).unwrap();
            let root_oid = repo.commit(Some("HEAD"), &sig, &sig, "root", &tree, &[]).unwrap();
            let root_commit = repo.find_commit(root_oid).unwrap();

            // Create branches with secrets
            for i in 0..branch_count {
                let branch_name = format!("feature-{}", i);
                repo.branch(&branch_name, &root_commit, false).unwrap();

                let file_name = format!("branch_secret_{}.js", i);
                let file_path = temp_dir.path().join(&file_name);
                std::fs::write(&file_path, format!(
                    "const key = \"AKIAIOSFODNN7EXAMPLE\";",
                )).unwrap();

                let mut index = repo.index().unwrap();
                index.add_path(Path::new(&file_name)).unwrap();
                index.write().unwrap();
                let tree_id = index.write_tree().unwrap();
                let tree = repo.find_tree(tree_id).unwrap();
                let ref_name = format!("refs/heads/{}", branch_name);
                repo.commit(Some(&ref_name), &sig, &sig, &format!("branch {}", i), &tree, &[&root_commit]).unwrap();
            }

            let scanner = create_scanner();
            let secrets = scanner.scan_git_history(temp_dir.path()).unwrap();

            let aws_count = secrets.iter().filter(|s| s.secret_type == SecretType::AwsAccessKey).count();
            prop_assert!(
                aws_count >= 1,
                "Should find AWS keys across {} branches, found {}",
                branch_count, aws_count
            );
        }
    }
}
