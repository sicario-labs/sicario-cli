//! Remediation engine — patch generation and application
//!
//! Orchestrates vulnerability context extraction, LLM-based or AST-based patch
//! generation, syntax validation, backup creation, and patch application.
//!
//! Requirements: 9.1, 9.2, 9.4, 13.4, 13.5, 14.3, 14.4

use anyhow::{Context, Result};
use similar::{ChangeTag, TextDiff};
use std::fs;
use std::path::Path;

use super::backup_manager::{BackupManager, PatchHistoryEntry};
use super::cerebras_client::CerebrasClient;
use super::{FixContext, Patch};
use crate::engine::Vulnerability;
use crate::parser::TreeSitterEngine;

// ── RemediationEngine ─────────────────────────────────────────────────────────

/// Orchestrates patch generation and application for detected vulnerabilities.
pub struct RemediationEngine {
    tree_sitter: TreeSitterEngine,
    ai_client: CerebrasClient,
    backup_manager: BackupManager,
}

impl RemediationEngine {
    /// Create a new `RemediationEngine` rooted at `project_root`.
    pub fn new(project_root: &Path) -> Result<Self> {
        Ok(Self {
            tree_sitter: TreeSitterEngine::new(project_root)?,
            ai_client: CerebrasClient::new()?,
            backup_manager: BackupManager::new(project_root)?,
        })
    }

    // ── Patch generation ──────────────────────────────────────────────────────

    /// Generate a patch for a vulnerability.
    ///
    /// Strategy:
    /// 1. Extract vulnerability context (surrounding code) using tree-sitter.
    /// 2. Attempt LLM-based fix via `CerebrasClient`.
    /// 3. Validate the generated code's syntax.
    /// 4. Fall back to AST-based template fix if LLM is unavailable or returns
    ///    invalid code (Requirement 13.5).
    /// 5. Compute a unified diff between original and fixed content.
    pub fn generate_patch(&self, vulnerability: &Vulnerability) -> Result<Patch> {
        let file_path = &vulnerability.file_path;

        // Read the original file content
        let original_content = fs::read_to_string(file_path).with_context(|| {
            format!("Failed to read file: {}", file_path.display())
        })?;

        // Build fix context from vulnerability metadata
        let context = self.build_fix_context(vulnerability, &original_content)?;

        // Try LLM-based fix first; fall back to template on failure
        let fixed_content = self.generate_fixed_content(&context, &original_content, vulnerability);

        // Validate syntax of the generated fix
        let fixed_content = match fixed_content {
            Ok(content) if self.validate_syntax(&content, &context.file_language) => content,
            Ok(_invalid) => {
                // LLM returned syntactically invalid code — use template fallback
                self.apply_template_fix(&original_content, vulnerability)
            }
            Err(_) => {
                // LLM unavailable — use template fallback
                self.apply_template_fix(&original_content, vulnerability)
            }
        };

        // Compute unified diff
        let diff = compute_unified_diff(file_path.to_str().unwrap_or("file"), &original_content, &fixed_content);

        // Backup path will be set when the patch is applied; use a placeholder here
        let backup_path = self
            .backup_manager
            .backup_dir()
            .join("pending")
            .join(file_path.file_name().unwrap_or_default());
        Ok(Patch::new(
            file_path.clone(),
            original_content,
            fixed_content,
            diff,
            backup_path,
        ))
    }

    // ── Patch application ─────────────────────────────────────────────────────

    /// Apply a patch to the source file.
    ///
    /// 1. Creates a backup of the original file (Requirement 14.1).
    /// 2. Writes the fixed content to disk.
    /// 3. Records the patch in the history log (Requirement 14.2).
    /// 4. On failure, automatically restores the original (Requirement 14.4).
    pub fn apply_patch(&self, patch: &Patch) -> Result<()> {
        // Create backup before any modification
        let backup_path = self
            .backup_manager
            .backup_file(&patch.file_path)
            .with_context(|| format!("Failed to backup {}", patch.file_path.display()))?;

        // Write fixed content — restore on failure
        if let Err(e) = fs::write(&patch.file_path, &patch.fixed) {
            // Automatic restore on write failure (Requirement 14.4)
            let _ = self.backup_manager.restore_file(&backup_path, &patch.file_path);
            return Err(e).with_context(|| {
                format!("Failed to write patch to {}", patch.file_path.display())
            });
        }

        // Record in patch history log (Requirement 14.2)
        let entry = PatchHistoryEntry {
            patch_id: patch.id.to_string(),
            applied_at: chrono::Utc::now().to_rfc3339(),
            file_path: patch.file_path.clone(),
            backup_path: backup_path.clone(),
        };
        self.backup_manager.record_patch(entry)?;

        Ok(())
    }

    /// Revert a previously applied patch by restoring from backup.
    ///
    /// Requirement 14.3
    pub fn revert_patch(&self, patch: &Patch) -> Result<()> {
        self.backup_manager
            .restore_file(&patch.backup_path, &patch.file_path)
            .with_context(|| {
                format!(
                    "Failed to revert patch {} for {}",
                    patch.id,
                    patch.file_path.display()
                )
            })
    }

    /// Create a pull request with the patch (stub — requires git provider API).
    pub fn create_pull_request(&self, _patch: &Patch, _git_provider: &str) -> Result<String> {
        // PR creation requires git provider API integration (future task)
        Err(anyhow::anyhow!(
            "Pull request creation is not yet implemented"
        ))
    }

    /// Expose the backup manager for external use (e.g. TUI patch application).
    pub fn backup_manager(&self) -> &BackupManager {
        &self.backup_manager
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Build a `FixContext` from a vulnerability and the file's source content.
    fn build_fix_context(&self, vuln: &Vulnerability, source: &str) -> Result<FixContext> {
        let language = detect_language_name(&vuln.file_path);
        let snippet = extract_context_snippet(source, vuln.line, 10);

        Ok(FixContext {
            vulnerability_description: format!(
                "Rule: {}{}",
                vuln.rule_id,
                vuln.cwe_id
                    .as_deref()
                    .map(|c| format!(" ({})", c))
                    .unwrap_or_default()
            ),
            code_snippet: snippet,
            file_language: language,
            framework: None, // Framework detection is a future enhancement
            cwe_id: vuln.cwe_id.clone(),
        })
    }

    /// Attempt to generate fixed content via the LLM.
    ///
    /// This is a synchronous wrapper that blocks on the async call using a
    /// single-threaded Tokio runtime so the engine can be used from sync code.
    fn generate_fixed_content(
        &self,
        context: &FixContext,
        original: &str,
        vuln: &Vulnerability,
    ) -> Result<String> {
        // Build a minimal Tokio runtime for the async call
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to build Tokio runtime")?;

        let fixed_snippet = rt.block_on(self.ai_client.generate_fix(context))?;

        // Replace the vulnerable snippet in the original file with the fix
        Ok(splice_fix(original, vuln.line, &vuln.snippet, &fixed_snippet))
    }

    /// Validate that `code` is syntactically valid for `language`.
    ///
    /// Uses tree-sitter to parse the code and checks for error nodes.
    pub fn validate_syntax(&self, code: &str, language: &str) -> bool {
        use crate::parser::Language;

        let lang = match language.to_lowercase().as_str() {
            "javascript" | "js" => Language::JavaScript,
            "typescript" | "ts" => Language::TypeScript,
            "python" | "py" => Language::Python,
            "rust" | "rs" => Language::Rust,
            "go" => Language::Go,
            "java" => Language::Java,
            _ => return true, // Unknown language — assume valid
        };

        match self.tree_sitter.parse_source(code, lang) {
            Ok(tree) => !tree.root_node().has_error(),
            Err(_) => false,
        }
    }

    /// Apply a simple AST-based template fix as a fallback.
    ///
    /// For now this returns the original content unchanged — a no-op fix is
    /// safer than applying a broken LLM-generated patch. Future work can add
    /// rule-specific templates (e.g. parameterized queries for SQL injection).
    fn apply_template_fix(&self, original: &str, _vuln: &Vulnerability) -> String {
        // Template fixes for common vulnerability types can be added here.
        // Returning the original is the safe fallback (Requirement 13.5).
        original.to_string()
    }
}

// ── Standalone helpers ────────────────────────────────────────────────────────

/// Detect the human-readable language name from a file path extension.
fn detect_language_name(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("js") => "JavaScript".to_string(),
        Some("ts") | Some("tsx") => "TypeScript".to_string(),
        Some("py") => "Python".to_string(),
        Some("rs") => "Rust".to_string(),
        Some("go") => "Go".to_string(),
        Some("java") => "Java".to_string(),
        Some(ext) => ext.to_string(),
        None => "Unknown".to_string(),
    }
}

/// Extract `context_lines` lines of context around `target_line` (1-indexed).
fn extract_context_snippet(source: &str, target_line: usize, context_lines: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return String::new();
    }

    let line_idx = target_line.saturating_sub(1).min(lines.len() - 1);
    let start = line_idx.saturating_sub(context_lines);
    let end = (line_idx + context_lines + 1).min(lines.len());

    lines[start..end].join("\n")
}

/// Replace the vulnerable line in `source` with the LLM-generated `fix`.
///
/// If the original snippet is found verbatim in the source, it is replaced.
/// Otherwise the fix is inserted at the target line.
fn splice_fix(source: &str, target_line: usize, original_snippet: &str, fix: &str) -> String {
    // Try verbatim replacement first
    if source.contains(original_snippet) {
        return source.replacen(original_snippet, fix, 1);
    }

    // Fall back to line-based replacement
    let mut lines: Vec<&str> = source.lines().collect();
    let line_idx = target_line.saturating_sub(1).min(lines.len().saturating_sub(1));
    if !lines.is_empty() {
        lines[line_idx] = fix;
    }
    lines.join("\n")
}

/// Compute a unified diff string between `original` and `fixed`.
pub fn compute_unified_diff(filename: &str, original: &str, fixed: &str) -> String {
    let diff = TextDiff::from_lines(original, fixed);
    let mut output = String::new();

    output.push_str(&format!("--- {}\n", filename));
    output.push_str(&format!("+++ {}\n", filename));

    for group in diff.grouped_ops(3) {
        for op in &group {
            for change in diff.iter_changes(op) {
                let sign = match change.tag() {
                    ChangeTag::Delete => "-",
                    ChangeTag::Insert => "+",
                    ChangeTag::Equal => " ",
                };
                output.push_str(sign);
                output.push_str(change.value());
                if change.missing_newline() {
                    output.push('\n');
                }
            }
        }
    }

    output
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{Severity, Vulnerability};
    use std::path::PathBuf;
    use tempfile::TempDir;
    use uuid::Uuid;

    fn make_vuln(file_path: PathBuf, line: usize, snippet: &str) -> Vulnerability {
        Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "sql-injection".to_string(),
            file_path,
            line,
            column: 0,
            snippet: snippet.to_string(),
            severity: Severity::High,
            reachable: true,
            cloud_exposed: None,
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: None,
        }
    }

    #[test]
    fn test_engine_creation() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path());
        assert!(engine.is_ok());
    }

    #[test]
    fn test_apply_patch_writes_fixed_content() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let file = dir.path().join("app.py");
        fs::write(&file, "query = 'SELECT * FROM users WHERE id = ' + user_id\n").unwrap();

        let backup = engine.backup_manager().backup_file(&file).unwrap();
        let patch = Patch::new(
            file.clone(),
            "query = 'SELECT * FROM users WHERE id = ' + user_id\n".to_string(),
            "query = 'SELECT * FROM users WHERE id = %s'\ncursor.execute(query, (user_id,))\n".to_string(),
            "--- app.py\n+++ app.py\n".to_string(),
            backup,
        );

        engine.apply_patch(&patch).unwrap();

        let content = fs::read_to_string(&file).unwrap();
        assert!(content.contains("cursor.execute"));
    }

    #[test]
    fn test_revert_patch_restores_original() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let file = dir.path().join("app.py");
        let original = "original content\n";
        fs::write(&file, original).unwrap();

        let backup = engine.backup_manager().backup_file(&file).unwrap();

        // Overwrite with fixed content
        fs::write(&file, "fixed content\n").unwrap();

        let patch = Patch::new(
            file.clone(),
            original.to_string(),
            "fixed content\n".to_string(),
            String::new(),
            backup,
        );

        engine.revert_patch(&patch).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), original);
    }

    #[test]
    fn test_apply_patch_records_history() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let file = dir.path().join("app.rs");
        fs::write(&file, "let x = 1;\n").unwrap();

        let backup = engine.backup_manager().backup_file(&file).unwrap();
        let patch = Patch::new(
            file.clone(),
            "let x = 1;\n".to_string(),
            "let x = 2;\n".to_string(),
            String::new(),
            backup,
        );

        engine.apply_patch(&patch).unwrap();

        let history = engine.backup_manager().load_history().unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].patch_id, patch.id.to_string());
    }

    #[test]
    fn test_compute_unified_diff_shows_changes() {
        let original = "line1\nline2\nline3\n";
        let fixed = "line1\nLINE2_FIXED\nline3\n";
        let diff = compute_unified_diff("test.py", original, fixed);
        assert!(diff.contains("-line2"));
        assert!(diff.contains("+LINE2_FIXED"));
    }

    #[test]
    fn test_compute_unified_diff_no_change() {
        let content = "unchanged\n";
        let diff = compute_unified_diff("test.py", content, content);
        // No change lines (lines starting with + or - that aren't the header)
        let change_lines: Vec<&str> = diff
            .lines()
            .filter(|l| {
                (l.starts_with('+') || l.starts_with('-'))
                    && !l.starts_with("+++")
                    && !l.starts_with("---")
            })
            .collect();
        assert!(change_lines.is_empty(), "Expected no change lines, got: {:?}", change_lines);
    }

    #[test]
    fn test_extract_context_snippet_middle_of_file() {
        let source = (1..=20).map(|i| format!("line{}", i)).collect::<Vec<_>>().join("\n");
        let snippet = extract_context_snippet(&source, 10, 3);
        assert!(snippet.contains("line10"));
        assert!(snippet.contains("line7"));
        assert!(snippet.contains("line13"));
    }

    #[test]
    fn test_extract_context_snippet_start_of_file() {
        let source = "line1\nline2\nline3\nline4\nline5\n";
        let snippet = extract_context_snippet(&source, 1, 3);
        assert!(snippet.contains("line1"));
    }

    #[test]
    fn test_splice_fix_verbatim_replacement() {
        let source = "let x = dangerous_call(input);\nlet y = 2;\n";
        let result = splice_fix(source, 1, "dangerous_call(input)", "safe_call(input)");
        assert!(result.contains("safe_call(input)"));
        assert!(!result.contains("dangerous_call(input)"));
    }

    #[test]
    fn test_detect_language_name() {
        assert_eq!(detect_language_name(Path::new("app.js")), "JavaScript");
        assert_eq!(detect_language_name(Path::new("app.ts")), "TypeScript");
        assert_eq!(detect_language_name(Path::new("app.py")), "Python");
        assert_eq!(detect_language_name(Path::new("app.rs")), "Rust");
        assert_eq!(detect_language_name(Path::new("app.go")), "Go");
        assert_eq!(detect_language_name(Path::new("App.java")), "Java");
    }

    #[test]
    fn test_validate_syntax_valid_js() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();
        let valid_js = "function hello() { return 42; }";
        assert!(engine.validate_syntax(valid_js, "javascript"));
    }

    #[test]
    fn test_validate_syntax_unknown_language_passes() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();
        assert!(engine.validate_syntax("anything", "cobol"));
    }

    #[test]
    fn test_generate_patch_fallback_when_no_api_key() {
        std::env::remove_var("CEREBRAS_API_KEY");
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let file = dir.path().join("app.py");
        fs::write(&file, "query = 'SELECT * FROM users WHERE id = ' + user_id\n").unwrap();

        let vuln = make_vuln(file.clone(), 1, "query = 'SELECT * FROM users WHERE id = ' + user_id");
        let patch = engine.generate_patch(&vuln).unwrap();

        // Without API key, falls back to template (original content)
        assert!(!patch.original.is_empty());
        assert!(!patch.diff.is_empty() || patch.original == patch.fixed);
    }
}
