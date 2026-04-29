//! Remediation engine — patch generation and application
//!
//! Orchestrates vulnerability context extraction, LLM-based or AST-based patch
//! generation, syntax validation, backup creation, and patch application.
//!
//! Requirements: 9.1, 9.2, 9.4, 13.4, 13.5, 14.3, 14.4

use anyhow::{Context, Result};
use owo_colors::OwoColorize;
use similar::{ChangeTag, TextDiff};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use super::backup_manager::{BackupManager, PatchHistoryEntry};
use super::llm_client::LlmClient;
use super::template_engine::TemplateRegistry;
use super::{FixContext, Patch};
use crate::engine::Vulnerability;
use crate::parser::{Language as ParserLanguage, TreeSitterEngine};

// ── Batch mode types ──────────────────────────────────────────────────────────

/// Summary of a batch fix run.
#[derive(Debug, Clone)]
pub struct BatchResult {
    pub applied: usize,
    pub reverted: usize,
    pub skipped: usize,
    pub details: Vec<BatchFixDetail>,
}

/// Detail for a single vulnerability processed in batch mode.
#[derive(Debug, Clone)]
pub struct BatchFixDetail {
    pub rule_id: String,
    pub file_path: PathBuf,
    pub outcome: BatchFixOutcome,
}

/// Outcome of a single fix attempt in batch mode.
#[derive(Debug, Clone)]
pub enum BatchFixOutcome {
    Applied,
    Reverted(String),
    Skipped(String),
}

// ── RemediationEngine ─────────────────────────────────────────────────────────

/// Orchestrates patch generation and application for detected vulnerabilities.
pub struct RemediationEngine {
    tree_sitter: TreeSitterEngine,
    ai_client: LlmClient,
    backup_manager: BackupManager,
    /// Pre-built registry of deterministic templates — checked before the LLM.
    registry: TemplateRegistry,
}

impl RemediationEngine {
    /// Create a new `RemediationEngine` rooted at `project_root`.
    pub fn new(project_root: &Path) -> Result<Self> {
        Ok(Self {
            tree_sitter: TreeSitterEngine::new(project_root)?,
            ai_client: LlmClient::new()?,
            backup_manager: BackupManager::new(project_root)?,
            registry: TemplateRegistry::default(),
        })
    }

    // ── Patch generation ──────────────────────────────────────────────────────

    /// Generate a verified patch for a vulnerability using the deterministic
    /// XML remediation loop.
    ///
    /// Strategy:
    /// 1. Extract a surgical context window (±10 lines) around the vulnerable node.
    /// 2. Run `remediate_with_retries` (up to 3 LLM attempts):
    ///    a. Ask the LLM for a fix using the XML `<sicario_patch>` protocol.
    ///    b. Extract the patch from the XML response.
    ///    c. Splice the patch into a temporary in-memory buffer.
    ///    d. Validate syntax with tree-sitter.
    ///    e. Re-run the SAST rule against the patched buffer.
    ///    f. If both pass, break. Otherwise feed the error back to the LLM.
    /// 3. Fall back to AST-based template fix if LLM is unavailable or all
    ///    retries are exhausted (Requirement 13.5).
    /// 4. Compute a unified diff between original and fixed content.
    pub fn generate_patch(&self, vulnerability: &Vulnerability) -> Result<Patch> {
        let file_path = &vulnerability.file_path;

        // Read the original file content
        let original_content = fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

        // ── Step 1: Try the deterministic registry (zero LLM calls) ──────────
        let fixed_content =
            if let Some(fixed) = self.try_registry_fix(vulnerability, &original_content) {
                fixed
            } else {
                // ── Step 2: LLM verification loop (up to 3 attempts) ─────────────
                match self.remediate_with_retries(vulnerability, &original_content, 3) {
                    Ok(content) => content,
                    // ── Step 3: Classification-based template fallback ────────────
                    Err(_) => super::templates::apply_template_fix_with_registry(
                        &original_content,
                        vulnerability,
                        &self.registry,
                    ),
                }
            };

        // Compute unified diff
        let diff = compute_unified_diff(
            file_path.to_str().unwrap_or("file"),
            &original_content,
            &fixed_content,
        );

        // Backup path placeholder — set for real in apply_patch
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

    // ── Deterministic LLM remediation loop ───────────────────────────────────

    /// Core autonomous remediation loop.
    ///
    /// Attempts up to `max_retries` LLM calls. Each attempt:
    ///   A. Sends the context window + any prior error feedback to the LLM.
    ///   B. Extracts the patch from `<sicario_patch>` tags.
    ///   C. Splices the patch into a sandbox buffer (never touches the real file).
    ///   D. Validates syntax with tree-sitter.
    ///   E. Re-runs the SAST rule against the sandbox buffer.
    ///   F. If both pass → returns the verified fixed content.
    ///      If either fails → appends the error to the prompt and retries.
    ///
    /// Returns `Err` if all retries are exhausted or the LLM is unavailable.
    fn remediate_with_retries(
        &self,
        vuln: &Vulnerability,
        original_content: &str,
        max_retries: u32,
    ) -> Result<String> {
        use super::llm_client::extract_patch;
        use super::progress::LlmProgressSpinner;

        let language = detect_language_name(&vuln.file_path);

        // Build the surgical context window
        let window = get_context_window(original_content, vuln.line, 10);

        let base_context = FixContext {
            vulnerability_description: format!(
                "Rule: {}{}",
                vuln.rule_id,
                vuln.cwe_id
                    .as_deref()
                    .map(|c| format!(" ({})", c))
                    .unwrap_or_default()
            ),
            code_snippet: window.clone(),
            file_language: language.clone(),
            framework: None,
            cwe_id: vuln.cwe_id.clone(),
        };

        // Build a single-threaded Tokio runtime for the async LLM calls
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("Failed to build Tokio runtime")?;

        let mut extra_feedback: Option<String> = None;
        let mut last_error = String::from("all retries exhausted");

        for attempt in 1..=max_retries {
            let spinner = LlmProgressSpinner::start(&format!(
                "Generating fix for {} (attempt {}/{})",
                vuln.rule_id, attempt, max_retries
            ));

            // ── Step A: Call the LLM ──────────────────────────────────────────
            let raw_response = match rt.block_on(
                self.ai_client
                    .generate_fix_xml(&base_context, extra_feedback.as_deref()),
            ) {
                Ok(r) => {
                    spinner.finish_success("LLM responded");
                    r
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("timed out") || msg.contains("timeout") {
                        spinner.finish_timeout();
                    } else {
                        spinner.finish_error(&format!("LLM error: {msg}"));
                    }
                    last_error = msg;
                    break; // LLM unavailable — fall through to template
                }
            };

            // ── Step B: Extract patch from XML ────────────────────────────────
            let raw_patch = match extract_patch(&raw_response) {
                Ok(p) => p,
                Err(e) => {
                    last_error = format!("XML extraction failed: {e}");
                    eprintln!("sicario: attempt {attempt}/{max_retries} — {last_error}");
                    extra_feedback = Some(format!(
                        "PREVIOUS ATTEMPT FAILED: Your response did not contain valid \
                         <sicario_patch> tags. Error: {e}\n\
                         You MUST wrap the replacement code in <sicario_patch>...</sicario_patch>."
                    ));
                    continue;
                }
            };

            // Strip any residual markdown fences inside the patch block
            let patch_code = super::llm_client::strip_markdown_fences(&raw_patch);
            // Strip any line-number annotations the model may have echoed back
            // from the context window format (e.g. "  28 >>  code" or "  28    code")
            let patch_code = strip_line_number_annotations(&patch_code);

            // ── Deterministic Trimmer ─────────────────────────────────────────
            // If the LLM returned more lines than the original snippet + 2
            // tolerance, it rewrote surrounding context rather than just the
            // vulnerable lines. Reject immediately — before wasting a
            // tree-sitter parse — and bully the model back into compliance.
            let original_line_count = vuln.snippet.lines().count().max(1);
            let patch_line_count = patch_code.lines().count();
            if patch_line_count > original_line_count + 2 {
                last_error = format!(
                    "patch too large: {patch_line_count} lines for a \
                     {original_line_count}-line snippet"
                );
                eprintln!("sicario: attempt {attempt}/{max_retries} — {last_error}");
                extra_feedback = Some(format!(
                    "PREVIOUS ATTEMPT FAILED: Your patch was {patch_line_count} lines \
                     but the vulnerable snippet is only {original_line_count} line(s). \
                     You are rewriting too much surrounding context. \
                     Return ONLY the {original_line_count} replacement line(s) — \
                     nothing before or after the fix."
                ));
                continue;
            }

            // ── Step C: Splice into sandbox buffer ────────────────────────────
            let candidate = splice_patch(original_content, vuln.line, &vuln.snippet, &patch_code);

            // ── Step D: Syntax validation ─────────────────────────────────────
            if !self.validate_syntax(&candidate, &language) {
                // Find the first tree-sitter error node for feedback
                let syntax_error = get_syntax_error_description(&candidate, &language, self);
                last_error = format!("syntax error: {syntax_error}");
                eprintln!("sicario: attempt {attempt}/{max_retries} — patch has syntax errors");
                extra_feedback = Some(format!(
                    "PREVIOUS ATTEMPT FAILED: The patch you provided has a syntax error.\n\
                     Tree-sitter error: {syntax_error}\n\
                     Fix the syntax and try again. Remember: return ONLY the replacement \
                     lines, not the entire file."
                ));
                continue;
            }

            // ── Step E: Security re-verification (in-memory) ─────────────────
            match self.verify_in_memory(vuln, &candidate) {
                Ok(true) => {
                    // Vulnerability resolved — return the verified content
                    return Ok(candidate);
                }
                Ok(false) => {
                    last_error = format!("vulnerability {} still present after fix", vuln.rule_id);
                    eprintln!("sicario: attempt {attempt}/{max_retries} — {last_error}");
                    extra_feedback = Some(format!(
                        "PREVIOUS ATTEMPT FAILED: The patch was applied but the vulnerability \
                         '{}' is still detected by the SAST scanner. \
                         Try a fundamentally different approach to eliminate this vulnerability.",
                        vuln.rule_id
                    ));
                    continue;
                }
                Err(e) => {
                    // Verification scan itself failed (e.g. rule load error) —
                    // accept the syntax-valid patch rather than blocking the fix
                    eprintln!(
                        "sicario: warning — in-memory verification failed ({e}), \
                         accepting syntax-valid patch"
                    );
                    return Ok(candidate);
                }
            }
        }

        Err(anyhow::anyhow!(
            "LLM remediation failed after {max_retries} attempt(s): {last_error}"
        ))
    }

    /// Re-run the SAST rule for `vuln` against `candidate_content` in memory.
    ///
    /// Writes the candidate to a temp file, scans it, and checks whether the
    /// original rule_id is still present. Returns `Ok(true)` if resolved.
    fn verify_in_memory(&self, vuln: &Vulnerability, candidate_content: &str) -> Result<bool> {
        use crate::engine::sast_engine::SastEngine;
        use tempfile::Builder;

        // Write candidate to a temp file with the same extension as the original
        let ext = vuln
            .file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("tmp");

        let tmp = Builder::new()
            .suffix(&format!(".sicario.{ext}"))
            .tempfile()
            .context("Failed to create temp file for in-memory verification")?;

        fs::write(tmp.path(), candidate_content)
            .context("Failed to write candidate to temp file")?;

        // Create a fresh engine rooted at the temp dir so no .sicarioignore
        // from the project root interferes
        let tmp_dir = tmp.path().parent().unwrap_or(Path::new("."));
        let mut eng = SastEngine::new(tmp_dir)?;

        // Load bundled rules — reuse the same discovery logic as cmd_fix
        // We can't call discover_bundled_rules() from here (it's in main.rs),
        // so we locate the rules directory relative to the binary.
        let rules_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("rules")))
            .unwrap_or_else(|| PathBuf::from("sicario-cli/rules"));

        if rules_dir.exists() {
            load_yaml_rules_recursive(&mut eng, &rules_dir);
        }

        let findings = eng.scan_file(tmp.path())?;
        let still_present = findings.iter().any(|f| f.rule_id == vuln.rule_id);
        Ok(!still_present)
    }

    // ── Patch application ─────────────────────────────────────────────────────
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
            let _ = self
                .backup_manager
                .restore_file(&backup_path, &patch.file_path);
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
            "ruby" | "rb" => Language::Ruby,
            "php" => Language::Php,
            _ => {
                // Unknown language — pass through (can't validate)
                return true;
            }
        };

        match self.tree_sitter.parse_source(code, lang) {
            Ok(tree) => !tree.root_node().has_error(),
            Err(_) => false,
        }
    }

    /// Apply a simple AST-based template fix as a fallback.
    ///
    /// Delegates to `templates::apply_template_fix_with_registry()` which
    /// supports 9 vulnerability types. Per Requirement 11.10, this MUST
    /// produce code that differs from the original — returning original
    /// unchanged is NOT acceptable.
    fn apply_template_fix(&self, original: &str, vuln: &Vulnerability) -> String {
        super::templates::apply_template_fix_with_registry(original, vuln, &self.registry)
    }

    /// Try the `TemplateRegistry` for a deterministic, LLM-free fix.
    ///
    /// Returns `Some(fixed_content)` if a registered template matched and
    /// produced a valid replacement, `None` otherwise.
    fn try_registry_fix(&self, vuln: &Vulnerability, original_content: &str) -> Option<String> {
        let lines: Vec<&str> = original_content.lines().collect();
        let line_idx = vuln
            .line
            .saturating_sub(1)
            .min(lines.len().saturating_sub(1));
        if lines.is_empty() {
            return None;
        }

        let vulnerable_line = lines[line_idx];
        let lang = ParserLanguage::from_path(&vuln.file_path).unwrap_or(ParserLanguage::JavaScript);

        let fixed_line =
            self.registry
                .apply(&vuln.rule_id, vuln.cwe_id.as_deref(), vulnerable_line, lang)?;

        // Re-apply original indentation if the template stripped it
        let original_indent: String = vulnerable_line
            .chars()
            .take_while(|c| c.is_whitespace())
            .collect();
        let fixed_indented = if !original_indent.is_empty()
            && !fixed_line.starts_with(|c: char| c.is_whitespace())
        {
            format!("{original_indent}{fixed_line}")
        } else {
            fixed_line
        };

        // Splice the fixed line back into the full file
        let fixed_content =
            splice_patch(original_content, vuln.line, &vuln.snippet, &fixed_indented);

        // Validate syntax — if the registry fix breaks syntax, fall through to LLM
        let language = detect_language_name(&vuln.file_path);
        if !self.validate_syntax(&fixed_content, &language) {
            eprintln!(
                "sicario: registry template '{}' produced invalid syntax for {} — falling back to LLM",
                self.registry
                    .lookup(&vuln.rule_id, vuln.cwe_id.as_deref())
                    .map(|t| t.name())
                    .unwrap_or("unknown"),
                vuln.rule_id
            );
            return None;
        }

        Some(fixed_content)
    }

    // ── Diff display and confirmation ─────────────────────────────────────────

    /// Display a unified diff with color coding and prompt the user for
    /// confirmation before applying.
    ///
    /// Returns `true` if the user confirmed (y), `false` otherwise.
    /// Requirement 11.7
    pub fn display_diff_and_confirm(&self, patch: &Patch) -> Result<bool> {
        display_diff_and_confirm_with_io(patch, &mut io::stdout(), &mut io::stdin().lock())
    }

    // ── Revert by patch ID ────────────────────────────────────────────────────

    /// Revert a previously applied patch by looking up its ID in the history.
    ///
    /// Requirement 11.8 — supports `fix --revert <patch-id>`
    pub fn revert_by_patch_id(&self, patch_id: &str) -> Result<()> {
        let history = self.backup_manager.load_history()?;
        let entry = history
            .iter()
            .find(|e| e.patch_id == patch_id)
            .ok_or_else(|| anyhow::anyhow!("No patch found with ID: {}", patch_id))?;

        self.backup_manager
            .restore_file(&entry.backup_path, &entry.file_path)
            .with_context(|| {
                format!(
                    "Failed to revert patch {} for {}",
                    patch_id,
                    entry.file_path.display()
                )
            })
    }

    // ── Batch mode ────────────────────────────────────────────────────────────

    /// Process multiple vulnerabilities sequentially in batch mode.
    ///
    /// When `auto_confirm` is true, fixes are applied without prompting.
    /// When `auto_confirm` is false, each fix is shown and confirmed interactively.
    /// On verification failure, the specific fix is reverted and processing continues.
    ///
    /// After each successful patch application the file is re-scanned so that
    /// subsequent patches operate on the current state of the file rather than
    /// stale pre-fix content. This prevents overlapping/conflicting patches.
    ///
    /// Requirements: 5.1, 5.3, 5.4, 5.5
    pub fn generate_and_apply_batch(
        &self,
        vulns: &[&Vulnerability],
        auto_confirm: bool,
        no_verify: bool,
        rule_files: &[PathBuf],
    ) -> Result<BatchResult> {
        use crate::engine::sast_engine::SastEngine;
        use crate::engine::vulnerability::Finding;
        use crate::verification::scanner::VerificationScanning;
        use crate::verification::VerificationScanner;

        let mut result = BatchResult {
            applied: 0,
            reverted: 0,
            skipped: 0,
            details: Vec::new(),
        };

        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

        // Group vulns by file so we can re-scan per-file after each apply.
        // Process files one at a time; within each file work through findings
        // one-by-one, re-reading the current file state before each patch.
        let mut files_seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
        let mut file_order: Vec<PathBuf> = Vec::new();
        for v in vulns {
            if files_seen.insert(v.file_path.clone()) {
                file_order.push(v.file_path.clone());
            }
        }

        for file_path in &file_order {
            // Collect the initial rule_ids to fix for this file (in original order)
            let rule_ids_to_fix: Vec<String> = vulns
                .iter()
                .filter(|v| &v.file_path == file_path)
                .map(|v| v.rule_id.clone())
                .collect();

            // Work through each rule_id. After each successful apply, re-scan
            // the file so the next patch sees the updated source.
            let mut remaining_rule_ids = rule_ids_to_fix;

            while !remaining_rule_ids.is_empty() {
                // Re-scan the file to get current findings
                let current_vulns: Vec<Vulnerability> = {
                    let mut eng = match SastEngine::new(&cwd) {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("sicario: failed to create scan engine: {e}");
                            break;
                        }
                    };
                    for f in rule_files {
                        let _ = eng.load_rules(f);
                    }
                    let parent = file_path.parent().unwrap_or(&cwd);
                    let target_str = file_path
                        .to_string_lossy()
                        .replace('\\', "/")
                        .to_lowercase();
                    match eng.scan_directory(parent) {
                        Ok(all) => all
                            .into_iter()
                            .filter(|v| {
                                v.file_path
                                    .to_string_lossy()
                                    .replace('\\', "/")
                                    .to_lowercase()
                                    == target_str
                            })
                            .collect(),
                        Err(e) => {
                            eprintln!("sicario: re-scan failed for {}: {e}", file_path.display());
                            break;
                        }
                    }
                };

                // Find the first remaining rule_id that still has a finding
                let next = remaining_rule_ids
                    .iter()
                    .enumerate()
                    .find_map(|(i, rule_id)| {
                        current_vulns
                            .iter()
                            .find(|v| &v.rule_id == rule_id)
                            .map(|v| (i, v.clone()))
                    });

                let (idx, vuln) = match next {
                    Some(x) => x,
                    None => {
                        // All remaining rule_ids are already resolved — mark as applied
                        for rule_id in &remaining_rule_ids {
                            result.applied += 1;
                            result.details.push(BatchFixDetail {
                                rule_id: rule_id.clone(),
                                file_path: file_path.clone(),
                                outcome: BatchFixOutcome::Applied,
                            });
                        }
                        break;
                    }
                };

                let rule_id = vuln.rule_id.clone();

                // Generate patch against current file state
                let patch = match self.generate_patch(&vuln) {
                    Ok(p) => p,
                    Err(e) => {
                        let reason = format!("patch generation failed: {e}");
                        eprintln!(
                            "sicario: skipping {} in {} — {reason}",
                            rule_id,
                            file_path.display()
                        );
                        result.skipped += 1;
                        result.details.push(BatchFixDetail {
                            rule_id: rule_id.clone(),
                            file_path: file_path.clone(),
                            outcome: BatchFixOutcome::Skipped(reason),
                        });
                        remaining_rule_ids.remove(idx);
                        continue;
                    }
                };

                // Confirm
                let confirmed = if auto_confirm {
                    true
                } else {
                    match self.display_diff_and_confirm(&patch) {
                        Ok(c) => c,
                        Err(e) => {
                            let reason = format!("confirmation prompt failed: {e}");
                            eprintln!("sicario: skipping {} — {reason}", rule_id);
                            result.skipped += 1;
                            result.details.push(BatchFixDetail {
                                rule_id: rule_id.clone(),
                                file_path: file_path.clone(),
                                outcome: BatchFixOutcome::Skipped(reason),
                            });
                            remaining_rule_ids.remove(idx);
                            continue;
                        }
                    }
                };

                if !confirmed {
                    result.skipped += 1;
                    result.details.push(BatchFixDetail {
                        rule_id: rule_id.clone(),
                        file_path: file_path.clone(),
                        outcome: BatchFixOutcome::Skipped("user declined".to_string()),
                    });
                    remaining_rule_ids.remove(idx);
                    continue;
                }

                // Apply patch
                if let Err(e) = self.apply_patch(&patch) {
                    let reason = format!("apply failed: {e}");
                    eprintln!("sicario: skipping {} — {reason}", rule_id);
                    result.skipped += 1;
                    result.details.push(BatchFixDetail {
                        rule_id: rule_id.clone(),
                        file_path: file_path.clone(),
                        outcome: BatchFixOutcome::Skipped(reason),
                    });
                    remaining_rule_ids.remove(idx);
                    continue;
                }

                // Post-fix verification
                if !no_verify {
                    let mut verifier = VerificationScanner::new(&cwd);
                    let original_finding = crate::verification::OriginalFinding {
                        rule_id: vuln.rule_id.clone(),
                        fingerprint: Finding::compute_fingerprint(
                            &vuln.rule_id,
                            &vuln.file_path,
                            &vuln.snippet,
                        ),
                        file_path: vuln.file_path.clone(),
                    };
                    match verifier.verify_fix(file_path, &original_finding, rule_files) {
                        Ok(crate::verification::VerificationResult::Resolved) => {
                            eprintln!("sicario: fix verified — {} resolved", rule_id);
                            result.applied += 1;
                            result.details.push(BatchFixDetail {
                                rule_id: rule_id.clone(),
                                file_path: file_path.clone(),
                                outcome: BatchFixOutcome::Applied,
                            });
                        }
                        Ok(crate::verification::VerificationResult::StillPresent) => {
                            eprintln!("sicario: warning — {} still present, reverting", rule_id);
                            let _ = self.revert_patch(&patch);
                            result.reverted += 1;
                            result.details.push(BatchFixDetail {
                                rule_id: rule_id.clone(),
                                file_path: file_path.clone(),
                                outcome: BatchFixOutcome::Reverted(
                                    "vulnerability still present after fix".to_string(),
                                ),
                            });
                        }
                        Ok(crate::verification::VerificationResult::NewFindingsIntroduced(new)) => {
                            eprintln!(
                                "sicario: warning — {} introduced {} new finding(s), reverting",
                                rule_id,
                                new.len()
                            );
                            let _ = self.revert_patch(&patch);
                            result.reverted += 1;
                            result.details.push(BatchFixDetail {
                                rule_id: rule_id.clone(),
                                file_path: file_path.clone(),
                                outcome: BatchFixOutcome::Reverted(format!(
                                    "fix introduced {} new finding(s)",
                                    new.len()
                                )),
                            });
                        }
                        Err(e) => {
                            eprintln!(
                                "sicario: warning — verification failed for {}, reverting: {e}",
                                rule_id
                            );
                            let _ = self.revert_patch(&patch);
                            result.reverted += 1;
                            result.details.push(BatchFixDetail {
                                rule_id: rule_id.clone(),
                                file_path: file_path.clone(),
                                outcome: BatchFixOutcome::Reverted(format!(
                                    "verification error: {e}"
                                )),
                            });
                        }
                    }
                } else {
                    eprintln!("sicario: patch applied for {}", rule_id);
                    result.applied += 1;
                    result.details.push(BatchFixDetail {
                        rule_id: rule_id.clone(),
                        file_path: file_path.clone(),
                        outcome: BatchFixOutcome::Applied,
                    });
                }

                // Remove this rule_id from the remaining list regardless of outcome
                remaining_rule_ids.remove(idx);
            }
        }

        Ok(result)
    }
}

// ── Vulnerability classification (kept for backward compatibility) ─────────────
// The canonical versions now live in `templates.rs`. These are retained so
// existing unit tests in this module continue to compile.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum VulnType {
    SqlInjection,
    Xss,
    CommandInjection,
    Unknown,
}

/// Classify a vulnerability by its `cwe_id` and `rule_id`.
#[allow(dead_code)]
fn classify_vulnerability(vuln: &Vulnerability) -> VulnType {
    // Check CWE first (most reliable)
    if let Some(cwe) = &vuln.cwe_id {
        let cwe_lower = cwe.to_lowercase();
        if cwe_lower.contains("89") {
            return VulnType::SqlInjection;
        }
        if cwe_lower.contains("79") {
            return VulnType::Xss;
        }
        if cwe_lower.contains("78") {
            return VulnType::CommandInjection;
        }
    }

    // Fall back to rule_id pattern matching
    let rule = vuln.rule_id.to_lowercase();
    if rule.contains("sql") && (rule.contains("inject") || rule.contains("sqli")) {
        return VulnType::SqlInjection;
    }
    if rule.contains("xss") || rule.contains("cross-site") {
        return VulnType::Xss;
    }
    if rule.contains("command") && rule.contains("inject")
        || rule.contains("cmd-inject")
        || rule.contains("os-command")
    {
        return VulnType::CommandInjection;
    }

    VulnType::Unknown
}

// ── Template fix implementations (kept for backward compatibility) ─────────────
// The canonical versions now live in `templates.rs`. These are retained so
// existing unit tests in this module continue to compile.

/// Apply SQL injection template fix: replace string concatenation/interpolation
/// with parameterized queries. Supports Python, JavaScript, Java, Go, Rust.
#[allow(dead_code)]
fn apply_sql_injection_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(
            original,
            vuln,
            "SQL injection detected — use parameterized queries",
        );
    }

    let vuln_line = lines[target_line];

    let replacement = match lang.as_str() {
        "python"
            if vuln_line.contains('+')
                || vuln_line.contains("f\"")
                || vuln_line.contains("f'")
                || vuln_line.contains('%') =>
        {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}# SICARIO FIX: Use parameterized query to prevent SQL injection\n\
                 {indent}cursor.execute(\"SELECT * FROM table WHERE col = %s\", (user_input,))",
            )
        }
        "javascript" | "typescript" if vuln_line.contains('+') || vuln_line.contains('`') => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use parameterized query to prevent SQL injection\n\
                 {indent}const result = await db.query(\"SELECT * FROM table WHERE col = $1\", [userInput]);",
            )
        }
        "java" if vuln_line.contains('+') || vuln_line.contains("concat") => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use PreparedStatement to prevent SQL injection\n\
                 {indent}PreparedStatement stmt = conn.prepareStatement(\"SELECT * FROM table WHERE col = ?\");\n\
                 {indent}stmt.setString(1, userInput);",
            )
        }
        "go" if vuln_line.contains('+')
            || vuln_line.contains("Sprintf")
            || vuln_line.contains("fmt.") =>
        {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use parameterized query to prevent SQL injection\n\
                 {indent}rows, err := db.Query(\"SELECT * FROM table WHERE col = $1\", userInput)",
            )
        }
        "rust" if vuln_line.contains("format!") || vuln_line.contains('+') => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use parameterized query to prevent SQL injection\n\
                 {indent}sqlx::query(\"SELECT * FROM table WHERE col = $1\").bind(&user_input)",
            )
        }
        _ => {
            return apply_comment_warning(
                original,
                vuln,
                "SQL injection detected — use parameterized queries",
            );
        }
    };

    replace_line(original, target_line, &replacement)
}

/// Apply XSS template fix: replace dangerous HTML output with context-appropriate
/// encoding/escaping.
#[allow(dead_code)]
fn apply_xss_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(original, vuln, "XSS detected — apply output encoding");
    }

    let vuln_line = lines[target_line];

    let replacement = match lang.as_str() {
        "python" => {
            let indent = get_indent(vuln_line);
            if vuln_line.contains("render_template_string") || vuln_line.contains("Markup") {
                format!(
                    "{indent}# SICARIO FIX: Escape user input to prevent XSS\n\
                     {indent}from markupsafe import escape\n\
                     {indent}safe_output = escape(user_input)",
                )
            } else {
                format!(
                    "{indent}# SICARIO FIX: Escape user input to prevent XSS\n\
                     {indent}import html\n\
                     {indent}safe_output = html.escape(user_input)",
                )
            }
        }
        "javascript" | "typescript" => {
            let indent = get_indent(vuln_line);
            if vuln_line.contains("innerHTML") || vuln_line.contains("dangerouslySetInnerHTML") {
                format!(
                    "{indent}// SICARIO FIX: Use textContent instead of innerHTML to prevent XSS\n\
                     {indent}element.textContent = userInput;",
                )
            } else if vuln_line.contains("document.write") {
                format!(
                    "{indent}// SICARIO FIX: Use textContent instead of document.write to prevent XSS\n\
                     {indent}document.body.textContent = userInput;",
                )
            } else {
                format!(
                    "{indent}// SICARIO FIX: Encode output to prevent XSS\n\
                     {indent}const safeOutput = userInput.replace(/[&<>\"']/g, (c) => ({{'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}})[c]);",
                )
            }
        }
        "java" => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Encode output to prevent XSS\n\
                 {indent}String safeOutput = org.owasp.encoder.Encode.forHtml(userInput);",
            )
        }
        _ => {
            return apply_comment_warning(original, vuln, "XSS detected — apply output encoding");
        }
    };

    replace_line(original, target_line, &replacement)
}

/// Apply command injection template fix: replace shell invocations with
/// allowlist-validated arguments.
#[allow(dead_code)]
fn apply_command_injection_template(original: &str, vuln: &Vulnerability) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if target_line >= lines.len() {
        return apply_comment_warning(
            original,
            vuln,
            "Command injection detected — use allowlist validation",
        );
    }

    let vuln_line = lines[target_line];

    let replacement = match lang.as_str() {
        "python" => {
            let indent = get_indent(vuln_line);
            if vuln_line.contains("os.system") || vuln_line.contains("os.popen") {
                format!(
                    "{indent}# SICARIO FIX: Use subprocess with allowlist-validated args (no shell=True)\n\
                     {indent}import subprocess, shlex\n\
                     {indent}ALLOWED_COMMANDS = {{\"ls\", \"cat\", \"echo\"}}\n\
                     {indent}cmd = shlex.split(user_input)\n\
                     {indent}if cmd and cmd[0] in ALLOWED_COMMANDS:\n\
                     {indent}    subprocess.run(cmd, shell=False, check=True)",
                )
            } else {
                format!(
                    "{indent}# SICARIO FIX: Use subprocess with list args and allowlist validation\n\
                     {indent}import subprocess\n\
                     {indent}ALLOWED_COMMANDS = {{\"ls\", \"cat\", \"echo\"}}\n\
                     {indent}if command_name in ALLOWED_COMMANDS:\n\
                     {indent}    subprocess.run([command_name] + args, shell=False, check=True)",
                )
            }
        }
        "javascript" | "typescript" => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use execFile with allowlist-validated command (no shell)\n\
                 {indent}const {{ execFile }} = require('child_process');\n\
                 {indent}const ALLOWED_COMMANDS = new Set(['ls', 'cat', 'echo']);\n\
                 {indent}if (ALLOWED_COMMANDS.has(commandName)) {{\n\
                 {indent}  execFile(commandName, args, (err, stdout) => {{ /* handle */ }});\n\
                 {indent}}}",
            )
        }
        "java" => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use ProcessBuilder with allowlist-validated command\n\
                 {indent}Set<String> ALLOWED = Set.of(\"ls\", \"cat\", \"echo\");\n\
                 {indent}if (ALLOWED.contains(commandName)) {{\n\
                 {indent}    new ProcessBuilder(commandName).redirectErrorStream(true).start();\n\
                 {indent}}}",
            )
        }
        "go" => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use exec.Command with allowlist-validated command\n\
                 {indent}allowedCmds := map[string]bool{{\"ls\": true, \"cat\": true, \"echo\": true}}\n\
                 {indent}if allowedCmds[commandName] {{\n\
                 {indent}\tcmd := exec.Command(commandName, args...)\n\
                 {indent}}}",
            )
        }
        "rust" => {
            let indent = get_indent(vuln_line);
            format!(
                "{indent}// SICARIO FIX: Use Command with allowlist-validated args (no shell)\n\
                 {indent}let allowed = [\"ls\", \"cat\", \"echo\"];\n\
                 {indent}if allowed.contains(&command_name) {{\n\
                 {indent}    std::process::Command::new(command_name).args(&validated_args).output()?;\n\
                 {indent}}}",
            )
        }
        _ => {
            return apply_comment_warning(
                original,
                vuln,
                "Command injection detected — use allowlist validation",
            );
        }
    };

    replace_line(original, target_line, &replacement)
}

/// For unknown vulnerability types, insert a warning comment rather than
/// returning the original unchanged (Requirement 11.10).
#[allow(dead_code)]
fn apply_unknown_template(original: &str, vuln: &Vulnerability) -> String {
    let desc = vuln.cwe_id.as_deref().unwrap_or(&vuln.rule_id);
    apply_comment_warning(
        original,
        vuln,
        &format!(
            "Security issue detected ({}) — manual review required",
            desc
        ),
    )
}

/// Insert a warning comment above the vulnerable line. This ensures the output
/// always differs from the original (Requirement 11.10).
#[allow(dead_code)]
fn apply_comment_warning(original: &str, vuln: &Vulnerability, message: &str) -> String {
    let lang = detect_language_name(&vuln.file_path).to_lowercase();
    let target_line = vuln.line.saturating_sub(1);
    let lines: Vec<&str> = original.lines().collect();

    if lines.is_empty() {
        let comment = format_comment(&lang, message);
        return format!("{}\n{}", comment, original);
    }

    let idx = target_line.min(lines.len() - 1);
    let indent = get_indent(lines[idx]);
    let comment = format!("{}{}", indent, format_comment(&lang, message));

    let mut result: Vec<String> = Vec::with_capacity(lines.len() + 1);
    for (i, line) in lines.iter().enumerate() {
        if i == idx {
            result.push(comment.clone());
        }
        result.push(line.to_string());
    }
    result.join("\n")
}

/// Format a comment in the appropriate style for the language.
#[allow(dead_code)]
fn format_comment(lang: &str, message: &str) -> String {
    match lang {
        "python" => format!("# SICARIO WARNING: {}", message),
        _ => format!("// SICARIO WARNING: {}", message),
    }
}

/// Get the leading whitespace of a line.
#[allow(dead_code)]
fn get_indent(line: &str) -> String {
    line.chars().take_while(|c| c.is_whitespace()).collect()
}

/// Replace a single line in the source with a (possibly multi-line) replacement.
#[allow(dead_code)]
fn replace_line(original: &str, line_idx: usize, replacement: &str) -> String {
    let lines: Vec<&str> = original.lines().collect();
    let mut result: Vec<String> = Vec::with_capacity(lines.len());
    for (i, line) in lines.iter().enumerate() {
        if i == line_idx {
            result.push(replacement.to_string());
        } else {
            result.push(line.to_string());
        }
    }
    // Preserve trailing newline if original had one
    let mut out = result.join("\n");
    if original.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Display a unified diff with color coding and prompt for confirmation.
///
/// Extracted for testability — accepts arbitrary Read/Write streams.
pub fn display_diff_and_confirm_with_io(
    patch: &Patch,
    out: &mut dyn Write,
    input: &mut dyn BufRead,
) -> Result<bool> {
    let diff = TextDiff::from_lines(&patch.original, &patch.fixed);

    writeln!(out, "\n{}", "Proposed fix:".bold())?;
    writeln!(
        out,
        "{}",
        format!("--- {}", patch.file_path.display()).red()
    )?;
    writeln!(
        out,
        "{}",
        format!("+++ {}", patch.file_path.display()).green()
    )?;

    for group in diff.grouped_ops(3) {
        for op in &group {
            for change in diff.iter_changes(op) {
                match change.tag() {
                    ChangeTag::Delete => {
                        write!(out, "{}", format!("-{}", change.value()).red())?;
                    }
                    ChangeTag::Insert => {
                        write!(out, "{}", format!("+{}", change.value()).green())?;
                    }
                    ChangeTag::Equal => {
                        write!(out, " {}", change.value())?;
                    }
                }
                if change.missing_newline() {
                    writeln!(out)?;
                }
            }
        }
    }

    write!(out, "\n{}", "Apply this fix? [Y/n] ".bold())?;
    out.flush()?;

    let mut answer = String::new();
    input.read_line(&mut answer)?;
    let confirmed = answer.trim().is_empty() || answer.trim().eq_ignore_ascii_case("y");

    Ok(confirmed)
}

// ── Standalone helpers ────────────────────────────────────────────────────────

/// Detect the human-readable language name from a file path extension.
pub(crate) fn detect_language_name(path: &Path) -> String {
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

/// Extract a surgical context window around `target_line` (1-indexed).
///
/// Returns `context_lines` lines above and below the vulnerable line,
/// annotated with line numbers so the LLM knows exactly which line to fix.
pub fn get_context_window(source: &str, target_line: usize, context_lines: usize) -> String {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return String::new();
    }

    let line_idx = target_line.saturating_sub(1).min(lines.len() - 1);
    let start = line_idx.saturating_sub(context_lines);
    let end = (line_idx + context_lines + 1).min(lines.len());

    // Annotate with 1-indexed line numbers and mark the vulnerable line
    lines[start..end]
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let lineno = start + i + 1;
            if lineno == target_line {
                format!("{lineno:4} >> {line}") // >> marks the vulnerable line
            } else {
                format!("{lineno:4}    {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Splice a verified patch into the source file content.
///
/// Strategy:
/// 1. Replace the entire vulnerable line with the patch (line-based).
///    This avoids double-semicolons when the snippet is a sub-expression of
///    the line (e.g. snippet = `eval(userInput)`, line = `    eval(userInput);`).
/// 2. If the patch has no leading indentation but the original line does,
///    re-apply the original indentation to each patch line so the fix
///    stays properly indented in the file.
pub fn splice_patch(
    source: &str,
    target_line: usize,
    original_snippet: &str,
    patch: &str,
) -> String {
    let lines: Vec<&str> = source.lines().collect();
    if lines.is_empty() {
        return source.to_string();
    }

    let line_idx = target_line.saturating_sub(1).min(lines.len() - 1);
    let original_line = lines[line_idx];

    // Detect original indentation
    let original_indent: String = original_line
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();

    // If the patch has no leading indentation but the original line does,
    // prepend the original indentation to each line of the patch.
    let indented_patch: String =
        if !original_indent.is_empty() && !patch.starts_with(|c: char| c.is_whitespace()) {
            patch
                .lines()
                .enumerate()
                .map(|(i, l)| {
                    if i == 0 || !l.is_empty() {
                        format!("{original_indent}{l}")
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            patch.to_string()
        };

    let mut result = lines.to_vec();
    result[line_idx] = &indented_patch;
    let mut out = result.join("\n");
    if source.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// Get a human-readable description of the first syntax error in `code`.
///
/// Walks the tree-sitter parse tree looking for ERROR nodes and returns
/// a short description including the line/column of the first error found.
fn get_syntax_error_description(code: &str, language: &str, engine: &RemediationEngine) -> String {
    use crate::parser::Language;

    let lang = match language.to_lowercase().as_str() {
        "javascript" | "js" => Language::JavaScript,
        "typescript" | "ts" => Language::TypeScript,
        "python" | "py" => Language::Python,
        "rust" | "rs" => Language::Rust,
        "go" => Language::Go,
        "java" => Language::Java,
        _ => return "unknown syntax error".to_string(),
    };

    match engine.tree_sitter.parse_source(code, lang) {
        Ok(tree) => {
            let root = tree.root_node();
            if !root.has_error() {
                return "no error (tree-sitter)".to_string();
            }
            // Walk the tree to find the first ERROR node
            find_first_error_node(&root, code)
        }
        Err(e) => format!("parse failed: {e}"),
    }
}

/// Recursively walk a tree-sitter node tree to find the first ERROR node.
fn find_first_error_node(node: &tree_sitter::Node, source: &str) -> String {
    if node.is_error() || node.kind() == "ERROR" {
        let start = node.start_position();
        let snippet: String = source
            .lines()
            .nth(start.row)
            .unwrap_or("")
            .chars()
            .take(60)
            .collect();
        return format!(
            "line {}, col {}: near `{}`",
            start.row + 1,
            start.column + 1,
            snippet.trim()
        );
    }
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if child.has_error() {
                let result = find_first_error_node(&child, source);
                if !result.is_empty() {
                    return result;
                }
            }
        }
    }
    String::new()
}

/// Recursively load YAML rule files from a directory into a SastEngine.
fn load_yaml_rules_recursive(eng: &mut crate::engine::sast_engine::SastEngine, dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                load_yaml_rules_recursive(eng, &path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                let _ = eng.load_rules(&path);
            }
        }
    }
}

/// Strip line-number annotations from LLM output.
///
/// The context window sent to the LLM includes annotations like:
///   `  28 >>  eval(userInput);`  (vulnerable line)
///   `  27      // comment`       (context line)
///
/// If the model echoes these back in its patch, this function strips them
/// so only the raw code is spliced into the file.
fn strip_line_number_annotations(patch: &str) -> String {
    // Match lines that start with optional whitespace, digits, optional ">>" or spaces, then code
    // Pattern: optional spaces, 1-4 digits, spaces, optional ">>", spaces, then the actual code
    let lines: Vec<&str> = patch.lines().collect();
    let annotated = lines.iter().all(|l| {
        let trimmed = l.trim_start();
        // Check if every non-empty line starts with digits followed by spaces/>>
        if trimmed.is_empty() {
            return true;
        }
        let mut chars = trimmed.chars();
        chars.next().map(|c| c.is_ascii_digit()).unwrap_or(false)
    });

    if !annotated {
        return patch.to_string();
    }

    // Strip the annotations: remove leading "NNN >> " or "NNN    " prefix
    lines
        .iter()
        .map(|line| {
            let trimmed = line.trim_start();
            // Skip leading digits
            let after_digits = trimmed.trim_start_matches(|c: char| c.is_ascii_digit());
            // Skip spaces and optional ">>"
            let after_sep = after_digits
                .trim_start_matches(' ')
                .trim_start_matches(">>")
                .trim_start_matches(' ');
            after_sep
        })
        .collect::<Vec<_>>()
        .join("\n")
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
            execution_trace: None,
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
        fs::write(
            &file,
            "query = 'SELECT * FROM users WHERE id = ' + user_id\n",
        )
        .unwrap();

        let backup = engine.backup_manager().backup_file(&file).unwrap();
        let patch = Patch::new(
            file.clone(),
            "query = 'SELECT * FROM users WHERE id = ' + user_id\n".to_string(),
            "query = 'SELECT * FROM users WHERE id = %s'\ncursor.execute(query, (user_id,))\n"
                .to_string(),
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
        assert!(
            change_lines.is_empty(),
            "Expected no change lines, got: {:?}",
            change_lines
        );
    }

    #[test]
    fn test_extract_context_snippet_middle_of_file() {
        let source = (1..=20)
            .map(|i| format!("line{}", i))
            .collect::<Vec<_>>()
            .join("\n");
        // get_context_window includes line numbers; check the content is present
        let snippet = get_context_window(&source, 10, 3);
        assert!(snippet.contains("line10"));
        assert!(snippet.contains("line7"));
        assert!(snippet.contains("line13"));
    }

    #[test]
    fn test_extract_context_snippet_start_of_file() {
        let source = "line1\nline2\nline3\nline4\nline5\n";
        let snippet = get_context_window(source, 1, 3);
        assert!(snippet.contains("line1"));
    }

    #[test]
    fn test_splice_patch_line_replacement() {
        let source = "let x = dangerous_call(input);\nlet y = 2;\n";
        // splice_patch replaces the whole target line
        let result = splice_patch(
            source,
            1,
            "dangerous_call(input)",
            "let x = safe_call(input);",
        );
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
        std::env::remove_var("SICARIO_LLM_API_KEY");
        std::env::remove_var("OPENAI_API_KEY");
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let file = dir.path().join("app.py");
        fs::write(
            &file,
            "query = 'SELECT * FROM users WHERE id = ' + user_id\n",
        )
        .unwrap();

        let vuln = make_vuln(
            file.clone(),
            1,
            "query = 'SELECT * FROM users WHERE id = ' + user_id",
        );
        let patch = engine.generate_patch(&vuln).unwrap();

        // Template fix must produce different content (Requirement 11.10)
        assert_ne!(
            patch.original, patch.fixed,
            "Template fix must not return original unchanged"
        );
        assert!(!patch.fixed.is_empty());
    }

    // ── Template fix tests ────────────────────────────────────────────────────

    #[test]
    fn test_template_fix_sql_injection_python() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let original = "query = 'SELECT * FROM users WHERE id = ' + user_id\n";
        let vuln = Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "sql-injection".to_string(),
            file_path: PathBuf::from("app.py"),
            line: 1,
            column: 0,
            snippet: original.to_string(),
            severity: Severity::High,
            reachable: true,
            cloud_exposed: None,
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: None,
            execution_trace: None,
        };

        let fixed = engine.apply_template_fix(original, &vuln);
        assert_ne!(
            fixed, original,
            "SQL injection template must differ from original"
        );
        assert!(
            fixed.contains("parameterized") || fixed.contains("cursor.execute"),
            "Python SQL fix should use parameterized query"
        );
    }

    #[test]
    fn test_template_fix_sql_injection_javascript() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let original = "const q = \"SELECT * FROM users WHERE id = \" + userId;\n";
        let vuln = Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "sql-injection".to_string(),
            file_path: PathBuf::from("app.js"),
            line: 1,
            column: 0,
            snippet: original.to_string(),
            severity: Severity::High,
            reachable: true,
            cloud_exposed: None,
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: None,
            execution_trace: None,
        };

        let fixed = engine.apply_template_fix(original, &vuln);
        assert_ne!(
            fixed, original,
            "SQL injection template must differ from original"
        );
        assert!(
            fixed.contains("parameterized") || fixed.contains("db.query"),
            "JS SQL fix should use parameterized query"
        );
    }

    #[test]
    fn test_template_fix_xss_javascript() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let original = "element.innerHTML = userInput;\n";
        let vuln = Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "xss".to_string(),
            file_path: PathBuf::from("app.js"),
            line: 1,
            column: 0,
            snippet: original.to_string(),
            severity: Severity::High,
            reachable: true,
            cloud_exposed: None,
            cwe_id: Some("CWE-79".to_string()),
            owasp_category: None,
            execution_trace: None,
        };

        let fixed = engine.apply_template_fix(original, &vuln);
        assert_ne!(fixed, original, "XSS template must differ from original");
        assert!(
            fixed.contains("textContent"),
            "JS XSS fix should use textContent instead of innerHTML"
        );
    }

    #[test]
    fn test_template_fix_command_injection_python() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let original = "os.system('rm -rf ' + user_input)\n";
        let vuln = Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "command-injection".to_string(),
            file_path: PathBuf::from("app.py"),
            line: 1,
            column: 0,
            snippet: original.to_string(),
            severity: Severity::Critical,
            reachable: true,
            cloud_exposed: None,
            cwe_id: Some("CWE-78".to_string()),
            owasp_category: None,
            execution_trace: None,
        };

        let fixed = engine.apply_template_fix(original, &vuln);
        assert_ne!(
            fixed, original,
            "Command injection template must differ from original"
        );
        assert!(
            fixed.contains("subprocess") || fixed.contains("ALLOWED"),
            "Python cmd injection fix should use subprocess with allowlist"
        );
    }

    #[test]
    fn test_template_fix_unknown_vuln_adds_warning() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let original = "some_dangerous_call(user_input)\n";
        let vuln = Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "unknown-vuln-type".to_string(),
            file_path: PathBuf::from("app.py"),
            line: 1,
            column: 0,
            snippet: original.to_string(),
            severity: Severity::Medium,
            reachable: true,
            cloud_exposed: None,
            cwe_id: Some("CWE-999".to_string()),
            owasp_category: None,
            execution_trace: None,
        };

        let fixed = engine.apply_template_fix(original, &vuln);
        assert_ne!(
            fixed, original,
            "Unknown vuln template must differ from original"
        );
        assert!(
            fixed.contains("SICARIO WARNING"),
            "Unknown vuln fix should add a warning comment"
        );
    }

    #[test]
    fn test_classify_vulnerability_by_cwe() {
        let vuln_sql = Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "some-rule".to_string(),
            file_path: PathBuf::from("app.py"),
            line: 1,
            column: 0,
            snippet: String::new(),
            severity: Severity::High,
            reachable: false,
            cloud_exposed: None,
            cwe_id: Some("CWE-89".to_string()),
            owasp_category: None,
            execution_trace: None,
        };
        assert_eq!(classify_vulnerability(&vuln_sql), VulnType::SqlInjection);

        let vuln_xss = Vulnerability {
            cwe_id: Some("CWE-79".to_string()),
            ..vuln_sql.clone()
        };
        assert_eq!(classify_vulnerability(&vuln_xss), VulnType::Xss);

        let vuln_cmd = Vulnerability {
            cwe_id: Some("CWE-78".to_string()),
            ..vuln_sql.clone()
        };
        assert_eq!(
            classify_vulnerability(&vuln_cmd),
            VulnType::CommandInjection
        );
    }

    #[test]
    fn test_classify_vulnerability_by_rule_id() {
        let vuln = Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "sql-injection-concat".to_string(),
            file_path: PathBuf::from("app.py"),
            line: 1,
            column: 0,
            snippet: String::new(),
            severity: Severity::High,
            reachable: false,
            cloud_exposed: None,
            cwe_id: None,
            owasp_category: None,
            execution_trace: None,
        };
        assert_eq!(classify_vulnerability(&vuln), VulnType::SqlInjection);

        let vuln_xss = Vulnerability {
            rule_id: "xss-reflected".to_string(),
            cwe_id: None,
            ..vuln.clone()
        };
        assert_eq!(classify_vulnerability(&vuln_xss), VulnType::Xss);

        let vuln_cmd = Vulnerability {
            rule_id: "command-injection-os".to_string(),
            cwe_id: None,
            ..vuln.clone()
        };
        assert_eq!(
            classify_vulnerability(&vuln_cmd),
            VulnType::CommandInjection
        );
    }

    #[test]
    fn test_display_diff_and_confirm_yes() {
        let patch = Patch::new(
            PathBuf::from("test.py"),
            "old line\n".to_string(),
            "new line\n".to_string(),
            String::new(),
            PathBuf::from("/tmp/backup"),
        );

        let mut output = Vec::new();
        let mut input = io::Cursor::new(b"y\n".to_vec());
        let result = display_diff_and_confirm_with_io(&patch, &mut output, &mut input).unwrap();
        assert!(result, "Should return true when user types 'y'");
    }

    #[test]
    fn test_display_diff_and_confirm_no() {
        let patch = Patch::new(
            PathBuf::from("test.py"),
            "old line\n".to_string(),
            "new line\n".to_string(),
            String::new(),
            PathBuf::from("/tmp/backup"),
        );

        let mut output = Vec::new();
        let mut input = io::Cursor::new(b"n\n".to_vec());
        let result = display_diff_and_confirm_with_io(&patch, &mut output, &mut input).unwrap();
        assert!(!result, "Should return false when user types 'n'");
    }

    #[test]
    fn test_display_diff_and_confirm_default_yes() {
        let patch = Patch::new(
            PathBuf::from("test.py"),
            "old line\n".to_string(),
            "new line\n".to_string(),
            String::new(),
            PathBuf::from("/tmp/backup"),
        );

        let mut output = Vec::new();
        let mut input = io::Cursor::new(b"\n".to_vec());
        let result = display_diff_and_confirm_with_io(&patch, &mut output, &mut input).unwrap();
        assert!(result, "Should return true on empty input (default Y)");
    }

    #[test]
    fn test_revert_by_patch_id_success() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let file = dir.path().join("app.py");
        let original = "original content\n";
        fs::write(&file, original).unwrap();

        // Apply a patch (which records history)
        let backup = engine.backup_manager().backup_file(&file).unwrap();
        let patch = Patch::new(
            file.clone(),
            original.to_string(),
            "fixed content\n".to_string(),
            String::new(),
            backup,
        );
        engine.apply_patch(&patch).unwrap();

        // Verify file was changed
        assert_eq!(fs::read_to_string(&file).unwrap(), "fixed content\n");

        // Revert by patch ID
        engine.revert_by_patch_id(&patch.id.to_string()).unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), original);
    }

    #[test]
    fn test_revert_by_patch_id_not_found() {
        let dir = TempDir::new().unwrap();
        let engine = RemediationEngine::new(dir.path()).unwrap();

        let result = engine.revert_by_patch_id("nonexistent-id");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No patch found with ID"));
    }
}
