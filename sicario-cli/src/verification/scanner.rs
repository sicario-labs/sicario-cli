//! Post-fix verification scanner — re-scans a patched file to confirm
//! the targeted vulnerability is resolved and no new findings were introduced.
//!
//! Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6

use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::engine::sast_engine::SastEngine;
use crate::engine::vulnerability::Finding;

// ── Data types ────────────────────────────────────────────────────────────────

/// Lightweight struct holding just the info needed to compare a finding
/// before and after a fix is applied.
#[derive(Debug, Clone)]
pub struct OriginalFinding {
    /// The rule that produced the original finding.
    pub rule_id: String,
    /// Stable fingerprint: SHA-256(rule_id + file_path + snippet_hash).
    pub fingerprint: String,
    /// Path of the file that contained the finding.
    pub file_path: PathBuf,
}

/// Outcome of a post-fix verification scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// The original finding is no longer present — fix worked.
    Resolved,
    /// The original finding is still present — fix did not work.
    StillPresent,
    /// New findings were introduced by the fix (fingerprints of the new ones).
    NewFindingsIntroduced(Vec<String>),
}

// ── Trait ──────────────────────────────────────────────────────────────────────

/// Trait for post-fix verification scanning.
pub trait VerificationScanning {
    /// Re-scan `file` after a fix and compare against `original_finding`.
    ///
    /// `rules_paths` is a list of YAML rule files to load into a fresh engine.
    fn verify_fix(
        &mut self,
        file: &Path,
        original_finding: &OriginalFinding,
        rules_paths: &[PathBuf],
    ) -> Result<VerificationResult>;
}

// ── Implementation ────────────────────────────────────────────────────────────

/// Concrete verification scanner backed by `SastEngine`.
pub struct VerificationScanner {
    /// Project root used to create a fresh `SastEngine`.
    project_root: PathBuf,
}

impl VerificationScanner {
    /// Create a new `VerificationScanner` rooted at `project_root`.
    pub fn new(project_root: &Path) -> Self {
        Self {
            project_root: project_root.to_path_buf(),
        }
    }
}

impl VerificationScanning for VerificationScanner {
    fn verify_fix(
        &mut self,
        file: &Path,
        original_finding: &OriginalFinding,
        rules_paths: &[PathBuf],
    ) -> Result<VerificationResult> {
        // 1. Create a fresh engine so we get a clean scan of the patched file.
        let mut engine = SastEngine::new(&self.project_root)?;

        // 2. Load all provided rule files.
        for rules_path in rules_paths {
            engine.load_rules(rules_path)?;
        }

        // 3. Scan the patched file.
        let vulnerabilities = engine.scan_file(file)?;

        // 4. Compute fingerprints for every finding in the re-scan.
        let rescan_fingerprints: Vec<String> = vulnerabilities
            .iter()
            .map(|v| Finding::compute_fingerprint(&v.rule_id, &v.file_path, &v.snippet))
            .collect();

        // 5. Check whether the original finding is still present.
        let still_present = rescan_fingerprints.contains(&original_finding.fingerprint);

        // 6. Identify new fingerprints that were NOT the original finding.
        let new_fingerprints: Vec<String> = rescan_fingerprints
            .into_iter()
            .filter(|fp| fp != &original_finding.fingerprint)
            .collect();

        // 7. Determine the result.
        //    Priority: if the original finding is still present, that is the
        //    primary concern (StillPresent). Otherwise, if new findings appeared,
        //    report them. If neither, the fix is verified.
        if still_present {
            Ok(VerificationResult::StillPresent)
        } else if !new_fingerprints.is_empty() {
            Ok(VerificationResult::NewFindingsIntroduced(new_fingerprints))
        } else {
            Ok(VerificationResult::Resolved)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::vulnerability::Finding;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: create a minimal YAML rule file that matches `eval(...)` calls
    /// in JavaScript.
    fn write_eval_rule(dir: &Path) -> PathBuf {
        let rule_path = dir.join("eval_rule.yaml");
        let yaml = r#"
- id: "js-eval"
  name: "Dangerous eval"
  description: "Use of eval with dynamic input"
  severity: High
  confidence: high
  languages:
    - JavaScript
  pattern:
    query: "(call_expression function: (identifier) @fn (#eq? @fn \"eval\")) @call"
    captures:
      - "call"
"#;
        fs::write(&rule_path, yaml).unwrap();
        rule_path
    }

    /// Helper: write a JS file with an `eval(...)` call.
    fn write_vulnerable_js(dir: &Path) -> PathBuf {
        let file = dir.join("app.js");
        fs::write(&file, "var x = eval(userInput);\n").unwrap();
        file
    }

    /// Helper: write a JS file without `eval(...)`.
    fn write_safe_js(dir: &Path) -> PathBuf {
        let file = dir.join("app.js");
        fs::write(&file, "var x = JSON.parse(userInput);\n").unwrap();
        file
    }

    /// Helper: write a JS file that replaces eval with a *different* dangerous
    /// pattern (for the "new findings introduced" scenario we use a second rule).
    fn write_new_vuln_rule(dir: &Path) -> PathBuf {
        let rule_path = dir.join("console_rule.yaml");
        let yaml = r#"
- id: "js-console-log"
  name: "Console log usage"
  description: "Console log detected"
  severity: Low
  confidence: high
  languages:
    - JavaScript
  pattern:
    query: "(call_expression function: (member_expression object: (identifier) @obj property: (property_identifier) @prop (#eq? @obj \"console\") (#eq? @prop \"log\"))) @call"
    captures:
      - "call"
"#;
        fs::write(&rule_path, yaml).unwrap();
        rule_path
    }

    #[test]
    fn test_verification_resolved() {
        let tmp = TempDir::new().unwrap();
        let rule_path = write_eval_rule(tmp.path());

        // First, compute the original fingerprint from the vulnerable file.
        let vuln_file = write_vulnerable_js(tmp.path());
        let original_fp = {
            let mut engine = SastEngine::new(tmp.path()).unwrap();
            engine.load_rules(&rule_path).unwrap();
            let vulns = engine.scan_file(&vuln_file).unwrap();
            assert!(!vulns.is_empty(), "should detect eval");
            Finding::compute_fingerprint(&vulns[0].rule_id, &vulns[0].file_path, &vulns[0].snippet)
        };

        let original = OriginalFinding {
            rule_id: "js-eval".into(),
            fingerprint: original_fp,
            file_path: vuln_file.clone(),
        };

        // Now "fix" the file by removing eval.
        write_safe_js(tmp.path());

        let mut scanner = VerificationScanner::new(tmp.path());
        let result = scanner
            .verify_fix(&vuln_file, &original, &[rule_path])
            .unwrap();

        assert_eq!(result, VerificationResult::Resolved);
    }

    #[test]
    fn test_verification_still_present() {
        let tmp = TempDir::new().unwrap();
        let rule_path = write_eval_rule(tmp.path());

        let vuln_file = write_vulnerable_js(tmp.path());
        let original_fp = {
            let mut engine = SastEngine::new(tmp.path()).unwrap();
            engine.load_rules(&rule_path).unwrap();
            let vulns = engine.scan_file(&vuln_file).unwrap();
            assert!(!vulns.is_empty());
            Finding::compute_fingerprint(&vulns[0].rule_id, &vulns[0].file_path, &vulns[0].snippet)
        };

        let original = OriginalFinding {
            rule_id: "js-eval".into(),
            fingerprint: original_fp,
            file_path: vuln_file.clone(),
        };

        // "Fix" doesn't actually remove eval — file stays the same.
        let mut scanner = VerificationScanner::new(tmp.path());
        let result = scanner
            .verify_fix(&vuln_file, &original, &[rule_path])
            .unwrap();

        assert_eq!(result, VerificationResult::StillPresent);
    }

    #[test]
    fn test_verification_new_findings_introduced() {
        let tmp = TempDir::new().unwrap();
        let eval_rule = write_eval_rule(tmp.path());
        let console_rule = write_new_vuln_rule(tmp.path());

        // Original file has eval.
        let vuln_file = write_vulnerable_js(tmp.path());
        let original_fp = {
            let mut engine = SastEngine::new(tmp.path()).unwrap();
            engine.load_rules(&eval_rule).unwrap();
            let vulns = engine.scan_file(&vuln_file).unwrap();
            assert!(!vulns.is_empty());
            Finding::compute_fingerprint(&vulns[0].rule_id, &vulns[0].file_path, &vulns[0].snippet)
        };

        let original = OriginalFinding {
            rule_id: "js-eval".into(),
            fingerprint: original_fp,
            file_path: vuln_file.clone(),
        };

        // "Fix" removes eval but introduces console.log.
        fs::write(&vuln_file, "var x = console.log(userInput);\n").unwrap();

        let mut scanner = VerificationScanner::new(tmp.path());
        let result = scanner
            .verify_fix(&vuln_file, &original, &[eval_rule, console_rule])
            .unwrap();

        match result {
            VerificationResult::NewFindingsIntroduced(fps) => {
                assert!(!fps.is_empty(), "should report new fingerprints");
            }
            other => panic!("Expected NewFindingsIntroduced, got {:?}", other),
        }
    }

    #[test]
    fn test_fingerprint_comparison_is_stable() {
        // Verify that the same inputs always produce the same fingerprint.
        let fp1 = Finding::compute_fingerprint("rule-a", Path::new("file.js"), "eval(x)");
        let fp2 = Finding::compute_fingerprint("rule-a", Path::new("file.js"), "eval(x)");
        assert_eq!(fp1, fp2);

        // Different rule → different fingerprint.
        let fp3 = Finding::compute_fingerprint("rule-b", Path::new("file.js"), "eval(x)");
        assert_ne!(fp1, fp3);

        // Different snippet → different fingerprint.
        let fp4 = Finding::compute_fingerprint("rule-a", Path::new("file.js"), "eval(y)");
        assert_ne!(fp1, fp4);
    }
}
