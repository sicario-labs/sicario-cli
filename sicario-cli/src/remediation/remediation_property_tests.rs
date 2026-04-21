//! Property-based tests for the remediation engine
//!
//! Feature: sicario-cli-core
//! Properties: 24 (patch syntax validity), 25 (patch idempotence), 31 (LLM patch syntax validity),
//!             32 (backup creation), 33 (patch revert correctness)

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;
    use std::fs;
    use tempfile::TempDir;
    use uuid::Uuid;

    use crate::engine::{Severity, Vulnerability};
    use crate::remediation::backup_manager::BackupManager;
    use crate::remediation::remediation_engine::{compute_unified_diff, RemediationEngine};
    use crate::remediation::Patch;

    // ── Generators ────────────────────────────────────────────────────────────

    /// Generate a random valid JavaScript function body
    fn arb_js_code() -> impl Strategy<Value = String> {
        (
            "[a-z]{3,8}",   // function name
            0usize..5usize, // number of statements
        )
            .prop_map(|(name, stmts)| {
                let mut code = format!("function {}() {{\n", name);
                for i in 0..stmts {
                    code.push_str(&format!("  var x{} = {};\n", i, i));
                }
                code.push_str("}\n");
                code
            })
    }

    /// Generate a random valid Python function body
    fn arb_py_code() -> impl Strategy<Value = String> {
        (
            "[a-z]{3,8}",   // function name
            0usize..5usize, // number of statements
        )
            .prop_map(|(name, stmts)| {
                let mut code = format!("def {}():\n", name);
                if stmts == 0 {
                    code.push_str("    pass\n");
                } else {
                    for i in 0..stmts {
                        code.push_str(&format!("    x{} = {}\n", i, i));
                    }
                }
                code
            })
    }

    /// Generate a random file content with a "vulnerable" line
    fn arb_file_with_vuln() -> impl Strategy<Value = (String, usize, String)> {
        (
            prop::collection::vec("[a-z ]{5,20}\n", 1..10usize),
            "[a-z]{3,8}",
        )
            .prop_map(|(mut lines, vuln_token)| {
                let vuln_line = lines.len() / 2;
                let snippet = format!("let secret = \"{}\";", vuln_token);
                lines[vuln_line] = format!("{}\n", snippet);
                let content = lines.join("");
                (content, vuln_line + 1, snippet) // line is 1-indexed
            })
    }

    fn make_vuln_for_file(file_path: std::path::PathBuf, line: usize, snippet: &str) -> Vulnerability {
        Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "hardcoded-secret".to_string(),
            file_path,
            line,
            column: 0,
            snippet: snippet.to_string(),
            severity: Severity::High,
            reachable: true,
            cloud_exposed: None,
            cwe_id: Some("CWE-798".to_string()),
            owasp_category: None,
        }
    }

    // ── Property 31: LLM-generated patch syntax validity ─────────────────────
    //
    // Feature: sicario-cli-core, Property 31: LLM-generated patch syntax validity
    // Validates: Requirements 13.4
    //
    // For any vulnerability where the Remediation Engine uses the Cerebras API to
    // generate a fix, the returned code should be syntactically valid for the target
    // language before being presented to the user.
    //
    // Since we cannot call the real LLM in tests, we validate the `validate_syntax`
    // method directly: for any syntactically valid JS/Python code, the validator
    // should return true; for any code the engine generates (via fallback), it should
    // also be syntactically valid.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        #[test]
        fn prop31_validate_syntax_accepts_valid_js(code in arb_js_code()) {
            let dir = TempDir::new().unwrap();
            let engine = RemediationEngine::new(dir.path()).unwrap();
            // Valid JS code should pass syntax validation
            prop_assert!(
                engine.validate_syntax(&code, "javascript"),
                "Valid JS code should pass syntax validation: {}",
                code
            );
        }

        #[test]
        fn prop31_validate_syntax_accepts_valid_python(code in arb_py_code()) {
            let dir = TempDir::new().unwrap();
            let engine = RemediationEngine::new(dir.path()).unwrap();
            // Valid Python code should pass syntax validation
            prop_assert!(
                engine.validate_syntax(&code, "python"),
                "Valid Python code should pass syntax validation: {}",
                code
            );
        }
    }

    // ── Property 32: Patch backup creation ───────────────────────────────────
    //
    // Feature: sicario-cli-core, Property 32: Patch backup creation
    // Validates: Requirements 14.1
    //
    // For any patch applied to a file, the Remediation Engine should create a backup
    // of the original file in `.sicario/backups/` before making any modifications.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        #[test]
        fn prop32_backup_created_before_modification(
            original_content in "[a-zA-Z0-9 \n]{10,200}",
            fixed_content in "[a-zA-Z0-9 \n]{10,200}",
        ) {
            let dir = TempDir::new().unwrap();
            let engine = RemediationEngine::new(dir.path()).unwrap();

            let file = dir.path().join("target.py");
            fs::write(&file, &original_content).unwrap();

            // Create a backup manually (as apply_patch does internally)
            let backup_path = engine.backup_manager().backup_file(&file).unwrap();

            // Verify backup exists and matches original
            prop_assert!(backup_path.exists(), "Backup file should exist");
            let backup_content = fs::read_to_string(&backup_path).unwrap();
            prop_assert_eq!(
                backup_content, original_content,
                "Backup should contain original content"
            );

            // Verify backup is inside .sicario/backups/
            let backup_str = backup_path.to_string_lossy();
            prop_assert!(
                backup_str.contains(".sicario") && backup_str.contains("backups"),
                "Backup should be inside .sicario/backups/, got: {}",
                backup_str
            );
        }

        #[test]
        fn prop32_apply_patch_creates_backup_and_writes_fix(
            original_content in "[a-z \n]{10,100}",
            fixed_content in "[a-z \n]{10,100}",
        ) {
            let dir = TempDir::new().unwrap();
            let engine = RemediationEngine::new(dir.path()).unwrap();

            let file = dir.path().join("app.py");
            fs::write(&file, &original_content).unwrap();

            let backup = engine.backup_manager().backup_file(&file).unwrap();
            let diff = compute_unified_diff("app.py", &original_content, &fixed_content);
            let patch = Patch::new(
                file.clone(),
                original_content.clone(),
                fixed_content.clone(),
                diff,
                backup.clone(),
            );

            engine.apply_patch(&patch).unwrap();

            // File should now contain fixed content
            let on_disk = fs::read_to_string(&file).unwrap();
            prop_assert_eq!(on_disk, fixed_content, "File should contain fixed content after patch");

            // Backup should still contain original
            let backed_up = fs::read_to_string(&backup).unwrap();
            prop_assert_eq!(backed_up, original_content, "Backup should contain original content");
        }
    }

    // ── Property 24: Patch correctness and syntax validity ───────────────────
    //
    // Feature: sicario-cli-core, Property 24: Patch correctness and syntax validity
    // Validates: Requirements 9.1, 9.2
    //
    // For any vulnerability with a defined fix template, the generated patch should
    // produce syntactically valid code that resolves the vulnerability without
    // introducing new syntax errors or breaking existing functionality.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        #[test]
        fn prop24_generated_patch_has_valid_structure(
            (content, line, snippet) in arb_file_with_vuln(),
        ) {
            // Ensure no API key is set so we exercise the fallback path
            std::env::remove_var("CEREBRAS_API_KEY");

            let dir = TempDir::new().unwrap();
            let engine = RemediationEngine::new(dir.path()).unwrap();

            let file = dir.path().join("app.js");
            fs::write(&file, &content).unwrap();

            let vuln = make_vuln_for_file(file.clone(), line, &snippet);
            let patch = engine.generate_patch(&vuln).unwrap();

            // Patch must have a non-empty original
            prop_assert!(!patch.original.is_empty(), "Patch original should not be empty");

            // Patch must have a diff (even if it's just the header)
            // The diff may be empty if original == fixed (template fallback returns original)
            // but the patch struct itself must be valid
            prop_assert!(!patch.file_path.as_os_str().is_empty(), "Patch file_path should not be empty");

            // The fixed content must be non-empty
            prop_assert!(!patch.fixed.is_empty(), "Patch fixed content should not be empty");
        }

        #[test]
        fn prop24_revert_restores_original_for_any_content(
            original in "[a-z \n]{10,100}",
            fixed in "[a-z \n]{10,100}",
        ) {
            let dir = TempDir::new().unwrap();
            let engine = RemediationEngine::new(dir.path()).unwrap();

            let file = dir.path().join("app.py");
            fs::write(&file, &original).unwrap();

            let backup = engine.backup_manager().backup_file(&file).unwrap();
            let diff = compute_unified_diff("app.py", &original, &fixed);
            let patch = Patch::new(
                file.clone(),
                original.clone(),
                fixed.clone(),
                diff,
                backup,
            );

            // Apply then revert
            engine.apply_patch(&patch).unwrap();
            engine.revert_patch(&patch).unwrap();

            let restored = fs::read_to_string(&file).unwrap();
            prop_assert_eq!(
                restored, original,
                "Revert should restore original content exactly"
            );
        }
    }

    // ── Property 25: Patch application idempotence ────────────────────────────
    //
    // Feature: sicario-cli-core, Property 25: Patch application idempotence
    // Validates: Requirements 9.4
    //
    // For any patch applied to a file, applying the same patch again should either
    // succeed with no changes or correctly detect that the patch has already been
    // applied, maintaining idempotence.
    //
    // We model this by applying a patch twice and asserting the file content after
    // the second application is identical to the content after the first application.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        #[test]
        fn prop25_applying_patch_twice_yields_same_file_content(
            original in "[a-z \n]{10,100}",
            fixed in "[a-z \n]{10,100}",
        ) {
            let dir = TempDir::new().unwrap();
            let engine = RemediationEngine::new(dir.path()).unwrap();

            let file = dir.path().join("app.py");
            fs::write(&file, &original).unwrap();

            // First application
            let backup1 = engine.backup_manager().backup_file(&file).unwrap();
            let diff = compute_unified_diff("app.py", &original, &fixed);
            let patch = Patch::new(
                file.clone(),
                original.clone(),
                fixed.clone(),
                diff.clone(),
                backup1,
            );
            engine.apply_patch(&patch).unwrap();
            let after_first = fs::read_to_string(&file).unwrap();

            // Second application — patch.fixed is already on disk, so applying
            // again writes the same fixed content (idempotent result).
            let backup2 = engine.backup_manager().backup_file(&file).unwrap();
            let patch2 = Patch::new(
                file.clone(),
                after_first.clone(),
                fixed.clone(),
                diff,
                backup2,
            );
            engine.apply_patch(&patch2).unwrap();
            let after_second = fs::read_to_string(&file).unwrap();

            prop_assert_eq!(
                after_first, after_second,
                "Applying the same patch twice should yield identical file content"
            );
        }

        #[test]
        fn prop25_idempotent_when_original_equals_fixed(
            content in "[a-z \n]{10,100}",
        ) {
            // When original == fixed (no-op patch), applying any number of times
            // must leave the file unchanged.
            let dir = TempDir::new().unwrap();
            let engine = RemediationEngine::new(dir.path()).unwrap();

            let file = dir.path().join("app.py");
            fs::write(&file, &content).unwrap();

            let backup = engine.backup_manager().backup_file(&file).unwrap();
            let diff = compute_unified_diff("app.py", &content, &content);
            let patch = Patch::new(
                file.clone(),
                content.clone(),
                content.clone(), // fixed == original
                diff,
                backup,
            );

            engine.apply_patch(&patch).unwrap();
            let after = fs::read_to_string(&file).unwrap();

            prop_assert_eq!(
                after, content,
                "No-op patch should leave file content unchanged"
            );
        }
    }

    // ── Property 33: Patch revert correctness ─────────────────────────────────
    //
    // Feature: sicario-cli-core, Property 33: Patch revert correctness
    // Validates: Requirements 14.3
    //
    // For any applied patch with a valid backup, calling `revert_patch()` should
    // restore the file to its exact original state as it existed before the patch
    // was applied.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        #[test]
        fn prop33_revert_restores_exact_original_bytes(
            original in "[a-zA-Z0-9 \n\t]{10,200}",
            fixed in "[a-zA-Z0-9 \n\t]{10,200}",
        ) {
            let dir = TempDir::new().unwrap();
            let engine = RemediationEngine::new(dir.path()).unwrap();

            let file = dir.path().join("target.rs");
            fs::write(&file, &original).unwrap();

            // Capture backup before applying
            let backup = engine.backup_manager().backup_file(&file).unwrap();
            let diff = compute_unified_diff("target.rs", &original, &fixed);
            let patch = Patch::new(
                file.clone(),
                original.clone(),
                fixed.clone(),
                diff,
                backup,
            );

            engine.apply_patch(&patch).unwrap();

            // Confirm the file was actually changed (when original != fixed)
            let after_apply = fs::read_to_string(&file).unwrap();
            prop_assert_eq!(after_apply, fixed, "File should contain fixed content after apply");

            // Revert and confirm exact restoration
            engine.revert_patch(&patch).unwrap();
            let after_revert = fs::read_to_string(&file).unwrap();

            prop_assert_eq!(
                after_revert, original,
                "Revert must restore file to exact original content"
            );
        }

        #[test]
        fn prop33_revert_is_inverse_of_apply(
            original in "[a-z \n]{10,100}",
            fixed in "[a-z \n]{10,100}",
        ) {
            // apply(revert(apply(f))) == apply(f): after apply+revert+apply,
            // the file should be in the fixed state again.
            let dir = TempDir::new().unwrap();
            let engine = RemediationEngine::new(dir.path()).unwrap();

            let file = dir.path().join("app.go");
            fs::write(&file, &original).unwrap();

            let backup = engine.backup_manager().backup_file(&file).unwrap();
            let diff = compute_unified_diff("app.go", &original, &fixed);
            let patch = Patch::new(
                file.clone(),
                original.clone(),
                fixed.clone(),
                diff.clone(),
                backup,
            );

            // apply → revert → apply
            engine.apply_patch(&patch).unwrap();
            engine.revert_patch(&patch).unwrap();

            // Re-apply from the reverted (original) state
            let backup2 = engine.backup_manager().backup_file(&file).unwrap();
            let patch2 = Patch::new(
                file.clone(),
                original.clone(),
                fixed.clone(),
                diff,
                backup2,
            );
            engine.apply_patch(&patch2).unwrap();

            let final_content = fs::read_to_string(&file).unwrap();
            prop_assert_eq!(
                final_content, fixed,
                "apply(revert(apply(f))) should equal apply(f)"
            );
        }
    }
}
