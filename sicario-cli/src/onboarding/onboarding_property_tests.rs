//! Property-based tests for the onboarding auto-detection module.
//!
//! Feature: sicario-cli-core
//! Property 26 — Auto-detection accuracy
//! Property 27 — Rule configuration based on detection
//!
//! Validates: Requirements 10.2, 10.3

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;
    use std::fs;
    use tempfile::TempDir;

    use crate::onboarding::detector::{DetectedTechnologies, TechDetector};
    use crate::onboarding::rule_configurator::RuleConfigurator;

    // ── Generators ────────────────────────────────────────────────────────────

    /// Generate a valid npm package name (lowercase letters and hyphens).
    fn arb_npm_pkg() -> impl Strategy<Value = String> {
        "[a-z]{3,10}".prop_map(|s| s)
    }

    /// Generate a valid semver string.
    fn arb_semver() -> impl Strategy<Value = String> {
        (0u32..10u32, 0u32..20u32, 0u32..20u32)
            .prop_map(|(maj, min, patch)| format!("{}.{}.{}", maj, min, patch))
    }

    /// Generate a valid Python package name.
    fn arb_py_pkg() -> impl Strategy<Value = String> {
        "[a-z][a-z0-9]{2,10}".prop_map(|s| s)
    }

    // ── Property 26: Auto-detection accuracy ─────────────────────────────────
    //
    // Feature: sicario-cli-core, Property 26: Auto-detection accuracy
    // Validates: Requirements 10.2
    //
    // For any project directory containing a known set of manifest files and
    // source files, TechDetector::detect() should correctly identify all
    // programming languages, package managers, and frameworks present without
    // false negatives.

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// For any package.json with a random package name, JavaScript and npm
        /// must always be detected.
        #[test]
        fn prop26_package_json_always_detects_js_and_npm(
            pkg in arb_npm_pkg(),
            ver in arb_semver(),
        ) {
            let dir = TempDir::new().unwrap();
            let content = format!(
                "{{\"dependencies\":{{\"{}\": \"^{}\"}}}}",
                pkg, ver
            );
            fs::write(dir.path().join("package.json"), &content).unwrap();

            let result = TechDetector::detect(dir.path()).unwrap();

            prop_assert!(
                result.languages.contains(&"JavaScript".to_string()),
                "JavaScript must be detected when package.json is present. Got: {:?}",
                result.languages
            );
            prop_assert!(
                result.package_managers.contains(&"npm".to_string()),
                "npm must be detected when package.json is present. Got: {:?}",
                result.package_managers
            );
        }

        /// For any requirements.txt with a random Python package, Python and pip
        /// must always be detected.
        #[test]
        fn prop26_requirements_txt_always_detects_python_and_pip(
            pkg in arb_py_pkg(),
            ver in arb_semver(),
        ) {
            let dir = TempDir::new().unwrap();
            let content = format!("{}=={}\n", pkg, ver);
            fs::write(dir.path().join("requirements.txt"), &content).unwrap();

            let result = TechDetector::detect(dir.path()).unwrap();

            prop_assert!(
                result.languages.contains(&"Python".to_string()),
                "Python must be detected when requirements.txt is present. Got: {:?}",
                result.languages
            );
            prop_assert!(
                result.package_managers.contains(&"pip".to_string()),
                "pip must be detected when requirements.txt is present. Got: {:?}",
                result.package_managers
            );
        }

        /// For any Cargo.toml with a random crate name, Rust and cargo must
        /// always be detected.
        #[test]
        fn prop26_cargo_toml_always_detects_rust_and_cargo(
            crate_name in "[a-z][a-z0-9_]{2,10}",
            ver in arb_semver(),
        ) {
            let dir = TempDir::new().unwrap();
            let content = format!(
                "[package]\nname = \"{}\"\nversion = \"{}\"\n\n[dependencies]\n",
                crate_name, ver
            );
            fs::write(dir.path().join("Cargo.toml"), &content).unwrap();

            let result = TechDetector::detect(dir.path()).unwrap();

            prop_assert!(
                result.languages.contains(&"Rust".to_string()),
                "Rust must be detected when Cargo.toml is present. Got: {:?}",
                result.languages
            );
            prop_assert!(
                result.package_managers.contains(&"cargo".to_string()),
                "cargo must be detected when Cargo.toml is present. Got: {:?}",
                result.package_managers
            );
        }

        /// For any go.mod with a random module path, Go and go modules must
        /// always be detected.
        #[test]
        fn prop26_go_mod_always_detects_go(
            module_name in "[a-z]{3,10}",
            major in 1u32..3u32,
            minor in 0u32..25u32,
        ) {
            let dir = TempDir::new().unwrap();
            let content = format!(
                "module example.com/{}\n\ngo {}.{}\n",
                module_name, major, minor
            );
            fs::write(dir.path().join("go.mod"), &content).unwrap();

            let result = TechDetector::detect(dir.path()).unwrap();

            prop_assert!(
                result.languages.contains(&"Go".to_string()),
                "Go must be detected when go.mod is present. Got: {:?}",
                result.languages
            );
            prop_assert!(
                result.package_managers.contains(&"go modules".to_string()),
                "go modules must be detected when go.mod is present. Got: {:?}",
                result.package_managers
            );
        }

        /// For any package.json containing "next" as a dependency, Next.js must
        /// be detected as a framework.
        #[test]
        fn prop26_next_dependency_always_detects_nextjs_framework(
            next_ver in arb_semver(),
            extra_pkg in arb_npm_pkg(),
            extra_ver in arb_semver(),
        ) {
            let dir = TempDir::new().unwrap();
            let content = format!(
                "{{\"dependencies\":{{\"next\":\"{}\",\"{}\":\"{}\"}}}}",
                next_ver, extra_pkg, extra_ver
            );
            fs::write(dir.path().join("package.json"), &content).unwrap();

            let result = TechDetector::detect(dir.path()).unwrap();

            prop_assert!(
                result.frameworks.contains(&"Next.js".to_string()),
                "Next.js must be detected when 'next' is in package.json dependencies. Got: {:?}",
                result.frameworks
            );
        }

        /// For any package.json containing "react" as a dependency, React must
        /// be detected as a framework.
        #[test]
        fn prop26_react_dependency_always_detects_react_framework(
            react_ver in arb_semver(),
        ) {
            let dir = TempDir::new().unwrap();
            let content = format!(
                "{{\"dependencies\":{{\"react\":\"{}\"}}}}",
                react_ver
            );
            fs::write(dir.path().join("package.json"), &content).unwrap();

            let result = TechDetector::detect(dir.path()).unwrap();

            prop_assert!(
                result.frameworks.contains(&"React".to_string()),
                "React must be detected when 'react' is in package.json dependencies. Got: {:?}",
                result.frameworks
            );
        }

        /// For any requirements.txt containing "django", Django must be detected
        /// as a framework.
        #[test]
        fn prop26_django_in_requirements_always_detects_django_framework(
            django_ver in arb_semver(),
            extra_pkg in arb_py_pkg(),
            extra_ver in arb_semver(),
        ) {
            let dir = TempDir::new().unwrap();
            let content = format!(
                "django=={}\n{}=={}\n",
                django_ver, extra_pkg, extra_ver
            );
            fs::write(dir.path().join("requirements.txt"), &content).unwrap();

            let result = TechDetector::detect(dir.path()).unwrap();

            prop_assert!(
                result.frameworks.contains(&"Django".to_string()),
                "Django must be detected when 'django' appears in requirements.txt. Got: {:?}",
                result.frameworks
            );
        }

        /// For any source file with a .rs extension placed in a subdirectory,
        /// Rust must be detected via extension scanning.
        #[test]
        fn prop26_rs_extension_always_detects_rust_language(
            file_stem in "[a-z]{3,10}",
        ) {
            let dir = TempDir::new().unwrap();
            let src = dir.path().join("src");
            fs::create_dir_all(&src).unwrap();
            fs::write(src.join(format!("{}.rs", file_stem)), "fn main() {}").unwrap();

            let result = TechDetector::detect(dir.path()).unwrap();

            prop_assert!(
                result.languages.contains(&"Rust".to_string()),
                "Rust must be detected from .rs file extension. Got: {:?}",
                result.languages
            );
        }

        /// For any source file with a .py extension placed in a subdirectory,
        /// Python must be detected via extension scanning.
        #[test]
        fn prop26_py_extension_always_detects_python_language(
            file_stem in "[a-z]{3,10}",
        ) {
            let dir = TempDir::new().unwrap();
            let src = dir.path().join("src");
            fs::create_dir_all(&src).unwrap();
            fs::write(src.join(format!("{}.py", file_stem)), "def main(): pass").unwrap();

            let result = TechDetector::detect(dir.path()).unwrap();

            prop_assert!(
                result.languages.contains(&"Python".to_string()),
                "Python must be detected from .py file extension. Got: {:?}",
                result.languages
            );
        }

        /// Files placed inside node_modules must never cause language detection,
        /// regardless of their extension.
        #[test]
        fn prop26_node_modules_never_contributes_to_detection(
            file_stem in "[a-z]{3,10}",
        ) {
            let dir = TempDir::new().unwrap();
            let nm = dir.path().join("node_modules").join("some-lib");
            fs::create_dir_all(&nm).unwrap();
            // Place .ts and .py files inside node_modules only
            fs::write(nm.join(format!("{}.ts", file_stem)), "export const x = 1;").unwrap();
            fs::write(nm.join(format!("{}.py", file_stem)), "x = 1").unwrap();

            let result = TechDetector::detect(dir.path()).unwrap();

            prop_assert!(
                !result.languages.contains(&"TypeScript".to_string()),
                "TypeScript must NOT be detected from node_modules. Got: {:?}",
                result.languages
            );
            prop_assert!(
                !result.languages.contains(&"Python".to_string()),
                "Python must NOT be detected from node_modules. Got: {:?}",
                result.languages
            );
        }

        /// Detection must be deterministic: calling detect() twice on the same
        /// directory must return identical results.
        #[test]
        fn prop26_detection_is_deterministic(
            pkg in arb_npm_pkg(),
            ver in arb_semver(),
        ) {
            let dir = TempDir::new().unwrap();
            let content = format!(
                "{{\"dependencies\":{{\"{}\": \"^{}\"}}}}",
                pkg, ver
            );
            fs::write(dir.path().join("package.json"), &content).unwrap();

            let result1 = TechDetector::detect(dir.path()).unwrap();
            let result2 = TechDetector::detect(dir.path()).unwrap();

            prop_assert_eq!(
                result1.languages, result2.languages,
                "Languages must be identical across two calls"
            );
            prop_assert_eq!(
                result1.package_managers, result2.package_managers,
                "Package managers must be identical across two calls"
            );
            prop_assert_eq!(
                result1.frameworks, result2.frameworks,
                "Frameworks must be identical across two calls"
            );
        }
    }

    // ── Property 27: Rule configuration based on detection ────────────────────
    //
    // Feature: sicario-cli-core, Property 27: Rule configuration based on detection
    // Validates: Requirements 10.3
    //
    // For any set of detected technologies (languages and frameworks), the CLI
    // should automatically configure optimal security rule subsets that are
    // relevant to those technologies without requiring user input.
    //
    // Key invariants:
    //   1. Rules for detected languages are always included when available.
    //   2. Rules for non-detected languages are never included.
    //   3. Rules for detected frameworks are always included when available.
    //   4. Rules for non-detected frameworks are never included.
    //   5. Configuration is deterministic (same input → same output).

    /// Helper: write a minimal YAML rule file with `n` rules.
    fn write_yaml_rules(dir: &std::path::Path, stem: &str, n: usize) {
        let mut content = String::new();
        for i in 0..n {
            content.push_str(&format!(
                "- id: \"{}-rule-{}\"\n  name: \"Rule {}\"\n",
                stem, i, i
            ));
        }
        fs::write(dir.join(format!("{}.yaml", stem)), content).unwrap();
    }

    /// Helper: build a `DetectedTechnologies` value from slices.
    fn make_tech(
        languages: &[&str],
        package_managers: &[&str],
        frameworks: &[&str],
    ) -> DetectedTechnologies {
        DetectedTechnologies {
            languages: languages.iter().map(|s| s.to_string()).collect(),
            package_managers: package_managers.iter().map(|s| s.to_string()).collect(),
            frameworks: frameworks.iter().map(|s| s.to_string()).collect(),
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// For any detected language that has a corresponding rule file, the
        /// configured rule set must include that file.
        ///
        /// Feature: sicario-cli-core, Property 27: Rule configuration based on detection
        #[test]
        fn prop27_detected_language_rules_always_included(
            lang in prop_oneof![
                Just("javascript"),
                Just("python"),
                Just("rust"),
                Just("go"),
                Just("java"),
                Just("typescript"),
            ],
            rule_count in 1usize..=5usize,
        ) {
            let rules_dir = TempDir::new().unwrap();
            write_yaml_rules(rules_dir.path(), lang, rule_count);

            // Capitalise first letter to match the detector output convention
            let lang_display = {
                let mut c = lang.chars();
                match c.next() {
                    None => String::new(),
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                }
            };

            let tech = make_tech(&[&lang_display], &[], &[]);
            let config = RuleConfigurator::configure(&tech, rules_dir.path());

            let expected_file = format!("{}.yaml", lang);
            prop_assert!(
                config.rule_files.iter().any(|f| f.file_name().and_then(|n| n.to_str()) == Some(&expected_file)),
                "Rule file '{}' must be included for detected language '{}'. Got: {:?}",
                expected_file, lang_display, config.rule_files
            );
        }

        /// For any language that is NOT detected, its rule file must never appear
        /// in the configured rule set, even when the file exists on disk.
        ///
        /// Feature: sicario-cli-core, Property 27: Rule configuration based on detection
        #[test]
        fn prop27_non_detected_language_rules_never_included(
            detected_lang in prop_oneof![
                Just(("javascript", "JavaScript")),
                Just(("python", "Python")),
                Just(("rust", "Rust")),
            ],
            absent_lang in prop_oneof![
                Just(("java", "Java")),
                Just(("go", "Go")),
                Just(("typescript", "TypeScript")),
            ],
        ) {
            // Only write rule files for both, but only detect one language
            let rules_dir = TempDir::new().unwrap();
            write_yaml_rules(rules_dir.path(), detected_lang.0, 2);
            write_yaml_rules(rules_dir.path(), absent_lang.0, 3);

            // Detect only the first language
            let tech = make_tech(&[detected_lang.1], &[], &[]);
            let config = RuleConfigurator::configure(&tech, rules_dir.path());

            let absent_file = format!("{}.yaml", absent_lang.0);
            prop_assert!(
                !config.rule_files.iter().any(|f| f.file_name().and_then(|n| n.to_str()) == Some(&absent_file)),
                "Rule file '{}' must NOT be included for non-detected language '{}'. Got: {:?}",
                absent_file, absent_lang.1, config.rule_files
            );
        }

        /// For any detected framework that has a corresponding rule file, the
        /// configured rule set must include that file.
        ///
        /// Feature: sicario-cli-core, Property 27: Rule configuration based on detection
        #[test]
        fn prop27_detected_framework_rules_always_included(
            fw in prop_oneof![
                Just(("next-js", "Next.js")),
                Just(("react", "React")),
                Just(("django", "Django")),
                Just(("fastapi", "FastAPI")),
            ],
            rule_count in 1usize..=5usize,
        ) {
            let rules_dir = TempDir::new().unwrap();
            // The configurator lowercases and replaces spaces/dots with '-'
            write_yaml_rules(rules_dir.path(), fw.0, rule_count);

            let tech = make_tech(&[], &[], &[fw.1]);
            let config = RuleConfigurator::configure(&tech, rules_dir.path());

            let expected_file = format!("{}.yaml", fw.0);
            prop_assert!(
                config.rule_files.iter().any(|f| f.file_name().and_then(|n| n.to_str()) == Some(&expected_file)),
                "Rule file '{}' must be included for detected framework '{}'. Got: {:?}",
                expected_file, fw.1, config.rule_files
            );
        }

        /// For any framework that is NOT detected, its rule file must never appear
        /// in the configured rule set, even when the file exists on disk.
        ///
        /// Feature: sicario-cli-core, Property 27: Rule configuration based on detection
        #[test]
        fn prop27_non_detected_framework_rules_never_included(
            detected_fw in prop_oneof![
                Just(("react", "React")),
                Just(("django", "Django")),
            ],
            absent_fw in prop_oneof![
                Just(("next-js", "Next.js")),
                Just(("fastapi", "FastAPI")),
            ],
        ) {
            let rules_dir = TempDir::new().unwrap();
            write_yaml_rules(rules_dir.path(), detected_fw.0, 2);
            write_yaml_rules(rules_dir.path(), absent_fw.0, 3);

            let tech = make_tech(&[], &[], &[detected_fw.1]);
            let config = RuleConfigurator::configure(&tech, rules_dir.path());

            let absent_file = format!("{}.yaml", absent_fw.0);
            prop_assert!(
                !config.rule_files.iter().any(|f| f.file_name().and_then(|n| n.to_str()) == Some(&absent_file)),
                "Rule file '{}' must NOT be included for non-detected framework '{}'. Got: {:?}",
                absent_file, absent_fw.1, config.rule_files
            );
        }

        /// Rule configuration must be deterministic: calling configure() twice
        /// with the same detected technologies and rules directory must return
        /// identical rule file lists.
        ///
        /// Feature: sicario-cli-core, Property 27: Rule configuration based on detection
        #[test]
        fn prop27_rule_configuration_is_deterministic(
            lang in prop_oneof![
                Just(("javascript", "JavaScript")),
                Just(("python", "Python")),
                Just(("rust", "Rust")),
            ],
            fw in prop_oneof![
                Just(("react", "React")),
                Just(("django", "Django")),
                Just(("next-js", "Next.js")),
            ],
        ) {
            let rules_dir = TempDir::new().unwrap();
            write_yaml_rules(rules_dir.path(), lang.0, 2);
            write_yaml_rules(rules_dir.path(), fw.0, 2);

            let tech = make_tech(&[lang.1], &[], &[fw.1]);

            let config1 = RuleConfigurator::configure(&tech, rules_dir.path());
            let config2 = RuleConfigurator::configure(&tech, rules_dir.path());

            prop_assert_eq!(
                config1.rule_files, config2.rule_files,
                "Rule files must be identical across two configure() calls"
            );
            prop_assert_eq!(
                config1.selected_categories, config2.selected_categories,
                "Selected categories must be identical across two configure() calls"
            );
            prop_assert_eq!(
                config1.rule_count, config2.rule_count,
                "Rule count must be identical across two configure() calls"
            );
        }

        /// For any set of detected technologies, every rule file in the configured
        /// set must correspond to a detected language, framework, package manager,
        /// or the universal ruleset — never to an unrelated technology.
        ///
        /// Feature: sicario-cli-core, Property 27: Rule configuration based on detection
        #[test]
        fn prop27_configured_rules_are_subset_of_relevant_technologies(
            pkg in arb_npm_pkg(),
            ver in arb_semver(),
        ) {
            let rules_dir = TempDir::new().unwrap();

            // Write rule files for detected and non-detected technologies
            write_yaml_rules(rules_dir.path(), "javascript", 3);
            write_yaml_rules(rules_dir.path(), "react", 2);
            // These should NOT be included
            write_yaml_rules(rules_dir.path(), "java", 4);
            write_yaml_rules(rules_dir.path(), "django", 2);
            write_yaml_rules(rules_dir.path(), "go", 3);

            // Detect only JavaScript + React via a package.json
            let project_dir = TempDir::new().unwrap();
            let content = format!(
                "{{\"dependencies\":{{\"react\":\"^18.0.0\",\"{}\":\"^{}\"}}}}",
                pkg, ver
            );
            fs::write(project_dir.path().join("package.json"), &content).unwrap();
            let tech = TechDetector::detect(project_dir.path()).unwrap();

            let config = RuleConfigurator::configure(&tech, rules_dir.path());

            // None of the non-detected technology rule files should appear
            for rule_file in &config.rule_files {
                let name = rule_file.file_name().and_then(|n| n.to_str()).unwrap_or("");
                prop_assert!(
                    name != "java.yaml" && name != "django.yaml" && name != "go.yaml",
                    "Non-detected technology rule file '{}' must not be included. Tech: {:?}",
                    name, tech
                );
            }
        }
    }
}
