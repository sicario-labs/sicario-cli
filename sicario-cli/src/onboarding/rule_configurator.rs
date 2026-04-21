//! Configures optimal security rule subsets based on detected technologies.
//!
//! Requirements: 10.3

use std::path::{Path, PathBuf};

use super::detector::DetectedTechnologies;

/// Selects and configures security rule files appropriate for the detected
/// technology stack, skipping rules irrelevant to the project.
pub struct RuleConfigurator;

/// A configured rule set ready for loading into the SAST engine.
#[derive(Debug, Clone)]
pub struct ConfiguredRules {
    /// Paths to YAML rule files that should be loaded
    pub rule_files: Vec<PathBuf>,
    /// Human-readable summary of which rule categories were selected
    pub selected_categories: Vec<String>,
    /// Total number of rules that will be active
    pub rule_count: usize,
}

impl RuleConfigurator {
    /// Given detected technologies and a `rules_dir` containing YAML rule files,
    /// return the subset of rule files relevant to the project.
    ///
    /// If `rules_dir` does not exist or contains no matching files, returns an
    /// empty `ConfiguredRules` so the caller can fall back to built-in defaults.
    pub fn configure(tech: &DetectedTechnologies, rules_dir: &Path) -> ConfiguredRules {
        let mut rule_files: Vec<PathBuf> = Vec::new();
        let mut selected_categories: Vec<String> = Vec::new();

        // ── Universal rules (always included) ────────────────────────────────
        let universal = rules_dir.join("universal.yaml");
        if universal.exists() {
            rule_files.push(universal);
            selected_categories.push("Universal".to_string());
        }

        // ── Language-specific rules ───────────────────────────────────────────
        for lang in &tech.languages {
            let file_stem = lang.to_lowercase().replace([' ', '.'], "-");
            let candidate = rules_dir.join(format!("{}.yaml", file_stem));
            if candidate.exists() {
                rule_files.push(candidate);
                selected_categories.push(lang.clone());
            }
        }

        // ── Framework-specific rules ──────────────────────────────────────────
        for fw in &tech.frameworks {
            let file_stem = fw.to_lowercase().replace([' ', '.'], "-");
            let candidate = rules_dir.join(format!("{}.yaml", file_stem));
            if candidate.exists() {
                rule_files.push(candidate);
                selected_categories.push(fw.clone());
            }
        }

        // ── Package-manager-specific rules ────────────────────────────────────
        for pm in &tech.package_managers {
            let file_stem = pm.to_lowercase().replace([' ', '.'], "-");
            let candidate = rules_dir.join(format!("{}-deps.yaml", file_stem));
            if candidate.exists() {
                rule_files.push(candidate);
                selected_categories.push(format!("{} dependencies", pm));
            }
        }

        // Deduplicate while preserving order
        rule_files.dedup();
        selected_categories.dedup();

        // Count rules by reading YAML files (best-effort; 0 on parse failure)
        let rule_count = count_rules_in_files(&rule_files);

        ConfiguredRules {
            rule_files,
            selected_categories,
            rule_count,
        }
    }

    /// Return the built-in default rule count estimate when no rule files exist.
    /// This is used during onboarding to show a meaningful number even before
    /// the user has a rules directory.
    pub fn estimate_default_rule_count(tech: &DetectedTechnologies) -> usize {
        // Rough heuristic: 5 universal + 8 per language + 6 per framework
        let base = 5usize;
        let lang_rules = tech.languages.len() * 8;
        let fw_rules = tech.frameworks.len() * 6;
        base + lang_rules + fw_rules
    }
}

/// Count the total number of rules across all provided YAML files.
/// Returns 0 if any file cannot be read or parsed.
fn count_rules_in_files(files: &[PathBuf]) -> usize {
    let mut total = 0usize;
    for path in files {
        if let Ok(content) = std::fs::read_to_string(path) {
            // Each rule starts with a `- id:` line; count those
            total += content.lines().filter(|l| l.trim_start().starts_with("- id:")).count();
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onboarding::detector::DetectedTechnologies;
    use std::fs;
    use tempfile::TempDir;

    fn make_tech(languages: &[&str], package_managers: &[&str], frameworks: &[&str]) -> DetectedTechnologies {
        DetectedTechnologies {
            languages: languages.iter().map(|s| s.to_string()).collect(),
            package_managers: package_managers.iter().map(|s| s.to_string()).collect(),
            frameworks: frameworks.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn write_rule_file(dir: &Path, name: &str, rule_count: usize) {
        let mut content = String::new();
        for i in 0..rule_count {
            content.push_str(&format!(
                "- id: \"{}-rule-{}\"\n  name: \"Rule {}\"\n",
                name, i, i
            ));
        }
        fs::write(dir.join(format!("{}.yaml", name)), content).unwrap();
    }

    #[test]
    fn test_configure_selects_language_rules() {
        let dir = TempDir::new().unwrap();
        write_rule_file(dir.path(), "javascript", 3);
        write_rule_file(dir.path(), "python", 2);

        let tech = make_tech(&["JavaScript", "Python"], &[], &[]);
        let config = RuleConfigurator::configure(&tech, dir.path());

        assert!(config.rule_files.iter().any(|f| f.ends_with("javascript.yaml")));
        assert!(config.rule_files.iter().any(|f| f.ends_with("python.yaml")));
        assert_eq!(config.rule_count, 5);
    }

    #[test]
    fn test_configure_skips_irrelevant_rules() {
        let dir = TempDir::new().unwrap();
        write_rule_file(dir.path(), "javascript", 3);
        write_rule_file(dir.path(), "java", 4); // not in tech stack

        let tech = make_tech(&["JavaScript"], &[], &[]);
        let config = RuleConfigurator::configure(&tech, dir.path());

        assert!(config.rule_files.iter().any(|f| f.ends_with("javascript.yaml")));
        assert!(!config.rule_files.iter().any(|f| f.ends_with("java.yaml")));
    }

    #[test]
    fn test_configure_includes_framework_rules() {
        let dir = TempDir::new().unwrap();
        write_rule_file(dir.path(), "javascript", 2);
        write_rule_file(dir.path(), "next-js", 3);

        let tech = make_tech(&["JavaScript"], &[], &["Next.js"]);
        let config = RuleConfigurator::configure(&tech, dir.path());

        assert!(config.rule_files.iter().any(|f| f.ends_with("next-js.yaml")));
        assert!(config.selected_categories.contains(&"Next.js".to_string()));
    }

    #[test]
    fn test_configure_empty_rules_dir() {
        let dir = TempDir::new().unwrap();
        let tech = make_tech(&["Rust", "Python"], &["cargo", "pip"], &[]);
        let config = RuleConfigurator::configure(&tech, dir.path());

        // No files exist — should return empty but not panic
        assert!(config.rule_files.is_empty());
        assert_eq!(config.rule_count, 0);
    }

    #[test]
    fn test_estimate_default_rule_count() {
        let tech = make_tech(&["JavaScript", "TypeScript"], &["npm"], &["React", "Next.js"]);
        let count = RuleConfigurator::estimate_default_rule_count(&tech);
        // 5 base + 2*8 lang + 2*6 fw = 5 + 16 + 12 = 33
        assert_eq!(count, 33);
    }

    #[test]
    fn test_configure_includes_universal_rules() {
        let dir = TempDir::new().unwrap();
        write_rule_file(dir.path(), "universal", 10);

        let tech = make_tech(&[], &[], &[]);
        let config = RuleConfigurator::configure(&tech, dir.path());

        assert!(config.rule_files.iter().any(|f| f.ends_with("universal.yaml")));
        assert!(config.selected_categories.contains(&"Universal".to_string()));
        assert_eq!(config.rule_count, 10);
    }
}
