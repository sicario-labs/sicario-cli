//! Auto-detection of languages, package managers, and frameworks.
//!
//! Requirements: 10.2

use anyhow::Result;
use std::collections::HashSet;
use std::path::Path;

/// Result of scanning a project directory for technologies.
#[derive(Debug, Clone, Default)]
pub struct DetectedTechnologies {
    /// Programming languages detected from file extensions and manifests
    pub languages: Vec<String>,
    /// Package managers detected from manifest files
    pub package_managers: Vec<String>,
    /// Frameworks detected from config files and manifest contents
    pub frameworks: Vec<String>,
}

/// Detects programming languages, package managers, and frameworks in a directory.
pub struct TechDetector;

impl TechDetector {
    /// Scan `project_root` and return all detected technologies.
    pub fn detect(project_root: &Path) -> Result<DetectedTechnologies> {
        let mut languages: HashSet<String> = HashSet::new();
        let mut package_managers: HashSet<String> = HashSet::new();
        let mut frameworks: HashSet<String> = HashSet::new();

        // ── Manifest-based detection ──────────────────────────────────────────
        Self::detect_from_manifests(
            project_root,
            &mut languages,
            &mut package_managers,
            &mut frameworks,
        )?;

        // ── File-extension-based language detection ───────────────────────────
        Self::detect_from_extensions(project_root, &mut languages)?;

        // ── Framework detection from config files ─────────────────────────────
        Self::detect_frameworks(project_root, &mut frameworks)?;

        let mut result = DetectedTechnologies {
            languages: sorted_vec(languages),
            package_managers: sorted_vec(package_managers),
            frameworks: sorted_vec(frameworks),
        };

        // Infer languages from package managers when extension scan found nothing
        if result.languages.is_empty() {
            if result.package_managers.contains(&"npm".to_string())
                || result.package_managers.contains(&"yarn".to_string())
                || result.package_managers.contains(&"pnpm".to_string())
            {
                result.languages.push("JavaScript".to_string());
            }
            if result.package_managers.contains(&"pip".to_string())
                || result.package_managers.contains(&"poetry".to_string())
            {
                result.languages.push("Python".to_string());
            }
            if result.package_managers.contains(&"cargo".to_string()) {
                result.languages.push("Rust".to_string());
            }
            if result.package_managers.contains(&"go modules".to_string()) {
                result.languages.push("Go".to_string());
            }
            if result.package_managers.contains(&"maven".to_string())
                || result.package_managers.contains(&"gradle".to_string())
            {
                result.languages.push("Java".to_string());
            }
        }

        Ok(result)
    }

    /// Detect package managers and languages from well-known manifest files.
    fn detect_from_manifests(
        root: &Path,
        languages: &mut HashSet<String>,
        package_managers: &mut HashSet<String>,
        frameworks: &mut HashSet<String>,
    ) -> Result<()> {
        // npm / yarn / pnpm
        let package_json = root.join("package.json");
        if package_json.exists() {
            languages.insert("JavaScript".to_string());
            package_managers.insert("npm".to_string());

            // Inspect package.json for framework hints
            if let Ok(content) = std::fs::read_to_string(&package_json) {
                Self::detect_js_frameworks(&content, frameworks);
                // TypeScript
                if content.contains("\"typescript\"") || content.contains("\"ts-node\"") {
                    languages.insert("TypeScript".to_string());
                }
                // yarn / pnpm
                if root.join("yarn.lock").exists() {
                    package_managers.insert("yarn".to_string());
                }
                if root.join("pnpm-lock.yaml").exists() {
                    package_managers.insert("pnpm".to_string());
                }
            }
        }

        // Python
        if root.join("requirements.txt").exists()
            || root.join("setup.py").exists()
            || root.join("pyproject.toml").exists()
        {
            languages.insert("Python".to_string());
            package_managers.insert("pip".to_string());
        }
        if root.join("pyproject.toml").exists() {
            if let Ok(content) = std::fs::read_to_string(root.join("pyproject.toml")) {
                if content.contains("[tool.poetry]") {
                    package_managers.insert("poetry".to_string());
                }
                Self::detect_python_frameworks(&content, frameworks);
            }
        }
        if root.join("requirements.txt").exists() {
            if let Ok(content) = std::fs::read_to_string(root.join("requirements.txt")) {
                Self::detect_python_frameworks(&content, frameworks);
            }
        }

        // Rust
        if root.join("Cargo.toml").exists() {
            languages.insert("Rust".to_string());
            package_managers.insert("cargo".to_string());
        }

        // Go
        if root.join("go.mod").exists() {
            languages.insert("Go".to_string());
            package_managers.insert("go modules".to_string());
        }

        // Java / Kotlin
        if root.join("pom.xml").exists() {
            languages.insert("Java".to_string());
            package_managers.insert("maven".to_string());
        }
        if root.join("build.gradle").exists() || root.join("build.gradle.kts").exists() {
            languages.insert("Java".to_string());
            package_managers.insert("gradle".to_string());
        }

        Ok(())
    }

    /// Walk the directory tree (up to 3 levels deep) and infer languages from
    /// file extensions. Skips common build/vendor directories.
    fn detect_from_extensions(root: &Path, languages: &mut HashSet<String>) -> Result<()> {
        Self::walk_for_extensions(root, languages, 0, 3);
        Ok(())
    }

    fn walk_for_extensions(
        dir: &Path,
        languages: &mut HashSet<String>,
        depth: usize,
        max_depth: usize,
    ) {
        if depth > max_depth {
            return;
        }
        let skip_dirs = [
            "node_modules",
            "target",
            "dist",
            "build",
            ".git",
            "vendor",
            "__pycache__",
        ];

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if skip_dirs.contains(&name) {
                    continue;
                }
                Self::walk_for_extensions(&path, languages, depth + 1, max_depth);
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                match ext {
                    "js" | "mjs" | "cjs" => {
                        languages.insert("JavaScript".to_string());
                    }
                    "ts" | "tsx" => {
                        languages.insert("TypeScript".to_string());
                    }
                    "py" => {
                        languages.insert("Python".to_string());
                    }
                    "rs" => {
                        languages.insert("Rust".to_string());
                    }
                    "go" => {
                        languages.insert("Go".to_string());
                    }
                    "java" | "kt" => {
                        languages.insert("Java".to_string());
                    }
                    _ => {}
                }
            }
        }
    }

    /// Detect frameworks from config files in the project root.
    fn detect_frameworks(root: &Path, frameworks: &mut HashSet<String>) -> Result<()> {
        // Next.js
        if root.join("next.config.js").exists()
            || root.join("next.config.ts").exists()
            || root.join("next.config.mjs").exists()
        {
            frameworks.insert("Next.js".to_string());
        }

        // React (via tsconfig or jsconfig)
        if root.join("tsconfig.json").exists() {
            if let Ok(content) = std::fs::read_to_string(root.join("tsconfig.json")) {
                if content.contains("react") || content.contains("jsx") {
                    frameworks.insert("React".to_string());
                }
            }
        }

        // Django
        if root.join("manage.py").exists() {
            frameworks.insert("Django".to_string());
        }

        // FastAPI / Flask
        if root.join("main.py").exists() || root.join("app.py").exists() {
            if let Ok(content) = std::fs::read_to_string(root.join("main.py").as_path())
                .or_else(|_| std::fs::read_to_string(root.join("app.py").as_path()))
            {
                if content.contains("FastAPI") || content.contains("fastapi") {
                    frameworks.insert("FastAPI".to_string());
                }
                if content.contains("Flask") || content.contains("flask") {
                    frameworks.insert("Flask".to_string());
                }
            }
        }

        Ok(())
    }

    /// Detect JavaScript/TypeScript frameworks from package.json content.
    fn detect_js_frameworks(package_json: &str, frameworks: &mut HashSet<String>) {
        if package_json.contains("\"next\"") || package_json.contains("\"next\":") {
            frameworks.insert("Next.js".to_string());
        }
        if package_json.contains("\"react\"") || package_json.contains("\"react\":") {
            frameworks.insert("React".to_string());
        }
        if package_json.contains("\"vue\"") || package_json.contains("\"vue\":") {
            frameworks.insert("Vue.js".to_string());
        }
        if package_json.contains("\"@angular/core\"") {
            frameworks.insert("Angular".to_string());
        }
        if package_json.contains("\"express\"") || package_json.contains("\"express\":") {
            frameworks.insert("Express".to_string());
        }
        if package_json.contains("\"fastify\"") {
            frameworks.insert("Fastify".to_string());
        }
    }

    /// Detect Python frameworks from requirements.txt or pyproject.toml content.
    fn detect_python_frameworks(content: &str, frameworks: &mut HashSet<String>) {
        let lower = content.to_lowercase();
        if lower.contains("django") {
            frameworks.insert("Django".to_string());
        }
        if lower.contains("fastapi") {
            frameworks.insert("FastAPI".to_string());
        }
        if lower.contains("flask") {
            frameworks.insert("Flask".to_string());
        }
        if lower.contains("starlette") {
            frameworks.insert("Starlette".to_string());
        }
    }
}

fn sorted_vec(set: HashSet<String>) -> Vec<String> {
    let mut v: Vec<String> = set.into_iter().collect();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_detect_npm_project() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"react":"^18.0.0"}}"#,
        )
        .unwrap();

        let result = TechDetector::detect(dir.path()).unwrap();
        assert!(result.languages.contains(&"JavaScript".to_string()));
        assert!(result.package_managers.contains(&"npm".to_string()));
        assert!(result.frameworks.contains(&"React".to_string()));
    }

    #[test]
    fn test_detect_nextjs_project() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies":{"next":"^14.0.0","react":"^18.0.0"}}"#,
        )
        .unwrap();
        fs::write(dir.path().join("next.config.js"), "module.exports = {}").unwrap();

        let result = TechDetector::detect(dir.path()).unwrap();
        assert!(result.frameworks.contains(&"Next.js".to_string()));
        assert!(result.frameworks.contains(&"React".to_string()));
    }

    #[test]
    fn test_detect_python_django() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("requirements.txt"),
            "django==4.2\npsycopg2==2.9\n",
        )
        .unwrap();
        fs::write(dir.path().join("manage.py"), "#!/usr/bin/env python").unwrap();

        let result = TechDetector::detect(dir.path()).unwrap();
        assert!(result.languages.contains(&"Python".to_string()));
        assert!(result.frameworks.contains(&"Django".to_string()));
    }

    #[test]
    fn test_detect_rust_project() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("Cargo.toml"),
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();

        let result = TechDetector::detect(dir.path()).unwrap();
        assert!(result.languages.contains(&"Rust".to_string()));
        assert!(result.package_managers.contains(&"cargo".to_string()));
    }

    #[test]
    fn test_detect_go_project() {
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join("go.mod"),
            "module example.com/myapp\n\ngo 1.21\n",
        )
        .unwrap();

        let result = TechDetector::detect(dir.path()).unwrap();
        assert!(result.languages.contains(&"Go".to_string()));
        assert!(result.package_managers.contains(&"go modules".to_string()));
    }

    #[test]
    fn test_detect_from_file_extensions() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("main.ts"), "const x: number = 1;").unwrap();
        fs::write(src.join("utils.py"), "def hello(): pass").unwrap();

        let result = TechDetector::detect(dir.path()).unwrap();
        assert!(result.languages.contains(&"TypeScript".to_string()));
        assert!(result.languages.contains(&"Python".to_string()));
    }

    #[test]
    fn test_empty_directory() {
        let dir = TempDir::new().unwrap();
        let result = TechDetector::detect(dir.path()).unwrap();
        assert!(result.languages.is_empty());
        assert!(result.package_managers.is_empty());
        assert!(result.frameworks.is_empty());
    }

    #[test]
    fn test_skips_node_modules() {
        let dir = TempDir::new().unwrap();
        let nm = dir.path().join("node_modules").join("some-lib");
        fs::create_dir_all(&nm).unwrap();
        // Only .ts files inside node_modules — should not be counted
        fs::write(nm.join("index.ts"), "export const x = 1;").unwrap();
        // No package.json at root
        let result = TechDetector::detect(dir.path()).unwrap();
        // TypeScript should NOT be detected from node_modules
        assert!(!result.languages.contains(&"TypeScript".to_string()));
    }
}
