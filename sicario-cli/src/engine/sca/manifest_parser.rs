//! Manifest parser for dependency extraction
//!
//! Parses `package.json`, `Cargo.toml`, and `requirements.txt` to extract
//! declared dependencies with their resolved versions.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A resolved dependency extracted from a manifest file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// Ecosystem identifier: "npm", "crates.io", "PyPI"
    pub ecosystem: String,
    /// Package name as declared in the manifest
    pub package_name: String,
    /// Resolved version string (may include range specifiers for requirements.txt)
    pub version: String,
}

/// Parses dependency manifests in a directory tree.
pub struct ManifestParser;

impl ManifestParser {
    /// Walk `dir` recursively and parse all supported manifest files.
    ///
    /// Returns a flat `Vec<Dependency>` covering all discovered manifests.
    pub fn parse_directory(dir: &Path) -> Result<Vec<Dependency>> {
        let mut deps = Vec::new();
        Self::walk(dir, &mut deps)?;
        Ok(deps)
    }

    fn walk(dir: &Path, deps: &mut Vec<Dependency>) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }

        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read directory: {:?}", dir))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Skip common non-source directories
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if matches!(name, "node_modules" | "target" | ".git" | "dist" | "build") {
                    continue;
                }
                Self::walk(&path, deps)?;
            } else if path.is_file() {
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                match file_name {
                    "package.json" => {
                        if let Ok(mut d) = parse_package_json(&path) {
                            deps.append(&mut d);
                        }
                    }
                    "Cargo.toml" => {
                        if let Ok(mut d) = parse_cargo_toml(&path) {
                            deps.append(&mut d);
                        }
                    }
                    "requirements.txt" => {
                        if let Ok(mut d) = parse_requirements_txt(&path) {
                            deps.append(&mut d);
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// package.json parser
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PackageJson {
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(rename = "devDependencies", default)]
    dev_dependencies: HashMap<String, String>,
}

/// Parse `package.json` and return npm dependencies.
pub fn parse_package_json(path: &Path) -> Result<Vec<Dependency>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read {:?}", path))?;

    let pkg: PackageJson = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse package.json at {:?}", path))?;

    let mut deps = Vec::new();

    for (name, version_spec) in pkg.dependencies.iter().chain(pkg.dev_dependencies.iter()) {
        let version = normalize_npm_version(version_spec);
        deps.push(Dependency {
            ecosystem: "npm".to_string(),
            package_name: name.clone(),
            version,
        });
    }

    Ok(deps)
}

/// Strip npm version range prefixes (`^`, `~`, `>=`, etc.) to get a plain version.
fn normalize_npm_version(spec: &str) -> String {
    let trimmed = spec.trim();
    // Strip leading range operators
    let stripped = trimmed.trim_start_matches(['^', '~', '>', '<', '=', ' ']);
    // If it looks like a plain semver, return it; otherwise return as-is
    if stripped.is_empty() {
        trimmed.to_string()
    } else {
        stripped.to_string()
    }
}

// ---------------------------------------------------------------------------
// Cargo.toml parser
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CargoToml {
    #[serde(default)]
    dependencies: HashMap<String, CargoDepValue>,
    #[serde(rename = "dev-dependencies", default)]
    dev_dependencies: HashMap<String, CargoDepValue>,
}

/// A Cargo dependency value can be a plain version string or a table.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CargoDepValue {
    Version(String),
    Table(CargoDepTable),
}

#[derive(Debug, Deserialize)]
struct CargoDepTable {
    version: Option<String>,
    #[serde(default)]
    workspace: bool,
}

/// Parse `Cargo.toml` and return crates.io dependencies.
pub fn parse_cargo_toml(path: &Path) -> Result<Vec<Dependency>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read {:?}", path))?;

    let cargo: CargoToml = toml::from_str(&content)
        .with_context(|| format!("Failed to parse Cargo.toml at {:?}", path))?;

    let mut deps = Vec::new();

    for (name, value) in cargo
        .dependencies
        .iter()
        .chain(cargo.dev_dependencies.iter())
    {
        let version = match value {
            CargoDepValue::Version(v) => normalize_cargo_version(v),
            CargoDepValue::Table(t) => {
                if t.workspace {
                    continue; // workspace deps resolved at workspace level
                }
                t.version
                    .as_deref()
                    .map(normalize_cargo_version)
                    .unwrap_or_default()
            }
        };

        if version.is_empty() {
            continue;
        }

        deps.push(Dependency {
            ecosystem: "crates.io".to_string(),
            package_name: name.clone(),
            version,
        });
    }

    Ok(deps)
}

/// Strip Cargo version requirement prefixes (`^`, `~`, `>=`, etc.).
fn normalize_cargo_version(spec: &str) -> String {
    let trimmed = spec.trim();
    let stripped = trimmed.trim_start_matches(['^', '~', '>', '<', '=', ' ']);
    if stripped.is_empty() {
        trimmed.to_string()
    } else {
        stripped.to_string()
    }
}

// ---------------------------------------------------------------------------
// requirements.txt parser
// ---------------------------------------------------------------------------

/// Parse `requirements.txt` and return PyPI dependencies.
///
/// Supports version specifiers: `==`, `>=`, `~=`, `<=`, `!=`, `>`, `<`.
pub fn parse_requirements_txt(path: &Path) -> Result<Vec<Dependency>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read {:?}", path))?;

    let mut deps = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }

        // Strip inline comments
        let line = line.split('#').next().unwrap_or(line).trim();

        if let Some(dep) = parse_requirements_line(line) {
            deps.push(dep);
        }
    }

    Ok(deps)
}

/// Parse a single requirements.txt line into a `Dependency`.
fn parse_requirements_line(line: &str) -> Option<Dependency> {
    // Handle extras like `requests[security]==2.28.0`
    let line = line.split('[').next().unwrap_or(line);

    // Split on version specifier operators
    let specifiers = ["==", "~=", ">=", "<=", "!=", ">", "<"];

    for spec in &specifiers {
        if let Some(pos) = line.find(spec) {
            let name = line[..pos].trim().to_string();
            let version_part = line[pos..].trim();

            if name.is_empty() {
                continue;
            }

            // For `==` and `~=`, extract the exact/compatible version
            let version = extract_requirements_version(version_part);

            return Some(Dependency {
                ecosystem: "PyPI".to_string(),
                package_name: name,
                version,
            });
        }
    }

    // No version specifier — just a package name
    let name = line.trim().to_string();
    if name.is_empty() {
        return None;
    }

    Some(Dependency {
        ecosystem: "PyPI".to_string(),
        package_name: name,
        version: String::new(),
    })
}

/// Extract the version string from a requirements specifier like `==2.28.0`.
fn extract_requirements_version(spec: &str) -> String {
    // Strip the operator prefix
    let stripped = spec.trim_start_matches(['=', '~', '>', '<', '!', ' ']);
    // Take only the first version if there are multiple constraints
    stripped
        .split(',')
        .next()
        .unwrap_or(stripped)
        .trim()
        .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    // ── package.json ────────────────────────────────────────────────────

    #[test]
    fn test_parse_package_json_basic() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"lodash":"^4.17.20","express":"~4.18.0"}}"#,
        );
        let deps = parse_package_json(&dir.path().join("package.json")).unwrap();
        assert_eq!(deps.len(), 2);
        assert!(deps
            .iter()
            .any(|d| d.package_name == "lodash" && d.version == "4.17.20"));
        assert!(deps
            .iter()
            .any(|d| d.package_name == "express" && d.version == "4.18.0"));
    }

    #[test]
    fn test_parse_package_json_dev_deps() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"devDependencies":{"jest":"29.0.0"}}"#,
        );
        let deps = parse_package_json(&dir.path().join("package.json")).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].package_name, "jest");
        assert_eq!(deps[0].ecosystem, "npm");
    }

    #[test]
    fn test_parse_package_json_empty() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "package.json", r#"{"name":"test"}"#);
        let deps = parse_package_json(&dir.path().join("package.json")).unwrap();
        assert!(deps.is_empty());
    }

    // ── Cargo.toml ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_cargo_toml_basic() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "Cargo.toml",
            r#"
[package]
name = "test"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"] }
"#,
        );
        let deps = parse_cargo_toml(&dir.path().join("Cargo.toml")).unwrap();
        assert!(deps
            .iter()
            .any(|d| d.package_name == "serde" && d.version == "1.0"));
        assert!(deps
            .iter()
            .any(|d| d.package_name == "tokio" && d.version == "1.35"));
    }

    #[test]
    fn test_parse_cargo_toml_dev_deps() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "Cargo.toml",
            r#"
[package]
name = "test"
version = "0.1.0"

[dev-dependencies]
proptest = "1.4"
"#,
        );
        let deps = parse_cargo_toml(&dir.path().join("Cargo.toml")).unwrap();
        assert!(deps
            .iter()
            .any(|d| d.package_name == "proptest" && d.ecosystem == "crates.io"));
    }

    // ── requirements.txt ─────────────────────────────────────────────────

    #[test]
    fn test_parse_requirements_txt_exact() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "requirements.txt",
            "requests==2.28.0\nflask>=2.0.0\ndjango~=4.2.0\n",
        );
        let deps = parse_requirements_txt(&dir.path().join("requirements.txt")).unwrap();
        assert!(deps
            .iter()
            .any(|d| d.package_name == "requests" && d.version == "2.28.0"));
        assert!(deps
            .iter()
            .any(|d| d.package_name == "flask" && d.version == "2.0.0"));
        assert!(deps
            .iter()
            .any(|d| d.package_name == "django" && d.version == "4.2.0"));
    }

    #[test]
    fn test_parse_requirements_txt_comments_skipped() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "requirements.txt",
            "# This is a comment\nrequests==2.28.0\n",
        );
        let deps = parse_requirements_txt(&dir.path().join("requirements.txt")).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].package_name, "requests");
    }

    #[test]
    fn test_parse_requirements_txt_no_version() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "requirements.txt", "requests\n");
        let deps = parse_requirements_txt(&dir.path().join("requirements.txt")).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].package_name, "requests");
        assert_eq!(deps[0].version, "");
    }

    // ── ManifestParser::parse_directory ──────────────────────────────────

    #[test]
    fn test_parse_directory_finds_all_manifests() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"lodash":"4.17.21"}}"#,
        );
        write(dir.path(), "requirements.txt", "requests==2.28.0\n");

        let sub = dir.path().join("sub");
        fs::create_dir_all(&sub).unwrap();
        write(
            &sub,
            "Cargo.toml",
            "[package]\nname=\"x\"\nversion=\"0.1.0\"\n[dependencies]\nserde=\"1.0\"\n",
        );

        let deps = ManifestParser::parse_directory(dir.path()).unwrap();
        assert!(deps.iter().any(|d| d.package_name == "lodash"));
        assert!(deps.iter().any(|d| d.package_name == "requests"));
        assert!(deps.iter().any(|d| d.package_name == "serde"));
    }

    #[test]
    fn test_parse_directory_skips_node_modules() {
        let dir = TempDir::new().unwrap();
        let nm = dir.path().join("node_modules").join("some-pkg");
        fs::create_dir_all(&nm).unwrap();
        write(
            &nm,
            "package.json",
            r#"{"dependencies":{"evil-pkg":"1.0.0"}}"#,
        );

        let deps = ManifestParser::parse_directory(dir.path()).unwrap();
        assert!(!deps.iter().any(|d| d.package_name == "evil-pkg"));
    }
}
