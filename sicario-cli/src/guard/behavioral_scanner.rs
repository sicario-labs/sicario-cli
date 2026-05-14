//! Behavioral scanner for npm packages.
//!
//! Scans a package directory using the behavioral anomaly rules and applies
//! category-based suppression for legitimate packages.

use std::path::Path;

use anyhow::Result;
use serde_json::Value;

use super::{AnomalySignal, BehavioralAnomaly};
use crate::engine::sast_engine::SastEngine;
use crate::engine::vulnerability::Severity;
use crate::guard::behavioral_rules::behavioral_rules;

/// Scans npm packages for behavioral anomalies.
pub struct BehavioralScanner;

impl BehavioralScanner {
    /// Scan a package directory for behavioral anomalies.
    ///
    /// Reads `package.json` to determine the package's category and applies
    /// suppression filters for legitimate packages (e.g. HTTP client packages
    /// are allowed to use `require('http')`).
    ///
    /// Returns anomalies sorted by severity (Critical first).
    pub fn scan_package(package_dir: &Path) -> Result<Vec<BehavioralAnomaly>> {
        // Create a SastEngine loaded with behavioral rules only.
        // We use the package_dir as the root so the engine's exclusion manager
        // is scoped to the package itself — not the parent project root.
        let mut engine = SastEngine::new(package_dir)?;
        for rule in behavioral_rules() {
            let _ = engine.load_rule_direct(rule);
        }

        // Collect JS/TS files directly (bypassing the exclusion manager which
        // may exclude node_modules/** via the parent project's .gitignore).
        let mut js_files: Vec<std::path::PathBuf> = Vec::new();
        collect_js_files_direct(package_dir, &mut js_files);

        // Scan each file directly using the parallel scan path with a fresh
        // exclusion manager that has no gitignore rules — this bypasses the
        // parent project's .gitignore which typically excludes node_modules/.
        let rules = engine.get_compiled_rules();
        let empty_exclusions = crate::parser::ExclusionManager::new_empty();
        let mut vulnerabilities = Vec::new();
        for file_path in &js_files {
            match SastEngine::scan_file_parallel(file_path, &rules, &empty_exclusions) {
                Ok(mut vulns) => vulnerabilities.append(&mut vulns),
                Err(e) => {
                    tracing::debug!("Failed to scan {:?}: {}", file_path, e);
                }
            }
        }

        // Read package.json for category filtering
        let (keywords, _name, _version) = read_package_json(package_dir);

        // Map vulnerabilities to BehavioralAnomaly structs
        let mut anomalies: Vec<BehavioralAnomaly> = vulnerabilities
            .into_iter()
            .filter_map(|vuln| {
                let signal = rule_id_to_signal(&vuln.rule_id)?;

                // Apply category filters
                if should_suppress(&signal, &keywords) {
                    return None;
                }

                let description = signal_description(&signal);
                Some(BehavioralAnomaly {
                    signal,
                    severity: vuln.severity,
                    file: vuln.file_path,
                    line: vuln.line,
                    snippet: vuln.snippet,
                    description,
                })
            })
            .collect();

        // Sort by severity: Critical first, then High, Medium, Low, Info
        anomalies.sort_by_key(|a| std::cmp::Reverse(a.severity));

        Ok(anomalies)
    }
}

/// Read `package.json` from the package directory and return
/// `(keywords, name, version)`.
fn read_package_json(package_dir: &Path) -> (Vec<String>, String, String) {
    let pkg_path = package_dir.join("package.json");
    let content = match std::fs::read_to_string(&pkg_path) {
        Ok(c) => c,
        Err(_) => return (vec![], String::new(), String::new()),
    };
    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return (vec![], String::new(), String::new()),
    };

    let keywords: Vec<String> = json
        .get("keywords")
        .and_then(|k| k.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                .collect()
        })
        .unwrap_or_default();

    let name = json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    (keywords, name, version)
}

/// Map a rule ID to an `AnomalySignal`.
fn rule_id_to_signal(rule_id: &str) -> Option<AnomalySignal> {
    match rule_id {
        "guard/unexpected-child-process" => Some(AnomalySignal::UnexpectedChildProcess),
        "guard/unexpected-net-access" => Some(AnomalySignal::UnexpectedNetworkAccess),
        "guard/unexpected-fs-access" => Some(AnomalySignal::UnexpectedFilesystemAccess),
        "guard/obfuscated-eval" => Some(AnomalySignal::ObfuscatedEval),
        "guard/process-env-access" => Some(AnomalySignal::PostInstallCredentialHarvest),
        "guard/dynamic-require" => Some(AnomalySignal::DynamicRequire),
        "guard/hex-encoded-string" => Some(AnomalySignal::HexEncodedPayload),
        _ => None,
    }
}

/// Returns a human-readable description for an anomaly signal.
fn signal_description(signal: &AnomalySignal) -> String {
    match signal {
        AnomalySignal::UnexpectedChildProcess => {
            "Package spawns child processes — potential command execution backdoor".to_string()
        }
        AnomalySignal::UnexpectedNetworkAccess => {
            "Package makes network connections — potential data exfiltration".to_string()
        }
        AnomalySignal::UnexpectedFilesystemAccess => {
            "Package accesses the filesystem — potential file theft or modification".to_string()
        }
        AnomalySignal::ObfuscatedEval => {
            "Package uses eval() with a dynamic argument — obfuscated code execution".to_string()
        }
        AnomalySignal::Base64DecodedEval => {
            "Package decodes base64 and passes result to eval() — obfuscated payload".to_string()
        }
        AnomalySignal::PostInstallCredentialHarvest => {
            "Package accesses process.env — potential credential harvesting".to_string()
        }
        AnomalySignal::HexEncodedPayload => {
            "Package contains a hex-encoded string payload — potential obfuscated malware"
                .to_string()
        }
        AnomalySignal::DynamicRequire => {
            "Package uses dynamic require() — potential arbitrary module loading".to_string()
        }
    }
}

/// Returns `true` if the anomaly should be suppressed for this package category.
fn should_suppress(signal: &AnomalySignal, keywords: &[String]) -> bool {
    match signal {
        AnomalySignal::UnexpectedNetworkAccess => {
            // Suppress for legitimate HTTP client packages
            let network_keywords = ["http", "request", "network", "fetch"];
            keywords
                .iter()
                .any(|k| network_keywords.contains(&k.as_str()))
        }
        AnomalySignal::UnexpectedFilesystemAccess => {
            // Suppress for legitimate file utility packages
            let fs_keywords = ["fs", "file", "io", "stream"];
            keywords.iter().any(|k| fs_keywords.contains(&k.as_str()))
        }
        _ => false,
    }
}

/// Recursively collect all JS/TS files under `dir`, bypassing any exclusion
/// manager. Used by `BehavioralScanner` to scan inside `node_modules` even
/// when the parent project's `.gitignore` excludes `node_modules/**`.
fn collect_js_files_direct(dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip hidden dirs and common non-source dirs within a package
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.')
                    || matches!(name, "node_modules" | "__tests__" | "test" | "tests")
                {
                    continue;
                }
            }
            collect_js_files_direct(&path, files);
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if matches!(ext, "js" | "ts" | "jsx" | "tsx" | "mjs" | "cjs") {
                    files.push(path);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_package(dir: &TempDir, pkg_json: &str, js_code: &str) {
        let mut f = std::fs::File::create(dir.path().join("package.json")).unwrap();
        f.write_all(pkg_json.as_bytes()).unwrap();

        let mut f = std::fs::File::create(dir.path().join("index.js")).unwrap();
        f.write_all(js_code.as_bytes()).unwrap();
    }

    #[test]
    fn test_child_process_anomaly_returned() {
        let dir = TempDir::new().unwrap();
        create_package(
            &dir,
            r#"{"name":"evil-pkg","version":"1.0.0","keywords":[]}"#,
            "const cp = require('child_process');",
        );

        let anomalies = BehavioralScanner::scan_package(dir.path()).unwrap();
        assert!(
            anomalies
                .iter()
                .any(|a| a.signal == AnomalySignal::UnexpectedChildProcess),
            "Expected UnexpectedChildProcess anomaly"
        );
    }

    #[test]
    fn test_http_client_package_suppresses_net_access() {
        let dir = TempDir::new().unwrap();
        create_package(
            &dir,
            r#"{"name":"my-http-client","version":"1.0.0","keywords":["http","request"]}"#,
            "const http = require('http');",
        );

        let anomalies = BehavioralScanner::scan_package(dir.path()).unwrap();
        assert!(
            !anomalies
                .iter()
                .any(|a| a.signal == AnomalySignal::UnexpectedNetworkAccess),
            "Expected UnexpectedNetworkAccess to be suppressed for HTTP client package"
        );
    }

    #[test]
    fn test_clean_math_package_returns_empty() {
        let dir = TempDir::new().unwrap();
        create_package(
            &dir,
            r#"{"name":"math-utils","version":"1.0.0","keywords":["math","utils"]}"#,
            "function add(a, b) { return a + b; }\nmodule.exports = { add };",
        );

        let anomalies = BehavioralScanner::scan_package(dir.path()).unwrap();
        assert!(
            anomalies.is_empty(),
            "Expected no anomalies for clean math package, got: {:?}",
            anomalies.iter().map(|a| &a.signal).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_obfuscated_eval_anomaly_returned() {
        let dir = TempDir::new().unwrap();
        create_package(
            &dir,
            r#"{"name":"evil-pkg","version":"1.0.0","keywords":[]}"#,
            "eval(Buffer.from(hex).toString());",
        );

        let anomalies = BehavioralScanner::scan_package(dir.path()).unwrap();
        assert!(
            anomalies
                .iter()
                .any(|a| a.signal == AnomalySignal::ObfuscatedEval),
            "Expected ObfuscatedEval anomaly"
        );
    }

    #[test]
    fn test_anomalies_sorted_critical_first() {
        let dir = TempDir::new().unwrap();
        create_package(
            &dir,
            r#"{"name":"evil-pkg","version":"1.0.0","keywords":[]}"#,
            // child_process = Critical, net = High
            "const cp = require('child_process');\nconst net = require('net');",
        );

        let anomalies = BehavioralScanner::scan_package(dir.path()).unwrap();
        if anomalies.len() >= 2 {
            assert_eq!(
                anomalies[0].severity,
                Severity::Critical,
                "First anomaly should be Critical"
            );
        }
    }

    #[test]
    fn test_fs_package_suppresses_fs_access() {
        let dir = TempDir::new().unwrap();
        create_package(
            &dir,
            r#"{"name":"fs-extra","version":"1.0.0","keywords":["fs","file","io"]}"#,
            "const fs = require('fs');",
        );

        let anomalies = BehavioralScanner::scan_package(dir.path()).unwrap();
        assert!(
            !anomalies
                .iter()
                .any(|a| a.signal == AnomalySignal::UnexpectedFilesystemAccess),
            "Expected UnexpectedFilesystemAccess to be suppressed for fs package"
        );
    }
}
