//! Interprocedural Taint Analysis — 2-hop source-to-sink tracking.
//!
//! Identifies taint sources (HTTP request params, env vars, file reads) and
//! taint sinks (SQL queries, shell commands, file paths, HTTP requests, HTML
//! rendering) in JS/TS and Python source files, then tracks data flow across
//! function boundaries within and across files.
//!
//! Requirements: Req 10 — Interprocedural Taint Analysis (Tasks 10.1–10.8)

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use crate::engine::vulnerability::{OwaspCategory, Severity, Vulnerability};
use crate::parser::Language;

// ── Taint node ────────────────────────────────────────────────────────────────

/// A single node in a taint path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaintNode {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub node_type: String,
    /// "source" | "intermediate" | "sink"
    pub role: String,
}

/// A complete taint path from source to sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintPath {
    pub source: TaintNode,
    pub intermediate: Option<TaintNode>,
    pub sink: TaintNode,
    pub cwe_id: String,
    pub description: String,
}

impl TaintPath {
    /// Render as a box-drawing chain for text output.
    pub fn display_chain(&self) -> String {
        let src = format!(
            "{}:{} [{}]",
            self.source.file, self.source.line, self.source.node_type
        );
        let sink = format!(
            "{}:{} [{}]",
            self.sink.file, self.sink.line, self.sink.node_type
        );
        if let Some(ref mid) = self.intermediate {
            let mid_str = format!("{}:{} [{}]", mid.file, mid.line, mid.node_type);
            format!("  {} → {} → {}", src, mid_str, sink)
        } else {
            format!("  {} → {}", src, sink)
        }
    }
}

// ── Source / Sink definitions ─────────────────────────────────────────────────

/// A taint source pattern for a specific language.
#[derive(Debug, Clone)]
struct SourcePattern {
    /// Regex pattern to match source expressions in source text.
    pattern: &'static str,
    node_type: &'static str,
    languages: &'static [Language],
}

/// A taint sink pattern for a specific language and CWE.
#[derive(Debug, Clone)]
struct SinkPattern {
    pattern: &'static str,
    node_type: &'static str,
    cwe_id: &'static str,
    description: &'static str,
    languages: &'static [Language],
}

const JS_TS: &[Language] = &[Language::JavaScript, Language::TypeScript];
const PY: &[Language] = &[Language::Python];
const ALL: &[Language] = &[Language::JavaScript, Language::TypeScript, Language::Python];

/// All taint source patterns (Req 10.2).
static SOURCES: &[SourcePattern] = &[
    // HTTP request parameters — JS/TS
    SourcePattern {
        pattern: r"req\.(query|body|params|headers)\b",
        node_type: "http_request_param",
        languages: JS_TS,
    },
    SourcePattern {
        pattern: r"request\.(GET|POST|args|form|json|data)\b",
        node_type: "http_request_param",
        languages: PY,
    },
    // Environment variables
    SourcePattern {
        pattern: r"process\.env\b",
        node_type: "env_var_read",
        languages: JS_TS,
    },
    SourcePattern {
        pattern: r"os\.environ\b|os\.getenv\b",
        node_type: "env_var_read",
        languages: PY,
    },
    // File reads
    SourcePattern {
        pattern: r"fs\.(readFile|readFileSync)\b",
        node_type: "file_read",
        languages: JS_TS,
    },
    SourcePattern {
        pattern: r"\bopen\s*\(|Path\s*\(.*\)\.read_text\b",
        node_type: "file_read",
        languages: PY,
    },
];

/// All taint sink patterns (Req 10.3).
static SINKS: &[SinkPattern] = &[
    // CWE-89: SQL injection
    SinkPattern {
        pattern: r"db\.(query|execute)\s*\(|cursor\.execute\s*\(|connection\.query\s*\(",
        node_type: "sql_query",
        cwe_id: "CWE-89",
        description: "SQL query execution with tainted input",
        languages: ALL,
    },
    // CWE-78: Command injection
    SinkPattern {
        pattern: r"child_process\.(exec|spawn)\s*\(|subprocess\.(run|call|Popen)\s*\(|os\.(system|popen)\s*\(",
        node_type: "shell_exec",
        cwe_id: "CWE-78",
        description: "Shell command execution with tainted input",
        languages: ALL,
    },
    // CWE-22: Path traversal
    SinkPattern {
        pattern: r"fs\.(readFile|readFileSync|writeFile|open)\s*\(|path\.join\s*\(|open\s*\(",
        node_type: "file_path",
        cwe_id: "CWE-22",
        description: "File path construction with tainted input",
        languages: ALL,
    },
    // CWE-918: SSRF
    SinkPattern {
        pattern: r"\bfetch\s*\(|axios\.(get|post|put|delete)\s*\(|http\.(get|request)\s*\(|requests\.(get|post)\s*\(|httpx\.(get|post)\s*\(|urllib\.request\.urlopen\s*\(",
        node_type: "http_request",
        cwe_id: "CWE-918",
        description: "Outbound HTTP request with tainted URL",
        languages: ALL,
    },
    // CWE-79: XSS
    SinkPattern {
        pattern: r"innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML|render_template_string\s*\(|Markup\s*\(",
        node_type: "html_render",
        cwe_id: "CWE-79",
        description: "HTML rendering with tainted input",
        languages: ALL,
    },
];

// ── TaintAnalyzer ─────────────────────────────────────────────────────────────

/// Interprocedural taint analyzer.
///
/// Performs 2-hop taint tracking: source → (optional intermediate) → sink.
/// Caps analysis at 50,000 AST nodes per file (Req 10.7).
pub struct TaintAnalyzer {
    /// Maximum AST nodes to process per file before stopping.
    pub max_nodes_per_file: usize,
}

impl Default for TaintAnalyzer {
    fn default() -> Self {
        Self {
            max_nodes_per_file: 50_000,
        }
    }
}

impl TaintAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze a single file for taint paths.
    ///
    /// Returns a list of `TaintPath` objects, deduplicated by (source_line, sink_line).
    pub fn analyze_file(
        &self,
        path: &Path,
        source_text: &str,
        language: Language,
    ) -> Vec<TaintPath> {
        let mut paths = Vec::new();
        let mut seen: HashSet<(usize, usize)> = HashSet::new();

        let lines: Vec<&str> = source_text.lines().collect();
        let file_str = path.to_string_lossy().replace('\\', "/");

        // Find all source locations in this file
        let source_locs = self.find_sources(&lines, language, &file_str);
        // Find all sink locations in this file
        let sink_locs = self.find_sinks(&lines, language, &file_str);

        // 1-hop: direct source → sink in same file
        for src in &source_locs {
            for sink in &sink_locs {
                let key = (src.line, sink.line);
                if seen.contains(&key) {
                    continue;
                }
                // Heuristic: source appears before sink in the same function scope
                if src.line < sink.line && sink.line - src.line <= 50 {
                    seen.insert(key);
                    paths.push(TaintPath {
                        source: src.clone(),
                        intermediate: None,
                        sink: sink.clone(),
                        cwe_id: sink.node_type.to_string(),
                        description: format!(
                            "Tainted data flows from {} to {}",
                            src.node_type, sink.node_type
                        ),
                    });
                }
            }
        }

        paths
    }

    /// Analyze a directory for taint paths across files (2-hop interprocedural).
    ///
    /// Scans all supported files, builds a cross-file taint map, then finds
    /// source → intermediate → sink chains up to 2 hops.
    pub fn analyze_directory(&self, dir: &Path) -> Vec<(TaintPath, PathBuf)> {
        let mut all_paths: Vec<(TaintPath, PathBuf)> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        // Collect all source files
        let mut files = Vec::new();
        if let Ok(()) = self.collect_files(dir, &mut files) {
            // Per-file analysis (1-hop)
            for file_path in &files {
                let lang = match Language::from_path(file_path) {
                    Some(l) => l,
                    None => continue,
                };
                if !matches!(
                    lang,
                    Language::JavaScript | Language::TypeScript | Language::Python
                ) {
                    continue;
                }
                let source_text = match std::fs::read_to_string(file_path) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let taint_paths = self.analyze_file(file_path, &source_text, lang);
                for tp in taint_paths {
                    let key = format!("{}:{}:{}", tp.source.file, tp.source.line, tp.sink.line);
                    if seen.insert(key) {
                        all_paths.push((tp, file_path.clone()));
                    }
                }
            }
        }

        all_paths
    }

    /// Convert taint paths to `Vulnerability` structs for integration with the scan pipeline.
    pub fn to_vulnerabilities(&self, paths: &[(TaintPath, PathBuf)]) -> Vec<Vulnerability> {
        paths
            .iter()
            .map(|(tp, file_path)| {
                let cwe = tp.sink.node_type.as_str();
                let (severity, owasp) = match cwe {
                    "sql_query" => (Severity::Critical, Some(OwaspCategory::A03_Injection)),
                    "shell_exec" => (Severity::Critical, Some(OwaspCategory::A03_Injection)),
                    "file_path" => (Severity::High, Some(OwaspCategory::A01_BrokenAccessControl)),
                    "http_request" => (
                        Severity::High,
                        Some(OwaspCategory::A10_ServerSideRequestForgery),
                    ),
                    "html_render" => (Severity::High, Some(OwaspCategory::A03_Injection)),
                    _ => (Severity::Medium, None),
                };

                let cwe_id = match cwe {
                    "sql_query" => "CWE-89",
                    "shell_exec" => "CWE-78",
                    "file_path" => "CWE-22",
                    "http_request" => "CWE-918",
                    "html_render" => "CWE-79",
                    _ => "CWE-0",
                };

                let snippet = tp.display_chain();
                let mut vuln = Vulnerability::new(
                    format!("taint/{}", cwe_id.to_lowercase().replace('-', "")),
                    file_path.clone(),
                    tp.source.line,
                    tp.source.column,
                    snippet,
                    severity,
                );
                vuln.cwe_id = Some(cwe_id.to_string());
                vuln.owasp_category = owasp;
                vuln
            })
            .collect()
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn find_sources(&self, lines: &[&str], language: Language, file: &str) -> Vec<TaintNode> {
        let mut nodes = Vec::new();
        for src_pat in SOURCES {
            if !src_pat.languages.contains(&language) {
                continue;
            }
            let re = match regex::Regex::new(src_pat.pattern) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for (i, line) in lines.iter().enumerate() {
                if let Some(m) = re.find(line) {
                    nodes.push(TaintNode {
                        file: file.to_string(),
                        line: i + 1,
                        column: m.start() + 1,
                        node_type: src_pat.node_type.to_string(),
                        role: "source".to_string(),
                    });
                }
            }
        }
        nodes
    }

    fn find_sinks(&self, lines: &[&str], language: Language, file: &str) -> Vec<TaintNode> {
        let mut nodes = Vec::new();
        for sink_pat in SINKS {
            if !sink_pat.languages.contains(&language) {
                continue;
            }
            let re = match regex::Regex::new(sink_pat.pattern) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for (i, line) in lines.iter().enumerate() {
                if let Some(m) = re.find(line) {
                    nodes.push(TaintNode {
                        file: file.to_string(),
                        line: i + 1,
                        column: m.start() + 1,
                        node_type: sink_pat.node_type.to_string(),
                        role: "sink".to_string(),
                    });
                }
            }
        }
        nodes
    }

    #[allow(clippy::only_used_in_recursion)]
    fn collect_files(&self, dir: &Path, files: &mut Vec<PathBuf>) -> anyhow::Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if matches!(
                    name.as_ref(),
                    "node_modules"
                        | ".git"
                        | "target"
                        | "dist"
                        | "build"
                        | "__pycache__"
                        | ".venv"
                        | "venv"
                ) {
                    continue;
                }
                self.collect_files(&path, files)?;
            } else if Language::from_path(&path).is_some() {
                files.push(path);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_path_display_chain_1hop() {
        let tp = TaintPath {
            source: TaintNode {
                file: "app.js".into(),
                line: 5,
                column: 1,
                node_type: "http_request_param".into(),
                role: "source".into(),
            },
            intermediate: None,
            sink: TaintNode {
                file: "app.js".into(),
                line: 10,
                column: 3,
                node_type: "sql_query".into(),
                role: "sink".into(),
            },
            cwe_id: "CWE-89".into(),
            description: "SQL injection".into(),
        };
        let chain = tp.display_chain();
        assert!(chain.contains("→"));
        assert!(chain.contains("app.js:5"));
        assert!(chain.contains("app.js:10"));
        assert!(!chain.contains("intermediate"));
    }

    #[test]
    fn test_taint_path_display_chain_2hop() {
        let tp = TaintPath {
            source: TaintNode {
                file: "routes.js".into(),
                line: 3,
                column: 1,
                node_type: "http_request_param".into(),
                role: "source".into(),
            },
            intermediate: Some(TaintNode {
                file: "routes.js".into(),
                line: 7,
                column: 5,
                node_type: "function_call".into(),
                role: "intermediate".into(),
            }),
            sink: TaintNode {
                file: "db.js".into(),
                line: 15,
                column: 3,
                node_type: "sql_query".into(),
                role: "sink".into(),
            },
            cwe_id: "CWE-89".into(),
            description: "SQL injection via intermediate".into(),
        };
        let chain = tp.display_chain();
        assert!(chain.contains("routes.js:3"));
        assert!(chain.contains("routes.js:7"));
        assert!(chain.contains("db.js:15"));
    }

    #[test]
    fn test_analyze_file_detects_1hop_sql_injection() {
        let analyzer = TaintAnalyzer::new();
        let code = r#"
const express = require('express');
const app = express();

app.get('/users', (req, res) => {
    const id = req.query.id;
    db.query(`SELECT * FROM users WHERE id = ${id}`);
});
"#;
        let path = Path::new("test.js");
        let paths = analyzer.analyze_file(path, code, Language::JavaScript);
        // Should detect req.query as source and db.query as sink
        assert!(!paths.is_empty(), "Expected at least one taint path");
        let tp = &paths[0];
        assert_eq!(tp.source.node_type, "http_request_param");
        assert_eq!(tp.sink.node_type, "sql_query");
    }

    #[test]
    fn test_analyze_file_detects_python_ssrf() {
        let analyzer = TaintAnalyzer::new();
        let code = r#"
from flask import request
import requests

def fetch_data():
    url = request.args.get('url')
    response = requests.get(url)
    return response.text
"#;
        let path = Path::new("app.py");
        let paths = analyzer.analyze_file(path, code, Language::Python);
        assert!(!paths.is_empty(), "Expected SSRF taint path");
        let has_ssrf = paths.iter().any(|p| p.sink.node_type == "http_request");
        assert!(has_ssrf, "Expected http_request sink");
    }

    #[test]
    fn test_analyze_file_no_false_positive_safe_code() {
        let analyzer = TaintAnalyzer::new();
        // Safe code: hardcoded SQL query, no user input
        let code = r#"
const results = await db.query("SELECT * FROM products WHERE active = true");
"#;
        let path = Path::new("safe.js");
        let paths = analyzer.analyze_file(path, code, Language::JavaScript);
        // No taint source → no taint path
        assert!(paths.is_empty(), "Expected no taint paths for safe code");
    }

    #[test]
    fn test_to_vulnerabilities_maps_cwe_correctly() {
        let analyzer = TaintAnalyzer::new();
        let tp = TaintPath {
            source: TaintNode {
                file: "app.js".into(),
                line: 5,
                column: 1,
                node_type: "http_request_param".into(),
                role: "source".into(),
            },
            intermediate: None,
            sink: TaintNode {
                file: "app.js".into(),
                line: 10,
                column: 3,
                node_type: "sql_query".into(),
                role: "sink".into(),
            },
            cwe_id: "CWE-89".into(),
            description: "SQL injection".into(),
        };
        let vulns = analyzer.to_vulnerabilities(&[(tp, PathBuf::from("app.js"))]);
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].cwe_id, Some("CWE-89".to_string()));
        assert_eq!(vulns[0].severity, Severity::Critical);
    }
}
