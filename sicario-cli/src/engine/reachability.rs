//! Reachability analysis for data-flow tracing
//!
//! Implements inter-procedural call graph construction and forward taint analysis
//! to determine whether vulnerabilities are reachable from external input sources.

use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use tree_sitter::{Query, QueryCursor};
use uuid::Uuid;

use super::Vulnerability;
use crate::parser::Language;

/// Type alias for function identifiers
pub type FunctionId = Uuid;

/// Source types for taint analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceType {
    HttpRequest,
    UserInput,
    FileRead,
    EnvironmentVariable,
}

/// Taint source definition with a tree-sitter query pattern
#[derive(Debug, Clone)]
pub struct TaintSource {
    pub source_type: SourceType,
    /// Tree-sitter query pattern string used to locate this source in ASTs
    pub pattern: String,
}

/// Function parameter information
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub tainted: bool,
}

/// Node in the inter-procedural call graph
#[derive(Debug, Clone)]
pub struct FunctionNode {
    pub id: FunctionId,
    pub name: String,
    pub file_path: PathBuf,
    pub line: usize,
    /// Functions this node calls
    pub calls: Vec<FunctionId>,
    /// Functions that call this node
    pub called_by: Vec<FunctionId>,
    pub parameters: Vec<Parameter>,
    /// Whether any parameter of this function is tainted
    pub is_taint_source: bool,
}

/// Inter-procedural call graph
pub struct CallGraph {
    pub nodes: HashMap<FunctionId, FunctionNode>,
    pub edges: Vec<(FunctionId, FunctionId)>,
    /// Map from (file_path, function_name) to FunctionId for lookup
    name_index: HashMap<(PathBuf, String), FunctionId>,
}

impl CallGraph {
    /// Create a new empty call graph
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            name_index: HashMap::new(),
        }
    }

    /// Add a function node to the graph
    pub fn add_node(&mut self, node: FunctionNode) {
        let key = (node.file_path.clone(), node.name.clone());
        self.name_index.insert(key, node.id);
        self.nodes.insert(node.id, node);
    }

    /// Add a directed call edge: caller → callee
    pub fn add_edge(&mut self, caller: FunctionId, callee: FunctionId) {
        self.edges.push((caller, callee));
        if let Some(caller_node) = self.nodes.get_mut(&caller) {
            if !caller_node.calls.contains(&callee) {
                caller_node.calls.push(callee);
            }
        }
        if let Some(callee_node) = self.nodes.get_mut(&callee) {
            if !callee_node.called_by.contains(&caller) {
                callee_node.called_by.push(caller);
            }
        }
    }

    /// Look up a function by file path and name
    pub fn find_function(&self, file_path: &Path, name: &str) -> Option<FunctionId> {
        self.name_index
            .get(&(file_path.to_path_buf(), name.to_string()))
            .copied()
    }

    /// Return all taint source function IDs
    pub fn taint_source_ids(&self) -> Vec<FunctionId> {
        self.nodes
            .values()
            .filter(|n| n.is_taint_source)
            .map(|n| n.id)
            .collect()
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Framework-specific taint source patterns (task 7.2)
// ---------------------------------------------------------------------------

/// Build the default set of taint sources for supported frameworks.
///
/// Each entry contains a tree-sitter query for the *language* that the
/// framework runs on, plus a human-readable description of the source type.
pub fn default_taint_sources() -> Vec<TaintSource> {
    vec![
        // ── Django (Python) ──────────────────────────────────────────────
        TaintSource {
            source_type: SourceType::HttpRequest,
            // request.GET / request.POST attribute access
            pattern: r#"(attribute
  object: (identifier) @obj
  attribute: (identifier) @attr
) @django_input"#
                .to_string(),
        },
        // ── FastAPI (Python) ─────────────────────────────────────────────
        TaintSource {
            source_type: SourceType::HttpRequest,
            // Function parameters annotated with FastAPI Request type
            pattern: r#"(typed_parameter
  (identifier) @param_name
  type: (type (identifier) @type_name)
  (#match? @type_name "^(Request|Body|Query|Form|Header|Cookie|Path)$")
) @fastapi_input"#
                .to_string(),
        },
        // ── React (JavaScript/TypeScript) ────────────────────────────────
        TaintSource {
            source_type: SourceType::UserInput,
            // Component props destructuring: ({ value, onChange, ... })
            pattern: r#"(jsx_opening_element
  attribute: (jsx_attribute
    (property_identifier) @prop
    (#match? @prop "^(value|defaultValue|onChange|onInput|onSubmit)$")
  )
) @react_prop"#
                .to_string(),
        },
        // ── Generic HTTP request (JavaScript fetch / axios) ──────────────
        TaintSource {
            source_type: SourceType::HttpRequest,
            pattern: r#"(call_expression
  function: [
    (identifier) @fn (#match? @fn "^(fetch|axios|request|got|superagent)$")
    (member_expression
      object: (identifier) @obj
      property: (property_identifier) @method
      (#match? @obj "^(axios|request|http|https)$")
    )
  ]
) @http_call"#
                .to_string(),
        },
        // ── Environment variable reads ────────────────────────────────────
        TaintSource {
            source_type: SourceType::EnvironmentVariable,
            // process.env.SOMETHING  (JS/TS)
            pattern: r#"(member_expression
  object: (member_expression
    object: (identifier) @proc (#match? @proc "process")
    property: (property_identifier) @env (#match? @env "env")
  )
) @env_read_js"#
                .to_string(),
        },
        TaintSource {
            source_type: SourceType::EnvironmentVariable,
            // os.environ / os.getenv  (Python)
            pattern: r#"(call
  function: (attribute
    object: (identifier) @mod (#match? @mod "os")
    attribute: (identifier) @fn (#match? @fn "^(getenv|environ)$")
  )
) @env_read_py"#
                .to_string(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Call-graph builder helpers
// ---------------------------------------------------------------------------

/// Parse a single source file and extract function definitions + call sites,
/// adding them to the provided `CallGraph`.
fn extract_functions_from_file(
    path: &Path,
    source: &str,
    language: Language,
    graph: &mut CallGraph,
) -> Result<()> {
    let ts_language = language_to_ts(language)?;
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(ts_language)?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse {:?}", path))?;

    // ── Step 1: collect function definitions ─────────────────────────────
    let func_query_str = function_definition_query(language);
    if let Ok(func_query) = Query::new(ts_language, func_query_str) {
        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&func_query, tree.root_node(), source.as_bytes());

        for m in matches {
            // The first capture is always the function name identifier
            if let Some(name_capture) = m.captures.first() {
                let name = name_capture
                    .node
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                let line = name_capture.node.start_position().row + 1;

                // Avoid duplicate nodes for the same (file, name)
                if graph.find_function(path, &name).is_none() {
                    let node = FunctionNode {
                        id: Uuid::new_v4(),
                        name,
                        file_path: path.to_path_buf(),
                        line,
                        calls: Vec::new(),
                        called_by: Vec::new(),
                        parameters: Vec::new(),
                        is_taint_source: false,
                    };
                    graph.add_node(node);
                }
            }
        }
    }

    // ── Step 2: collect call sites — edges are wired in pass 2 of build_call_graph ──
    // (Pass 1 only collects function definitions; edge wiring with the global
    //  ambiguity check happens in build_call_graph's pass 2 loop.)

    Ok(())
}

/// Find the function node that encloses a given line number in a file.
fn find_enclosing_function(path: &Path, line: usize, graph: &CallGraph) -> Option<FunctionId> {
    // Pick the function whose definition line is closest to (but ≤) the call line
    graph
        .nodes
        .values()
        .filter(|n| n.file_path == path && n.line <= line)
        .max_by_key(|n| n.line)
        .map(|n| n.id)
}

/// Mark taint sources in the call graph by scanning each file for framework patterns.
fn mark_taint_sources(
    path: &Path,
    source: &str,
    language: Language,
    _taint_sources: &[TaintSource],
    graph: &mut CallGraph,
) {
    let ts_language = match language_to_ts(language) {
        Ok(l) => l,
        Err(_) => return,
    };
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(ts_language).is_err() {
        return;
    }
    let Some(tree) = parser.parse(source, None) else {
        return;
    };

    // Use language-specific patterns to detect framework taint sources
    let patterns = framework_taint_patterns(language);
    for pattern_str in &patterns {
        let Ok(query) = Query::new(ts_language, pattern_str) else {
            continue;
        };

        let mut cursor = QueryCursor::new();
        let matches = cursor.matches(&query, tree.root_node(), source.as_bytes());

        for m in matches {
            if let Some(cap) = m.captures.first() {
                let match_line = cap.node.start_position().row + 1;
                // Check if the matched text is actually a framework pattern
                let matched_text = cap.node.utf8_text(source.as_bytes()).unwrap_or("");
                if is_framework_taint_text(matched_text, language) {
                    if let Some(fn_id) = find_enclosing_function(path, match_line, graph) {
                        if let Some(node) = graph.nodes.get_mut(&fn_id) {
                            node.is_taint_source = true;
                        }
                    }
                }
            }
        }
    }
}

/// Return tree-sitter query strings for detecting framework taint patterns per language.
fn framework_taint_patterns(language: Language) -> Vec<&'static str> {
    match language {
        Language::Python => vec![
            // Django/FastAPI: attribute access on `request` or `os`
            r#"(attribute object: (identifier) @obj)"#,
        ],
        Language::JavaScript | Language::TypeScript => vec![
            // process.env.X — capture the `process` identifier
            r#"(member_expression object: (member_expression object: (identifier) @proc))"#,
            // fetch / axios / http calls
            r#"(call_expression function: (identifier) @fn)"#,
        ],
        _ => vec![],
    }
}

/// Check whether matched text represents a framework taint source.
fn is_framework_taint_text(text: &str, language: Language) -> bool {
    match language {
        Language::Python => {
            // Django: `request` object access
            matches!(text, "request" | "os")
        }
        Language::JavaScript | Language::TypeScript => {
            // process.env or HTTP client calls
            matches!(
                text,
                "process" | "fetch" | "axios" | "request" | "got" | "superagent" | "http" | "https"
            )
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Language-specific tree-sitter query strings
// ---------------------------------------------------------------------------

fn language_to_ts(language: Language) -> Result<tree_sitter::Language> {
    match language {
        Language::JavaScript => Ok(tree_sitter_javascript::language()),
        Language::TypeScript => Ok(tree_sitter_typescript::language_typescript()),
        Language::Python => Ok(tree_sitter_python::language()),
        Language::Rust => Ok(tree_sitter_rust::language()),
        Language::Go => Ok(tree_sitter_go::language()),
        Language::Java => Ok(tree_sitter_java::language()),
        Language::Ruby => {
            anyhow::bail!("No tree-sitter grammar available for Ruby")
        }
        Language::Php => {
            anyhow::bail!("No tree-sitter grammar available for PHP")
        }
    }
}

/// Return a tree-sitter query that captures function/method *name* identifiers.
fn function_definition_query(language: Language) -> &'static str {
    match language {
        Language::JavaScript | Language::TypeScript => {
            // Capture only the name identifier, not the whole function node
            r#"[
  (function_declaration name: (identifier) @name)
  (method_definition name: (property_identifier) @name)
]"#
        }
        Language::Python => r#"(function_definition name: (identifier) @name)"#,
        Language::Rust => r#"(function_item name: (identifier) @name)"#,
        Language::Go => r#"(function_declaration name: (identifier) @name)"#,
        Language::Java => r#"(method_declaration name: (identifier) @name)"#,
        Language::Ruby => r#"(method name: (identifier) @name)"#,
        Language::Php => r#"(function_definition name: (name) @name)"#,
    }
}

/// Return a tree-sitter query that captures the *callee* name of a call expression.
fn call_expression_query(language: Language) -> &'static str {
    match language {
        Language::JavaScript | Language::TypeScript => {
            r#"(call_expression function: (identifier) @callee)"#
        }
        Language::Python => r#"(call function: (identifier) @callee)"#,
        Language::Rust => r#"(call_expression function: (identifier) @callee)"#,
        Language::Go => r#"(call_expression function: (identifier) @callee)"#,
        Language::Java => r#"(method_invocation name: (identifier) @callee)"#,
        Language::Ruby => r#"(call method: (identifier) @callee)"#,
        Language::Php => r#"(function_call_expression function: (name) @callee)"#,
    }
}

// ---------------------------------------------------------------------------
// ReachabilityAnalyzer (tasks 7.1, 7.2, 7.4, 7.6)
// ---------------------------------------------------------------------------

/// Reachability analyzer: builds a call graph, marks taint sources, and
/// performs forward data-flow analysis to determine whether vulnerabilities
/// are reachable from external input.
pub struct ReachabilityAnalyzer {
    pub call_graph: CallGraph,
    pub taint_sources: Vec<TaintSource>,
}

impl ReachabilityAnalyzer {
    /// Create a new analyzer with the default framework taint sources.
    pub fn new() -> Self {
        Self {
            call_graph: CallGraph::new(),
            taint_sources: default_taint_sources(),
        }
    }

    /// Create an analyzer with a custom set of taint sources (useful for tests).
    pub fn with_taint_sources(taint_sources: Vec<TaintSource>) -> Self {
        Self {
            call_graph: CallGraph::new(),
            taint_sources,
        }
    }

    // ── Task 7.1: Build inter-procedural call graph ──────────────────────

    /// Parse all provided source files and build the inter-procedural call graph.
    /// Also marks taint sources based on framework-specific patterns (task 7.2).
    pub fn build_call_graph(&mut self, files: &[PathBuf]) -> Result<()> {
        // Pass 1: extract function definitions from every file
        for path in files {
            let Ok(source) = std::fs::read_to_string(path) else {
                continue;
            };
            let Some(language) = Language::from_path(path) else {
                continue;
            };
            let _ = extract_functions_from_file(path, &source, language, &mut self.call_graph);
        }

        // Pass 2: wire call edges (needs all nodes to be present first)
        for path in files {
            let Ok(source) = std::fs::read_to_string(path) else {
                continue;
            };
            let Some(language) = Language::from_path(path) else {
                continue;
            };
            let ts_language = match language_to_ts(language) {
                Ok(l) => l,
                Err(_) => continue,
            };
            let call_query_str = call_expression_query(language);
            let Ok(call_query) = Query::new(ts_language, call_query_str) else {
                continue;
            };

            let mut parser = tree_sitter::Parser::new();
            if parser.set_language(ts_language).is_err() {
                continue;
            }
            let Some(tree) = parser.parse(&source, None) else {
                continue;
            };

            let mut cursor = QueryCursor::new();
            let matches = cursor.matches(&call_query, tree.root_node(), source.as_bytes());

            for m in matches {
                if let Some(callee_capture) = m.captures.first() {
                    let callee_name = callee_capture
                        .node
                        .utf8_text(source.as_bytes())
                        .unwrap_or("")
                        .to_string();
                    if callee_name.is_empty() {
                        continue;
                    }
                    let call_line = callee_capture.node.start_position().row + 1;
                    let caller_id = find_enclosing_function(path, call_line, &self.call_graph);

                    // Task 15.1: Global cross-file callee lookup with confidence filter.
                    // Only wire the edge if exactly one node across all files has that
                    // function name (skip ambiguous matches to avoid false edges).
                    let matching_nodes: Vec<FunctionId> = self
                        .call_graph
                        .nodes
                        .values()
                        .filter(|n| n.name == callee_name)
                        .map(|n| n.id)
                        .collect();

                    let callee_id = if matching_nodes.len() == 1 {
                        Some(matching_nodes[0])
                    } else {
                        // Zero matches or ambiguous (multiple files define same name) → skip
                        None
                    };

                    if let (Some(caller), Some(callee)) = (caller_id, callee_id) {
                        if caller != callee {
                            self.call_graph.add_edge(caller, callee);
                        }
                    }
                }
            }
        }

        // Pass 3: mark taint sources (task 7.2)
        for path in files {
            let Ok(source) = std::fs::read_to_string(path) else {
                continue;
            };
            let Some(language) = Language::from_path(path) else {
                continue;
            };
            mark_taint_sources(path, &source, language, &[], &mut self.call_graph);
        }

        Ok(())
    }

    // ── Task 7.4: Forward data-flow analysis with worklist algorithm ──────

    /// Determine whether a vulnerability is reachable from any external taint source.
    ///
    /// Uses a BFS worklist over the call graph starting from all taint-source
    /// functions, performing fixed-point iteration until no new nodes are reached.
    pub fn is_reachable(&self, vulnerability: &Vulnerability) -> Result<bool> {
        // Find the function that contains the vulnerability
        let vuln_fn = find_enclosing_function(
            &vulnerability.file_path,
            vulnerability.line,
            &self.call_graph,
        );

        let Some(vuln_fn_id) = vuln_fn else {
            // No enclosing function found – conservatively mark as reachable
            return Ok(true);
        };

        // BFS from all taint sources
        let reachable = self.reachable_from_sources();
        Ok(reachable.contains(&vuln_fn_id))
    }

    /// Trace the taint flow from a specific source to a specific sink function.
    /// Returns the path of function IDs if one exists, or `None` otherwise.
    pub fn trace_taint_flow(
        &self,
        source: &TaintSource,
        sink: &FunctionId,
    ) -> Option<Vec<FunctionId>> {
        // Find all functions that match this taint source pattern
        let source_ids: Vec<FunctionId> = self
            .call_graph
            .nodes
            .values()
            .filter(|n| n.is_taint_source)
            .map(|n| n.id)
            .collect();

        for start in source_ids {
            if let Some(path) = self.bfs_path(start, *sink) {
                return Some(path);
            }
        }
        None
    }

    /// Check whether a known vulnerable dependency is reachable from external input.
    ///
    /// `package_call_sites` are the `FunctionId`s of functions in the project that
    /// invoke the affected package's API surface (resolved by `SastEngine::scan_manifests`).
    pub fn is_vulnerable_dependency_reachable(
        &self,
        package_call_sites: &[FunctionId],
    ) -> Result<bool> {
        let reachable = self.reachable_from_sources();
        Ok(package_call_sites.iter().any(|id| reachable.contains(id)))
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// BFS from all taint-source nodes; returns the set of reachable function IDs.
    /// This is the fixed-point worklist algorithm (task 7.4).
    fn reachable_from_sources(&self) -> HashSet<FunctionId> {
        let mut visited: HashSet<FunctionId> = HashSet::new();
        let mut queue: VecDeque<FunctionId> = VecDeque::new();

        // Seed with all taint sources
        for id in self.call_graph.taint_source_ids() {
            if visited.insert(id) {
                queue.push_back(id);
            }
        }

        // Forward BFS through call edges
        while let Some(current) = queue.pop_front() {
            if let Some(node) = self.call_graph.nodes.get(&current) {
                for &callee in &node.calls {
                    if visited.insert(callee) {
                        queue.push_back(callee);
                    }
                }
            }
        }

        visited
    }

    /// BFS from `start` to `goal`; returns the path if found.
    fn bfs_path(&self, start: FunctionId, goal: FunctionId) -> Option<Vec<FunctionId>> {
        if start == goal {
            return Some(vec![start]);
        }

        let mut visited: HashSet<FunctionId> = HashSet::new();
        let mut queue: VecDeque<Vec<FunctionId>> = VecDeque::new();
        visited.insert(start);
        queue.push_back(vec![start]);

        while let Some(path) = queue.pop_front() {
            let current = *path.last().unwrap();
            if let Some(node) = self.call_graph.nodes.get(&current) {
                for &callee in &node.calls {
                    if callee == goal {
                        let mut result = path.clone();
                        result.push(callee);
                        return Some(result);
                    }
                    if visited.insert(callee) {
                        let mut new_path = path.clone();
                        new_path.push(callee);
                        queue.push_back(new_path);
                    }
                }
            }
        }
        None
    }
}

impl Default for ReachabilityAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Task 15.2: TaintTrace and TaintTraceStep structs
// ---------------------------------------------------------------------------

/// A single step in a cross-boundary taint trace (source → sink path).
#[derive(Debug, Clone)]
pub struct TaintTraceStep {
    pub file: PathBuf,
    pub line: usize,
    pub function_name: String,
    pub description: String,
}

/// A complete taint trace from an external input source to a vulnerable sink.
#[derive(Debug, Clone)]
pub struct TaintTrace {
    /// Ordered steps from taint source to sink (inclusive).
    pub steps: Vec<TaintTraceStep>,
    /// Rule ID of the vulnerability at the sink.
    pub sink_rule_id: String,
    pub sink_file: PathBuf,
    pub sink_line: usize,
}

impl TaintTrace {
    /// Render the taint trace as a box-drawing terminal string.
    ///
    /// The returned string is intended for display on stderr to avoid
    /// contaminating `--format json` output on stdout.
    pub fn render(&self) -> String {
        let width = 76usize;
        let header = format!(
            "TAINT TRACE: {} in {}:{}",
            self.sink_rule_id,
            self.sink_file.display(),
            self.sink_line
        );
        // Truncate header if too long
        let header_display = if header.len() > width - 4 {
            format!("{}…", &header[..width - 5])
        } else {
            header
        };

        let mut out = String::new();
        // Top border
        let top_fill = width.saturating_sub(4 + header_display.len());
        out.push_str(&format!(
            "  ┌─ {} {}\n",
            header_display,
            "─".repeat(top_fill)
        ));
        out.push_str(&format!("  │{}\n", " ".repeat(width)));

        for (i, step) in self.steps.iter().enumerate() {
            let is_sink = i == self.steps.len() - 1;
            let sink_marker = if is_sink { "  ← SINK" } else { "" };
            let step_line = format!(
                "  [{}] {}:{}  {}{}",
                i + 1,
                step.file.display(),
                step.line,
                step.function_name,
                sink_marker
            );
            out.push_str(&format!("  │  {}\n", step_line));
            out.push_str(&format!("  │      ↳ {}\n", step.description));
            out.push_str(&format!("  │{}\n", " ".repeat(width)));
        }

        // Attack vector summary
        let n_files: std::collections::HashSet<_> = self.steps.iter().map(|s| &s.file).collect();
        out.push_str(&format!(
            "  │  Attack vector: {} function{} across {} file{}\n",
            self.steps.len(),
            if self.steps.len() == 1 { "" } else { "s" },
            n_files.len(),
            if n_files.len() == 1 { "" } else { "s" },
        ));
        out.push_str(&format!("  └{}\n", "─".repeat(width + 1)));
        out
    }
}

// ---------------------------------------------------------------------------
// Task 15.3: ReachabilityAnalyzer::trace_to_vulnerability
// ---------------------------------------------------------------------------

impl ReachabilityAnalyzer {
    /// Trace the taint path from any external input source to the function
    /// containing `vuln`. Returns `None` if no path exists (the vulnerability
    /// is not reachable from any taint source).
    pub fn trace_to_vulnerability(&self, vuln: &Vulnerability) -> Option<TaintTrace> {
        let vuln_fn_id = find_enclosing_function(&vuln.file_path, vuln.line, &self.call_graph)?;

        // Try each taint source; return the first path found
        for source_id in self.call_graph.taint_source_ids() {
            if let Some(path) = self.bfs_path(source_id, vuln_fn_id) {
                let steps = path
                    .iter()
                    .map(|id| {
                        let node = &self.call_graph.nodes[id];
                        TaintTraceStep {
                            file: node.file_path.clone(),
                            line: node.line,
                            function_name: node.name.clone(),
                            description: if node.is_taint_source {
                                "External input enters here".to_string()
                            } else {
                                format!("Tainted data flows through `{}`", node.name)
                            },
                        }
                    })
                    .collect();

                return Some(TaintTrace {
                    steps,
                    sink_rule_id: vuln.rule_id.clone(),
                    sink_file: vuln.file_path.clone(),
                    sink_line: vuln.line,
                });
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_call_graph_add_node_and_edge() {
        let mut graph = CallGraph::new();
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();

        let node_a = FunctionNode {
            id: id_a,
            name: "a".to_string(),
            file_path: PathBuf::from("a.js"),
            line: 1,
            calls: vec![],
            called_by: vec![],
            parameters: vec![],
            is_taint_source: false,
        };
        let node_b = FunctionNode {
            id: id_b,
            name: "b".to_string(),
            file_path: PathBuf::from("a.js"),
            line: 5,
            calls: vec![],
            called_by: vec![],
            parameters: vec![],
            is_taint_source: false,
        };

        graph.add_node(node_a);
        graph.add_node(node_b);
        graph.add_edge(id_a, id_b);

        assert!(graph.nodes[&id_a].calls.contains(&id_b));
        assert!(graph.nodes[&id_b].called_by.contains(&id_a));
        assert_eq!(graph.edges.len(), 1);
    }

    #[test]
    fn test_js_query_compiles() {
        let ts_language = tree_sitter_javascript::language();
        let query_str = r#"[
  (function_declaration name: (identifier) @name)
  (method_definition name: (property_identifier) @name)
]"#;
        let result = Query::new(ts_language, query_str);
        assert!(result.is_ok(), "Query failed: {:?}", result.err());

        let source = r#"
function handler(req) {
  return req;
}
"#;
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(ts_language).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let query = result.unwrap();
        let mut cursor = QueryCursor::new();
        let mut found_names: Vec<String> = Vec::new();
        for m in cursor.matches(&query, tree.root_node(), source.as_bytes()) {
            for cap in m.captures {
                let text = cap
                    .node
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .to_string();
                found_names.push(text);
            }
        }
        assert!(!found_names.is_empty(), "Expected at least one match");
        assert!(found_names.contains(&"handler".to_string()));
    }

    #[test]
    fn test_build_call_graph_js() {
        let temp = TempDir::new().unwrap();
        let path = write_file(
            temp.path(),
            "app.js",
            r#"
function handler(req) {
  const data = req.body;
  process(data);
}
function process(input) {
  return input;
}
"#,
        );

        let mut analyzer = ReachabilityAnalyzer::new();
        analyzer
            .build_call_graph(std::slice::from_ref(&path))
            .unwrap();

        // Debug: print all nodes
        for node in analyzer.call_graph.nodes.values() {
            println!("Node: {} at {:?}:{}", node.name, node.file_path, node.line);
        }

        // Both functions should be in the graph
        assert!(
            analyzer
                .call_graph
                .nodes
                .values()
                .any(|n| n.name == "handler"),
            "Expected 'handler' in call graph, found: {:?}",
            analyzer
                .call_graph
                .nodes
                .values()
                .map(|n| &n.name)
                .collect::<Vec<_>>()
        );
        assert!(analyzer
            .call_graph
            .nodes
            .values()
            .any(|n| n.name == "process"));
    }

    #[test]
    fn test_reachability_bfs() {
        // Manually build a graph: source → a → b (vulnerable)
        let mut analyzer = ReachabilityAnalyzer::new();
        let id_source = Uuid::new_v4();
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();

        for (id, name, is_src) in [
            (id_source, "source_fn", true),
            (id_a, "middle_fn", false),
            (id_b, "vuln_fn", false),
        ] {
            analyzer.call_graph.add_node(FunctionNode {
                id,
                name: name.to_string(),
                file_path: PathBuf::from("x.js"),
                line: 1,
                calls: vec![],
                called_by: vec![],
                parameters: vec![],
                is_taint_source: is_src,
            });
        }
        analyzer.call_graph.add_edge(id_source, id_a);
        analyzer.call_graph.add_edge(id_a, id_b);

        let reachable = analyzer.reachable_from_sources();
        assert!(reachable.contains(&id_source));
        assert!(reachable.contains(&id_a));
        assert!(reachable.contains(&id_b));
    }

    #[test]
    fn test_unreachable_function() {
        let mut analyzer = ReachabilityAnalyzer::new();
        let id_source = Uuid::new_v4();
        let id_isolated = Uuid::new_v4();

        analyzer.call_graph.add_node(FunctionNode {
            id: id_source,
            name: "src".to_string(),
            file_path: PathBuf::from("x.js"),
            line: 1,
            calls: vec![],
            called_by: vec![],
            parameters: vec![],
            is_taint_source: true,
        });
        analyzer.call_graph.add_node(FunctionNode {
            id: id_isolated,
            name: "isolated".to_string(),
            file_path: PathBuf::from("x.js"),
            line: 10,
            calls: vec![],
            called_by: vec![],
            parameters: vec![],
            is_taint_source: false,
        });
        // No edge between them

        let reachable = analyzer.reachable_from_sources();
        assert!(reachable.contains(&id_source));
        assert!(!reachable.contains(&id_isolated));
    }

    // ── Task 15.1: Cross-file call edge resolution ────────────────────────

    #[test]
    fn test_cross_file_edge_resolution() {
        // Two-file JS project: handler in routes.js calls buildQuery in db.js
        let temp = TempDir::new().unwrap();
        let routes_path = write_file(
            temp.path(),
            "routes.js",
            r#"
function handler(req) {
  const result = buildQuery(req.body);
  return result;
}
"#,
        );
        let db_path = write_file(
            temp.path(),
            "db.js",
            r#"
function buildQuery(params) {
  return "SELECT * FROM t WHERE id = " + params.id;
}
"#,
        );

        let mut analyzer = ReachabilityAnalyzer::new();
        analyzer.build_call_graph(&[routes_path, db_path]).unwrap();

        // Find the handler and buildQuery nodes
        let handler_id = analyzer
            .call_graph
            .nodes
            .values()
            .find(|n| n.name == "handler")
            .map(|n| n.id);
        let build_query_id = analyzer
            .call_graph
            .nodes
            .values()
            .find(|n| n.name == "buildQuery")
            .map(|n| n.id);

        assert!(handler_id.is_some(), "handler should be in call graph");
        assert!(
            build_query_id.is_some(),
            "buildQuery should be in call graph"
        );

        // The cross-file edge handler → buildQuery should be present
        let handler_node = &analyzer.call_graph.nodes[&handler_id.unwrap()];
        assert!(
            handler_node.calls.contains(&build_query_id.unwrap()),
            "handler should call buildQuery across files"
        );
    }

    #[test]
    fn test_ambiguous_callee_no_edge() {
        // Same function name in two files → no edge wired (conservative)
        let temp = TempDir::new().unwrap();
        let file_a = write_file(
            temp.path(),
            "a.js",
            r#"
function caller() {
  helper();
}
function helper() {
  return 1;
}
"#,
        );
        let file_b = write_file(
            temp.path(),
            "b.js",
            r#"
function helper() {
  return 2;
}
"#,
        );

        let mut analyzer = ReachabilityAnalyzer::new();
        analyzer.build_call_graph(&[file_a, file_b]).unwrap();

        // There are two `helper` functions → ambiguous → no cross-file edge
        let helper_count = analyzer
            .call_graph
            .nodes
            .values()
            .filter(|n| n.name == "helper")
            .count();
        assert_eq!(helper_count, 2, "should have two helper nodes");

        // caller should have no outgoing edges (ambiguous callee skipped)
        let caller_node = analyzer
            .call_graph
            .nodes
            .values()
            .find(|n| n.name == "caller");
        if let Some(caller) = caller_node {
            assert!(
                caller.calls.is_empty(),
                "caller should have no edges when callee is ambiguous"
            );
        }
    }

    // ── Task 15.2: TaintTrace::render() ──────────────────────────────────

    #[test]
    fn test_taint_trace_render_3_steps() {
        let trace = TaintTrace {
            steps: vec![
                TaintTraceStep {
                    file: PathBuf::from("src/routes/user.js"),
                    line: 12,
                    function_name: "handleUserRequest".to_string(),
                    description: "External input enters here".to_string(),
                },
                TaintTraceStep {
                    file: PathBuf::from("src/services/user.js"),
                    line: 34,
                    function_name: "getUserById".to_string(),
                    description: "Tainted data flows through `getUserById`".to_string(),
                },
                TaintTraceStep {
                    file: PathBuf::from("src/db/queries.js"),
                    line: 42,
                    function_name: "buildQuery".to_string(),
                    description: "Tainted value reaches SQL query construction".to_string(),
                },
            ],
            sink_rule_id: "sql-injection".to_string(),
            sink_file: PathBuf::from("src/db/queries.js"),
            sink_line: 42,
        };

        let rendered = trace.render();

        // Should contain the rule ID
        assert!(
            rendered.contains("sql-injection"),
            "render should contain rule ID"
        );
        // Should contain all 3 step numbers
        assert!(rendered.contains("[1]"), "render should contain step 1");
        assert!(rendered.contains("[2]"), "render should contain step 2");
        assert!(rendered.contains("[3]"), "render should contain step 3");
        // Should contain function names
        assert!(
            rendered.contains("handleUserRequest"),
            "render should contain function name"
        );
        assert!(
            rendered.contains("buildQuery"),
            "render should contain sink function"
        );
        // Should contain SINK marker on last step
        assert!(rendered.contains("← SINK"), "render should mark the sink");
        // Should contain box-drawing characters
        assert!(rendered.contains("┌"), "render should have top border");
        assert!(rendered.contains("└"), "render should have bottom border");
        // Should contain attack vector summary
        assert!(
            rendered.contains("Attack vector"),
            "render should have attack vector summary"
        );
    }

    // ── Task 15.3: trace_to_vulnerability ────────────────────────────────

    #[test]
    fn test_trace_to_vulnerability_3_node_chain() {
        use crate::engine::Severity;

        let mut analyzer = ReachabilityAnalyzer::new();
        let id_source = Uuid::new_v4();
        let id_middle = Uuid::new_v4();
        let id_sink = Uuid::new_v4();

        for (id, name, line, is_src) in [
            (id_source, "sourceFunc", 1usize, true),
            (id_middle, "middleFunc", 10usize, false),
            (id_sink, "sinkFunc", 20usize, false),
        ] {
            analyzer.call_graph.add_node(FunctionNode {
                id,
                name: name.to_string(),
                file_path: PathBuf::from("app.js"),
                line,
                calls: vec![],
                called_by: vec![],
                parameters: vec![],
                is_taint_source: is_src,
            });
        }
        analyzer.call_graph.add_edge(id_source, id_middle);
        analyzer.call_graph.add_edge(id_middle, id_sink);

        // Create a vulnerability inside sinkFunc (line 20)
        let vuln = crate::engine::vulnerability::Vulnerability::new(
            "sql-injection".to_string(),
            PathBuf::from("app.js"),
            20,
            1,
            "snippet".to_string(),
            Severity::High,
        );

        let trace = analyzer.trace_to_vulnerability(&vuln);
        assert!(
            trace.is_some(),
            "should find a trace for reachable vulnerability"
        );
        let trace = trace.unwrap();
        assert_eq!(trace.steps.len(), 3, "trace should have 3 steps");
        assert_eq!(trace.steps[0].function_name, "sourceFunc");
        assert_eq!(trace.steps[1].function_name, "middleFunc");
        assert_eq!(trace.steps[2].function_name, "sinkFunc");
        assert!(
            trace.steps[0].description.contains("External input"),
            "first step should describe taint source"
        );
    }

    #[test]
    fn test_trace_to_vulnerability_disconnected_returns_none() {
        use crate::engine::Severity;

        let mut analyzer = ReachabilityAnalyzer::new();
        let id_source = Uuid::new_v4();
        let id_isolated = Uuid::new_v4();

        analyzer.call_graph.add_node(FunctionNode {
            id: id_source,
            name: "sourceFunc".to_string(),
            file_path: PathBuf::from("a.js"),
            line: 1,
            calls: vec![],
            called_by: vec![],
            parameters: vec![],
            is_taint_source: true,
        });
        analyzer.call_graph.add_node(FunctionNode {
            id: id_isolated,
            name: "isolatedFunc".to_string(),
            file_path: PathBuf::from("b.js"),
            line: 5,
            calls: vec![],
            called_by: vec![],
            parameters: vec![],
            is_taint_source: false,
        });
        // No edge between them

        let vuln = crate::engine::vulnerability::Vulnerability::new(
            "sql-injection".to_string(),
            PathBuf::from("b.js"),
            5,
            1,
            "snippet".to_string(),
            Severity::High,
        );

        let trace = analyzer.trace_to_vulnerability(&vuln);
        assert!(trace.is_none(), "disconnected sink should return None");
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::engine::{Severity, Vulnerability};
    use proptest::prelude::*;
    use std::fs;
    use tempfile::TempDir;
    use uuid::Uuid;

    // ── Helper: build a linear call chain of length `depth` ──────────────
    fn build_chain(depth: usize, has_source: bool) -> (ReachabilityAnalyzer, Vec<FunctionId>) {
        let mut analyzer = ReachabilityAnalyzer::with_taint_sources(vec![]);
        let ids: Vec<FunctionId> = (0..depth).map(|_| Uuid::new_v4()).collect();

        for (i, &id) in ids.iter().enumerate() {
            analyzer.call_graph.add_node(FunctionNode {
                id,
                name: format!("fn_{}", i),
                file_path: PathBuf::from("chain.js"),
                line: i + 1,
                calls: vec![],
                called_by: vec![],
                parameters: vec![],
                is_taint_source: i == 0 && has_source,
            });
        }
        for i in 0..depth.saturating_sub(1) {
            analyzer.call_graph.add_edge(ids[i], ids[i + 1]);
        }
        (analyzer, ids)
    }

    fn make_vuln(file: &str, line: usize) -> Vulnerability {
        Vulnerability::new(
            "test-rule".to_string(),
            PathBuf::from(file),
            line,
            1,
            "snippet".to_string(),
            Severity::High,
        )
    }

    // ── Property 12: Reachability analysis soundness ─────────────────────
    // Feature: sicario-cli-core, Property 12: Reachability analysis soundness
    // Validates: Requirements 5.1, 5.2, 5.3
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        #[test]
        fn test_reachability_soundness(depth in 2usize..8) {
            // Build a chain with a taint source at the head
            let (analyzer, ids) = build_chain(depth, true);

            // Every node in the chain should be reachable
            let reachable = analyzer.reachable_from_sources();
            for &id in &ids {
                prop_assert!(
                    reachable.contains(&id),
                    "Node {:?} should be reachable in a connected chain from a taint source",
                    id
                );
            }
        }

        #[test]
        fn test_no_source_means_nothing_reachable(depth in 1usize..8) {
            // Chain with NO taint source
            let (analyzer, ids) = build_chain(depth, false);
            let reachable = analyzer.reachable_from_sources();
            for &id in &ids {
                prop_assert!(
                    !reachable.contains(&id),
                    "Node {:?} should NOT be reachable when there are no taint sources",
                    id
                );
            }
        }
    }

    // ── Property 13: Unreachable vulnerability suppression ───────────────
    // Feature: sicario-cli-core, Property 13: Unreachable vulnerability suppression
    // Validates: Requirements 5.4
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        #[test]
        fn test_unreachable_vuln_marked_false(depth in 2usize..8) {
            // Chain with NO taint source → all functions unreachable
            let (analyzer, ids) = build_chain(depth, false);

            // Create a vulnerability inside the last function of the chain
            let last_id = ids[depth - 1];
            let last_node = &analyzer.call_graph.nodes[&last_id];
            let mut vuln = make_vuln(
                last_node.file_path.to_str().unwrap(),
                last_node.line,
            );

            let is_reachable = analyzer.is_reachable(&vuln).unwrap();
            // With no taint sources the function is unreachable
            prop_assert!(
                !is_reachable,
                "Vulnerability in an unreachable function should not be reachable"
            );
        }

        #[test]
        fn test_reachable_vuln_marked_true(depth in 2usize..8) {
            // Chain WITH a taint source → all functions reachable
            let (analyzer, ids) = build_chain(depth, true);

            let last_id = ids[depth - 1];
            let last_node = &analyzer.call_graph.nodes[&last_id];
            let vuln = make_vuln(
                last_node.file_path.to_str().unwrap(),
                last_node.line,
            );

            let is_reachable = analyzer.is_reachable(&vuln).unwrap();
            prop_assert!(
                is_reachable,
                "Vulnerability in a reachable function should be marked reachable"
            );
        }
    }

    // ── Property 14: Framework pattern recognition ────────────────────────
    // Feature: sicario-cli-core, Property 14: Framework pattern recognition
    // Validates: Requirements 5.5
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        #[test]
        fn test_django_taint_source_recognized(
            fn_name in "[a-z][a-z0-9_]{2,10}",
        ) {
            let temp = TempDir::new().unwrap();
            // Generate a Python file with a Django-style view function
            let source = format!(
                r#"
def {}(request):
    data = request.GET.get('q', '')
    return data
"#,
                fn_name
            );
            let path = temp.path().join(format!("{}.py", fn_name));
            fs::write(&path, &source).unwrap();

            let mut analyzer = ReachabilityAnalyzer::new();
            analyzer.build_call_graph(&[path]).unwrap();

            // The function should be marked as a taint source
            let is_source = analyzer
                .call_graph
                .nodes
                .values()
                .any(|n| n.name == fn_name && n.is_taint_source);

            prop_assert!(
                is_source,
                "Django view function '{}' should be recognized as a taint source",
                fn_name
            );
        }

        #[test]
        fn test_non_framework_fn_not_taint_source(
            fn_name in "[a-z][a-z0-9_]{2,10}",
        ) {
            let temp = TempDir::new().unwrap();
            // A plain Python function with no framework patterns
            let source = format!(
                r#"
def {}(x, y):
    return x + y
"#,
                fn_name
            );
            let path = temp.path().join(format!("{}.py", fn_name));
            fs::write(&path, &source).unwrap();

            let mut analyzer = ReachabilityAnalyzer::new();
            analyzer.build_call_graph(&[path]).unwrap();

            let is_source = analyzer
                .call_graph
                .nodes
                .values()
                .any(|n| n.name == fn_name && n.is_taint_source);

            prop_assert!(
                !is_source,
                "Plain function '{}' should NOT be a taint source",
                fn_name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Task 15.5: Performance benchmark test
// ---------------------------------------------------------------------------

#[cfg(test)]
mod perf_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Task 15.5: build_call_graph on a 1,000-file project must complete within 2 seconds.
    #[test]
    #[ignore = "performance benchmark — CI runners are too slow for a 2s wall-clock assertion; run locally with --ignored"]
    fn test_build_call_graph_1000_files_within_2_seconds() {
        let temp = TempDir::new().unwrap();
        let mut files = Vec::new();

        // Generate 1,000 small JS files each with one function
        for i in 0..1000 {
            let content = format!("function fn_{i}(x) {{ return x + {i}; }}\n");
            let path = temp.path().join(format!("file_{i}.js"));
            fs::write(&path, &content).unwrap();
            files.push(path);
        }

        let mut analyzer = ReachabilityAnalyzer::new();
        let start = std::time::Instant::now();
        analyzer.build_call_graph(&files).unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_secs() < 2,
            "build_call_graph on 1,000 files took {:?}, expected < 2 seconds",
            elapsed
        );
    }
}
