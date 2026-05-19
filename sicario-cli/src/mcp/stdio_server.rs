//! stdio-based MCP server for Kiro Power integration.
//!
//! Listens on stdin/stdout using JSON-RPC 2.0 over newline-delimited JSON.
//! All logging MUST go to stderr to avoid corrupting the JSON-RPC stream.
//!
//! Requirements: 6.1, 6.2, 6.3, 6.4, 6.5

use anyhow::{Context, Result};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{debug, error, info, warn};

use crate::engine::{SastEngine, Vulnerability};
use crate::mcp::assistant_memory::AssistantMemory;
use crate::mcp::protocol::{
    parse_request, serialize_error, serialize_response, JsonRpcError, McpMethod, McpResponse,
    McpResponsePayload,
};
use crate::mcp::security_guard::ShellExecutionGuard;
use std::collections::HashMap;

/// stdio-based MCP server for Kiro Power integration.
///
/// Reads JSON-RPC 2.0 requests from stdin (newline-delimited) and writes
/// responses to stdout. All logging goes to stderr.
pub struct StdioMcpServer {
    engine: Arc<Mutex<SastEngine>>,
    memory: Arc<AssistantMemory>,
    findings_cache: Arc<Mutex<HashMap<String, Vulnerability>>>,
}

impl StdioMcpServer {
    /// Create a new stdio MCP server.
    pub fn new(project_root: &Path, memory_db_path: &Path) -> Result<Self> {
        let engine = SastEngine::new(project_root)
            .context("Failed to initialise SAST engine for stdio MCP server")?;
        let memory = AssistantMemory::new(memory_db_path)
            .context("Failed to initialise Assistant Memory")?;

        Ok(Self {
            engine: Arc::new(Mutex::new(engine)),
            memory: Arc::new(memory),
            findings_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Start the stdio server loop.
    ///
    /// Blocks the calling thread and processes requests until stdin is closed
    /// or a fatal error occurs.
    pub fn run(&self) -> Result<()> {
        // CRITICAL: All logging MUST go to stderr
        info!("Sicario stdio MCP server starting...");

        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let reader = BufReader::new(stdin.lock());

        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) if l.trim().is_empty() => continue,
                Ok(l) => l,
                Err(e) => {
                    // Check for broken pipe (Kiro closed the connection)
                    if e.kind() == io::ErrorKind::BrokenPipe {
                        info!("Sicario MCP: stdin closed (broken pipe), exiting cleanly");
                        return Ok(());
                    }
                    error!("Sicario MCP: stdin read error: {}", e);
                    return Err(e.into());
                }
            };

            debug!("Sicario MCP: received request: {}", line);

            // Handle MCP protocol lifecycle messages (initialize, tools/list, etc.)
            // before falling through to the tool dispatcher.
            let response_str =
                if let Some(resp) = crate::mcp::kiro_tools::handle_mcp_lifecycle(&line) {
                    resp
                } else {
                    self.dispatch(&line)
                };

            // Notifications return an empty string sentinel — no response to write.
            if response_str.is_empty() {
                continue;
            }

            debug!("Sicario MCP: sending response: {}", response_str);

            // Write response to stdout with newline
            if let Err(e) = writeln!(stdout, "{}", response_str) {
                // Check for broken pipe
                if e.kind() == io::ErrorKind::BrokenPipe {
                    info!("Sicario MCP: stdout closed (broken pipe), exiting cleanly");
                    return Ok(());
                }
                error!("Sicario MCP: stdout write error: {}", e);
                return Err(e.into());
            }

            // Flush stdout to ensure the response is sent immediately
            if let Err(e) = stdout.flush() {
                if e.kind() == io::ErrorKind::BrokenPipe {
                    info!("Sicario MCP: stdout flush failed (broken pipe), exiting cleanly");
                    return Ok(());
                }
                error!("Sicario MCP: stdout flush error: {}", e);
                return Err(e.into());
            }
        }

        info!("Sicario MCP: stdin closed, exiting cleanly");
        Ok(())
    }

    /// Parse and dispatch a single JSON-RPC request.
    fn dispatch(&self, raw: &str) -> String {
        // Extract the request ID first so we can echo it back in error responses.
        // This must happen before full parsing so that even malformed requests
        // get a properly correlated error response (JSON-RPC 2.0 §5).
        let id = serde_json::from_str::<serde_json::Value>(raw)
            .ok()
            .and_then(|v| v.get("id").cloned());

        // Parse the request
        let request = match parse_request(raw) {
            Ok(r) => r,
            Err(e) => return serialize_error(id, e),
        };

        let method = request.method;

        // Dispatch to the appropriate handler
        self.handle_method(method, request.id)
    }

    /// Execute the MCP method and return the serialised response.
    fn handle_method(&self, method: McpMethod, id: Option<serde_json::Value>) -> String {
        match method {
            McpMethod::ScanFile { path } => self.handle_scan_file(path, id),
            McpMethod::ScanCode { code, language } => self.handle_scan_code(code, language, id),
            McpMethod::GetRules => self.handle_get_rules(id),
            McpMethod::GetAstNode {
                file_path,
                line_number,
            } => self.handle_get_ast_node(file_path, line_number, id),
            McpMethod::AnalyzeReachability {
                source_node,
                sink_node,
            } => self.handle_analyze_reachability(source_node, sink_node, id),
            McpMethod::ProposeSafeMutation {
                node_id,
                patched_syntax,
            } => self.handle_propose_safe_mutation(node_id, patched_syntax, id),
        }
    }

    /// Handle `scan_file` — scan a file at the given path.
    fn handle_scan_file(&self, path: String, id: Option<serde_json::Value>) -> String {
        // Path traversal protection: reject paths with ".."
        if path.contains("..") {
            return serialize_error(
                id,
                JsonRpcError::invalid_params(
                    "Path traversal detected: file paths cannot contain '..'",
                ),
            );
        }

        let file_path = PathBuf::from(&path);

        // Ensure the file exists and is a file (not a directory)
        if !file_path.exists() {
            return serialize_error(
                id,
                JsonRpcError::invalid_params(format!("File not found: {}", path)),
            );
        }

        if !file_path.is_file() {
            return serialize_error(
                id,
                JsonRpcError::invalid_params(format!("Path is not a file: {}", path)),
            );
        }

        let mut eng = match self.engine.lock() {
            Ok(e) => e,
            Err(_) => {
                return serialize_error(id, JsonRpcError::internal_error("Engine lock poisoned"));
            }
        };

        match eng.scan_file(&file_path) {
            Ok(vulns) => {
                // Filter out previously approved patterns via Assistant Memory
                let filtered = self.filter_approved(vulns);

                // Populate findings cache for remediation patches
                if let Ok(mut cache) = self.findings_cache.lock() {
                    for v in &filtered {
                        cache.insert(v.id.to_string(), v.clone());
                    }
                }

                let response = McpResponse {
                    id,
                    payload: McpResponsePayload::Vulnerabilities(filtered),
                };
                serialize_response(response)
            }
            Err(e) => serialize_error(id, JsonRpcError::internal_error(e.to_string())),
        }
    }

    /// Handle `scan_code` — write code to a temp file, scan it, then clean up.
    fn handle_scan_code(
        &self,
        code: String,
        language: String,
        id: Option<serde_json::Value>,
    ) -> String {
        // Determine file extension from language
        let ext = language_to_extension(&language);

        // Write to a temp file using std::env::temp_dir
        let tmp_path = std::env::temp_dir().join(format!(
            "sicario_mcp_{}.{}",
            uuid::Uuid::new_v4().simple(),
            ext
        ));

        if let Err(e) = std::fs::write(&tmp_path, code.as_bytes()) {
            return serialize_error(
                id,
                JsonRpcError::internal_error(format!("Failed to write temp file: {}", e)),
            );
        }

        let mut eng = match self.engine.lock() {
            Ok(e) => e,
            Err(_) => {
                let _ = std::fs::remove_file(&tmp_path);
                return serialize_error(id, JsonRpcError::internal_error("Engine lock poisoned"));
            }
        };

        let result = eng.scan_file(&tmp_path);
        // Clean up temp file regardless of outcome
        let _ = std::fs::remove_file(&tmp_path);

        match result {
            Ok(mut vulns) => {
                // Rewrite file_path to reflect the virtual code snippet origin
                for v in &mut vulns {
                    v.file_path = PathBuf::from(format!("<code>.{}", ext));
                }
                let filtered = self.filter_approved(vulns);

                // Populate findings cache for remediation patches
                if let Ok(mut cache) = self.findings_cache.lock() {
                    for v in &filtered {
                        cache.insert(v.id.to_string(), v.clone());
                    }
                }

                let response = McpResponse {
                    id,
                    payload: McpResponsePayload::Vulnerabilities(filtered),
                };
                serialize_response(response)
            }
            Err(e) => serialize_error(id, JsonRpcError::internal_error(e.to_string())),
        }
    }

    /// Handle `get_rules` — return all loaded security rules.
    fn handle_get_rules(&self, id: Option<serde_json::Value>) -> String {
        let eng = match self.engine.lock() {
            Ok(e) => e,
            Err(_) => {
                return serialize_error(id, JsonRpcError::internal_error("Engine lock poisoned"));
            }
        };

        let rules = eng.get_rules().to_vec();
        let response = McpResponse {
            id,
            payload: McpResponsePayload::Rules(rules),
        };
        serialize_response(response)
    }

    /// Handle `get_ast_node` — parse the file with tree-sitter and return the node at `line_number`.
    fn handle_get_ast_node(
        &self,
        file_path: String,
        line_number: usize,
        id: Option<serde_json::Value>,
    ) -> String {
        // Path traversal protection
        if file_path.contains("..") {
            return serialize_error(
                id,
                JsonRpcError::invalid_params(
                    "Path traversal detected: file paths cannot contain '..'",
                ),
            );
        }

        let path = Path::new(&file_path);

        // Read the file
        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                return serialize_error(
                    id,
                    JsonRpcError::internal_error(format!(
                        "Failed to read file '{}': {}",
                        file_path, e
                    )),
                );
            }
        };

        // Detect language from extension
        let ts_language = match path.extension().and_then(|e| e.to_str()) {
            Some("js") | Some("mjs") | Some("cjs") => tree_sitter_javascript::language(),
            Some("ts") | Some("tsx") => tree_sitter_typescript::language_typescript(),
            Some("py") => tree_sitter_python::language(),
            Some("rs") => tree_sitter_rust::language(),
            Some("go") => tree_sitter_go::language(),
            Some("java") => tree_sitter_java::language(),
            _ => {
                return serialize_error(
                    id,
                    JsonRpcError::internal_error(format!(
                        "Unsupported file extension for AST parsing: '{}'",
                        file_path
                    )),
                );
            }
        };

        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&ts_language).is_err() {
            return serialize_error(
                id,
                JsonRpcError::internal_error("Failed to initialise tree-sitter parser"),
            );
        }

        let tree = match parser.parse(&source, None) {
            Some(t) => t,
            None => {
                return serialize_error(
                    id,
                    JsonRpcError::internal_error(format!("Failed to parse file '{}'", file_path)),
                );
            }
        };

        // line_number is 1-indexed; tree-sitter uses 0-indexed rows
        if line_number == 0 {
            return serialize_error(id, JsonRpcError::invalid_params("line_number must be >= 1"));
        }
        let row = line_number - 1;

        let root = tree.root_node();
        let node = root.descendant_for_point_range(
            tree_sitter::Point { row, column: 0 },
            tree_sitter::Point {
                row,
                column: usize::MAX,
            },
        );

        let node = match node {
            Some(n) => n,
            None => {
                return serialize_error(
                    id,
                    JsonRpcError::internal_error(format!(
                        "No AST node found at line {} in '{}'",
                        line_number, file_path
                    )),
                );
            }
        };

        let node_text = node
            .utf8_text(source.as_bytes())
            .unwrap_or("")
            .chars()
            .take(500)
            .collect::<String>();

        let result = crate::mcp::protocol::AstNodeResult {
            file_path,
            line_number,
            node_type: node.kind().to_string(),
            node_text,
            start_line: node.start_position().row + 1,
            end_line: node.end_position().row + 1,
        };

        let response = McpResponse {
            id,
            payload: McpResponsePayload::AstNode(result),
        };
        serialize_response(response)
    }

    /// Handle `analyze_reachability` — best-effort reachability check between two named functions.
    fn handle_analyze_reachability(
        &self,
        source_node: String,
        sink_node: String,
        id: Option<serde_json::Value>,
    ) -> String {
        use crate::engine::reachability::ReachabilityAnalyzer;

        let analyzer = ReachabilityAnalyzer::new();

        // Check if both nodes exist in the call graph
        let source_exists = analyzer
            .call_graph
            .nodes
            .values()
            .any(|n| n.name == source_node);
        let sink_exists = analyzer
            .call_graph
            .nodes
            .values()
            .any(|n| n.name == sink_node);

        let (is_reachable, path) = if source_exists && sink_exists {
            // Find source and sink IDs and check reachability
            let source_id = analyzer
                .call_graph
                .nodes
                .values()
                .find(|n| n.name == source_node)
                .map(|n| n.id);
            let sink_id = analyzer
                .call_graph
                .nodes
                .values()
                .find(|n| n.name == sink_node)
                .map(|n| n.id);

            if let (Some(src), Some(snk)) = (source_id, sink_id) {
                // Use BFS to find reachability path
                let path_ids = analyzer
                    .call_graph
                    .nodes
                    .get(&src)
                    .map(|_| {
                        // Simple BFS
                        let mut visited = std::collections::HashSet::new();
                        let mut queue = std::collections::VecDeque::new();
                        let mut parent: std::collections::HashMap<uuid::Uuid, uuid::Uuid> =
                            std::collections::HashMap::new();
                        visited.insert(src);
                        queue.push_back(src);
                        let mut found = false;
                        while let Some(cur) = queue.pop_front() {
                            if cur == snk {
                                found = true;
                                break;
                            }
                            if let Some(node) = analyzer.call_graph.nodes.get(&cur) {
                                for &callee in &node.calls {
                                    if visited.insert(callee) {
                                        parent.insert(callee, cur);
                                        queue.push_back(callee);
                                    }
                                }
                            }
                        }
                        if found {
                            // Reconstruct path
                            let mut path = vec![snk];
                            let mut cur = snk;
                            while let Some(&p) = parent.get(&cur) {
                                path.push(p);
                                cur = p;
                            }
                            path.reverse();
                            path
                        } else {
                            vec![]
                        }
                    })
                    .unwrap_or_default();

                let is_reachable = !path_ids.is_empty();
                let path_names: Vec<String> = path_ids
                    .iter()
                    .filter_map(|id| analyzer.call_graph.nodes.get(id))
                    .map(|n| n.name.clone())
                    .collect();
                (is_reachable, path_names)
            } else {
                (false, vec![])
            }
        } else {
            // No call graph data available
            (false, vec![])
        };

        let result = crate::mcp::protocol::ReachabilityResult {
            source_node,
            sink_node,
            is_reachable,
            path,
        };

        let response = McpResponse {
            id,
            payload: McpResponsePayload::ReachabilityResult(result),
        };
        serialize_response(response)
    }

    /// Handle `propose_safe_mutation` — queue a patch for developer review.
    fn handle_propose_safe_mutation(
        &self,
        node_id: String,
        patched_syntax: String,
        id: Option<serde_json::Value>,
    ) -> String {
        // Security guardrail: reject dangerous shell execution patterns
        if let Err(msg) = ShellExecutionGuard::validate_mutation(&patched_syntax) {
            return serialize_error(id, JsonRpcError::invalid_params(msg));
        }

        // Audit log — never write to files
        info!(
            "MCP propose_safe_mutation: node_id='{}' queued for developer review",
            node_id
        );

        let proposal = crate::mcp::protocol::MutationProposal {
            node_id: node_id.clone(),
            patched_syntax,
            status: "queued".to_string(),
            message: format!(
                "Patch queued for developer review. Run `sicario fix --id={}` to apply.",
                node_id
            ),
        };

        let response = McpResponse {
            id,
            payload: McpResponsePayload::MutationProposal(proposal),
        };
        serialize_response(response)
    }

    /// Filter out vulnerabilities whose patterns have been previously approved.
    fn filter_approved(
        &self,
        vulns: Vec<crate::engine::Vulnerability>,
    ) -> Vec<crate::engine::Vulnerability> {
        vulns
            .into_iter()
            .filter(|v| !self.memory.is_approved(&v.rule_id, &v.snippet))
            .collect()
    }
}

/// Map a language name to a file extension.
fn language_to_extension(language: &str) -> &'static str {
    match language.to_lowercase().as_str() {
        "javascript" | "js" => "js",
        "typescript" | "ts" => "ts",
        "python" | "py" => "py",
        "rust" | "rs" => "rs",
        "go" => "go",
        "java" => "java",
        _ => "js", // default to JS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_server(dir: &Path) -> StdioMcpServer {
        let mem_path = dir.join("memory.db");
        StdioMcpServer::new(dir, &mem_path).unwrap()
    }

    #[test]
    fn test_language_to_extension() {
        assert_eq!(language_to_extension("javascript"), "js");
        assert_eq!(language_to_extension("TypeScript"), "ts");
        assert_eq!(language_to_extension("python"), "py");
        assert_eq!(language_to_extension("rust"), "rs");
        assert_eq!(language_to_extension("go"), "go");
        assert_eq!(language_to_extension("java"), "java");
        assert_eq!(language_to_extension("unknown"), "js");
    }

    #[test]
    fn test_server_creation() {
        let dir = TempDir::new().unwrap();
        let server = make_server(dir.path());
        // Engine and memory should be accessible
        assert!(server.engine.lock().is_ok());
    }

    #[test]
    fn test_dispatch_get_rules_no_rules_loaded() {
        let dir = TempDir::new().unwrap();
        let server = make_server(dir.path());
        let raw = r#"{"jsonrpc":"2.0","method":"get_rules","params":{},"id":1}"#;
        let resp = server.dispatch(raw);
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert!(v["result"].is_array());
        assert_eq!(v["result"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_dispatch_unknown_method() {
        let dir = TempDir::new().unwrap();
        let server = make_server(dir.path());
        let raw = r#"{"jsonrpc":"2.0","method":"nonexistent","params":{},"id":2}"#;
        let resp = server.dispatch(raw);
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert!(v["error"].is_object());
        assert_eq!(v["error"]["code"], JsonRpcError::METHOD_NOT_FOUND);
    }

    #[test]
    fn test_dispatch_scan_file_path_traversal() {
        let dir = TempDir::new().unwrap();
        let server = make_server(dir.path());
        let raw =
            r#"{"jsonrpc":"2.0","method":"scan_file","params":{"path":"../../etc/shadow"},"id":3}"#;
        let resp = server.dispatch(raw);
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert!(v["error"].is_object());
        assert_eq!(v["error"]["code"], JsonRpcError::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Path traversal"));
    }

    #[test]
    fn test_dispatch_scan_code_javascript() {
        let dir = TempDir::new().unwrap();
        let server = make_server(dir.path());
        let raw = r#"{"jsonrpc":"2.0","method":"scan_code","params":{"code":"const x = 1;","language":"javascript"},"id":4}"#;
        let resp = server.dispatch(raw);
        let v: serde_json::Value = serde_json::from_str(&resp).unwrap();
        // No rules loaded, so result should be an empty array
        assert_eq!(v["jsonrpc"], "2.0");
        assert!(v["result"].is_array());
    }
}
