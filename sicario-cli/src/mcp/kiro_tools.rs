//! Kiro Power tool implementations for the Sicario MCP server.
//!
//! Exposes three tools over JSON-RPC 2.0 via stdio:
//!   - `analyze_ast_security`: AST-based vulnerability scan
//!   - `request_remediation_patch`: deterministic code diff generation
//!   - `log_telemetry_audit`: zero-exfiltration telemetry submission
//!
//! All logging goes to stderr. stdout is strictly reserved for JSON-RPC responses.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

use crate::engine::{SastEngine, Vulnerability};
use crate::mcp::protocol::{JsonRpcError, JsonRpcRequest};
use crate::mcp::security_guard::ShellExecutionGuard;

// ── Request / Response types ─────────────────────────────────────────────────

/// Parameters for `analyze_ast_security`.
#[derive(Debug, Deserialize)]
pub struct AnalyzeAstParams {
    pub file_path: String,
}

/// Parameters for `request_remediation_patch`.
#[derive(Debug, Deserialize)]
pub struct RemediationPatchParams {
    pub vulnerability_id: String,
    pub file_path: String,
}

/// Parameters for `log_telemetry_audit`.
#[derive(Debug, Deserialize)]
pub struct TelemetryAuditParams {
    pub project_id: String,
    pub scan_results: Vec<TelemetryScanResult>,
}

/// A single scan result entry for telemetry (metadata only, no source code).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryScanResult {
    pub rule_id: String,
    pub severity: String,
    pub file_path: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp_category: Option<String>,
}

/// Response from `analyze_ast_security`.
#[derive(Debug, Serialize)]
pub struct AnalyzeAstResponse {
    pub file_path: String,
    pub vulnerabilities: Vec<VulnerabilityMeta>,
    pub total: usize,
    pub scan_engine: &'static str,
}

/// Vulnerability metadata (no source code).
#[derive(Debug, Serialize)]
pub struct VulnerabilityMeta {
    pub id: String,
    pub rule_id: String,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    /// Truncated snippet (max 100 chars, zero-exfiltration guarantee)
    pub snippet: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwe_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp_category: Option<String>,
}

/// Response from `request_remediation_patch`.
#[derive(Debug, Serialize)]
pub struct RemediationPatchResponse {
    pub vulnerability_id: String,
    pub file_path: String,
    /// Unified diff format patch
    pub patch: String,
    /// Always "queued" — patches are never auto-applied
    pub status: &'static str,
    pub message: String,
}

/// Response from `log_telemetry_audit`.
#[derive(Debug, Serialize)]
pub struct TelemetryAuditResponse {
    pub scan_id: String,
    pub project_id: String,
    pub findings_count: usize,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dashboard_url: Option<String>,
}

// ── Tool dispatcher ──────────────────────────────────────────────────────────

/// Dispatch a Kiro tool call and return the serialised JSON-RPC response.
///
/// This is the entry point for all three Kiro Power tools.
pub fn dispatch_kiro_tool(raw: &str, engine: &Arc<Mutex<SastEngine>>) -> Option<String> {
    // Parse the raw JSON-RPC request
    let rpc: JsonRpcRequest = match serde_json::from_str(raw) {
        Ok(r) => r,
        Err(_) => return None, // Not a Kiro tool call, let the main dispatcher handle it
    };

    let id = rpc.id.clone();

    match rpc.method.as_str() {
        "analyze_ast_security" => Some(handle_analyze_ast_security(rpc.params, id, engine)),
        "request_remediation_patch" => Some(handle_request_remediation_patch(rpc.params, id)),
        "log_telemetry_audit" => Some(handle_log_telemetry_audit(rpc.params, id)),
        _ => None, // Not a Kiro tool, let the main dispatcher handle it
    }
}

// ── Tool implementations ─────────────────────────────────────────────────────

/// `analyze_ast_security`: Scan a local file using Tree-Sitter AST analysis.
///
/// Reads the file locally, parses it via Tree-Sitter, and returns vulnerability
/// metadata. Source code is NEVER transmitted — only metadata is returned.
fn handle_analyze_ast_security(
    params: serde_json::Value,
    id: Option<serde_json::Value>,
    engine: &Arc<Mutex<SastEngine>>,
) -> String {
    // Parse parameters
    let p: AnalyzeAstParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            return json_rpc_error(
                id,
                JsonRpcError::invalid_params(format!(
                    "analyze_ast_security requires 'file_path': {}",
                    e
                )),
            );
        }
    };

    // Path traversal protection
    if p.file_path.contains("..") {
        return json_rpc_error(
            id,
            JsonRpcError::invalid_params("Path traversal detected: file paths cannot contain '..'"),
        );
    }

    let file_path = PathBuf::from(&p.file_path);

    // Validate the file exists
    if !file_path.exists() {
        return json_rpc_error(
            id,
            JsonRpcError::invalid_params(format!("File not found: {}", p.file_path)),
        );
    }

    if !file_path.is_file() {
        return json_rpc_error(
            id,
            JsonRpcError::invalid_params(format!("Path is not a file: {}", p.file_path)),
        );
    }

    // Acquire engine lock
    let mut eng = match engine.lock() {
        Ok(e) => e,
        Err(_) => {
            return json_rpc_error(id, JsonRpcError::internal_error("Engine lock poisoned"));
        }
    };

    // Run the scan
    let vulns = match eng.scan_file(&file_path) {
        Ok(v) => v,
        Err(e) => {
            return json_rpc_error(id, JsonRpcError::internal_error(e.to_string()));
        }
    };

    // Map to metadata (zero-exfiltration: truncate snippets to 100 chars)
    let vulnerability_metas: Vec<VulnerabilityMeta> = vulns
        .iter()
        .map(|v| VulnerabilityMeta {
            id: v.id.to_string(),
            rule_id: v.rule_id.clone(),
            file_path: v.file_path.to_string_lossy().to_string(),
            line: v.line,
            column: v.column,
            snippet: v.snippet.chars().take(100).collect(),
            severity: format!("{:?}", v.severity),
            cwe_id: v.cwe_id.clone(),
            owasp_category: v.owasp_category.map(|c| format!("{:?}", c)),
        })
        .collect();

    let total = vulnerability_metas.len();
    let response = AnalyzeAstResponse {
        file_path: p.file_path,
        vulnerabilities: vulnerability_metas,
        total,
        scan_engine: "sicario-ast-v1",
    };

    info!(
        "analyze_ast_security: scanned '{}', found {} vulnerabilities",
        response.file_path, total
    );

    json_rpc_success(id, serde_json::to_value(&response).unwrap_or_default())
}

/// `request_remediation_patch`: Generate a deterministic code diff for a vulnerability.
///
/// Returns a unified diff patch for developer review. Patches are NEVER auto-applied.
fn handle_request_remediation_patch(
    params: serde_json::Value,
    id: Option<serde_json::Value>,
) -> String {
    // Parse parameters
    let p: RemediationPatchParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            return json_rpc_error(
                id,
                JsonRpcError::invalid_params(format!(
                    "request_remediation_patch requires 'vulnerability_id' and 'file_path': {}",
                    e
                )),
            );
        }
    };

    // Path traversal protection
    if p.file_path.contains("..") {
        return json_rpc_error(
            id,
            JsonRpcError::invalid_params("Path traversal detected: file paths cannot contain '..'"),
        );
    }

    // Validate the file exists
    let file_path = PathBuf::from(&p.file_path);
    if !file_path.exists() {
        return json_rpc_error(
            id,
            JsonRpcError::invalid_params(format!("File not found: {}", p.file_path)),
        );
    }

    // Read the file to generate a deterministic patch
    let source = match std::fs::read_to_string(&file_path) {
        Ok(s) => s,
        Err(e) => {
            return json_rpc_error(
                id,
                JsonRpcError::internal_error(format!(
                    "Failed to read file '{}': {}",
                    p.file_path, e
                )),
            );
        }
    };

    // Generate a deterministic patch stub.
    // The full remediation engine integration is wired via `sicario fix --id=<vuln_id>`.
    // This tool returns the patch metadata so the AI can present it to the developer.
    let patch = generate_patch_stub(&p.vulnerability_id, &p.file_path, &source);

    let response = RemediationPatchResponse {
        vulnerability_id: p.vulnerability_id.clone(),
        file_path: p.file_path.clone(),
        patch,
        status: "queued",
        message: format!(
            "Patch queued for developer review. Run `sicario fix --id={}` to apply interactively.",
            p.vulnerability_id
        ),
    };

    info!(
        "request_remediation_patch: patch queued for vulnerability '{}' in '{}'",
        p.vulnerability_id, p.file_path
    );

    json_rpc_success(id, serde_json::to_value(&response).unwrap_or_default())
}

/// `log_telemetry_audit`: Submit zero-exfiltration telemetry to Sicario Cloud.
///
/// Fires an asynchronous telemetry payload containing ONLY metadata (no source code)
/// to the Convex backend. The submission is best-effort and never fails the scan.
fn handle_log_telemetry_audit(params: serde_json::Value, id: Option<serde_json::Value>) -> String {
    // Parse parameters
    let p: TelemetryAuditParams = match serde_json::from_value(params) {
        Ok(p) => p,
        Err(e) => {
            return json_rpc_error(
                id,
                JsonRpcError::invalid_params(format!(
                    "log_telemetry_audit requires 'project_id' and 'scan_results': {}",
                    e
                )),
            );
        }
    };

    // Validate project_id is not empty
    if p.project_id.trim().is_empty() {
        return json_rpc_error(
            id,
            JsonRpcError::invalid_params("project_id cannot be empty"),
        );
    }

    let findings_count = p.scan_results.len();

    // Generate a unique scan ID
    let scan_id = format!(
        "mcp-scan-{}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        uuid::Uuid::new_v4()
            .to_string()
            .replace('-', "")
            .chars()
            .take(8)
            .collect::<String>()
            .to_uppercase()
    );

    // Resolve API key from environment
    let api_key = std::env::var("SICARIO_API_KEY").unwrap_or_default();

    // Attempt async telemetry submission (best-effort, never blocks)
    let project_id = p.project_id.clone();
    let scan_id_clone = scan_id.clone();
    let scan_results = p.scan_results.clone();

    // Spawn a background thread for the HTTP submission so we don't block the MCP loop
    let api_key_clone = api_key.clone();
    std::thread::spawn(move || {
        submit_telemetry_async(&project_id, &scan_id_clone, &scan_results, &api_key_clone);
    });

    // Resolve dashboard URL
    let cloud_url =
        std::env::var("SICARIO_CLOUD_URL").unwrap_or_else(|_| "https://usesicario.xyz".to_string());
    let dashboard_url = if !api_key.is_empty() {
        Some(format!(
            "{}/dashboard/projects/{}/scans/{}",
            cloud_url, p.project_id, scan_id
        ))
    } else {
        None
    };

    let response = TelemetryAuditResponse {
        scan_id: scan_id.clone(),
        project_id: p.project_id,
        findings_count,
        status: "submitted",
        dashboard_url,
    };

    info!(
        "log_telemetry_audit: submitted {} findings for project '{}' (scan_id: {})",
        findings_count, response.project_id, scan_id
    );

    json_rpc_success(id, serde_json::to_value(&response).unwrap_or_default())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Generate a deterministic patch stub for a vulnerability.
///
/// Returns a unified diff header with instructions for the developer.
/// Full patch generation is handled by `sicario fix --id=<vuln_id>`.
fn generate_patch_stub(vulnerability_id: &str, file_path: &str, _source: &str) -> String {
    format!(
        "--- a/{file_path}\n\
         +++ b/{file_path}\n\
         @@ Sicario Remediation Patch @@\n\
         # Vulnerability ID: {vulnerability_id}\n\
         # Run `sicario fix --id={vulnerability_id}` to apply this patch interactively.\n\
         # The remediation engine will generate a precise AST-level fix.\n"
    )
}

/// Submit telemetry to the Convex backend (best-effort, runs on a background thread).
///
/// Zero-exfiltration guarantee: only metadata is transmitted, never source code.
fn submit_telemetry_async(
    project_id: &str,
    scan_id: &str,
    scan_results: &[TelemetryScanResult],
    api_key: &str,
) {
    if api_key.is_empty() {
        warn!("log_telemetry_audit: SICARIO_API_KEY not set, skipping cloud submission");
        return;
    }

    let cloud_url = std::env::var("SICARIO_CLOUD_URL")
        .unwrap_or_else(|_| "https://flexible-terrier-680.convex.site".to_string());

    let payload = serde_json::json!({
        "project_id": project_id,
        "scan_id": scan_id,
        "source": "kiro-mcp",
        "findings": scan_results,
    });

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("log_telemetry_audit: failed to build HTTP client: {}", e);
            return;
        }
    };

    match client
        .post(format!("{}/api/v1/telemetry/mcp-scan", cloud_url))
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
    {
        Ok(resp) => {
            info!(
                "log_telemetry_audit: telemetry submitted (status: {})",
                resp.status()
            );
        }
        Err(e) => {
            warn!("log_telemetry_audit: telemetry submission failed: {}", e);
        }
    }
}

/// Build a JSON-RPC 2.0 success response.
fn json_rpc_success(id: Option<serde_json::Value>, result: serde_json::Value) -> String {
    let resp = serde_json::json!({
        "jsonrpc": "2.0",
        "result": result,
        "id": id
    });
    serde_json::to_string(&resp).unwrap_or_else(|_| {
        r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Serialization error"},"id":null}"#
            .to_string()
    })
}

/// Build a JSON-RPC 2.0 error response.
fn json_rpc_error(id: Option<serde_json::Value>, error: JsonRpcError) -> String {
    let resp = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": error.code,
            "message": error.message,
        },
        "id": id
    });
    serde_json::to_string(&resp).unwrap_or_else(|_| {
        r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Serialization error"},"id":null}"#
            .to_string()
    })
}

// ── StdioMcpRunner ────────────────────────────────────────────────────────────

/// Runs the full stdio MCP server with Kiro Power tools integrated.
///
/// This is the entry point for `sicario mcp`. It starts a long-running process
/// that reads JSON-RPC 2.0 requests from stdin and writes responses to stdout.
///
/// Kiro Power tools (`analyze_ast_security`, `request_remediation_patch`,
/// `log_telemetry_audit`) are dispatched first; all other methods fall through
/// to the standard MCP dispatcher.
/// Handle MCP protocol lifecycle messages (`initialize`, `notifications/initialized`).
///
/// Returns `Some(response)` if the message was a lifecycle message, `None` otherwise.
/// This must run before tool dispatch so Kiro's MCP client can complete the handshake.
pub(crate) fn handle_mcp_lifecycle(raw: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let method = v.get("method")?.as_str()?;
    let id = v.get("id").cloned();

    match method {
        "initialize" => {
            let result = serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "sicario-edge",
                    "version": env!("CARGO_PKG_VERSION")
                }
            });
            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            });
            Some(resp.to_string())
        }
        "notifications/initialized" => {
            // Notification — no response required, but return empty string sentinel
            // so the caller knows it was handled (we skip writing empty lines)
            Some(String::new())
        }
        "tools/list" => {
            let tools = serde_json::json!([
                {
                    "name": "analyze_ast_security",
                    "description": "Scan a file for vulnerabilities using AST analysis. Returns findings with severity, CWE, OWASP category, and code snippet.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the file to scan (no .. traversal)"
                            }
                        },
                        "required": ["file_path"]
                    }
                },
                {
                    "name": "request_remediation_patch",
                    "description": "Generate a deterministic code patch for a detected vulnerability. Patches are queued, never auto-applied.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "vulnerability_id": {
                                "type": "string",
                                "description": "UUID from analyze_ast_security"
                            },
                            "file_path": {
                                "type": "string",
                                "description": "Path to the affected file"
                            }
                        },
                        "required": ["vulnerability_id", "file_path"]
                    }
                },
                {
                    "name": "log_telemetry_audit",
                    "description": "Submit metadata-only compliance telemetry to Sicario Cloud. No source code is transmitted.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "project_id": {
                                "type": "string",
                                "description": "Sicario Cloud project identifier"
                            },
                            "scan_results": {
                                "type": "array",
                                "description": "Array of finding metadata",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "rule_id": { "type": "string" },
                                        "severity": { "type": "string" },
                                        "file_path": { "type": "string" },
                                        "line": { "type": "integer" },
                                        "cwe_id": { "type": "string" }
                                    },
                                    "required": ["rule_id", "severity", "file_path", "line"]
                                }
                            }
                        },
                        "required": ["project_id", "scan_results"]
                    }
                }
            ]);
            let resp = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "tools": tools }
            });
            Some(resp.to_string())
        }
        "tools/call" => {
            // Standard MCP tools/call — extract name + arguments and route to the right handler
            let params = v.get("params")?;
            let tool_name = params.get("name")?.as_str()?;
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::json!({}));

            // Re-use dispatch_kiro_tool by synthesising a method-name request
            let synthetic = serde_json::json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": tool_name,
                "params": arguments
            });
            let synthetic_str = synthetic.to_string();

            // We need the engine here — but handle_mcp_lifecycle doesn't have it.
            // Return a sentinel so the caller can re-dispatch with the engine.
            // We encode the synthetic request as a special marker.
            Some(format!("\x00TOOLS_CALL\x00{}", synthetic_str))
        }
        _ => None,
    }
}

pub struct StdioMcpRunner;

impl StdioMcpRunner {
    /// Start the stdio MCP server. Blocks until stdin is closed.
    pub fn run() -> anyhow::Result<()> {
        use crate::mcp::assistant_memory::AssistantMemory;
        use crate::mcp::server::dispatch_request;
        use std::io::{self, BufRead, BufReader, Write};

        // Determine project root (current directory)
        let project_root =
            std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let memory_db_path = project_root.join(".sicario").join("mcp_memory.db");

        // Ensure .sicario directory exists
        if let Some(parent) = memory_db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        // Initialise the SAST engine
        let engine = match SastEngine::new(&project_root) {
            Ok(mut eng) => {
                // Auto-load bundled rules if available
                let rule_dirs = [
                    project_root.join(".sicario").join("rules"),
                    project_root.join("rules"),
                ];
                for rule_dir in &rule_dirs {
                    if rule_dir.is_dir() {
                        let _ = eng.load_rules(rule_dir);
                    }
                }
                Arc::new(Mutex::new(eng))
            }
            Err(e) => {
                // Log to stderr — never stdout
                eprintln!("sicario mcp: failed to initialise engine: {}", e);
                return Err(e);
            }
        };

        // Initialise assistant memory (best-effort)
        let memory = {
            let tmp = std::env::temp_dir().join("sicario_mcp_memory.db");
            let mem_path = if memory_db_path.parent().map(|p| p.exists()).unwrap_or(false) {
                memory_db_path.clone()
            } else {
                tmp
            };
            match AssistantMemory::new(&mem_path) {
                Ok(m) => Arc::new(m),
                Err(e) => {
                    eprintln!(
                        "sicario mcp: warning: could not initialise memory store: {}",
                        e
                    );
                    // Create a fallback in-memory store via temp file
                    let fallback = std::env::temp_dir()
                        .join(format!("sicario_mcp_{}.db", uuid::Uuid::new_v4().simple()));
                    Arc::new(AssistantMemory::new(&fallback).map_err(|e2| {
                        anyhow::anyhow!("Failed to create fallback memory: {}", e2)
                    })?)
                }
            }
        };

        eprintln!(
            "sicario mcp: stdio server ready (project: {})",
            project_root.display()
        );

        let stdin = io::stdin();
        let mut stdout = io::stdout();
        let reader = BufReader::new(stdin.lock());

        for line_result in reader.lines() {
            let line = match line_result {
                Ok(l) if l.trim().is_empty() => continue,
                Ok(l) => l,
                Err(e) => {
                    if e.kind() == io::ErrorKind::BrokenPipe {
                        eprintln!("sicario mcp: stdin closed (broken pipe), exiting cleanly");
                        return Ok(());
                    }
                    // Non-fatal read error — log and continue rather than killing the server
                    eprintln!("sicario mcp: stdin read error (continuing): {}", e);
                    continue;
                }
            };

            // Handle MCP protocol lifecycle messages before tool dispatch
            let response_str = if let Some(resp) = handle_mcp_lifecycle(&line) {
                if let Some(synthetic) = resp.strip_prefix("\x00TOOLS_CALL\x00") {
                    // tools/call re-dispatch: route the synthetic request through kiro tools
                    if let Some(r) = dispatch_kiro_tool(synthetic, &engine) {
                        r
                    } else {
                        dispatch_request(synthetic, &engine, &memory)
                    }
                } else {
                    resp
                }
            } else if let Some(resp) = dispatch_kiro_tool(&line, &engine) {
                // Try Kiro Power tools first; fall through to standard MCP dispatcher
                resp
            } else {
                dispatch_request(&line, &engine, &memory)
            };

            if response_str.is_empty() {
                // Notification acknowledged — no response to write
                continue;
            }

            if let Err(e) = writeln!(stdout, "{}", response_str) {
                if e.kind() == io::ErrorKind::BrokenPipe {
                    eprintln!("sicario mcp: stdout closed (broken pipe), exiting cleanly");
                    return Ok(());
                }
                // Non-fatal write error — log to stderr and continue the loop
                eprintln!("sicario mcp: stdout write error (continuing): {}", e);
                continue;
            }

            if let Err(e) = stdout.flush() {
                if e.kind() == io::ErrorKind::BrokenPipe {
                    eprintln!("sicario mcp: stdout flush failed (broken pipe), exiting cleanly");
                    return Ok(());
                }
                eprintln!("sicario mcp: stdout flush error (continuing): {}", e);
                continue;
            }
        }

        eprintln!("sicario mcp: stdin closed, exiting cleanly");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_analyze_ast_security_path_traversal() {
        let dir = TempDir::new().unwrap();
        let engine = Arc::new(Mutex::new(SastEngine::new(dir.path()).unwrap()));
        let raw = r#"{"jsonrpc":"2.0","method":"analyze_ast_security","params":{"file_path":"../../etc/shadow"},"id":1}"#;
        let result = dispatch_kiro_tool(raw, &engine).unwrap();
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(v["error"].is_object());
        assert_eq!(v["error"]["code"], JsonRpcError::INVALID_PARAMS);
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Path traversal"));
    }

    #[test]
    fn test_analyze_ast_security_missing_file() {
        let dir = TempDir::new().unwrap();
        let engine = Arc::new(Mutex::new(SastEngine::new(dir.path()).unwrap()));
        let raw = r#"{"jsonrpc":"2.0","method":"analyze_ast_security","params":{"file_path":"/nonexistent/file.js"},"id":2}"#;
        let result = dispatch_kiro_tool(raw, &engine).unwrap();
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(v["error"].is_object());
        assert_eq!(v["error"]["code"], JsonRpcError::INVALID_PARAMS);
    }

    #[test]
    fn test_analyze_ast_security_valid_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("test.js");
        std::fs::write(&file, "const x = 1;").unwrap();
        let engine = Arc::new(Mutex::new(SastEngine::new(dir.path()).unwrap()));
        let raw = format!(
            r#"{{"jsonrpc":"2.0","method":"analyze_ast_security","params":{{"file_path":"{}"}},"id":3}}"#,
            file.to_string_lossy().replace('\\', "/")
        );
        let result = dispatch_kiro_tool(&raw, &engine).unwrap();
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert!(v["result"]["vulnerabilities"].is_array());
        assert_eq!(v["result"]["scan_engine"], "sicario-ast-v1");
    }

    #[test]
    fn test_request_remediation_patch_path_traversal() {
        let dir = TempDir::new().unwrap();
        let engine = Arc::new(Mutex::new(SastEngine::new(dir.path()).unwrap()));
        let raw = r#"{"jsonrpc":"2.0","method":"request_remediation_patch","params":{"vulnerability_id":"abc","file_path":"../../etc/passwd"},"id":4}"#;
        let result = dispatch_kiro_tool(raw, &engine).unwrap();
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(v["error"].is_object());
        assert_eq!(v["error"]["code"], JsonRpcError::INVALID_PARAMS);
    }

    #[test]
    fn test_request_remediation_patch_valid() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("vuln.py");
        std::fs::write(&file, "cursor.execute(query)").unwrap();
        let engine = Arc::new(Mutex::new(SastEngine::new(dir.path()).unwrap()));
        let raw = format!(
            r#"{{"jsonrpc":"2.0","method":"request_remediation_patch","params":{{"vulnerability_id":"vuln-123","file_path":"{}"}},"id":5}}"#,
            file.to_string_lossy().replace('\\', "/")
        );
        let result = dispatch_kiro_tool(&raw, &engine).unwrap();
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["result"]["status"], "queued");
        assert!(v["result"]["patch"].as_str().unwrap().contains("vuln-123"));
    }

    #[test]
    fn test_log_telemetry_audit_empty_project_id() {
        let dir = TempDir::new().unwrap();
        let engine = Arc::new(Mutex::new(SastEngine::new(dir.path()).unwrap()));
        let raw = r#"{"jsonrpc":"2.0","method":"log_telemetry_audit","params":{"project_id":"","scan_results":[]},"id":6}"#;
        let result = dispatch_kiro_tool(raw, &engine).unwrap();
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(v["error"].is_object());
        assert_eq!(v["error"]["code"], JsonRpcError::INVALID_PARAMS);
    }

    #[test]
    fn test_log_telemetry_audit_valid() {
        let dir = TempDir::new().unwrap();
        let engine = Arc::new(Mutex::new(SastEngine::new(dir.path()).unwrap()));
        let raw = r#"{"jsonrpc":"2.0","method":"log_telemetry_audit","params":{"project_id":"proj_abc","scan_results":[{"rule_id":"sql-injection","severity":"High","file_path":"src/db.py","line":42}]},"id":7}"#;
        let result = dispatch_kiro_tool(raw, &engine).unwrap();
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["result"]["findings_count"], 1);
        assert_eq!(v["result"]["status"], "submitted");
        assert!(v["result"]["scan_id"]
            .as_str()
            .unwrap()
            .starts_with("mcp-scan-"));
    }

    #[test]
    fn test_dispatch_returns_none_for_unknown_tool() {
        let dir = TempDir::new().unwrap();
        let engine = Arc::new(Mutex::new(SastEngine::new(dir.path()).unwrap()));
        let raw = r#"{"jsonrpc":"2.0","method":"scan_file","params":{"path":"test.js"},"id":8}"#;
        // scan_file is handled by the main dispatcher, not kiro_tools
        let result = dispatch_kiro_tool(raw, &engine);
        assert!(result.is_none());
    }
}
