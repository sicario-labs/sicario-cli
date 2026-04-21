//! JSON-RPC 2.0 protocol types for the MCP server.
//!
//! Requirements: 6.1, 6.2

use serde::{Deserialize, Serialize};

/// A JSON-RPC 2.0 request object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be exactly "2.0"
    pub jsonrpc: String,
    /// Method name to invoke
    pub method: String,
    /// Optional parameters
    #[serde(default)]
    pub params: serde_json::Value,
    /// Request ID — null for notifications, string/number for calls
    pub id: Option<serde_json::Value>,
}

/// A JSON-RPC 2.0 response object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Must be exactly "2.0"
    pub jsonrpc: String,
    /// Present on success
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Present on error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Mirrors the request ID
    pub id: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    /// Build a successful response.
    pub fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Build an error response.
    pub fn error(id: Option<serde_json::Value>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    // Standard JSON-RPC error codes
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    pub fn parse_error() -> Self {
        Self { code: Self::PARSE_ERROR, message: "Parse error".to_string(), data: None }
    }

    pub fn invalid_request(msg: impl Into<String>) -> Self {
        Self { code: Self::INVALID_REQUEST, message: msg.into(), data: None }
    }

    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: Self::METHOD_NOT_FOUND,
            message: format!("Method not found: {}", method),
            data: None,
        }
    }

    pub fn invalid_params(msg: impl Into<String>) -> Self {
        Self { code: Self::INVALID_PARAMS, message: msg.into(), data: None }
    }

    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self { code: Self::INTERNAL_ERROR, message: msg.into(), data: None }
    }
}

/// High-level MCP request (parsed from JSON-RPC).
#[derive(Debug, Clone)]
pub struct McpRequest {
    pub id: Option<serde_json::Value>,
    pub method: McpMethod,
}

/// High-level MCP response.
#[derive(Debug, Clone, Serialize)]
pub struct McpResponse {
    pub id: Option<serde_json::Value>,
    pub payload: McpResponsePayload,
}

/// Supported MCP methods.
#[derive(Debug, Clone)]
pub enum McpMethod {
    /// Scan a file at the given path.
    ScanFile { path: String },
    /// Scan a code snippet in the given language.
    ScanCode { code: String, language: String },
    /// Return all loaded security rules.
    GetRules,
}

/// Response payload variants.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum McpResponsePayload {
    Vulnerabilities(Vec<crate::engine::Vulnerability>),
    Rules(Vec<crate::engine::SecurityRule>),
}

/// Parse a raw JSON-RPC request into a typed `McpRequest`.
pub fn parse_request(raw: &str) -> Result<McpRequest, JsonRpcError> {
    let rpc: JsonRpcRequest =
        serde_json::from_str(raw).map_err(|_| JsonRpcError::parse_error())?;

    if rpc.jsonrpc != "2.0" {
        return Err(JsonRpcError::invalid_request("jsonrpc must be \"2.0\""));
    }

    let method = match rpc.method.as_str() {
        "scan_file" => {
            let path = rpc
                .params
                .get("path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("scan_file requires 'path' param"))?
                .to_string();
            McpMethod::ScanFile { path }
        }
        "scan_code" => {
            let code = rpc
                .params
                .get("code")
                .and_then(|v| v.as_str())
                .ok_or_else(|| JsonRpcError::invalid_params("scan_code requires 'code' param"))?
                .to_string();
            let language = rpc
                .params
                .get("language")
                .and_then(|v| v.as_str())
                .unwrap_or("javascript")
                .to_string();
            McpMethod::ScanCode { code, language }
        }
        "get_rules" => McpMethod::GetRules,
        other => return Err(JsonRpcError::method_not_found(other)),
    };

    Ok(McpRequest { id: rpc.id, method })
}

/// Serialize an `McpResponse` into a JSON-RPC 2.0 response string.
pub fn serialize_response(response: McpResponse) -> String {
    let result = serde_json::to_value(&response.payload)
        .unwrap_or(serde_json::Value::Null);
    let rpc = JsonRpcResponse::success(response.id, result);
    serde_json::to_string(&rpc).unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Serialization error"},"id":null}"#.to_string())
}

/// Serialize a JSON-RPC error response.
pub fn serialize_error(id: Option<serde_json::Value>, error: JsonRpcError) -> String {
    let rpc = JsonRpcResponse::error(id, error);
    serde_json::to_string(&rpc).unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Serialization error"},"id":null}"#.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_scan_file_request() {
        let raw = r#"{"jsonrpc":"2.0","method":"scan_file","params":{"path":"src/main.rs"},"id":1}"#;
        let req = parse_request(raw).unwrap();
        assert!(matches!(req.method, McpMethod::ScanFile { path } if path == "src/main.rs"));
        assert_eq!(req.id, Some(serde_json::json!(1)));
    }

    #[test]
    fn test_parse_scan_code_request() {
        let raw = r#"{"jsonrpc":"2.0","method":"scan_code","params":{"code":"const x = 1;","language":"javascript"},"id":"abc"}"#;
        let req = parse_request(raw).unwrap();
        assert!(matches!(req.method, McpMethod::ScanCode { .. }));
    }

    #[test]
    fn test_parse_get_rules_request() {
        let raw = r#"{"jsonrpc":"2.0","method":"get_rules","params":{},"id":2}"#;
        let req = parse_request(raw).unwrap();
        assert!(matches!(req.method, McpMethod::GetRules));
    }

    #[test]
    fn test_parse_unknown_method() {
        let raw = r#"{"jsonrpc":"2.0","method":"unknown_method","params":{},"id":3}"#;
        let err = parse_request(raw).unwrap_err();
        assert_eq!(err.code, JsonRpcError::METHOD_NOT_FOUND);
    }

    #[test]
    fn test_parse_invalid_json() {
        let err = parse_request("not json").unwrap_err();
        assert_eq!(err.code, JsonRpcError::PARSE_ERROR);
    }

    #[test]
    fn test_parse_wrong_jsonrpc_version() {
        let raw = r#"{"jsonrpc":"1.0","method":"get_rules","params":{},"id":1}"#;
        let err = parse_request(raw).unwrap_err();
        assert_eq!(err.code, JsonRpcError::INVALID_REQUEST);
    }

    #[test]
    fn test_serialize_error_response() {
        let s = serialize_error(Some(serde_json::json!(1)), JsonRpcError::internal_error("oops"));
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["error"]["code"], JsonRpcError::INTERNAL_ERROR);
        assert_eq!(v["id"], 1);
    }

    #[test]
    fn test_json_rpc_response_success() {
        let resp = JsonRpcResponse::success(Some(serde_json::json!(42)), serde_json::json!({"ok": true}));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_json_rpc_response_error() {
        let resp = JsonRpcResponse::error(None, JsonRpcError::parse_error());
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
    }
}
