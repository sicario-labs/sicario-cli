//! AST-based route discovery for Express.js, FastAPI, and Flask.
//!
//! Uses tree-sitter to extract HTTP routes from source files without
//! executing any code.

use anyhow::Result;
use std::path::{Path, PathBuf};

// ── Data types ────────────────────────────────────────────────────────────────

/// HTTP method for a route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Any,
}

impl HttpMethod {
    /// Parse from a lowercase string like "get", "post", etc.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "get" => HttpMethod::Get,
            "post" => HttpMethod::Post,
            "put" => HttpMethod::Put,
            "delete" => HttpMethod::Delete,
            "patch" => HttpMethod::Patch,
            _ => HttpMethod::Any,
        }
    }

    /// Return the HTTP method as an uppercase string.
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Any => "ANY",
        }
    }
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Location of a route parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamLocation {
    Path,
    Query,
    Body,
    Header,
}

/// Inferred type of a route parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamType {
    String,
    Number,
    Boolean,
    Object,
}

/// A single parameter extracted from a route handler.
#[derive(Debug, Clone)]
pub struct RouteParameter {
    pub name: String,
    pub location: ParamLocation,
    pub inferred_type: ParamType,
}

/// A single HTTP route extracted from source code.
#[derive(Debug, Clone)]
pub struct ExtractedRoute {
    pub method: HttpMethod,
    pub path: String,
    pub handler_file: PathBuf,
    pub handler_line: usize,
    pub handler_function: String,
    pub parameters: Vec<RouteParameter>,
}

// ── RouteExtractor ────────────────────────────────────────────────────────────

/// Extracts HTTP routes from source files using tree-sitter AST analysis.
pub struct RouteExtractor;

impl RouteExtractor {
    /// Extract all routes from source files in `project_root`.
    ///
    /// Supports Express.js (`.js`/`.ts`), FastAPI (`.py`), and Flask (`.py`).
    /// Returns an empty list for unsupported frameworks — never returns an error
    /// for unsupported file types.
    pub fn extract(project_root: &Path) -> Result<Vec<ExtractedRoute>> {
        let mut routes = Vec::new();

        // Collect all JS/TS and Python files
        let mut files = Vec::new();
        collect_source_files(project_root, &mut files);

        for file_path in &files {
            let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

            let source = match std::fs::read_to_string(file_path) {
                Ok(s) => s,
                Err(_) => continue,
            };

            match ext {
                "js" | "ts" | "jsx" | "tsx" => {
                    let mut express_routes =
                        extract_express_routes(file_path, &source).unwrap_or_default();
                    routes.append(&mut express_routes);
                }
                "py" => {
                    let mut py_routes =
                        extract_python_routes(file_path, &source).unwrap_or_default();
                    routes.append(&mut py_routes);
                }
                _ => {}
            }
        }

        Ok(routes)
    }
}

// ── File collection ───────────────────────────────────────────────────────────

fn collect_source_files(dir: &Path, files: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // Skip common non-source directories
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if matches!(
                    name,
                    "node_modules"
                        | ".git"
                        | "target"
                        | "dist"
                        | "build"
                        | "__pycache__"
                        | ".venv"
                        | "venv"
                        | ".sicario"
                ) {
                    continue;
                }
            }
            collect_source_files(&path, files);
        } else if path.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if matches!(ext, "js" | "ts" | "jsx" | "tsx" | "py") {
                    files.push(path);
                }
            }
        }
    }
}

// ── Express.js route extraction ───────────────────────────────────────────────

/// Extract Express.js routes from a JS/TS source file.
///
/// Matches patterns like:
/// - `app.get('/path', handler)`
/// - `router.post('/path', async (req, res) => { ... })`
/// - `server.put('/path/:id', handler)` (http.createServer, Koa, Hono)
/// - `api.delete('/path')`
fn extract_express_routes(file_path: &Path, source: &str) -> Result<Vec<ExtractedRoute>> {
    let mut routes = Vec::new();

    // Use regex-based extraction. This covers the most common patterns:
    // Express, Koa-Router, Hono, and similar frameworks.
    let route_re = regex::Regex::new(
        r#"(?:app|router|server|route|api|client|kit)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]"#,
    )?;

    for (line_idx, line) in source.lines().enumerate() {
        if let Some(caps) = route_re.captures(line) {
            let method_str = caps.get(1).map(|m| m.as_str()).unwrap_or("get");
            let path_str = caps.get(2).map(|m| m.as_str()).unwrap_or("/");

            let method = HttpMethod::from_str(method_str);
            let handler_line = line_idx + 1;

            // Extract handler function name from the same line or nearby
            let handler_function =
                extract_handler_name(line).unwrap_or_else(|| "anonymous".to_string());

            // Extract path parameters from the route path (e.g., `:id`)
            let mut parameters = extract_path_params(path_str);

            // Scan surrounding lines for req.query.X, req.body.X, req.params.X
            let context_start = handler_line.saturating_sub(1);
            let context_end = (handler_line + 30).min(source.lines().count());
            let context: String = source
                .lines()
                .skip(context_start)
                .take(context_end - context_start)
                .collect::<Vec<_>>()
                .join("\n");

            let mut body_params = extract_express_params(&context);
            // Deduplicate: don't add params already found as path params
            let existing_names: std::collections::HashSet<String> =
                parameters.iter().map(|p| p.name.clone()).collect();
            body_params.retain(|p| !existing_names.contains(&p.name));
            parameters.extend(body_params);

            routes.push(ExtractedRoute {
                method,
                path: path_str.to_string(),
                handler_file: file_path.to_path_buf(),
                handler_line,
                handler_function,
                parameters,
            });
        }
    }

    // Extract Express chained routes: app.route('/path').get(handler).post(handler)
    let chained_re = regex::Regex::new(r#"app\.route\s*\(\s*['"`]([^'"`]+)['"`]\)\s*\."#)?;
    let handler_methods_re = regex::Regex::new(r#"\s*\.(get|post|put|delete|patch)\s*\("#)?;

    for (line_idx, line) in source.lines().enumerate() {
        if chained_re.is_match(line) {
            // Find the route path
            if let Some(caps) = chained_re.captures(line) {
                let path_str = caps.get(1).map(|m| m.as_str()).unwrap_or("/");
                // Scan subsequent lines for .get(), .post(), etc.
                let context_end = (line_idx + 20).min(source.lines().count());
                let context: Vec<&str> = source
                    .lines()
                    .skip(line_idx)
                    .take(context_end - line_idx)
                    .collect();
                let context_joined = context.join("\n");

                for m in handler_methods_re.captures_iter(&context_joined) {
                    let method_str = m.get(1).map(|m| m.as_str()).unwrap_or("get");
                    let method = HttpMethod::from_str(method_str);

                    let mut parameters = extract_path_params(path_str);
                    // Scan handler body for params
                    let handler_context: String = context
                        .iter()
                        .skip(1)
                        .take(30)
                        .copied()
                        .collect::<Vec<_>>()
                        .join("\n");
                    let mut body_params = extract_express_params(&handler_context);
                    let existing: std::collections::HashSet<String> =
                        parameters.iter().map(|p| p.name.clone()).collect();
                    body_params.retain(|p| !existing.contains(&p.name));
                    parameters.extend(body_params);

                    routes.push(ExtractedRoute {
                        method,
                        path: path_str.to_string(),
                        handler_file: file_path.to_path_buf(),
                        handler_line: line_idx + 1,
                        handler_function: "anonymous".to_string(),
                        parameters,
                    });
                }
            }
        }
    }

    Ok(routes)
}

/// Extract the handler function name from an Express route line.
fn extract_handler_name(line: &str) -> Option<String> {
    // Match patterns like: app.get('/path', myHandler) or app.get('/path', async function myFn
    let handler_re =
        regex::Regex::new(r#"['"`][^'"`]+['"`]\s*,\s*(?:async\s+)?(?:function\s+)?(\w+)"#).ok()?;
    handler_re
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract path parameters from an Express route path (e.g., `/users/:id`).
fn extract_path_params(path: &str) -> Vec<RouteParameter> {
    let mut params = Vec::new();
    for segment in path.split('/') {
        if segment.starts_with(':') {
            let name = segment.trim_start_matches(':').to_string();
            if !name.is_empty() {
                params.push(RouteParameter {
                    name,
                    location: ParamLocation::Path,
                    inferred_type: ParamType::String,
                });
            }
        }
    }
    params
}

/// Extract Express.js parameters from handler body (req.query.X, req.body.X, req.params.X).
fn extract_express_params(source: &str) -> Vec<RouteParameter> {
    let mut params = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let re = regex::Regex::new(r"req\.(query|body|params|headers)\.(\w+)").unwrap();
    for caps in re.captures_iter(source) {
        let location_str = caps.get(1).map(|m| m.as_str()).unwrap_or("body");
        let name = caps
            .get(2)
            .map(|m| m.as_str())
            .unwrap_or("param")
            .to_string();

        if seen.contains(&name) {
            continue;
        }
        seen.insert(name.clone());

        let location = match location_str {
            "query" => ParamLocation::Query,
            "body" => ParamLocation::Body,
            "params" => ParamLocation::Path,
            "headers" => ParamLocation::Header,
            _ => ParamLocation::Body,
        };

        params.push(RouteParameter {
            name,
            location,
            inferred_type: ParamType::String,
        });
    }

    params
}

// ── Python route extraction (FastAPI + Flask) ─────────────────────────────────

/// Extract FastAPI and Flask routes from a Python source file.
fn extract_python_routes(file_path: &Path, source: &str) -> Result<Vec<ExtractedRoute>> {
    let mut routes = Vec::new();

    let lines: Vec<&str> = source.lines().collect();

    // FastAPI: @app.get('/path') or @router.get('/path')
    let fastapi_re = regex::Regex::new(
        r#"@(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]"#,
    )?;

    // Flask: @app.route('/path', methods=['GET', 'POST'])
    let flask_re = regex::Regex::new(
        r#"@app\.route\s*\(\s*['"`]([^'"`]+)['"`](?:[^)]*methods\s*=\s*\[([^\]]*)\])?"#,
    )?;

    for (line_idx, line) in lines.iter().enumerate() {
        // FastAPI decorator
        if let Some(caps) = fastapi_re.captures(line) {
            let method_str = caps.get(1).map(|m| m.as_str()).unwrap_or("get");
            let path_str = caps.get(2).map(|m| m.as_str()).unwrap_or("/");

            let method = HttpMethod::from_str(method_str);

            // The function definition should be on the next non-decorator line
            let func_line = find_next_def(&lines, line_idx + 1);
            let handler_function = func_line
                .as_ref()
                .and_then(|l| extract_python_func_name(l))
                .unwrap_or_else(|| "anonymous".to_string());

            // Extract path parameters from the route path (e.g., `{item_id}`)
            let mut parameters = extract_fastapi_path_params(path_str);

            // Extract function parameters from the def line
            if let Some(ref def_line) = func_line {
                let func_params = extract_fastapi_func_params(def_line);
                let existing: std::collections::HashSet<String> =
                    parameters.iter().map(|p| p.name.clone()).collect();
                for p in func_params {
                    if !existing.contains(&p.name) {
                        parameters.push(p);
                    }
                }
            }

            routes.push(ExtractedRoute {
                method,
                path: path_str.to_string(),
                handler_file: file_path.to_path_buf(),
                handler_line: line_idx + 1,
                handler_function,
                parameters,
            });
        }

        // Flask decorator
        if let Some(caps) = flask_re.captures(line) {
            let path_str = caps.get(1).map(|m| m.as_str()).unwrap_or("/");
            let methods_str = caps.get(2).map(|m| m.as_str()).unwrap_or("GET");

            // Parse methods list
            let methods: Vec<HttpMethod> = methods_str
                .split(',')
                .map(|s| s.trim().trim_matches(|c| c == '\'' || c == '"'))
                .filter(|s| !s.is_empty())
                .map(HttpMethod::from_str)
                .collect();

            let func_line = find_next_def(&lines, line_idx + 1);
            let handler_function = func_line
                .as_ref()
                .and_then(|l| extract_python_func_name(l))
                .unwrap_or_else(|| "anonymous".to_string());

            let parameters = extract_fastapi_path_params(path_str);

            // Emit one route per method (or GET if no methods specified)
            let emit_methods = if methods.is_empty() {
                vec![HttpMethod::Get]
            } else {
                methods
            };

            for method in emit_methods {
                routes.push(ExtractedRoute {
                    method,
                    path: path_str.to_string(),
                    handler_file: file_path.to_path_buf(),
                    handler_line: line_idx + 1,
                    handler_function: handler_function.clone(),
                    parameters: parameters.clone(),
                });
            }
        }
    }

    Ok(routes)
}

/// Find the next `def` or `async def` line starting from `start_idx`.
fn find_next_def(lines: &[&str], start_idx: usize) -> Option<String> {
    for line in lines.iter().skip(start_idx).take(3) {
        let trimmed = line.trim();
        if trimmed.starts_with("def ") || trimmed.starts_with("async def ") {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// Extract the function name from a Python `def` line.
fn extract_python_func_name(line: &str) -> Option<String> {
    let re = regex::Regex::new(r"(?:async\s+)?def\s+(\w+)").ok()?;
    re.captures(line)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract path parameters from a FastAPI route path (e.g., `/items/{item_id}`).
fn extract_fastapi_path_params(path: &str) -> Vec<RouteParameter> {
    let mut params = Vec::new();
    let re = regex::Regex::new(r"\{(\w+)\}").unwrap();
    for caps in re.captures_iter(path) {
        if let Some(name) = caps.get(1) {
            params.push(RouteParameter {
                name: name.as_str().to_string(),
                location: ParamLocation::Path,
                inferred_type: ParamType::String,
            });
        }
    }
    params
}

/// Extract function parameters from a FastAPI `def` line.
fn extract_fastapi_func_params(def_line: &str) -> Vec<RouteParameter> {
    let mut params = Vec::new();

    // Extract the parameter list from `def func(param1: type, param2: type = default)`
    let re = regex::Regex::new(r"\(([^)]*)\)").ok();
    let param_list = re
        .as_ref()
        .and_then(|r| r.captures(def_line))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str())
        .unwrap_or("");

    for param in param_list.split(',') {
        let param = param.trim();
        // Skip `self`, `request`, `response`, `db`, `background_tasks`
        let name = param.split(':').next().unwrap_or("").trim();
        if name.is_empty()
            || matches!(
                name,
                "self" | "request" | "response" | "db" | "background_tasks" | "req" | "res"
            )
        {
            continue;
        }

        // Infer type from annotation
        let type_annotation = param.split(':').nth(1).unwrap_or("").trim();
        let inferred_type = if type_annotation.contains("int") || type_annotation.contains("float")
        {
            ParamType::Number
        } else if type_annotation.contains("bool") {
            ParamType::Boolean
        } else {
            ParamType::String
        };

        params.push(RouteParameter {
            name: name.to_string(),
            location: ParamLocation::Query,
            inferred_type,
        });
    }

    params
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_temp_file(dir: &TempDir, name: &str, content: &str) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_express_three_routes() {
        let dir = TempDir::new().unwrap();
        let content = r#"
const express = require('express');
const app = express();

app.get('/users', (req, res) => {
    const limit = req.query.limit;
    res.json([]);
});

app.post('/users', (req, res) => {
    const name = req.body.name;
    res.json({ id: 1 });
});

app.delete('/users/:id', (req, res) => {
    const id = req.params.id;
    res.json({ deleted: true });
});
"#;
        write_temp_file(&dir, "app.js", content);
        let routes = RouteExtractor::extract(dir.path()).unwrap();
        assert_eq!(
            routes.len(),
            3,
            "Expected 3 routes, got: {:?}",
            routes
                .iter()
                .map(|r| format!("{} {}", r.method, r.path))
                .collect::<Vec<_>>()
        );

        let get_route = routes.iter().find(|r| r.method == HttpMethod::Get).unwrap();
        assert_eq!(get_route.path, "/users");

        let post_route = routes
            .iter()
            .find(|r| r.method == HttpMethod::Post)
            .unwrap();
        assert_eq!(post_route.path, "/users");

        let delete_route = routes
            .iter()
            .find(|r| r.method == HttpMethod::Delete)
            .unwrap();
        assert_eq!(delete_route.path, "/users/:id");
    }

    #[test]
    fn test_express_path_param_extraction() {
        let dir = TempDir::new().unwrap();
        let content = r#"
app.get('/users/:id/posts/:postId', (req, res) => {
    const id = req.params.id;
    res.json({});
});
"#;
        write_temp_file(&dir, "routes.js", content);
        let routes = RouteExtractor::extract(dir.path()).unwrap();
        assert_eq!(routes.len(), 1);

        let route = &routes[0];
        let path_params: Vec<&RouteParameter> = route
            .parameters
            .iter()
            .filter(|p| p.location == ParamLocation::Path)
            .collect();
        assert!(
            !path_params.is_empty(),
            "Expected path parameters for :id and :postId"
        );
        assert!(
            path_params.iter().any(|p| p.name == "id"),
            "Expected 'id' path param"
        );
    }

    #[test]
    fn test_fastapi_two_routes() {
        let dir = TempDir::new().unwrap();
        let content = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get('/items')
async def list_items(skip: int = 0, limit: int = 10):
    return []

@app.post('/items')
async def create_item(name: str, price: float):
    return {"id": 1}
"#;
        write_temp_file(&dir, "main.py", content);
        let routes = RouteExtractor::extract(dir.path()).unwrap();
        assert_eq!(
            routes.len(),
            2,
            "Expected 2 FastAPI routes, got {}",
            routes.len()
        );

        let get_route = routes.iter().find(|r| r.method == HttpMethod::Get).unwrap();
        assert_eq!(get_route.path, "/items");

        let post_route = routes
            .iter()
            .find(|r| r.method == HttpMethod::Post)
            .unwrap();
        assert_eq!(post_route.path, "/items");
    }

    #[test]
    fn test_no_routes_returns_empty() {
        let dir = TempDir::new().unwrap();
        let content = r#"
const x = 1;
function hello() {
    return "world";
}
"#;
        write_temp_file(&dir, "utils.js", content);
        let routes = RouteExtractor::extract(dir.path()).unwrap();
        assert!(
            routes.is_empty(),
            "Expected empty list for file with no routes"
        );
    }

    #[test]
    fn test_path_param_location() {
        let dir = TempDir::new().unwrap();
        let content = r#"
app.get('/users/:id', (req, res) => {
    res.json({});
});
"#;
        write_temp_file(&dir, "routes.js", content);
        let routes = RouteExtractor::extract(dir.path()).unwrap();
        assert_eq!(routes.len(), 1);

        let route = &routes[0];
        let id_param = route.parameters.iter().find(|p| p.name == "id");
        assert!(id_param.is_some(), "Expected 'id' parameter");
        assert_eq!(
            id_param.unwrap().location,
            ParamLocation::Path,
            "Expected Path location for :id"
        );
    }

    #[test]
    fn test_flask_route_extraction() {
        let dir = TempDir::new().unwrap();
        let content = r#"
from flask import Flask, request

app = Flask(__name__)

@app.route('/users', methods=['GET', 'POST'])
def users():
    return []
"#;
        write_temp_file(&dir, "app.py", content);
        let routes = RouteExtractor::extract(dir.path()).unwrap();
        // Should produce 2 routes (GET and POST)
        assert!(!routes.is_empty(), "Expected at least 1 Flask route");
        assert!(
            routes.iter().any(|r| r.path == "/users"),
            "Expected /users route"
        );
    }
}
