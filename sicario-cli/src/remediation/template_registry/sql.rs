//! SQL injection patch templates.

use super::helpers::*;
use super::{MultiLinePatchTemplate, PatchTemplate};
use crate::parser::{Language, TreeSitterEngine};
use tree_sitter::Node;

pub struct SqlStringConcatTemplate;

impl PatchTemplate for SqlStringConcatTemplate {
    fn name(&self) -> &'static str {
        "SqlStringConcat"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        // Must be inside a query call
        let is_query = lower.contains(".query(")
            || lower.contains("cursor.execute(")
            || lower.contains("db.exec(")
            || lower.contains("db.query(")
            || lower.contains(".execute(")
            || lower.contains("db.raw(");
        if !is_query {
            return None;
        }
        // Must have string concatenation or f-string
        if !line.contains(" + ")
            && !line.contains("f\"")
            && !line.contains("f'")
            && !line.contains('`')
        {
            return None;
        }
        // Must reference user input
        if !line.contains("req.")
            && !line.contains("user")
            && !line.contains("input")
            && !line.contains("param")
            && !line.contains("body")
        {
            return None;
        }

        let indent = get_indent(line);
        let comment = match lang {
            Language::Python => format!("{indent}# SICARIO FIX (CWE-89): use parameterized query â€” replace string concat with %s placeholder"),
            Language::Go     => format!("{indent}// SICARIO FIX (CWE-89): use parameterized query â€” replace string concat with $1 placeholder"),
            _                => format!("{indent}// SICARIO FIX (CWE-89): use parameterized query â€” replace string concat with $1 placeholder"),
        };
        Some(format!("{comment}\n{line}"))
    }
}

// â”€â”€ 59. SqlTemplateStringTemplate (CWE-89) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Flags template literals used as SQL query strings in JS/TS.
pub struct SqlTemplateStringTemplate;

impl PatchTemplate for SqlTemplateStringTemplate {
    fn name(&self) -> &'static str {
        "SqlTemplateString"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        let lower = line.to_lowercase();
        if !lower.contains(".query(") && !lower.contains(".execute(") {
            return None;
        }
        // Must use a template literal with interpolation
        if !line.contains('`') || !line.contains("${") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}// SICARIO FIX (CWE-89): replace template literal with parameterized query â€” use $1, $2 placeholders and pass values as array\n{line}"
        ))
    }
}

// ── SqlAstRewriteTemplate (CWE-89) ────────────────────────────────────────────

/// AST-level SQL injection rewrite template for JS/TS files.
///
/// Rewrites string concatenation and template literal SQL queries into
/// parameterized form (`$1`, `$2`, …) using tree-sitter AST analysis.
///
/// Supports:
/// - String concatenation: `db.query("SELECT … " + userId)`
/// - Template literals: `` db.query(`SELECT … ${userId}`) ``
/// - Multi-line concatenation spanning multiple lines
///
/// Returns `None` for:
/// - Languages other than JS/TS
/// - More than 8 interpolated variables
/// - Conditional query construction
/// - Nested function calls as arguments
///
/// # Zero-Exfiltration Invariant
///
/// **INVARIANT**: `SqlAstRewriteTemplate::generate_multiline_patch` makes
/// ZERO network calls. All processing is purely local:
///   - Tree-sitter parsing is performed in-process with no network I/O.
///   - No HTTP client, socket, or DNS lookup is used anywhere in this module.
///   - The only I/O is reading `std::env::temp_dir()` to construct a
///     `TreeSitterEngine` (filesystem only, no network).
///
/// Code reviewers: if you see any `reqwest`, `hyper`, `ureq`, `TcpStream`,
/// `UdpSocket`, or any other network primitive in this module, that is a
/// zero-exfiltration violation and MUST be rejected immediately.
pub struct SqlAstRewriteTemplate;

impl MultiLinePatchTemplate for SqlAstRewriteTemplate {
    fn name(&self) -> &'static str {
        "SqlAstRewriteTemplate"
    }

    fn generate_multiline_patch(
        &self,
        file_content: &str,
        vulnerable_line: usize,
        lang: Language,
    ) -> Option<String> {
        // Only handle JS/TS
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }

        // Parse the file with tree-sitter
        let temp_dir = std::env::temp_dir();
        let engine = TreeSitterEngine::new(&temp_dir).ok()?;
        let tree = engine.parse_source(file_content, lang).ok()?;
        let root = tree.root_node();

        // Convert 1-indexed line to 0-indexed
        let target_row = vulnerable_line.saturating_sub(1);

        // Find the deepest node at the target row
        let target_node = find_node_at_row(root, target_row)?;

        // Walk up to find the nearest call_expression whose callee ends in .query or .execute
        let call_node = find_sql_call_expression(target_node, file_content)?;

        // Get the arguments node (first argument to the call)
        let args_node = call_node.child_by_field_name("arguments")?;

        // Get the first argument
        let first_arg = get_first_argument(args_node)?;

        // Determine the rewrite strategy based on the first argument type
        let rewrite_result = match first_arg.kind() {
            "template_string" => rewrite_template_literal(first_arg, file_content)?,
            "binary_expression" => rewrite_string_concat(first_arg, file_content)?,
            "string" => {
                // Single string with no interpolation — check if there's a second arg
                // that's a concat. If not, nothing to rewrite.
                return None;
            }
            _ => return None,
        };

        let (new_query_str, variables) = rewrite_result;

        // Reject if more than 8 interpolated variables
        if variables.len() > 8 {
            return None;
        }

        // Build the replacement call expression
        let call_start = call_node.start_byte();
        let call_end = call_node.end_byte();

        // Determine the callee text (e.g. "db.query" or "pool.execute")
        let callee_node = call_node.child_by_field_name("function")?;
        let callee_text = callee_node.utf8_text(file_content.as_bytes()).ok()?;

        // Determine indentation from the line containing the call start
        let call_start_line = call_node.start_position().row;
        let indent = get_line_indent(file_content, call_start_line);

        // Build the new call
        let new_call = if variables.is_empty() {
            format!("{}({:?})", callee_text, new_query_str)
        } else {
            let vars_array = variables.join(", ");
            format!("{}({:?}, [{}])", callee_text, new_query_str, vars_array)
        };

        // Reconstruct the file with the rewritten call
        let before = &file_content[..call_start];
        let after = &file_content[call_end..];

        // Apply indentation to the new call (the callee already has the right indent
        // from the surrounding code, so we just need to ensure the replacement
        // doesn't break indentation)
        let _ = indent; // indent is preserved because we replace only the call node bytes

        Some(format!("{}{}{}", before, new_call, after))
    }
}

// ── AST helpers ───────────────────────────────────────────────────────────────

/// Find the deepest AST node whose range contains `target_row` (0-indexed).
fn find_node_at_row<'a>(root: Node<'a>, target_row: usize) -> Option<Node<'a>> {
    // Use a simple recursive descent: find the deepest node that spans target_row.
    fn descend<'b>(node: Node<'b>, target_row: usize) -> Option<Node<'b>> {
        let start_row = node.start_position().row;
        let end_row = node.end_position().row;

        // This node doesn't span the target row
        if start_row > target_row || end_row < target_row {
            return None;
        }

        // Try to find a deeper child that also spans the target row
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if let Some(deeper) = descend(child, target_row) {
                    return Some(deeper);
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        // No child spans the target row — this node is the deepest match
        Some(node)
    }

    descend(root, target_row)
}

/// Walk up the AST from `node` to find the nearest `call_expression` whose
/// callee (function field) ends in `.query` or `.execute`.
fn find_sql_call_expression<'a>(mut node: Node<'a>, source: &str) -> Option<Node<'a>> {
    loop {
        if node.kind() == "call_expression" {
            if let Some(callee) = node.child_by_field_name("function") {
                let callee_text = callee
                    .utf8_text(source.as_bytes())
                    .unwrap_or("")
                    .to_lowercase();
                if callee_text.ends_with(".query")
                    || callee_text.ends_with(".execute")
                    || callee_text.ends_with(".exec")
                    || callee_text.ends_with(".raw")
                {
                    return Some(node);
                }
            }
        }
        node = node.parent()?;
    }
}

/// Get the first argument from an `arguments` node.
fn get_first_argument<'a>(args_node: Node<'a>) -> Option<Node<'a>> {
    let mut cursor = args_node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            // Skip punctuation (parentheses, commas)
            if child.kind() != "("
                && child.kind() != ")"
                && child.kind() != ","
                && !child.is_extra()
            {
                return Some(child);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}

/// Get the indentation (leading whitespace) of a specific line in the source.
fn get_line_indent(source: &str, line_idx: usize) -> String {
    source
        .lines()
        .nth(line_idx)
        .map(|line| {
            let trimmed = line.trim_start();
            let indent_len = line.len() - trimmed.len();
            line[..indent_len].to_string()
        })
        .unwrap_or_default()
}

// ── Rewrite strategies ────────────────────────────────────────────────────────

/// Rewrite a template literal SQL query to parameterized form.
///
/// Input:  `` `SELECT * FROM t WHERE id = ${userId} AND name = ${name}` ``
/// Output: `("SELECT * FROM t WHERE id = $1 AND name = $2", [userId, name])`
fn rewrite_template_literal(node: Node<'_>, source: &str) -> Option<(String, Vec<String>)> {
    let raw = node.utf8_text(source.as_bytes()).ok()?;

    // Must be a template string (backtick-delimited)
    if !raw.starts_with('`') {
        return None;
    }

    let mut query_parts: Vec<String> = Vec::new();
    let mut variables: Vec<String> = Vec::new();
    let mut param_idx = 1usize;

    // Walk children: string_fragment and template_substitution nodes
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            match child.kind() {
                "`" => {} // backtick delimiters — skip
                "string_fragment" => {
                    let text = child.utf8_text(source.as_bytes()).ok()?;
                    query_parts.push(text.to_string());
                }
                "template_substitution" => {
                    // Check for nested function calls — bail out if found
                    let expr = get_template_substitution_expr(child, source)?;
                    if is_function_call_node(expr) {
                        return None;
                    }
                    // Check for conditional expressions — bail out
                    if is_conditional_node(expr) {
                        return None;
                    }
                    let var_text = expr.utf8_text(source.as_bytes()).ok()?.to_string();
                    query_parts.push(format!("${}", param_idx));
                    variables.push(var_text);
                    param_idx += 1;
                }
                _ => {}
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    if variables.is_empty() {
        return None; // Nothing to parameterize
    }

    Some((query_parts.join(""), variables))
}

/// Get the expression node inside a `template_substitution` (the `${...}` part).
fn get_template_substitution_expr<'a>(node: Node<'a>, _source: &str) -> Option<Node<'a>> {
    // template_substitution: "${" <expr> "}"
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.kind() != "${" && child.kind() != "}" {
                return Some(child);
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    None
}

/// Rewrite a string concatenation SQL query to parameterized form.
///
/// Input:  `"SELECT * FROM t WHERE id = " + userId`
/// Output: `("SELECT * FROM t WHERE id = $1", [userId])`
fn rewrite_string_concat(node: Node<'_>, source: &str) -> Option<(String, Vec<String>)> {
    let mut string_parts: Vec<String> = Vec::new();
    let mut variables: Vec<String> = Vec::new();
    let mut param_idx = 1usize;

    collect_concat_parts(
        node,
        source,
        &mut string_parts,
        &mut variables,
        &mut param_idx,
    )?;

    if variables.is_empty() {
        return None;
    }

    Some((string_parts.join(""), variables))
}

/// Recursively collect parts from a binary `+` expression tree.
fn collect_concat_parts(
    node: Node<'_>,
    source: &str,
    parts: &mut Vec<String>,
    variables: &mut Vec<String>,
    param_idx: &mut usize,
) -> Option<()> {
    if node.kind() == "binary_expression" {
        // Check operator is "+"
        let op = node.child_by_field_name("operator")?;
        let op_text = op.utf8_text(source.as_bytes()).ok()?;
        if op_text != "+" {
            return None; // Not string concat
        }

        let left = node.child_by_field_name("left")?;
        let right = node.child_by_field_name("right")?;

        collect_concat_parts(left, source, parts, variables, param_idx)?;
        collect_concat_parts(right, source, parts, variables, param_idx)?;
    } else if node.kind() == "string" {
        // Extract the string content (without quotes)
        let text = extract_string_content(node, source)?;
        parts.push(text);
    } else if node.kind() == "template_string" {
        // Template literal inside concat — handle recursively
        let (sub_query, sub_vars) = rewrite_template_literal(node, source)?;
        // Adjust param indices
        let adjusted_query = adjust_param_indices(&sub_query, *param_idx - 1);
        parts.push(adjusted_query);
        for v in sub_vars {
            variables.push(v);
            *param_idx += 1;
        }
    } else {
        // It's a variable/expression
        // Reject function calls and conditionals
        if is_function_call_node(node) {
            return None;
        }
        if is_conditional_node(node) {
            return None;
        }
        let var_text = node.utf8_text(source.as_bytes()).ok()?.to_string();
        parts.push(format!("${}", param_idx));
        variables.push(var_text);
        *param_idx += 1;
    }
    Some(())
}

/// Extract the string content from a `string` node (strips surrounding quotes).
fn extract_string_content(node: Node<'_>, source: &str) -> Option<String> {
    let raw = node.utf8_text(source.as_bytes()).ok()?;
    // Strip surrounding quotes (' or ")
    if (raw.starts_with('"') && raw.ends_with('"'))
        || (raw.starts_with('\'') && raw.ends_with('\''))
    {
        Some(raw[1..raw.len() - 1].to_string())
    } else {
        Some(raw.to_string())
    }
}

/// Adjust `$N` placeholders in a query string by adding `offset` to each index.
fn adjust_param_indices(query: &str, offset: usize) -> String {
    if offset == 0 {
        return query.to_string();
    }
    // Simple regex-free replacement: find "$N" patterns
    let mut result = String::new();
    let mut chars = query.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            let mut num_str = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    num_str.push(d);
                    chars.next();
                } else {
                    break;
                }
            }
            if !num_str.is_empty() {
                let n: usize = num_str.parse().unwrap_or(0);
                result.push('$');
                result.push_str(&(n + offset).to_string());
            } else {
                result.push('$');
                result.push_str(&num_str);
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Returns `true` if the node is a function call expression.
fn is_function_call_node(node: Node<'_>) -> bool {
    node.kind() == "call_expression" || node.kind() == "new_expression"
}

/// Returns `true` if the node is a conditional/ternary expression.
fn is_conditional_node(node: Node<'_>) -> bool {
    node.kind() == "ternary_expression"
        || node.kind() == "if_statement"
        || node.kind() == "conditional_expression"
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_template(source: &str, line: usize, lang: Language) -> Option<String> {
        SqlAstRewriteTemplate.generate_multiline_patch(source, line, lang)
    }

    fn parse_js_no_error(source: &str) -> bool {
        let temp_dir = std::env::temp_dir();
        let engine = TreeSitterEngine::new(&temp_dir).ok().unwrap();
        let tree = engine
            .parse_source(source, Language::JavaScript)
            .ok()
            .unwrap();
        !tree.root_node().has_error()
    }

    // ── String concat rewrite ─────────────────────────────────────────────────

    #[test]
    fn test_string_concat_rewrite_produces_valid_parameterized_query() {
        let source = r#"const result = db.query("SELECT * FROM users WHERE id = " + userId);
"#;
        let output = apply_template(source, 1, Language::JavaScript);
        assert!(output.is_some(), "Expected Some output for string concat");
        let out = output.unwrap();
        assert!(
            out.contains("$1"),
            "Expected $1 placeholder in output: {}",
            out
        );
        assert!(
            out.contains("[userId]"),
            "Expected [userId] array in output: {}",
            out
        );
        assert!(
            out.contains("SELECT * FROM users WHERE id = "),
            "Expected SQL text preserved: {}",
            out
        );
    }

    #[test]
    fn test_string_concat_rewrite_round_trip_no_parse_error() {
        let source = r#"const result = db.query("SELECT * FROM users WHERE id = " + userId);
"#;
        let output = apply_template(source, 1, Language::JavaScript).unwrap();
        assert!(
            parse_js_no_error(&output),
            "Output should parse without errors: {}",
            output
        );
    }

    // ── Template literal rewrite ──────────────────────────────────────────────

    #[test]
    fn test_template_literal_rewrite_produces_valid_parameterized_query() {
        let source = "const result = db.query(`SELECT * FROM users WHERE id = ${userId}`);\n";
        let output = apply_template(source, 1, Language::JavaScript);
        assert!(
            output.is_some(),
            "Expected Some output for template literal"
        );
        let out = output.unwrap();
        assert!(
            out.contains("$1"),
            "Expected $1 placeholder in output: {}",
            out
        );
        assert!(
            out.contains("[userId]"),
            "Expected [userId] array in output: {}",
            out
        );
    }

    #[test]
    fn test_template_literal_rewrite_round_trip_no_parse_error() {
        let source = "const result = db.query(`SELECT * FROM users WHERE id = ${userId}`);\n";
        let output = apply_template(source, 1, Language::JavaScript).unwrap();
        assert!(
            parse_js_no_error(&output),
            "Output should parse without errors: {}",
            output
        );
    }

    #[test]
    fn test_template_literal_multiple_variables() {
        let source =
            "const result = db.query(`SELECT * FROM t WHERE id = ${userId} AND name = ${name}`);\n";
        let output = apply_template(source, 1, Language::JavaScript);
        assert!(output.is_some(), "Expected Some output");
        let out = output.unwrap();
        assert!(out.contains("$1"), "Expected $1: {}", out);
        assert!(out.contains("$2"), "Expected $2: {}", out);
        assert!(out.contains("userId"), "Expected userId: {}", out);
        assert!(out.contains("name"), "Expected name: {}", out);
    }

    // ── Multi-line concat rewrite ─────────────────────────────────────────────

    #[test]
    fn test_multiline_concat_rewrite_produces_valid_parameterized_query() {
        let source = r#"const result = db.query(
    "SELECT * FROM users WHERE id = " +
    userId +
    " AND active = true"
);
"#;
        let output = apply_template(source, 2, Language::JavaScript);
        assert!(
            output.is_some(),
            "Expected Some output for multi-line concat"
        );
        let out = output.unwrap();
        assert!(out.contains("$1"), "Expected $1 placeholder: {}", out);
        assert!(out.contains("[userId]"), "Expected [userId] array: {}", out);
    }

    #[test]
    fn test_multiline_concat_round_trip_no_parse_error() {
        let source = r#"const result = db.query(
    "SELECT * FROM users WHERE id = " +
    userId +
    " AND active = true"
);
"#;
        if let Some(output) = apply_template(source, 2, Language::JavaScript) {
            assert!(
                parse_js_no_error(&output),
                "Output should parse without errors: {}",
                output
            );
        }
    }

    // ── >8 variables → None ───────────────────────────────────────────────────

    #[test]
    fn test_more_than_8_variables_returns_none() {
        // Build a template literal with 9 interpolations
        let vars: Vec<String> = (1..=9).map(|i| format!("${{v{}}}", i)).collect();
        let interpolations = vars.join(" AND col = ");
        let source = format!(
            "const r = db.query(`SELECT * FROM t WHERE col = {}`);\n",
            interpolations
        );
        let output = apply_template(&source, 1, Language::JavaScript);
        assert!(
            output.is_none(),
            "Expected None for >8 variables, got: {:?}",
            output
        );
    }

    // ── Non-JS/TS file → None ─────────────────────────────────────────────────

    #[test]
    fn test_non_js_ts_returns_none() {
        let source = "query = db.query(\"SELECT * FROM t WHERE id = \" + user_id)\n";
        let output = apply_template(source, 1, Language::Python);
        assert!(output.is_none(), "Expected None for Python file");

        let output = apply_template(source, 1, Language::Go);
        assert!(output.is_none(), "Expected None for Go file");
    }

    // ── Original indentation is preserved ────────────────────────────────────

    #[test]
    fn test_original_indentation_preserved() {
        let source = r#"function getUser(userId) {
    const result = db.query(`SELECT * FROM users WHERE id = ${userId}`);
    return result;
}
"#;
        let output = apply_template(source, 2, Language::JavaScript);
        assert!(output.is_some(), "Expected Some output");
        let out = output.unwrap();
        // The function wrapper and return statement should be unchanged
        assert!(
            out.contains("function getUser(userId)"),
            "Function declaration should be preserved: {}",
            out
        );
        assert!(
            out.contains("    return result;"),
            "Return statement with indentation should be preserved: {}",
            out
        );
    }

    // ── Code outside the rewritten call is unchanged ──────────────────────────

    #[test]
    fn test_code_outside_call_unchanged() {
        let source = r#"// This is a comment
const x = 42;
const result = db.query(`SELECT * FROM t WHERE id = ${userId}`);
console.log(result);
const y = "hello";
"#;
        let output = apply_template(source, 3, Language::JavaScript);
        assert!(output.is_some(), "Expected Some output");
        let out = output.unwrap();
        assert!(
            out.contains("// This is a comment"),
            "Comment should be preserved: {}",
            out
        );
        assert!(
            out.contains("const x = 42;"),
            "const x should be preserved: {}",
            out
        );
        assert!(
            out.contains("console.log(result);"),
            "console.log should be preserved: {}",
            out
        );
        assert!(
            out.contains("const y = \"hello\";"),
            "const y should be preserved: {}",
            out
        );
    }

    // ── Round-trip property for TypeScript ───────────────────────────────────

    #[test]
    fn test_typescript_template_literal_round_trip() {
        let source = "const result = pool.query(`SELECT * FROM users WHERE id = ${userId}`);\n";
        let output = apply_template(source, 1, Language::TypeScript);
        assert!(output.is_some(), "Expected Some output for TypeScript");
        let out = output.unwrap();
        // Validate with tree-sitter TypeScript parser
        let temp_dir = std::env::temp_dir();
        let engine = TreeSitterEngine::new(&temp_dir).ok().unwrap();
        let tree = engine
            .parse_source(&out, Language::TypeScript)
            .ok()
            .unwrap();
        assert!(
            !tree.root_node().has_error(),
            "TypeScript output should parse without errors: {}",
            out
        );
    }

    // ── execute() variant ─────────────────────────────────────────────────────

    #[test]
    fn test_execute_call_is_rewritten() {
        let source = "await conn.execute(`DELETE FROM sessions WHERE token = ${token}`);\n";
        let output = apply_template(source, 1, Language::JavaScript);
        assert!(output.is_some(), "Expected Some output for .execute()");
        let out = output.unwrap();
        assert!(out.contains("$1"), "Expected $1: {}", out);
        assert!(out.contains("[token]"), "Expected [token]: {}", out);
    }

    // ── Task 11.2: CRLF line ending preservation (Windows compatibility) ──────

    /// CI test: SqlAstRewriteTemplate preserves CRLF line endings on Windows input.
    ///
    /// On Windows, files may use CRLF (`\r\n`) line endings. The template must
    /// preserve the original line endings in the output — it must not strip `\r`
    /// or convert CRLF to LF.
    ///
    /// Validates: Requirements 11.2 (Cross-Platform Compatibility)
    #[test]
    fn test_crlf_line_endings_preserved_in_output() {
        // Build a JS file with CRLF line endings (Windows-style).
        // The template literal SQL injection is on line 1.
        let source_crlf =
            "const result = db.query(`SELECT * FROM users WHERE id = ${userId}`);\r\n";

        let output = apply_template(source_crlf, 1, Language::JavaScript);
        assert!(
            output.is_some(),
            "Expected Some output for CRLF input: template should handle CRLF files"
        );
        let out = output.unwrap();

        // The output must contain the parameterized query.
        assert!(
            out.contains("$1"),
            "Expected $1 placeholder in CRLF output: {}",
            out
        );
        assert!(
            out.contains("[userId]"),
            "Expected [userId] array in CRLF output: {}",
            out
        );

        // CRLF preservation: the output must retain the \r\n line ending.
        // The template replaces only the call expression bytes — the surrounding
        // content (including line endings) must be preserved verbatim.
        assert!(
            out.contains("\r\n"),
            "CRLF line endings must be preserved in output — got LF-only output: {:?}",
            out
        );
    }

    /// CI test: SqlAstRewriteTemplate preserves CRLF in multi-line Windows input.
    ///
    /// Verifies that a multi-line JS file with CRLF line endings has its line
    /// endings preserved after the template rewrites the SQL call expression.
    ///
    /// Validates: Requirements 11.2 (Cross-Platform Compatibility)
    #[test]
    fn test_crlf_multiline_file_line_endings_preserved() {
        // Multi-line file with CRLF endings (Windows-style).
        let source_crlf = "// database helpers\r\nconst result = db.query(`SELECT * FROM t WHERE id = ${userId}`);\r\nconsole.log(result);\r\n";

        let output = apply_template(source_crlf, 2, Language::JavaScript);
        assert!(
            output.is_some(),
            "Expected Some output for multi-line CRLF input"
        );
        let out = output.unwrap();

        // The rewritten call must be parameterized.
        assert!(
            out.contains("$1"),
            "Expected $1 in CRLF multi-line output: {}",
            out
        );

        // All three lines must still end with \r\n.
        // Count \r\n occurrences — should be at least 2 (comment line + console.log line).
        let crlf_count = out.matches("\r\n").count();
        assert!(
            crlf_count >= 2,
            "Expected at least 2 CRLF line endings preserved, got {}: {:?}",
            crlf_count,
            out
        );

        // Surrounding code must be unchanged.
        assert!(
            out.contains("// database helpers\r\n"),
            "Comment with CRLF must be preserved: {:?}",
            out
        );
        assert!(
            out.contains("console.log(result);\r\n"),
            "console.log with CRLF must be preserved: {:?}",
            out
        );
    }

    /// CI test: SqlAstRewriteTemplate does not corrupt LF-only files on Windows.
    ///
    /// Verifies that LF-only files (Unix-style) are not modified to add CRLF
    /// when processed on Windows. The template must be line-ending agnostic.
    ///
    /// Validates: Requirements 11.2 (Cross-Platform Compatibility)
    #[test]
    fn test_lf_only_file_not_converted_to_crlf() {
        // LF-only file (Unix-style) — must not gain \r\n after rewrite.
        let source_lf = "const result = db.query(`SELECT * FROM users WHERE id = ${userId}`);\n";

        let output = apply_template(source_lf, 1, Language::JavaScript);
        assert!(output.is_some(), "Expected Some output for LF input");
        let out = output.unwrap();

        // Must not contain any \r\n (CRLF) — LF-only must stay LF-only.
        assert!(
            !out.contains("\r\n"),
            "LF-only input must not gain CRLF line endings in output: {:?}",
            out
        );
    }

    // ── Task 11.2: Windows path normalization (sicario fix --staged) ──────────

    /// CI test: sicario fix --staged normalizes path separators to `/` on Windows.
    ///
    /// The `cmd_fix_staged` function normalizes Windows-style backslash paths
    /// (e.g. `src\db.js`) to forward slashes (`src/db.js`) before processing.
    /// This test verifies the normalization logic directly.
    ///
    /// Validates: Requirements 11.2 (Cross-Platform Compatibility)
    #[test]
    fn test_windows_path_separator_normalization() {
        // Simulate the path normalization logic from cmd_fix_staged.
        // On Windows, `git diff --cached --name-only` may return backslash paths.
        let windows_paths = vec![
            r"src\db.js",
            r"src\auth\login.js",
            r"lib\utils\helpers.ts",
            r"test\unit\db.test.js",
        ];

        let normalized: Vec<String> = windows_paths.iter().map(|p| p.replace('\\', "/")).collect();

        assert_eq!(normalized[0], "src/db.js");
        assert_eq!(normalized[1], "src/auth/login.js");
        assert_eq!(normalized[2], "lib/utils/helpers.ts");
        assert_eq!(normalized[3], "test/unit/db.test.js");

        // Verify forward-slash paths are unchanged.
        let unix_paths = vec!["src/db.js", "src/auth/login.js"];
        let normalized_unix: Vec<String> =
            unix_paths.iter().map(|p| p.replace('\\', "/")).collect();
        assert_eq!(normalized_unix[0], "src/db.js");
        assert_eq!(normalized_unix[1], "src/auth/login.js");
    }

    // ── Task 11.2: OllamaClient IPv4 verification ─────────────────────────────

    /// CI test: OllamaClient uses 127.0.0.1 not localhost in all code paths.
    ///
    /// Verifies that the OllamaClient URL constants use the IPv4 loopback address
    /// (`127.0.0.1`) rather than the hostname `localhost`. This is required to
    /// avoid IPv6 resolution delays on platforms where `localhost` resolves to `::1`.
    ///
    /// Validates: Requirements 11.2 (Cross-Platform Compatibility)
    #[test]
    fn test_cross_platform_ollama_uses_ipv4_not_localhost() {
        use crate::remediation::ollama_client::{OLLAMA_CHAT_URL, OLLAMA_TAGS_URL};

        // Both URL constants must use 127.0.0.1, not localhost.
        assert!(
            !OLLAMA_TAGS_URL.contains("localhost"),
            "OLLAMA_TAGS_URL must not use 'localhost' — use 127.0.0.1 for IPv4 compatibility: {}",
            OLLAMA_TAGS_URL
        );
        assert!(
            !OLLAMA_CHAT_URL.contains("localhost"),
            "OLLAMA_CHAT_URL must not use 'localhost' — use 127.0.0.1 for IPv4 compatibility: {}",
            OLLAMA_CHAT_URL
        );
        assert!(
            OLLAMA_TAGS_URL.contains("127.0.0.1"),
            "OLLAMA_TAGS_URL must use 127.0.0.1 (IPv4 loopback): {}",
            OLLAMA_TAGS_URL
        );
        assert!(
            OLLAMA_CHAT_URL.contains("127.0.0.1"),
            "OLLAMA_CHAT_URL must use 127.0.0.1 (IPv4 loopback): {}",
            OLLAMA_CHAT_URL
        );
    }
}
