//! Micro-context extractor for local LLM remediation.
//!
//! Extracts the smallest enclosing function block containing a vulnerable line
//! from a source file, along with all in-scope identifiers. This context is
//! used to build a focused, zero-exfiltration prompt for the local Ollama model.
//!
//! Requirements: eta-engine 1.3

use crate::parser::{Language, TreeSitterEngine};
use std::collections::HashSet;
use std::path::Path;
use tree_sitter::{Node, Tree};

/// The maximum character length of the extracted function block before
/// falling back to a ±15 line window. Approximates 2,000 tokens.
const MAX_BLOCK_CHARS: usize = 1_500;

/// Number of lines above and below the vulnerable line used for the fallback
/// window when the function block exceeds `MAX_BLOCK_CHARS`.
const FALLBACK_WINDOW_LINES: usize = 15;

/// Extracted micro-context for a vulnerable line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroContext {
    /// The text of the smallest enclosing function block (or a ±15 line
    /// window if the block exceeds the token cap).
    pub function_block: String,
    /// All identifier names found within the extracted block.
    pub in_scope_variables: Vec<String>,
}

/// Extracts a `MicroContext` from source files using tree-sitter.
pub struct MicroContextExtractor;

impl MicroContextExtractor {
    /// Extract the micro-context for a vulnerable line.
    ///
    /// # Arguments
    /// - `file_content` — full source text of the file.
    /// - `vulnerable_line` — 1-indexed line number of the vulnerability.
    /// - `lang` — programming language of the file.
    ///
    /// # Algorithm
    /// 1. Parse the file with tree-sitter.
    /// 2. Find the AST node that starts on `vulnerable_line`.
    /// 3. Walk up the AST to find the nearest enclosing function-like node.
    /// 4. Extract the text of that node.
    /// 5. If the text exceeds `MAX_BLOCK_CHARS`, fall back to a ±15 line window.
    /// 6. Collect all `identifier` nodes within the extracted block.
    pub fn extract(file_content: &str, vulnerable_line: usize, lang: Language) -> MicroContext {
        // Parse the source with a fresh parser (no file path needed here).
        let temp_dir = std::env::temp_dir();
        let engine_result = TreeSitterEngine::new(&temp_dir);

        let tree_opt: Option<Tree> = engine_result
            .ok()
            .and_then(|engine| engine.parse_source(file_content, lang).ok());

        if let Some(tree) = tree_opt {
            let root = tree.root_node();
            // Convert 1-indexed line to 0-indexed for tree-sitter.
            let target_row = vulnerable_line.saturating_sub(1);

            // Find the deepest node that contains the target row.
            if let Some(target_node) = find_node_at_row(root, target_row) {
                // Walk up to find the nearest enclosing function-like node.
                if let Some(func_node) = find_enclosing_function(target_node) {
                    let block_text = func_node
                        .utf8_text(file_content.as_bytes())
                        .unwrap_or("")
                        .to_string();

                    if block_text.len() <= MAX_BLOCK_CHARS {
                        let identifiers = collect_identifiers(func_node, file_content);
                        return MicroContext {
                            function_block: block_text,
                            in_scope_variables: identifiers,
                        };
                    }
                    // Block too large — fall through to line-window fallback.
                }
            }
        }

        // Fallback: ±15 line window around the vulnerable line.
        let window = extract_line_window(file_content, vulnerable_line, FALLBACK_WINDOW_LINES);
        let identifiers = collect_identifiers_from_text(&window);
        MicroContext {
            function_block: window,
            in_scope_variables: identifiers,
        }
    }
}

// ── AST traversal helpers ─────────────────────────────────────────────────────

/// Find the deepest AST node whose range contains `target_row` (0-indexed).
fn find_node_at_row<'a>(root: Node<'a>, target_row: usize) -> Option<Node<'a>> {
    // Walk the tree to find the deepest node covering the target row.
    let mut cursor = root.walk();
    let mut best: Option<Node<'a>> = None;

    // Iterative DFS using the cursor.
    loop {
        let node = cursor.node();
        let start_row = node.start_position().row;
        let end_row = node.end_position().row;

        if start_row <= target_row && target_row <= end_row {
            best = Some(node);
            // Try to go deeper.
            if cursor.goto_first_child() {
                continue;
            }
        }

        // Try next sibling, then parent's next sibling.
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                return best;
            }
            // If we've gone back above the target range, stop.
            let parent = cursor.node();
            if parent.start_position().row > target_row {
                return best;
            }
        }
    }
}

/// Node kinds that represent function-like constructs across supported languages.
///
/// These are the tree-sitter node type names for:
/// - JavaScript/TypeScript: function declarations, arrow functions, methods,
///   function expressions, generator functions.
/// - Python: function definitions, async function definitions.
/// - Rust: function items.
/// - Go: function declarations, method declarations.
/// - Java: method declarations, constructor declarations.
const FUNCTION_NODE_KINDS: &[&str] = &[
    // JavaScript / TypeScript
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function",
    "generator_function_declaration",
    // Python
    "function_definition",
    "async_function_definition",
    // Rust
    "function_item",
    // Go
    "function_declaration",
    "method_declaration",
    // Java
    "method_declaration",
    "constructor_declaration",
];

/// Walk up the AST from `node` to find the nearest enclosing function-like node.
fn find_enclosing_function<'a>(mut node: Node<'a>) -> Option<Node<'a>> {
    // Check the node itself first, then walk up.
    loop {
        if FUNCTION_NODE_KINDS.contains(&node.kind()) {
            return Some(node);
        }
        match node.parent() {
            Some(parent) => node = parent,
            None => return None,
        }
    }
}

/// Collect all `identifier` node texts within `root_node`.
fn collect_identifiers(root_node: Node<'_>, source: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    collect_identifiers_recursive(root_node, source, &mut seen);
    let mut result: Vec<String> = seen.into_iter().collect();
    result.sort();
    result
}

fn collect_identifiers_recursive(node: Node<'_>, source: &str, seen: &mut HashSet<String>) {
    if node.kind() == "identifier" {
        if let Ok(text) = node.utf8_text(source.as_bytes()) {
            let s = text.trim().to_string();
            if !s.is_empty() {
                seen.insert(s);
            }
        }
    }
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            collect_identifiers_recursive(cursor.node(), source, seen);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

// ── Line-window fallback ──────────────────────────────────────────────────────

/// Extract a ±`window` line slice around `vulnerable_line` (1-indexed).
fn extract_line_window(content: &str, vulnerable_line: usize, window: usize) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    if total == 0 {
        return String::new();
    }

    // Convert to 0-indexed.
    let center = vulnerable_line.saturating_sub(1).min(total - 1);
    let start = center.saturating_sub(window);
    let end = (center + window + 1).min(total);

    lines[start..end].join("\n")
}

/// Extract identifiers from plain text using a simple tokeniser.
///
/// Used for the line-window fallback where we don't have an AST.
/// Splits on non-alphanumeric/underscore characters and keeps tokens that
/// look like identifiers (start with a letter or underscore).
fn collect_identifiers_from_text(text: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    for token in text.split(|c: char| !c.is_alphanumeric() && c != '_') {
        let t = token.trim();
        if !t.is_empty()
            && t.chars()
                .next()
                .map(|c| c.is_alphabetic() || c == '_')
                .unwrap_or(false)
        {
            seen.insert(t.to_string());
        }
    }
    let mut result: Vec<String> = seen.into_iter().collect();
    result.sort();
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── JavaScript arrow function ─────────────────────────────────────────────

    #[test]
    fn test_extract_js_arrow_function() {
        let source = r#"
const greet = (name) => {
    const message = "Hello, " + name;
    return message;
};

const other = () => 42;
"#;
        // Line 3 is inside the arrow function body.
        let ctx = MicroContextExtractor::extract(source, 3, Language::JavaScript);

        // The extracted block should contain the arrow function.
        assert!(
            ctx.function_block.contains("greet") || ctx.function_block.contains("message"),
            "Expected arrow function block, got: {}",
            ctx.function_block
        );
        // Identifiers should include variables used in the function.
        assert!(
            ctx.in_scope_variables.contains(&"name".to_string())
                || ctx.in_scope_variables.contains(&"message".to_string()),
            "Expected identifiers to include 'name' or 'message', got: {:?}",
            ctx.in_scope_variables
        );
    }

    // ── Python def ───────────────────────────────────────────────────────────

    #[test]
    fn test_extract_python_def() {
        let source = "def process_query(user_input):\n    query = \"SELECT * FROM users WHERE id = \" + user_input\n    return query\n\ndef other():\n    pass\n";
        // Line 2 is inside process_query.
        let ctx = MicroContextExtractor::extract(source, 2, Language::Python);

        assert!(
            ctx.function_block.contains("process_query")
                || ctx.function_block.contains("user_input"),
            "Expected Python function block, got: {}",
            ctx.function_block
        );
        assert!(
            ctx.in_scope_variables.contains(&"user_input".to_string())
                || ctx.in_scope_variables.contains(&"query".to_string()),
            "Expected identifiers to include 'user_input' or 'query', got: {:?}",
            ctx.in_scope_variables
        );
    }

    // ── TypeScript method ─────────────────────────────────────────────────────

    #[test]
    fn test_extract_typescript_method() {
        let source = r#"
class UserService {
    async findUser(userId: string): Promise<User> {
        const result = await this.db.query(userId);
        return result;
    }

    otherMethod() {
        return null;
    }
}
"#;
        // Line 4 is inside findUser.
        let ctx = MicroContextExtractor::extract(source, 4, Language::TypeScript);

        assert!(
            ctx.function_block.contains("findUser") || ctx.function_block.contains("userId"),
            "Expected TypeScript method block, got: {}",
            ctx.function_block
        );
        assert!(
            ctx.in_scope_variables.contains(&"userId".to_string())
                || ctx.in_scope_variables.contains(&"result".to_string()),
            "Expected identifiers to include 'userId' or 'result', got: {:?}",
            ctx.in_scope_variables
        );
    }

    // ── Identifier list completeness ──────────────────────────────────────────

    #[test]
    fn test_identifier_list_is_complete() {
        let source = r#"
function computeTotal(price, quantity, discount) {
    const subtotal = price * quantity;
    const total = subtotal - discount;
    return total;
}
"#;
        let ctx = MicroContextExtractor::extract(source, 3, Language::JavaScript);

        // All parameter and local variable names should appear.
        for name in &["price", "quantity", "discount", "subtotal", "total"] {
            assert!(
                ctx.in_scope_variables.contains(&name.to_string()),
                "Expected '{}' in identifiers, got: {:?}",
                name,
                ctx.in_scope_variables
            );
        }
    }

    // ── Token cap triggers fallback ───────────────────────────────────────────

    #[test]
    fn test_cap_triggers_line_window_fallback() {
        // Build a function that is definitely > 1500 chars.
        let mut source = String::from("function bigFunction(input) {\n");
        for i in 0..200 {
            source.push_str(&format!("    const var_{i} = input + {i};\n"));
        }
        source.push_str("    return var_0;\n}\n");

        // The function body is well over 1500 chars.
        assert!(source.len() > MAX_BLOCK_CHARS);

        // Line 5 is inside the function.
        let ctx = MicroContextExtractor::extract(&source, 5, Language::JavaScript);

        // The fallback window should be much smaller than the full function.
        let window_line_count = ctx.function_block.lines().count();
        assert!(
            window_line_count <= (FALLBACK_WINDOW_LINES * 2 + 1),
            "Expected fallback window of at most {} lines, got {}",
            FALLBACK_WINDOW_LINES * 2 + 1,
            window_line_count
        );
    }

    // ── Line window fallback helper ───────────────────────────────────────────

    #[test]
    fn test_line_window_at_start_of_file() {
        let content = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj";
        let window = extract_line_window(content, 1, 3);
        // Should not go below line 0.
        let lines: Vec<&str> = window.lines().collect();
        assert!(lines.contains(&"a"));
        assert!(lines.contains(&"b"));
        assert!(lines.contains(&"c"));
        assert!(lines.contains(&"d"));
    }

    #[test]
    fn test_line_window_at_end_of_file() {
        let content = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj";
        let window = extract_line_window(content, 10, 3);
        let lines: Vec<&str> = window.lines().collect();
        assert!(lines.contains(&"j"));
        assert!(lines.contains(&"g"));
    }

    // ── Identifier extraction from text ──────────────────────────────────────

    #[test]
    fn test_collect_identifiers_from_text_basic() {
        let text = "const foo = bar + baz;";
        let ids = collect_identifiers_from_text(text);
        assert!(ids.contains(&"const".to_string()));
        assert!(ids.contains(&"foo".to_string()));
        assert!(ids.contains(&"bar".to_string()));
        assert!(ids.contains(&"baz".to_string()));
    }

    #[test]
    fn test_collect_identifiers_from_text_excludes_numbers() {
        let text = "x = 42 + y;";
        let ids = collect_identifiers_from_text(text);
        assert!(ids.contains(&"x".to_string()));
        assert!(ids.contains(&"y".to_string()));
        // "42" starts with a digit, should not be included.
        assert!(!ids.contains(&"42".to_string()));
    }

    // ── No enclosing function (top-level code) ────────────────────────────────

    #[test]
    fn test_extract_top_level_code_falls_back_to_window() {
        let source = "const x = 1;\nconst y = 2;\nconst z = x + y;\n";
        // Line 2 is top-level, no enclosing function.
        let ctx = MicroContextExtractor::extract(source, 2, Language::JavaScript);
        // Should still return something useful.
        assert!(!ctx.function_block.is_empty());
    }
}
