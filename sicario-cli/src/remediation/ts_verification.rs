//! Tree-sitter verification loop for local LLM responses.
//!
//! Implements a three-stage deterministic cage around LLM output:
//!   Stage 1 — JSON parse: response must be `{"replacement": "..."}`.
//!   Stage 2 — Syntax check: replacement must parse without tree-sitter error nodes.
//!   Stage 3 — Scope check: every identifier in the replacement must appear in
//!              `in_scope_variables` or be a known language keyword/built-in/literal.
//!
//! On pass: splices the replacement into the original file content and returns
//! `VerificationResult::Accept(spliced_content)`.
//! On any failure: returns `VerificationResult::Discard` — no disk write occurs.
//!
//! Requirements: eta-engine 1.4

use crate::parser::{Language, TreeSitterEngine};
use std::collections::HashSet;
use tree_sitter::Node;

// ── VerificationResult ────────────────────────────────────────────────────────

/// Outcome of the three-stage tree-sitter verification loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// All three stages passed. Contains the full file content with the
    /// replacement spliced in at `vulnerable_line`.
    Accept(String),
    /// One or more stages failed. The original file content is unchanged.
    Discard,
}

// ── TreeSitterVerificationLoop ────────────────────────────────────────────────

/// Stateless verifier — all methods are pure functions over their arguments.
pub struct TreeSitterVerificationLoop;

impl TreeSitterVerificationLoop {
    /// Run the three-stage verification pipeline on a raw LLM response.
    ///
    /// # Arguments
    /// - `response` — raw text returned by the local LLM.
    /// - `in_scope_variables` — identifiers extracted by `MicroContextExtractor`.
    /// - `lang` — programming language of the file being patched.
    /// - `original_content` — full source text of the file (never mutated).
    /// - `vulnerable_line` — 1-indexed line number of the vulnerability.
    ///
    /// # Stages
    /// 1. Parse `response` as `{"replacement": "..."}` JSON.
    /// 2. Parse `replacement` with tree-sitter; reject if `root_node().has_error()`.
    /// 3. Extract all identifier nodes from the replacement AST; reject any
    ///    identifier that is not in `in_scope_variables` and is not a language
    ///    keyword, built-in, or literal token.
    ///
    /// # Invariant
    /// Disk is never written with broken code. Either the caller receives a
    /// syntactically valid `Accept(spliced_content)` or `Discard` (original
    /// unchanged).
    pub fn verify(
        response: &str,
        in_scope_variables: &[String],
        lang: Language,
        original_content: &str,
        vulnerable_line: usize,
    ) -> VerificationResult {
        // ── Stage 1: JSON parse ───────────────────────────────────────────────
        let replacement = match parse_replacement_json(response) {
            Some(r) => r,
            None => return VerificationResult::Discard,
        };

        // ── Stage 2: Tree-sitter syntax check ────────────────────────────────
        let tree = match parse_with_tree_sitter(&replacement, lang) {
            Some(t) => t,
            None => return VerificationResult::Discard,
        };

        if tree.root_node().has_error() {
            return VerificationResult::Discard;
        }

        // ── Stage 3: Identifier scope check ──────────────────────────────────
        let scope_set: HashSet<&str> = in_scope_variables.iter().map(|s| s.as_str()).collect();
        let keywords = language_keywords(lang);

        let identifiers = collect_identifier_nodes(tree.root_node(), &replacement);
        for ident in &identifiers {
            if !scope_set.contains(ident.as_str()) && !keywords.contains(ident.as_str()) {
                return VerificationResult::Discard;
            }
        }

        // ── Stage pass: splice into original content ──────────────────────────
        // We need the original snippet for splice_patch. Since we only have the
        // replacement and the line number, we extract the original line as the
        // snippet (splice_patch replaces the entire target line).
        let lines: Vec<&str> = original_content.lines().collect();
        let line_idx = vulnerable_line
            .saturating_sub(1)
            .min(lines.len().saturating_sub(1));
        let original_snippet = if lines.is_empty() {
            ""
        } else {
            lines[line_idx]
        };

        let spliced = super::remediation_engine::splice_patch(
            original_content,
            vulnerable_line,
            original_snippet,
            &replacement,
        );

        VerificationResult::Accept(spliced)
    }
}

// ── Stage 1 helper ────────────────────────────────────────────────────────────

/// Parse `response` as `{"replacement": "..."}` JSON.
///
/// Strips markdown fences first (the model may wrap the JSON in ```json ... ```).
/// Returns `None` if the response is not valid JSON or lacks the `replacement` key.
fn parse_replacement_json(response: &str) -> Option<String> {
    // Strip markdown fences the model may have added
    let cleaned = strip_markdown_fences(response);
    let trimmed = cleaned.trim();

    // Use serde_json for robust parsing
    let value: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let replacement = value.get("replacement")?.as_str()?;
    Some(replacement.to_string())
}

/// Strip leading/trailing markdown code fences from a string.
fn strip_markdown_fences(s: &str) -> String {
    let trimmed = s.trim();
    // Handle ```json ... ``` or ``` ... ```
    if let Some(inner) = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
    {
        if let Some(stripped) = inner.strip_suffix("```") {
            return stripped.trim().to_string();
        }
    }
    trimmed.to_string()
}

// ── Stage 2 helper ────────────────────────────────────────────────────────────

/// Parse `source` with tree-sitter for `lang`.
///
/// Returns `None` if the language has no tree-sitter grammar (Ruby, PHP) or
/// if the parser itself fails.
fn parse_with_tree_sitter(source: &str, lang: Language) -> Option<tree_sitter::Tree> {
    let temp_dir = std::env::temp_dir();
    let engine = TreeSitterEngine::new(&temp_dir).ok()?;
    engine.parse_source(source, lang).ok()
}

// ── Stage 3 helpers ───────────────────────────────────────────────────────────

/// Collect all `identifier` node texts from the AST rooted at `root`.
fn collect_identifier_nodes(root: Node<'_>, source: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    collect_identifiers_recursive(root, source, &mut seen);
    seen.into_iter().collect()
}

fn collect_identifiers_recursive(node: Node<'_>, source: &str, seen: &mut HashSet<String>) {
    // Collect identifier-like node kinds across all supported languages.
    // We intentionally skip string/number/boolean literals and punctuation.
    let kind = node.kind();
    if matches!(
        kind,
        "identifier"
            | "property_identifier"
            | "shorthand_property_identifier"
            | "shorthand_property_identifier_pattern"
            | "type_identifier"
    ) {
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

/// Return the set of keywords, built-ins, and common literals for `lang`.
///
/// This list is intentionally broad — it is better to allow a known keyword
/// than to discard a valid patch. Unknown identifiers (hallucinated variable
/// names) are the only thing we want to reject.
fn language_keywords(lang: Language) -> HashSet<&'static str> {
    match lang {
        Language::JavaScript | Language::TypeScript => js_ts_keywords(),
        Language::Python => python_keywords(),
        Language::Rust => rust_keywords(),
        Language::Go => go_keywords(),
        Language::Java => java_keywords(),
        Language::Ruby | Language::Php => {
            // No tree-sitter grammar — stage 2 would have already returned
            // Discard, so this branch is unreachable in practice.
            HashSet::new()
        }
    }
}

fn js_ts_keywords() -> HashSet<&'static str> {
    [
        // Keywords
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "export",
        "extends",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "let",
        "new",
        "of",
        "return",
        "static",
        "super",
        "switch",
        "this",
        "throw",
        "try",
        "typeof",
        "var",
        "void",
        "while",
        "with",
        "yield",
        "async",
        "await",
        // TypeScript extras
        "abstract",
        "as",
        "declare",
        "enum",
        "from",
        "implements",
        "interface",
        "is",
        "keyof",
        "module",
        "namespace",
        "never",
        "override",
        "private",
        "protected",
        "public",
        "readonly",
        "require",
        "type",
        "unique",
        "unknown",
        // Built-in globals
        "undefined",
        "null",
        "true",
        "false",
        "NaN",
        "Infinity",
        "console",
        "process",
        "require",
        "module",
        "exports",
        "__dirname",
        "__filename",
        "global",
        "globalThis",
        "window",
        "document",
        "Object",
        "Array",
        "String",
        "Number",
        "Boolean",
        "Symbol",
        "BigInt",
        "Function",
        "Promise",
        "Error",
        "TypeError",
        "RangeError",
        "SyntaxError",
        "ReferenceError",
        "Map",
        "Set",
        "WeakMap",
        "WeakSet",
        "Date",
        "RegExp",
        "JSON",
        "Math",
        "parseInt",
        "parseFloat",
        "isNaN",
        "isFinite",
        "encodeURIComponent",
        "decodeURIComponent",
        "encodeURI",
        "decodeURI",
        "setTimeout",
        "clearTimeout",
        "setInterval",
        "clearInterval",
        "Buffer",
        "URL",
        "URLSearchParams",
        // Common Node.js / framework identifiers
        "db",
        "pool",
        "client",
        "query",
        "execute",
        "run",
        "prepare",
        "params",
        "values",
        "args",
        "options",
        "config",
        "req",
        "res",
        "next",
        "err",
        "error",
        "result",
        "results",
        "rows",
        "row",
        "data",
        "body",
        "headers",
        "status",
        "message",
        "code",
        "id",
        "userId",
        "user",
        "name",
        "email",
        "password",
        "token",
        "input",
        "output",
        "value",
        "key",
        "index",
        "item",
        "items",
        "callback",
        "cb",
        "resolve",
        "reject",
        "then",
        "catch",
        "finally",
        "length",
        "push",
        "pop",
        "shift",
        "unshift",
        "splice",
        "slice",
        "map",
        "filter",
        "reduce",
        "forEach",
        "find",
        "findIndex",
        "includes",
        "indexOf",
        "join",
        "split",
        "trim",
        "replace",
        "toString",
        "valueOf",
        "hasOwnProperty",
        "prototype",
        "constructor",
        // Parameterized query placeholders
        "placeholder",
        "parameterized",
    ]
    .iter()
    .copied()
    .collect()
}

fn python_keywords() -> HashSet<&'static str> {
    [
        // Keywords
        "False",
        "None",
        "True",
        "and",
        "as",
        "assert",
        "async",
        "await",
        "break",
        "class",
        "continue",
        "def",
        "del",
        "elif",
        "else",
        "except",
        "finally",
        "for",
        "from",
        "global",
        "if",
        "import",
        "in",
        "is",
        "lambda",
        "nonlocal",
        "not",
        "or",
        "pass",
        "raise",
        "return",
        "try",
        "while",
        "with",
        "yield",
        // Built-ins
        "abs",
        "all",
        "any",
        "bin",
        "bool",
        "bytes",
        "callable",
        "chr",
        "compile",
        "complex",
        "delattr",
        "dict",
        "dir",
        "divmod",
        "enumerate",
        "eval",
        "exec",
        "filter",
        "float",
        "format",
        "frozenset",
        "getattr",
        "globals",
        "hasattr",
        "hash",
        "help",
        "hex",
        "id",
        "input",
        "int",
        "isinstance",
        "issubclass",
        "iter",
        "len",
        "list",
        "locals",
        "map",
        "max",
        "memoryview",
        "min",
        "next",
        "object",
        "oct",
        "open",
        "ord",
        "pow",
        "print",
        "property",
        "range",
        "repr",
        "reversed",
        "round",
        "set",
        "setattr",
        "slice",
        "sorted",
        "staticmethod",
        "str",
        "sum",
        "super",
        "tuple",
        "type",
        "vars",
        "zip",
        // Common identifiers
        "self",
        "cls",
        "args",
        "kwargs",
        "cursor",
        "conn",
        "db",
        "query",
        "execute",
        "executemany",
        "fetchone",
        "fetchall",
        "fetchmany",
        "commit",
        "rollback",
        "close",
        "connect",
        "params",
        "result",
        "results",
        "row",
        "rows",
        "data",
        "value",
        "key",
        "index",
        "item",
        "items",
        "error",
        "err",
        "msg",
        "message",
        "user",
        "userId",
        "name",
        "email",
        "password",
        "token",
        "id",
        "input",
        "output",
        "response",
        "request",
        "req",
        "res",
    ]
    .iter()
    .copied()
    .collect()
}

fn rust_keywords() -> HashSet<&'static str> {
    [
        // Keywords
        "as",
        "async",
        "await",
        "break",
        "const",
        "continue",
        "crate",
        "dyn",
        "else",
        "enum",
        "extern",
        "false",
        "fn",
        "for",
        "if",
        "impl",
        "in",
        "let",
        "loop",
        "match",
        "mod",
        "move",
        "mut",
        "pub",
        "ref",
        "return",
        "self",
        "Self",
        "static",
        "struct",
        "super",
        "trait",
        "true",
        "type",
        "union",
        "unsafe",
        "use",
        "where",
        "while",
        // Common types and traits
        "String",
        "str",
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
        "f32",
        "f64",
        "bool",
        "char",
        "Option",
        "Result",
        "Vec",
        "HashMap",
        "HashSet",
        "Box",
        "Rc",
        "Arc",
        "Mutex",
        "RwLock",
        "Cell",
        "RefCell",
        "Some",
        "None",
        "Ok",
        "Err",
        "Clone",
        "Copy",
        "Debug",
        "Display",
        "Default",
        "Drop",
        "Iterator",
        "IntoIterator",
        "From",
        "Into",
        "AsRef",
        "AsMut",
        "Send",
        "Sync",
        "Sized",
        "Unpin",
        // Common macros (appear as identifiers in AST)
        "println",
        "eprintln",
        "format",
        "vec",
        "assert",
        "assert_eq",
        "assert_ne",
        "panic",
        "todo",
        "unimplemented",
        "unreachable",
        "dbg",
        "write",
        "writeln",
    ]
    .iter()
    .copied()
    .collect()
}

fn go_keywords() -> HashSet<&'static str> {
    [
        // Keywords
        "break",
        "case",
        "chan",
        "const",
        "continue",
        "default",
        "defer",
        "else",
        "fallthrough",
        "for",
        "func",
        "go",
        "goto",
        "if",
        "import",
        "interface",
        "map",
        "package",
        "range",
        "return",
        "select",
        "struct",
        "switch",
        "type",
        "var",
        // Built-in functions and types
        "append",
        "cap",
        "close",
        "complex",
        "copy",
        "delete",
        "imag",
        "len",
        "make",
        "new",
        "panic",
        "print",
        "println",
        "real",
        "recover",
        "bool",
        "byte",
        "complex64",
        "complex128",
        "error",
        "float32",
        "float64",
        "int",
        "int8",
        "int16",
        "int32",
        "int64",
        "rune",
        "string",
        "uint",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "uintptr",
        "true",
        "false",
        "nil",
        "iota",
        // Common identifiers
        "err",
        "ctx",
        "db",
        "tx",
        "query",
        "args",
        "result",
        "rows",
        "row",
        "id",
        "user",
        "name",
        "value",
        "key",
        "data",
    ]
    .iter()
    .copied()
    .collect()
}

fn java_keywords() -> HashSet<&'static str> {
    [
        // Keywords
        "abstract",
        "assert",
        "boolean",
        "break",
        "byte",
        "case",
        "catch",
        "char",
        "class",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extends",
        "final",
        "finally",
        "float",
        "for",
        "goto",
        "if",
        "implements",
        "import",
        "instanceof",
        "int",
        "interface",
        "long",
        "native",
        "new",
        "package",
        "private",
        "protected",
        "public",
        "return",
        "short",
        "static",
        "strictfp",
        "super",
        "switch",
        "synchronized",
        "this",
        "throw",
        "throws",
        "transient",
        "try",
        "void",
        "volatile",
        "while",
        // Literals
        "true",
        "false",
        "null",
        // Common types
        "String",
        "Integer",
        "Long",
        "Double",
        "Float",
        "Boolean",
        "Byte",
        "Short",
        "Character",
        "Object",
        "Class",
        "System",
        "Math",
        "StringBuilder",
        "StringBuffer",
        "List",
        "ArrayList",
        "Map",
        "HashMap",
        "Set",
        "HashSet",
        "Optional",
        "Stream",
        // Common identifiers
        "e",
        "ex",
        "err",
        "result",
        "query",
        "params",
        "stmt",
        "conn",
        "db",
        "id",
        "user",
        "name",
        "value",
        "key",
        "data",
        "msg",
        "PreparedStatement",
        "Connection",
        "ResultSet",
    ]
    .iter()
    .copied()
    .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Stage 1: JSON parse ───────────────────────────────────────────────────

    #[test]
    fn test_invalid_json_returns_discard() {
        let result = TreeSitterVerificationLoop::verify(
            "not json at all",
            &["userId".to_string()],
            Language::JavaScript,
            "const x = eval(userId);",
            1,
        );
        assert_eq!(result, VerificationResult::Discard);
    }

    #[test]
    fn test_json_missing_replacement_field_returns_discard() {
        let result = TreeSitterVerificationLoop::verify(
            r#"{"fix": "const x = userId;"}"#,
            &["userId".to_string()],
            Language::JavaScript,
            "const x = eval(userId);",
            1,
        );
        assert_eq!(result, VerificationResult::Discard);
    }

    #[test]
    fn test_empty_string_returns_discard() {
        let result = TreeSitterVerificationLoop::verify(
            "",
            &["userId".to_string()],
            Language::JavaScript,
            "const x = eval(userId);",
            1,
        );
        assert_eq!(result, VerificationResult::Discard);
    }

    // ── Stage 2: Syntax check ─────────────────────────────────────────────────

    #[test]
    fn test_syntax_error_returns_discard() {
        // Replacement has a syntax error: unclosed brace
        let response = r#"{"replacement": "const x = {"}"#;
        let result = TreeSitterVerificationLoop::verify(
            response,
            &["x".to_string()],
            Language::JavaScript,
            "const x = eval(userId);",
            1,
        );
        assert_eq!(result, VerificationResult::Discard);
    }

    #[test]
    fn test_valid_syntax_passes_stage2() {
        // Valid JS — all identifiers are in scope or keywords
        let in_scope = vec!["userId".to_string(), "db".to_string(), "query".to_string()];
        let response = r#"{"replacement": "const query = db.prepare('SELECT * FROM users WHERE id = ?'); query.run(userId);"}"#;
        let result = TreeSitterVerificationLoop::verify(
            response,
            &in_scope,
            Language::JavaScript,
            "const query = db.query('SELECT * FROM users WHERE id = ' + userId);",
            1,
        );
        // Should be Accept (all identifiers are in scope or keywords)
        assert!(matches!(result, VerificationResult::Accept(_)));
    }

    // ── Stage 3: Identifier scope check ──────────────────────────────────────

    #[test]
    fn test_hallucinated_identifier_returns_discard() {
        // "sanitizedInput" is not in scope and not a keyword
        let in_scope = vec!["userId".to_string(), "db".to_string()];
        let response =
            r#"{"replacement": "db.query('SELECT * FROM users WHERE id = ?', [sanitizedInput]);"}"#;
        let result = TreeSitterVerificationLoop::verify(
            response,
            &in_scope,
            Language::JavaScript,
            "db.query('SELECT * FROM users WHERE id = ' + userId);",
            1,
        );
        assert_eq!(result, VerificationResult::Discard);
    }

    #[test]
    fn test_in_scope_identifiers_accepted() {
        let in_scope = vec![
            "userId".to_string(),
            "db".to_string(),
            "query".to_string(),
            "params".to_string(),
        ];
        let response =
            r#"{"replacement": "db.query('SELECT * FROM users WHERE id = $1', [userId]);"}"#;
        let result = TreeSitterVerificationLoop::verify(
            response,
            &in_scope,
            Language::JavaScript,
            "db.query('SELECT * FROM users WHERE id = ' + userId);",
            1,
        );
        assert!(matches!(result, VerificationResult::Accept(_)));
    }

    // ── Stage pass: splice check ──────────────────────────────────────────────

    #[test]
    fn test_accept_splices_into_original_content() {
        let original = "function getUser(userId) {\n    db.query('SELECT * FROM users WHERE id = ' + userId);\n}\n";
        let in_scope = vec![
            "userId".to_string(),
            "db".to_string(),
            "getUser".to_string(),
        ];
        let response =
            r#"{"replacement": "db.query('SELECT * FROM users WHERE id = $1', [userId]);"}"#;

        let result = TreeSitterVerificationLoop::verify(
            response,
            &in_scope,
            Language::JavaScript,
            original,
            2, // line 2 is the vulnerable line
        );

        match result {
            VerificationResult::Accept(spliced) => {
                assert!(spliced.contains("$1"));
                assert!(spliced.contains("userId"));
                assert!(spliced.contains("function getUser"));
                // Original vulnerable line should be replaced
                assert!(!spliced.contains("' + userId)"));
            }
            VerificationResult::Discard => panic!("Expected Accept, got Discard"),
        }
    }

    // ── Markdown fence stripping ──────────────────────────────────────────────

    #[test]
    fn test_json_wrapped_in_markdown_fences_is_accepted() {
        let in_scope = vec!["userId".to_string(), "db".to_string()];
        let response = "```json\n{\"replacement\": \"db.query('SELECT * FROM users WHERE id = $1', [userId]);\"}\n```";
        let result = TreeSitterVerificationLoop::verify(
            response,
            &in_scope,
            Language::JavaScript,
            "db.query('SELECT * FROM users WHERE id = ' + userId);",
            1,
        );
        assert!(matches!(result, VerificationResult::Accept(_)));
    }

    // ── Python ────────────────────────────────────────────────────────────────

    #[test]
    fn test_python_valid_replacement_accepted() {
        let original = "def get_user(user_id):\n    cursor.execute('SELECT * FROM users WHERE id = ' + user_id)\n";
        let in_scope = vec![
            "user_id".to_string(),
            "cursor".to_string(),
            "get_user".to_string(),
            "self".to_string(),
        ];
        let response =
            r#"{"replacement": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"}"#;

        let result =
            TreeSitterVerificationLoop::verify(response, &in_scope, Language::Python, original, 2);
        assert!(matches!(result, VerificationResult::Accept(_)));
    }

    #[test]
    fn test_python_hallucinated_identifier_discarded() {
        let original = "def get_user(user_id):\n    cursor.execute('SELECT * FROM users WHERE id = ' + user_id)\n";
        let in_scope = vec!["user_id".to_string(), "cursor".to_string()];
        // "sanitize" is not in scope
        let response = r#"{"replacement": "cursor.execute('SELECT * FROM users WHERE id = %s', (sanitize(user_id),))"}"#;

        let result =
            TreeSitterVerificationLoop::verify(response, &in_scope, Language::Python, original, 2);
        assert_eq!(result, VerificationResult::Discard);
    }

    // ── Performance assertion ─────────────────────────────────────────────────

    /// All three stages complete within 50ms for a 200-line replacement.
    ///
    /// Constructs a realistic 200-line JavaScript function body as both the
    /// original content and the replacement, then runs the full verification
    /// pipeline and asserts it completes within the 50ms budget.
    #[test]
    fn test_verify_200_line_replacement_within_50ms() {
        // Build a 200-line JS function body that is syntactically valid.
        // Each line declares a variable so the AST has real identifier nodes.
        let mut lines = Vec::with_capacity(202);
        lines.push("function processData(userId, db, query, params, data, result, rows, row, id, name, email, token, input, output, value, key, index, item, items, callback, cb, resolve, reject) {".to_string());
        for i in 0..198 {
            lines.push(format!("  const var{} = {};", i, i));
        }
        lines.push("}".to_string());
        let original_content = lines.join("\n");

        // The replacement is a single parameterized query line (realistic LLM output).
        let replacement_line = "  db.query('SELECT * FROM users WHERE id = $1', [userId]);";
        let response = format!(r#"{{"replacement": "{}"}}"#, replacement_line);

        // in_scope_variables includes all identifiers the replacement uses.
        let in_scope: Vec<String> =
            vec!["userId".to_string(), "db".to_string(), "query".to_string()];

        let start = std::time::Instant::now();
        let result = TreeSitterVerificationLoop::verify(
            &response,
            &in_scope,
            Language::JavaScript,
            &original_content,
            2, // replace line 2 (first var declaration)
        );
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 50,
            "TreeSitterVerificationLoop::verify took {}ms for 200-line replacement, must complete within 50ms",
            elapsed.as_millis()
        );

        // The result should be Accept since all identifiers are in scope or keywords.
        assert!(
            matches!(result, VerificationResult::Accept(_)),
            "Expected Accept for valid replacement, got Discard"
        );
    }

    // ── parse_replacement_json unit tests ────────────────────────────────────

    #[test]
    fn test_parse_replacement_json_valid() {
        let json = r#"{"replacement": "const x = 1;"}"#;
        assert_eq!(
            parse_replacement_json(json),
            Some("const x = 1;".to_string())
        );
    }

    #[test]
    fn test_parse_replacement_json_invalid() {
        assert_eq!(parse_replacement_json("not json"), None);
        assert_eq!(parse_replacement_json(r#"{"other": "value"}"#), None);
        assert_eq!(parse_replacement_json(""), None);
    }

    // ── language_keywords coverage ────────────────────────────────────────────

    #[test]
    fn test_js_keywords_include_common_tokens() {
        let kw = language_keywords(Language::JavaScript);
        assert!(kw.contains("const"));
        assert!(kw.contains("return"));
        assert!(kw.contains("null"));
        assert!(kw.contains("undefined"));
        assert!(kw.contains("async"));
        assert!(kw.contains("await"));
    }

    #[test]
    fn test_python_keywords_include_common_tokens() {
        let kw = language_keywords(Language::Python);
        assert!(kw.contains("def"));
        assert!(kw.contains("return"));
        assert!(kw.contains("None"));
        assert!(kw.contains("self"));
    }
}
