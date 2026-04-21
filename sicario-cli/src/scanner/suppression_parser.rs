//! Inline suppression comment parser
//!
//! Detects suppression directives in source code comments:
//!
//! **Secret scanner (legacy):**
//! - `sicario-ignore-secret` — suppress secret findings on the next line
//!
//! **SAST scanner (new):**
//! - `sicario-ignore` — blanket suppress all SAST findings on the next line
//! - `sicario-ignore-next-line` — alias for `sicario-ignore`
//! - `sicario-ignore:<rule-id>` — suppress only the specified rule on the next line
//!
//! All directives are recognized in `//`, `#`, `/* */`, and `<!-- -->` comment styles.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// The legacy suppression directive for the secret scanner.
const SECRET_SUPPRESSION_DIRECTIVE: &str = "sicario-ignore-secret";

/// Blanket SAST suppression directive.
const SAST_IGNORE_DIRECTIVE: &str = "sicario-ignore";

/// Next-line alias for blanket SAST suppression.
const SAST_IGNORE_NEXT_LINE_DIRECTIVE: &str = "sicario-ignore-next-line";

/// Prefix for rule-specific SAST suppression (`sicario-ignore:<rule-id>`).
const SAST_IGNORE_RULE_PREFIX: &str = "sicario-ignore:";

/// The kind of suppression parsed from a comment line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuppressionKind {
    /// Suppress all findings (blanket).
    All,
    /// Suppress only the specified rule ID.
    Rule(String),
}

/// Result of checking whether a finding is suppressed.
#[derive(Debug, Clone)]
pub struct SuppressionResult {
    /// Whether the finding is suppressed.
    pub suppressed: bool,
    /// If suppressed by a rule-specific directive, the rule ID.
    pub rule_id: Option<String>,
}

/// Parser for detecting inline suppression comments.
///
/// When a suppression comment appears on line N, detection is skipped
/// for line N+1 (the next line of code).
pub struct SuppressionParser;

impl SuppressionParser {
    /// Create a new SuppressionParser
    pub fn new() -> Self {
        Self
    }

    // ── Legacy secret-scanner API (backward compatible) ───────────────────

    /// Check if the given line (1-indexed) is suppressed by a
    /// `sicario-ignore-secret` comment on the preceding line.
    pub fn check_suppression_comment(&self, file: &Path, target_line: usize) -> Result<bool> {
        if target_line == 0 {
            return Ok(false);
        }

        let source = std::fs::read_to_string(file)
            .with_context(|| format!("Failed to read file for suppression check: {:?}", file))?;

        Ok(self.is_suppressed_in_source(&source, target_line))
    }

    /// Check suppression directly from source text (avoids re-reading the file).
    ///
    /// `target_line` is 1-indexed. Returns true if the line immediately before
    /// `target_line` contains a suppression directive (legacy secret-scanner).
    pub fn is_suppressed_in_source(&self, source: &str, target_line: usize) -> bool {
        if target_line <= 1 {
            return false;
        }

        let preceding_line_idx = target_line - 2; // 0-indexed
        let lines: Vec<&str> = source.lines().collect();

        if preceding_line_idx >= lines.len() {
            return false;
        }

        let preceding = lines[preceding_line_idx];
        line_contains_secret_suppression(preceding)
    }

    /// Scan an entire source file and return the set of suppressed line numbers
    /// (1-indexed) for the legacy secret scanner.
    pub fn suppressed_lines_in_source(&self, source: &str) -> HashSet<usize> {
        let mut suppressed = HashSet::new();
        for (idx, line) in source.lines().enumerate() {
            if line_contains_secret_suppression(line) {
                suppressed.insert(idx + 2);
            }
        }
        suppressed
    }

    /// Scan a file and return all suppressed line numbers (1-indexed) for the
    /// legacy secret scanner.
    pub fn suppressed_lines(&self, file: &Path) -> Result<HashSet<usize>> {
        let source = std::fs::read_to_string(file)
            .with_context(|| format!("Failed to read file for suppression scan: {:?}", file))?;
        Ok(self.suppressed_lines_in_source(&source))
    }

    // ── New SAST suppression API ──────────────────────────────────────────

    /// Check whether a SAST finding at `target_line` (1-indexed) with the
    /// given `rule_id` is suppressed by a directive on the preceding line.
    pub fn is_sast_suppressed(
        &self,
        source: &str,
        target_line: usize,
        rule_id: &str,
    ) -> SuppressionResult {
        if target_line <= 1 {
            return SuppressionResult { suppressed: false, rule_id: None };
        }

        let preceding_line_idx = target_line - 2;
        let lines: Vec<&str> = source.lines().collect();

        if preceding_line_idx >= lines.len() {
            return SuppressionResult { suppressed: false, rule_id: None };
        }

        let preceding = lines[preceding_line_idx];
        match parse_sast_suppression(preceding) {
            Some(SuppressionKind::All) => SuppressionResult {
                suppressed: true,
                rule_id: None,
            },
            Some(SuppressionKind::Rule(ref rid)) if rid == rule_id => SuppressionResult {
                suppressed: true,
                rule_id: Some(rid.clone()),
            },
            _ => SuppressionResult { suppressed: false, rule_id: None },
        }
    }

    /// Scan source and return a map of line number (1-indexed) → suppression
    /// kind for all SAST suppression directives. The line number is the line
    /// that is suppressed (i.e. the line *after* the comment).
    pub fn sast_suppressed_lines(&self, source: &str) -> HashMap<usize, SuppressionKind> {
        let mut result = HashMap::new();
        for (idx, line) in source.lines().enumerate() {
            if let Some(kind) = parse_sast_suppression(line) {
                result.insert(idx + 2, kind); // next line is suppressed
            }
        }
        result
    }

    /// Count the number of suppressed findings in a source file.
    /// Returns the total count of SAST suppression directives found.
    pub fn count_sast_suppressions(&self, source: &str) -> usize {
        source.lines().filter(|l| parse_sast_suppression(l).is_some()).count()
    }
}

impl Default for SuppressionParser {
    fn default() -> Self {
        Self::new()
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Check whether a line contains the legacy `sicario-ignore-secret` directive.
fn line_contains_secret_suppression(line: &str) -> bool {
    let trimmed = line.trim();
    if !trimmed.contains(SECRET_SUPPRESSION_DIRECTIVE) {
        return false;
    }
    is_inside_comment(trimmed)
}

/// Check whether a trimmed line starts with a recognized comment marker.
fn is_inside_comment(trimmed: &str) -> bool {
    trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("<!--")
        || trimmed.starts_with("/*")
        || (trimmed.contains("//") || trimmed.contains('#'))
}

/// Parse a SAST suppression directive from a source line.
///
/// Returns `None` if the line does not contain a recognized directive.
fn parse_sast_suppression(line: &str) -> Option<SuppressionKind> {
    let trimmed = line.trim();

    // Must be inside a comment
    if !is_inside_comment(trimmed) {
        return None;
    }

    // Extract the comment body (strip comment markers)
    let body = extract_comment_body(trimmed);
    let body = body.trim();

    // Rule-specific: `sicario-ignore:<rule-id>`
    if let Some(rest) = body.strip_prefix(SAST_IGNORE_RULE_PREFIX) {
        let rule_id = rest.trim();
        if !rule_id.is_empty() {
            return Some(SuppressionKind::Rule(rule_id.to_string()));
        }
    }

    // Blanket: `sicario-ignore-next-line` (must check before `sicario-ignore`
    // since `sicario-ignore` is a prefix of `sicario-ignore-next-line`)
    if body.contains(SAST_IGNORE_NEXT_LINE_DIRECTIVE) {
        return Some(SuppressionKind::All);
    }

    // Blanket: `sicario-ignore` — but NOT `sicario-ignore-secret` (legacy)
    if body.contains(SAST_IGNORE_DIRECTIVE) {
        // Make sure it's not the secret directive or next-line (already handled)
        // We need to check that the match is exactly `sicario-ignore` and not
        // `sicario-ignore-secret` or `sicario-ignore-next-line` or `sicario-ignore:<rule>`.
        // Find the position and check what follows.
        if let Some(pos) = body.find(SAST_IGNORE_DIRECTIVE) {
            let after = &body[pos + SAST_IGNORE_DIRECTIVE.len()..];
            // If nothing follows, or whitespace follows, it's a blanket directive
            if after.is_empty() || after.starts_with(char::is_whitespace) {
                return Some(SuppressionKind::All);
            }
            // If ':' follows, it's a rule-specific directive (already handled above)
            // If '-secret' or '-next-line' follows, it's NOT a blanket directive
        }
    }

    None
}

/// Extract the body of a comment, stripping the comment markers.
fn extract_comment_body(trimmed: &str) -> &str {
    if let Some(rest) = trimmed.strip_prefix("//") {
        return rest;
    }
    if let Some(rest) = trimmed.strip_prefix('#') {
        return rest;
    }
    if let Some(rest) = trimmed.strip_prefix("<!--") {
        // Strip trailing -->
        return rest.strip_suffix("-->").unwrap_or(rest).trim();
    }
    if let Some(rest) = trimmed.strip_prefix("/*") {
        // Strip trailing */
        return rest.strip_suffix("*/").unwrap_or(rest).trim();
    }
    // Inline comment after code: find // or #
    if let Some(pos) = trimmed.find("//") {
        return &trimmed[pos + 2..];
    }
    if let Some(pos) = trimmed.find('#') {
        return &trimmed[pos + 1..];
    }
    trimmed
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_file(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    // ── Legacy secret-scanner unit tests ──────────────────────────────────

    #[test]
    fn test_js_suppression_comment() {
        let source = "// sicario-ignore-secret\nconst key = \"AKIAIOSFODNN7EXAMPLE\";";
        let parser = SuppressionParser::new();
        assert!(parser.is_suppressed_in_source(source, 2));
        assert!(!parser.is_suppressed_in_source(source, 1));
    }

    #[test]
    fn test_python_suppression_comment() {
        let source = "# sicario-ignore-secret\napi_key = \"sk_test_abc123def456ghij7890\"";
        let parser = SuppressionParser::new();
        assert!(parser.is_suppressed_in_source(source, 2));
    }

    #[test]
    fn test_html_suppression_comment() {
        let source = "<!-- sicario-ignore-secret -->\n<input value=\"secret\">";
        let parser = SuppressionParser::new();
        assert!(parser.is_suppressed_in_source(source, 2));
    }

    #[test]
    fn test_block_comment_suppression() {
        let source = "/* sicario-ignore-secret */\nconst token = \"ghp_abc\";";
        let parser = SuppressionParser::new();
        assert!(parser.is_suppressed_in_source(source, 2));
    }

    #[test]
    fn test_no_suppression_without_comment() {
        let source = "const key = \"AKIAIOSFODNN7EXAMPLE\";";
        let parser = SuppressionParser::new();
        assert!(!parser.is_suppressed_in_source(source, 1));
    }

    #[test]
    fn test_suppression_only_applies_to_next_line() {
        let source = "// sicario-ignore-secret\nconst key = \"secret\";\nconst other = \"also_secret\";";
        let parser = SuppressionParser::new();
        assert!(!parser.is_suppressed_in_source(source, 1));
        assert!(parser.is_suppressed_in_source(source, 2));
        assert!(!parser.is_suppressed_in_source(source, 3));
    }

    #[test]
    fn test_suppressed_lines_set() {
        let source = "line1\n// sicario-ignore-secret\nline3\nline4\n# sicario-ignore-secret\nline6";
        let parser = SuppressionParser::new();
        let suppressed = parser.suppressed_lines_in_source(source);
        assert!(suppressed.contains(&3));
        assert!(suppressed.contains(&6));
        assert!(!suppressed.contains(&1));
        assert!(!suppressed.contains(&2));
        assert!(!suppressed.contains(&4));
        assert!(!suppressed.contains(&5));
    }

    #[test]
    fn test_check_suppression_from_file() {
        let content = "// sicario-ignore-secret\nconst key = \"secret\";";
        let f = write_temp_file(content);
        let parser = SuppressionParser::new();
        assert!(parser.check_suppression_comment(f.path(), 2).unwrap());
        assert!(!parser.check_suppression_comment(f.path(), 1).unwrap());
    }

    #[test]
    fn test_line_zero_never_suppressed() {
        let parser = SuppressionParser::new();
        let f = write_temp_file("// sicario-ignore-secret\nline2");
        assert!(!parser.check_suppression_comment(f.path(), 0).unwrap());
    }

    // ── New SAST suppression unit tests ───────────────────────────────────

    #[test]
    fn test_sast_blanket_suppression_js() {
        let source = "// sicario-ignore\nlet x = eval(input);";
        let parser = SuppressionParser::new();
        let result = parser.is_sast_suppressed(source, 2, "any-rule");
        assert!(result.suppressed);
        assert!(result.rule_id.is_none());
    }

    #[test]
    fn test_sast_blanket_suppression_python() {
        let source = "# sicario-ignore\nos.system(cmd)";
        let parser = SuppressionParser::new();
        let result = parser.is_sast_suppressed(source, 2, "cmd-injection");
        assert!(result.suppressed);
    }

    #[test]
    fn test_sast_next_line_suppression() {
        let source = "// sicario-ignore-next-line\nlet x = eval(input);";
        let parser = SuppressionParser::new();
        let result = parser.is_sast_suppressed(source, 2, "any-rule");
        assert!(result.suppressed);
    }

    #[test]
    fn test_sast_rule_specific_suppression() {
        let source = "// sicario-ignore:sql-injection\ndb.query(userInput);";
        let parser = SuppressionParser::new();

        let result = parser.is_sast_suppressed(source, 2, "sql-injection");
        assert!(result.suppressed);
        assert_eq!(result.rule_id, Some("sql-injection".to_string()));

        // Different rule should NOT be suppressed
        let result2 = parser.is_sast_suppressed(source, 2, "xss");
        assert!(!result2.suppressed);
    }

    #[test]
    fn test_sast_suppression_html_comment() {
        let source = "<!-- sicario-ignore -->\n<div v-html=\"userInput\"></div>";
        let parser = SuppressionParser::new();
        let result = parser.is_sast_suppressed(source, 2, "xss");
        assert!(result.suppressed);
    }

    #[test]
    fn test_sast_suppression_block_comment() {
        let source = "/* sicario-ignore:cmd-injection */\nos.system(cmd);";
        let parser = SuppressionParser::new();
        let result = parser.is_sast_suppressed(source, 2, "cmd-injection");
        assert!(result.suppressed);
    }

    #[test]
    fn test_sast_secret_directive_does_not_suppress_sast() {
        let source = "// sicario-ignore-secret\nlet x = eval(input);";
        let parser = SuppressionParser::new();
        let result = parser.is_sast_suppressed(source, 2, "eval-usage");
        assert!(!result.suppressed);
    }

    #[test]
    fn test_sast_suppressed_lines_map() {
        let source = "line1\n// sicario-ignore\nline3\n# sicario-ignore:xss\nline5";
        let parser = SuppressionParser::new();
        let map = parser.sast_suppressed_lines(source);
        assert_eq!(map.get(&3), Some(&SuppressionKind::All));
        assert_eq!(map.get(&5), Some(&SuppressionKind::Rule("xss".to_string())));
        assert!(map.get(&1).is_none());
    }

    #[test]
    fn test_count_sast_suppressions() {
        let source = "// sicario-ignore\nline\n# sicario-ignore:xss\nline";
        let parser = SuppressionParser::new();
        assert_eq!(parser.count_sast_suppressions(source), 2);
    }

    // ── Property tests ────────────────────────────────────────────────────────

    // Feature: sicario-cli-core, Property 35: Inline suppression recognition
    // Validates: Requirements 16.1, 16.2
    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(30))]

        #[test]
        fn prop_js_suppression_always_recognized(
            content in "[^\n]{0,80}",
            prefix_lines in 0usize..5,
        ) {
            let mut source = String::new();
            for i in 0..prefix_lines {
                source.push_str(&format!("const x{} = {};\n", i, i));
            }
            let suppression_line = prefix_lines + 1;
            let target_line = prefix_lines + 2;

            source.push_str("// sicario-ignore-secret\n");
            source.push_str(&content);
            source.push('\n');

            let parser = SuppressionParser::new();
            prop_assert!(
                parser.is_suppressed_in_source(&source, target_line),
                "Line {} should be suppressed after comment on line {}. Source:\n{}",
                target_line, suppression_line, source
            );
        }

        #[test]
        fn prop_hash_suppression_always_recognized(
            content in "[^\n]{0,80}",
            prefix_lines in 0usize..5,
        ) {
            let mut source = String::new();
            for i in 0..prefix_lines {
                source.push_str(&format!("x{} = {}\n", i, i));
            }
            let target_line = prefix_lines + 2;

            source.push_str("# sicario-ignore-secret\n");
            source.push_str(&content);
            source.push('\n');

            let parser = SuppressionParser::new();
            prop_assert!(
                parser.is_suppressed_in_source(&source, target_line),
                "Line {} should be suppressed after # comment. Source:\n{}", target_line, source
            );
        }

        #[test]
        fn prop_suppression_does_not_bleed_beyond_next_line(
            content in "[^\n]{0,40}",
            gap in 1usize..10,
        ) {
            let mut source = String::new();
            source.push_str("// sicario-ignore-secret\n");
            for i in 0..gap {
                source.push_str(&format!("normal_line_{}\n", i));
            }
            source.push_str(&content);
            source.push('\n');

            let target_line = gap + 2;

            let parser = SuppressionParser::new();
            prop_assert!(
                parser.is_suppressed_in_source(&source, 2),
                "Line 2 should be suppressed"
            );
            if gap > 0 {
                prop_assert!(
                    !parser.is_suppressed_in_source(&source, target_line),
                    "Line {} should NOT be suppressed (gap={})", target_line, gap
                );
            }
        }

        #[test]
        fn prop_no_false_suppression_without_comment(
            lines in proptest::collection::vec("[^\n#/]{0,40}", 1..10),
        ) {
            let source = lines.join("\n");
            let parser = SuppressionParser::new();
            let suppressed = parser.suppressed_lines_in_source(&source);
            prop_assert!(
                suppressed.is_empty(),
                "No lines should be suppressed when there are no suppression comments. Source:\n{}",
                source
            );
        }
    }
}
