//! Zero-Exfiltration Patch Receipt
//!
//! Every successful deterministic patch prints a receipt that makes the
//! zero-exfiltration guarantee viscerally visible. For deterministic patches,
//! `tokens_burned` and `lines_exfiltrated` are always 0 — no code was sent
//! to any LLM. When AI Fallback is used, these fields reflect the actual cost.
//!
//! Requirements: Phase 5.3

/// A receipt printed after every successful patch.
///
/// For deterministic patches:
///   - `tokens_burned`     is always 0 (no LLM call was made)
///   - `lines_exfiltrated` is always 0 (no code was transmitted)
///
/// For AI Fallback patches (--allow-ai):
///   - `tokens_burned`     is the actual token count from the LLM response
///   - `lines_exfiltrated` is the line count of the transmitted context
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchReceipt {
    pub rule_id: String,
    pub file: String,
    pub line: u32,
    pub execution_ms: u128,
    pub tokens_burned: u32,     // always 0 for deterministic patches
    pub lines_exfiltrated: u32, // always 0 for deterministic patches
    pub template_used: String,
}

impl PatchReceipt {
    /// Create a receipt for a deterministic patch (zero tokens, zero exfiltration).
    pub fn deterministic(
        rule_id: impl Into<String>,
        file: impl Into<String>,
        line: u32,
        execution_ms: u128,
        template_used: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            file: file.into(),
            line,
            execution_ms,
            tokens_burned: 0,
            lines_exfiltrated: 0,
            template_used: template_used.into(),
        }
    }

    /// Create a receipt for a local agent (Ollama) patch.
    ///
    /// `tokens_burned` and `lines_exfiltrated` are always 0 — the local agent
    /// calls only `http://127.0.0.1:11434` and no code leaves the machine.
    ///
    /// `template_used` is set to `"ollama-local (<model_name>)"` so the receipt
    /// makes the zero-exfiltration guarantee visible.
    pub fn local_agent(
        rule_id: impl Into<String>,
        file: impl Into<String>,
        line: u32,
        execution_ms: u128,
        model_name: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            file: file.into(),
            line,
            execution_ms,
            tokens_burned: 0,
            lines_exfiltrated: 0,
            template_used: format!("ollama-local ({})", model_name.into()),
        }
    }

    /// Create a receipt for an AI Fallback patch (tokens and lines are non-zero).
    pub fn ai_fallback(
        rule_id: impl Into<String>,
        file: impl Into<String>,
        line: u32,
        execution_ms: u128,
        tokens_burned: u32,
        lines_exfiltrated: u32,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            file: file.into(),
            line,
            execution_ms,
            tokens_burned,
            lines_exfiltrated,
            template_used: "llm-fallback".to_string(),
        }
    }

    /// Render the receipt as a tabular string.
    ///
    /// The box is 48 characters wide (inner content width = 46).
    /// Unicode box-drawing characters are used for the border.
    pub fn render(&self) -> String {
        // Inner width: total box width 48, minus 2 border chars = 46
        const INNER: usize = 46;

        let file_line = format!("{}:{}", self.file, self.line);
        let time_str = format!("{}ms", self.execution_ms);

        // Helper: pad a "  Label   value" row to INNER chars
        let row = |label: &str, value: &str| -> String {
            let content = format!("  {:<14}{}", label, value);
            format!("║{:<width$}║", content, width = INNER)
        };

        let divider = format!("╠{}╣", "═".repeat(INNER));
        let top = format!("╔{}╗", "═".repeat(INNER));
        let bottom = format!("╚{}╝", "═".repeat(INNER));

        // Title row — centred
        let title = "SICARIO PATCH RECEIPT";
        let padding = INNER.saturating_sub(title.len());
        let left_pad = padding / 2;
        let right_pad = padding - left_pad;
        let title_row = format!(
            "║{}{}{}║",
            " ".repeat(left_pad),
            title,
            " ".repeat(right_pad)
        );

        let lines = vec![
            top,
            title_row,
            divider.clone(),
            row("Rule", &self.rule_id),
            row("File", &file_line),
            row("Template", &self.template_used),
            row("Time", &time_str),
            divider,
            row("Tokens Burned", &self.tokens_burned.to_string()),
            row("Lines Exfiltrated", &self.lines_exfiltrated.to_string()),
            bottom,
        ];

        lines.join("\n")
    }

    /// Print the receipt to stdout.
    pub fn print(&self) {
        println!("{}", self.render());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Task 5.3.7: Deterministic patch always produces tokens_burned: 0 and
    /// lines_exfiltrated: 0.
    #[test]
    fn test_deterministic_patch_zero_tokens_and_exfiltration() {
        let receipt = PatchReceipt::deterministic(
            "sql-injection",
            "src/db/queries.js",
            42,
            3,
            "parameterized-query",
        );

        assert_eq!(
            receipt.tokens_burned, 0,
            "Deterministic patch must have tokens_burned = 0"
        );
        assert_eq!(
            receipt.lines_exfiltrated, 0,
            "Deterministic patch must have lines_exfiltrated = 0"
        );
    }

    /// Task 5.3.7 (continued): Verify the deterministic constructor sets all fields correctly.
    #[test]
    fn test_deterministic_receipt_fields() {
        let receipt =
            PatchReceipt::deterministic("xss", "src/views/render.py", 10, 7, "html-escape");

        assert_eq!(receipt.rule_id, "xss");
        assert_eq!(receipt.file, "src/views/render.py");
        assert_eq!(receipt.line, 10);
        assert_eq!(receipt.execution_ms, 7);
        assert_eq!(receipt.tokens_burned, 0);
        assert_eq!(receipt.lines_exfiltrated, 0);
        assert_eq!(receipt.template_used, "html-escape");
    }

    /// Task 5.3.8: Receipt renders correctly with a known PatchReceipt value (snapshot test).
    #[test]
    fn test_receipt_render_snapshot() {
        let receipt = PatchReceipt {
            rule_id: "sql-injection".to_string(),
            file: "src/db/queries.js".to_string(),
            line: 42,
            execution_ms: 3,
            tokens_burned: 0,
            lines_exfiltrated: 0,
            template_used: "parameterized-query".to_string(),
        };

        let rendered = receipt.render();

        // Verify the box structure
        assert!(rendered.contains("╔"), "Should have top-left corner");
        assert!(rendered.contains("╗"), "Should have top-right corner");
        assert!(rendered.contains("╚"), "Should have bottom-left corner");
        assert!(rendered.contains("╝"), "Should have bottom-right corner");
        assert!(rendered.contains("╠"), "Should have left divider");
        assert!(rendered.contains("╣"), "Should have right divider");
        assert!(rendered.contains("║"), "Should have vertical bars");
        assert!(rendered.contains("═"), "Should have horizontal bars");

        // Verify content
        assert!(
            rendered.contains("SICARIO PATCH RECEIPT"),
            "Should contain title"
        );
        assert!(rendered.contains("sql-injection"), "Should contain rule_id");
        assert!(
            rendered.contains("src/db/queries.js:42"),
            "Should contain file:line"
        );
        assert!(
            rendered.contains("parameterized-query"),
            "Should contain template"
        );
        assert!(rendered.contains("3ms"), "Should contain time");
        assert!(
            rendered.contains("Tokens Burned"),
            "Should contain tokens label"
        );
        assert!(
            rendered.contains("Lines Exfiltrated"),
            "Should contain exfiltration label"
        );

        // Verify zero values are shown
        let lines: Vec<&str> = rendered.lines().collect();
        let tokens_line = lines.iter().find(|l| l.contains("Tokens Burned")).unwrap();
        assert!(tokens_line.contains("0"), "Tokens Burned should show 0");
        let exfil_line = lines
            .iter()
            .find(|l| l.contains("Lines Exfiltrated"))
            .unwrap();
        assert!(exfil_line.contains("0"), "Lines Exfiltrated should show 0");
    }

    /// Task 5.3.8 (continued): Verify box width is consistent (48 chars per line).
    #[test]
    fn test_receipt_render_consistent_width() {
        let receipt = PatchReceipt::deterministic(
            "sql-injection",
            "src/db/queries.js",
            42,
            3,
            "parameterized-query",
        );

        let rendered = receipt.render();
        for line in rendered.lines() {
            // Count display characters (Unicode box chars are single-width)
            let char_count = line.chars().count();
            assert_eq!(
                char_count, 48,
                "Each line should be exactly 48 chars wide, got {char_count} for: {line:?}"
            );
        }
    }

    /// Task 1.5: `local_agent` constructor always produces `tokens_burned: 0`
    /// and `lines_exfiltrated: 0`.
    #[test]
    fn test_local_agent_constructor_zero_tokens_and_exfiltration() {
        let receipt = PatchReceipt::local_agent(
            "sql-injection",
            "src/db/queries.js",
            42,
            150,
            "qwen2.5-coder:7b",
        );

        assert_eq!(
            receipt.tokens_burned, 0,
            "local_agent patch must have tokens_burned = 0"
        );
        assert_eq!(
            receipt.lines_exfiltrated, 0,
            "local_agent patch must have lines_exfiltrated = 0"
        );
    }

    /// Task 1.5: `local_agent` constructor sets `template_used` to
    /// `"ollama-local (<model_name>)"`.
    #[test]
    fn test_local_agent_constructor_template_used() {
        let receipt = PatchReceipt::local_agent(
            "xss",
            "src/views/render.py",
            10,
            200,
            "deepseek-coder-v2:latest",
        );

        assert_eq!(
            receipt.template_used,
            "ollama-local (deepseek-coder-v2:latest)"
        );
        assert_eq!(receipt.rule_id, "xss");
        assert_eq!(receipt.file, "src/views/render.py");
        assert_eq!(receipt.line, 10);
        assert_eq!(receipt.execution_ms, 200);
        assert_eq!(receipt.tokens_burned, 0);
        assert_eq!(receipt.lines_exfiltrated, 0);
    }

    /// Verify AI fallback receipt has non-zero tokens and exfiltration.
    #[test]
    fn test_ai_fallback_receipt_fields() {
        let receipt =
            PatchReceipt::ai_fallback("path-traversal", "src/files/handler.go", 77, 250, 1024, 15);

        assert_eq!(receipt.tokens_burned, 1024);
        assert_eq!(receipt.lines_exfiltrated, 15);
        assert_eq!(receipt.template_used, "llm-fallback");
    }

    /// Verify the render output contains the AI fallback token count.
    #[test]
    fn test_ai_fallback_receipt_render_shows_tokens() {
        let receipt = PatchReceipt::ai_fallback("xss", "src/views/render.py", 10, 500, 2048, 20);

        let rendered = receipt.render();
        let lines: Vec<&str> = rendered.lines().collect();
        let tokens_line = lines.iter().find(|l| l.contains("Tokens Burned")).unwrap();
        assert!(
            tokens_line.contains("2048"),
            "Should show actual token count"
        );
        let exfil_line = lines
            .iter()
            .find(|l| l.contains("Lines Exfiltrated"))
            .unwrap();
        assert!(
            exfil_line.contains("20"),
            "Should show actual exfiltration count"
        );
    }
}
