/// Configuration for snippet extraction.
pub struct SnippetConfig {
    /// Number of context lines above and below the target line (default: 3, min: 0, max: 10).
    pub context_lines: usize,
    /// Maximum characters per line in the output snippet (default: 100).
    pub max_line_length: usize,
}

impl Default for SnippetConfig {
    fn default() -> Self {
        Self {
            context_lines: 3,
            max_line_length: 100,
        }
    }
}

impl SnippetConfig {
    /// Create a new SnippetConfig, clamping `context_lines` to [0, 10].
    pub fn new(context_lines: usize, max_line_length: usize) -> Self {
        Self {
            context_lines: context_lines.min(10),
            max_line_length,
        }
    }
}

pub struct SnippetExtractor;

impl SnippetExtractor {
    /// Extract a snippet from `content` around `target_line` (1-indexed).
    ///
    /// Returns the extracted lines joined by newlines, with each line truncated
    /// to `config.max_line_length` characters. Returns an empty string if
    /// `target_line` is 0, exceeds the file length, or the file is empty.
    pub fn extract(content: &str, target_line: usize, config: &SnippetConfig) -> String {
        if content.is_empty() {
            return String::new();
        }

        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();

        if target_line == 0 || target_line > total_lines {
            tracing::warn!(
                "target_line {} is out of bounds (file has {} lines)",
                target_line,
                total_lines
            );
            return String::new();
        }

        let start = target_line.saturating_sub(config.context_lines).max(1);
        let end = (target_line + config.context_lines).min(total_lines);

        // start and end are 1-indexed; convert to 0-indexed for slice access
        let extracted: Vec<String> = lines[(start - 1)..=end - 1]
            .iter()
            .map(|line| truncate_line(line, config.max_line_length))
            .collect();

        extracted.join("\n")
    }
}

/// Truncate a line to at most `max_len` characters, respecting char boundaries.
fn truncate_line(line: &str, max_len: usize) -> String {
    if line.len() <= max_len {
        return line.to_string();
    }
    // Use char_indices to truncate at a char boundary
    match line.char_indices().nth(max_len) {
        Some((byte_idx, _)) => line[..byte_idx].to_string(),
        None => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_extraction() {
        let content = "line1\nline2\nline3\nline4\nline5\nline6\nline7";
        let config = SnippetConfig::default(); // context_lines=3
        let result = SnippetExtractor::extract(content, 4, &config);
        assert_eq!(result, "line1\nline2\nline3\nline4\nline5\nline6\nline7");
    }

    #[test]
    fn test_target_line_zero_returns_empty() {
        let content = "line1\nline2\nline3";
        let config = SnippetConfig::default();
        let result = SnippetExtractor::extract(content, 0, &config);
        assert_eq!(result, "");
    }

    #[test]
    fn test_target_line_exceeds_total_returns_empty() {
        let content = "line1\nline2\nline3";
        let config = SnippetConfig::default();
        let result = SnippetExtractor::extract(content, 10, &config);
        assert_eq!(result, "");
    }

    #[test]
    fn test_empty_file_returns_empty() {
        let config = SnippetConfig::default();
        let result = SnippetExtractor::extract("", 1, &config);
        assert_eq!(result, "");
    }

    #[test]
    fn test_context_lines_zero() {
        let content = "line1\nline2\nline3\nline4\nline5";
        let config = SnippetConfig::new(0, 100);
        let result = SnippetExtractor::extract(content, 3, &config);
        assert_eq!(result, "line3");
    }

    #[test]
    fn test_truncation() {
        let long_line = "a".repeat(200);
        let content = format!("short\n{}\nshort", long_line);
        let config = SnippetConfig::new(1, 100);
        let result = SnippetExtractor::extract(&content, 2, &config);
        let result_lines: Vec<&str> = result.lines().collect();
        assert_eq!(result_lines.len(), 3);
        assert_eq!(result_lines[1].len(), 100);
    }

    #[test]
    fn test_window_at_start_of_file() {
        let content = "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10";
        let config = SnippetConfig::new(3, 100);
        let result = SnippetExtractor::extract(content, 1, &config);
        // Window: max(1, 1-3)=1 to min(10, 1+3)=4
        assert_eq!(result, "line1\nline2\nline3\nline4");
    }

    #[test]
    fn test_window_at_end_of_file() {
        let content = "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10";
        let config = SnippetConfig::new(3, 100);
        let result = SnippetExtractor::extract(content, 10, &config);
        // Window: max(1, 10-3)=7 to min(10, 10+3)=10
        assert_eq!(result, "line7\nline8\nline9\nline10");
    }

    #[test]
    fn test_single_line_file() {
        let content = "only line";
        let config = SnippetConfig::default();
        let result = SnippetExtractor::extract(content, 1, &config);
        assert_eq!(result, "only line");
    }

    #[test]
    fn test_config_clamps_context_lines() {
        let config = SnippetConfig::new(20, 100);
        assert_eq!(config.context_lines, 10);
    }
}
