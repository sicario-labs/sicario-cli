//! Property-based tests for snippet extraction.
//!
//! Feature: zero-exfil-edge-scanning
//! Property 2 — Snippet Line Truncation Invariant
//! Property 5 — Zero-Exfiltration Snippet Window Correctness
//!
//! Validates: Requirements 15.2, 7.1, 15.1, 15.5

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use crate::snippet::extractor::{SnippetConfig, SnippetExtractor};

    // ── Generators ────────────────────────────────────────────────────────────

    /// Generate a random line of 0–500 characters using printable ASCII.
    fn arb_line() -> impl Strategy<Value = String> {
        proptest::collection::vec(0x20u8..=0x7Eu8, 0..=500)
            .prop_map(|bytes| bytes.into_iter().map(|b| b as char).collect::<String>())
    }

    /// Generate random file content as 1–50 lines of 0–500 chars each.
    fn arb_file_content() -> impl Strategy<Value = String> {
        proptest::collection::vec(arb_line(), 1..=50)
            .prop_map(|lines| lines.join("\n"))
    }

    // ── Property 2: Snippet Line Truncation Invariant ────────────────────────
    //
    // For any source file content and for any target line number within the file,
    // every line in the extracted snippet SHALL have a length of at most
    // `max_line_length` characters, regardless of the original line lengths.
    //
    // **Validates: Requirements 15.2, 7.1**

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// For any random file content with lines of 0–500 chars and any valid
        /// target line, every line in the extracted snippet must be at most
        /// `max_line_length` (100) characters long.
        ///
        /// Feature: zero-exfil-edge-scanning, Property 2: Snippet Line Truncation Invariant
        /// **Validates: Requirements 15.2, 7.1**
        #[test]
        fn prop2_all_snippet_lines_within_max_length(
            content in arb_file_content(),
            context_lines in 0usize..=10usize,
        ) {
            let total_lines = content.lines().count();
            // Pick a valid target line (1-indexed)
            let target_line = if total_lines == 0 { 1 } else { (total_lines / 2).max(1) };

            let max_line_length = 100;
            let config = SnippetConfig::new(context_lines, max_line_length);
            let snippet = SnippetExtractor::extract(&content, target_line, &config);

            for (i, line) in snippet.lines().enumerate() {
                let char_count = line.chars().count();
                prop_assert!(
                    char_count <= max_line_length,
                    "Snippet line {} has {} chars, exceeds max_line_length {}. Line: {:?}",
                    i,
                    char_count,
                    max_line_length,
                    line
                );
            }
        }

        /// For any random file content and any random valid target line,
        /// every snippet line must respect the truncation limit.
        /// This variant randomises the target line as well.
        ///
        /// Feature: zero-exfil-edge-scanning, Property 2: Snippet Line Truncation Invariant
        /// **Validates: Requirements 15.2, 7.1**
        #[test]
        fn prop2_random_target_line_truncation(
            content in arb_file_content(),
            target_frac in 0.0f64..=1.0f64,
            context_lines in 0usize..=10usize,
        ) {
            let total_lines = content.lines().count();
            if total_lines == 0 {
                return Ok(());
            }

            // Map the fraction to a valid 1-indexed target line
            let target_line = ((target_frac * total_lines as f64).floor() as usize)
                .max(1)
                .min(total_lines);

            let max_line_length = 100;
            let config = SnippetConfig::new(context_lines, max_line_length);
            let snippet = SnippetExtractor::extract(&content, target_line, &config);

            for (i, line) in snippet.lines().enumerate() {
                let char_count = line.chars().count();
                prop_assert!(
                    char_count <= max_line_length,
                    "Snippet line {} has {} chars (max {}). target_line={}, context_lines={}, total_lines={}",
                    i,
                    char_count,
                    max_line_length,
                    target_line,
                    context_lines,
                    total_lines
                );
            }
        }

        /// Edge case: when target_line is out of bounds (0 or > total lines),
        /// the snippet must be empty — and therefore trivially satisfies the
        /// truncation invariant.
        ///
        /// Feature: zero-exfil-edge-scanning, Property 2: Snippet Line Truncation Invariant
        /// **Validates: Requirements 15.2, 7.1**
        #[test]
        fn prop2_out_of_bounds_target_returns_empty(
            content in arb_file_content(),
            context_lines in 0usize..=10usize,
        ) {
            let total_lines = content.lines().count();
            let config = SnippetConfig::new(context_lines, 100);

            // target_line = 0
            let snippet_zero = SnippetExtractor::extract(&content, 0, &config);
            prop_assert!(
                snippet_zero.is_empty(),
                "Snippet for target_line=0 must be empty, got: {:?}",
                snippet_zero
            );

            // target_line > total_lines
            let snippet_over = SnippetExtractor::extract(&content, total_lines + 1, &config);
            prop_assert!(
                snippet_over.is_empty(),
                "Snippet for target_line={} (total={}) must be empty, got: {:?}",
                total_lines + 1,
                total_lines,
                snippet_over
            );
        }
    }
}

// ── Property 5: Zero-Exfiltration Snippet Window Correctness ─────────────
//
// For any source file with uniquely identifiable lines and for any target
// line number and context window size (0–10), the extracted snippet SHALL
// contain only content from lines within the range
// [max(1, target - context_lines), min(total_lines, target + context_lines)]
// and SHALL NOT contain any content from lines outside that range.
//
// Strategy: Generate files where each line is `LINE_N` (e.g., LINE_1,
// LINE_2, ..., LINE_50). Then extract a snippet and verify that only
// markers within the expected window appear in the output.
//
// **Validates: Requirements 15.1, 15.5**

#[cfg(test)]
mod window_tests {
    use proptest::prelude::*;

    use crate::snippet::extractor::{SnippetConfig, SnippetExtractor};

    // ── Generators ────────────────────────────────────────────────────────

    /// Generate a file with `num_lines` lines, each being `MARKER_N_END`
    /// where N is the 1-indexed line number. The `_END` suffix prevents
    /// false substring matches (e.g., `MARKER_1_END` is not a substring
    /// of `MARKER_10_END`). Returns (content, num_lines).
    fn arb_marker_file() -> impl Strategy<Value = (String, usize)> {
        (5usize..=50usize).prop_map(|num_lines| {
            let content = (1..=num_lines)
                .map(|n| format!("MARKER_{}_END", n))
                .collect::<Vec<_>>()
                .join("\n");
            (content, num_lines)
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(30))]

        /// For any marker file and any valid target line and context size,
        /// the snippet must contain ONLY markers within the expected window
        /// and NONE from outside it.
        ///
        /// Feature: zero-exfil-edge-scanning, Property 5: Zero-Exfiltration Snippet Window Correctness
        /// **Validates: Requirements 15.1, 15.5**
        #[test]
        fn prop5_snippet_contains_only_window_markers(
            (content, num_lines) in arb_marker_file(),
            target_frac in 0.0f64..1.0f64,
            context_lines in 0usize..=10usize,
        ) {
            // Map fraction to a valid 1-indexed target line
            let target_line = ((target_frac * num_lines as f64).floor() as usize)
                .max(1)
                .min(num_lines);

            let config = SnippetConfig::new(context_lines, 200); // large max_line_length so markers aren't truncated
            let snippet = SnippetExtractor::extract(&content, target_line, &config);

            // Compute expected window bounds (1-indexed)
            let window_start = if target_line > context_lines {
                target_line - context_lines
            } else {
                1
            };
            let window_end = (target_line + context_lines).min(num_lines);

            // Check that every marker inside the window IS present
            for n in window_start..=window_end {
                let marker = format!("MARKER_{}_END", n);
                prop_assert!(
                    snippet.contains(&marker),
                    "Expected marker {} in snippet but not found. target={}, context={}, window=[{}, {}]\nSnippet:\n{}",
                    marker, target_line, context_lines, window_start, window_end, snippet
                );
            }

            // Check that NO marker outside the window is present
            for n in 1..window_start {
                let marker = format!("MARKER_{}_END", n);
                prop_assert!(
                    !snippet.contains(&marker),
                    "Out-of-window marker {} found in snippet! target={}, context={}, window=[{}, {}]\nSnippet:\n{}",
                    marker, target_line, context_lines, window_start, window_end, snippet
                );
            }
            for n in (window_end + 1)..=num_lines {
                let marker = format!("MARKER_{}_END", n);
                prop_assert!(
                    !snippet.contains(&marker),
                    "Out-of-window marker {} found in snippet! target={}, context={}, window=[{}, {}]\nSnippet:\n{}",
                    marker, target_line, context_lines, window_start, window_end, snippet
                );
            }
        }

        /// For out-of-bounds target lines on a marker file, the snippet must
        /// be empty (no markers at all).
        ///
        /// Feature: zero-exfil-edge-scanning, Property 5: Zero-Exfiltration Snippet Window Correctness
        /// **Validates: Requirements 15.1, 15.5**
        #[test]
        fn prop5_out_of_bounds_target_contains_no_markers(
            (content, num_lines) in arb_marker_file(),
            context_lines in 0usize..=10usize,
        ) {
            let config = SnippetConfig::new(context_lines, 200);

            // target_line = 0
            let snippet_zero = SnippetExtractor::extract(&content, 0, &config);
            prop_assert!(
                snippet_zero.is_empty(),
                "Snippet for target_line=0 should be empty, got: {:?}",
                snippet_zero
            );

            // target_line > num_lines
            let snippet_over = SnippetExtractor::extract(&content, num_lines + 1, &config);
            prop_assert!(
                snippet_over.is_empty(),
                "Snippet for target_line={} (total={}) should be empty, got: {:?}",
                num_lines + 1, num_lines, snippet_over
            );

            // Verify no MARKER_N_END markers in empty snippets
            for n in 1..=num_lines {
                let marker = format!("MARKER_{}_END", n);
                prop_assert!(
                    !snippet_zero.contains(&marker),
                    "Empty snippet (target=0) contains marker {}",
                    marker
                );
                prop_assert!(
                    !snippet_over.contains(&marker),
                    "Empty snippet (target={}) contains marker {}",
                    num_lines + 1, marker
                );
            }
        }
    }
}
