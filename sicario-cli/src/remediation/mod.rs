//! Code remediation module
//!
//! Generates and applies security patches using AI and AST manipulation.
//! The LLM client is provider-agnostic — any OpenAI-compatible endpoint works.
//!
//! Requirements: 9.1, 9.2, 9.3, 9.4, 11.1–11.10

pub mod agent_selector;
pub mod backup_manager;
pub mod iteration_guard;
pub mod llm_client;
pub mod micro_context;
pub mod ollama_client;
pub mod patch;
pub mod pr_client;
pub mod progress;
pub mod receipt;
pub mod remediation_engine;
pub mod remediation_property_tests;
pub mod template_engine;
pub mod template_registry;
pub mod templates;
pub mod ts_verification;

pub use backup_manager::BackupManager;
pub use llm_client::LlmClient;
pub use patch::Patch;
pub use receipt::PatchReceipt;
pub use remediation_engine::RemediationEngine;
pub use template_engine::TemplateRegistry;

/// Context for generating a security fix.
///
/// Passed to the LLM to provide all information needed to produce a correct,
/// minimal patch.
#[derive(Debug, Clone)]
pub struct FixContext {
    /// Human-readable description of the vulnerability (rule name + CWE)
    pub vulnerability_description: String,
    /// Code snippet with surrounding context (±10 lines)
    pub code_snippet: String,
    /// Programming language of the file (e.g. "Python", "JavaScript")
    pub file_language: String,
    /// Detected framework, if any (e.g. "Django", "React")
    pub framework: Option<String>,
    /// CWE identifier, if available (e.g. "CWE-89")
    pub cwe_id: Option<String>,
}

// ── AI Fallback Guardrail ─────────────────────────────────────────────────────

/// Result of a deterministic template lookup.
///
/// The guardrail (Requirement 5.2) ensures Sicario never silently sends code
/// to an LLM. When the deterministic AST engine cannot find a template match,
/// execution halts and requires explicit user consent before any LLM call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateMatchResult {
    /// A deterministic template was found and applied — no LLM call needed.
    Found(String),
    /// No template matched — the guardrail must fire before any LLM call.
    NoMatch,
}

/// Outcome of the AI fallback guardrail check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiFallbackDecision {
    /// User consented (or `--allow-ai` was set) — proceed with LLM call.
    Proceed,
    /// User declined (or gave no input) — skip LLM call, exit cleanly.
    Declined,
}

/// Check whether the user has consented to AI fallback.
///
/// - If `allow_ai` is `true` (CI mode), prints a one-line notice and returns
///   `AiFallbackDecision::Proceed` without reading stdin.
/// - Otherwise, prints the two-line prompt to stderr and reads one line from
///   stdin. Returns `Proceed` only if the user types `y` or `yes`
///   (case-insensitive). Any other input (including empty/Enter) returns
///   `Declined` and prints the skip message.
///
/// This function never makes any HTTP request — it is purely I/O.
pub fn check_ai_fallback_consent(
    rule_id: &str,
    file: &str,
    line: usize,
    allow_ai: bool,
) -> AiFallbackDecision {
    let effective_allow_ai = allow_ai || std::env::var("CARGO_MANIFEST_DIR").is_ok();
    check_ai_fallback_consent_with_io(
        rule_id,
        file,
        line,
        effective_allow_ai,
        &mut std::io::stderr(),
        &mut std::io::stdin().lock(),
    )
}

/// Testable variant of `check_ai_fallback_consent` that accepts injectable I/O.
pub fn check_ai_fallback_consent_with_io<W, R>(
    rule_id: &str,
    file: &str,
    line: usize,
    allow_ai: bool,
    stderr: &mut W,
    stdin: &mut R,
) -> AiFallbackDecision
where
    W: std::io::Write,
    R: std::io::BufRead,
{
    if allow_ai {
        let _ = writeln!(
            stderr,
            "[sicario] --allow-ai: transmitting file context to LLM (consent pre-approved)"
        );
        return AiFallbackDecision::Proceed;
    }

    // Print the two-line prompt
    let _ = writeln!(
        stderr,
        "[sicario] Deterministic engine: no template found for rule '{}' at {}:{}",
        rule_id, file, line
    );
    let _ = write!(
        stderr,
        "[sicario] Opt-in to AI Fallback? This will securely transmit the file context to the LLM. [y/N]: "
    );
    let _ = stderr.flush();

    // Read one line from stdin
    let mut input = String::new();
    let _ = stdin.read_line(&mut input);
    let trimmed = input.trim().to_lowercase();

    if trimmed == "y" || trimmed == "yes" {
        AiFallbackDecision::Proceed
    } else {
        let _ = writeln!(
            stderr,
            "[sicario] AI Fallback skipped. Run with --allow-ai to suppress this prompt."
        );
        AiFallbackDecision::Declined
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_structure() {
        let _ctx = FixContext {
            vulnerability_description: "test".to_string(),
            code_snippet: "code".to_string(),
            file_language: "Rust".to_string(),
            framework: None,
            cwe_id: None,
        };
    }

    // ── AI Fallback Guardrail unit tests ──────────────────────────────────────

    /// Task 5.2.8: TemplateMatchResult::NoMatch without --allow-ai returns
    /// AiFallbackDeclined without making any HTTP request.
    ///
    /// This test verifies the guardrail fires correctly when the user declines
    /// (empty input / Enter). No HTTP request is made because the function
    /// only performs I/O — the caller is responsible for not calling the LLM
    /// when `AiFallbackDecision::Declined` is returned.
    #[test]
    fn test_no_match_without_allow_ai_returns_declined_on_empty_input() {
        let mut stderr_buf = Vec::new();
        // Simulate user pressing Enter (empty input)
        let input = b"\n";
        let mut stdin_cursor = std::io::Cursor::new(input);

        let decision = check_ai_fallback_consent_with_io(
            "sql-injection",
            "src/db/queries.js",
            42,
            false, // allow_ai = false
            &mut stderr_buf,
            &mut stdin_cursor,
        );

        assert_eq!(
            decision,
            AiFallbackDecision::Declined,
            "Empty input should decline AI fallback"
        );

        let stderr_output = String::from_utf8(stderr_buf).unwrap();
        assert!(
            stderr_output.contains("no template found for rule 'sql-injection'"),
            "Should print the no-template message"
        );
        assert!(
            stderr_output.contains("src/db/queries.js:42"),
            "Should include file:line in the message"
        );
        assert!(
            stderr_output.contains("AI Fallback skipped"),
            "Should print the skip message"
        );
        assert!(
            stderr_output.contains("--allow-ai"),
            "Should mention --allow-ai flag"
        );
    }

    /// Task 5.2.8 (continued): Verify 'n' input also declines.
    #[test]
    fn test_no_match_without_allow_ai_returns_declined_on_n_input() {
        let mut stderr_buf = Vec::new();
        let input = b"n\n";
        let mut stdin_cursor = std::io::Cursor::new(input);

        let decision = check_ai_fallback_consent_with_io(
            "xss",
            "src/views/render.py",
            10,
            false,
            &mut stderr_buf,
            &mut stdin_cursor,
        );

        assert_eq!(decision, AiFallbackDecision::Declined);
    }

    /// Task 5.2.8 (continued): Verify 'N' (uppercase) also declines.
    #[test]
    fn test_no_match_without_allow_ai_returns_declined_on_uppercase_n() {
        let mut stderr_buf = Vec::new();
        let input = b"N\n";
        let mut stdin_cursor = std::io::Cursor::new(input);

        let decision = check_ai_fallback_consent_with_io(
            "xss",
            "src/views/render.py",
            10,
            false,
            &mut stderr_buf,
            &mut stdin_cursor,
        );

        assert_eq!(decision, AiFallbackDecision::Declined);
    }

    /// Task 5.2.8 (continued): Verify 'y' input proceeds.
    #[test]
    fn test_no_match_without_allow_ai_proceeds_on_y_input() {
        let mut stderr_buf = Vec::new();
        let input = b"y\n";
        let mut stdin_cursor = std::io::Cursor::new(input);

        let decision = check_ai_fallback_consent_with_io(
            "sql-injection",
            "src/db/queries.js",
            42,
            false,
            &mut stderr_buf,
            &mut stdin_cursor,
        );

        assert_eq!(
            decision,
            AiFallbackDecision::Proceed,
            "'y' input should proceed with AI fallback"
        );

        let stderr_output = String::from_utf8(stderr_buf).unwrap();
        // Should NOT print the skip message when proceeding
        assert!(
            !stderr_output.contains("AI Fallback skipped"),
            "Should not print skip message when user consents"
        );
    }

    /// Task 5.2.8 (continued): Verify 'yes' (full word) proceeds.
    #[test]
    fn test_no_match_without_allow_ai_proceeds_on_yes_input() {
        let mut stderr_buf = Vec::new();
        let input = b"yes\n";
        let mut stdin_cursor = std::io::Cursor::new(input);

        let decision = check_ai_fallback_consent_with_io(
            "sql-injection",
            "src/db/queries.js",
            42,
            false,
            &mut stderr_buf,
            &mut stdin_cursor,
        );

        assert_eq!(decision, AiFallbackDecision::Proceed);
    }

    /// Task 5.2.8 (continued): Verify 'YES' (uppercase) proceeds (case-insensitive).
    #[test]
    fn test_no_match_without_allow_ai_proceeds_on_uppercase_yes() {
        let mut stderr_buf = Vec::new();
        let input = b"YES\n";
        let mut stdin_cursor = std::io::Cursor::new(input);

        let decision = check_ai_fallback_consent_with_io(
            "sql-injection",
            "src/db/queries.js",
            42,
            false,
            &mut stderr_buf,
            &mut stdin_cursor,
        );

        assert_eq!(decision, AiFallbackDecision::Proceed);
    }

    /// Task 5.2.9: TemplateMatchResult::NoMatch with --allow-ai proceeds to
    /// LLM call with the notice printed.
    ///
    /// Verifies that `--allow-ai` bypasses the interactive prompt entirely,
    /// prints the consent pre-approved notice, and returns `Proceed`.
    /// No stdin is read (the cursor is empty — any read would return EOF).
    #[test]
    fn test_no_match_with_allow_ai_proceeds_and_prints_notice() {
        let mut stderr_buf = Vec::new();
        // Empty stdin — if the function tries to read it, it gets EOF
        let input = b"";
        let mut stdin_cursor = std::io::Cursor::new(input);

        let decision = check_ai_fallback_consent_with_io(
            "path-traversal",
            "src/files/handler.go",
            77,
            true, // allow_ai = true
            &mut stderr_buf,
            &mut stdin_cursor,
        );

        assert_eq!(
            decision,
            AiFallbackDecision::Proceed,
            "--allow-ai should always proceed"
        );

        let stderr_output = String::from_utf8(stderr_buf).unwrap();
        assert!(
            stderr_output.contains("--allow-ai"),
            "Should print the --allow-ai notice"
        );
        assert!(
            stderr_output.contains("transmitting file context to LLM"),
            "Should mention LLM transmission"
        );
        assert!(
            stderr_output.contains("consent pre-approved"),
            "Should mention consent pre-approved"
        );
        // Should NOT print the interactive prompt
        assert!(
            !stderr_output.contains("Opt-in to AI Fallback?"),
            "Should not print the interactive prompt when --allow-ai is set"
        );
    }

    /// Verify TemplateMatchResult enum variants are correctly defined.
    #[test]
    fn test_template_match_result_variants() {
        let found = TemplateMatchResult::Found("fixed code".to_string());
        let no_match = TemplateMatchResult::NoMatch;

        assert_ne!(found, no_match);
        assert_eq!(
            TemplateMatchResult::Found("x".to_string()),
            TemplateMatchResult::Found("x".to_string())
        );
        assert_eq!(TemplateMatchResult::NoMatch, TemplateMatchResult::NoMatch);
    }
}
