//! Miette-style diagnostic output for scan findings.
//!
//! Renders vulnerabilities as compiler-style diagnostics with source context,
//! span underlines, and help hints — without depending on miette's Report type.

use std::io::{self, Write};

use owo_colors::OwoColorize;

use crate::engine::vulnerability::{Severity, Vulnerability};

/// Render all vulnerabilities as miette/rustc-style diagnostics.
pub fn render_diagnostics(
    vulns: &[Vulnerability],
    color_enabled: bool,
    writer: &mut dyn Write,
) -> io::Result<()> {
    if vulns.is_empty() {
        writeln!(writer, "No findings detected.")?;
        return Ok(());
    }

    for vuln in vulns {
        render_one(vuln, color_enabled, writer)?;
        writeln!(writer)?;
    }

    Ok(())
}

/// Render a single vulnerability as a diagnostic block.
fn render_one(
    vuln: &Vulnerability,
    color: bool,
    w: &mut dyn Write,
) -> io::Result<()> {
    let sev_tag = severity_tag(vuln.severity);
    let cwe = vuln
        .cwe_id
        .as_deref()
        .map(|c| format!(" ({c})"))
        .unwrap_or_default();

    // Header:  × [CRITICAL] rule-id (CWE-94)
    let cross = if color { "×".red().bold().to_string() } else { "×".to_string() };
    let header_label = format!("[{sev_tag}] {}{cwe}", vuln.rule_id);
    let header = if color {
        match vuln.severity {
            Severity::Critical => header_label.red().bold().to_string(),
            Severity::High => header_label.yellow().bold().to_string(),
            Severity::Medium => header_label.yellow().to_string(),
            Severity::Low => header_label.blue().to_string(),
            Severity::Info => header_label.bright_black().to_string(),
        }
    } else {
        header_label
    };
    writeln!(w, "  {cross} {header}")?;

    // Source location: ╭─[file:line:col]
    let loc = format!(
        "{}:{}:{}",
        vuln.file_path.display(),
        vuln.line,
        vuln.column
    );
    let top_border = if color {
        format!("  {}",
            format!("╭─[{loc}]").bright_black())
    } else {
        format!("  ╭─[{loc}]")
    };
    writeln!(w, "{top_border}")?;

    // Read source context (line before, finding line, line after)
    let source_lines = read_source_context(&vuln.file_path, vuln.line);

    for ctx in &source_lines {
        let gutter = format!("{:>3}", ctx.line_number);
        if ctx.is_finding_line {
            // Finding line
            let pipe = "│";
            if color {
                write!(w, "  {} {} ", gutter.bright_black(), pipe.bright_black())?;
            } else {
                write!(w, "  {gutter} {pipe} ")?;
            }
            writeln!(w, "{}", ctx.text)?;

            // Underline span
            let col = vuln.column.saturating_sub(1);
            let span_len = compute_span_len(vuln, &ctx.text);
            let padding = " ".repeat(col);
            let carets = "^".repeat(span_len.max(1));
            let message = extract_message(vuln);

            if color {
                write!(w, "  {} {} ", "·".bright_black(), " ".repeat(0))?;
                // Align under the gutter
                write!(w, "    {padding}")?;
                writeln!(w, "{} {}", carets.red().bold(), message.red().bold())?;
            } else {
                writeln!(w, "  ·     {padding}{carets} {message}")?;
            }
        } else {
            // Context line
            let pipe = "│";
            if color {
                write!(w, "  {} {} ", gutter.bright_black(), pipe.bright_black())?;
            } else {
                write!(w, "  {gutter} {pipe} ")?;
            }
            writeln!(w, "{}", ctx.text)?;
        }
    }

    // Bottom border
    let bottom = if color {
        format!("  {}", "╰─".bright_black())
    } else {
        "  ╰─".to_string()
    };
    writeln!(w, "{bottom}")?;

    // Help hint
    let help = help_for_rule(&vuln.rule_id);
    if !help.is_empty() {
        if color {
            writeln!(w, "  {}: {help}", "help".cyan().bold())?;
        } else {
            writeln!(w, "  help: {help}")?;
        }
    }

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

struct ContextLine {
    line_number: usize,
    text: String,
    is_finding_line: bool,
}

/// Read 1 line before, the finding line, and 1 line after from the source file.
fn read_source_context(path: &std::path::Path, finding_line: usize) -> Vec<ContextLine> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return fallback_context(finding_line),
    };

    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::new();

    let start = if finding_line > 1 { finding_line - 1 } else { 1 };
    let end = (finding_line + 1).min(lines.len());

    for ln in start..=end {
        if ln == 0 || ln > lines.len() {
            continue;
        }
        result.push(ContextLine {
            line_number: ln,
            text: lines[ln - 1].to_string(),
            is_finding_line: ln == finding_line,
        });
    }

    result
}

/// Fallback when the source file can't be read — show the snippet from the vuln.
fn fallback_context(finding_line: usize) -> Vec<ContextLine> {
    vec![ContextLine {
        line_number: finding_line,
        text: "<source unavailable>".to_string(),
        is_finding_line: true,
    }]
}

fn severity_tag(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// Compute the underline span length from the snippet or a reasonable default.
fn compute_span_len(vuln: &Vulnerability, line_text: &str) -> usize {
    let col = vuln.column.saturating_sub(1);
    let snippet_trimmed = vuln.snippet.trim();

    // Try to find the snippet text in the line starting near the column
    if !snippet_trimmed.is_empty() {
        if let Some(pos) = line_text.find(snippet_trimmed) {
            if pos <= col + 2 {
                return snippet_trimmed.len();
            }
        }
    }

    // Fallback: underline from column to end of meaningful content
    let remaining = line_text.len().saturating_sub(col);
    remaining.min(40).max(1)
}

/// Extract a short message describing the finding.
fn extract_message(vuln: &Vulnerability) -> String {
    let snippet = vuln.snippet.trim();
    let rule = &vuln.rule_id;

    // Generate a contextual message based on common rule patterns
    if rule.contains("eval") || snippet.contains("eval(") {
        return format!("Untrusted input passed to eval()");
    }
    if rule.contains("sql") || rule.contains("injection") {
        return format!("Potential injection vulnerability");
    }
    if rule.contains("xss") {
        return format!("Potential cross-site scripting");
    }
    if rule.contains("hardcoded") || rule.contains("secret") || rule.contains("password") {
        return format!("Hardcoded secret or credential");
    }
    if rule.contains("exec") || rule.contains("command") {
        return format!("Potential command injection");
    }
    if rule.contains("path") || rule.contains("traversal") {
        return format!("Potential path traversal");
    }
    if rule.contains("deserial") {
        return format!("Unsafe deserialization");
    }
    if rule.contains("crypto") || rule.contains("weak") {
        return format!("Weak cryptographic usage");
    }

    format!("Security finding: {rule}")
}

/// Return a help hint for common rule IDs.
fn help_for_rule(rule_id: &str) -> String {
    let r = rule_id.to_lowercase();

    if r.contains("eval") {
        return "Replace eval() with a safe alternative like JSON.parse() or a sandboxed interpreter".to_string();
    }
    if r.contains("sql-injection") || r.contains("sqli") {
        return "Use parameterized queries or prepared statements instead of string concatenation".to_string();
    }
    if r.contains("xss") {
        return "Sanitize or escape user input before inserting into HTML output".to_string();
    }
    if r.contains("command") || r.contains("exec") || r.contains("os-command") {
        return "Avoid passing user input to shell commands; use safe APIs with argument lists".to_string();
    }
    if r.contains("hardcoded") || r.contains("secret") || r.contains("password") {
        return "Move secrets to environment variables or a secrets manager".to_string();
    }
    if r.contains("path-traversal") || r.contains("directory-traversal") {
        return "Validate and canonicalize file paths; reject inputs containing '..'".to_string();
    }
    if r.contains("deserial") {
        return "Avoid deserializing untrusted data; use safe formats like JSON with schema validation".to_string();
    }
    if r.contains("crypto") || r.contains("weak-hash") || r.contains("md5") || r.contains("sha1") {
        return "Use strong cryptographic algorithms (e.g., SHA-256, AES-256)".to_string();
    }
    if r.contains("redos") || r.contains("regex") {
        return "Simplify the regex pattern or add input length limits to prevent ReDoS".to_string();
    }
    if r.contains("nosql") {
        return "Validate and sanitize input before using in NoSQL queries".to_string();
    }
    if r.contains("info-leak") || r.contains("information-leak") || r.contains("info_leak") {
        return "Avoid exposing internal details in error messages or responses".to_string();
    }

    String::new()
}
