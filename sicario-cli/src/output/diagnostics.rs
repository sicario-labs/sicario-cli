//! Miette-style diagnostic output for scan findings.
//!
//! Renders vulnerabilities as compiler-style diagnostics with source context,
//! span underlines, and help hints — without depending on miette's Report type.

use std::io::{self, Write};

use owo_colors::OwoColorize;

use crate::engine::vulnerability::{Severity, Vulnerability};

/// Render all vulnerabilities as miette/rustc-style diagnostics, grouped by file.
/// Files are sorted by the maximum severity of their findings to ensure critical
/// issues appear first. Inline remediation commands are appended to help developers
/// immediately fix detected issues.
/// Implements Tasks 2.1 and 3.1 of the DX Improvement Plan.
pub fn render_diagnostics(
    vulns: &[Vulnerability],
    color_enabled: bool,
    writer: &mut dyn Write,
) -> io::Result<()> {
    if vulns.is_empty() {
        writeln!(writer, "No findings detected.")?;
        return Ok(());
    }

    // Separate normal file-based SAST/Secrets findings from pure synthetic SCA findings
    let mut normal_vulns = Vec::new();
    let mut sca_vulns = Vec::new();

    for v in vulns {
        if is_sca_finding(v) {
            sca_vulns.push(v);
        } else {
            normal_vulns.push(v);
        }
    }

    // Group normal findings by file path
    // Using std::collections::BTreeMap preserves a deterministic base ordering
    let mut groups: std::collections::BTreeMap<std::path::PathBuf, Vec<&Vulnerability>> =
        std::collections::BTreeMap::new();
    for v in &normal_vulns {
        groups.entry(v.file_path.clone()).or_default().push(v);
    }

    // Convert groups into a list so we can sort them by maximum severity descending
    struct FileGroup<'a> {
        path: std::path::PathBuf,
        findings: Vec<&'a Vulnerability>,
        max_severity: Severity,
        crit_count: usize,
        high_count: usize,
        med_count: usize,
        low_count: usize,
        info_count: usize,
    }

    let mut sorted_groups = Vec::new();
    for (path, findings) in groups {
        let mut max_severity = Severity::Info;
        let mut crit_count = 0;
        let mut high_count = 0;
        let mut med_count = 0;
        let mut low_count = 0;
        let mut info_count = 0;

        for v in &findings {
            if v.severity > max_severity {
                max_severity = v.severity;
            }
            match v.severity {
                Severity::Critical => crit_count += 1,
                Severity::High => high_count += 1,
                Severity::Medium => med_count += 1,
                Severity::Low => low_count += 1,
                Severity::Info => info_count += 1,
            }
        }

        sorted_groups.push(FileGroup {
            path,
            findings,
            max_severity,
            crit_count,
            high_count,
            med_count,
            low_count,
            info_count,
        });
    }

    // Sort file groups: highest maximum severity first, then by finding count descending, then path ascending
    sorted_groups.sort_by(|a, b| {
        let sev_cmp = b.max_severity.cmp(&a.max_severity);
        if sev_cmp != std::cmp::Ordering::Equal {
            return sev_cmp;
        }
        let count_cmp = b.findings.len().cmp(&a.findings.len());
        if count_cmp != std::cmp::Ordering::Equal {
            return count_cmp;
        }
        a.path.cmp(&b.path)
    });

    // Check if multiple scan types exist for prefixing lines where needed
    let scan_types: std::collections::HashSet<&str> =
        vulns.iter().map(|v| v.scan_type.as_str()).collect();
    let multi_scan_type = scan_types.len() > 1;

    // Instantiate deterministic template registry once to check auto-fixability
    let registry = crate::remediation::TemplateRegistry::default();

    // Render grouped file blocks
    for group in sorted_groups {
        let file_display = group.path.display().to_string();
        let total = group.findings.len();
        let findings_str = if total == 1 { "finding" } else { "findings" };

        // Construct concise breakdown summary e.g. "(2 Critical, 1 High)"
        let mut breakdown = Vec::new();
        if group.crit_count > 0 {
            breakdown.push(format!("{} Critical", group.crit_count));
        }
        if group.high_count > 0 {
            breakdown.push(format!("{} High", group.high_count));
        }
        if group.med_count > 0 {
            breakdown.push(format!("{} Medium", group.med_count));
        }
        if group.low_count > 0 {
            breakdown.push(format!("{} Low", group.low_count));
        }
        if group.info_count > 0 {
            breakdown.push(format!("{} Info", group.info_count));
        }
        let breakdown_str = if breakdown.is_empty() {
            String::new()
        } else {
            format!(" ({})", breakdown.join(", "))
        };

        let header_text = format!(
            "━━ {} ━━━━━━━━━━━━━━━━━━━━━━━ {} {}{}",
            file_display, total, findings_str, breakdown_str
        );
        if color_enabled {
            writeln!(writer, "{}", header_text.bright_blue().bold())?;
        } else {
            writeln!(writer, "{header_text}")?;
        }
        writeln!(writer)?;

        for vuln in group.findings {
            if multi_scan_type {
                let prefix = match vuln.scan_type.as_str() {
                    "secrets" => "[SECRETS]",
                    "sca" => "[SCA]",
                    "license" => "[LICENSE]",
                    _ => "[SAST]",
                };
                if color_enabled {
                    write!(writer, "{} ", prefix.bright_black())?;
                } else {
                    write!(writer, "{prefix} ")?;
                }
            }

            render_one(vuln, color_enabled, writer)?;

            // Append inline remediation / fix command hint (Task 3.1)
            let has_template = registry
                .lookup(&vuln.rule_id, vuln.cwe_id.as_deref())
                .is_some()
                || registry
                    .lookup_multi(&vuln.rule_id, vuln.cwe_id.as_deref())
                    .is_some();

            let auto_fix_badge = if has_template {
                "  (auto-fixable ✓)"
            } else {
                ""
            };
            let fix_cmd = format!(
                "sicario fix --rule {} --file {} --line {}",
                vuln.rule_id,
                vuln.file_path.display(),
                vuln.line
            );

            if color_enabled {
                write!(writer, "  {}:  {}", "fix".green().bold(), fix_cmd)?;
                if has_template {
                    writeln!(writer, "{}", auto_fix_badge.green())?;
                } else {
                    writeln!(writer)?;
                }
            } else {
                writeln!(writer, "  fix:  {fix_cmd}{auto_fix_badge}")?;
            }

            writeln!(writer)?;
        }
    }

    // Render standalone SCA synthetic findings if any exist
    if !sca_vulns.is_empty() {
        let header_text = format!(
            "━━ Dependencies (SCA) ━━━━━━━━━━━━━━━━━━━━━━━ {} findings",
            sca_vulns.len()
        );
        if color_enabled {
            writeln!(writer, "{}", header_text.bright_blue().bold())?;
        } else {
            writeln!(writer, "{header_text}")?;
        }
        writeln!(writer)?;

        for vuln in sca_vulns {
            if multi_scan_type {
                let prefix = match vuln.scan_type.as_str() {
                    "secrets" => "[SECRETS]",
                    "sca" => "[SCA]",
                    "license" => "[LICENSE]",
                    _ => "[SAST]",
                };
                if color_enabled {
                    write!(writer, "{} ", prefix.bright_black())?;
                } else {
                    write!(writer, "{prefix} ")?;
                }
            }

            render_sca(vuln, color_enabled, writer)?;
            writeln!(writer)?;
        }
    }

    Ok(())
}

/// Returns true if this is a synthetic SCA dependency finding.
///
/// SCA findings use a synthetic file path of the form `<ecosystem/package>`,
/// e.g. `<npm/protobufjs>` or `<cargo/openssl>`. They have no real source
/// file to read, so the snippet box must not be rendered.
fn is_sca_finding(vuln: &Vulnerability) -> bool {
    vuln.file_path.to_string_lossy().starts_with('<')
}

/// Render a SCA dependency finding as a clean, minimal block — no snippet box.
///
/// Example output:
/// ```text
///   × [MEDIUM] sca/CVE-2026-4867 (CVE-2026-4867)
///   Dependency: path-to-regexp  |  Ecosystem: npm  |  Source: package.json
///   protobufjs@7.2.4 — Prototype pollution via crafted message
/// ```
fn render_sca(vuln: &Vulnerability, color: bool, w: &mut dyn Write) -> io::Result<()> {
    let sev_tag = severity_tag(vuln.severity);
    let cwe = vuln
        .cwe_id
        .as_deref()
        .map(|c| format!(" ({c})"))
        .unwrap_or_default();

    // Header
    let cross = if color {
        "×".red().bold().to_string()
    } else {
        "×".to_string()
    };
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

    // Parse ecosystem and package name from the synthetic path `<ecosystem/package>`
    let raw_path = vuln.file_path.to_string_lossy();
    let inner = raw_path.trim_start_matches('<').trim_end_matches('>');
    let (ecosystem, package) = inner.split_once('/').unwrap_or(("unknown", inner));

    // Infer the manifest file name from the ecosystem
    let manifest = match ecosystem {
        "npm" => "package.json",
        "cargo" => "Cargo.toml",
        "pypi" => "requirements.txt",
        "maven" => "pom.xml",
        "go" => "go.mod",
        _ => "manifest",
    };

    // Dependency resolution line
    let dep_line = format!(
        "  Dependency: {}  |  Ecosystem: {}  |  Source: {}",
        package, ecosystem, manifest
    );
    if color {
        writeln!(w, "{}", dep_line.bright_black())?;
    } else {
        writeln!(w, "{dep_line}")?;
    }

    // Summary snippet (the human-readable description from the vuln DB)
    if !vuln.snippet.is_empty() {
        let summary = vuln.snippet.lines().next().unwrap_or(&vuln.snippet);
        writeln!(w, "  {summary}")?;
    }

    Ok(())
}

/// Render a single vulnerability as a diagnostic block.
fn render_one(vuln: &Vulnerability, color: bool, w: &mut dyn Write) -> io::Result<()> {
    let sev_tag = severity_tag(vuln.severity);
    let cwe = vuln
        .cwe_id
        .as_deref()
        .map(|c| format!(" ({c})"))
        .unwrap_or_default();

    // Header:  × [CRITICAL] rule-id (CWE-94)
    let cross = if color {
        "×".red().bold().to_string()
    } else {
        "×".to_string()
    };
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
    let loc = format!("{}:{}:{}", vuln.file_path.display(), vuln.line, vuln.column);
    let top_border = if color {
        format!("  {}", format!("╭─[{loc}]").bright_black())
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

    let start = if finding_line > 1 {
        finding_line - 1
    } else {
        1
    };
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
    remaining.clamp(1, 40)
}

/// Extract a short message describing the finding.
fn extract_message(vuln: &Vulnerability) -> String {
    let snippet = vuln.snippet.trim();
    let rule = &vuln.rule_id;

    // Generate a contextual message based on common rule patterns
    if rule.contains("eval") || snippet.contains("eval(") {
        return "Untrusted input passed to eval()".to_string();
    }
    if rule.contains("sql") || rule.contains("injection") {
        return "Potential injection vulnerability".to_string();
    }
    if rule.contains("xss") {
        return "Potential cross-site scripting".to_string();
    }
    if rule.contains("hardcoded") || rule.contains("secret") || rule.contains("password") {
        return "Hardcoded secret or credential".to_string();
    }
    if rule.contains("exec") || rule.contains("command") {
        return "Potential command injection".to_string();
    }
    if rule.contains("path") || rule.contains("traversal") {
        return "Potential path traversal".to_string();
    }
    if rule.contains("deserial") {
        return "Unsafe deserialization".to_string();
    }
    if rule.contains("crypto") || rule.contains("weak") {
        return "Weak cryptographic usage".to_string();
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
        return "Use parameterized queries or prepared statements instead of string concatenation"
            .to_string();
    }
    if r.contains("xss") {
        return "Sanitize or escape user input before inserting into HTML output".to_string();
    }
    if r.contains("command") || r.contains("exec") || r.contains("os-command") {
        return "Avoid passing user input to shell commands; use safe APIs with argument lists"
            .to_string();
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
        return "Simplify the regex pattern or add input length limits to prevent ReDoS"
            .to_string();
    }
    if r.contains("nosql") {
        return "Validate and sanitize input before using in NoSQL queries".to_string();
    }
    if r.contains("info-leak") || r.contains("information-leak") || r.contains("info_leak") {
        return "Avoid exposing internal details in error messages or responses".to_string();
    }

    String::new()
}
