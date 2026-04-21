//! Color-coded severity output, progress bars, and formatted tables.
//!
//! Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.6, 18.8, 18.11, 18.12

use std::io::{self, IsTerminal, Write};

use comfy_table::{modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Table, ContentArrangement, Cell};
use indicatif::{ProgressBar, ProgressStyle};
use owo_colors::OwoColorize;

use crate::engine::vulnerability::{Finding, Severity, Vulnerability};

/// Configuration for output formatting.
#[derive(Debug, Clone)]
pub struct FormatterConfig {
    /// Whether color output is enabled.
    pub color_enabled: bool,
    /// Whether progress bars are enabled (TTY only).
    pub progress_enabled: bool,
    /// Max lines of snippet per finding.
    pub max_lines_per_finding: usize,
    /// Max characters per line before truncation.
    pub max_chars_per_line: usize,
    /// Whether to use Unicode box-drawing characters.
    pub unicode_enabled: bool,
}

impl FormatterConfig {
    /// Build config from CLI flags and TTY detection.
    pub fn from_flags(no_color: bool, force_color: bool, max_lines: usize, max_chars: usize) -> Self {
        let is_tty = io::stdout().is_terminal();
        let color_enabled = if force_color {
            true
        } else if no_color {
            false
        } else {
            is_tty
        };

        Self {
            color_enabled,
            progress_enabled: is_tty && !no_color,
            max_lines_per_finding: max_lines,
            max_chars_per_line: max_chars,
            unicode_enabled: is_tty,
        }
    }
}

/// Format a severity label with color.
pub fn colored_severity(severity: &Severity, color_enabled: bool) -> String {
    let label = match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    };

    if !color_enabled {
        return label.to_string();
    }

    match severity {
        Severity::Critical => label.red().bold().to_string(),
        Severity::High => label.yellow().bold().to_string(),
        Severity::Medium => label.yellow().to_string(),
        Severity::Low => label.blue().to_string(),
        Severity::Info => label.bright_black().to_string(),
    }
}

/// Truncate a line to the configured max chars, appending "…" if truncated.
pub fn truncate_line(line: &str, max_chars: usize) -> String {
    if line.len() <= max_chars {
        line.to_string()
    } else if max_chars > 1 {
        format!("{}…", &line[..max_chars - 1])
    } else {
        "…".to_string()
    }
}

/// Truncate a snippet to the configured max lines and max chars per line.
pub fn truncate_snippet(snippet: &str, max_lines: usize, max_chars: usize) -> String {
    let lines: Vec<&str> = snippet.lines().collect();
    let take = lines.len().min(max_lines);
    let mut result: Vec<String> = lines[..take]
        .iter()
        .map(|l| truncate_line(l, max_chars))
        .collect();
    if lines.len() > max_lines {
        result.push(format!("  ... ({} more lines)", lines.len() - max_lines));
    }
    result.join("\n")
}

/// Create a progress bar for scanning.
pub fn create_scan_progress(total_files: u64, config: &FormatterConfig) -> ProgressBar {
    if !config.progress_enabled {
        return ProgressBar::hidden();
    }

    let pb = ProgressBar::new(total_files);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})"
        )
        .unwrap()
        .progress_chars("█▓░"),
    );
    pb
}

/// Render findings as a formatted table to stdout.
pub fn render_findings_table(
    vulns: &[Vulnerability],
    config: &FormatterConfig,
    writer: &mut dyn Write,
) -> io::Result<()> {
    if vulns.is_empty() {
        writeln!(writer, "No findings detected.")?;
        return Ok(());
    }

    let mut table = Table::new();

    if config.unicode_enabled {
        table.load_preset(UTF8_FULL);
        table.apply_modifier(UTF8_ROUND_CORNERS);
    } else {
        table.load_preset(comfy_table::presets::ASCII_FULL);
    }

    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["Severity", "Confidence", "Rule ID", "File", "Line", "Snippet"]);

    for v in vulns {
        let sev_str = colored_severity(&v.severity, config.color_enabled);
        let confidence_str = "—".to_string(); // confidence scoring not yet wired
        let snippet = truncate_snippet(&v.snippet, config.max_lines_per_finding, config.max_chars_per_line);
        let file_str = v.file_path.display().to_string();

        table.add_row(vec![
            Cell::new(&sev_str),
            Cell::new(&confidence_str),
            Cell::new(&v.rule_id),
            Cell::new(&file_str),
            Cell::new(v.line),
            Cell::new(&snippet),
        ]);
    }

    writeln!(writer, "{table}")?;
    Ok(())
}

/// Render a single finding in compact text format.
pub fn render_finding_text(
    v: &Vulnerability,
    config: &FormatterConfig,
    writer: &mut dyn Write,
) -> io::Result<()> {
    let sev = colored_severity(&v.severity, config.color_enabled);
    let snippet = truncate_snippet(&v.snippet, config.max_lines_per_finding, config.max_chars_per_line);
    writeln!(
        writer,
        "[{}] {} {}:{}",
        sev,
        v.rule_id,
        v.file_path.display(),
        v.line,
    )?;
    for line in snippet.lines() {
        writeln!(writer, "  {line}")?;
    }
    Ok(())
}

/// Render extended findings (with confidence scores) as a formatted table.
///
/// Displays confidence as a percentage (e.g., "92% confidence") per the
/// requirements in 14.7.
pub fn render_extended_findings_table(
    findings: &[Finding],
    config: &FormatterConfig,
    writer: &mut dyn Write,
) -> io::Result<()> {
    use crate::confidence::ConfidenceScorer;
    use crate::confidence::scorer::ConfidenceScoring;

    if findings.is_empty() {
        writeln!(writer, "No findings detected.")?;
        return Ok(());
    }

    let mut table = Table::new();

    if config.unicode_enabled {
        table.load_preset(UTF8_FULL);
        table.apply_modifier(UTF8_ROUND_CORNERS);
    } else {
        table.load_preset(comfy_table::presets::ASCII_FULL);
    }

    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["Severity", "Confidence", "Rule ID", "File", "Line", "Snippet"]);

    for f in findings {
        let sev_str = colored_severity(&f.severity, config.color_enabled);
        let confidence_str = ConfidenceScorer::format_score(f.confidence_score);
        let snippet = truncate_snippet(&f.snippet, config.max_lines_per_finding, config.max_chars_per_line);
        let file_str = f.file_path.display().to_string();

        table.add_row(vec![
            Cell::new(&sev_str),
            Cell::new(&confidence_str),
            Cell::new(&f.rule_id),
            Cell::new(&file_str),
            Cell::new(f.line),
            Cell::new(&snippet),
        ]);
    }

    writeln!(writer, "{table}")?;
    Ok(())
}

/// Render a single extended finding in compact text format with confidence.
pub fn render_extended_finding_text(
    f: &Finding,
    config: &FormatterConfig,
    writer: &mut dyn Write,
) -> io::Result<()> {
    use crate::confidence::ConfidenceScorer;
    use crate::confidence::scorer::ConfidenceScoring;

    let sev = colored_severity(&f.severity, config.color_enabled);
    let confidence = ConfidenceScorer::format_score(f.confidence_score);
    let snippet = truncate_snippet(&f.snippet, config.max_lines_per_finding, config.max_chars_per_line);
    writeln!(
        writer,
        "[{}] ({} confidence) {} {}:{}",
        sev,
        confidence,
        f.rule_id,
        f.file_path.display(),
        f.line,
    )?;
    for line in snippet.lines() {
        writeln!(writer, "  {line}")?;
    }
    Ok(())
}

/// Render diff output with green/red coloring for fix command.
pub fn render_diff(diff_text: &str, config: &FormatterConfig, writer: &mut dyn Write) -> io::Result<()> {
    for line in diff_text.lines() {
        if !config.color_enabled {
            writeln!(writer, "{line}")?;
        } else if line.starts_with('+') && !line.starts_with("+++") {
            writeln!(writer, "{}", line.green())?;
        } else if line.starts_with('-') && !line.starts_with("---") {
            writeln!(writer, "{}", line.red())?;
        } else if line.starts_with("@@") {
            writeln!(writer, "{}", line.cyan())?;
        } else {
            writeln!(writer, "{line}")?;
        }
    }
    Ok(())
}
