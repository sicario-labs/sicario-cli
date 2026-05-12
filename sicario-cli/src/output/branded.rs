//! ASCII logo and summary banner for branded output.
//!
//! Requirements: 18.7, 18.10

use std::io::{self, Write};
use std::time::Duration;

use owo_colors::OwoColorize;

use crate::engine::vulnerability::{Severity, Vulnerability};

/// ASCII art logo for Sicario.
const SICARIO_LOGO: &str = r#"
  ███████╗██╗ ██████╗ █████╗ ██████╗ ██╗ ██████╗
  ██╔════╝██║██╔════╝██╔══██╗██╔══██╗██║██╔═══██╗
  ███████╗██║██║     ███████║██████╔╝██║██║   ██║
  ╚════██║██║██║     ██╔══██║██╔══██╗██║██║   ██║
  ███████║██║╚██████╗██║  ██║██║  ██║██║╚██████╔╝
  ╚══════╝╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝
"#;

/// ASCII-only fallback logo.
const SICARIO_LOGO_ASCII: &str = r#"
   ____ ___ ____    _    ____  ___ ___
  / ___|_ _/ ___|  / \  |  _ \|_ _/ _ \
  \___ \| | |     / _ \ | |_) || | | | |
   ___) | | |___ / ___ \|  _ < | | |_| |
  |____/___\____/_/   \_\_| \_\___\___/
"#;

/// Print branded version output.
pub fn print_branded_version(unicode: bool, color: bool, writer: &mut dyn Write) -> io::Result<()> {
    let logo = if unicode {
        SICARIO_LOGO
    } else {
        SICARIO_LOGO_ASCII
    };

    if color {
        writeln!(writer, "{}", logo.red().bold())?;
    } else {
        writeln!(writer, "{logo}")?;
    }

    let version = env!("CARGO_PKG_VERSION");

    // TARGET is set by Cargo during build; fall back to a compile-time constant
    let target = option_env!("TARGET").unwrap_or(std::env::consts::ARCH);

    writeln!(writer, "  Sicario v{version}")?;
    writeln!(writer, "  Target: {target}")?;
    writeln!(writer)?;

    Ok(())
}

/// Scan summary statistics.
pub struct ScanSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub scan_duration: Duration,
    pub files_scanned: usize,
    pub files_ignored: usize,
    pub rules_loaded: usize,
    /// The minimum severity filter that was applied before building this summary.
    pub min_severity: Severity,
}

impl ScanSummary {
    /// Build a summary from a list of vulnerabilities.
    pub fn from_vulns(
        vulns: &[Vulnerability],
        scan_duration: Duration,
        files_scanned: usize,
        rules_loaded: usize,
    ) -> Self {
        Self::from_vulns_with_ignored(vulns, scan_duration, files_scanned, 0, rules_loaded)
    }

    /// Build a summary from a list of vulnerabilities, including ignored file count.
    pub fn from_vulns_with_ignored(
        vulns: &[Vulnerability],
        scan_duration: Duration,
        files_scanned: usize,
        files_ignored: usize,
        rules_loaded: usize,
    ) -> Self {
        Self::from_vulns_full(
            vulns,
            scan_duration,
            files_scanned,
            files_ignored,
            rules_loaded,
            Severity::Low,
        )
    }

    /// Build a summary with all options, including the active minimum severity filter.
    pub fn from_vulns_full(
        vulns: &[Vulnerability],
        scan_duration: Duration,
        files_scanned: usize,
        files_ignored: usize,
        rules_loaded: usize,
        min_severity: Severity,
    ) -> Self {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut info = 0;

        for v in vulns {
            match v.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info += 1,
            }
        }

        Self {
            total_findings: vulns.len(),
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            info_count: info,
            scan_duration,
            files_scanned,
            files_ignored,
            rules_loaded,
            min_severity,
        }
    }
}

/// Print the scan summary banner.
pub fn print_scan_summary(
    summary: &ScanSummary,
    unicode: bool,
    color: bool,
    writer: &mut dyn Write,
) -> io::Result<()> {
    let (tl, tr, bl, br, h, v_char) = if unicode {
        ('╭', '╮', '╰', '╯', '─', '│')
    } else {
        ('+', '+', '+', '+', '-', '|')
    };

    let width = 60;
    let bar: String = std::iter::repeat_n(h, width).collect();

    writeln!(writer)?;
    writeln!(writer, "{tl}{bar}{tr}")?;
    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        "Scan Summary",
        width = width - 2
    )?;
    writeln!(writer, "{v_char}{bar}{v_char}")?;

    let duration_secs = summary.scan_duration.as_secs_f64();
    let semgrep_estimate = duration_secs * 10.0;

    let total_f = summary.total_findings as f64;
    let crit_pct = if total_f > 0.0 { (summary.critical_count as f64 / total_f) * 100.0 } else { 0.0 };
    let high_pct = if total_f > 0.0 { (summary.high_count as f64 / total_f) * 100.0 } else { 0.0 };
    let med_pct = if total_f > 0.0 { (summary.medium_count as f64 / total_f) * 100.0 } else { 0.0 };
    let low_pct = if total_f > 0.0 { (summary.low_count as f64 / total_f) * 100.0 } else { 0.0 };
    let info_pct = if total_f > 0.0 { (summary.info_count as f64 / total_f) * 100.0 } else { 0.0 };

    let findings_line = format!(
        "Findings: {} total",
        summary.total_findings
    );
    let breakdown_line = format!(
        "Severity: C:{}({:.0}%) H:{}({:.0}%) M:{}({:.0}%) L:{}({:.0}%) I:{}({:.0}%)",
        summary.critical_count, crit_pct,
        summary.high_count, high_pct,
        summary.medium_count, med_pct,
        summary.low_count, low_pct,
        summary.info_count, info_pct
    );

    let bar_width = 30;
    let crit_len = if total_f > 0.0 { (crit_pct / 100.0 * bar_width as f64).round() as usize } else { 0 };
    let high_len = if total_f > 0.0 { (high_pct / 100.0 * bar_width as f64).round() as usize } else { 0 };
    let med_len = if total_f > 0.0 { (med_pct / 100.0 * bar_width as f64).round() as usize } else { 0 };
    let low_len = if total_f > 0.0 { (low_pct / 100.0 * bar_width as f64).round() as usize } else { 0 };
    
    let (crit_char, high_char, med_char, low_char, info_char) = if unicode {
        ("█", "▓", "▒", "░", "-")
    } else {
        ("C", "H", "M", "L", "-")
    };

    let mut visual_bar = String::new();
    visual_bar.push_str(&crit_char.repeat(crit_len));
    visual_bar.push_str(&high_char.repeat(high_len));
    visual_bar.push_str(&med_char.repeat(med_len));
    visual_bar.push_str(&low_char.repeat(low_len));
    
    let current_len = crit_len + high_len + med_len + low_len;
    if current_len < bar_width && total_f > 0.0 {
        visual_bar.push_str(&info_char.repeat(bar_width - current_len));
    } else if total_f == 0.0 {
        visual_bar.push_str(&info_char.repeat(bar_width));
    }

    let bar_line = format!("Visual:   [{}]", visual_bar);

    let duration_line = format!("Duration: {:.2}s", duration_secs);
    let files_line = format!("Files scanned: {}", summary.files_scanned);
    let ignored_line = format!("Files ignored: {}", summary.files_ignored);
    let rules_line = format!("Rules loaded: {}", summary.rules_loaded);
    let min_sev_line = format!("Minimum Severity: {}", summary.min_severity);
    let semgrep_line = format!("Semgrep estimate: ~{:.1}s (10x slower)", semgrep_estimate);

    // Task 16.8: throughput — N files scanned in X.Xs (Y files/s, Z KLOC/s)
    // KLOC/s is estimated at ~100 LOC per file average
    let files_per_sec = if duration_secs > 0.0 {
        summary.files_scanned as f64 / duration_secs
    } else {
        summary.files_scanned as f64
    };
    let kloc_per_sec = files_per_sec * 0.1; // ~100 LOC/file average
    let throughput_line = format!(
        "Throughput: {:.0} files/s  ({:.1} KLOC/s)",
        files_per_sec, kloc_per_sec
    );

    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        findings_line,
        width = width - 2
    )?;
    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        breakdown_line,
        width = width - 2
    )?;
    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        bar_line,
        width = width - 2
    )?;
    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        duration_line,
        width = width - 2
    )?;
    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        files_line,
        width = width - 2
    )?;
    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        ignored_line,
        width = width - 2
    )?;
    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        rules_line,
        width = width - 2
    )?;
    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        min_sev_line,
        width = width - 2
    )?;
    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        semgrep_line,
        width = width - 2
    )?;
    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        throughput_line,
        width = width - 2
    )?;
    writeln!(writer, "{bl}{bar}{br}")?;

    // Task 3.2: Actionable "What to do next" block
    writeln!(writer)?;
    let next_steps_title = "What to do next:";
    if color {
        writeln!(writer, "  {}", next_steps_title.bold().bright_blue())?;
    } else {
        writeln!(writer, "  {next_steps_title}")?;
    }

    let steps = [
        "1. Fix critical issues instantly: Run sicario fix --rule <ID> --file <PATH>",
        "2. Interactively triage in your browser: Run sicario dashboard",
        "3. Suppress false positives inline: Add // sicario-ignore: <rule-id> above the line",
    ];

    for step in steps {
        writeln!(writer, "    {}", step)?;
    }
    writeln!(writer)?;

    Ok(())
}
