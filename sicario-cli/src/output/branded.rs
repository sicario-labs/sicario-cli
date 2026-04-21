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
    pub rules_loaded: usize,
}

impl ScanSummary {
    /// Build a summary from a list of vulnerabilities.
    pub fn from_vulns(
        vulns: &[Vulnerability],
        scan_duration: Duration,
        files_scanned: usize,
        rules_loaded: usize,
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
            rules_loaded,
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

    let findings_line = format!(
        "Findings: {} total  (C:{} H:{} M:{} L:{} I:{})",
        summary.total_findings,
        summary.critical_count,
        summary.high_count,
        summary.medium_count,
        summary.low_count,
        summary.info_count,
    );

    let duration_line = format!("Duration: {:.2}s", duration_secs);
    let files_line = format!("Files scanned: {}", summary.files_scanned);
    let rules_line = format!("Rules loaded: {}", summary.rules_loaded);
    let semgrep_line = format!("Semgrep estimate: ~{:.1}s (10x slower)", semgrep_estimate);

    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        findings_line,
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
        rules_line,
        width = width - 2
    )?;
    writeln!(
        writer,
        "{v_char}  {:<width$}{v_char}",
        semgrep_line,
        width = width - 2
    )?;
    writeln!(writer, "{bl}{bar}{br}")?;

    Ok(())
}
