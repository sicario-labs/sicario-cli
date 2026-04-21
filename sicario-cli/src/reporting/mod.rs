//! OWASP compliance reporting module
//!
//! Groups vulnerabilities by OWASP Top 10 category, generates compliance
//! reports in JSON and Markdown formats.

#[cfg(test)]
pub mod owasp_property_tests;
pub mod owasp_report;

pub use owasp_report::{
    generate_compliance_report, group_by_owasp, report_to_json, report_to_markdown,
    ComplianceReport, OwaspCategoryReport,
};

use anyhow::Result;
use std::path::Path;

/// Write a compliance report to disk in both JSON and Markdown formats.
///
/// - `{output_dir}/owasp_report.json`
/// - `{output_dir}/owasp_report.md`
pub fn write_compliance_reports(
    report: &ComplianceReport,
    output_dir: &Path,
) -> Result<(std::path::PathBuf, std::path::PathBuf)> {
    std::fs::create_dir_all(output_dir)?;

    let json_path = output_dir.join("owasp_report.json");
    let md_path = output_dir.join("owasp_report.md");

    let json = report_to_json(report)?;
    std::fs::write(&json_path, &json)?;

    let md = report_to_markdown(report);
    std::fs::write(&md_path, &md)?;

    Ok((json_path, md_path))
}
