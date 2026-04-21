//! OWASP Top 10 compliance report generation
//!
//! Groups vulnerabilities by OWASP category, computes severity distributions,
//! and exports reports in JSON and Markdown formats.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::engine::{OwaspCategory, Severity, Vulnerability};

/// Human-readable label for each OWASP Top 10 2021 category.
pub fn owasp_label(cat: OwaspCategory) -> &'static str {
    match cat {
        OwaspCategory::A01_BrokenAccessControl => "A01:2021 – Broken Access Control",
        OwaspCategory::A02_CryptographicFailures => "A02:2021 – Cryptographic Failures",
        OwaspCategory::A03_Injection => "A03:2021 – Injection",
        OwaspCategory::A04_InsecureDesign => "A04:2021 – Insecure Design",
        OwaspCategory::A05_SecurityMisconfiguration => "A05:2021 – Security Misconfiguration",
        OwaspCategory::A06_VulnerableComponents => "A06:2021 – Vulnerable and Outdated Components",
        OwaspCategory::A07_IdentificationAuthFailures => {
            "A07:2021 – Identification and Authentication Failures"
        }
        OwaspCategory::A08_SoftwareDataIntegrityFailures => {
            "A08:2021 – Software and Data Integrity Failures"
        }
        OwaspCategory::A09_SecurityLoggingFailures => {
            "A09:2021 – Security Logging and Monitoring Failures"
        }
        OwaspCategory::A10_ServerSideRequestForgery => {
            "A10:2021 – Server-Side Request Forgery (SSRF)"
        }
    }
}

/// All OWASP Top 10 2021 categories in order.
pub const ALL_OWASP_CATEGORIES: [OwaspCategory; 10] = [
    OwaspCategory::A01_BrokenAccessControl,
    OwaspCategory::A02_CryptographicFailures,
    OwaspCategory::A03_Injection,
    OwaspCategory::A04_InsecureDesign,
    OwaspCategory::A05_SecurityMisconfiguration,
    OwaspCategory::A06_VulnerableComponents,
    OwaspCategory::A07_IdentificationAuthFailures,
    OwaspCategory::A08_SoftwareDataIntegrityFailures,
    OwaspCategory::A09_SecurityLoggingFailures,
    OwaspCategory::A10_ServerSideRequestForgery,
];

/// Per-category summary used in the compliance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwaspCategoryReport {
    /// OWASP category identifier (e.g. "A03_Injection")
    pub category: String,
    /// Human-readable label
    pub label: String,
    /// Total number of findings in this category
    pub total: usize,
    /// Breakdown by severity
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl OwaspCategoryReport {
    fn new(cat: OwaspCategory) -> Self {
        Self {
            category: format!("{:?}", cat),
            label: owasp_label(cat).to_string(),
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
        }
    }

    fn add(&mut self, severity: Severity) {
        self.total += 1;
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }
}

/// Full compliance report across all OWASP Top 10 categories.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Total vulnerabilities across all categories
    pub total_vulnerabilities: usize,
    /// Number of OWASP categories with at least one finding
    pub categories_affected: usize,
    /// Per-category breakdown (all 10 categories always present)
    pub categories: Vec<OwaspCategoryReport>,
    /// Vulnerabilities that have no OWASP category assigned
    pub uncategorized: usize,
}

/// Build a `ComplianceReport` from a slice of vulnerabilities.
pub fn generate_compliance_report(vulnerabilities: &[Vulnerability]) -> ComplianceReport {
    // Build a map from category → report entry
    let mut map: HashMap<String, OwaspCategoryReport> = ALL_OWASP_CATEGORIES
        .iter()
        .map(|&cat| (format!("{:?}", cat), OwaspCategoryReport::new(cat)))
        .collect();

    let mut uncategorized = 0usize;

    for vuln in vulnerabilities {
        match vuln.owasp_category {
            Some(cat) => {
                let key = format!("{:?}", cat);
                if let Some(entry) = map.get_mut(&key) {
                    entry.add(vuln.severity);
                }
            }
            None => uncategorized += 1,
        }
    }

    // Collect in canonical order
    let categories: Vec<OwaspCategoryReport> = ALL_OWASP_CATEGORIES
        .iter()
        .map(|&cat| map.remove(&format!("{:?}", cat)).unwrap())
        .collect();

    let categories_affected = categories.iter().filter(|c| c.total > 0).count();

    ComplianceReport {
        total_vulnerabilities: vulnerabilities.len(),
        categories_affected,
        categories,
        uncategorized,
    }
}

/// Serialize a `ComplianceReport` to a pretty-printed JSON string.
pub fn report_to_json(report: &ComplianceReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// Render a `ComplianceReport` as a Markdown document.
pub fn report_to_markdown(report: &ComplianceReport) -> String {
    let mut md = String::new();

    md.push_str("# OWASP Top 10 Compliance Report\n\n");
    md.push_str(&format!(
        "**Total vulnerabilities:** {}  \n",
        report.total_vulnerabilities
    ));
    md.push_str(&format!(
        "**Categories affected:** {}/10  \n",
        report.categories_affected
    ));
    if report.uncategorized > 0 {
        md.push_str(&format!(
            "**Uncategorized findings:** {}  \n",
            report.uncategorized
        ));
    }
    md.push('\n');

    md.push_str("## Category Breakdown\n\n");
    md.push_str("| Category | Total | Critical | High | Medium | Low | Info |\n");
    md.push_str("|----------|------:|---------:|-----:|-------:|----:|-----:|\n");

    for cat in &report.categories {
        let status = if cat.total == 0 { "✅" } else { "⚠️" };
        md.push_str(&format!(
            "| {} {} | {} | {} | {} | {} | {} | {} |\n",
            status,
            cat.label,
            cat.total,
            cat.critical,
            cat.high,
            cat.medium,
            cat.low,
            cat.info,
        ));
    }

    md.push('\n');
    md.push_str("## Coverage Summary\n\n");

    let covered = 10 - report.categories_affected;
    md.push_str(&format!(
        "- **{}/10** OWASP Top 10 categories have no findings (clean)\n",
        covered
    ));
    md.push_str(&format!(
        "- **{}/10** OWASP Top 10 categories have findings requiring attention\n",
        report.categories_affected
    ));

    md
}

/// Group a slice of vulnerabilities by OWASP category.
/// Returns a `Vec` of `(OwaspCategory, Vec<&Vulnerability>)` in canonical order,
/// only including categories that have at least one finding.
pub fn group_by_owasp(
    vulnerabilities: &[Vulnerability],
) -> Vec<(OwaspCategory, Vec<&Vulnerability>)> {
    let mut map: HashMap<String, (OwaspCategory, Vec<&Vulnerability>)> = HashMap::new();

    for vuln in vulnerabilities {
        if let Some(cat) = vuln.owasp_category {
            let key = format!("{:?}", cat);
            map.entry(key).or_insert_with(|| (cat, Vec::new())).1.push(vuln);
        }
    }

    // Return in canonical OWASP order
    ALL_OWASP_CATEGORIES
        .iter()
        .filter_map(|&cat| {
            let key = format!("{:?}", cat);
            map.remove(&key)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{OwaspCategory, Severity, Vulnerability};
    use std::path::PathBuf;
    use uuid::Uuid;

    fn make_vuln(severity: Severity, owasp: Option<OwaspCategory>) -> Vulnerability {
        Vulnerability {
            id: Uuid::new_v4(),
            rule_id: "test-rule".to_string(),
            file_path: PathBuf::from("src/main.rs"),
            line: 1,
            column: 1,
            snippet: "code".to_string(),
            severity,
            reachable: true,
            cloud_exposed: None,
            cwe_id: None,
            owasp_category: owasp,
        }
    }

    #[test]
    fn test_empty_report() {
        let report = generate_compliance_report(&[]);
        assert_eq!(report.total_vulnerabilities, 0);
        assert_eq!(report.categories_affected, 0);
        assert_eq!(report.categories.len(), 10);
        assert_eq!(report.uncategorized, 0);
    }

    #[test]
    fn test_report_counts_by_category() {
        let vulns = vec![
            make_vuln(Severity::High, Some(OwaspCategory::A03_Injection)),
            make_vuln(Severity::Critical, Some(OwaspCategory::A03_Injection)),
            make_vuln(Severity::Medium, Some(OwaspCategory::A01_BrokenAccessControl)),
        ];
        let report = generate_compliance_report(&vulns);
        assert_eq!(report.total_vulnerabilities, 3);
        assert_eq!(report.categories_affected, 2);

        let injection = report
            .categories
            .iter()
            .find(|c| c.category == "A03_Injection")
            .unwrap();
        assert_eq!(injection.total, 2);
        assert_eq!(injection.critical, 1);
        assert_eq!(injection.high, 1);
    }

    #[test]
    fn test_uncategorized_counted() {
        let vulns = vec![
            make_vuln(Severity::High, None),
            make_vuln(Severity::Low, Some(OwaspCategory::A03_Injection)),
        ];
        let report = generate_compliance_report(&vulns);
        assert_eq!(report.uncategorized, 1);
        assert_eq!(report.total_vulnerabilities, 2);
    }

    #[test]
    fn test_report_to_json_valid() {
        let vulns = vec![make_vuln(Severity::High, Some(OwaspCategory::A03_Injection))];
        let report = generate_compliance_report(&vulns);
        let json = report_to_json(&report).unwrap();
        assert!(json.contains("A03_Injection"));
        assert!(json.contains("total_vulnerabilities"));
    }

    #[test]
    fn test_report_to_markdown_contains_all_categories() {
        let report = generate_compliance_report(&[]);
        let md = report_to_markdown(&report);
        assert!(md.contains("A01:2021"));
        assert!(md.contains("A10:2021"));
        assert!(md.contains("| Category |"));
    }

    #[test]
    fn test_group_by_owasp_canonical_order() {
        let vulns = vec![
            make_vuln(Severity::High, Some(OwaspCategory::A10_ServerSideRequestForgery)),
            make_vuln(Severity::Medium, Some(OwaspCategory::A01_BrokenAccessControl)),
        ];
        let groups = group_by_owasp(&vulns);
        assert_eq!(groups.len(), 2);
        // A01 should come before A10
        assert_eq!(groups[0].0, OwaspCategory::A01_BrokenAccessControl);
        assert_eq!(groups[1].0, OwaspCategory::A10_ServerSideRequestForgery);
    }

    #[test]
    fn test_all_categories_present_in_report() {
        let report = generate_compliance_report(&[]);
        assert_eq!(report.categories.len(), 10);
        let labels: Vec<&str> = report.categories.iter().map(|c| c.label.as_str()).collect();
        assert!(labels.iter().any(|l| l.contains("A01")));
        assert!(labels.iter().any(|l| l.contains("A10")));
    }
}
