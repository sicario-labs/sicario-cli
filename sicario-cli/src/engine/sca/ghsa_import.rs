//! GitHub Security Advisory (GHSA) GraphQL import
//!
//! Queries the GitHub Advisory Database GraphQL API, paginates through results,
//! and upserts records into the local SQLite cache, cross-referencing CVE IDs
//! from existing OSV records.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::engine::Severity;
use super::known_vulnerability::KnownVulnerability;
use super::vuln_db::{severity_to_str, owasp_to_str};

const GHSA_API_URL: &str = "https://api.github.com/graphql";

// ---------------------------------------------------------------------------
// GraphQL request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct GraphQlRequest {
    query: String,
    variables: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct GraphQlResponse {
    data: Option<GraphQlData>,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct GraphQlData {
    #[serde(rename = "securityVulnerabilities")]
    security_vulnerabilities: Option<SecurityVulnerabilitiesConnection>,
}

#[derive(Debug, Deserialize)]
struct SecurityVulnerabilitiesConnection {
    nodes: Vec<GhsaNode>,
    #[serde(rename = "pageInfo")]
    page_info: PageInfo,
}

#[derive(Debug, Deserialize)]
struct PageInfo {
    #[serde(rename = "hasNextPage")]
    has_next_page: bool,
    #[serde(rename = "endCursor")]
    end_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GhsaNode {
    #[serde(rename = "ghsaId")]
    ghsa_id: Option<String>,
    advisory: Option<GhsaAdvisory>,
    package: Option<GhsaPackage>,
    #[serde(rename = "vulnerableVersionRange")]
    vulnerable_version_range: Option<String>,
    #[serde(rename = "firstPatchedVersion")]
    first_patched_version: Option<GhsaFirstPatchedVersion>,
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GhsaAdvisory {
    identifiers: Vec<GhsaIdentifier>,
    summary: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GhsaIdentifier {
    #[serde(rename = "type")]
    id_type: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct GhsaPackage {
    name: String,
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct GhsaFirstPatchedVersion {
    identifier: String,
}

// ---------------------------------------------------------------------------
// Importer
// ---------------------------------------------------------------------------

pub struct GhsaImporter {
    conn: Arc<Mutex<Connection>>,
    /// Optional GitHub token for authenticated requests (higher rate limits)
    github_token: Option<String>,
}

impl GhsaImporter {
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        let github_token = std::env::var("GITHUB_TOKEN").ok();
        Self { conn, github_token }
    }

    /// Import all GHSA advisories, paginating through the full result set.
    /// Returns the number of new/updated records upserted.
    pub fn import_all(&self) -> Result<usize> {
        let mut total = 0usize;
        let mut cursor: Option<String> = None;

        loop {
            let (nodes, page_info) = self.fetch_page(cursor.as_deref())?;
            for node in nodes {
                if let Ok(kv) = ghsa_node_to_known_vulnerability(node) {
                    if self.upsert_kv(&kv).is_ok() {
                        total += 1;
                    }
                }
            }

            if !page_info.has_next_page {
                break;
            }
            cursor = page_info.end_cursor;
        }

        Ok(total)
    }

    /// Fetch a single page of GHSA advisories.
    fn fetch_page(&self, after: Option<&str>) -> Result<(Vec<GhsaNode>, PageInfo)> {
        let after_arg = match after {
            Some(c) => format!(r#", after: "{}""#, c),
            None => String::new(),
        };

        let query = format!(
            r#"
            query {{
              securityVulnerabilities(first: 100{}) {{
                nodes {{
                  ghsaId
                  advisory {{
                    identifiers {{ type value }}
                    summary
                  }}
                  package {{ name ecosystem }}
                  vulnerableVersionRange
                  firstPatchedVersion {{ identifier }}
                  severity
                }}
                pageInfo {{
                  hasNextPage
                  endCursor
                }}
              }}
            }}
            "#,
            after_arg
        );

        let request_body = GraphQlRequest {
            query,
            variables: serde_json::Value::Object(Default::default()),
        };

        let client = reqwest::blocking::Client::new();
        let mut req = client
            .post(GHSA_API_URL)
            .header("Content-Type", "application/json")
            .header("User-Agent", "sicario-cli/0.1");

        if let Some(ref token) = self.github_token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        let response = req
            .json(&request_body)
            .send()
            .context("Failed to send GHSA GraphQL request")?;

        if !response.status().is_success() {
            anyhow::bail!("GHSA API returned HTTP {}", response.status());
        }

        let gql_response: GraphQlResponse = response
            .json()
            .context("Failed to parse GHSA GraphQL response")?;

        if !gql_response.errors.is_empty() {
            anyhow::bail!("GHSA GraphQL errors: {:?}", gql_response.errors);
        }

        let conn = gql_response
            .data
            .and_then(|d| d.security_vulnerabilities)
            .ok_or_else(|| anyhow::anyhow!("No securityVulnerabilities in GHSA response"))?;

        Ok((conn.nodes, conn.page_info))
    }

    fn upsert_kv(&self, kv: &KnownVulnerability) -> Result<()> {
        let conn = self.conn.lock().map_err(|e| anyhow::anyhow!("Lock error: {}", e))?;

        let versions_json = serde_json::to_string(&kv.vulnerable_versions)?;
        let severity_str = severity_to_str(kv.severity);
        let owasp_str = kv.owasp_category.map(owasp_to_str);
        let unique_key = kv.unique_key();

        conn.execute(
            "INSERT OR REPLACE INTO known_vulnerabilities
             (cve_id, ghsa_id, package_name, ecosystem, vulnerable_versions,
              patched_version, summary, severity, owasp_category, last_synced_at, unique_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                kv.cve_id,
                kv.ghsa_id,
                kv.package_name,
                kv.ecosystem,
                versions_json,
                kv.patched_version,
                kv.summary,
                severity_str,
                owasp_str,
                kv.last_synced_at.to_rfc3339(),
                unique_key,
            ],
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn ghsa_node_to_known_vulnerability(node: GhsaNode) -> Result<KnownVulnerability> {
    let package = node
        .package
        .ok_or_else(|| anyhow::anyhow!("GHSA node missing package"))?;

    // Extract CVE ID from advisory identifiers
    let mut cve_id: Option<String> = None;
    let mut summary = String::new();

    if let Some(ref advisory) = node.advisory {
        for id in &advisory.identifiers {
            if id.id_type == "CVE" && cve_id.is_none() {
                cve_id = Some(id.value.clone());
            }
        }
        if let Some(ref s) = advisory.summary {
            summary = s.clone();
        }
    }

    if summary.is_empty() {
        summary = format!("Vulnerability in {}", package.name);
    }

    // Build semver range from vulnerableVersionRange
    let vulnerable_versions = node
        .vulnerable_version_range
        .as_deref()
        .map(parse_ghsa_version_range)
        .unwrap_or_default();

    let patched_version = node
        .first_patched_version
        .map(|v| v.identifier);

    let severity = ghsa_severity_to_enum(node.severity.as_deref());

    // Normalize ecosystem name to match OSV conventions
    let ecosystem = normalize_ecosystem(&package.ecosystem);

    Ok(KnownVulnerability {
        cve_id,
        ghsa_id: node.ghsa_id,
        package_name: package.name,
        ecosystem,
        vulnerable_versions,
        patched_version,
        summary,
        severity,
        owasp_category: None,
        last_synced_at: Utc::now(),
    })
}

/// Parse GHSA's `vulnerableVersionRange` string into semver range strings.
///
/// GHSA uses a comma-separated format like `>= 1.0.0, < 2.0.0`.
fn parse_ghsa_version_range(range: &str) -> Vec<String> {
    // GHSA already uses semver-compatible range syntax; wrap in a Vec
    let trimmed = range.trim();
    if trimmed.is_empty() {
        Vec::new()
    } else {
        vec![trimmed.to_string()]
    }
}

fn ghsa_severity_to_enum(severity: Option<&str>) -> Severity {
    match severity {
        Some("CRITICAL") => Severity::Critical,
        Some("HIGH") => Severity::High,
        Some("MODERATE") => Severity::Medium,
        Some("LOW") => Severity::Low,
        _ => Severity::Medium,
    }
}

/// Normalize GHSA ecosystem names to match OSV conventions.
fn normalize_ecosystem(ecosystem: &str) -> String {
    match ecosystem.to_uppercase().as_str() {
        "NPM" => "npm".to_string(),
        "PYPI" => "PyPI".to_string(),
        "RUST" | "CRATES_IO" => "crates.io".to_string(),
        "MAVEN" => "Maven".to_string(),
        "GO" => "Go".to_string(),
        "RUBYGEMS" => "RubyGems".to_string(),
        "NUGET" => "NuGet".to_string(),
        _ => ecosystem.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ghsa_version_range() {
        let ranges = parse_ghsa_version_range(">= 1.0.0, < 2.0.0");
        assert_eq!(ranges, vec![">= 1.0.0, < 2.0.0"]);
    }

    #[test]
    fn test_parse_ghsa_version_range_empty() {
        let ranges = parse_ghsa_version_range("");
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_ghsa_severity_to_enum() {
        assert_eq!(ghsa_severity_to_enum(Some("CRITICAL")), Severity::Critical);
        assert_eq!(ghsa_severity_to_enum(Some("HIGH")), Severity::High);
        assert_eq!(ghsa_severity_to_enum(Some("MODERATE")), Severity::Medium);
        assert_eq!(ghsa_severity_to_enum(Some("LOW")), Severity::Low);
        assert_eq!(ghsa_severity_to_enum(None), Severity::Medium);
    }

    #[test]
    fn test_normalize_ecosystem() {
        assert_eq!(normalize_ecosystem("NPM"), "npm");
        assert_eq!(normalize_ecosystem("PYPI"), "PyPI");
        assert_eq!(normalize_ecosystem("RUST"), "crates.io");
        assert_eq!(normalize_ecosystem("MAVEN"), "Maven");
        assert_eq!(normalize_ecosystem("GO"), "Go");
    }

    #[test]
    fn test_ghsa_node_conversion() {
        let node = GhsaNode {
            ghsa_id: Some("GHSA-test-1234-5678".to_string()),
            advisory: Some(GhsaAdvisory {
                identifiers: vec![GhsaIdentifier {
                    id_type: "CVE".to_string(),
                    value: "CVE-2023-1234".to_string(),
                }],
                summary: Some("Test vulnerability".to_string()),
            }),
            package: Some(GhsaPackage {
                name: "test-pkg".to_string(),
                ecosystem: "NPM".to_string(),
            }),
            vulnerable_version_range: Some(">= 1.0.0, < 2.0.0".to_string()),
            first_patched_version: Some(GhsaFirstPatchedVersion {
                identifier: "2.0.0".to_string(),
            }),
            severity: Some("HIGH".to_string()),
        };

        let kv = ghsa_node_to_known_vulnerability(node).unwrap();
        assert_eq!(kv.package_name, "test-pkg");
        assert_eq!(kv.ecosystem, "npm");
        assert_eq!(kv.cve_id, Some("CVE-2023-1234".to_string()));
        assert_eq!(kv.ghsa_id, Some("GHSA-test-1234-5678".to_string()));
        assert_eq!(kv.severity, Severity::High);
        assert_eq!(kv.patched_version, Some("2.0.0".to_string()));
        assert!(!kv.vulnerable_versions.is_empty());
    }
}
