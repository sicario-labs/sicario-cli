//! CSV export and BI schema documentation.
//!
//! Requirements: 21.28

use crate::models::*;

/// Generate CSV content from a list of findings.
pub fn findings_to_csv(findings: &[StoredFinding]) -> Result<String, csv::Error> {
    let mut wtr = csv::Writer::from_writer(Vec::new());

    wtr.write_record([
        "id",
        "scan_id",
        "rule_id",
        "rule_name",
        "file_path",
        "line",
        "column",
        "end_line",
        "end_column",
        "snippet",
        "severity",
        "confidence_score",
        "reachable",
        "cloud_exposed",
        "cwe_id",
        "owasp_category",
        "fingerprint",
        "triage_state",
        "triage_note",
        "assigned_to",
        "created_at",
        "updated_at",
    ])?;

    for f in findings {
        wtr.write_record([
            f.id.to_string(),
            f.scan_id.to_string(),
            f.rule_id.clone(),
            f.rule_name.clone(),
            f.file_path.clone(),
            f.line.to_string(),
            f.column.to_string(),
            f.end_line.map_or(String::new(), |v| v.to_string()),
            f.end_column.map_or(String::new(), |v| v.to_string()),
            f.snippet.clone(),
            f.severity.clone(),
            f.confidence_score.to_string(),
            f.reachable.to_string(),
            f.cloud_exposed.map_or(String::new(), |v| v.to_string()),
            f.cwe_id.clone().unwrap_or_default(),
            f.owasp_category.clone().unwrap_or_default(),
            f.fingerprint.clone(),
            f.triage_state.clone(),
            f.triage_note.clone().unwrap_or_default(),
            f.assigned_to.clone().unwrap_or_default(),
            f.created_at.to_rfc3339(),
            f.updated_at.to_rfc3339(),
        ])?;
    }

    let bytes = wtr.into_inner().map_err(|e| e.into_error())?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Return the documented data schema for BI tool integration.
///
/// Schema describes the Convex tables. Types use Convex's type system
/// but are presented in a BI-friendly format for Grafana/Looker/Snowflake.
pub fn export_schema() -> ExportSchema {
    ExportSchema {
        version: "1.0.0".to_string(),
        tables: vec![
            ExportTable {
                name: "scans".to_string(),
                columns: vec![
                    col("id", "string (UUID)", "Unique scan identifier"),
                    col("repository", "string", "Git repository URL or name"),
                    col("branch", "string", "Git branch name"),
                    col("commit_sha", "string", "Git commit SHA"),
                    col("timestamp", "string (ISO 8601)", "Scan execution timestamp"),
                    col("duration_ms", "number", "Scan duration in milliseconds"),
                    col("rules_loaded", "number", "Number of security rules loaded"),
                    col("files_scanned", "number", "Number of files scanned"),
                    col("language_breakdown", "object", "File count per language"),
                    col("tags", "array<string>", "User-defined tags"),
                ],
            },
            ExportTable {
                name: "findings".to_string(),
                columns: vec![
                    col("id", "string (UUID)", "Unique finding identifier"),
                    col("scan_id", "string (UUID)", "Reference to scans table"),
                    col("rule_id", "string", "Security rule identifier"),
                    col("rule_name", "string", "Human-readable rule name"),
                    col("file_path", "string", "Source file path"),
                    col("line", "number", "Start line number"),
                    col("column", "number", "Start column number"),
                    col("end_line", "number | null", "End line number"),
                    col("end_column", "number | null", "End column number"),
                    col("snippet", "string", "Code snippet containing the finding"),
                    col(
                        "severity",
                        "string",
                        "Severity: Info, Low, Medium, High, Critical",
                    ),
                    col("confidence_score", "number", "AI confidence score 0.0-1.0"),
                    col(
                        "reachable",
                        "boolean",
                        "Whether finding is reachable from entry point",
                    ),
                    col(
                        "cloud_exposed",
                        "boolean | null",
                        "Whether finding is cloud-exposed",
                    ),
                    col("cwe_id", "string | null", "CWE identifier"),
                    col("owasp_category", "string | null", "OWASP Top 10 category"),
                    col(
                        "fingerprint",
                        "string",
                        "Stable finding fingerprint for deduplication",
                    ),
                    col(
                        "triage_state",
                        "string",
                        "Triage state: Open, Reviewing, ToFix, Fixed, Ignored, AutoIgnored",
                    ),
                    col("triage_note", "string | null", "Triage note from reviewer"),
                    col("assigned_to", "string | null", "Assigned team member"),
                    col(
                        "created_at",
                        "string (ISO 8601)",
                        "Finding creation timestamp",
                    ),
                    col("updated_at", "string (ISO 8601)", "Last update timestamp"),
                ],
            },
            ExportTable {
                name: "projects".to_string(),
                columns: vec![
                    col("id", "string (UUID)", "Unique project identifier"),
                    col("name", "string", "Project name"),
                    col("repository_url", "string", "Repository URL"),
                    col("description", "string", "Project description"),
                    col(
                        "team_id",
                        "string (UUID) | null",
                        "Reference to teams table",
                    ),
                    col("created_at", "string (ISO 8601)", "Creation timestamp"),
                ],
            },
            ExportTable {
                name: "teams".to_string(),
                columns: vec![
                    col("id", "string (UUID)", "Unique team identifier"),
                    col("name", "string", "Team name"),
                    col(
                        "org_id",
                        "string (UUID)",
                        "Reference to organizations table",
                    ),
                    col("created_at", "string (ISO 8601)", "Creation timestamp"),
                ],
            },
            ExportTable {
                name: "organizations".to_string(),
                columns: vec![
                    col("id", "string (UUID)", "Unique organization identifier"),
                    col("name", "string", "Organization name"),
                    col("created_at", "string (ISO 8601)", "Creation timestamp"),
                ],
            },
            ExportTable {
                name: "webhooks".to_string(),
                columns: vec![
                    col("id", "string (UUID)", "Unique webhook identifier"),
                    col(
                        "org_id",
                        "string (UUID)",
                        "Reference to organizations table",
                    ),
                    col("url", "string", "Webhook delivery URL"),
                    col("events", "array<string>", "Event types to trigger on"),
                    col(
                        "delivery_type",
                        "string",
                        "Delivery format: slack, teams, pagerduty, http",
                    ),
                    col("secret", "string | null", "HMAC signing secret"),
                    col("enabled", "boolean", "Whether webhook is active"),
                    col("created_at", "string (ISO 8601)", "Creation timestamp"),
                ],
            },
            ExportTable {
                name: "webhook_deliveries".to_string(),
                columns: vec![
                    col("id", "string (UUID)", "Unique delivery identifier"),
                    col("webhook_id", "string (UUID)", "Reference to webhooks table"),
                    col("event_type", "string", "Event type that triggered delivery"),
                    col("payload", "object", "Webhook payload body"),
                    col("status", "string", "Delivery status"),
                    col(
                        "response_code",
                        "number | null",
                        "HTTP response code from target",
                    ),
                    col("delivered_at", "string (ISO 8601)", "Delivery timestamp"),
                ],
            },
            ExportTable {
                name: "memberships".to_string(),
                columns: vec![
                    col("user_id", "string", "User identifier"),
                    col(
                        "org_id",
                        "string (UUID)",
                        "Reference to organizations table",
                    ),
                    col("role", "string", "Role: admin, manager, developer"),
                    col(
                        "team_ids",
                        "array<string>",
                        "Team IDs the member belongs to",
                    ),
                    col(
                        "created_at",
                        "string (ISO 8601)",
                        "Membership creation timestamp",
                    ),
                ],
            },
        ],
    }
}

fn col(name: &str, col_type: &str, description: &str) -> ExportColumn {
    ExportColumn {
        name: name.to_string(),
        col_type: col_type.to_string(),
        description: description.to_string(),
    }
}
