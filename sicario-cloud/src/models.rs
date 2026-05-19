//! Data models for the Sicario Cloud Platform REST API.
//!
//! These mirror the OpenAPI schema and database tables.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ── Enums ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "Info"),
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Info" => Ok(Severity::Info),
            "Low" => Ok(Severity::Low),
            "Medium" => Ok(Severity::Medium),
            "High" => Ok(Severity::High),
            "Critical" => Ok(Severity::Critical),
            _ => Err(format!("unknown severity: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriageState {
    Open,
    Reviewing,
    ToFix,
    Fixed,
    Ignored,
    AutoIgnored,
}

impl std::fmt::Display for TriageState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TriageState::Open => write!(f, "Open"),
            TriageState::Reviewing => write!(f, "Reviewing"),
            TriageState::ToFix => write!(f, "ToFix"),
            TriageState::Fixed => write!(f, "Fixed"),
            TriageState::Ignored => write!(f, "Ignored"),
            TriageState::AutoIgnored => write!(f, "AutoIgnored"),
        }
    }
}

impl std::str::FromStr for TriageState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Open" => Ok(TriageState::Open),
            "Reviewing" => Ok(TriageState::Reviewing),
            "ToFix" => Ok(TriageState::ToFix),
            "Fixed" => Ok(TriageState::Fixed),
            "Ignored" => Ok(TriageState::Ignored),
            "AutoIgnored" => Ok(TriageState::AutoIgnored),
            _ => Err(format!("unknown triage state: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebhookDeliveryType {
    Slack,
    Teams,
    Pagerduty,
    Http,
}

impl std::fmt::Display for WebhookDeliveryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookDeliveryType::Slack => write!(f, "slack"),
            WebhookDeliveryType::Teams => write!(f, "teams"),
            WebhookDeliveryType::Pagerduty => write!(f, "pagerduty"),
            WebhookDeliveryType::Http => write!(f, "http"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebhookEventType {
    CriticalFinding,
    SlaBreach,
    ScanFailure,
}

impl std::fmt::Display for WebhookEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookEventType::CriticalFinding => write!(f, "critical_finding"),
            WebhookEventType::SlaBreach => write!(f, "sla_breach"),
            WebhookEventType::ScanFailure => write!(f, "scan_failure"),
        }
    }
}

// ── Request / Response types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub repository: String,
    pub branch: String,
    pub commit_sha: String,
    pub timestamp: DateTime<Utc>,
    pub duration_ms: u64,
    pub rules_loaded: usize,
    pub files_scanned: usize,
    #[serde(default)]
    pub language_breakdown: HashMap<String, usize>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Incoming finding from the CLI publish client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingFinding {
    pub id: Uuid,
    pub rule_id: String,
    pub rule_name: String,
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub end_line: Option<usize>,
    pub end_column: Option<usize>,
    pub snippet: String,
    pub severity: Severity,
    pub confidence_score: f64,
    pub reachable: bool,
    pub cloud_exposed: Option<bool>,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub fingerprint: String,
    #[serde(default)]
    pub suppressed: bool,
    pub suppression_rule: Option<String>,
    #[serde(default)]
    pub suggested_suppression: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub findings: Vec<IncomingFinding>,
    pub metadata: ScanMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishResponse {
    pub scan_id: String,
    pub dashboard_url: Option<String>,
}

// ── Stored entities ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scan {
    pub id: Uuid,
    pub repository: String,
    pub branch: String,
    pub commit_sha: String,
    pub timestamp: DateTime<Utc>,
    pub duration_ms: i64,
    pub rules_loaded: i32,
    pub files_scanned: i32,
    pub language_breakdown: HashMap<String, usize>,
    pub tags: Vec<String>,
    pub findings_count: i64,
    pub critical_count: i64,
    pub high_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredFinding {
    pub id: Uuid,
    pub scan_id: Uuid,
    pub rule_id: String,
    pub rule_name: String,
    pub file_path: String,
    pub line: i32,
    pub column: i32,
    pub end_line: Option<i32>,
    pub end_column: Option<i32>,
    pub snippet: String,
    pub severity: String,
    pub confidence_score: f64,
    pub reachable: bool,
    pub cloud_exposed: Option<bool>,
    pub cwe_id: Option<String>,
    pub owasp_category: Option<String>,
    pub fingerprint: String,
    pub triage_state: String,
    pub triage_note: Option<String>,
    pub assigned_to: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub repository_url: String,
    pub description: String,
    pub team_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Team {
    pub id: Uuid,
    pub name: String,
    pub org_id: Uuid,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub id: Uuid,
    pub org_id: Uuid,
    pub url: String,
    pub events: Vec<WebhookEventType>,
    pub delivery_type: WebhookDeliveryType,
    pub secret: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
}

// ── Analytics ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsOverview {
    pub total_findings: i64,
    pub open_findings: i64,
    pub fixed_findings: i64,
    pub ignored_findings: i64,
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub info_count: i64,
    pub total_scans: i64,
    pub avg_scan_duration_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendDataPoint {
    pub timestamp: DateTime<Utc>,
    pub open_findings: i64,
    pub new_findings: i64,
    pub fixed_findings: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MttrMetrics {
    pub overall_mttr_hours: f64,
    pub by_severity: HashMap<String, f64>,
}

// ── Pagination ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
    pub items: Vec<T>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_per_page")]
    pub per_page: i64,
}

fn default_page() -> i64 {
    1
}
fn default_per_page() -> i64 {
    20
}

// ── Request bodies ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct TriageFindingRequest {
    pub triage_state: Option<TriageState>,
    pub triage_note: Option<String>,
    pub assigned_to: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BulkTriageRequest {
    pub finding_ids: Vec<Uuid>,
    pub triage_state: TriageState,
    pub triage_note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BulkTriageResponse {
    pub updated_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
    pub repository_url: Option<String>,
    pub description: Option<String>,
    pub team_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateProjectRequest {
    pub name: Option<String>,
    pub repository_url: Option<String>,
    pub description: Option<String>,
    pub team_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
    pub org_id: Uuid,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateWebhookRequest {
    pub url: String,
    pub events: Vec<WebhookEventType>,
    pub delivery_type: WebhookDeliveryType,
    pub secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateWebhookRequest {
    pub url: Option<String>,
    pub events: Option<Vec<WebhookEventType>>,
    pub delivery_type: Option<WebhookDeliveryType>,
    pub secret: Option<String>,
    pub enabled: Option<bool>,
}

// ── Export schema ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ExportSchema {
    pub version: String,
    pub tables: Vec<ExportTable>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportTable {
    pub name: String,
    pub columns: Vec<ExportColumn>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportColumn {
    pub name: String,
    #[serde(rename = "type")]
    pub col_type: String,
    pub description: String,
}

// ── Query filter params ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FindingsFilter {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_per_page")]
    pub per_page: i64,
    pub severity: Option<String>,
    pub triage_state: Option<String>,
    pub confidence_min: Option<f64>,
    pub scan_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ScansFilter {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_per_page")]
    pub per_page: i64,
    pub repository: Option<String>,
    pub branch: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct TrendsFilter {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub interval: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ExportFilter {
    pub severity: Option<String>,
    pub triage_state: Option<String>,
    pub project_id: Option<Uuid>,
}

// ── Error response ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
}
