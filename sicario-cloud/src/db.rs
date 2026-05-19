//! Data store abstraction for the Sicario Cloud Platform.
//!
//! Provides a `DataStore` trait with two implementations:
//! - `ConvexStore`: Production store backed by Convex (https://convex.dev)
//! - `InMemoryStore`: In-memory store for testing without a live Convex instance
//!
//! The Convex deployment URL is configured via `SICARIO_CONVEX_URL` env var
//! or passed directly. The existing `sicario-cli/src/convex/` module handles
//! the WebSocket connection for real-time features; this module uses the
//! Convex HTTP API for CRUD operations from the REST server.

use crate::models::*;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

// ── Application State ─────────────────────────────────────────────────────────

/// Thread-safe application state shared across all Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn DataStore>,
    pub jwt_secret: String,
    pub webhook_client: reqwest::Client,
}

impl AppState {
    /// Create state with the in-memory store (for tests).
    pub fn new(jwt_secret: String) -> Self {
        Self {
            store: Arc::new(InMemoryStore::default()),
            jwt_secret,
            webhook_client: reqwest::Client::new(),
        }
    }

    /// Create state with the Convex-backed store (for production).
    pub fn with_convex(jwt_secret: String, convex_url: String) -> Self {
        Self {
            store: Arc::new(ConvexStore::new(convex_url)),
            jwt_secret,
            webhook_client: reqwest::Client::new(),
        }
    }
}

// ── DataStore trait ───────────────────────────────────────────────────────────

/// Abstraction over the backing data store. All route handlers go through
/// this trait so we can swap between Convex (production) and in-memory (tests).
#[async_trait]
pub trait DataStore: Send + Sync {
    // Scans
    async fn insert_scan(&self, report: &ScanReport) -> Uuid;
    async fn get_scan(&self, id: Uuid) -> Option<Scan>;
    async fn list_scans(&self, filter: &ScansFilter) -> (Vec<Scan>, i64);
    async fn get_critical_findings_for_scan(&self, scan_id: Uuid) -> Vec<StoredFinding>;

    // Findings
    async fn get_finding(&self, id: Uuid) -> Option<StoredFinding>;
    async fn list_findings(&self, filter: &FindingsFilter) -> (Vec<StoredFinding>, i64);
    async fn triage_finding(&self, id: Uuid, req: &TriageFindingRequest) -> Option<StoredFinding>;
    async fn bulk_triage(&self, req: &BulkTriageRequest) -> usize;

    // Analytics
    async fn analytics_overview(&self) -> AnalyticsOverview;
    async fn analytics_trends(&self, filter: &TrendsFilter) -> Vec<TrendDataPoint>;
    async fn analytics_mttr(&self) -> MttrMetrics;

    // Projects
    async fn list_projects(&self) -> Vec<Project>;
    async fn create_project(&self, req: &CreateProjectRequest) -> Project;
    async fn get_project(&self, id: Uuid) -> Option<Project>;
    async fn update_project(&self, id: Uuid, req: &UpdateProjectRequest) -> Option<Project>;

    // Teams
    async fn list_teams(&self) -> Vec<Team>;
    async fn create_team(&self, req: &CreateTeamRequest) -> Team;

    // Webhooks
    async fn list_webhooks(&self) -> Vec<WebhookConfig>;
    async fn create_webhook(&self, req: &CreateWebhookRequest) -> WebhookConfig;
    async fn update_webhook(&self, id: Uuid, req: &UpdateWebhookRequest) -> Option<WebhookConfig>;
    async fn delete_webhook(&self, id: Uuid) -> bool;
    async fn get_enabled_webhooks_for_event(&self, event: &WebhookEventType) -> Vec<WebhookConfig>;
    async fn record_webhook_delivery(&self, delivery: WebhookDelivery);

    // Export
    async fn list_findings_for_export(&self, filter: &ExportFilter) -> Vec<StoredFinding>;
}

// ── Convex Store (production) ─────────────────────────────────────────────────

/// Production data store backed by Convex HTTP API.
///
/// Calls Convex mutations/queries via the HTTP endpoint at
/// `{convex_url}/api/mutation` and `{convex_url}/api/query`.
///
/// The Convex project should define the corresponding functions
/// (e.g. `scans:insert`, `findings:list`, etc.) in its `convex/` directory.
pub struct ConvexStore {
    /// Base URL of the Convex deployment, e.g. `https://flexible-terrier-680.convex.cloud`
    convex_url: String,
    http: reqwest::Client,
    /// Local fallback cache — used when Convex is unreachable so the server
    /// can still operate in a degraded mode. Also used as a write-through
    /// cache for reads.
    cache: RwLock<InMemoryDb>,
}

impl ConvexStore {
    pub fn new(convex_url: String) -> Self {
        Self {
            convex_url,
            http: reqwest::Client::new(),
            cache: RwLock::new(InMemoryDb::default()),
        }
    }

    /// Call a Convex mutation via the HTTP API.
    async fn call_mutation(
        &self,
        name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, reqwest::Error> {
        let url = format!("{}/api/mutation", self.convex_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({
                "path": name,
                "args": args,
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        Ok(resp)
    }

    /// Call a Convex query via the HTTP API.
    async fn call_query(
        &self,
        name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, reqwest::Error> {
        let url = format!("{}/api/query", self.convex_url.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({
                "path": name,
                "args": args,
            }))
            .send()
            .await?
            .json::<serde_json::Value>()
            .await?;
        Ok(resp)
    }
}

#[async_trait]
impl DataStore for ConvexStore {
    async fn insert_scan(&self, report: &ScanReport) -> Uuid {
        let scan_id = Uuid::new_v4();
        let payload = serde_json::json!({
            "scanId": scan_id.to_string(),
            "report": serde_json::to_value(report).unwrap_or_default(),
        });

        // Try Convex first, fall back to local cache
        if let Err(e) = self.call_mutation("scans:insert", payload).await {
            tracing::warn!("Convex mutation scans:insert failed, using local cache: {e}");
        }

        // Always write to local cache for read-back consistency
        let mut cache = self.cache.write().await;
        cache.insert_scan(report)
    }

    async fn get_scan(&self, id: Uuid) -> Option<Scan> {
        // Try Convex, fall back to cache
        if let Ok(resp) = self
            .call_query("scans:get", serde_json::json!({"id": id.to_string()}))
            .await
        {
            if let Some(value) = resp.get("value") {
                if let Ok(scan) = serde_json::from_value::<Scan>(value.clone()) {
                    return Some(scan);
                }
            }
        }
        let cache = self.cache.read().await;
        cache.get_scan(id)
    }

    async fn list_scans(&self, filter: &ScansFilter) -> (Vec<Scan>, i64) {
        let cache = self.cache.read().await;
        cache.list_scans(filter)
    }

    async fn get_critical_findings_for_scan(&self, scan_id: Uuid) -> Vec<StoredFinding> {
        let cache = self.cache.read().await;
        cache
            .get_critical_findings_for_scan(scan_id)
            .into_iter()
            .cloned()
            .collect()
    }

    async fn get_finding(&self, id: Uuid) -> Option<StoredFinding> {
        let cache = self.cache.read().await;
        cache.findings.get(&id).cloned()
    }

    async fn list_findings(&self, filter: &FindingsFilter) -> (Vec<StoredFinding>, i64) {
        let cache = self.cache.read().await;
        cache.list_findings(filter)
    }

    async fn triage_finding(&self, id: Uuid, req: &TriageFindingRequest) -> Option<StoredFinding> {
        // Write to Convex
        let _ = self
            .call_mutation(
                "findings:triage",
                serde_json::json!({
                    "id": id.to_string(),
                    "triageState": req.triage_state.as_ref().map(|t| t.to_string()),
                    "triageNote": req.triage_note,
                    "assignedTo": req.assigned_to,
                }),
            )
            .await;

        // Update local cache
        let mut cache = self.cache.write().await;
        if let Some(f) = cache.findings.get_mut(&id) {
            if let Some(ref ts) = req.triage_state {
                f.triage_state = ts.to_string();
            }
            if let Some(ref note) = req.triage_note {
                f.triage_note = Some(note.clone());
            }
            if let Some(ref assignee) = req.assigned_to {
                f.assigned_to = Some(assignee.clone());
            }
            f.updated_at = Utc::now();
            Some(f.clone())
        } else {
            None
        }
    }

    async fn bulk_triage(&self, req: &BulkTriageRequest) -> usize {
        let ids: Vec<String> = req.finding_ids.iter().map(|id| id.to_string()).collect();
        let _ = self
            .call_mutation(
                "findings:bulkTriage",
                serde_json::json!({
                    "ids": ids,
                    "triageState": req.triage_state.to_string(),
                    "triageNote": req.triage_note,
                }),
            )
            .await;

        let mut cache = self.cache.write().await;
        let now = Utc::now();
        let mut count = 0usize;
        for fid in &req.finding_ids {
            if let Some(f) = cache.findings.get_mut(fid) {
                f.triage_state = req.triage_state.to_string();
                if let Some(ref note) = req.triage_note {
                    f.triage_note = Some(note.clone());
                }
                f.updated_at = now;
                count += 1;
            }
        }
        count
    }

    async fn analytics_overview(&self) -> AnalyticsOverview {
        let cache = self.cache.read().await;
        cache.analytics_overview()
    }

    async fn analytics_trends(&self, _filter: &TrendsFilter) -> Vec<TrendDataPoint> {
        let cache = self.cache.read().await;
        cache.analytics_trends()
    }

    async fn analytics_mttr(&self) -> MttrMetrics {
        let cache = self.cache.read().await;
        cache.analytics_mttr()
    }

    async fn list_projects(&self) -> Vec<Project> {
        let cache = self.cache.read().await;
        let mut projects: Vec<_> = cache.projects.values().cloned().collect();
        projects.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        projects
    }

    async fn create_project(&self, req: &CreateProjectRequest) -> Project {
        let project = Project {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            repository_url: req.repository_url.clone().unwrap_or_default(),
            description: req.description.clone().unwrap_or_default(),
            team_id: req.team_id,
            created_at: Utc::now(),
        };
        let _ = self
            .call_mutation(
                "projects:create",
                serde_json::to_value(&project).unwrap_or_default(),
            )
            .await;
        let mut cache = self.cache.write().await;
        cache.projects.insert(project.id, project.clone());
        project
    }

    async fn get_project(&self, id: Uuid) -> Option<Project> {
        let cache = self.cache.read().await;
        cache.projects.get(&id).cloned()
    }

    async fn update_project(&self, id: Uuid, req: &UpdateProjectRequest) -> Option<Project> {
        let mut cache = self.cache.write().await;
        if let Some(p) = cache.projects.get_mut(&id) {
            if let Some(ref name) = req.name {
                p.name = name.clone();
            }
            if let Some(ref url) = req.repository_url {
                p.repository_url = url.clone();
            }
            if let Some(ref desc) = req.description {
                p.description = desc.clone();
            }
            if let Some(tid) = req.team_id {
                p.team_id = Some(tid);
            }
            let updated = p.clone();
            let _ = self
                .call_mutation(
                    "projects:update",
                    serde_json::to_value(&updated).unwrap_or_default(),
                )
                .await;
            Some(updated)
        } else {
            None
        }
    }

    async fn list_teams(&self) -> Vec<Team> {
        let cache = self.cache.read().await;
        let mut teams: Vec<_> = cache.teams.values().cloned().collect();
        teams.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        teams
    }

    async fn create_team(&self, req: &CreateTeamRequest) -> Team {
        let team = Team {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            org_id: req.org_id,
            created_at: Utc::now(),
        };
        let _ = self
            .call_mutation(
                "teams:create",
                serde_json::to_value(&team).unwrap_or_default(),
            )
            .await;
        let mut cache = self.cache.write().await;
        cache.teams.insert(team.id, team.clone());
        team
    }

    async fn list_webhooks(&self) -> Vec<WebhookConfig> {
        let cache = self.cache.read().await;
        cache.webhooks.values().cloned().collect()
    }

    async fn create_webhook(&self, req: &CreateWebhookRequest) -> WebhookConfig {
        let webhook = WebhookConfig {
            id: Uuid::new_v4(),
            org_id: Uuid::nil(),
            url: req.url.clone(),
            events: req.events.clone(),
            delivery_type: req.delivery_type,
            secret: req.secret.clone(),
            enabled: true,
            created_at: Utc::now(),
        };
        let _ = self
            .call_mutation(
                "webhooks:create",
                serde_json::to_value(&webhook).unwrap_or_default(),
            )
            .await;
        let mut cache = self.cache.write().await;
        cache.webhooks.insert(webhook.id, webhook.clone());
        webhook
    }

    async fn update_webhook(&self, id: Uuid, req: &UpdateWebhookRequest) -> Option<WebhookConfig> {
        let mut cache = self.cache.write().await;
        if let Some(w) = cache.webhooks.get_mut(&id) {
            if let Some(ref url) = req.url {
                w.url = url.clone();
            }
            if let Some(ref events) = req.events {
                w.events = events.clone();
            }
            if let Some(dt) = req.delivery_type {
                w.delivery_type = dt;
            }
            if let Some(ref secret) = req.secret {
                w.secret = Some(secret.clone());
            }
            if let Some(enabled) = req.enabled {
                w.enabled = enabled;
            }
            let updated = w.clone();
            let _ = self
                .call_mutation(
                    "webhooks:update",
                    serde_json::to_value(&updated).unwrap_or_default(),
                )
                .await;
            Some(updated)
        } else {
            None
        }
    }

    async fn delete_webhook(&self, id: Uuid) -> bool {
        let _ = self
            .call_mutation("webhooks:delete", serde_json::json!({"id": id.to_string()}))
            .await;
        let mut cache = self.cache.write().await;
        cache.webhooks.remove(&id).is_some()
    }

    async fn get_enabled_webhooks_for_event(&self, event: &WebhookEventType) -> Vec<WebhookConfig> {
        let cache = self.cache.read().await;
        cache
            .webhooks
            .values()
            .filter(|w| w.enabled && w.events.contains(event))
            .cloned()
            .collect()
    }

    async fn record_webhook_delivery(&self, delivery: WebhookDelivery) {
        let mut cache = self.cache.write().await;
        cache.webhook_deliveries.push(delivery);
    }

    async fn list_findings_for_export(&self, filter: &ExportFilter) -> Vec<StoredFinding> {
        let cache = self.cache.read().await;
        cache
            .findings
            .values()
            .filter(|f| {
                filter.severity.as_ref().is_none_or(|s| &f.severity == s)
                    && filter
                        .triage_state
                        .as_ref()
                        .is_none_or(|t| &f.triage_state == t)
            })
            .cloned()
            .collect()
    }
}

// ── In-Memory Store (tests) ───────────────────────────────────────────────────

/// In-memory data store for testing. No external dependencies required.
#[derive(Default)]
pub struct InMemoryStore {
    db: RwLock<InMemoryDb>,
}

#[async_trait]
impl DataStore for InMemoryStore {
    async fn insert_scan(&self, report: &ScanReport) -> Uuid {
        let mut db = self.db.write().await;
        db.insert_scan(report)
    }

    async fn get_scan(&self, id: Uuid) -> Option<Scan> {
        let db = self.db.read().await;
        db.get_scan(id)
    }

    async fn list_scans(&self, filter: &ScansFilter) -> (Vec<Scan>, i64) {
        let db = self.db.read().await;
        db.list_scans(filter)
    }

    async fn get_critical_findings_for_scan(&self, scan_id: Uuid) -> Vec<StoredFinding> {
        let db = self.db.read().await;
        db.get_critical_findings_for_scan(scan_id)
            .into_iter()
            .cloned()
            .collect()
    }

    async fn get_finding(&self, id: Uuid) -> Option<StoredFinding> {
        let db = self.db.read().await;
        db.findings.get(&id).cloned()
    }

    async fn list_findings(&self, filter: &FindingsFilter) -> (Vec<StoredFinding>, i64) {
        let db = self.db.read().await;
        db.list_findings(filter)
    }

    async fn triage_finding(&self, id: Uuid, req: &TriageFindingRequest) -> Option<StoredFinding> {
        let mut db = self.db.write().await;
        if let Some(f) = db.findings.get_mut(&id) {
            if let Some(ref ts) = req.triage_state {
                f.triage_state = ts.to_string();
            }
            if let Some(ref note) = req.triage_note {
                f.triage_note = Some(note.clone());
            }
            if let Some(ref assignee) = req.assigned_to {
                f.assigned_to = Some(assignee.clone());
            }
            f.updated_at = Utc::now();
            Some(f.clone())
        } else {
            None
        }
    }

    async fn bulk_triage(&self, req: &BulkTriageRequest) -> usize {
        let mut db = self.db.write().await;
        let now = Utc::now();
        let mut count = 0usize;
        for fid in &req.finding_ids {
            if let Some(f) = db.findings.get_mut(fid) {
                f.triage_state = req.triage_state.to_string();
                if let Some(ref note) = req.triage_note {
                    f.triage_note = Some(note.clone());
                }
                f.updated_at = now;
                count += 1;
            }
        }
        count
    }

    async fn analytics_overview(&self) -> AnalyticsOverview {
        let db = self.db.read().await;
        db.analytics_overview()
    }

    async fn analytics_trends(&self, _filter: &TrendsFilter) -> Vec<TrendDataPoint> {
        let db = self.db.read().await;
        db.analytics_trends()
    }

    async fn analytics_mttr(&self) -> MttrMetrics {
        let db = self.db.read().await;
        db.analytics_mttr()
    }

    async fn list_projects(&self) -> Vec<Project> {
        let db = self.db.read().await;
        let mut projects: Vec<_> = db.projects.values().cloned().collect();
        projects.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        projects
    }

    async fn create_project(&self, req: &CreateProjectRequest) -> Project {
        let project = Project {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            repository_url: req.repository_url.clone().unwrap_or_default(),
            description: req.description.clone().unwrap_or_default(),
            team_id: req.team_id,
            created_at: Utc::now(),
        };
        let mut db = self.db.write().await;
        db.projects.insert(project.id, project.clone());
        project
    }

    async fn get_project(&self, id: Uuid) -> Option<Project> {
        let db = self.db.read().await;
        db.projects.get(&id).cloned()
    }

    async fn update_project(&self, id: Uuid, req: &UpdateProjectRequest) -> Option<Project> {
        let mut db = self.db.write().await;
        if let Some(p) = db.projects.get_mut(&id) {
            if let Some(ref name) = req.name {
                p.name = name.clone();
            }
            if let Some(ref url) = req.repository_url {
                p.repository_url = url.clone();
            }
            if let Some(ref desc) = req.description {
                p.description = desc.clone();
            }
            if let Some(tid) = req.team_id {
                p.team_id = Some(tid);
            }
            Some(p.clone())
        } else {
            None
        }
    }

    async fn list_teams(&self) -> Vec<Team> {
        let db = self.db.read().await;
        let mut teams: Vec<_> = db.teams.values().cloned().collect();
        teams.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        teams
    }

    async fn create_team(&self, req: &CreateTeamRequest) -> Team {
        let team = Team {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            org_id: req.org_id,
            created_at: Utc::now(),
        };
        let mut db = self.db.write().await;
        db.teams.insert(team.id, team.clone());
        team
    }

    async fn list_webhooks(&self) -> Vec<WebhookConfig> {
        let db = self.db.read().await;
        db.webhooks.values().cloned().collect()
    }

    async fn create_webhook(&self, req: &CreateWebhookRequest) -> WebhookConfig {
        let webhook = WebhookConfig {
            id: Uuid::new_v4(),
            org_id: Uuid::nil(),
            url: req.url.clone(),
            events: req.events.clone(),
            delivery_type: req.delivery_type,
            secret: req.secret.clone(),
            enabled: true,
            created_at: Utc::now(),
        };
        let mut db = self.db.write().await;
        db.webhooks.insert(webhook.id, webhook.clone());
        webhook
    }

    async fn update_webhook(&self, id: Uuid, req: &UpdateWebhookRequest) -> Option<WebhookConfig> {
        let mut db = self.db.write().await;
        if let Some(w) = db.webhooks.get_mut(&id) {
            if let Some(ref url) = req.url {
                w.url = url.clone();
            }
            if let Some(ref events) = req.events {
                w.events = events.clone();
            }
            if let Some(dt) = req.delivery_type {
                w.delivery_type = dt;
            }
            if let Some(ref secret) = req.secret {
                w.secret = Some(secret.clone());
            }
            if let Some(enabled) = req.enabled {
                w.enabled = enabled;
            }
            Some(w.clone())
        } else {
            None
        }
    }

    async fn delete_webhook(&self, id: Uuid) -> bool {
        let mut db = self.db.write().await;
        db.webhooks.remove(&id).is_some()
    }

    async fn get_enabled_webhooks_for_event(&self, event: &WebhookEventType) -> Vec<WebhookConfig> {
        let db = self.db.read().await;
        db.webhooks
            .values()
            .filter(|w| w.enabled && w.events.contains(event))
            .cloned()
            .collect()
    }

    async fn record_webhook_delivery(&self, delivery: WebhookDelivery) {
        let mut db = self.db.write().await;
        db.webhook_deliveries.push(delivery);
    }

    async fn list_findings_for_export(&self, filter: &ExportFilter) -> Vec<StoredFinding> {
        let db = self.db.read().await;
        db.findings
            .values()
            .filter(|f| {
                filter.severity.as_ref().is_none_or(|s| &f.severity == s)
                    && filter
                        .triage_state
                        .as_ref()
                        .is_none_or(|t| &f.triage_state == t)
            })
            .cloned()
            .collect()
    }
}

// ── InMemoryDb helper ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub webhook_id: Uuid,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub status: String,
    pub response_code: Option<i32>,
    pub delivered_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Default)]
pub struct InMemoryDb {
    #[allow(dead_code)]
    pub organizations: HashMap<Uuid, Organization>,
    pub teams: HashMap<Uuid, Team>,
    pub projects: HashMap<Uuid, Project>,
    pub scans: HashMap<Uuid, ScanRecord>,
    pub findings: HashMap<Uuid, StoredFinding>,
    pub webhooks: HashMap<Uuid, WebhookConfig>,
    pub webhook_deliveries: Vec<WebhookDelivery>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ScanRecord {
    pub id: Uuid,
    pub repository: String,
    pub branch: String,
    pub commit_sha: String,
    pub timestamp: chrono::DateTime<Utc>,
    pub duration_ms: i64,
    pub rules_loaded: i32,
    pub files_scanned: i32,
    pub language_breakdown: HashMap<String, usize>,
    pub tags: Vec<String>,
    pub project_id: Option<Uuid>,
    #[allow(dead_code)]
    pub created_at: chrono::DateTime<Utc>,
}

impl InMemoryDb {
    pub fn insert_scan(&mut self, report: &ScanReport) -> Uuid {
        let scan_id = Uuid::new_v4();
        let now = Utc::now();
        let record = ScanRecord {
            id: scan_id,
            repository: report.metadata.repository.clone(),
            branch: report.metadata.branch.clone(),
            commit_sha: report.metadata.commit_sha.clone(),
            timestamp: report.metadata.timestamp,
            duration_ms: report.metadata.duration_ms as i64,
            rules_loaded: report.metadata.rules_loaded as i32,
            files_scanned: report.metadata.files_scanned as i32,
            language_breakdown: report.metadata.language_breakdown.clone(),
            tags: report.metadata.tags.clone(),
            project_id: None,
            created_at: now,
        };
        self.scans.insert(scan_id, record);
        for f in &report.findings {
            let finding = StoredFinding {
                id: f.id,
                scan_id,
                rule_id: f.rule_id.clone(),
                rule_name: f.rule_name.clone(),
                file_path: f.file_path.clone(),
                line: f.line as i32,
                column: f.column as i32,
                end_line: f.end_line.map(|v| v as i32),
                end_column: f.end_column.map(|v| v as i32),
                snippet: f.snippet.clone(),
                severity: f.severity.to_string(),
                confidence_score: f.confidence_score,
                reachable: f.reachable,
                cloud_exposed: f.cloud_exposed,
                cwe_id: f.cwe_id.clone(),
                owasp_category: f.owasp_category.clone(),
                fingerprint: f.fingerprint.clone(),
                triage_state: "Open".to_string(),
                triage_note: None,
                assigned_to: None,
                created_at: now,
                updated_at: now,
            };
            self.findings.insert(f.id, finding);
        }
        scan_id
    }

    pub fn get_scan(&self, scan_id: Uuid) -> Option<Scan> {
        let record = self.scans.get(&scan_id)?;
        let (findings_count, critical_count, high_count) = self.count_findings_for_scan(scan_id);
        Some(Scan {
            id: record.id,
            repository: record.repository.clone(),
            branch: record.branch.clone(),
            commit_sha: record.commit_sha.clone(),
            timestamp: record.timestamp,
            duration_ms: record.duration_ms,
            rules_loaded: record.rules_loaded,
            files_scanned: record.files_scanned,
            language_breakdown: record.language_breakdown.clone(),
            tags: record.tags.clone(),
            findings_count,
            critical_count,
            high_count,
        })
    }

    fn count_findings_for_scan(&self, scan_id: Uuid) -> (i64, i64, i64) {
        let (mut total, mut critical, mut high) = (0i64, 0i64, 0i64);
        for f in self.findings.values() {
            if f.scan_id == scan_id {
                total += 1;
                if f.severity == "Critical" {
                    critical += 1;
                }
                if f.severity == "High" {
                    high += 1;
                }
            }
        }
        (total, critical, high)
    }

    pub fn list_scans(&self, filter: &ScansFilter) -> (Vec<Scan>, i64) {
        let mut scans: Vec<_> = self
            .scans
            .values()
            .filter(|s| {
                filter
                    .repository
                    .as_ref()
                    .is_none_or(|r| &s.repository == r)
                    && filter.branch.as_ref().is_none_or(|b| &s.branch == b)
            })
            .collect();
        scans.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        let total = scans.len() as i64;
        let offset = ((filter.page - 1) * filter.per_page) as usize;
        let items: Vec<Scan> = scans
            .into_iter()
            .skip(offset)
            .take(filter.per_page as usize)
            .filter_map(|r| self.get_scan(r.id))
            .collect();
        (items, total)
    }

    pub fn list_findings(&self, filter: &FindingsFilter) -> (Vec<StoredFinding>, i64) {
        // Build a scan_id → project_id lookup so we can filter findings by project
        let scan_project: std::collections::HashMap<Uuid, Option<Uuid>> = self
            .scans
            .iter()
            .map(|(id, r)| (*id, r.project_id))
            .collect();

        let mut findings: Vec<_> = self
            .findings
            .values()
            .filter(|f| {
                filter.severity.as_ref().is_none_or(|s| &f.severity == s)
                    && filter
                        .triage_state
                        .as_ref()
                        .is_none_or(|t| &f.triage_state == t)
                    && filter
                        .confidence_min
                        .is_none_or(|c| f.confidence_score >= c)
                    && filter.scan_id.is_none_or(|s| f.scan_id == s)
                    && filter.project_id.is_none_or(|pid| {
                        scan_project.get(&f.scan_id).and_then(|p| *p) == Some(pid)
                    })
            })
            .cloned()
            .collect();
        findings.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let total = findings.len() as i64;
        let offset = ((filter.page - 1) * filter.per_page) as usize;
        let items: Vec<StoredFinding> = findings
            .into_iter()
            .skip(offset)
            .take(filter.per_page as usize)
            .collect();
        (items, total)
    }

    pub fn analytics_overview(&self) -> AnalyticsOverview {
        let (mut total, mut open, mut fixed, mut ignored) = (0i64, 0i64, 0i64, 0i64);
        let (mut critical, mut high, mut medium, mut low, mut info) =
            (0i64, 0i64, 0i64, 0i64, 0i64);
        for f in self.findings.values() {
            total += 1;
            match f.triage_state.as_str() {
                "Open" | "Reviewing" | "ToFix" => open += 1,
                "Fixed" => fixed += 1,
                "Ignored" | "AutoIgnored" => ignored += 1,
                _ => open += 1,
            }
            match f.severity.as_str() {
                "Critical" => critical += 1,
                "High" => high += 1,
                "Medium" => medium += 1,
                "Low" => low += 1,
                "Info" => info += 1,
                _ => {}
            }
        }
        let total_scans = self.scans.len() as i64;
        let avg_duration = if total_scans > 0 {
            self.scans.values().map(|s| s.duration_ms).sum::<i64>() / total_scans
        } else {
            0
        };
        AnalyticsOverview {
            total_findings: total,
            open_findings: open,
            fixed_findings: fixed,
            ignored_findings: ignored,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            info_count: info,
            total_scans,
            avg_scan_duration_ms: avg_duration,
        }
    }

    pub fn analytics_trends(&self) -> Vec<TrendDataPoint> {
        let mut by_day: std::collections::BTreeMap<String, (i64, i64, i64)> =
            std::collections::BTreeMap::new();
        for f in self.findings.values() {
            let day = f.created_at.format("%Y-%m-%d").to_string();
            let entry = by_day.entry(day).or_insert((0, 0, 0));
            match f.triage_state.as_str() {
                "Open" | "Reviewing" | "ToFix" => entry.0 += 1,
                "Fixed" => entry.2 += 1,
                _ => {}
            }
            entry.1 += 1;
        }
        by_day
            .into_iter()
            .filter_map(|(day, (open, new, fixed))| {
                let ts = chrono::NaiveDate::parse_from_str(&day, "%Y-%m-%d")
                    .ok()?
                    .and_hms_opt(0, 0, 0)?;
                Some(TrendDataPoint {
                    timestamp: chrono::DateTime::<Utc>::from_naive_utc_and_offset(ts, Utc),
                    open_findings: open,
                    new_findings: new,
                    fixed_findings: fixed,
                })
            })
            .collect()
    }

    pub fn analytics_mttr(&self) -> MttrMetrics {
        let mut total_hours = 0.0f64;
        let mut count = 0u64;
        let mut by_severity: HashMap<String, (f64, u64)> = HashMap::new();
        for f in self.findings.values() {
            if f.triage_state == "Fixed" {
                let hours = (f.updated_at - f.created_at).num_seconds() as f64 / 3600.0;
                total_hours += hours;
                count += 1;
                let entry = by_severity.entry(f.severity.clone()).or_insert((0.0, 0));
                entry.0 += hours;
                entry.1 += 1;
            }
        }
        let overall = if count > 0 {
            total_hours / count as f64
        } else {
            0.0
        };
        let by_sev = by_severity
            .into_iter()
            .map(|(k, (h, c))| (k, if c > 0 { h / c as f64 } else { 0.0 }))
            .collect();
        MttrMetrics {
            overall_mttr_hours: overall,
            by_severity: by_sev,
        }
    }

    pub fn get_critical_findings_for_scan(&self, scan_id: Uuid) -> Vec<&StoredFinding> {
        self.findings
            .values()
            .filter(|f| f.scan_id == scan_id && f.severity == "Critical")
            .collect()
    }
}
