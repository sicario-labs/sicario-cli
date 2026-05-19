//! Axum route handlers for the Sicario Cloud Platform REST API v1.
//!
//! All handlers go through the `DataStore` trait so the backing store
//! (Convex in production, in-memory for tests) is transparent.
//!
//! Requirements: 21.26, 21.27, 21.28

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json::json;
use uuid::Uuid;

use crate::db::AppState;
use crate::export;
use crate::models::*;
use crate::webhooks;

// ── Scans ─────────────────────────────────────────────────────────────────────

pub async fn create_scan(
    State(state): State<AppState>,
    Json(report): Json<ScanReport>,
) -> impl IntoResponse {
    let scan_id = state.store.insert_scan(&report).await;

    // Fire webhooks for critical findings asynchronously
    let critical = state.store.get_critical_findings_for_scan(scan_id).await;
    if !critical.is_empty() {
        let findings_json: Vec<_> = critical
            .iter()
            .map(|f| {
                json!({
                    "id": f.id, "rule_id": f.rule_id,
                    "file_path": f.file_path, "severity": f.severity,
                })
            })
            .collect();
        let payload = json!({ "scan_id": scan_id, "critical_findings": findings_json });
        webhooks::dispatch_webhooks(&state, WebhookEventType::CriticalFinding, payload).await;
    }

    (
        StatusCode::CREATED,
        Json(PublishResponse {
            scan_id: scan_id.to_string(),
            dashboard_url: Some(format!("https://app.sicario.dev/scans/{scan_id}")),
        }),
    )
}

pub async fn list_scans(
    State(state): State<AppState>,
    Query(filter): Query<ScansFilter>,
) -> impl IntoResponse {
    let (items, total) = state.store.list_scans(&filter).await;
    Json(PaginatedResponse {
        page: filter.page,
        per_page: filter.per_page,
        total,
        items,
    })
}

pub async fn get_scan(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.store.get_scan(id).await {
        Some(scan) => match serde_json::to_value(&scan) {
            Ok(json) => (StatusCode::OK, Json(json)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "serialization_error".into(),
                    message: format!("Failed to serialize scan: {e}"),
                }),
            )
                .into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "not_found".into(),
                message: format!("Scan {id} not found"),
            }),
        )
            .into_response(),
    }
}

// ── Findings ──────────────────────────────────────────────────────────────────

pub async fn list_findings(
    State(state): State<AppState>,
    Query(filter): Query<FindingsFilter>,
) -> impl IntoResponse {
    let (items, total) = state.store.list_findings(&filter).await;
    Json(PaginatedResponse {
        page: filter.page,
        per_page: filter.per_page,
        total,
        items,
    })
}

pub async fn get_finding(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.store.get_finding(id).await {
        Some(f) => match serde_json::to_value(&f) {
            Ok(json) => (StatusCode::OK, Json(json)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "serialization_error".into(),
                    message: format!("Failed to serialize finding: {e}"),
                }),
            )
                .into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "not_found".into(),
                message: format!("Finding {id} not found"),
            }),
        )
            .into_response(),
    }
}

pub async fn triage_finding(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<TriageFindingRequest>,
) -> impl IntoResponse {
    match state.store.triage_finding(id, &req).await {
        Some(f) => match serde_json::to_value(&f) {
            Ok(json) => (StatusCode::OK, Json(json)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "serialization_error".into(),
                    message: format!("Failed to serialize finding: {e}"),
                }),
            )
                .into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "not_found".into(),
                message: format!("Finding {id} not found"),
            }),
        )
            .into_response(),
    }
}

pub async fn bulk_triage(
    State(state): State<AppState>,
    Json(req): Json<BulkTriageRequest>,
) -> impl IntoResponse {
    let count = state.store.bulk_triage(&req).await;
    Json(BulkTriageResponse {
        updated_count: count,
    })
}

// ── Analytics ─────────────────────────────────────────────────────────────────

pub async fn analytics_overview(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.analytics_overview().await)
}

pub async fn analytics_trends(
    State(state): State<AppState>,
    Query(filter): Query<TrendsFilter>,
) -> impl IntoResponse {
    Json(state.store.analytics_trends(&filter).await)
}

pub async fn analytics_mttr(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.analytics_mttr().await)
}

// ── Projects ──────────────────────────────────────────────────────────────────

pub async fn list_projects(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.list_projects().await)
}

pub async fn create_project(
    State(state): State<AppState>,
    Json(req): Json<CreateProjectRequest>,
) -> impl IntoResponse {
    let project = state.store.create_project(&req).await;
    (StatusCode::CREATED, Json(project))
}

pub async fn get_project(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.store.get_project(id).await {
        Some(p) => match serde_json::to_value(&p) {
            Ok(json) => (StatusCode::OK, Json(json)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "serialization_error".into(),
                    message: format!("Failed to serialize project: {e}"),
                }),
            )
                .into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "not_found".into(),
                message: format!("Project {id} not found"),
            }),
        )
            .into_response(),
    }
}

pub async fn update_project(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateProjectRequest>,
) -> impl IntoResponse {
    match state.store.update_project(id, &req).await {
        Some(p) => match serde_json::to_value(&p) {
            Ok(json) => (StatusCode::OK, Json(json)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "serialization_error".into(),
                    message: format!("Failed to serialize project: {e}"),
                }),
            )
                .into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "not_found".into(),
                message: format!("Project {id} not found"),
            }),
        )
            .into_response(),
    }
}

// ── Teams ─────────────────────────────────────────────────────────────────────

pub async fn list_teams(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.list_teams().await)
}

pub async fn create_team(
    State(state): State<AppState>,
    Json(req): Json<CreateTeamRequest>,
) -> impl IntoResponse {
    let team = state.store.create_team(&req).await;
    (StatusCode::CREATED, Json(team))
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

pub async fn list_webhooks(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.store.list_webhooks().await)
}

pub async fn create_webhook(
    State(state): State<AppState>,
    Json(req): Json<CreateWebhookRequest>,
) -> impl IntoResponse {
    let webhook = state.store.create_webhook(&req).await;
    (StatusCode::CREATED, Json(webhook))
}

pub async fn update_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateWebhookRequest>,
) -> impl IntoResponse {
    match state.store.update_webhook(id, &req).await {
        Some(w) => match serde_json::to_value(&w) {
            Ok(json) => (StatusCode::OK, Json(json)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    error: "serialization_error".into(),
                    message: format!("Failed to serialize webhook: {e}"),
                }),
            )
                .into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "not_found".into(),
                message: format!("Webhook {id} not found"),
            }),
        )
            .into_response(),
    }
}

pub async fn delete_webhook(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if state.store.delete_webhook(id).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ApiError {
                error: "not_found".into(),
                message: format!("Webhook {id} not found"),
            }),
        )
            .into_response()
    }
}

// ── Export ─────────────────────────────────────────────────────────────────────

pub async fn export_findings_csv(
    State(state): State<AppState>,
    Query(filter): Query<ExportFilter>,
) -> impl IntoResponse {
    let findings = state.store.list_findings_for_export(&filter).await;
    match export::findings_to_csv(&findings) {
        Ok(csv) => (
            StatusCode::OK,
            [
                ("content-type", "text/csv"),
                (
                    "content-disposition",
                    "attachment; filename=\"findings.csv\"",
                ),
            ],
            csv,
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiError {
                error: "export_error".into(),
                message: "Failed to generate CSV export".into(),
            }),
        )
            .into_response(),
    }
}

pub async fn export_schema() -> impl IntoResponse {
    Json(export::export_schema())
}
