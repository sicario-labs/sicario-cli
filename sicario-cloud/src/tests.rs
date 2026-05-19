//! Integration tests for the Sicario Cloud Platform REST API.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::{json, Value};
use tower::util::ServiceExt;
use uuid::Uuid;

use crate::auth::Claims;
use crate::build_router;
use crate::db::AppState;

const TEST_SECRET: &str = "test-secret";

fn test_state() -> AppState {
    AppState::new(TEST_SECRET.to_string())
}

fn make_jwt() -> String {
    let claims = Claims {
        sub: "test-user".to_string(),
        org_id: Uuid::nil().to_string(),
        exp: (Utc::now().timestamp() + 3600) as usize,
        iat: Utc::now().timestamp() as usize,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
    )
    .unwrap()
}

fn scan_report_json() -> Value {
    json!({
        "findings": [{
            "id": Uuid::new_v4(),
            "rule_id": "sql-injection-001",
            "rule_name": "SQL Injection via string concat",
            "file_path": "src/db.rs",
            "line": 42,
            "column": 10,
            "end_line": 42,
            "end_column": 50,
            "snippet": "query(format!(\"SELECT * FROM users WHERE id = {}\", input))",
            "severity": "Critical",
            "confidence_score": 0.95,
            "reachable": true,
            "cloud_exposed": true,
            "cwe_id": "CWE-89",
            "owasp_category": "A03_Injection",
            "fingerprint": "abc123",
            "suppressed": false,
            "suppression_rule": null,
            "suggested_suppression": false
        }],
        "metadata": {
            "repository": "https://github.com/test/repo",
            "branch": "main",
            "commit_sha": "abc123def456",
            "timestamp": Utc::now().to_rfc3339(),
            "duration_ms": 1500,
            "rules_loaded": 100,
            "files_scanned": 50,
            "language_breakdown": {"rust": 30, "javascript": 20},
            "tags": ["ci", "nightly"]
        }
    })
}

async fn body_json(body: Body) -> Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn test_unauthorized_without_token() {
    let app = build_router(test_state());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/scans")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_and_list_scans() {
    let state = test_state();
    let token = make_jwt();

    // Create scan
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/scans")
                .method("POST")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&scan_report_json()).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp.into_body()).await;
    assert!(body["scan_id"].is_string());
    assert!(body["dashboard_url"].is_string());

    // List scans
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/scans")
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_findings_crud_and_triage() {
    let state = test_state();
    let token = make_jwt();

    // Create scan with a finding
    let app = build_router(state.clone());
    app.oneshot(
        Request::builder()
            .uri("/api/v1/scans")
            .method("POST")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&scan_report_json()).unwrap(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    // List findings
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/findings")
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["total"], 1);
    let finding_id = body["items"][0]["id"].as_str().unwrap().to_string();

    // Triage finding
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&format!("/api/v1/findings/{finding_id}"))
                .method("PATCH")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({"triage_state": "Fixed", "triage_note": "Patched"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["triage_state"], "Fixed");
}

#[tokio::test]
async fn test_bulk_triage() {
    let state = test_state();
    let token = make_jwt();

    // Create scan
    let app = build_router(state.clone());
    app.oneshot(
        Request::builder()
            .uri("/api/v1/scans")
            .method("POST")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&scan_report_json()).unwrap(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    // Get finding ID
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/findings")
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = body_json(resp.into_body()).await;
    let finding_id = body["items"][0]["id"].as_str().unwrap().to_string();

    // Bulk triage
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/findings/bulk-triage")
                .method("POST")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "finding_ids": [finding_id],
                        "triage_state": "Ignored",
                        "triage_note": "False positive"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["updated_count"], 1);
}

#[tokio::test]
async fn test_analytics_overview() {
    let state = test_state();
    let token = make_jwt();

    // Create scan
    let app = build_router(state.clone());
    app.oneshot(
        Request::builder()
            .uri("/api/v1/scans")
            .method("POST")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&scan_report_json()).unwrap(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/analytics/overview")
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["total_findings"], 1);
    assert_eq!(body["critical_count"], 1);
    assert_eq!(body["total_scans"], 1);
}

#[tokio::test]
async fn test_projects_crud() {
    let state = test_state();
    let token = make_jwt();

    // Create project
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/projects")
                .method("POST")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(json!({"name": "Test Project", "repository_url": "https://github.com/test/repo"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp.into_body()).await;
    let project_id = body["id"].as_str().unwrap().to_string();

    // Get project
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&format!("/api/v1/projects/{project_id}"))
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // List projects
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/projects")
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn test_webhooks_crud() {
    let state = test_state();
    let token = make_jwt();

    // Create webhook
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/webhooks")
                .method("POST")
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json")
                .body(Body::from(
                    json!({
                        "url": "https://hooks.slack.com/test",
                        "events": ["critical_finding"],
                        "delivery_type": "slack"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp.into_body()).await;
    let webhook_id = body["id"].as_str().unwrap().to_string();

    // List webhooks
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/webhooks")
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Delete webhook
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri(&format!("/api/v1/webhooks/{webhook_id}"))
                .method("DELETE")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_csv_export() {
    let state = test_state();
    let token = make_jwt();

    // Create scan with findings
    let app = build_router(state.clone());
    app.oneshot(
        Request::builder()
            .uri("/api/v1/scans")
            .method("POST")
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::to_string(&scan_report_json()).unwrap(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    // Export CSV
    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/export/findings.csv")
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let csv_content = String::from_utf8_lossy(&bytes);
    assert!(csv_content.contains("id,scan_id,rule_id"));
    assert!(csv_content.contains("sql-injection-001"));
}

#[tokio::test]
async fn test_export_schema() {
    let state = test_state();
    let token = make_jwt();

    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/export/schema")
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["version"], "1.0.0");
    assert!(body["tables"].as_array().unwrap().len() >= 5);
}

#[tokio::test]
async fn test_analytics_trends_and_mttr() {
    let state = test_state();
    let token = make_jwt();

    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/analytics/trends")
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let app = build_router(state.clone());
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/analytics/mttr")
                .method("GET")
                .header("Authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    assert!(body["overall_mttr_hours"].is_number());
}
