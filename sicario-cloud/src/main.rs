//! Sicario Cloud Platform — REST API server.
//!
//! A standalone Axum server exposing the v1 REST API for centralized
//! findings management, triage workflows, analytics, and webhook dispatch.
//!
//! Data is stored in Convex (https://convex.dev). The in-memory store is
//! used for tests and as a local cache when Convex is unavailable.
//!
//! Requirements: 21.26, 21.27, 21.28

mod auth;
mod db;
mod export;
mod models;
mod routes;
mod webhooks;

use axum::{
    middleware,
    routing::{get, patch, post},
    Router,
};
use db::AppState;
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Build the Axum router with all v1 API routes.
pub fn build_router(state: AppState) -> Router {
    let api_v1 = Router::new()
        // Scans
        .route("/scans", post(routes::create_scan))
        .route("/scans", get(routes::list_scans))
        .route("/scans/:id", get(routes::get_scan))
        // Findings
        .route("/findings", get(routes::list_findings))
        .route("/findings/bulk-triage", post(routes::bulk_triage))
        .route(
            "/findings/:id",
            get(routes::get_finding).patch(routes::triage_finding),
        )
        // Analytics
        .route("/analytics/overview", get(routes::analytics_overview))
        .route("/analytics/trends", get(routes::analytics_trends))
        .route("/analytics/mttr", get(routes::analytics_mttr))
        // Projects
        .route("/projects", get(routes::list_projects))
        .route("/projects", post(routes::create_project))
        .route(
            "/projects/:id",
            get(routes::get_project).patch(routes::update_project),
        )
        // Teams
        .route("/teams", get(routes::list_teams))
        .route("/teams", post(routes::create_team))
        // Webhooks
        .route("/webhooks", get(routes::list_webhooks))
        .route("/webhooks", post(routes::create_webhook))
        .route(
            "/webhooks/:id",
            patch(routes::update_webhook).delete(routes::delete_webhook),
        )
        // Export
        .route("/export/findings.csv", get(routes::export_findings_csv))
        .route("/export/schema", get(routes::export_schema))
        // JWT auth on all routes
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::jwt_auth_middleware,
        ))
        .with_state(state);

    Router::new()
        .nest("/api/v1", api_v1)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sicario_cloud=info,tower_http=info".into()),
        )
        .init();

    // JWT secret MUST be configured via environment variable for production security.
    // No default is provided — the server will not start without it.
    let jwt_secret = std::env::var("SICARIO_JWT_SECRET")
        .expect("SICARIO_JWT_SECRET must be set. Generate a strong random secret and set it as an environment variable.");

    // Convex deployment URL — defaults to the Sicario project deployment.
    // Must match the frontend's Convex backend (flexible-terrier-680) so
    // projects created on the web dashboard are visible to the API (DASH-001).
    let convex_url = std::env::var("SICARIO_CONVEX_URL")
        .unwrap_or_else(|_| "https://flexible-terrier-680.convex.cloud".to_string());

    let state = AppState::with_convex(jwt_secret, convex_url.clone());

    let host = std::env::var("SICARIO_CLOUD_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = std::env::var("SICARIO_CLOUD_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3000);

    let addr: SocketAddr = format!("{host}:{port}").parse().unwrap_or_else(|_| {
        panic!("Invalid SICARIO_CLOUD_HOST '{host}' or SICARIO_CLOUD_PORT '{port}'")
    });
    tracing::info!("Sicario Cloud Platform listening on {addr}");
    tracing::info!("Convex backend: {convex_url}");

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("Failed to bind to {addr}: {e}"));
    axum::serve(listener, build_router(state))
        .await
        .unwrap_or_else(|e| panic!("Server error: {e}"));
}

#[cfg(test)]
mod tests;
