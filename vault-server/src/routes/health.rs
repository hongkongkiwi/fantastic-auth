//! Health check and monitoring routes
//!
//! Public endpoints for health checks and metrics.

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;
use std::sync::Arc;

use crate::monitoring::{HealthStatus, SystemHealth};
use crate::state::AppState;

/// Create health check routes
/// These are mounted at the root level (not under /api/v1)
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/health/live", get(liveness_check))
        .route("/health/ready", get(readiness_check))
        .route("/metrics", get(metrics_handler))
}

/// Basic health check - returns overall system status
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let health = state.health_registry.check_health().await;

    let status_code = match health.status {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded => StatusCode::OK, // Still serving but issues
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (status_code, Json(health))
}

/// Liveness probe - is the application running?
/// Kubernetes uses this to know if the pod should be restarted
async fn liveness_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "alive",
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
    )
}

/// Readiness probe - is the application ready to serve traffic?
/// Kubernetes uses this to know when to add/remove from load balancer
async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    // Run health checks
    state
        .health_registry
        .run_checks(&state.db, &state.redis)
        .await;

    let health = state.health_registry.check_health().await;

    // Check if critical components are healthy
    let is_ready = matches!(
        health.status,
        HealthStatus::Healthy | HealthStatus::Degraded
    );

    let status_code = if is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let response = serde_json::json!({
        "status": if is_ready { "ready" } else { "not_ready" },
        "components": health.components,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    (status_code, Json(response))
}

/// Prometheus metrics endpoint
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let metrics = state.metrics_registry.export_prometheus().await;

    // Add system metrics
    let sys_metrics = format!(
        "{}
# HELP vault_build_info Build information
# TYPE vault_build_info gauge
vault_build_info{{version=\"{}\"}} 1
# HELP vault_uptime_seconds Server uptime in seconds
# TYPE vault_uptime_seconds gauge
vault_uptime_seconds {}
",
        metrics,
        vault_core::VERSION,
        state.health_registry.check_health().await.uptime_seconds
    );

    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4")],
        sys_metrics,
    )
}

/// Simple health response for backwards compatibility
#[derive(Debug, Serialize)]
pub struct SimpleHealthResponse {
    pub status: String,
    pub version: String,
    #[serde(rename = "serverTime")]
    pub server_time: String,
}

/// Legacy health check (used by old clients)
pub async fn simple_health_check() -> Json<SimpleHealthResponse> {
    Json(SimpleHealthResponse {
        status: "healthy".to_string(),
        version: vault_core::VERSION.to_string(),
        server_time: chrono::Utc::now().to_rfc3339(),
    })
}
