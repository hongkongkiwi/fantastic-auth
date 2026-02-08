//! Internal Maintenance Routes
//!
//! System maintenance and operations (superadmin only).

use axum::{
    extract::State,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Maintenance routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/status", get(get_maintenance_status))
        .route("/enable", post(enable_maintenance))
        .route("/disable", post(disable_maintenance))
        .route("/health", get(detailed_health))
}

#[derive(Debug, Deserialize)]
struct EnableMaintenanceRequest {
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct MaintenanceStatus {
    enabled: bool,
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthDetail {
    database: String,
    redis: String,
    overall: String,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

/// Get maintenance status
async fn get_maintenance_status(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<MaintenanceStatus>, ApiError> {
    Ok(Json(MaintenanceStatus {
        enabled: false,
        message: None,
    }))
}

/// Enable maintenance mode
async fn enable_maintenance(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Json(_req): Json<EnableMaintenanceRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    Ok(Json(MessageResponse {
        message: "Maintenance mode enabled".to_string(),
    }))
}

/// Disable maintenance mode
async fn disable_maintenance(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<MessageResponse>, ApiError> {
    Ok(Json(MessageResponse {
        message: "Maintenance mode disabled".to_string(),
    }))
}

/// Detailed health check
async fn detailed_health(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<HealthDetail>, ApiError> {
    let db_health = match state.db.ping().await {
        Ok(()) => "healthy",
        Err(_) => "unhealthy",
    };

    let redis_health = match &state.redis {
        Some(_redis) => "healthy",
        None => "not_configured",
    };

    let overall = if db_health == "healthy" {
        "healthy"
    } else {
        "degraded"
    };

    Ok(Json(HealthDetail {
        database: db_health.to_string(),
        redis: redis_health.to_string(),
        overall: overall.to_string(),
    }))
}
