//! Admin System Routes
//!
//! System health and status endpoints.

use axum::{extract::State, routing::get, Extension, Json, Router};
use serde::Serialize;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// System routes
pub fn routes() -> Router<AppState> {
    Router::new().route("/system/health", get(system_health))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    database: String,
}

/// Get system health status
async fn system_health(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<HealthResponse>, ApiError> {
    let db_health = match state.db.ping().await {
        Ok(()) => "healthy",
        Err(_) => "unhealthy",
    };

    Ok(Json(HealthResponse {
        status: "healthy".to_string(),
        version: vault_core::VERSION.to_string(),
        database: db_health.to_string(),
    }))
}
