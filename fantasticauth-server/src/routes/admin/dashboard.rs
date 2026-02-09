//! Admin Dashboard Routes
//!
//! Provides overview metrics and statistics for admin users.

use axum::{extract::State, routing::get, Extension, Json, Router};
use serde::Serialize;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Dashboard routes
pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(get_dashboard))
}

#[derive(Debug, Serialize)]
struct DashboardResponse {
    stats: Stats,
}

#[derive(Debug, Serialize)]
struct Stats {
    total_users: i64,
    active_users: i64,
    pending_users: i64,
    total_organizations: i64,
}

/// Get admin dashboard data
async fn get_dashboard(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<DashboardResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let user_stats = state
        .db
        .users()
        .get_stats(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let org_count = state
        .db
        .organizations()
        .count(&current_user.tenant_id, None)
        .await
        .unwrap_or(0);

    Ok(Json(DashboardResponse {
        stats: Stats {
            total_users: user_stats.total,
            active_users: user_stats.active,
            pending_users: user_stats.pending,
            total_organizations: org_count,
        },
    }))
}
