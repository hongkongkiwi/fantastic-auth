//! Internal Analytics Routes
//!
//! Platform-wide analytics and metrics (superadmin only).

use axum::{
    extract::{Query, State},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Analytics routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/overview", get(get_platform_overview))
        .route("/growth", get(get_growth_metrics))
}

#[derive(Debug, Deserialize)]
struct AnalyticsQuery {
    #[serde(rename = "startDate")]
    _start_date: Option<String>,
    #[serde(rename = "endDate")]
    _end_date: Option<String>,
}

#[derive(Debug, Serialize)]
struct OverviewResponse {
    total_tenants: i64,
    total_users: i64,
    active_users_today: i64,
    mrr: f64,
}

#[derive(Debug, Serialize)]
struct GrowthResponse {
    labels: Vec<String>,
    data: Vec<i64>,
}

/// Get platform overview
async fn get_platform_overview(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<OverviewResponse>, ApiError> {
    Ok(Json(OverviewResponse {
        total_tenants: 0,
        total_users: 0,
        active_users_today: 0,
        mrr: 0.0,
    }))
}

/// Get growth metrics
async fn get_growth_metrics(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Query(_query): Query<AnalyticsQuery>,
) -> Result<Json<GrowthResponse>, ApiError> {
    Ok(Json(GrowthResponse {
        labels: vec![],
        data: vec![],
    }))
}
