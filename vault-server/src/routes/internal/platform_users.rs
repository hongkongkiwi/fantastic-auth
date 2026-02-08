//! Internal Platform User Routes
//!
//! Platform-level user search and management (superadmin only).

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Platform user routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(search_platform_users))
        .route("/:user_id", get(get_platform_user))
}

#[derive(Debug, Deserialize)]
struct SearchUsersQuery {
    search: Option<String>,
    page: Option<i64>,
    #[serde(rename = "per_page")]
    per_page: Option<i64>,
}

#[derive(Debug, Serialize)]
struct PlatformUserResponse {
    id: String,
    email: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
    status: String,
}

#[derive(Debug, Serialize)]
struct PaginatedUsersResponse {
    data: Vec<PlatformUserResponse>,
    pagination: serde_json::Value,
}

/// Search users across platform
async fn search_platform_users(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Query(_query): Query<SearchUsersQuery>,
) -> Result<Json<PaginatedUsersResponse>, ApiError> {
    Ok(Json(PaginatedUsersResponse {
        data: vec![],
        pagination: serde_json::json!({"page": 1, "per_page": 20, "total": 0}),
    }))
}

/// Get platform user details
async fn get_platform_user(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<PlatformUserResponse>, ApiError> {
    Ok(Json(PlatformUserResponse {
        id: user_id,
        email: "user@example.com".to_string(),
        tenant_id: "tenant-1".to_string(),
        status: "active".to_string(),
    }))
}
