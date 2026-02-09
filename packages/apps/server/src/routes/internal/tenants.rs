//! Internal Tenant Management Routes
//!
//! Platform-level tenant management (superadmin only).

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Tenant management routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_tenants).post(create_tenant))
        .route(
            "/:tenant_id",
            get(get_tenant).patch(update_tenant).delete(delete_tenant),
        )
        .route("/:tenant_id/suspend", post(suspend_tenant))
        .route("/:tenant_id/activate", post(activate_tenant))
}

#[derive(Debug, Deserialize)]
struct ListTenantsQuery {
    page: Option<i64>,
    #[serde(rename = "per_page")]
    per_page: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CreateTenantRequest {
    name: String,
    slug: String,
}

#[derive(Debug, Deserialize)]
struct UpdateTenantRequest {
    name: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Serialize)]
struct TenantResponse {
    id: String,
    name: String,
    slug: String,
    status: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Debug, Serialize)]
struct PaginatedTenantsResponse {
    data: Vec<TenantResponse>,
    pagination: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

/// List all tenants
async fn list_tenants(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Query(query): Query<ListTenantsQuery>,
) -> Result<Json<PaginatedTenantsResponse>, ApiError> {
    const MAX_PER_PAGE: i64 = 100;
    let per_page = query.per_page.unwrap_or(20).min(MAX_PER_PAGE);
    let page = query.page.unwrap_or(1);
    Ok(Json(PaginatedTenantsResponse {
        data: vec![],
        pagination: serde_json::json!({"page": page, "per_page": per_page, "total": 0}),
    }))
}

/// Create tenant
async fn create_tenant(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Json(req): Json<CreateTenantRequest>,
) -> Result<Json<TenantResponse>, ApiError> {
    Ok(Json(TenantResponse {
        id: uuid::Uuid::new_v4().to_string(),
        name: req.name,
        slug: req.slug,
        status: "active".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// Get tenant
async fn get_tenant(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
) -> Result<Json<TenantResponse>, ApiError> {
    Ok(Json(TenantResponse {
        id: tenant_id,
        name: "Tenant".to_string(),
        slug: "tenant".to_string(),
        status: "active".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// Update tenant
async fn update_tenant(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
    Json(req): Json<UpdateTenantRequest>,
) -> Result<Json<TenantResponse>, ApiError> {
    Ok(Json(TenantResponse {
        id: tenant_id,
        name: req.name.unwrap_or_else(|| "Tenant".to_string()),
        slug: "tenant".to_string(),
        status: req.status.unwrap_or_else(|| "active".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// Delete tenant
async fn delete_tenant(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    Ok(Json(MessageResponse {
        message: format!("Tenant {} deleted", tenant_id),
    }))
}

/// Suspend tenant
async fn suspend_tenant(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
) -> Result<Json<TenantResponse>, ApiError> {
    Ok(Json(TenantResponse {
        id: tenant_id,
        name: "Tenant".to_string(),
        slug: "tenant".to_string(),
        status: "suspended".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// Activate tenant
async fn activate_tenant(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
) -> Result<Json<TenantResponse>, ApiError> {
    Ok(Json(TenantResponse {
        id: tenant_id,
        name: "Tenant".to_string(),
        slug: "tenant".to_string(),
        status: "active".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
    }))
}
