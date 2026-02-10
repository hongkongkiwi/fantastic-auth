//! Internal Tenant Admin Management Routes (Platform)

use axum::{
    extract::{Path, State},
    routing::{delete, get},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/tenants/:tenant_id/admins", get(list_admins).post(create_admin))
        .route(
            "/tenants/:tenant_id/admins/:user_id",
            delete(remove_admin),
        )
}

#[derive(Debug, Deserialize)]
struct CreateAdminRequest {
    #[serde(rename = "userId")]
    user_id: String,
    role: String,
}

#[derive(Debug, Serialize)]
struct TenantAdminResponse {
    id: String,
    #[serde(rename = "userId")]
    user_id: String,
    role: String,
    status: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

async fn list_admins(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
) -> Result<Json<Vec<TenantAdminResponse>>, ApiError> {
    state
        .set_tenant_context(&tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let admins = state
        .auth_service
        .db()
        .tenant_admins()
        .list_admins(&tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(
        admins
            .into_iter()
            .map(|a| TenantAdminResponse {
                id: a.id,
                user_id: a.user_id,
                role: a.role,
                status: a.status,
                created_at: a.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}

async fn create_admin(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
    Json(req): Json<CreateAdminRequest>,
) -> Result<Json<TenantAdminResponse>, ApiError> {
    state
        .set_tenant_context(&tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let admin = state
        .auth_service
        .db()
        .tenant_admins()
        .upsert_admin(&tenant_id, &req.user_id, &req.role, "active")
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(TenantAdminResponse {
        id: admin.id,
        user_id: admin.user_id,
        role: admin.role,
        status: admin.status,
        created_at: admin.created_at.to_rfc3339(),
    }))
}

async fn remove_admin(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path((tenant_id, user_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .auth_service
        .db()
        .tenant_admins()
        .remove_admin(&tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(serde_json::json!({"message": "Admin removed"})))
}
