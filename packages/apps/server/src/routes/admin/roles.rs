//! Admin Organization Roles Routes

use axum::{
    extract::{Path, State},
    routing::{get, patch},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::db::set_connection_context;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/organizations/:org_id/roles",
            get(list_org_roles).post(create_org_role),
        )
        .route(
            "/organizations/:org_id/roles/:role_id",
            patch(update_org_role).delete(delete_org_role),
        )
}

#[derive(Debug, Deserialize)]
struct CreateOrganizationRoleRequest {
    name: String,
    permissions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UpdateOrganizationRoleRequest {
    name: Option<String>,
    permissions: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct OrganizationRoleResponse {
    id: String,
    name: String,
    permissions: Vec<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

#[derive(Debug, FromRow)]
struct OrganizationRoleRow {
    id: String,
    name: String,
    permissions: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

fn permissions_from_value(value: serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

async fn list_org_roles(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let rows = sqlx::query_as::<_, OrganizationRoleRow>(
        r#"SELECT id::text as id, name, permissions, created_at, updated_at
           FROM organization_roles
           WHERE tenant_id = $1::uuid AND organization_id = $2::uuid
           ORDER BY created_at DESC"#
    )
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    let responses: Vec<OrganizationRoleResponse> = rows
        .into_iter()
        .map(|row| OrganizationRoleResponse {
            id: row.id,
            name: row.name,
            permissions: permissions_from_value(row.permissions),
            created_at: row.created_at.to_rfc3339(),
            updated_at: row.updated_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(serde_json::json!({ "data": responses })))
}

async fn create_org_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
    Json(req): Json<CreateOrganizationRoleRequest>,
) -> Result<Json<OrganizationRoleResponse>, ApiError> {
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let permissions = serde_json::Value::Array(
        req.permissions
            .unwrap_or_default()
            .into_iter()
            .map(serde_json::Value::String)
            .collect(),
    );

    let row = sqlx::query_as::<_, OrganizationRoleRow>(
        r#"INSERT INTO organization_roles (id, tenant_id, organization_id, name, permissions, created_at, updated_at)
           VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7)
           RETURNING id::text as id, name, permissions, created_at, updated_at"#
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .bind(&req.name)
    .bind(permissions)
    .bind(chrono::Utc::now())
    .bind(chrono::Utc::now())
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(OrganizationRoleResponse {
        id: row.id,
        name: row.name,
        permissions: permissions_from_value(row.permissions),
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }))
}

async fn update_org_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((_org_id, role_id)): Path<(String, String)>,
    Json(req): Json<UpdateOrganizationRoleRequest>,
) -> Result<Json<OrganizationRoleResponse>, ApiError> {
    let org_id = _org_id;
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let existing = sqlx::query_as::<_, OrganizationRoleRow>(
        r#"SELECT id::text as id, name, permissions, created_at, updated_at
           FROM organization_roles
           WHERE tenant_id = $1::uuid AND organization_id = $2::uuid AND id = $3::uuid"#
    )
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .bind(&role_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?
    .ok_or(ApiError::NotFound)?;

    let name = req.name.unwrap_or(existing.name);
    let permissions = req.permissions
        .map(|perms| {
            serde_json::Value::Array(
                perms
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            )
        })
        .unwrap_or(existing.permissions);

    let row = sqlx::query_as::<_, OrganizationRoleRow>(
        r#"UPDATE organization_roles
           SET name = $1, permissions = $2, updated_at = $3
           WHERE tenant_id = $4::uuid AND organization_id = $5::uuid AND id = $6::uuid
           RETURNING id::text as id, name, permissions, created_at, updated_at"#
    )
    .bind(name)
    .bind(permissions)
    .bind(chrono::Utc::now())
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .bind(&role_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(OrganizationRoleResponse {
        id: row.id,
        name: row.name,
        permissions: permissions_from_value(row.permissions),
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    }))
}

async fn delete_org_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((_org_id, _role_id)): Path<(String, String)>,
) -> Result<(), ApiError> {
    let org_id = _org_id;
    let role_id = _role_id;
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let result = sqlx::query(
        r#"DELETE FROM organization_roles
           WHERE tenant_id = $1::uuid AND organization_id = $2::uuid AND id = $3::uuid"#
    )
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .bind(&role_id)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    Ok(())
}
