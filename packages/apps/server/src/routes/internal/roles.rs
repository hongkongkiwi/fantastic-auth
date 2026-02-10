//! Internal roles & permissions routes

use axum::{
    extract::{Path, State},
    routing::{get, patch},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::permissions::checker::PermissionChecker;
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

#[derive(Debug, Serialize, Clone)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub scope: String,
    pub permissions: Vec<String>,
    pub members: i64,
    pub status: String,
}

#[derive(Debug, Deserialize)]
struct CreateRoleRequest {
    name: String,
    description: Option<String>,
    scope: Option<String>,
    permissions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UpdateRoleRequest {
    name: Option<String>,
    description: Option<String>,
    permissions: Option<Vec<String>>,
    status: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct RoleRow {
    id: String,
    name: String,
    description: Option<String>,
    tenant_id: Option<String>,
    permissions: serde_json::Value,
    members: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct RoleExistingRow {
    id: String,
    name: String,
    description: Option<String>,
    tenant_id: Option<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/roles", get(list_roles).post(create_role))
        .route("/roles/:role_id", patch(update_role))
}

async fn require_role_read(
    state: &AppState,
    current_user: &CurrentUser,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let checker = PermissionChecker::new(state.db.pool().clone(), state.redis.clone());
    let allowed = checker
        .has_permission(&current_user.user_id, "role:read")
        .await;
    if !allowed {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn require_role_write(
    state: &AppState,
    current_user: &CurrentUser,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let checker = PermissionChecker::new(state.db.pool().clone(), state.redis.clone());
    let allowed = checker
        .has_permission(&current_user.user_id, "role:write")
        .await;
    if !allowed {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

fn permissions_from_value(value: serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => vec![],
    }
}

async fn list_roles(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<RoleResponse>>, ApiError> {
    require_role_read(&state, &current_user).await?;

    let rows = sqlx::query_as::<_, RoleRow>(
        r#"
        SELECT r.id::text as id,
               r.name,
               r.description,
               r.tenant_id::text as tenant_id,
               COALESCE(p.permissions, '[]'::json) as permissions,
               COALESCE(m.members, 0) as members
        FROM roles r
        LEFT JOIN (
            SELECT rp.role_id, json_agg(p.name ORDER BY p.name) as permissions
            FROM role_permissions rp
            JOIN permissions p ON p.id = rp.permission_id
            GROUP BY rp.role_id
        ) p ON p.role_id = r.id
        LEFT JOIN (
            SELECT role_id, COUNT(*) as members
            FROM user_roles
            GROUP BY role_id
        ) m ON m.role_id = r.id
        WHERE r.tenant_id IS NULL OR r.tenant_id = $1::uuid
        ORDER BY r.created_at DESC
        "#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let roles = rows
        .into_iter()
        .map(|row| RoleResponse {
            id: row.id,
            name: row.name,
            description: row.description.unwrap_or_default(),
            scope: if row.tenant_id.is_some() {
                "tenant".to_string()
            } else {
                "platform".to_string()
            },
            permissions: permissions_from_value(row.permissions),
            members: row.members,
            status: "active".to_string(),
        })
        .collect();

    Ok(Json(roles))
}

async fn create_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(payload): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>, ApiError> {
    require_role_write(&state, &current_user).await?;

    let CreateRoleRequest {
        name,
        description,
        scope,
        permissions,
    } = payload;

    let scope = scope.unwrap_or_else(|| "platform".to_string());
    if scope != "platform" && scope != "tenant" {
        return Err(ApiError::BadRequest("Invalid role scope".to_string()));
    }
    let tenant_id = if scope == "tenant" {
        Some(Uuid::parse_str(&current_user.tenant_id).map_err(|_| ApiError::BadRequest("Invalid tenant id".to_string()))?)
    } else {
        None
    };
    let permissions = permissions.unwrap_or_default();

    let mut tx = state.db.pool().begin().await.map_err(|_| ApiError::internal())?;

    let role_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO roles (id, tenant_id, name, description, is_system_role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, false, NOW(), NOW())
        "#,
    )
    .bind(role_id)
    .bind(tenant_id)
    .bind(&name)
    .bind(&description)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::internal())?;

    if !permissions.is_empty() {
        let permission_rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM permissions WHERE name = ANY($1)",
        )
        .bind(&permissions)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::internal())?;

        if permission_rows.len() != permissions.len() {
            let _ = tx.rollback().await;
            return Err(ApiError::BadRequest("Unknown permission in role".to_string()));
        }

        for (permission_id,) in permission_rows {
            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
            )
            .bind(role_id)
            .bind(permission_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::internal())?;
        }
    }

    tx.commit().await.map_err(|_| ApiError::internal())?;

    Ok(Json(RoleResponse {
        id: role_id.to_string(),
        name,
        description: description.unwrap_or_default(),
        scope,
        permissions,
        members: 0,
        status: "active".to_string(),
    }))
}

async fn update_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(role_id): Path<String>,
    Json(payload): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, ApiError> {
    require_role_write(&state, &current_user).await?;

    let UpdateRoleRequest {
        name,
        description,
        permissions: requested_permissions,
        status,
    } = payload;

    let role_uuid = Uuid::parse_str(&role_id).map_err(|_| ApiError::BadRequest("Invalid role id".to_string()))?;
    let mut tx = state.db.pool().begin().await.map_err(|_| ApiError::internal())?;

    let existing: Option<RoleExistingRow> = sqlx::query_as(
        r#"SELECT id::text as id, name, description, tenant_id::text as tenant_id FROM roles WHERE id = $1"#,
    )
    .bind(role_uuid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError::internal())?;

    let RoleExistingRow {
        id,
        name: current_name,
        description: current_description,
        tenant_id,
    } = match existing {
        Some(row) => row,
        None => {
            let _ = tx.rollback().await;
            return Err(ApiError::NotFound);
        }
    };

    let new_name = name.unwrap_or(current_name);
    let new_description = if description.is_some() {
        description
    } else {
        current_description
    };

    sqlx::query(
        r#"UPDATE roles SET name = $1, description = $2, updated_at = NOW() WHERE id = $3"#,
    )
    .bind(&new_name)
    .bind(&new_description)
    .bind(role_uuid)
    .execute(&mut *tx)
    .await
    .map_err(|_| ApiError::internal())?;

    let mut permissions = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT COALESCE(json_agg(p.name ORDER BY p.name), '[]'::json) FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = $1",
    )
    .bind(role_uuid)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or_else(|_| serde_json::Value::Array(vec![]));

    if let Some(new_permissions) = requested_permissions {
        let permission_rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM permissions WHERE name = ANY($1)",
        )
        .bind(&new_permissions)
        .fetch_all(&mut *tx)
        .await
        .map_err(|_| ApiError::internal())?;

        if permission_rows.len() != new_permissions.len() {
            let _ = tx.rollback().await;
            return Err(ApiError::BadRequest("Unknown permission in role".to_string()));
        }

        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
            .bind(role_uuid)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::internal())?;

        for (permission_id,) in permission_rows {
            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2)",
            )
            .bind(role_uuid)
            .bind(permission_id)
            .execute(&mut *tx)
            .await
            .map_err(|_| ApiError::internal())?;
        }

        permissions = serde_json::Value::Array(
            new_permissions
                .iter()
                .map(|p| serde_json::Value::String(p.clone()))
                .collect(),
        );
    }

    let members: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_roles WHERE role_id = $1",
    )
    .bind(role_uuid)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or(0);

    tx.commit().await.map_err(|_| ApiError::internal())?;

    Ok(Json(RoleResponse {
        id,
        name: new_name,
        description: new_description.unwrap_or_default(),
        scope: if tenant_id.is_some() { "tenant".to_string() } else { "platform".to_string() },
        permissions: permissions_from_value(permissions),
        members,
        status: status.unwrap_or_else(|| "active".to_string()),
    }))
}
