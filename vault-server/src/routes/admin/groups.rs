//! Admin Group Management Routes

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::db::set_connection_context;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/organizations/:org_id/groups", get(list_groups).post(create_group))
        .route("/groups/:group_id", patch(update_group).delete(delete_group))
        .route(
            "/groups/:group_id/members",
            get(list_group_members).post(add_group_member),
        )
        .route(
            "/groups/:group_id/members/:user_id",
            delete(remove_group_member),
        )
}

#[derive(Debug, Deserialize)]
struct ListGroupsQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CreateGroupRequest {
    name: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateGroupRequest {
    name: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct GroupResponse {
    id: String,
    #[serde(rename = "orgId")]
    organization_id: String,
    name: String,
    description: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct GroupMemberResponse {
    id: String,
    #[serde(rename = "groupId")]
    group_id: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct AddMemberRequest {
    #[serde(rename = "userId")]
    user_id: String,
}

async fn list_groups(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
    Query(query): Query<ListGroupsQuery>,
) -> Result<Json<Vec<GroupResponse>>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * per_page;

    let rows = sqlx::query_as::<_, GroupResponse>(
        r#"SELECT id::text, organization_id::text as organization_id, name, description, created_at::text as created_at, updated_at::text as updated_at
            FROM org_groups
            WHERE tenant_id = $1::uuid AND organization_id = $2::uuid
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .bind(per_page)
    .bind(offset)
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(rows))
}

async fn create_group(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<GroupResponse>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let row = sqlx::query_as::<_, GroupResponse>(
        r#"INSERT INTO org_groups (tenant_id, organization_id, name, description)
           VALUES ($1::uuid, $2::uuid, $3, $4)
           RETURNING id::text, organization_id::text as organization_id, name, description, created_at::text as created_at, updated_at::text as updated_at"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .bind(&req.name)
    .bind(&req.description)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(row))
}

async fn update_group(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(group_id): Path<String>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<GroupResponse>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let row = sqlx::query_as::<_, GroupResponse>(
        r#"UPDATE org_groups
           SET name = COALESCE($1, name), description = COALESCE($2, description), updated_at = NOW()
           WHERE tenant_id = $3::uuid AND id = $4::uuid
           RETURNING id::text, organization_id::text as organization_id, name, description, created_at::text as created_at, updated_at::text as updated_at"#,
    )
    .bind(req.name)
    .bind(req.description)
    .bind(&current_user.tenant_id)
    .bind(&group_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(row))
}

async fn delete_group(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(group_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    sqlx::query("DELETE FROM org_groups WHERE tenant_id = $1::uuid AND id = $2::uuid")
        .bind(&current_user.tenant_id)
        .bind(&group_id)
        .execute(&mut *conn)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({"deleted": true})))
}

async fn list_group_members(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(group_id): Path<String>,
) -> Result<Json<Vec<GroupMemberResponse>>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let rows = sqlx::query_as::<_, GroupMemberResponse>(
        r#"SELECT id::text, group_id::text as group_id, user_id::text as user_id, created_at::text as created_at
           FROM org_group_members
           WHERE tenant_id = $1::uuid AND group_id = $2::uuid
           ORDER BY created_at DESC"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&group_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(rows))
}

async fn add_group_member(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(group_id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<GroupMemberResponse>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let row = sqlx::query_as::<_, GroupMemberResponse>(
        r#"INSERT INTO org_group_members (tenant_id, organization_id, group_id, user_id)
           SELECT $1::uuid, g.organization_id, g.id, $2::uuid
           FROM org_groups g
           WHERE g.tenant_id = $1::uuid AND g.id = $3::uuid
           RETURNING id::text, group_id::text as group_id, user_id::text as user_id, created_at::text as created_at"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&req.user_id)
    .bind(&group_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(row))
}

async fn remove_group_member(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((group_id, user_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    sqlx::query(
        "DELETE FROM org_group_members WHERE tenant_id = $1::uuid AND group_id = $2::uuid AND user_id = $3::uuid",
    )
    .bind(&current_user.tenant_id)
    .bind(&group_id)
    .bind(&user_id)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({"deleted": true})))
}
