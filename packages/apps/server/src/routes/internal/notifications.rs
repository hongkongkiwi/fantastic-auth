//! Internal notifications routes

use axum::{
    extract::State,
    routing::{get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::permissions::checker::PermissionChecker;
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

#[derive(Debug, Serialize, Clone)]
pub struct NotificationResponse {
    pub id: String,
    pub title: String,
    pub description: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub r#type: String,
    pub read: bool,
}

#[derive(Debug, Deserialize)]
struct MarkReadRequest {
    ids: Vec<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct NotificationRow {
    id: String,
    title: String,
    description: String,
    created_at: DateTime<Utc>,
    r#type: String,
    read: bool,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/notifications", get(list_notifications))
        .route("/notifications/mark-read", post(mark_notifications_read))
}

async fn require_notifications_read(
    state: &AppState,
    current_user: &CurrentUser,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let checker = PermissionChecker::new(state.db.pool().clone(), state.redis.clone());
    let allowed = checker
        .has_permission(&current_user.user_id, "settings:read")
        .await;
    if !allowed {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn require_notifications_write(
    state: &AppState,
    current_user: &CurrentUser,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let checker = PermissionChecker::new(state.db.pool().clone(), state.redis.clone());
    let allowed = checker
        .has_permission(&current_user.user_id, "settings:write")
        .await;
    if !allowed {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn list_notifications(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<NotificationResponse>>, ApiError> {
    require_notifications_read(&state, &current_user).await?;

    let rows = sqlx::query_as::<_, NotificationRow>(
        r#"
        SELECT id::text as id,
               title,
               description,
               created_at,
               "type" as "type",
               read
        FROM notifications
        WHERE tenant_id = $1::uuid
        ORDER BY created_at DESC
        "#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let items = rows
        .into_iter()
        .map(|row| NotificationResponse {
            id: row.id,
            title: row.title,
            description: row.description,
            created_at: row.created_at.to_rfc3339(),
            r#type: row.r#type,
            read: row.read,
        })
        .collect();

    Ok(Json(items))
}

async fn mark_notifications_read(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(payload): Json<MarkReadRequest>,
) -> Result<Json<Vec<NotificationResponse>>, ApiError> {
    require_notifications_write(&state, &current_user).await?;

    let ids: Vec<Uuid> = payload
        .ids
        .iter()
        .filter_map(|id| Uuid::parse_str(id).ok())
        .collect();

    if ids.is_empty() {
        return Err(ApiError::BadRequest("No valid notification ids".to_string()));
    }

    sqlx::query(
        r#"
        UPDATE notifications
        SET read = true
        WHERE tenant_id = $1::uuid AND id = ANY($2)
        "#,
    )
    .bind(&current_user.tenant_id)
    .bind(&ids)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let rows = sqlx::query_as::<_, NotificationRow>(
        r#"
        SELECT id::text as id,
               title,
               description,
               created_at,
               "type" as "type",
               read
        FROM notifications
        WHERE tenant_id = $1::uuid
        ORDER BY created_at DESC
        "#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let items = rows
        .into_iter()
        .map(|row| NotificationResponse {
            id: row.id,
            title: row.title,
            description: row.description,
            created_at: row.created_at.to_rfc3339(),
            r#type: row.r#type,
            read: row.read,
        })
        .collect();

    Ok(Json(items))
}
