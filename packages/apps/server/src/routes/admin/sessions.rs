//! Admin Session Management Routes

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::db::set_connection_context;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/sessions", get(list_sessions))
        .route("/sessions/:session_id/revoke", post(revoke_session))
        .route("/users/:user_id/sessions", get(list_user_sessions))
        .route("/users/:user_id/sessions/revoke", post(revoke_user_sessions))
        .route("/devices", get(list_devices))
        .route("/devices/:device_id/block", post(block_device))
        .route("/devices/:device_id/unblock", post(unblock_device))
        .route("/devices/:device_id/trust", post(trust_device))
        .route("/devices/:device_id", delete(delete_device))
}

#[derive(Debug, Deserialize)]
struct ListSessionsQuery {
    #[serde(rename = "userId")]
    user_id: Option<String>,
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct SessionResponse {
    id: String,
    #[serde(rename = "userId")]
    user_id: String,
    status: String,
    #[serde(rename = "ipAddress")]
    ip_address: Option<String>,
    #[serde(rename = "userAgent")]
    user_agent: Option<String>,
    #[serde(rename = "deviceFingerprint")]
    device_fingerprint: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "lastActivityAt")]
    last_activity_at: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "revokedAt")]
    revoked_at: Option<String>,
    #[serde(rename = "revokedReason")]
    revoked_reason: Option<String>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct DeviceResponse {
    id: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "deviceFingerprint")]
    device_fingerprint: String,
    #[serde(rename = "deviceName")]
    device_name: Option<String>,
    #[serde(rename = "deviceType")]
    device_type: Option<String>,
    browser: Option<String>,
    os: Option<String>,
    #[serde(rename = "ipAddress")]
    ip_address: Option<String>,
    #[serde(rename = "firstSeenAt")]
    first_seen_at: String,
    #[serde(rename = "lastSeenAt")]
    last_seen_at: String,
    #[serde(rename = "isTrusted")]
    is_trusted: bool,
    #[serde(rename = "isBlocked")]
    is_blocked: bool,
}

async fn list_sessions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListSessionsQuery>,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * per_page;

    let mut qb = sqlx::QueryBuilder::new(
        "SELECT id::text, user_id::text as user_id, status::text as status, ip_address::text as ip_address, user_agent, device_fingerprint, created_at::text as created_at, last_activity_at::text as last_activity_at, expires_at::text as expires_at, revoked_at::text as revoked_at, revoked_reason FROM sessions WHERE tenant_id = ",
    );
    qb.push_bind(&current_user.tenant_id);
    if let Some(user_id) = &query.user_id {
        qb.push(" AND user_id = ");
        qb.push_bind(user_id);
    }
    qb.push(" ORDER BY created_at DESC LIMIT ");
    qb.push_bind(per_page);
    qb.push(" OFFSET ");
    qb.push_bind(offset);

    let rows = qb
        .build_query_as::<SessionResponse>()
        .fetch_all(&mut *conn)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(rows))
}

async fn list_user_sessions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let rows = sqlx::query_as::<_, SessionResponse>(
        r#"SELECT id::text, user_id::text as user_id, status::text as status, ip_address::text as ip_address, user_agent, device_fingerprint, created_at::text as created_at, last_activity_at::text as last_activity_at, expires_at::text as expires_at, revoked_at::text as revoked_at, revoked_reason
            FROM sessions
            WHERE tenant_id = $1::uuid AND user_id = $2::uuid
            ORDER BY created_at DESC"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&user_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(rows))
}

async fn revoke_session(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(session_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let revoked = state
        .db
        .sessions()
        .revoke_for_routes(&session_id, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({"revoked": revoked})))
}

async fn revoke_user_sessions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let count = state
        .db
        .sessions()
        .revoke_all_for_user_for_routes(&user_id, &current_user.tenant_id, None)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({"revokedCount": count})))
}

async fn list_devices(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListSessionsQuery>,
) -> Result<Json<Vec<DeviceResponse>>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let mut qb = sqlx::QueryBuilder::new(
        "SELECT id::text, user_id::text as user_id, device_fingerprint, device_name, device_type, browser, os, ip_address::text as ip_address, first_seen_at::text as first_seen_at, last_seen_at::text as last_seen_at, is_trusted, is_blocked FROM user_known_devices WHERE tenant_id = ",
    );
    qb.push_bind(&current_user.tenant_id);
    if let Some(user_id) = &query.user_id {
        qb.push(" AND user_id = ");
        qb.push_bind(user_id);
    }
    qb.push(" ORDER BY last_seen_at DESC");

    let rows = qb
        .build_query_as::<DeviceResponse>()
        .fetch_all(&mut *conn)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(rows))
}

async fn block_device(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    sqlx::query("UPDATE user_known_devices SET is_blocked = true WHERE tenant_id = $1::uuid AND id = $2::uuid")
        .bind(&current_user.tenant_id)
        .bind(&device_id)
        .execute(&mut *conn)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({"blocked": true})))
}

async fn unblock_device(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    sqlx::query("UPDATE user_known_devices SET is_blocked = false WHERE tenant_id = $1::uuid AND id = $2::uuid")
        .bind(&current_user.tenant_id)
        .bind(&device_id)
        .execute(&mut *conn)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({"blocked": false})))
}

async fn trust_device(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    sqlx::query("UPDATE user_known_devices SET is_trusted = true, verified_at = NOW() WHERE tenant_id = $1::uuid AND id = $2::uuid")
        .bind(&current_user.tenant_id)
        .bind(&device_id)
        .execute(&mut *conn)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({"trusted": true})))
}

async fn delete_device(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(device_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    sqlx::query("DELETE FROM user_known_devices WHERE tenant_id = $1::uuid AND id = $2::uuid")
        .bind(&current_user.tenant_id)
        .bind(&device_id)
        .execute(&mut *conn)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({"deleted": true})))
}
