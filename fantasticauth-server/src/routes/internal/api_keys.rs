//! Internal API key management

use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::permissions::checker::PermissionChecker;
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

#[derive(Debug, Serialize, Clone)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub prefix: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(rename = "lastUsedAt")]
    pub last_used_at: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub key: String,
    #[serde(rename = "apiKey")]
    pub api_key: ApiKeyResponse,
}

#[derive(Debug, Deserialize)]
struct CreateApiKeyRequest {
    name: String,
    scopes: Vec<String>,
    #[serde(rename = "expiresInDays")]
    expires_in_days: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct ApiKeyRow {
    id: String,
    name: String,
    prefix: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    scopes: Vec<String>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api-keys/:key_id", delete(delete_api_key))
}

async fn require_settings_manage(
    state: &AppState,
    current_user: &CurrentUser,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let checker = PermissionChecker::new(state.db.pool().clone(), state.redis.clone());
    let allowed = checker
        .has_permission(&current_user.user_id, "settings:manage")
        .await;
    if !allowed {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn list_api_keys(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<ApiKeyResponse>>, ApiError> {
    require_settings_manage(&state, &current_user).await?;

    let rows = sqlx::query_as::<_, ApiKeyRow>(
        r#"
        SELECT id::text as id,
               name,
               prefix,
               created_at,
               expires_at,
               last_used_at,
               scopes
        FROM admin_api_keys
        WHERE tenant_id = $1::uuid
        ORDER BY created_at DESC
        "#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let keys = rows
        .into_iter()
        .map(|row| ApiKeyResponse {
            id: row.id,
            name: row.name,
            prefix: row.prefix,
            created_at: row.created_at.to_rfc3339(),
            expires_at: row.expires_at.map(|dt| dt.to_rfc3339()),
            last_used_at: row.last_used_at.map(|dt| dt.to_rfc3339()),
            scopes: row.scopes,
        })
        .collect();

    Ok(Json(keys))
}

async fn create_api_key(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, ApiError> {
    require_settings_manage(&state, &current_user).await?;

    let id = Uuid::new_v4();
    let prefix = format!("pk_fake_removed
    let created_at = Utc::now();
    let expires_at = payload
        .expires_in_days
        .map(|days| created_at + Duration::days(days));
    let key = format!("{}_{}", prefix, Uuid::new_v4().to_string().replace('-', ""));
    let hash = Sha256::digest(key.as_bytes());
    let key_hash = format!("{:x}", hash);

    sqlx::query(
        r#"
        INSERT INTO admin_api_keys
            (id, tenant_id, name, prefix, key_hash, scopes, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#,
    )
    .bind(id)
    .bind(&current_user.tenant_id)
    .bind(&payload.name)
    .bind(&prefix)
    .bind(&key_hash)
    .bind(&payload.scopes)
    .bind(expires_at)
    .bind(created_at)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let api_key = ApiKeyResponse {
        id: id.to_string(),
        name: payload.name,
        prefix,
        created_at: created_at.to_rfc3339(),
        expires_at: expires_at.map(|dt| dt.to_rfc3339()),
        last_used_at: None,
        scopes: payload.scopes,
    };

    Ok(Json(CreateApiKeyResponse { key, api_key }))
}

async fn delete_api_key(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(key_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_settings_manage(&state, &current_user).await?;

    let result = sqlx::query(
        "DELETE FROM admin_api_keys WHERE id = $1::uuid AND tenant_id = $2::uuid",
    )
    .bind(&key_id)
    .bind(&current_user.tenant_id)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    Ok(Json(serde_json::json!({"message": "API key revoked"})))
}
