//! Admin WebKey/JWKS Management Routes

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::crypto::{KeyManager, KeyType};
use vault_core::db::set_connection_context;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/keys", get(list_keys).post(rotate_key))
        .route("/keys/:key_id/deactivate", post(deactivate_key))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct KeyResponse {
    id: String,
    #[serde(rename = "keyType")]
    key_type: String,
    #[serde(rename = "isActive")]
    is_active: bool,
    version: i32,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "expiresAt")]
    expires_at: Option<String>,
    #[serde(rename = "publicKey")]
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct RotateKeyRequest {
    #[serde(rename = "keyType")]
    key_type: String,
}

async fn list_keys(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<KeyResponse>>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let rows = sqlx::query_as::<_, KeyResponse>(
        r#"SELECT id as id, key_type::text as key_type, is_active, version, created_at::text as created_at,
            expires_at::text as expires_at, public_key
           FROM keys
           WHERE tenant_id = $1::uuid
           ORDER BY created_at DESC"#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(rows))
}

async fn rotate_key(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<Json<KeyResponse>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let key_type = match req.key_type.as_str() {
        "jwt_signing" => KeyType::JwtSigning,
        "data_encryption" => KeyType::DataEncryption,
        "api_key_signing" => KeyType::ApiKeySigning,
        "session_encryption" => KeyType::SessionEncryption,
        _ => return Err(ApiError::BadRequest("Invalid keyType".to_string())),
    };

    let current_version: Option<i32> = sqlx::query_scalar(
        "SELECT MAX(version) FROM keys WHERE tenant_id = $1::uuid AND key_type = $2",
    )
    .bind(&current_user.tenant_id)
    .bind(key_type)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    let next_version = current_version.unwrap_or(0) + 1;

    // Deactivate old keys of this type
    sqlx::query(
        "UPDATE keys SET is_active = false, expires_at = NOW() WHERE tenant_id = $1::uuid AND key_type = $2 AND is_active = true",
    )
    .bind(&current_user.tenant_id)
    .bind(key_type)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    let key_manager = KeyManager::new((*state.data_encryption_key).clone());
    let key_pair = key_manager
        .generate_key_pair(&current_user.tenant_id, key_type, next_version as u32)
        .map_err(|_| ApiError::internal())?;

    let row = sqlx::query_as::<_, KeyResponse>(
        r#"INSERT INTO keys (id, tenant_id, key_type, created_at, expires_at, is_active, version, encrypted_secret, public_key)
           VALUES ($1, $2::uuid, $3, $4, $5, $6, $7, $8, $9)
           RETURNING id as id, key_type::text as key_type, is_active, version, created_at::text as created_at,
                    expires_at::text as expires_at, public_key"#,
    )
    .bind(&key_pair.id)
    .bind(&current_user.tenant_id)
    .bind(key_pair.key_type)
    .bind(key_pair.created_at)
    .bind(key_pair.expires_at)
    .bind(key_pair.is_active)
    .bind(key_pair.version as i32)
    .bind(&key_pair.encrypted_secret)
    .bind(&key_pair.public_key)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(row))
}

async fn deactivate_key(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(key_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::internal())?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    sqlx::query(
        "UPDATE keys SET is_active = false, expires_at = NOW() WHERE tenant_id = $1::uuid AND id = $2",
    )
    .bind(&current_user.tenant_id)
    .bind(&key_id)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(serde_json::json!({"deactivated": true})))
}
