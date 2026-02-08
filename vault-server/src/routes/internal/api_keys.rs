//! Internal API key management

use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Extension, Json, Router,
};
use chrono::{Duration, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use uuid::Uuid;

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

static API_KEYS: Lazy<Mutex<Vec<ApiKeyResponse>>> = Lazy::new(|| {
    Mutex::new(vec![ApiKeyResponse {
        id: "key-1".to_string(),
        name: "Production API".to_string(),
        prefix: "pk_fake_removed
        created_at: "2024-01-15T10:00:00Z".to_string(),
        expires_at: None,
        last_used_at: Some("2024-02-08T14:30:00Z".to_string()),
        scopes: vec!["read:users".to_string(), "write:users".to_string()],
    }])
});

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route("/api-keys/:key_id", delete(delete_api_key))
}

async fn list_api_keys(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<ApiKeyResponse>>, ApiError> {
    let keys = API_KEYS.lock().map_err(|_| ApiError::Internal)?;
    Ok(Json(keys.clone()))
}

async fn create_api_key(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Json(payload): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, ApiError> {
    let mut keys = API_KEYS.lock().map_err(|_| ApiError::Internal)?;
    let id = format!("key-{}", keys.len() + 1);
    let prefix = format!("pk_fake_removed
    let created_at = Utc::now();
    let expires_at = payload
        .expires_in_days
        .map(|days| (created_at + Duration::days(days)).to_rfc3339());
    let api_key = ApiKeyResponse {
        id,
        name: payload.name,
        prefix: prefix.clone(),
        created_at: created_at.to_rfc3339(),
        expires_at,
        last_used_at: None,
        scopes: payload.scopes,
    };
    let key = format!("{}_{}", prefix, Uuid::new_v4().to_string().replace('-', ""));
    keys.insert(0, api_key.clone());
    Ok(Json(CreateApiKeyResponse { key, api_key }))
}

async fn delete_api_key(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(key_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut keys = API_KEYS.lock().map_err(|_| ApiError::Internal)?;
    let before = keys.len();
    keys.retain(|k| k.id != key_id);
    if keys.len() == before {
        return Err(ApiError::NotFound);
    }
    Ok(Json(serde_json::json!({"message": "API key revoked"})))
}
