//! Admin M2M Management Routes
//!
//! Provides administrative endpoints for managing service accounts and API keys.
//!
//! # Endpoints
//!
//! - `POST /api/v1/admin/service-accounts` - Create service account
//! - `GET /api/v1/admin/service-accounts` - List service accounts
//! - `GET /api/v1/admin/service-accounts/:id` - Get service account
//! - `PUT /api/v1/admin/service-accounts/:id` - Update service account
//! - `DELETE /api/v1/admin/service-accounts/:id` - Delete service account
//! - `POST /api/v1/admin/service-accounts/:id/rotate-secret` - Rotate client secret
//! - `POST /api/v1/admin/service-accounts/:id/keys` - Create API key
//! - `GET /api/v1/admin/service-accounts/:id/keys` - List API keys
//! - `DELETE /api/v1/admin/service-accounts/:id/keys/:key_id` - Revoke API key
//! - `POST /api/v1/admin/service-accounts/:id/revoke-keys` - Revoke all keys

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::{
    audit::{AuditAction, AuditLogger, ResourceType},
    m2m::{
        ApiKeyWithSecret, CreateApiKeyRequest, CreateServiceAccountRequest,
        ServiceAccountCredentials, ServiceAccountSummary, ServiceAccount, UpdateServiceAccountRequest, UpdateApiKeyRequest,
    },
    routes::ApiError,
    state::{AppState, CurrentUser},
};

/// Admin M2M routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/service-accounts", get(list_service_accounts).post(create_service_account))
        .route(
            "/service-accounts/:id",
            get(get_service_account)
                .put(update_service_account)
                .delete(delete_service_account),
        )
        .route("/service-accounts/:id/rotate-secret", post(rotate_secret))
        .route(
            "/service-accounts/:id/keys",
            get(list_api_keys).post(create_api_key),
        )
        .route("/service-accounts/:id/keys/:key_id", delete(revoke_api_key))
        .route("/service-accounts/:id/revoke-keys", post(revoke_all_keys))
}

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
struct ListServiceAccountsQuery {
    page: Option<i64>,
    per_page: Option<i64>,
}

#[derive(Debug, Serialize)]
struct ServiceAccountListResponse {
    service_accounts: Vec<ServiceAccountSummary>,
    total: i64,
    page: i64,
    per_page: i64,
}

#[derive(Debug, Serialize)]
struct RotatedSecretResponse {
    client_secret: String,
    #[serde(rename = "rotatedAt")]
    rotated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
struct RevokedKeysResponse {
    #[serde(rename = "revokedCount")]
    revoked_count: u64,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

// ============ Handlers ============

/// List all service accounts for the tenant
async fn list_service_accounts(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListServiceAccountsQuery>,
) -> Result<Json<ServiceAccountListResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);

    let (service_accounts, total) = state
        .m2m_service
        .list_service_accounts(&current_user.tenant_id, page, per_page)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list service accounts: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(ServiceAccountListResponse {
        service_accounts,
        total,
        page,
        per_page,
    }))
}

/// Get a single service account by ID
async fn get_service_account(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ServiceAccount>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let service_account = state
        .m2m_service
        .get_service_account(&current_user.tenant_id, &id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get service account: {}", e);
            ApiError::Internal
        })?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(service_account))
}

/// Create a new service account
async fn create_service_account(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(request): Json<CreateServiceAccountRequest>,
) -> Result<(StatusCode, Json<ServiceAccountCredentials>), ApiError> {
    // Validate request
    request
        .validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Create the service account
    let credentials = state
        .m2m_service
        .create_service_account(&current_user.tenant_id, request)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create service account: {}", e);
            ApiError::Internal
        })?;

    // Log the creation
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("service_account.created"),
        ResourceType::Admin,
        &credentials.id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "client_id": credentials.client_id,
            "name": credentials.name,
        })),
    );

    Ok((StatusCode::CREATED, Json(credentials)))
}

/// Update a service account
async fn update_service_account(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(request): Json<UpdateServiceAccountRequest>,
) -> Result<Json<ServiceAccount>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if service account exists
    let exists = state
        .m2m_service
        .get_service_account(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !exists {
        return Err(ApiError::NotFound);
    }

    // Update the service account
    let updated = state
        .m2m_service
        .update_service_account(&current_user.tenant_id, &id, request)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update service account: {}", e);
            ApiError::Internal
        })?;

    // Log the update
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("service_account.updated"),
        ResourceType::Admin,
        &id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        None,
    );

    Ok(Json(updated))
}

/// Delete a service account
async fn delete_service_account(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if service account exists
    let service_account = state
        .m2m_service
        .get_service_account(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    // Delete the service account (this also revokes all API keys)
    state
        .m2m_service
        .delete_service_account(&current_user.tenant_id, &id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete service account: {}", e);
            ApiError::Internal
        })?;

    // Log the deletion
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("service_account.deleted"),
        ResourceType::Admin,
        &id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "client_id": service_account.client_id,
            "name": service_account.name,
        })),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Rotate the client secret for a service account
async fn rotate_secret(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<RotatedSecretResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if service account exists
    let exists = state
        .m2m_service
        .get_service_account(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !exists {
        return Err(ApiError::NotFound);
    }

    // Rotate the secret
    let new_secret = state
        .m2m_service
        .rotate_client_secret(&current_user.tenant_id, &id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to rotate client secret: {}", e);
            ApiError::Internal
        })?;

    // Log the rotation
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("service_account.secret_rotated"),
        ResourceType::Admin,
        &id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        None,
    );

    Ok(Json(RotatedSecretResponse {
        client_secret: new_secret,
        rotated_at: chrono::Utc::now(),
    }))
}

/// List all API keys for a service account
async fn list_api_keys(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<Vec<crate::m2m::ApiKeySummary>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if service account exists
    let exists = state
        .m2m_service
        .get_service_account(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !exists {
        return Err(ApiError::NotFound);
    }

    let keys = state
        .m2m_service
        .api_keys()
        .list_keys(&current_user.tenant_id, &id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list API keys: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(keys))
}

/// Create a new API key for a service account
async fn create_api_key(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<ApiKeyWithSecret>), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if service account exists
    let exists = state
        .m2m_service
        .get_service_account(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !exists {
        return Err(ApiError::NotFound);
    }

    // Create the API key
    let api_key = state
        .m2m_service
        .api_keys()
        .create_key(&current_user.tenant_id, &id, request)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create API key: {}", e);
            ApiError::Internal
        })?;

    // Log the creation
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("service_account.api_key_created"),
        ResourceType::Admin,
        &api_key.id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "service_account_id": id,
            "key_name": api_key.name,
        })),
    );

    Ok((StatusCode::CREATED, Json(api_key)))
}

/// Revoke (deactivate) an API key
async fn revoke_api_key(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((service_account_id, key_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if service account exists
    let exists = state
        .m2m_service
        .get_service_account(&current_user.tenant_id, &service_account_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !exists {
        return Err(ApiError::NotFound);
    }

    // Revoke the key
    state
        .m2m_service
        .api_keys()
        .revoke_key(&current_user.tenant_id, &key_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke API key: {}", e);
            ApiError::Internal
        })?;

    // Log the revocation
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("service_account.api_key_revoked"),
        ResourceType::Admin,
        &key_id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "service_account_id": service_account_id,
        })),
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Revoke all API keys for a service account
async fn revoke_all_keys(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<RevokedKeysResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if service account exists
    let exists = state
        .m2m_service
        .get_service_account(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !exists {
        return Err(ApiError::NotFound);
    }

    // Revoke all keys
    let revoked_count = state
        .m2m_service
        .api_keys()
        .revoke_all_keys(&current_user.tenant_id, &id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to revoke all API keys: {}", e);
            ApiError::Internal
        })?;

    // Log the revocation
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("service_account.all_keys_revoked"),
        ResourceType::Admin,
        &id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "revoked_count": revoked_count,
        })),
    );

    Ok(Json(RevokedKeysResponse { revoked_count }))
}
