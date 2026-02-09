//! Admin API Key Management Routes
//!
//! Provides administrative endpoints for managing tenant-scoped API keys:
//! - GET /api/v1/admin/api-keys - List all API keys
//! - POST /api/v1/admin/api-keys - Create new API key
//! - GET /api/v1/admin/api-keys/:id - Get API key details
//! - PUT /api/v1/admin/api-keys/:id - Update API key
//! - DELETE /api/v1/admin/api-keys/:id - Revoke API key
//! - GET /api/v1/admin/api-keys/:id/stats - Get API key usage stats
//! - POST /api/v1/admin/api-keys/:id/rotate - Rotate API key
//!
//! Features:
//! - Scoped API keys with granular permissions
//! - Expiration management
//! - Usage statistics
//! - Revocation with audit logging

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use validator::Validate;

use crate::audit::{AuditAction, AuditLogger, ResourceType};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// API key routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .route(
            "/api-keys/:id",
            get(get_api_key).put(update_api_key).delete(revoke_api_key),
        )
        .route("/api-keys/:id/stats", get(get_api_key_stats))
        .route("/api-keys/:id/rotate", post(rotate_api_key))
        .route("/api-keys/:id/revoke", put(revoke_api_key))
}

// ============ Request/Response Types ============

/// API key scope
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyScope {
    /// Full admin access
    Admin,
    /// Read-only access
    ReadOnly,
    /// User management only
    Users,
    /// Organization management only
    Organizations,
    /// Audit logs access
    Audit,
    /// Custom scope with specific permissions
    Custom(Vec<String>),
}

/// Create API key request
#[derive(Debug, Deserialize, Validate)]
pub struct CreateApiKeyRequest {
    /// Display name for the API key
    #[validate(length(min = 1, max = 100, message = "Name must be between 1 and 100 characters"))]
    pub name: String,
    /// Description of the key's purpose
    #[validate(length(max = 500, message = "Description must be at most 500 characters"))]
    pub description: Option<String>,
    /// Scope/permissions for the key
    pub scope: ApiKeyScope,
    /// Expiration in days (None for no expiration)
    pub expires_in_days: Option<i64>,
    /// IP allowlist (optional)
    pub allowed_ips: Option<Vec<String>>,
    /// Rate limit override (requests per minute)
    pub rate_limit_per_minute: Option<u32>,
}

/// Update API key request
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateApiKeyRequest {
    /// Display name
    #[validate(length(min = 1, max = 100))]
    pub name: Option<String>,
    /// Description
    #[validate(length(max = 500))]
    pub description: Option<String>,
    /// Scope/permissions
    pub scope: Option<ApiKeyScope>,
    /// IP allowlist
    pub allowed_ips: Option<Vec<String>>,
    /// Rate limit override
    pub rate_limit_per_minute: Option<u32>,
}

/// API key response (without secret)
#[derive(Debug, Serialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub prefix: String,
    pub scope: ApiKeyScope,
    pub created_at: String,
    pub created_by: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub is_active: bool,
    pub allowed_ips: Option<Vec<String>>,
    pub rate_limit_per_minute: Option<u32>,
}

/// API key response with secret (only returned on creation)
#[derive(Debug, Serialize)]
pub struct ApiKeyWithSecretResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    /// The full API key (only shown once)
    pub key: String,
    pub prefix: String,
    pub scope: ApiKeyScope,
    pub created_at: String,
    pub created_by: String,
    pub expires_at: Option<String>,
    pub is_active: bool,
}

/// API key usage statistics
#[derive(Debug, Serialize)]
pub struct ApiKeyStats {
    pub total_requests: i64,
    pub requests_today: i64,
    pub requests_this_week: i64,
    pub requests_this_month: i64,
    pub error_count: i64,
    pub last_used_endpoint: Option<String>,
    pub top_endpoints: Vec<EndpointStat>,
}

#[derive(Debug, Serialize)]
pub struct EndpointStat {
    pub endpoint: String,
    pub count: i64,
}

/// List API keys query parameters
#[derive(Debug, Deserialize)]
pub struct ListApiKeysQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub active_only: Option<bool>,
    pub scope: Option<String>,
}

/// List API keys response
#[derive(Debug, Serialize)]
pub struct ListApiKeysResponse {
    pub keys: Vec<ApiKeyResponse>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct ApiKeyRow {
    id: String,
    name: String,
    description: Option<String>,
    prefix: String,
    key_hash: String,
    scope: serde_json::Value,
    created_at: DateTime<Utc>,
    created_by: String,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    is_active: bool,
    allowed_ips: Option<serde_json::Value>,
    rate_limit_per_minute: Option<i32>,
}

// ============ Handlers ============

/// List all API keys for the tenant
async fn list_api_keys(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListApiKeysQuery>,
) -> Result<Json<ListApiKeysResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * per_page;

    // Build query based on filters
    let (rows, total): (Vec<ApiKeyRow>, i64) = if let Some(true) = query.active_only {
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            r#"SELECT id::text, name, description, prefix, key_hash, scope,
                   created_at, created_by::text, expires_at, last_used_at, is_active,
                   allowed_ips, rate_limit_per_minute
            FROM admin_api_keys
            WHERE tenant_id = $1::uuid AND is_active = true
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3"#,
        )
        .bind(&current_user.tenant_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM admin_api_keys WHERE tenant_id = $1::uuid AND is_active = true",
        )
        .bind(&current_user.tenant_id)
        .fetch_one(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;

        (rows, total)
    } else {
        let rows = sqlx::query_as::<_, ApiKeyRow>(
            r#"SELECT id::text, name, description, prefix, key_hash, scope,
                   created_at, created_by::text, expires_at, last_used_at, is_active,
                   allowed_ips, rate_limit_per_minute
            FROM admin_api_keys
            WHERE tenant_id = $1::uuid
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3"#,
        )
        .bind(&current_user.tenant_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM admin_api_keys WHERE tenant_id = $1::uuid",
        )
        .bind(&current_user.tenant_id)
        .fetch_one(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;

        (rows, total)
    };

    let keys: Vec<ApiKeyResponse> = rows
        .into_iter()
        .map(|row| ApiKeyResponse {
            id: row.id,
            name: row.name,
            description: row.description,
            prefix: row.prefix,
            scope: serde_json::from_value(row.scope).unwrap_or(ApiKeyScope::ReadOnly),
            created_at: row.created_at.to_rfc3339(),
            created_by: row.created_by,
            expires_at: row.expires_at.map(|dt| dt.to_rfc3339()),
            last_used_at: row.last_used_at.map(|dt| dt.to_rfc3339()),
            is_active: row.is_active,
            allowed_ips: row
                .allowed_ips
                .and_then(|v| serde_json::from_value(v).ok()),
            rate_limit_per_minute: row.rate_limit_per_minute.map(|v| v as u32),
        })
        .collect();

    Ok(Json(ListApiKeysResponse {
        keys,
        total,
        page,
        per_page,
    }))
}

/// Create a new API key
async fn create_api_key(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<ApiKeyWithSecretResponse>), ApiError> {
    req.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let id = Uuid::new_v4();
    let prefix = format!("vault_{}", &Uuid::new_v4().to_string()[..12]);
    let key = format!("{}_{}", prefix, Uuid::new_v4().to_string().replace('-', ""));
    let hash = Sha256::digest(key.as_bytes());
    let key_hash = format!("{:x}", hash);
    let created_at = Utc::now();
    let expires_at = req.expires_in_days.map(|days| created_at + Duration::days(days));

    let scope_json = serde_json::to_value(&req.scope).map_err(|_| ApiError::Internal)?;
    let allowed_ips_json = req
        .allowed_ips
        .as_ref()
        .map(|ips| serde_json::to_value(ips).unwrap_or_default());

    sqlx::query(
        r#"INSERT INTO admin_api_keys
           (id, tenant_id, name, description, prefix, key_hash, scope,
            created_at, created_by, expires_at, is_active, allowed_ips, rate_limit_per_minute)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, $11, $12)"#,
    )
    .bind(id)
    .bind(&current_user.tenant_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&prefix)
    .bind(&key_hash)
    .bind(scope_json)
    .bind(created_at)
    .bind(&current_user.user_id)
    .bind(expires_at)
    .bind(allowed_ips_json)
    .bind(req.rate_limit_per_minute.map(|v| v as i32))
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to create API key: {}", e);
        ApiError::Internal
    })?;

    // Log the creation
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("api_key.created"),
        ResourceType::Admin,
        &id.to_string(),
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "name": req.name,
            "scope": req.scope,
            "expires_in_days": req.expires_in_days,
        })),
    );

    Ok((
        StatusCode::CREATED,
        Json(ApiKeyWithSecretResponse {
            id: id.to_string(),
            name: req.name,
            description: req.description,
            key,
            prefix,
            scope: req.scope,
            created_at: created_at.to_rfc3339(),
            created_by: current_user.user_id,
            expires_at: expires_at.map(|dt| dt.to_rfc3339()),
            is_active: true,
        }),
    ))
}

/// Get a single API key by ID
async fn get_api_key(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiKeyResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let row: Option<ApiKeyRow> = sqlx::query_as(
        r#"SELECT id::text, name, description, prefix, key_hash, scope,
               created_at, created_by::text, expires_at, last_used_at, is_active,
               allowed_ips, rate_limit_per_minute
        FROM admin_api_keys
        WHERE id = $1::uuid AND tenant_id = $2::uuid"#,
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let row = row.ok_or(ApiError::NotFound)?;

    Ok(Json(ApiKeyResponse {
        id: row.id,
        name: row.name,
        description: row.description,
        prefix: row.prefix,
        scope: serde_json::from_value(row.scope).unwrap_or(ApiKeyScope::ReadOnly),
        created_at: row.created_at.to_rfc3339(),
        created_by: row.created_by,
        expires_at: row.expires_at.map(|dt| dt.to_rfc3339()),
        last_used_at: row.last_used_at.map(|dt| dt.to_rfc3339()),
        is_active: row.is_active,
        allowed_ips: row
            .allowed_ips
            .and_then(|v| serde_json::from_value(v).ok()),
        rate_limit_per_minute: row.rate_limit_per_minute.map(|v| v as u32),
    }))
}

/// Update an API key
async fn update_api_key(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, ApiError> {
    req.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if key exists
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM admin_api_keys WHERE id = $1::uuid AND tenant_id = $2::uuid)",
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    if !exists {
        return Err(ApiError::NotFound);
    }

    // Apply updates
    if let Some(name) = req.name {
        sqlx::query("UPDATE admin_api_keys SET name = $1 WHERE id = $2::uuid")
            .bind(name)
            .bind(&id)
            .execute(state.db.pool())
            .await
            .map_err(|_| ApiError::Internal)?;
    }

    if let Some(description) = req.description {
        sqlx::query("UPDATE admin_api_keys SET description = $1 WHERE id = $2::uuid")
            .bind(description)
            .bind(&id)
            .execute(state.db.pool())
            .await
            .map_err(|_| ApiError::Internal)?;
    }

    if let Some(scope) = req.scope {
        let scope_json = serde_json::to_value(scope).map_err(|_| ApiError::Internal)?;
        sqlx::query("UPDATE admin_api_keys SET scope = $1 WHERE id = $2::uuid")
            .bind(scope_json)
            .bind(&id)
            .execute(state.db.pool())
            .await
            .map_err(|_| ApiError::Internal)?;
    }

    if let Some(allowed_ips) = req.allowed_ips {
        let ips_json = serde_json::to_value(allowed_ips).map_err(|_| ApiError::Internal)?;
        sqlx::query("UPDATE admin_api_keys SET allowed_ips = $1 WHERE id = $2::uuid")
            .bind(ips_json)
            .bind(&id)
            .execute(state.db.pool())
            .await
            .map_err(|_| ApiError::Internal)?;
    }

    if let Some(rate_limit) = req.rate_limit_per_minute {
        sqlx::query("UPDATE admin_api_keys SET rate_limit_per_minute = $1 WHERE id = $2::uuid")
            .bind(rate_limit as i32)
            .bind(&id)
            .execute(state.db.pool())
            .await
            .map_err(|_| ApiError::Internal)?;
    }

    // Log the update
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("api_key.updated"),
        ResourceType::Admin,
        &id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        None,
    );

    // Return updated key
    get_api_key(State(state), Extension(current_user), Path(id)).await
}

/// Revoke an API key
async fn revoke_api_key(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let result = sqlx::query(
        "UPDATE admin_api_keys SET is_active = false, revoked_at = NOW(), revoked_by = $1
         WHERE id = $2::uuid AND tenant_id = $3::uuid AND is_active = true",
    )
    .bind(&current_user.user_id)
    .bind(&id)
    .bind(&current_user.tenant_id)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    // Log the revocation
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("api_key.revoked"),
        ResourceType::Admin,
        &id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        None,
    );

    Ok(Json(serde_json::json!({
        "message": "API key revoked successfully",
        "id": id
    })))
}

/// Rotate an API key (revoke old one and create new)
async fn rotate_api_key(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<ApiKeyWithSecretResponse>), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Get the old key details
    let old_key: Option<ApiKeyRow> = sqlx::query_as(
        r#"SELECT id::text, name, description, prefix, key_hash, scope,
               created_at, created_by::text, expires_at, last_used_at, is_active,
               allowed_ips, rate_limit_per_minute
        FROM admin_api_keys
        WHERE id = $1::uuid AND tenant_id = $2::uuid AND is_active = true"#,
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let old_key = old_key.ok_or(ApiError::NotFound)?;

    // Revoke the old key
    sqlx::query(
        "UPDATE admin_api_keys SET is_active = false, revoked_at = NOW(), revoked_by = $1
         WHERE id = $2::uuid",
    )
    .bind(&current_user.user_id)
    .bind(&id)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    // Create new key with same settings
    let new_id = Uuid::new_v4();
    let prefix = format!("vault_{}", &Uuid::new_v4().to_string()[..12]);
    let key = format!("{}_{}", prefix, Uuid::new_v4().to_string().replace('-', ""));
    let hash = Sha256::digest(key.as_bytes());
    let key_hash = format!("{:x}", hash);
    let created_at = Utc::now();

    sqlx::query(
        r#"INSERT INTO admin_api_keys
           (id, tenant_id, name, description, prefix, key_hash, scope,
            created_at, created_by, expires_at, is_active, allowed_ips, rate_limit_per_minute)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, $11, $12)"#,
    )
    .bind(new_id)
    .bind(&current_user.tenant_id)
    .bind(format!("{} (rotated)", old_key.name))
    .bind(&old_key.description)
    .bind(&prefix)
    .bind(&key_hash)
    .bind(&old_key.scope)
    .bind(created_at)
    .bind(&current_user.user_id)
    .bind(old_key.expires_at)
    .bind(&old_key.allowed_ips)
    .bind(old_key.rate_limit_per_minute)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    // Log the rotation
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("api_key.rotated"),
        ResourceType::Admin,
        &new_id.to_string(),
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "old_key_id": id,
            "new_key_id": new_id.to_string(),
        })),
    );

    Ok((
        StatusCode::CREATED,
        Json(ApiKeyWithSecretResponse {
            id: new_id.to_string(),
            name: format!("{} (rotated)", old_key.name),
            description: old_key.description,
            key,
            prefix,
            scope: serde_json::from_value(old_key.scope).unwrap_or(ApiKeyScope::ReadOnly),
            created_at: created_at.to_rfc3339(),
            created_by: current_user.user_id,
            expires_at: old_key.expires_at.map(|dt| dt.to_rfc3339()),
            is_active: true,
        }),
    ))
}

/// Get API key usage statistics
async fn get_api_key_stats(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<ApiKeyStats>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Verify key exists and belongs to tenant
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM admin_api_keys WHERE id = $1::uuid AND tenant_id = $2::uuid)",
    )
    .bind(&id)
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    if !exists {
        return Err(ApiError::NotFound);
    }

    // Get stats from analytics (simplified - in production would query from analytics tables)
    let today = Utc::now().date_naive();
    let week_ago = today - chrono::Duration::days(7);
    let month_ago = today - chrono::Duration::days(30);

    let total_requests: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_key_usage_logs WHERE api_key_id = $1::uuid",
    )
    .bind(&id)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(0);

    let requests_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_key_usage_logs 
         WHERE api_key_id = $1::uuid AND DATE(created_at) = $2",
    )
    .bind(&id)
    .bind(today)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(0);

    let requests_this_week: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_key_usage_logs 
         WHERE api_key_id = $1::uuid AND DATE(created_at) >= $2",
    )
    .bind(&id)
    .bind(week_ago)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(0);

    let requests_this_month: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_key_usage_logs 
         WHERE api_key_id = $1::uuid AND DATE(created_at) >= $2",
    )
    .bind(&id)
    .bind(month_ago)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(0);

    let error_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_key_usage_logs 
         WHERE api_key_id = $1::uuid AND status_code >= 400",
    )
    .bind(&id)
    .fetch_one(state.db.pool())
    .await
    .unwrap_or(0);

    // Get top endpoints
    let top_endpoints: Vec<(String, i64)> = sqlx::query_as(
        r#"SELECT endpoint, COUNT(*) as count
           FROM api_key_usage_logs
           WHERE api_key_id = $1::uuid
           GROUP BY endpoint
           ORDER BY count DESC
           LIMIT 5"#,
    )
    .bind(&id)
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    let last_used_endpoint: Option<String> = sqlx::query_scalar(
        "SELECT endpoint FROM api_key_usage_logs 
         WHERE api_key_id = $1::uuid ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&id)
    .fetch_optional(state.db.pool())
    .await
    .ok()
    .flatten();

    Ok(Json(ApiKeyStats {
        total_requests,
        requests_today,
        requests_this_week,
        requests_this_month,
        error_count,
        last_used_endpoint,
        top_endpoints: top_endpoints
            .into_iter()
            .map(|(endpoint, count)| EndpointStat { endpoint, count })
            .collect(),
    }))
}
