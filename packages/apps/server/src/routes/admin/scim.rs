//! Admin SCIM Configuration Routes
//!
//! Provides endpoints for administrators to manage SCIM provisioning:
//! - Generate SCIM tokens for IdP integration
//! - View and revoke SCIM tokens
//! - View SCIM audit logs
//! - Configure SCIM settings

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post},
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{FromRow, Row};

use crate::routes::ApiError;
use crate::scim::auth::{
    create_scim_token, delete_scim_token, list_scim_tokens, revoke_scim_token,
    CreateScimTokenRequest, ScimToken, ScimTokenWithValue,
};
use crate::state::{AppState, CurrentUser};

/// Routes for SCIM admin endpoints
///
/// These routes are mounted under /api/v1/admin/scim
pub fn routes() -> Router<AppState> {
    Router::new()
        // Token management
        .route("/tokens", get(list_tokens).post(create_token))
        .route("/tokens/:token_id", delete(delete_token).post(revoke_token))
        // Audit logs
        .route("/audit-logs", get(list_audit_logs))
        // Configuration
        .route("/config", get(get_config).put(update_config))
        // Stats
        .route("/stats", get(get_stats))
}

// ============================================================================
// Token Management
// ============================================================================

/// List SCIM tokens
///
/// GET /api/v1/admin/scim/tokens
async fn list_tokens(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Verify admin access
    if !is_admin(&current_user) {
        return Err(ApiError::Forbidden);
    }

    let tokens = list_scim_tokens(&state, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Transform tokens to hide hash
    let token_list: Vec<serde_json::Value> = tokens
        .into_iter()
        .map(|t| {
            json!({
                "id": t.id,
                "name": t.name,
                "status": t.status,
                "created_at": t.created_at,
                "expires_at": t.expires_at,
                "last_used_at": t.last_used_at,
                "created_by": t.created_by,
            })
        })
        .collect();

    Ok(Json(json!({
        "tokens": token_list,
        "total": token_list.len(),
    })))
}

/// Create a new SCIM token
///
/// POST /api/v1/admin/scim/tokens
async fn create_token(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateScimTokenRequest>,
) -> Result<Json<ScimTokenWithValue>, ApiError> {
    // Verify admin access
    if !is_admin(&current_user) {
        return Err(ApiError::Forbidden);
    }

    // Validate request
    if req.name.is_empty() {
        return Err(ApiError::Validation("Token name is required".to_string()));
    }

    if req.name.len() > 100 {
        return Err(ApiError::Validation(
            "Token name must be less than 100 characters".to_string(),
        ));
    }

    let token = create_scim_token(
        &state,
        &current_user.tenant_id,
        &req.name,
        req.expires_in_days,
        Some(&current_user.user_id),
    )
    .await
    .map_err(|_| ApiError::internal())?;

    // Log the action
    tracing::info!(
        "SCIM token created by user {}: {}",
        current_user.user_id,
        token.token.id
    );

    Ok(Json(token))
}

/// Revoke a SCIM token
///
/// POST /api/v1/admin/scim/tokens/:token_id (revoke - soft delete)
async fn revoke_token(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(token_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Verify admin access
    if !is_admin(&current_user) {
        return Err(ApiError::Forbidden);
    }

    let revoked = revoke_scim_token(&state, &current_user.tenant_id, &token_id)
        .await
        .map_err(|_| ApiError::internal())?;

    if !revoked {
        return Err(ApiError::NotFound);
    }

    tracing::info!(
        "SCIM token revoked by user {}: {}",
        current_user.user_id,
        token_id
    );

    Ok(Json(json!({
        "success": true,
        "message": "Token revoked successfully",
    })))
}

/// Delete a SCIM token (hard delete)
///
/// DELETE /api/v1/admin/scim/tokens/:token_id
async fn delete_token(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(token_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    // Verify admin access
    if !is_admin(&current_user) {
        return Err(ApiError::Forbidden);
    }

    let deleted = delete_scim_token(&state, &current_user.tenant_id, &token_id)
        .await
        .map_err(|_| ApiError::internal())?;

    if !deleted {
        return Err(ApiError::NotFound);
    }

    tracing::info!(
        "SCIM token deleted by user {}: {}",
        current_user.user_id,
        token_id
    );

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Audit Logs
// ============================================================================

/// SCIM Audit Log Entry
#[derive(Debug, FromRow, Serialize)]
struct ScimAuditLogEntry {
    id: String,
    tenant_id: String,
    token_id: String,
    action: String,
    resource_type: String,
    resource_id: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    success: bool,
    error: Option<String>,
    created_at: DateTime<Utc>,
}

/// Query parameters for audit logs
#[derive(Debug, Deserialize)]
struct AuditLogQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
    action: Option<String>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    #[serde(rename = "startDate")]
    start_date: Option<DateTime<Utc>>,
    #[serde(rename = "endDate")]
    end_date: Option<DateTime<Utc>>,
}

fn default_limit() -> i64 {
    50
}

/// List SCIM audit logs
///
/// GET /api/v1/admin/scim/audit-logs
async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Verify admin access
    if !is_admin(&current_user) {
        return Err(ApiError::Forbidden);
    }

    let limit = query.limit.clamp(1, 100);
    let action = query.action;
    let resource_type = query.resource_type;
    let start_date = query.start_date;
    let end_date = query.end_date;

    let logs = sqlx::query_as::<_, ScimAuditLogEntry>(
        r#"
        SELECT id::text as id,
               tenant_id::text as tenant_id,
               token_id::text as token_id,
               action,
               resource_type,
               resource_id,
               ip_address::text as ip_address,
               user_agent,
               success,
               error,
               created_at
        FROM scim_audit_logs
        WHERE tenant_id = $1::uuid
          AND ($2::text IS NULL OR action = $2)
          AND ($3::text IS NULL OR resource_type = $3)
          AND ($4::timestamptz IS NULL OR created_at >= $4)
          AND ($5::timestamptz IS NULL OR created_at <= $5)
        ORDER BY created_at DESC
        LIMIT $6 OFFSET $7
        "#,
    )
        .bind(&current_user.tenant_id)
        .bind(action.as_deref())
        .bind(resource_type.as_deref())
        .bind(start_date)
        .bind(end_date)
        .bind(limit)
        .bind(query.offset.max(0))
        .fetch_all(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch SCIM audit logs: {}", e);
            ApiError::internal()
        })?;

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM scim_audit_logs
        WHERE tenant_id = $1::uuid
          AND ($2::text IS NULL OR action = $2)
          AND ($3::text IS NULL OR resource_type = $3)
          AND ($4::timestamptz IS NULL OR created_at >= $4)
          AND ($5::timestamptz IS NULL OR created_at <= $5)
        "#,
    )
    .bind(&current_user.tenant_id)
    .bind(action.as_deref())
    .bind(resource_type.as_deref())
    .bind(start_date)
    .bind(end_date)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(json!({
        "logs": logs,
        "total": total,
        "limit": limit,
        "offset": query.offset,
    })))
}

// ============================================================================
// Configuration
// ============================================================================

/// SCIM Configuration
#[derive(Debug, Serialize, Deserialize)]
struct ScimConfig {
    enabled: bool,
    #[serde(rename = "baseUrl")]
    base_url: String,
    #[serde(rename = "userSchema")]
    user_schema: ScimUserSchemaConfig,
    #[serde(rename = "groupSchema")]
    group_schema: ScimGroupSchemaConfig,
    mappings: ScimMappingsConfig,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScimUserSchemaConfig {
    #[serde(rename = "customAttributes")]
    custom_attributes: Vec<String>,
    #[serde(rename = "requiredAttributes")]
    required_attributes: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScimGroupSchemaConfig {
    #[serde(rename = "syncMembers")]
    sync_members: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ScimMappingsConfig {
    #[serde(rename = "autoCreateUsers")]
    auto_create_users: bool,
    #[serde(rename = "autoDeactivateUsers")]
    auto_deactivate_users: bool,
    #[serde(rename = "defaultRole")]
    default_role: String,
}

/// Get SCIM configuration
///
/// GET /api/v1/admin/scim/config
async fn get_config(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ScimConfig>, ApiError> {
    // Verify admin access
    if !is_admin(&current_user) {
        return Err(ApiError::Forbidden);
    }

    let row = sqlx::query(
        r#"
        SELECT enabled, auto_create_users, auto_deactivate_users, default_user_role, sync_group_members
        FROM scim_settings
        WHERE tenant_id = $1::uuid
        "#
    )
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let config = if let Some(row) = row.as_ref() {
        ScimConfig {
            enabled: row.get::<bool, _>("enabled"),
            base_url: format!("{}/scim/v2", state.config.base_url),
            user_schema: ScimUserSchemaConfig {
                custom_attributes: vec![],
                required_attributes: vec!["userName".to_string()],
            },
            group_schema: ScimGroupSchemaConfig {
                sync_members: row.get::<bool, _>("sync_group_members"),
            },
            mappings: ScimMappingsConfig {
                auto_create_users: row.get::<bool, _>("auto_create_users"),
                auto_deactivate_users: row.get::<bool, _>("auto_deactivate_users"),
                default_role: row.get::<String, _>("default_user_role"),
            },
        }
    } else {
        ScimConfig {
            enabled: true,
            base_url: format!("{}/scim/v2", state.config.base_url),
            user_schema: ScimUserSchemaConfig {
                custom_attributes: vec![],
                required_attributes: vec!["userName".to_string()],
            },
            group_schema: ScimGroupSchemaConfig { sync_members: true },
            mappings: ScimMappingsConfig {
                auto_create_users: true,
                auto_deactivate_users: true,
                default_role: "member".to_string(),
            },
        }
    };

    Ok(Json(config))
}

/// Update SCIM configuration
///
/// PUT /api/v1/admin/scim/config
async fn update_config(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(config): Json<ScimConfig>,
) -> Result<Json<ScimConfig>, ApiError> {
    // Verify admin access
    if !is_admin(&current_user) {
        return Err(ApiError::Forbidden);
    }

    sqlx::query(
        r#"
        INSERT INTO scim_settings (
            tenant_id, enabled, auto_create_users, auto_deactivate_users,
            default_user_role, sync_groups, sync_group_members
        )
        VALUES ($1::uuid, $2, $3, $4, $5, true, $6)
        ON CONFLICT (tenant_id) DO UPDATE
        SET enabled = EXCLUDED.enabled,
            auto_create_users = EXCLUDED.auto_create_users,
            auto_deactivate_users = EXCLUDED.auto_deactivate_users,
            default_user_role = EXCLUDED.default_user_role,
            sync_group_members = EXCLUDED.sync_group_members,
            updated_at = NOW()
        "#
    )
    .bind(&current_user.tenant_id)
    .bind(config.enabled)
    .bind(config.mappings.auto_create_users)
    .bind(config.mappings.auto_deactivate_users)
    .bind(&config.mappings.default_role)
    .bind(config.group_schema.sync_members)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(config))
}

// ============================================================================
// Statistics
// ============================================================================

/// SCIM Statistics
#[derive(Debug, Serialize)]
struct ScimStats {
    #[serde(rename = "totalUsers")]
    total_users: i64,
    #[serde(rename = "totalGroups")]
    total_groups: i64,
    #[serde(rename = "activeTokens")]
    active_tokens: i64,
    #[serde(rename = "totalRequests")]
    total_requests: i64,
    #[serde(rename = "recentErrors")]
    recent_errors: i64,
    #[serde(rename = "lastSync")]
    last_sync: Option<DateTime<Utc>>,
}

/// Get SCIM statistics
///
/// GET /api/v1/admin/scim/stats
async fn get_stats(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ScimStats>, ApiError> {
    // Verify admin access
    if !is_admin(&current_user) {
        return Err(ApiError::Forbidden);
    }

    // Get counts from database
    let total_users: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM scim_users WHERE tenant_id = $1")
            .bind(&current_user.tenant_id)
            .fetch_one(state.db.pool())
            .await
            .map_err(|_| ApiError::internal())?;

    let total_groups: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM scim_groups WHERE tenant_id = $1")
            .bind(&current_user.tenant_id)
            .fetch_one(state.db.pool())
            .await
            .map_err(|_| ApiError::internal())?;

    let active_tokens: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scim_tokens WHERE tenant_id = $1 AND status = 'active'",
    )
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let total_requests: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM scim_audit_logs WHERE tenant_id = $1")
            .bind(&current_user.tenant_id)
            .fetch_one(state.db.pool())
            .await
            .map_err(|_| ApiError::internal())?;

    let recent_errors: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM scim_audit_logs WHERE tenant_id = $1 AND success = false AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let last_sync: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MAX(created_at) FROM scim_audit_logs WHERE tenant_id = $1 AND action = 'create'",
    )
    .bind(&current_user.tenant_id)
    .fetch_one(state.db.pool())
    .await
    .ok()
    .flatten();

    Ok(Json(ScimStats {
        total_users,
        total_groups,
        active_tokens,
        total_requests,
        recent_errors,
        last_sync,
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

use axum::http::StatusCode;

fn is_admin(user: &CurrentUser) -> bool {
    user.claims
        .roles
        .as_ref()
        .map(|roles| {
            roles
                .iter()
                .any(|r| r == "admin" || r == "owner" || r == "superadmin")
        })
        .unwrap_or(false)
}

// ============================================================================
// Legacy SCIM Endpoints (from existing implementation)
// These are kept for backward compatibility but should be migrated
// to use the new SCIM module handlers
// ============================================================================

// Note: The original implementation had SCIM endpoints here.
// Those have been moved to vault-server/src/scim/handlers.rs
// for proper RFC 7644 compliance.
