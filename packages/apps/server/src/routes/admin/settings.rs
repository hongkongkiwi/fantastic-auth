//! Admin Settings Routes (Legacy)
//!
//! ⚠️ DEPRECATED: Use `/api/v1/admin/settings/v2/` endpoints instead.
//! This module is kept for backward compatibility and will be removed in a future version.
//!
//! Manage tenant-wide settings and configuration.

use axum::{
    extract::State,
    routing::{get, patch},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::db::set_connection_context;

/// Settings routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/settings",
            get(get_tenant_settings).patch(update_tenant_settings),
        )
        .route("/settings/mfa", patch(update_mfa_settings))
}

#[derive(Debug, Serialize)]
struct TenantSettingsResponse {
    id: String,
    name: String,
    slug: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    settings: TenantSettings,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct TenantSettings {
    /// Authentication settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthSettings>,
    /// Session settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionSettings>,
    /// MFA settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa: Option<MfaSettings>,
    /// OAuth settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth: Option<serde_json::Value>,
    /// Email settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<EmailSettings>,
    /// Custom settings JSON
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct AuthSettings {
    #[serde(rename = "requireEmailVerification")]
    pub require_email_verification: bool,
    #[serde(rename = "allowRegistration")]
    pub allow_registration: bool,
    #[serde(rename = "passwordMinLength")]
    pub password_min_length: i32,
    #[serde(rename = "passwordRequireUppercase")]
    pub password_require_uppercase: bool,
    #[serde(rename = "passwordRequireLowercase")]
    pub password_require_lowercase: bool,
    #[serde(rename = "passwordRequireNumbers")]
    pub password_require_numbers: bool,
    #[serde(rename = "passwordRequireSpecial")]
    pub password_require_special: bool,
    #[serde(rename = "maxLoginAttempts")]
    pub max_login_attempts: i32,
    #[serde(rename = "lockoutDurationMinutes")]
    pub lockout_duration_minutes: i32,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct SessionSettings {
    #[serde(rename = "accessTokenLifetime")]
    pub access_token_lifetime: i32,
    #[serde(rename = "refreshTokenLifetime")]
    pub refresh_token_lifetime: i32,
    #[serde(rename = "idleTimeoutMinutes")]
    pub idle_timeout_minutes: i32,
    #[serde(rename = "absoluteTimeoutHours")]
    pub absolute_timeout_hours: i32,
    #[serde(rename = "allowConcurrentSessions")]
    pub allow_concurrent_sessions: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct MfaSettings {
    #[serde(rename = "requireMfa")]
    pub require_mfa: bool,
    #[serde(rename = "allowedMethods")]
    pub allowed_methods: Vec<String>,
    #[serde(rename = "gracePeriodDays")]
    pub grace_period_days: i32,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct EmailSettings {
    #[serde(rename = "fromAddress")]
    pub from_address: Option<String>,
    #[serde(rename = "fromName")]
    pub from_name: Option<String>,
    #[serde(rename = "welcomeEmailEnabled")]
    pub welcome_email_enabled: bool,
    #[serde(rename = "verificationEmailEnabled")]
    pub verification_email_enabled: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateSettingsRequest {
    name: Option<String>,
    settings: Option<TenantSettings>,
}

#[derive(Debug, Deserialize)]
struct UpdateMfaSettingsRequest {
    required: Option<bool>,
    #[serde(rename = "allowedMethods")]
    allowed_methods: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct MfaSettingsResponse {
    required: bool,
    #[serde(rename = "allowedMethods")]
    allowed_methods: Vec<String>,
}

/// Get tenant settings
async fn get_tenant_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<TenantSettingsResponse>, ApiError> {
    // For now, return default settings since tenant settings table may not exist
    // In a full implementation, this would fetch from a tenant_settings table
    let mut conn = state.db.acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let tenant_info =
        sqlx::query("SELECT id, name, slug, created_at, updated_at FROM tenants WHERE id = $1")
            .bind(&current_user.tenant_id)
            .fetch_one(&mut *conn)
            .await;

    let (id, name, slug, created_at, updated_at) = match tenant_info {
        Ok(row) => {
            let created: chrono::DateTime<chrono::Utc> = row
                .try_get("created_at")
                .unwrap_or_else(|_| chrono::Utc::now());
            let updated: chrono::DateTime<chrono::Utc> = row
                .try_get("updated_at")
                .unwrap_or_else(|_| chrono::Utc::now());
            (
                row.try_get("id").unwrap_or_default(),
                row.try_get("name").unwrap_or_else(|_| "Tenant".to_string()),
                row.try_get("slug")
                    .unwrap_or_else(|_| "default".to_string()),
                created,
                updated,
            )
        }
        Err(_) => {
            // Fallback if tenant table doesn't have expected columns
            (
                current_user.tenant_id.clone(),
                "Tenant".to_string(),
                "default".to_string(),
                chrono::Utc::now(),
                chrono::Utc::now(),
            )
        }
    };

    // Build default settings
    let settings = TenantSettings {
        auth: Some(AuthSettings {
            require_email_verification: true,
            allow_registration: true,
            password_min_length: 12,
            password_require_uppercase: true,
            password_require_lowercase: true,
            password_require_numbers: true,
            password_require_special: false,
            max_login_attempts: 5,
            lockout_duration_minutes: 30,
        }),
        session: Some(SessionSettings {
            access_token_lifetime: 900,     // 15 minutes
            refresh_token_lifetime: 604800, // 7 days
            idle_timeout_minutes: 30,
            absolute_timeout_hours: 24,
            allow_concurrent_sessions: true,
        }),
        mfa: Some(MfaSettings {
            require_mfa: false,
            allowed_methods: vec![
                "totp".to_string(),
                "email".to_string(),
                "sms".to_string(),
                "webauthn".to_string(),
            ],
            grace_period_days: 7,
        }),
        oauth: Some(serde_json::json!({
            "enabled": false,
            "providers": []
        })),
        email: Some(EmailSettings {
            from_address: Some("noreply@example.com".to_string()),
            from_name: Some("Vault".to_string()),
            welcome_email_enabled: true,
            verification_email_enabled: true,
        }),
        custom: Some(serde_json::json!({})),
    };

    Ok(Json(TenantSettingsResponse {
        id,
        name,
        slug,
        created_at: created_at.to_rfc3339(),
        updated_at: updated_at.to_rfc3339(),
        settings,
    }))
}

/// Update tenant settings
async fn update_tenant_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<Json<TenantSettingsResponse>, ApiError> {
    // Update tenant name if provided
    if let Some(name) = req.name {
        let mut conn = state.db.acquire().await.map_err(|_| ApiError::Internal)?;
        set_connection_context(&mut conn, &current_user.tenant_id)
            .await
            .map_err(|_| ApiError::Internal)?;
        let _ = sqlx::query("UPDATE tenants SET name = $1, updated_at = NOW() WHERE id = $2")
            .bind(&name)
            .bind(&current_user.tenant_id)
            .execute(&mut *conn)
            .await;
    }

    // In a full implementation, settings would be saved to a tenant_settings table
    // For now, we just return the current settings
    get_tenant_settings(State(state), Extension(current_user)).await
}

/// Update MFA enforcement settings
async fn update_mfa_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<UpdateMfaSettingsRequest>,
) -> Result<Json<MfaSettingsResponse>, ApiError> {
    Ok(Json(MfaSettingsResponse {
        required: req.required.unwrap_or(false),
        allowed_methods: req.allowed_methods.unwrap_or_else(|| {
            vec![
                "totp".to_string(),
                "webauthn".to_string(),
                "backup_codes".to_string(),
            ]
        }),
    }))
}
