//! Admin Settings Routes v2
//!
//! Comprehensive tenant settings management API.

use crate::routes::ApiError;
use crate::settings::models::*;
use crate::state::{AppState, CurrentUser};
use axum::{
    extract::{Path, Query, State},
    routing::{get, patch},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

/// Settings routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // Get all settings
        .route("/", get(get_all_settings))
        // Update entire settings (dangerous)
        .route("/", patch(update_all_settings))
        // Individual category routes
        .route("/auth", get(get_auth_settings).patch(update_auth_settings))
        .route(
            "/security",
            get(get_security_settings).patch(update_security_settings),
        )
        .route("/org", get(get_org_settings).patch(update_org_settings))
        .route(
            "/branding",
            get(get_branding_settings).patch(update_branding_settings),
        )
        .route(
            "/email",
            get(get_email_settings).patch(update_email_settings),
        )
        .route("/sms", get(get_sms_settings).patch(update_sms_settings))
        .route(
            "/oauth",
            get(get_oauth_settings).patch(update_oauth_settings),
        )
        .route(
            "/localization",
            get(get_localization_settings).patch(update_localization_settings),
        )
        .route(
            "/webhook",
            get(get_webhook_settings).patch(update_webhook_settings),
        )
        .route(
            "/privacy",
            get(get_privacy_settings).patch(update_privacy_settings),
        )
        .route(
            "/advanced",
            get(get_advanced_settings).patch(update_advanced_settings),
        )
        // Settings history
        .route("/history", get(get_settings_history))
        // Public settings (for hosted pages)
        .route("/public/:tenant_id", get(get_public_settings))
}

// ============================================
// Request/Response Types
// ============================================

#[derive(Debug, Deserialize)]
struct UpdateReason {
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    category: Option<String>,
    #[serde(default = "default_page")]
    page: i64,
    #[serde(default = "default_per_page")]
    per_page: i64,
}

fn default_page() -> i64 {
    1
}
fn default_per_page() -> i64 {
    20
}

// ============================================
// Get All Settings
// ============================================

async fn get_all_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsResponse>, ApiError> {
    let response = state
        .settings_service
        .get_settings_response_redacted(&current_user.tenant_id)
        .await?;
    Ok(Json(response))
}

// ============================================
// Authentication Settings
// ============================================

async fn get_auth_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsCategoryResponse<AuthSettings>>, ApiError> {
    let settings = state
        .settings_service
        .get_settings_redacted(&current_user.tenant_id)
        .await?;
    let row = state
        .settings_service
        .get_settings_response(&current_user.tenant_id)
        .await?;

    Ok(Json(SettingsCategoryResponse {
        tenant_id: current_user.tenant_id.clone(),
        category: "auth".to_string(),
        settings: settings.auth,
        updated_at: row.updated_at,
    }))
}

async fn update_auth_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(reason): Query<UpdateReason>,
    Json(settings): Json<AuthSettings>,
) -> Result<Json<AuthSettings>, ApiError> {
    let updated = state
        .settings_service
        .update_auth_settings(
            &current_user.tenant_id,
            settings,
            Some(&current_user.user_id),
            reason.reason.as_deref(),
        )
        .await?;

    Ok(Json(updated))
}

// ============================================
// Security Settings
// ============================================

async fn get_security_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsCategoryResponse<SecuritySettings>>, ApiError> {
    let settings = state
        .settings_service
        .get_settings_redacted(&current_user.tenant_id)
        .await?;
    let row = state
        .settings_service
        .get_settings_response(&current_user.tenant_id)
        .await?;

    Ok(Json(SettingsCategoryResponse {
        tenant_id: current_user.tenant_id.clone(),
        category: "security".to_string(),
        settings: settings.security,
        updated_at: row.updated_at,
    }))
}

async fn update_security_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(reason): Query<UpdateReason>,
    Json(settings): Json<SecuritySettings>,
) -> Result<Json<SecuritySettings>, ApiError> {
    let updated = state
        .settings_service
        .update_security_settings(
            &current_user.tenant_id,
            settings,
            Some(&current_user.user_id),
            reason.reason.as_deref(),
        )
        .await?;

    Ok(Json(updated))
}

// ============================================
// Organization Settings
// ============================================

async fn get_org_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsCategoryResponse<OrgSettings>>, ApiError> {
    let settings = state
        .settings_service
        .get_settings_redacted(&current_user.tenant_id)
        .await?;
    let row = state
        .settings_service
        .get_settings_response(&current_user.tenant_id)
        .await?;

    Ok(Json(SettingsCategoryResponse {
        tenant_id: current_user.tenant_id.clone(),
        category: "org".to_string(),
        settings: settings.org,
        updated_at: row.updated_at,
    }))
}

async fn update_org_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(reason): Query<UpdateReason>,
    Json(settings): Json<OrgSettings>,
) -> Result<Json<OrgSettings>, ApiError> {
    let updated = state
        .settings_service
        .update_org_settings(
            &current_user.tenant_id,
            settings,
            Some(&current_user.user_id),
            reason.reason.as_deref(),
        )
        .await?;

    Ok(Json(updated))
}

// ============================================
// Branding Settings
// ============================================

async fn get_branding_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsCategoryResponse<BrandingSettings>>, ApiError> {
    let settings = state
        .settings_service
        .get_settings_redacted(&current_user.tenant_id)
        .await?;
    let row = state
        .settings_service
        .get_settings_response(&current_user.tenant_id)
        .await?;

    Ok(Json(SettingsCategoryResponse {
        tenant_id: current_user.tenant_id.clone(),
        category: "branding".to_string(),
        settings: settings.branding,
        updated_at: row.updated_at,
    }))
}

async fn update_branding_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(reason): Query<UpdateReason>,
    Json(settings): Json<BrandingSettings>,
) -> Result<Json<BrandingSettings>, ApiError> {
    let updated = state
        .settings_service
        .update_branding_settings(
            &current_user.tenant_id,
            settings,
            Some(&current_user.user_id),
            reason.reason.as_deref(),
        )
        .await?;

    Ok(Json(updated))
}

// ============================================
// Email Settings
// ============================================

async fn get_email_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsCategoryResponse<EmailSettings>>, ApiError> {
    let settings = state
        .settings_service
        .get_settings_redacted(&current_user.tenant_id)
        .await?;
    let row = state
        .settings_service
        .get_settings_response(&current_user.tenant_id)
        .await?;

    Ok(Json(SettingsCategoryResponse {
        tenant_id: current_user.tenant_id.clone(),
        category: "email".to_string(),
        settings: settings.email,
        updated_at: row.updated_at,
    }))
}

async fn update_email_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(reason): Query<UpdateReason>,
    Json(settings): Json<EmailSettings>,
) -> Result<Json<EmailSettings>, ApiError> {
    let updated = state
        .settings_service
        .update_email_settings(
            &current_user.tenant_id,
            settings,
            Some(&current_user.user_id),
            reason.reason.as_deref(),
        )
        .await?;

    Ok(Json(
        crate::settings::service::SettingsService::redact_email_settings(updated),
    ))
}

// ============================================
// SMS Settings
// ============================================

async fn get_sms_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsCategoryResponse<SmsSettings>>, ApiError> {
    let settings = state
        .settings_service
        .get_settings_redacted(&current_user.tenant_id)
        .await?;
    let row = state
        .settings_service
        .get_settings_response(&current_user.tenant_id)
        .await?;

    Ok(Json(SettingsCategoryResponse {
        tenant_id: current_user.tenant_id.clone(),
        category: "sms".to_string(),
        settings: settings.sms,
        updated_at: row.updated_at,
    }))
}

async fn update_sms_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(reason): Query<UpdateReason>,
    Json(settings): Json<SmsSettings>,
) -> Result<Json<SmsSettings>, ApiError> {
    let updated = state
        .settings_service
        .update_sms_settings(
            &current_user.tenant_id,
            settings,
            Some(&current_user.user_id),
            reason.reason.as_deref(),
        )
        .await?;

    Ok(Json(
        crate::settings::service::SettingsService::redact_sms_settings(updated),
    ))
}

// ============================================
// OAuth Settings
// ============================================

async fn get_oauth_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsCategoryResponse<OAuthSettings>>, ApiError> {
    let settings = state
        .settings_service
        .get_settings_redacted(&current_user.tenant_id)
        .await?;
    let row = state
        .settings_service
        .get_settings_response(&current_user.tenant_id)
        .await?;

    Ok(Json(SettingsCategoryResponse {
        tenant_id: current_user.tenant_id.clone(),
        category: "oauth".to_string(),
        settings: settings.oauth,
        updated_at: row.updated_at,
    }))
}

async fn update_oauth_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(reason): Query<UpdateReason>,
    Json(settings): Json<OAuthSettings>,
) -> Result<Json<OAuthSettings>, ApiError> {
    let updated = state
        .settings_service
        .update_oauth_settings(
            &current_user.tenant_id,
            settings,
            Some(&current_user.user_id),
            reason.reason.as_deref(),
        )
        .await?;

    Ok(Json(updated))
}

// ============================================
// Localization Settings
// ============================================

async fn get_localization_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsCategoryResponse<LocalizationSettings>>, ApiError> {
    let settings = state
        .settings_service
        .get_settings_redacted(&current_user.tenant_id)
        .await?;
    let row = state
        .settings_service
        .get_settings_response(&current_user.tenant_id)
        .await?;

    Ok(Json(SettingsCategoryResponse {
        tenant_id: current_user.tenant_id.clone(),
        category: "localization".to_string(),
        settings: settings.localization,
        updated_at: row.updated_at,
    }))
}

async fn update_localization_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(reason): Query<UpdateReason>,
    Json(settings): Json<LocalizationSettings>,
) -> Result<Json<LocalizationSettings>, ApiError> {
    let updated = state
        .settings_service
        .update_localization_settings(
            &current_user.tenant_id,
            settings,
            Some(&current_user.user_id),
            reason.reason.as_deref(),
        )
        .await?;

    Ok(Json(updated))
}

// ============================================
// Webhook Settings
// ============================================

async fn get_webhook_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsCategoryResponse<WebhookSettings>>, ApiError> {
    let settings = state
        .settings_service
        .get_settings_redacted(&current_user.tenant_id)
        .await?;
    let row = state
        .settings_service
        .get_settings_response(&current_user.tenant_id)
        .await?;

    Ok(Json(SettingsCategoryResponse {
        tenant_id: current_user.tenant_id.clone(),
        category: "webhook".to_string(),
        settings: settings.webhook,
        updated_at: row.updated_at,
    }))
}

async fn update_webhook_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(reason): Query<UpdateReason>,
    Json(settings): Json<WebhookSettings>,
) -> Result<Json<WebhookSettings>, ApiError> {
    let updated = state
        .settings_service
        .update_webhook_settings(
            &current_user.tenant_id,
            settings,
            Some(&current_user.user_id),
            reason.reason.as_deref(),
        )
        .await?;

    Ok(Json(
        crate::settings::service::SettingsService::redact_webhook_settings(updated),
    ))
}

// ============================================
// Privacy Settings
// ============================================

async fn get_privacy_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsCategoryResponse<PrivacySettings>>, ApiError> {
    let settings = state
        .settings_service
        .get_settings_redacted(&current_user.tenant_id)
        .await?;
    let row = state
        .settings_service
        .get_settings_response(&current_user.tenant_id)
        .await?;

    Ok(Json(SettingsCategoryResponse {
        tenant_id: current_user.tenant_id.clone(),
        category: "privacy".to_string(),
        settings: settings.privacy,
        updated_at: row.updated_at,
    }))
}

async fn update_privacy_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(reason): Query<UpdateReason>,
    Json(settings): Json<PrivacySettings>,
) -> Result<Json<PrivacySettings>, ApiError> {
    let updated = state
        .settings_service
        .update_privacy_settings(
            &current_user.tenant_id,
            settings,
            Some(&current_user.user_id),
            reason.reason.as_deref(),
        )
        .await?;

    Ok(Json(updated))
}

// ============================================
// Advanced Settings
// ============================================

async fn get_advanced_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsCategoryResponse<AdvancedSettings>>, ApiError> {
    let settings = state
        .settings_service
        .get_settings_redacted(&current_user.tenant_id)
        .await?;
    let row = state
        .settings_service
        .get_settings_response(&current_user.tenant_id)
        .await?;

    Ok(Json(SettingsCategoryResponse {
        tenant_id: current_user.tenant_id.clone(),
        category: "advanced".to_string(),
        settings: settings.advanced,
        updated_at: row.updated_at,
    }))
}

async fn update_advanced_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(reason): Query<UpdateReason>,
    Json(settings): Json<AdvancedSettings>,
) -> Result<Json<AdvancedSettings>, ApiError> {
    let updated = state
        .settings_service
        .update_advanced_settings(
            &current_user.tenant_id,
            settings,
            Some(&current_user.user_id),
            reason.reason.as_deref(),
        )
        .await?;

    Ok(Json(updated))
}

// ============================================
// Update All Settings
// ============================================

#[derive(Debug, Deserialize)]
struct UpdateAllRequest {
    settings: TenantSettings,
    reason: Option<String>,
}

async fn update_all_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<UpdateAllRequest>,
) -> Result<Json<TenantSettings>, ApiError> {
    let updated = state
        .settings_service
        .update_all_settings(
            &current_user.tenant_id,
            req.settings,
            Some(&current_user.user_id),
            req.reason.as_deref(),
        )
        .await?;

    Ok(Json(
        crate::settings::service::SettingsService::redact_tenant_settings(updated),
    ))
}

// ============================================
// Settings History
// ============================================

#[derive(Debug, Serialize)]
struct HistoryResponse {
    tenant_id: String,
    changes: Vec<HistoryItem>,
    total: i64,
    page: i64,
    per_page: i64,
}

#[derive(Debug, Serialize)]
struct HistoryItem {
    id: String,
    change_type: String,
    changed_by: Option<String>,
    reason: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

async fn get_settings_history(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<HistoryResponse>, ApiError> {
    let (rows, total) = state
        .settings_service
        .get_settings_history(
            &current_user.tenant_id,
            query.category.as_deref(),
            query.page,
            query.per_page,
        )
        .await?;

    let changes: Vec<HistoryItem> = rows
        .into_iter()
        .map(|row| HistoryItem {
            id: row.id,
            change_type: row.change_type,
            changed_by: row.changed_by,
            reason: row.reason,
            created_at: row.created_at,
        })
        .collect();

    Ok(Json(HistoryResponse {
        tenant_id: current_user.tenant_id,
        changes,
        total,
        page: query.page,
        per_page: query.per_page,
    }))
}

// ============================================
// Public Settings (for hosted pages)
// ============================================

/// Public settings that can be exposed without authentication
/// (for customizing hosted login pages, etc.)
#[derive(Debug, Serialize)]
struct PublicSettings {
    tenant_id: String,
    branding: BrandingSettings,
    auth: PublicAuthSettings,
    localization: LocalizationSettings,
}

#[derive(Debug, Serialize)]
struct PublicAuthSettings {
    allowed_auth_methods: Vec<AuthMethod>,
    default_auth_method: AuthMethod,
    allow_registration: bool,
    require_email_verification: bool,
}

async fn get_public_settings(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
) -> Result<Json<PublicSettings>, ApiError> {
    let settings = state.settings_service.get_settings(&tenant_id).await?;

    let public_settings = PublicSettings {
        tenant_id: tenant_id.clone(),
        branding: settings.branding,
        auth: PublicAuthSettings {
            allowed_auth_methods: settings.auth.allowed_auth_methods,
            default_auth_method: settings.auth.default_auth_method,
            allow_registration: settings.auth.allow_registration,
            require_email_verification: settings.auth.require_email_verification,
        },
        localization: settings.localization,
    };

    Ok(Json(public_settings))
}
