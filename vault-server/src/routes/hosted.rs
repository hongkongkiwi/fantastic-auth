//! Hosted UI Routes
//!
//! Provides API endpoints for hosted UI configuration and operations.
//! These endpoints are used by the hosted authentication pages.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info, warn};

use vault_core::hosted::{HostedUiConfig, OAuthProvider, ValidateRedirectResponse};

use crate::{
    routes::ApiError,
    state::AppState,
};

/// Query parameters for getting hosted config
#[derive(Debug, Deserialize)]
pub struct GetConfigQuery {
    pub tenant_id: String,
}

/// Response for hosted config endpoint
#[derive(Debug, Serialize)]
pub struct HostedConfigResponse {
    pub tenant_id: String,
    pub company_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favicon_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_in_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_up_title: Option<String>,
    pub oauth_providers: Vec<String>,
    pub show_magic_link: bool,
    pub show_web_authn: bool,
    pub require_email_verification: bool,
    pub allow_sign_up: bool,
    pub after_sign_in_url: String,
    pub after_sign_up_url: String,
    pub after_sign_out_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_css: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_js: Option<String>,
    pub allowed_redirect_urls: Vec<String>,
}

impl From<HostedUiConfig> for HostedConfigResponse {
    fn from(config: HostedUiConfig) -> Self {
        Self {
            tenant_id: config.tenant_id,
            company_name: config.company_name,
            logo_url: config.logo_url,
            favicon_url: config.favicon_url,
            primary_color: config.primary_color,
            background_color: config.background_color,
            sign_in_title: config.sign_in_title,
            sign_up_title: config.sign_up_title,
            oauth_providers: config
                .oauth_providers
                .into_iter()
                .map(|p| p.to_string())
                .collect(),
            show_magic_link: config.show_magic_link,
            show_web_authn: config.show_web_authn,
            require_email_verification: config.require_email_verification,
            allow_sign_up: config.allow_sign_up,
            after_sign_in_url: config.after_sign_in_url,
            after_sign_up_url: config.after_sign_up_url,
            after_sign_out_url: config.after_sign_out_url,
            terms_url: config.terms_url,
            privacy_url: config.privacy_url,
            custom_css: config.custom_css,
            custom_js: config.custom_js,
            allowed_redirect_urls: config.allowed_redirect_urls,
        }
    }
}

/// Request to validate a redirect URL
#[derive(Debug, Deserialize)]
pub struct ValidateRedirectQuery {
    pub tenant_id: String,
    pub url: String,
}

/// Request to update hosted config (admin only)
#[derive(Debug, Deserialize)]
pub struct UpdateHostedConfigRequest {
    #[serde(flatten)]
    pub config: HostedUiConfig,
}

/// Get hosted UI configuration for a tenant
async fn get_hosted_config(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GetConfigQuery>,
) -> Result<Json<HostedConfigResponse>, ApiError> {
    debug!("Fetching hosted config for tenant: {}", query.tenant_id);

    // TODO: Fetch from database in production
    // For now, return a default config
    let config = HostedUiConfig::new(
        query.tenant_id.clone(),
        "Vault".to_string(), // Would be fetched from tenant settings
    );

    info!("Retrieved hosted config for tenant: {}", query.tenant_id);
    Ok(Json(config.into()))
}

/// Validate a redirect URL
async fn validate_redirect(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ValidateRedirectQuery>,
) -> Result<Json<ValidateRedirectResponse>, ApiError> {
    debug!(
        "Validating redirect URL for tenant {}: {}",
        query.tenant_id, query.url
    );

    // TODO: Fetch config from database
    let config = HostedUiConfig::new(query.tenant_id.clone(), "Vault".to_string());

    let valid = config.validate_redirect_url(&query.url);

    let response = ValidateRedirectResponse {
        valid,
        sanitized_url: if valid { Some(query.url) } else { None },
    };

    Ok(Json(response))
}

/// Update hosted UI configuration (requires admin access)
async fn update_hosted_config(
    State(state): State<Arc<AppState>>,
    Json(request): Json<UpdateHostedConfigRequest>,
) -> Result<Json<HostedConfigResponse>, ApiError> {
    info!(
        "Updating hosted config for tenant: {}",
        request.config.tenant_id
    );

    // TODO: Validate admin permissions
    // TODO: Save to database

    warn!("Hosted config update not yet implemented - returning requested config");

    Ok(Json(request.config.into()))
}

/// Request for hosted sign-in
#[derive(Debug, Deserialize)]
pub struct HostedSignInRequest {
    pub email: String,
    pub password: String,
    pub tenant_id: String,
}

/// Response for hosted sign-in
#[derive(Debug, Serialize)]
pub struct HostedSignInResponse {
    pub session_token: String,
    pub user: UserInfo,
    pub redirect_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_mfa: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_token: Option<String>,
}

/// User information
#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Hosted sign-in endpoint
async fn hosted_sign_in(
    State(state): State<Arc<AppState>>,
    Json(request): Json<HostedSignInRequest>,
) -> Result<Json<HostedSignInResponse>, ApiError> {
    debug!("Hosted sign-in attempt for tenant: {}", request.tenant_id);

    // TODO: Implement actual authentication
    // This would:
    // 1. Validate credentials against the tenant's user database
    // 2. Check MFA requirements
    // 3. Generate session token
    // 4. Return appropriate response

    Err(ApiError::NotImplemented)
}

/// Request for hosted sign-up
#[derive(Debug, Deserialize)]
pub struct HostedSignUpRequest {
    pub email: String,
    pub password: String,
    pub name: String,
    pub tenant_id: String,
}

/// Response for hosted sign-up
#[derive(Debug, Serialize)]
pub struct HostedSignUpResponse {
    pub session_token: String,
    pub user: UserInfo,
    pub redirect_url: String,
    pub requires_email_verification: bool,
}

/// Hosted sign-up endpoint
async fn hosted_sign_up(
    State(state): State<Arc<AppState>>,
    Json(request): Json<HostedSignUpRequest>,
) -> Result<Json<HostedSignUpResponse>, ApiError> {
    debug!("Hosted sign-up attempt for tenant: {}", request.tenant_id);

    // TODO: Implement actual registration
    // This would:
    // 1. Check if sign-ups are allowed for the tenant
    // 2. Validate email uniqueness
    // 3. Hash password and create user
    // 4. Send verification email if required
    // 5. Return session or pending status

    Err(ApiError::NotImplemented)
}

/// Request to start OAuth flow
#[derive(Debug, Deserialize)]
pub struct HostedOAuthStartRequest {
    pub provider: String,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

/// Response for OAuth start
#[derive(Debug, Serialize)]
pub struct HostedOAuthStartResponse {
    pub auth_url: String,
    pub state: String,
}

/// Start OAuth flow for hosted UI
async fn hosted_oauth_start(
    State(state): State<Arc<AppState>>,
    Json(request): Json<HostedOAuthStartRequest>,
) -> Result<Json<HostedOAuthStartResponse>, ApiError> {
    debug!(
        "Starting OAuth flow for tenant {} with provider {}",
        request.tenant_id, request.provider
    );

    // TODO: Implement OAuth flow initiation
    // This would:
    // 1. Validate the provider is enabled for the tenant
    // 2. Generate state parameter for CSRF protection
    // 3. Build the OAuth authorization URL
    // 4. Return the URL for redirect

    Err(ApiError::NotImplemented)
}

/// Request for OAuth callback
#[derive(Debug, Deserialize)]
pub struct HostedOAuthCallbackRequest {
    pub code: String,
    pub state: String,
    pub tenant_id: String,
}

/// Handle OAuth callback for hosted UI
async fn hosted_oauth_callback(
    State(state): State<Arc<AppState>>,
    Json(request): Json<HostedOAuthCallbackRequest>,
) -> Result<Json<HostedSignInResponse>, ApiError> {
    debug!(
        "Handling OAuth callback for tenant: {}",
        request.tenant_id
    );

    // TODO: Implement OAuth callback handling
    // This would:
    // 1. Validate state parameter
    // 2. Exchange code for tokens with the provider
    // 3. Get user info from provider
    // 4. Link or create user account
    // 5. Generate session token

    Err(ApiError::NotImplemented)
}

/// Request for password reset
#[derive(Debug, Deserialize)]
pub struct HostedPasswordResetRequest {
    pub email: String,
    pub tenant_id: String,
}

/// Response for password reset request
#[derive(Debug, Serialize)]
pub struct HostedPasswordResetResponse {
    pub success: bool,
    pub message: String,
}

/// Request password reset for hosted UI
async fn hosted_request_password_reset(
    State(state): State<Arc<AppState>>,
    Json(request): Json<HostedPasswordResetRequest>,
) -> Result<Json<HostedPasswordResetResponse>, ApiError> {
    debug!(
        "Password reset request for tenant {}: {}",
        request.tenant_id, request.email
    );

    // TODO: Implement password reset
    // This would:
    // 1. Find user by email (if exists)
    // 2. Generate reset token
    // 3. Send reset email
    // 4. Return success (even if user not found for security)

    // Always return success to prevent email enumeration
    Ok(Json(HostedPasswordResetResponse {
        success: true,
        message: "If an account exists, a reset email has been sent".to_string(),
    }))
}

/// Create the hosted routes router
pub fn hosted_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Config endpoints
        .route("/config", get(get_hosted_config))
        .route("/config", post(update_hosted_config))
        .route("/validate-redirect", get(validate_redirect))
        // Auth endpoints
        .route("/auth/signin", post(hosted_sign_in))
        .route("/auth/signup", post(hosted_sign_up))
        .route("/auth/oauth/start", post(hosted_oauth_start))
        .route("/auth/oauth/callback", post(hosted_oauth_callback))
        .route("/auth/password-reset", post(hosted_request_password_reset))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hosted_config_response_from_config() {
        let config = HostedUiConfig::new("tenant-123".to_string(), "Acme".to_string());
        let response: HostedConfigResponse = config.into();

        assert_eq!(response.tenant_id, "tenant-123");
        assert_eq!(response.company_name, "Acme");
        assert!(response.show_magic_link);
    }
}
