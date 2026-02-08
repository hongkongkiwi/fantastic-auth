//! Hosted UI Routes
//!
//! Provides API endpoints for hosted UI configuration and operations.
//! These endpoints are used by the hosted authentication pages.

use axum::{
    extract::{ConnectInfo, Query, Request, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Extension, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info};

use vault_core::hosted::{HostedUiConfig, OAuthProvider, ValidateRedirectResponse};
use vault_core::auth::{LoginCredentials, oauth as oauth_core};
use vault_core::models::user::UserStatus;

use crate::{
    middleware::auth::auth_middleware,
    routes::ApiError,
    state::AppState,
};
use crate::settings::models::AuthMethod;

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

    let config = build_hosted_config(state.as_ref(), &query.tenant_id).await?;

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

    let config = build_hosted_config(state.as_ref(), &query.tenant_id).await?;

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
    Extension(current_user): Extension<crate::state::CurrentUser>,
    Json(request): Json<UpdateHostedConfigRequest>,
) -> Result<Json<HostedConfigResponse>, ApiError> {
    info!(
        "Updating hosted config for tenant: {}",
        request.config.tenant_id
    );

    if request.config.custom_js.is_some() {
        return Err(ApiError::BadRequest(
            "custom_js is disabled for hosted config updates".to_string(),
        ));
    }

    let tenant_id = request.config.tenant_id.clone();
    let mut settings = state.settings_service.get_settings(&tenant_id).await?;

    // Branding updates
    if let Some(company_name) = Some(request.config.company_name.clone()) {
        settings.branding.brand_name = company_name;
    }
    settings.branding.brand_logo_url = request.config.logo_url.clone();
    settings.branding.brand_favicon_url = request.config.favicon_url.clone();
    if let Some(primary_color) = request.config.primary_color.clone() {
        settings.branding.primary_color = primary_color;
    }
    settings.branding.custom_css = request.config.custom_css.clone();
    settings.branding.terms_of_service_url = request.config.terms_url.clone();
    settings.branding.privacy_policy_url = request.config.privacy_url.clone();

    // Auth updates
    settings.auth.allow_registration = request.config.allow_sign_up;
    settings.auth.require_email_verification = request.config.require_email_verification;
    settings.auth.allow_passwordless = request.config.show_magic_link;

    let mut allowed_methods = settings.auth.allowed_auth_methods.clone();
    allowed_methods.retain(|method| match method {
        AuthMethod::MagicLink => request.config.show_magic_link,
        AuthMethod::WebAuthn => request.config.show_web_authn,
        _ => true,
    });

    if request.config.show_magic_link && !allowed_methods.contains(&AuthMethod::MagicLink) {
        allowed_methods.push(AuthMethod::MagicLink);
    }
    if request.config.show_web_authn && !allowed_methods.contains(&AuthMethod::WebAuthn) {
        allowed_methods.push(AuthMethod::WebAuthn);
    }
    if !request.config.oauth_providers.is_empty()
        && !allowed_methods.contains(&AuthMethod::OAuth)
    {
        allowed_methods.push(AuthMethod::OAuth);
    }

    settings.auth.allowed_auth_methods = allowed_methods;

    // Redirect allowlist
    settings.advanced.allowed_callback_urls = request.config.allowed_redirect_urls.clone();
    settings.advanced.allowed_logout_urls = request.config.allowed_redirect_urls.clone();

    // Persist updates
    state
        .settings_service
        .update_branding_settings(&tenant_id, settings.branding.clone(), Some(&current_user.user_id), Some("hosted_config_update"))
        .await?;
    state
        .settings_service
        .update_auth_settings(&tenant_id, settings.auth.clone(), Some(&current_user.user_id), Some("hosted_config_update"))
        .await?;
    state
        .settings_service
        .update_advanced_settings(&tenant_id, settings.advanced.clone(), Some(&current_user.user_id), Some("hosted_config_update"))
        .await?;

    let config = build_hosted_config(state.as_ref(), &tenant_id).await?;

    Ok(Json(config.into()))
}

/// Request for hosted sign-in
#[derive(Debug, Deserialize)]
pub struct HostedSignInRequest {
    pub email: String,
    pub password: String,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
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
    let config = build_hosted_config(state.as_ref(), &request.tenant_id).await?;
    let redirect_url = resolve_hosted_redirect(&config, request.redirect_url.as_deref())?;

    let credentials = LoginCredentials {
        email: request.email.clone(),
        password: request.password,
        mfa_code: request.mfa_code,
    };

    let auth_result = state
        .auth_service
        .authenticate(&request.tenant_id, credentials, None, None)
        .await
        .map_err(|_| ApiError::Unauthorized)?;

    Ok(Json(HostedSignInResponse {
        session_token: if auth_result.mfa_required {
            String::new()
        } else {
            auth_result.access_token
        },
        user: UserInfo {
            id: auth_result.user.id,
            email: auth_result.user.email,
            name: auth_result.user.profile.name,
        },
        redirect_url,
        requires_mfa: Some(auth_result.mfa_required),
        mfa_token: None,
    }))
}

/// Request for hosted sign-up
#[derive(Debug, Deserialize)]
pub struct HostedSignUpRequest {
    pub email: String,
    pub password: String,
    pub name: String,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
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
    let config = build_hosted_config(state.as_ref(), &request.tenant_id).await?;
    if !config.allow_sign_up {
        return Err(ApiError::Forbidden);
    }
    let redirect_url = resolve_hosted_redirect(&config, request.redirect_url.as_deref())?;

    let (user, _verify_token) = state
        .auth_service
        .register(
            &request.tenant_id,
            request.email.clone(),
            request.password.clone(),
            Some(request.name.clone()),
        )
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    if config.require_email_verification && !user.email_verified {
        return Ok(Json(HostedSignUpResponse {
            session_token: String::new(),
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.profile.name,
            },
            redirect_url,
            requires_email_verification: true,
        }));
    }

    let auth_result = state
        .auth_service
        .authenticate(
            &request.tenant_id,
            LoginCredentials {
                email: request.email,
                password: request.password,
                mfa_code: None,
            },
            None,
            None,
        )
        .await
        .map_err(|_| ApiError::Unauthorized)?;

    Ok(Json(HostedSignUpResponse {
        session_token: auth_result.access_token,
        user: UserInfo {
            id: auth_result.user.id,
            email: auth_result.user.email,
            name: auth_result.user.profile.name,
        },
        redirect_url,
        requires_email_verification: false,
    }))
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

    let config = build_hosted_config(state.as_ref(), &request.tenant_id).await?;
    let provider_enum = parse_hosted_provider(&request.provider)?;
    if !config.oauth_providers.contains(&provider_enum) {
        return Err(ApiError::Forbidden);
    }

    let redirect_url = if let Some(ref url) = request.redirect_url {
        if !config.validate_redirect_url(url) {
            return Err(ApiError::BadRequest("Invalid redirect URL".to_string()));
        }
        Some(url.clone())
    } else {
        None
    };

    let (oauth_config, _provider) = get_oauth_config(state.as_ref(), &request.provider)?;
    let state_param = oauth_core::generate_state();
    let code_verifier = if oauth_config.pkce_enabled {
        Some(oauth_core::generate_code_verifier())
    } else {
        None
    };

    store_hosted_oauth_state(
        state.as_ref(),
        &state_param,
        HostedOAuthState {
            tenant_id: request.tenant_id.clone(),
            provider: request.provider.clone(),
            code_verifier: code_verifier.clone(),
            redirect_url,
        },
    )
    .await?;

    let oauth_service = oauth_core::OAuthService::new(oauth_config);
    let auth_url = oauth_service.get_authorization_url(oauth_core::AuthUrlRequest {
        state: state_param.clone(),
        code_verifier,
        scopes: vec![],
    });

    Ok(Json(HostedOAuthStartResponse {
        auth_url,
        state: state_param,
    }))
}

/// Request for OAuth callback
#[derive(Debug, Deserialize)]
pub struct HostedOAuthCallbackRequest {
    pub code: String,
    pub state: String,
    pub tenant_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
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

    let stored = verify_hosted_oauth_state(state.as_ref(), &request.state).await?;
    if stored.tenant_id != request.tenant_id {
        return Err(ApiError::BadRequest("OAuth tenant mismatch".to_string()));
    }

    let config = build_hosted_config(state.as_ref(), &stored.tenant_id).await?;
    let redirect_url = resolve_hosted_redirect(
        &config,
        request
            .redirect_url
            .as_deref()
            .or(stored.redirect_url.as_deref()),
    )?;

    let (oauth_config, provider_enum) = get_oauth_config(state.as_ref(), &stored.provider)?;
    let oauth_service = oauth_core::OAuthService::new(oauth_config);

    let token_response = oauth_service
        .exchange_code(&request.code, stored.code_verifier.as_deref())
        .await
        .map_err(|_| ApiError::Internal)?;

    let user_info = oauth_service
        .get_user_info(&token_response.access_token)
        .await
        .map_err(|_| ApiError::Internal)?;

    let email = user_info
        .email
        .clone()
        .ok_or_else(|| ApiError::BadRequest("Email not provided by OAuth provider".to_string()))?;

    let user = match state.db.users().find_by_email(&stored.tenant_id, &email).await {
        Ok(Some(existing)) => existing,
        Ok(None) => {
            if !state.config.features.enable_oauth_signup {
                return Err(ApiError::Forbidden);
            }
            let profile = serde_json::json!({
                "name": user_info.name,
                "given_name": user_info.given_name,
                "family_name": user_info.family_name,
                "picture": user_info.picture,
                "oauth_provider": provider_enum.name(),
                "oauth_id": user_info.id,
            });
            let req = vault_core::db::users::CreateUserRequest {
                tenant_id: stored.tenant_id.clone(),
                email: email.clone(),
                password_hash: None,
                email_verified: user_info.email_verified,
                profile: Some(profile),
                metadata: None,
            };
            state.db.users().create(req).await.map_err(|_| ApiError::Internal)?
        }
        Err(_) => return Err(ApiError::Internal),
    };

    if user.status != UserStatus::Active || user.is_locked() {
        return Err(ApiError::Forbidden);
    }

    match state
        .check_session_limits(&stored.tenant_id, &user.id, None)
        .await
        .map_err(|_| ApiError::Internal)?
    {
        Ok(()) => {}
        Err(limit_err) => return Err(ApiError::SessionLimitReached(limit_err)),
    }

    let session = state
        .auth_service
        .create_session_for_oauth_user(&user, None, None)
        .await
        .map_err(|_| ApiError::Internal)?;

    let session_req = vault_core::db::sessions::CreateSessionRequest {
        tenant_id: stored.tenant_id.clone(),
        user_id: user.id.clone(),
        access_token_jti: session.access_token_jti.clone(),
        refresh_token_hash: session.refresh_token_hash.clone(),
        token_family: session.token_family.clone(),
        ip_address: None,
        user_agent: None,
        device_fingerprint: None,
        device_info: serde_json::json!({
            "oauth_provider": provider_enum.name(),
            "hosted": true
        }),
        location: None,
        mfa_verified: false,
        expires_at: session.expires_at,
        bind_to_ip: state.config.security.session_binding.bind_to_ip,
        bind_to_device: state.config.security.session_binding.bind_to_device,
    };
    state.db.sessions().create(session_req).await.map_err(|_| ApiError::Internal)?;

    let token_pair = state
        .auth_service
        .generate_tokens(&user, &session.id)
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(HostedSignInResponse {
        session_token: token_pair.access_token,
        user: UserInfo {
            id: user.id,
            email: user.email,
            name: user.profile.name,
        },
        redirect_url,
        requires_mfa: Some(false),
        mfa_token: None,
    }))
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

    let _ = state
        .auth_service
        .request_password_reset(&request.tenant_id, &request.email)
        .await;

    // Always return success to prevent email enumeration
    Ok(Json(HostedPasswordResetResponse {
        success: true,
        message: "If an account exists, a reset email has been sent".to_string(),
    }))
}

#[derive(Debug, Serialize, Deserialize)]
struct HostedOAuthState {
    tenant_id: String,
    provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_verifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_url: Option<String>,
}

fn parse_hosted_provider(provider: &str) -> Result<OAuthProvider, ApiError> {
    match provider.to_lowercase().as_str() {
        "google" => Ok(OAuthProvider::Google),
        "github" => Ok(OAuthProvider::Github),
        "apple" => Ok(OAuthProvider::Apple),
        "microsoft" => Ok(OAuthProvider::Microsoft),
        _ => Err(ApiError::BadRequest(format!(
            "Unsupported OAuth provider: {}",
            provider
        ))),
    }
}

fn get_oauth_config(
    state: &AppState,
    provider: &str,
) -> Result<(oauth_core::OAuthConfig, oauth_core::OAuthProvider), ApiError> {
    let provider_lower = provider.to_lowercase();
    let provider_config = match provider_lower.as_str() {
        "google" => state.config.oauth.google.clone(),
        "github" => state.config.oauth.github.clone(),
        "microsoft" => state.config.oauth.microsoft.clone(),
        "apple" => state.config.oauth.apple.clone(),
        _ => {
            return Err(ApiError::BadRequest(format!(
                "Unsupported OAuth provider: {}",
                provider
            )))
        }
    };
    let config = provider_config.ok_or(ApiError::Internal)?;
    let provider_enum = match provider_lower.as_str() {
        "google" => oauth_core::OAuthProvider::Google,
        "github" => oauth_core::OAuthProvider::GitHub,
        "microsoft" => oauth_core::OAuthProvider::Microsoft,
        "apple" => oauth_core::OAuthProvider::Apple,
        _ => {
            return Err(ApiError::BadRequest(format!(
                "Unsupported OAuth provider: {}",
                provider
            )))
        }
    };
    let apple_credentials = if provider_enum == oauth_core::OAuthProvider::Apple {
        config
            .apple_config
            .map(|apple| oauth_core::AppleOAuthCredentials {
                client_id: config.client_id.clone(),
                team_id: apple.team_id,
                key_id: apple.key_id,
                private_key: apple.private_key,
                redirect_uri: config.redirect_uri.clone(),
            })
    } else {
        None
    };
    let oauth_config = oauth_core::OAuthConfig {
        provider: provider_enum.clone(),
        client_id: config.client_id,
        client_secret: config.client_secret,
        redirect_uri: config.redirect_uri,
        scopes: vec![],
        pkce_enabled: true,
        apple_credentials,
        extra_config: None,
    };
    Ok((oauth_config, provider_enum))
}

async fn store_hosted_oauth_state(
    state: &AppState,
    state_param: &str,
    data: HostedOAuthState,
) -> Result<(), ApiError> {
    let Some(redis) = state.redis.clone() else {
        return Err(ApiError::Internal);
    };
    let value = serde_json::to_string(&data).map_err(|_| ApiError::Internal)?;
    let mut conn = redis;
    let key = format!("hosted:oauth:state:{}", state_param);
    let result: Result<(), _> = redis::cmd("SETEX")
        .arg(&key)
        .arg(600)
        .arg(value)
        .query_async(&mut conn)
        .await;
    result.map_err(|_| ApiError::Internal)
}

async fn verify_hosted_oauth_state(state: &AppState, state_param: &str) -> Result<HostedOAuthState, ApiError> {
    let Some(redis) = state.redis.clone() else {
        return Err(ApiError::BadRequest("OAuth state expired".to_string()));
    };
    let mut conn = redis;
    let key = format!("hosted:oauth:state:{}", state_param);
    let value: Option<String> = redis::cmd("GET")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .map_err(|_| ApiError::BadRequest("Invalid OAuth state".to_string()))?;
    if value.is_none() {
        return Err(ApiError::BadRequest("Invalid OAuth state".to_string()));
    }
    let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut conn).await;
    serde_json::from_str(value.as_deref().unwrap_or_default())
        .map_err(|_| ApiError::BadRequest("Invalid OAuth state".to_string()))
}

fn resolve_hosted_redirect(config: &HostedUiConfig, requested: Option<&str>) -> Result<String, ApiError> {
    if let Some(url) = requested {
        if !config.validate_redirect_url(url) {
            return Err(ApiError::BadRequest("Invalid redirect URL".to_string()));
        }
        return Ok(url.to_string());
    }
    Ok(config.after_sign_in_url.clone())
}

/// Create the hosted routes router
pub fn hosted_routes() -> Router<Arc<AppState>> {
    let admin_routes = Router::new()
        .route("/config", post(update_hosted_config))
        .layer(middleware::from_fn(crate::middleware::admin_roles::admin_role_middleware))
        .layer(middleware::from_fn(hosted_admin_auth_middleware));

    Router::new()
        // Config endpoints
        .route("/config", get(get_hosted_config))
        .merge(admin_routes)
        .route("/validate-redirect", get(validate_redirect))
        // Auth endpoints
        .route("/auth/signin", post(hosted_sign_in))
        .route("/auth/signup", post(hosted_sign_up))
        .route("/auth/oauth/start", post(hosted_oauth_start))
        .route("/auth/oauth/callback", post(hosted_oauth_callback))
        .route("/auth/password-reset", post(hosted_request_password_reset))
}

async fn hosted_admin_auth_middleware(mut request: Request, next: middleware::Next) -> Response {
    let state = match request.extensions().get::<AppState>().cloned() {
        Some(state) => state,
        None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

    match auth_middleware(State(state), ConnectInfo(addr), request, next).await {
        Ok(response) => response,
        Err(status) => status.into_response(),
    }
}

async fn build_hosted_config(
    state: &AppState,
    tenant_id: &str,
) -> Result<HostedUiConfig, ApiError> {
    let settings = state.settings_service.get_settings(tenant_id).await?;

    let oauth_providers: Vec<OAuthProvider> = if settings.oauth.allow_social_logins {
        settings
            .oauth
            .oauth_providers
            .iter()
            .filter(|p| p.enabled)
            .filter_map(|p| match p.provider_id.as_str() {
                "google" => Some(OAuthProvider::Google),
                "github" => Some(OAuthProvider::Github),
                "apple" => Some(OAuthProvider::Apple),
                "microsoft" => Some(OAuthProvider::Microsoft),
                "slack" => Some(OAuthProvider::Slack),
                "discord" => Some(OAuthProvider::Discord),
                _ => None,
            })
            .collect()
    } else {
        Vec::new()
    };

    let show_magic_link = settings.auth.allowed_auth_methods.contains(&AuthMethod::MagicLink)
        && settings.auth.allow_passwordless;
    let show_web_authn = settings.auth.allowed_auth_methods.contains(&AuthMethod::WebAuthn);

    let mut allowed_redirect_urls = settings.advanced.allowed_callback_urls.clone();
    allowed_redirect_urls.extend(settings.advanced.allowed_logout_urls.clone());
    allowed_redirect_urls.sort();
    allowed_redirect_urls.dedup();

    let after_sign_in_url = settings
        .advanced
        .allowed_callback_urls
        .first()
        .cloned()
        .unwrap_or_else(|| "/".to_string());
    let after_sign_up_url = after_sign_in_url.clone();
    let after_sign_out_url = settings
        .advanced
        .allowed_logout_urls
        .first()
        .cloned()
        .unwrap_or_else(|| "/".to_string());

    Ok(HostedUiConfig {
        tenant_id: tenant_id.to_string(),
        company_name: settings.branding.brand_name,
        logo_url: settings.branding.brand_logo_url,
        favicon_url: settings.branding.brand_favicon_url,
        primary_color: Some(settings.branding.primary_color),
        background_color: None,
        sign_in_title: None,
        sign_up_title: None,
        oauth_providers,
        show_magic_link,
        show_web_authn,
        require_email_verification: settings.auth.require_email_verification,
        allow_sign_up: settings.auth.allow_registration,
        after_sign_in_url,
        after_sign_up_url,
        after_sign_out_url,
        terms_url: settings.branding.terms_of_service_url,
        privacy_url: settings.branding.privacy_policy_url,
        custom_css: settings.branding.custom_css,
        custom_js: None,
        allowed_redirect_urls,
    })
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
