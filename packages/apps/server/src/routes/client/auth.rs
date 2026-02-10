//! Authentication routes

use axum::{
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use validator::Validate;

use crate::{
    actions,
    audit::{AuditLogger, RequestContext},
    auth::{
        create_anonymous_session, convert_to_full_account, AuthProvider, CreateAnonymousSessionRequest,
        ConvertAnonymousRequest, LinkAccountRequest, StepUpAuthMethod, StepUpCredentials,
        StepUpFailureReason, StepUpRequest, StepUpService, StepUpTokenResponse,
    },
    middleware::{
        auth::auth_middleware, is_captcha_required_for_login, record_failed_login, reset_failed_login,
        CaptchaSiteKeyResponse,
    },
    routes::ApiError,
    security::{EnforcementMode, LoginContext, RiskAction, UserInfo},
    state::{AppState, CurrentUser, SessionLimitStatus},
};
use vault_core::crypto::{AuthMethod, StepUpLevel, TokenType, HybridJwt};

/// Authentication middleware wrapper for auth routes.
/// 
/// This wrapper extracts the AppState from request extensions and calls the
/// main auth_middleware. This is required because auth_middleware needs
/// access to AppState for token validation and other operations.
async fn auth_routes_middleware(
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
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

/// Auth routes
///
/// Bot protection is applied to:
/// - POST /register - Always protected
/// - POST /login - Protected after N failed attempts (configurable)
/// - POST /forgot-password - Always protected
/// - POST /magic-link - Always protected
/// - POST /oauth/:provider - Optional protection (based on config)
pub fn routes() -> Router<AppState> {
    // Public auth endpoints - no authentication required
    let public_routes = Router::new()
        // Registration and login
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh_token))
        // Magic link authentication
        .route("/magic-link", post(send_magic_link))
        .route("/magic-link/verify", post(verify_magic_link))
        // Password reset
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
        // Email verification (token-based, no auth required)
        .route("/verify-email", post(verify_email))
        // CAPTCHA site key endpoint (no protection needed)
        .route("/captcha-site-key", get(get_captcha_site_key))
        // OAuth endpoints
        .route("/oauth/:provider", post(oauth_redirect))
        .route("/oauth/:provider/callback", get(oauth_callback))
        // Apple uses form_post response mode, so we need a POST handler
        .route("/oauth/apple/callback", post(apple_oauth_callback))
        // SSO endpoints
        .route("/sso/redirect", get(sso_redirect))
        .route("/sso/callback", post(sso_callback))
        .route("/sso/metadata", get(sso_metadata))
        // WebAuthn/Passkey authentication (public - for logging in)
        .route(
            "/webauthn/authenticate/begin",
            post(webauthn_authenticate_begin),
        )
        .route(
            "/webauthn/authenticate/finish",
            post(webauthn_authenticate_finish),
        )
        // Step-up authentication endpoint
        .route("/step-up", post(step_up))
        // Web3 authentication endpoints
        .route("/web3/nonce", post(web3_nonce))
        .route("/web3/verify", post(web3_verify))
        // Anonymous/guest authentication endpoints
        .route("/anonymous", post(create_anonymous_session_handler))
        .route("/anonymous/convert", post(convert_anonymous_handler))
        // Biometric authentication endpoints
        .route("/biometric/challenge", post(biometric_challenge))
        .route("/biometric/authenticate", post(biometric_authenticate));

    // Authenticated endpoints - require valid authentication
    // CSRF protection is provided by requiring a valid access token
    let authenticated_routes = Router::new()
        // Session management (state-changing, requires auth)
        .route("/logout", post(logout))
        // User profile (requires auth)
        .route("/me", get(get_current_user))
        // WebAuthn credential management (requires auth)
        .route("/webauthn/register/begin", post(webauthn_register_begin))
        .route("/webauthn/register/finish", post(webauthn_register_finish))
        .route("/webauthn/credentials", get(list_webauthn_credentials))
        .route(
            "/webauthn/credentials/:id",
            delete(delete_webauthn_credential),
        )
        // OAuth account linking (requires auth)
        .route("/oauth/:provider/link", post(oauth_link_account))
        // Biometric key management (requires auth)
        .route("/biometric/keys", post(biometric_register_key).get(biometric_list_keys))
        .route("/biometric/keys/:id", delete(biometric_revoke_key))
        // Apply authentication middleware to all routes in this router
        .layer(middleware::from_fn(auth_routes_middleware));

    // Combine public and authenticated routes
    Router::new()
        .merge(public_routes)
        .merge(authenticated_routes)
}

type SsoCallbackRequest = serde_json::Value;

// ============ Request/Response Types ============

#[derive(Debug, Deserialize, Validate)]
struct RegisterRequest {
    #[validate(email)]
    email: String,
    #[validate(length(min = 12))]
    password: String,
    name: Option<String>,
    /// Required: Consent to Terms of Service
    #[serde(rename = "termsAccepted")]
    terms_accepted: bool,
    /// Required: Consent to Privacy Policy
    #[serde(rename = "privacyAccepted")]
    privacy_accepted: bool,
    /// Optional: Consent to marketing communications
    #[serde(rename = "marketingConsent")]
    marketing_consent: Option<bool>,
    /// Optional: Consent to analytics cookies
    #[serde(rename = "analyticsConsent")]
    analytics_consent: Option<bool>,
    /// Optional: Consent to cookie usage
    #[serde(rename = "cookiesConsent")]
    cookies_consent: Option<bool>,
}

#[derive(Debug, Deserialize, Validate)]
struct LoginRequest {
    #[validate(email)]
    email: String,
    password: String,
    #[serde(rename = "mfaCode")]
    mfa_code: Option<String>,
    /// CAPTCHA token (required after failed attempts)
    #[serde(rename = "captchaToken")]
    captcha_token: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
struct RefreshRequest {
    #[validate(length(min = 1, message = "Refresh token is required"))]
    #[serde(rename = "refreshToken")]
    refresh_token: String,
}

#[derive(Debug, Deserialize, Validate)]
struct MagicLinkRequest {
    #[validate(email(message = "Invalid email format"))]
    email: String,
}

#[derive(Debug, Deserialize, Validate)]
struct VerifyMagicLinkRequest {
    #[validate(length(min = 1, message = "Token is required"))]
    token: String,
}

#[derive(Debug, Deserialize, Validate)]
struct ForgotPasswordRequest {
    #[validate(email(message = "Invalid email format"))]
    email: String,
}

#[derive(Debug, Deserialize, Validate)]
struct ResetPasswordRequest {
    #[validate(length(min = 1, message = "Token is required"))]
    token: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    #[serde(rename = "newPassword")]
    new_password: String,
}

#[derive(Debug, Deserialize, Validate)]
struct VerifyEmailRequest {
    #[validate(length(min = 1, message = "Token is required"))]
    token: String,
}

#[derive(Debug, Deserialize, Validate)]
struct OAuthRequest {
    #[validate(url(message = "Invalid redirect URI format"))]
    #[serde(rename = "redirectUri")]
    redirect_uri: Option<String>,
    /// Set to true if this is for linking an account (user must be authenticated)
    link: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SsoRedirectQuery {
    domain: Option<String>,
    #[serde(rename = "connection_id")]
    connection_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct OAuthRedirectResponse {
    #[serde(rename = "authUrl")]
    auth_url: String,
    state: String,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    user: UserResponse,
    #[serde(rename = "mfaRequired")]
    mfa_required: bool,
    /// Session information including limit status
    #[serde(rename = "sessionInfo")]
    session_info: Option<SessionInfoResponse>,
}

#[derive(Debug, Serialize)]
struct SessionInfoResponse {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "currentSessions")]
    current_sessions: usize,
    #[serde(rename = "maxSessions")]
    max_sessions: usize,
    warning: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    id: String,
    email: String,
    #[serde(rename = "emailVerified")]
    email_verified: bool,
    name: Option<String>,
    #[serde(rename = "mfaEnabled")]
    mfa_enabled: bool,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

/// Helper to extract tenant ID from request
/// First tries the X-Tenant-ID header, then falls back to "default"
fn extract_tenant_id(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "default".to_string())
}

async fn apply_token_issue_actions(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    access_token: &str,
) -> Result<String, ApiError> {
    if access_token.is_empty() {
        return Ok(access_token.to_string());
    }
    let decision = actions::run_actions(
        state,
        tenant_id,
        "token_issue",
        Some(user_id),
        serde_json::json!({
            "user_id": user_id,
            "access_token": access_token,
        }),
    )
    .await?;

    if !decision.allowed {
        return Err(ApiError::Forbidden);
    }

    if decision.claims.is_empty() {
        return Ok(access_token.to_string());
    }

    let mut claims = HybridJwt::decode(access_token, state.auth_service.verifying_key())
        .map_err(|_| ApiError::internal())?;

    for (k, v) in decision.claims.into_iter() {
        claims.custom.insert(k, v);
    }

    let new_token = HybridJwt::encode(&claims, state.auth_service.signing_key())
        .map_err(|_| ApiError::internal())?;

    Ok(new_token)
}

// ============ Handlers ============

/// Get CAPTCHA site key for frontend integration
async fn get_captcha_site_key(State(state): State<AppState>) -> Json<CaptchaSiteKeyResponse> {
    Json(CaptchaSiteKeyResponse::from_state(&state))
}

/// Register a new user
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        ip_address = %addr.ip(),
        action = "register",
        success = tracing::field::Empty,
    )
)]
async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Validate request
    if let Err(e) = req.validate() {
        tracing::warn!(validation_error = %e, "Registration validation failed");
        return Err(ApiError::Validation(e.to_string()));
    }

    let tenant_id = extract_tenant_id(&headers);
    tracing::Span::current().record("tenant_id", &tenant_id.as_str());
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let password = req.password.clone();
    let email = req.email.clone();
    let ip = addr.ip().to_string();
    let audit = AuditLogger::new(state.db.clone());

    // Validate password against policy
    let user_info = UserInfo {
        email: email.clone(),
        name: req.name.clone(),
        user_id: "pending".to_string(), // User ID not yet assigned
    };

    let validation_result = state
        .security_service
        .validate_password(&password, Some(&user_info))
        .await;

    if !validation_result.is_valid {
        let policy = state.security_service.policy();

        match policy.enforcement_mode {
            EnforcementMode::Block => {
                tracing::warn!(
                    error_codes = ?validation_result.error_codes(),
                    "Registration rejected due to password policy violations"
                );

                // Log the policy violation
                audit.log(
                    &tenant_id,
                    crate::audit::AuditAction::RegistrationFailed,
                    crate::audit::ResourceType::User,
                    &email,
                    None,
                    None,
                    context.clone(),
                    false,
                    Some("Password policy violation".to_string()),
                    Some(serde_json::json!({
                        "errors": validation_result.error_messages(),
                        "codes": validation_result.error_codes(),
                    })),
                );

                return Err(ApiError::Validation(
                    "Password does not meet policy requirements".to_string(),
                ));
            }
            EnforcementMode::Warn | EnforcementMode::Audit => {
                // Log but allow
                let mode = if matches!(policy.enforcement_mode, EnforcementMode::Warn) {
                    "warn"
                } else {
                    "audit"
                };
                tracing::info!(
                    enforcement_mode = mode,
                    error_codes = ?validation_result.error_codes(),
                    "Password policy violations detected (allowed)"
                );
            }
        }
    }

    // Validate required consents
    if !req.terms_accepted {
        return Err(ApiError::Validation(
            "You must accept the Terms of Service to register".to_string(),
        ));
    }
    if !req.privacy_accepted {
        return Err(ApiError::Validation(
            "You must accept the Privacy Policy to register".to_string(),
        ));
    }

    // Pre-register actions/rules
    let pre_register = actions::run_actions(
        &state,
        &tenant_id,
        "pre_register",
        None,
        serde_json::json!({
            "email": email.clone(),
            "ip": ip,
            "user_agent": headers.get("user-agent").and_then(|h| h.to_str().ok())
        }),
    )
    .await?;
    if !pre_register.allowed {
        return Err(ApiError::Forbidden);
    }

    // Register user
    match state
        .auth_service
        .register(&tenant_id, req.email, req.password, req.name)
        .await
    {
        Ok((user, _token)) => {
            // Log successful registration
            audit.log_user_registered(&tenant_id, &user.id, &email, context.clone());

            // Record consent for Terms of Service and Privacy Policy
            let consent_context = crate::consent::ConsentContext {
                ip_address: Some(ip.clone()),
                user_agent: headers.get("user-agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
                jurisdiction: headers.get("cf-ipcountry").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
            };

            // Record required consents
            if let Err(e) = record_registration_consents(
                &state,
                &user.id,
                &tenant_id,
                req.terms_accepted,
                req.privacy_accepted,
                req.marketing_consent.unwrap_or(false),
                req.analytics_consent.unwrap_or(false),
                req.cookies_consent.unwrap_or(false),
                consent_context,
            ).await {
                tracing::error!(user_id = %user.id, error = %e, "Failed to record consents");
                // Don't fail registration if consent recording fails, but log it
            }

            // Trigger webhook event
            crate::webhooks::events::trigger_user_created(
                &state,
                &tenant_id,
                &user.id,
                &user.email,
                user.profile.name.as_deref(),
            )
            .await;

            // Post-register actions/rules
            let _ = actions::run_actions(
                &state,
                &tenant_id,
                "post_register",
                Some(&user.id),
                serde_json::json!({
                    "user_id": user.id,
                    "email": user.email.clone(),
                }),
            )
            .await;

            // Check for B2B auto-enrollment based on email domain
            if let Ok(domain_service) =
                crate::domains::service::DomainService::new(state.db.pool().clone().into()).await
            {
                match domain_service
                    .auto_enroll_user(&tenant_id, &user.id, &user.email)
                    .await
                {
                    Ok(enrollment) if enrollment.enrolled => {
                        if let Some(org_id) = enrollment.organization_id {
                            tracing::info!(
                                user_id = %user.id,
                                organization_id = %org_id,
                                "User auto-enrolled in organization via domain verification"
                            );

                            // Trigger webhook for auto-enrollment
                            crate::domains::service::webhook_events_ext::trigger_user_joined_organization(
                                &state,
                                &tenant_id,
                                &user.id,
                                &user.email,
                                &org_id,
                                enrollment.role.as_deref(),
                                true, // auto_enrolled
                            ).await;

                            // TODO: Send notification to org admins about new auto-enrolled user
                            // This would be handled by a notification service
                        }
                    }
                    Ok(_) => {
                        // No auto-enrollment available for this domain
                        tracing::debug!(user_id = %user.id, "No auto-enrollment available");
                    }
                    Err(e) => {
                        // Log error but don't fail registration
                        tracing::warn!(user_id = %user.id, error = %e, "Auto-enrollment check failed");
                    }
                }
            }

            // Auto-login after registration
            let credentials = vault_core::auth::LoginCredentials {
                email: user.email.clone(),
                password,
                mfa_code: None,
            };

            match state
                .auth_service
                .authenticate(&tenant_id, credentials, Some(addr.to_string()), None)
                .await
            {
                Ok(auth_result) => {
                    // Log successful login
                    audit.log_login_success(
                        &tenant_id,
                        &user.id,
                        Some(&auth_result.session.id),
                        &user.email,
                        context.clone(),
                        "password",
                    );

                    // Get session limit status for response
                    let limit_status = state
                        .get_session_limit_status(&tenant_id, &auth_result.user.id)
                        .await
                        .unwrap_or(SessionLimitStatus {
                            current_sessions: 1,
                            max_sessions: state
                                .config
                                .security
                                .session_limits
                                .max_concurrent_sessions,
                            warning: None,
                        });

                    let access_token = apply_token_issue_actions(
                        &state,
                        &tenant_id,
                        &auth_result.user.id,
                        &auth_result.access_token,
                    )
                    .await?;

                    Ok(Json(AuthResponse {
                        access_token,
                        refresh_token: auth_result.refresh_token,
                        user: UserResponse {
                            id: user.id,
                            email: user.email,
                            email_verified: user.email_verified,
                            name: user.profile.name,
                            mfa_enabled: user.mfa_enabled,
                        },
                        mfa_required: auth_result.mfa_required,
                        session_info: if auth_result.mfa_required {
                            None
                        } else {
                            Some(SessionInfoResponse {
                                session_id: auth_result.session.id.clone(),
                                current_sessions: limit_status.current_sessions,
                                max_sessions: limit_status.max_sessions,
                                warning: limit_status.warning,
                            })
                        },
                    }))
                }
                Err(e) => {
                    tracing::error!(error = %e, "Auto-login after registration failed");
                    Err(ApiError::internal())
                }
            }
        }
        Err(e) => {
            let error_msg = e.to_string();
            tracing::warn!(email = %email, error = %error_msg, "Registration failed");
            // Log failed registration
            let reason = if error_msg.contains("already exists") {
                "Email already exists"
            } else {
                "Registration failed"
            };
            audit.log_registration_failed(&tenant_id, &email, context, reason);

            // Check for specific errors
            if e.to_string().contains("already exists") {
                return Err(ApiError::Conflict("Email already exists".to_string()));
            }
            Err(ApiError::BadRequest("Registration failed".to_string()))
        }
    }
}

/// Login with email and password
///
/// CAPTCHA is required after N failed login attempts (configurable)
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        email = %req.email,
        ip_address = %addr.ip(),
        action = "login",
        success = tracing::field::Empty,
    )
)]
async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Validate request
    if let Err(e) = req.validate() {
        tracing::warn!(validation_error = %e, "Login validation failed");
        return Err(ApiError::Validation(e.to_string()));
    }

    let tenant_id = extract_tenant_id(&headers);
    tracing::Span::current().record("tenant_id", &tenant_id.as_str());
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let email = req.email.clone();
    let audit = AuditLogger::new(state.db.clone());

    // Build key for tracking failed logins (tenant + email + IP combination)
    let ip = addr.ip().to_string();
    let failed_login_key = format!("{}:{}:{}", tenant_id, email, ip);

    // Check if CAPTCHA is required based on failed attempts
    let captcha_required = is_captcha_required_for_login(&state, &failed_login_key).await;

    // If CAPTCHA is required, verify the token
    if captcha_required && state.bot_protection.is_enabled() {
        let token = req
            .captcha_token
            .or_else(|| {
                headers
                    .get("X-Turnstile-Token")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .or_else(|| {
                headers
                    .get("X-Captcha-Token")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            });

        match token {
            Some(t) => {
                let remote_ip = Some(ip.clone());
                match state
                    .bot_protection
                    .verify_token(&t, remote_ip.as_deref())
                    .await
                {
                    Ok(result) if result.success => {
                        tracing::debug!("CAPTCHA verified for login attempt");
                    }
                    Ok(result) => {
                        tracing::warn!(
                            error_codes = ?result.error_codes,
                            "CAPTCHA verification failed for login"
                        );
                        // Return 403 with CAPTCHA required indicator
                        return Err(ApiError::Forbidden);
                    }
                    Err(e) => {
                        tracing::error!("CAPTCHA verification error: {}", e);
                        return Err(ApiError::Forbidden);
                    }
                }
            }
            None => {
                tracing::warn!("CAPTCHA required but not provided for login");
                // Log the CAPTCHA requirement
                audit.log(
                    &tenant_id,
                    crate::audit::AuditAction::LoginFailed,
                    crate::audit::ResourceType::User,
                    &email,
                    None,
                    None,
                    context.clone(),
                    false,
                    Some("CAPTCHA required".to_string()),
                    Some(serde_json::json!({
                        "captcha_required": true,
                        "failed_attempts": state.failed_login_tracker.get_failure_count(&failed_login_key).await
                    })),
                );
                return Err(ApiError::Forbidden);
            }
        }
    }

    // Clone email and password for potential LDAP fallback
    let email_for_ldap = req.email.clone();
    let password_for_ldap = req.password.clone();

    // Pre-login actions/rules
    let pre_payload = serde_json::json!({
        "email": email_for_ldap,
        "ip": ip,
        "user_agent": headers.get("user-agent").and_then(|h| h.to_str().ok())
    });
    let pre_decision = actions::run_actions(
        &state,
        &tenant_id,
        "pre_login",
        None,
        pre_payload,
    )
    .await?;
    if !pre_decision.allowed {
        return Err(ApiError::Forbidden);
    }

    // Clone MFA code for potential LDAP fallback before moving into credentials
    let mfa_code_for_ldap = req.mfa_code.clone();
    
    let credentials = vault_core::auth::LoginCredentials {
        email: req.email,
        password: req.password,
        mfa_code: req.mfa_code,
    };

    match state
        .auth_service
        .authenticate(&tenant_id, credentials, Some(addr.to_string()), None)
        .await
    {
        Ok(auth_result) => {
            // Reset failed login attempts on successful login
            reset_failed_login(&state, &failed_login_key).await;

            if auth_result.mfa_required {
                // Log MFA required event
                audit.log_mfa_verification(
                    &tenant_id,
                    &auth_result.user.id,
                    None,
                    context.clone(),
                    false,
                    "totp",
                );

                // Return partial response indicating MFA is needed
                return Ok(Json(AuthResponse {
                    access_token: String::new(),
                    refresh_token: String::new(),
                    user: UserResponse {
                        id: auth_result.user.id,
                        email: auth_result.user.email,
                        email_verified: auth_result.user.email_verified,
                        name: auth_result.user.profile.name,
                        mfa_enabled: auth_result.user.mfa_enabled,
                    },
                    mfa_required: true,
                    session_info: None,
                }));
            }

            // Check session limits before completing login
            match state
                .check_session_limits(&tenant_id, &auth_result.user.id, Some(&ip))
                .await
            {
                Ok(Ok(())) => {
                    // Session limits passed, continue with login
                }
                Ok(Err(limit_err)) => {
                    // Session limit reached - deny login
                    tracing::warn!(
                        "Session limit reached for user {}: {}/{} sessions",
                        auth_result.user.id,
                        limit_err.current_sessions,
                        limit_err.max_sessions
                    );

                    // Log the session limit event
                    audit.log(
                        &tenant_id,
                        crate::audit::AuditAction::LoginFailed,
                        crate::audit::ResourceType::User,
                        &auth_result.user.id,
                        None,
                        None,
                        context.clone(),
                        false,
                        Some("SESSION_LIMIT_REACHED".to_string()),
                        Some(serde_json::json!({
                            "current_sessions": limit_err.current_sessions,
                            "max_sessions": limit_err.max_sessions
                        })),
                    );

                    return Err(ApiError::SessionLimitReached(limit_err));
                }
                Err(e) => {
                    tracing::error!("Failed to check session limits: {}", e);
                    return Err(ApiError::internal());
                }
            }

            // ===== Risk-Based Authentication =====
            // Perform risk assessment after successful auth but before completing login
            let login_context = LoginContext::new(&tenant_id)
                .with_ip(addr.ip())
                .with_headers(headers.clone())
                .with_email(&auth_result.user.email)
                .with_user_id(&auth_result.user.id)
                .with_failed_attempts(
                    state.failed_login_tracker.get_failure_count(&failed_login_key).await,
                )
                .with_mfa_enabled(auth_result.user.mfa_enabled);

            let risk_assessment = state.risk_engine.assess(login_context).await;

            // Handle risk-based action
            match risk_assessment.action {
                RiskAction::Block => {
                    // Log blocked login due to risk
                    audit.log(
                        &tenant_id,
                        crate::audit::AuditAction::LoginBlockedRisk,
                        crate::audit::ResourceType::RiskAssessment,
                        &risk_assessment.id,
                        Some(auth_result.user.id.clone()),
                        None,
                        context.clone(),
                        false,
                        Some(format!("Risk score {} exceeds threshold", risk_assessment.score.value())),
                        Some(serde_json::json!({
                            "risk_score": risk_assessment.score.value(),
                            "risk_level": risk_assessment.score.level(),
                            "factors": risk_assessment.factors,
                        })),
                    );

                    tracing::warn!(
                        "Login blocked for user {} due to high risk score: {}",
                        auth_result.user.id,
                        risk_assessment.score.value()
                    );

                    return Err(ApiError::Forbidden);
                }
                RiskAction::Challenge => {
                    // Log challenge required
                    audit.log(
                        &tenant_id,
                        crate::audit::AuditAction::RiskAssessmentCreated,
                        crate::audit::ResourceType::RiskAssessment,
                        &risk_assessment.id,
                        Some(auth_result.user.id.clone()),
                        None,
                        context.clone(),
                        true,
                        None,
                        Some(serde_json::json!({
                            "action": "challenge",
                            "risk_score": risk_assessment.score.value(),
                            "risk_level": risk_assessment.score.level(),
                        })),
                    );

                    // Return response indicating challenge is required
                    // Note: In a full implementation, this would return a challenge token
                    return Err(ApiError::Forbidden);
                }
                RiskAction::StepUp => {
                    // If MFA is already required, continue with normal MFA flow
                    if auth_result.user.mfa_enabled {
                        // MFA will be handled below
                    } else {
                        // User doesn't have MFA enabled but risk requires it
                        // Log and require MFA setup
                        audit.log(
                            &tenant_id,
                            crate::audit::AuditAction::RiskAssessmentCreated,
                            crate::audit::ResourceType::RiskAssessment,
                            &risk_assessment.id,
                            Some(auth_result.user.id.clone()),
                            None,
                            context.clone(),
                            true,
                            None,
                            Some(serde_json::json!({
                                "action": "step_up",
                                "risk_score": risk_assessment.score.value(),
                                "risk_level": risk_assessment.score.level(),
                            })),
                        );

                        // Return error indicating MFA setup is required
                        return Err(ApiError::Forbidden);
                    }
                }
                RiskAction::Allow => {
                    // Low risk, continue with normal login flow
                }
            }

            // Get session limit status for response
            let limit_status = state
                .get_session_limit_status(&tenant_id, &auth_result.user.id)
                .await
                .unwrap_or(SessionLimitStatus {
                    current_sessions: 0,
                    max_sessions: state.config.security.session_limits.max_concurrent_sessions,
                    warning: None,
                });

            // Log successful login
            audit.log_login_success(
                &tenant_id,
                &auth_result.user.id,
                Some(&auth_result.session.id),
                &auth_result.user.email,
                context.clone(),
                "password",
            );

            // Trigger webhook events
            let ip = context.as_ref().and_then(|c| c.ip_address.clone());
            let ua = context.as_ref().and_then(|c| c.user_agent.clone());

            crate::webhooks::events::trigger_session_created(
                &state,
                &tenant_id,
                &auth_result.user.id,
                &auth_result.session.id,
                &auth_result.user.email,
                ip.as_deref(),
                ua.as_deref(),
                "password",
            )
            .await;

            crate::webhooks::events::trigger_user_login(
                &state,
                &tenant_id,
                &auth_result.user.id,
                &auth_result.user.email,
                ip.as_deref(),
                ua.as_deref(),
                "password",
                true,
            )
            .await;

            // JIT org auto-enrollment on login
            if let Ok(domain_service) =
                crate::domains::service::DomainService::new(state.db.pool().clone().into()).await
            {
                let _ = domain_service
                    .auto_enroll_user(&tenant_id, &auth_result.user.id, &auth_result.user.email)
                    .await;
            }

            // Post-login actions/rules
            let _ = actions::run_actions(
                &state,
                &tenant_id,
                "post_login",
                Some(&auth_result.user.id),
                serde_json::json!({
                    "user_id": auth_result.user.id,
                    "email": auth_result.user.email,
                    "session_id": auth_result.session.id,
                }),
            )
            .await;

            let access_token = apply_token_issue_actions(
                &state,
                &tenant_id,
                &auth_result.user.id,
                &auth_result.access_token,
            )
            .await?;

            Ok(Json(AuthResponse {
                access_token,
                refresh_token: auth_result.refresh_token,
                user: UserResponse {
                    id: auth_result.user.id,
                    email: auth_result.user.email,
                    email_verified: auth_result.user.email_verified,
                    name: auth_result.user.profile.name,
                    mfa_enabled: auth_result.user.mfa_enabled,
                },
                mfa_required: auth_result.mfa_required,
                session_info: if auth_result.mfa_required {
                    None // Don't return session info if MFA is still required
                } else {
                    Some(SessionInfoResponse {
                        session_id: auth_result.session.id.clone(),
                        current_sessions: limit_status.current_sessions + 1, // +1 for the new session
                        max_sessions: limit_status.max_sessions,
                        warning: limit_status.warning,
                    })
                },
            }))
        }
        Err(e) => {
            let error_msg = e.to_string();
            tracing::warn!(error = %error_msg, "Authentication failed");

            // Record failed login attempt
            let failure_count = record_failed_login(&state, &failed_login_key).await;

            // Log failed login
            audit.log_login_failed(&tenant_id, &email, context.clone(), &error_msg);

            tracing::info!(
                failure_count = failure_count,
                email = %email,
                ip = %ip,
                "Failed login attempt recorded"
            );

            // Try LDAP authentication if local auth failed
            // SECURITY: Pass MFA code if provided to prevent MFA bypass
            match try_ldap_authenticate(&state, &tenant_id, &email_for_ldap, &password_for_ldap, mfa_code_for_ldap)
                .await
            {
                Ok(Some(auth_result)) => {
                    // Reset failed login attempts on successful LDAP login
                    reset_failed_login(&state, &failed_login_key).await;

                    // Check session limits
                    match state
                        .check_session_limits(&tenant_id, &auth_result.user.id, Some(&ip))
                        .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(limit_err)) => {
                            return Err(ApiError::SessionLimitReached(limit_err));
                        }
                        Err(e) => {
                            tracing::error!("Failed to check session limits: {}", e);
                            return Err(ApiError::internal());
                        }
                    }

                    let limit_status = state
                        .get_session_limit_status(&tenant_id, &auth_result.user.id)
                        .await
                        .unwrap_or(SessionLimitStatus {
                            current_sessions: 1,
                            max_sessions: state
                                .config
                                .security
                                .session_limits
                                .max_concurrent_sessions,
                            warning: None,
                        });

                    // Log successful LDAP login
                    audit.log_login_success(
                        &tenant_id,
                        &auth_result.user.id,
                        Some(&auth_result.session.id),
                        &auth_result.user.email,
                        context.clone(),
                        "ldap",
                    );

                    // Trigger webhooks
                    crate::webhooks::events::trigger_user_login(
                        &state,
                        &tenant_id,
                        &auth_result.user.id,
                        &auth_result.user.email,
                        context.as_ref().and_then(|c| c.ip_address.as_deref()),
                        context.as_ref().and_then(|c| c.user_agent.as_deref()),
                        "ldap",
                        true,
                    )
                    .await;

                    let access_token = apply_token_issue_actions(
                        &state,
                        &tenant_id,
                        &auth_result.user.id,
                        &auth_result.access_token,
                    )
                    .await?;

                    // SECURITY FIX: Properly propagate MFA requirements from LDAP authentication
                    // Previously this was hardcoded to false, allowing MFA bypass
                    return Ok(Json(AuthResponse {
                        access_token,
                        refresh_token: auth_result.refresh_token,
                        user: UserResponse {
                            id: auth_result.user.id,
                            email: auth_result.user.email,
                            email_verified: auth_result.user.email_verified,
                            name: auth_result.user.profile.name,
                            mfa_enabled: auth_result.user.mfa_enabled,
                        },
                        mfa_required: auth_result.mfa_required,
                        session_info: if auth_result.mfa_required {
                            None // Don't return session info if MFA is still required
                        } else {
                            Some(SessionInfoResponse {
                                session_id: auth_result.session.id.clone(),
                                current_sessions: limit_status.current_sessions + 1,
                                max_sessions: limit_status.max_sessions,
                                warning: limit_status.warning,
                            })
                        },
                    }));
                }
                Ok(None) => {
                    // LDAP also failed or not configured
                }
                Err(e) => {
                    tracing::error!(error = %e, "LDAP authentication error");
                }
            }

            Err(ApiError::Unauthorized)
        }
    }
}

/// Try LDAP authentication as fallback
/// 
/// SECURITY: This function properly handles MFA requirements after LDAP JIT authentication.
/// If the user has MFA enabled, the authentication will return mfa_required=true and
/// the client must complete MFA verification before receiving tokens.
async fn try_ldap_authenticate(
    state: &AppState,
    tenant_id: &str,
    email: &str,
    password: &str,
    mfa_code: Option<String>,
) -> Result<Option<vault_core::auth::AuthResult>, anyhow::Error> {
    use crate::ldap::sync::LdapJitAuth;

    // Check if LDAP is enabled for this tenant
    let ldap_enabled: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ldap_connections WHERE tenant_id = $1 AND enabled = true)",
    )
    .bind(tenant_id)
    .fetch_one(state.db.pool())
    .await?;

    if !ldap_enabled {
        return Ok(None);
    }

    let jit_auth = LdapJitAuth::new(state.db.pool().clone(), state.tenant_key_service.clone());

    // Try LDAP authentication with JIT provisioning
    match jit_auth.authenticate(tenant_id, email, password).await {
        Ok(Some(_ldap_user)) => {
            // After JIT auth, the user should exist in the database
            // Authenticate them locally now, passing through the MFA code if provided
            let credentials = vault_core::auth::LoginCredentials {
                email: email.to_string(),
                password: password.to_string(),
                mfa_code,
            };

            match state
                .auth_service
                .authenticate(tenant_id, credentials, None, None)
                .await
            {
                Ok(auth_result) => Ok(Some(auth_result)),
                Err(e) => {
                    tracing::warn!("LDAP auth succeeded but local auth failed: {}", e);
                    Ok(None)
                }
            }
        }
        Ok(None) => Ok(None),
        Err(e) => {
            tracing::warn!("LDAP authentication error: {}", e);
            Ok(None)
        }
    }
}

/// Refresh access token
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        action = "token_refresh",
        success = tracing::field::Empty,
    )
)]
async fn refresh_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // Validate input
    if let Err(e) = req.validate() {
        tracing::debug!(validation_error = %e, "Refresh token validation failed");
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let tenant_id = extract_tenant_id(&headers);
    let audit = AuditLogger::new(state.db.clone());

    match state
        .auth_service
        .refresh_token(&tenant_id, &req.refresh_token)
        .await
    {
        Ok(auth_result) => {
            // Log successful token refresh
            audit.log_token_refresh(
                &tenant_id,
                &auth_result.user.id,
                &auth_result.session.id,
                true,
                None,
            );

            Ok(Json(AuthResponse {
                access_token: apply_token_issue_actions(
                    &state,
                    &tenant_id,
                    &auth_result.user.id,
                    &auth_result.access_token,
                )
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
                refresh_token: auth_result.refresh_token,
                user: UserResponse {
                    id: auth_result.user.id,
                    email: auth_result.user.email,
                    email_verified: auth_result.user.email_verified,
                    name: auth_result.user.profile.name,
                    mfa_enabled: auth_result.user.mfa_enabled,
                },
                mfa_required: false,
                session_info: None,
            }))
        }
        Err(e) => {
            tracing::warn!(error = %e, "Token refresh failed");
            // Log failed token refresh - we don't have user_id here
            audit.log(
                &tenant_id,
                crate::audit::AuditAction::TokenRefreshFailed,
                crate::audit::ResourceType::Token,
                "unknown",
                None,
                None,
                None,
                false,
                Some(e.to_string()),
                None,
            );
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Logout user
#[tracing::instrument(
    skip(state, user),
    fields(
        tenant_id = %user.tenant_id,
        user_id = %user.user_id,
        session_id = tracing::field::Empty,
        action = "logout",
    )
)]
async fn logout(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Get session ID from JWT claims
    let session_id = user.session_id.ok_or(StatusCode::BAD_REQUEST)?;
    tracing::Span::current().record("session_id", &session_id.as_str());
    let audit = AuditLogger::new(state.db.clone());

    match state
        .auth_service
        .logout(&user.tenant_id, &session_id, false)
        .await
    {
        Ok(_) => {
            // Log successful logout
            audit.log_logout(&user.tenant_id, &user.user_id, &session_id);

            // Trigger webhook events
            crate::webhooks::events::trigger_session_revoked(
                &state,
                &user.tenant_id,
                &user.user_id,
                &session_id,
                Some("logout"),
            )
            .await;

            crate::webhooks::events::trigger_user_logout(
                &state,
                &user.tenant_id,
                &user.user_id,
                &user.email,
            )
            .await;

            Ok(Json(MessageResponse {
                message: "Logged out successfully".to_string(),
            }))
        }
        Err(e) => {
            tracing::error!(error = %e, "Logout failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get current user
async fn get_current_user(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<UserResponse>, StatusCode> {
    let db_user = state
        .db
        .users()
        .find_by_id(&user.tenant_id, &user.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let profile = db_user.profile;
    let name = profile.name.clone().or_else(|| {
        match (profile.given_name.as_deref(), profile.family_name.as_deref()) {
            (Some(f), Some(l)) => Some(format!("{} {}", f, l)),
            (Some(f), None) => Some(f.to_string()),
            (None, Some(l)) => Some(l.to_string()),
            _ => None,
        }
    });

    Ok(Json(UserResponse {
        id: user.user_id,
        email: user.email,
        email_verified: user.email_verified,
        name,
        mfa_enabled: db_user.mfa_enabled,
    }))
}

/// Send magic link for passwordless login
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        email = %req.email,
        ip_address = %addr.ip(),
        action = "magic_link_send",
        success = tracing::field::Empty,
    )
)]
async fn send_magic_link(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MagicLinkRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    if let Err(e) = req.validate() {
        tracing::warn!(validation_error = %e, "Magic link validation failed");
        return Err(StatusCode::BAD_REQUEST);
    }

    let tenant_id = extract_tenant_id(&headers);
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let email = req.email.clone();
    let audit = AuditLogger::new(state.db.clone());

    match state
        .auth_service
        .send_magic_link(&tenant_id, &req.email)
        .await
    {
        Ok(_) => {
            // Log magic link sent
            audit.log_magic_link(
                &tenant_id,
                None,
                &email,
                context,
                crate::audit::AuditAction::MagicLinkSent,
                true,
                None,
            );

            Ok(Json(MessageResponse {
                message: "Magic link sent".to_string(),
            }))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to send magic link");
            // Don't reveal if email exists to the client, but log it
            audit.log_magic_link(
                &tenant_id,
                None,
                &email,
                context,
                crate::audit::AuditAction::MagicLinkFailed,
                false,
                Some(&e.to_string()),
            );
            Ok(Json(MessageResponse {
                message: "Magic link sent".to_string(),
            }))
        }
    }
}

/// Verify magic link
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        ip_address = %addr.ip(),
        action = "magic_link_verify",
        success = tracing::field::Empty,
    )
)]
async fn verify_magic_link(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VerifyMagicLinkRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // Validate input
    if let Err(e) = req.validate() {
        tracing::debug!(validation_error = %e, "Magic link validation failed");
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let tenant_id = extract_tenant_id(&headers);
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());

    match state
        .auth_service
        .verify_magic_link(&req.token, Some(addr.to_string()), None)
        .await
    {
        Ok(auth_result) => {
            // Log successful magic link usage
            audit.log_magic_link(
                &tenant_id,
                Some(&auth_result.user.id),
                &auth_result.user.email,
                context,
                crate::audit::AuditAction::MagicLinkUsed,
                true,
                None,
            );

            let access_token = match apply_token_issue_actions(
                &state,
                &tenant_id,
                &auth_result.user.id,
                &auth_result.access_token,
            )
            .await
            {
                Ok(token) => token,
                Err(ApiError::Forbidden) => return Err(StatusCode::FORBIDDEN),
                Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
            };

            Ok(Json(AuthResponse {
                access_token,
                refresh_token: auth_result.refresh_token,
                user: UserResponse {
                    id: auth_result.user.id,
                    email: auth_result.user.email,
                    email_verified: auth_result.user.email_verified,
                    name: auth_result.user.profile.name,
                    mfa_enabled: auth_result.user.mfa_enabled,
                },
                mfa_required: false,
                session_info: None,
            }))
        }
        Err(e) => {
            tracing::warn!(error = %e, "Magic link verification failed");
            // Log failed magic link usage
            audit.log_magic_link(
                &tenant_id,
                None,
                "unknown",
                context,
                crate::audit::AuditAction::MagicLinkFailed,
                false,
                Some(&e.to_string()),
            );
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

/// Request password reset
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        email = %req.email,
        ip_address = %addr.ip(),
        action = "forgot_password",
        success = tracing::field::Empty,
    )
)]
async fn forgot_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    if let Err(e) = req.validate() {
        tracing::warn!(validation_error = %e, "Forgot password validation failed");
        return Err(StatusCode::BAD_REQUEST);
    }

    let tenant_id = extract_tenant_id(&headers);
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let email = req.email.clone();
    let audit = AuditLogger::new(state.db.clone());

    match state
        .auth_service
        .request_password_reset(&tenant_id, &req.email)
        .await
    {
        Ok(_) => {
            // Log password reset request
            audit.log_password_reset_requested(&tenant_id, &email, context);

            Ok(Json(MessageResponse {
                message: "Password reset email sent".to_string(),
            }))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to send password reset");
            // Don't reveal if email exists to the client, but log it
            audit.log(
                &tenant_id,
                crate::audit::AuditAction::PasswordResetRequested,
                crate::audit::ResourceType::Password,
                &email,
                None,
                None,
                context,
                false,
                Some(e.to_string()),
                Some(serde_json::json!({ "email": email })),
            );
            Ok(Json(MessageResponse {
                message: "Password reset email sent".to_string(),
            }))
        }
    }
}

/// Reset password with token
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        ip_address = %addr.ip(),
        action = "reset_password",
        success = tracing::field::Empty,
    )
)]
async fn reset_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Validate input
    if let Err(e) = req.validate() {
        tracing::debug!(validation_error = %e, "Reset password validation failed");
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let tenant_id = extract_tenant_id(&headers);
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());

    // Validate password against policy (without user info for token-based reset)
    let validation_result = state
        .security_service
        .validate_password(&req.new_password, None)
        .await;

    if !validation_result.is_valid {
        let policy = state.security_service.policy();

        match policy.enforcement_mode {
            EnforcementMode::Block => {
                tracing::warn!(
                    error_codes = ?validation_result.error_codes(),
                    "Password reset rejected due to password policy violations"
                );

                audit.log(
                    &tenant_id,
                    crate::audit::AuditAction::PasswordResetFailed,
                    crate::audit::ResourceType::Password,
                    &req.token,
                    None,
                    None,
                    context.clone(),
                    false,
                    Some("Password policy violation".to_string()),
                    Some(serde_json::json!({
                        "errors": validation_result.error_messages(),
                        "codes": validation_result.error_codes(),
                    })),
                );

                return Err(StatusCode::BAD_REQUEST);
            }
            EnforcementMode::Warn | EnforcementMode::Audit => {
                let mode = if matches!(policy.enforcement_mode, EnforcementMode::Warn) {
                    "warn"
                } else {
                    "audit"
                };
                tracing::info!(
                    enforcement_mode = mode,
                    error_codes = ?validation_result.error_codes(),
                    "Password policy violations detected during reset (allowed)"
                );
            }
        }
    }

    match state
        .auth_service
        .reset_password(&req.token, &req.new_password)
        .await
    {
        Ok(()) => {
            // Log successful password reset
            // Note: We don't have user_id here since reset_password returns ()
            audit.log(
                &tenant_id,
                crate::audit::AuditAction::PasswordReset,
                crate::audit::ResourceType::Password,
                &req.token,
                None,
                None,
                context,
                true,
                None,
                None,
            );

            Ok(Json(MessageResponse {
                message: "Password reset successful".to_string(),
            }))
        }
        Err(e) => {
            tracing::warn!(error = %e, "Password reset failed");
            // Log failed password reset - we don't have user_id here
            audit.log(
                &tenant_id,
                crate::audit::AuditAction::PasswordResetFailed,
                crate::audit::ResourceType::Password,
                &req.token,
                None,
                None,
                context,
                false,
                Some(e.to_string()),
                None,
            );
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

/// Verify email address
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        ip_address = %addr.ip(),
        action = "verify_email",
        success = tracing::field::Empty,
    )
)]
async fn verify_email(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    // Validate input
    if let Err(e) = req.validate() {
        tracing::debug!(validation_error = %e, "Email verification validation failed");
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let tenant_id = extract_tenant_id(&headers);
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());

    match state.auth_service.verify_email(&req.token).await {
        Ok(user) => {
            // Log successful email verification
            audit.log_email_verification(&tenant_id, &user.id, context, true, None);

            // Trigger webhook event
            crate::webhooks::events::trigger_email_verified(
                &state,
                &tenant_id,
                &user.id,
                &user.email,
            )
            .await;

            Ok(Json(UserResponse {
                id: user.id,
                email: user.email,
                email_verified: user.email_verified,
                name: user.profile.name,
                mfa_enabled: user.mfa_enabled,
            }))
        }
        Err(e) => {
            tracing::warn!(error = %e, "Email verification failed");
            // Log failed email verification
            audit.log_email_verification(
                &tenant_id,
                "unknown",
                context,
                false,
                Some(&e.to_string()),
            );
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

/// OAuth redirect - generates authorization URL for the provider
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        provider = %provider,
        action = "oauth_redirect",
    )
)]
async fn oauth_redirect(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<OAuthRequest>,
) -> Result<Json<OAuthRedirectResponse>, ApiError> {
    // Validate input
    req.validate()
        .map_err(|e| ApiError::Validation(format!("Invalid request: {}", e)))?;
    
    let tenant_id = extract_tenant_id(&headers);

    // Parse provider and get config
    let (oauth_config, provider_enum) = get_oauth_config(&state, &provider)?;

    // Generate state parameter for CSRF protection
    let state_param = vault_core::auth::oauth::generate_state();

    // Generate PKCE code verifier if needed
    let code_verifier = if oauth_config.pkce_enabled {
        Some(vault_core::auth::oauth::generate_code_verifier())
    } else {
        None
    };

    // Store state in Redis/session for verification in callback
    // Store as "oauth:state:{state}" -> {tenant_id}:{provider}:{code_verifier}:{link_mode}
    let link_mode = if req.link == Some(true) {
        "link"
    } else {
        "auth"
    };
    let state_value = format!(
        "{}:{}:{}:{}",
        tenant_id,
        provider,
        code_verifier.as_deref().unwrap_or(""),
        link_mode
    );

    if let Some(ref redis) = state.redis {
        let mut conn = redis.clone();
        let redis_key = format!("oauth:state:{}", state_param);
        let _: Result<(), _> = redis::cmd("SETEX")
            .arg(&redis_key)
            .arg(600) // 10 minutes expiry
            .arg(&state_value)
            .query_async(&mut conn)
            .await;
    } else {
        // Without Redis, we'll use a signed state that includes the data
        // This is a fallback - in production Redis should be used
        tracing::warn!("Redis not available, OAuth state verification may be less secure (fallback mode)");
    }

    // Build authorization URL
    let auth_service = vault_core::auth::oauth::OAuthService::new(oauth_config);
    let auth_url_req = vault_core::auth::oauth::AuthUrlRequest {
        state: state_param.clone(),
        code_verifier,
        scopes: vec![],
    };

    let auth_url = auth_service.get_authorization_url(auth_url_req);

    tracing::info!(
        provider = provider_enum.name(),
        mode = link_mode,
        "Generated OAuth redirect URL"
    );

    Ok(Json(OAuthRedirectResponse {
        auth_url,
        state: state_param,
    }))
}

/// OAuth callback query parameters
#[derive(Debug, Deserialize)]
struct OAuthCallbackQuery {
    code: String,
    state: String,
    error: Option<String>,
}

/// Apple OAuth callback form data (uses form_post response mode)
#[derive(Debug, Deserialize)]
struct AppleOAuthCallbackForm {
    code: String,
    state: String,
    error: Option<String>,
    /// User info is only sent on first authorization (JSON string)
    user: Option<String>,
}

/// Apple user info sent on first authorization
#[derive(Debug, Deserialize)]
struct AppleUserInfo {
    name: Option<AppleName>,
    email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AppleName {
    first_name: Option<String>,
    last_name: Option<String>,
}

/// OAuth callback - handles the OAuth provider callback
#[tracing::instrument(
    skip(state, params),
    fields(
        tenant_id = tracing::field::Empty,
        provider = %provider,
        ip_address = %addr.ip(),
        action = "oauth_callback",
        success = tracing::field::Empty,
    )
)]
async fn oauth_callback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(provider): Path<String>,
    Query(params): Query<OAuthCallbackQuery>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Check for OAuth error
    if let Some(error) = params.error {
        tracing::warn!(oauth_error = %error, "OAuth callback error");
        return Err(ApiError::BadRequest(format!("OAuth error: {}", error)));
    }

    // Parse provider and get config
    let (oauth_config, provider_enum) = get_oauth_config(&state, &provider)
        .map_err(|_| ApiError::BadRequest("Invalid OAuth provider".to_string()))?;

    // Verify state parameter and retrieve stored data
    let (tenant_id, stored_provider, code_verifier, _is_link_mode) =
        verify_oauth_state(&state, &params.state)
            .await
            .map_err(|_| ApiError::BadRequest("Invalid OAuth state".to_string()))?;

    // Verify provider matches
    if stored_provider != provider {
        tracing::warn!(
            expected = stored_provider,
            got = provider.as_str(),
            "OAuth provider mismatch"
        );
        return Err(ApiError::BadRequest("OAuth provider mismatch".to_string()));
    }

    // Exchange code for access token
    let oauth_service = vault_core::auth::oauth::OAuthService::new(oauth_config);
    let token_response = oauth_service
        .exchange_code(&params.code, code_verifier.as_deref())
        .await
        .map_err(|e| {
            tracing::error!("OAuth token exchange failed: {}", e);
            ApiError::internal()
        })?;

    // Fetch user info from provider
    let user_info = oauth_service
        .get_user_info(&token_response.access_token)
        .await
        .map_err(|e| {
            tracing::error!("OAuth user info fetch failed: {}", e);
            ApiError::internal()
        })?;

    // Extract email - required for account creation/linking
    let email = user_info.email.ok_or_else(|| {
        tracing::warn!("OAuth provider did not return email");
        ApiError::BadRequest("Email not provided by OAuth provider".to_string())
    })?;

    tracing::info!(
        provider = provider_enum.name(),
        email = %email,
        "OAuth login attempt"
    );

    let audit = AuditLogger::new(state.db.clone());
    let context = Some(RequestContext::from_request(
        &axum::http::HeaderMap::new(),
        Some(&ConnectInfo(addr)),
    ));

    let ip_str = addr.ip().to_string();

    // Check if user exists by email
    let user = match state.db.users().find_by_email(&tenant_id, &email).await {
        Ok(Some(existing_user)) => {
            // User exists - update OAuth connection info if needed
            tracing::info!(user_id = %existing_user.id, "Existing user logging in via OAuth");
            existing_user
        }
        Ok(None) => {
            // Check if OAuth signup is enabled
            if !state.config.features.enable_oauth_signup {
                tracing::warn!(email = %email, "OAuth signup disabled, rejecting new user");
                audit.log_oauth_login(
                    &tenant_id,
                    "unknown",
                    provider_enum.name(),
                    context.clone(),
                    false,
                    Some("OAuth signup disabled"),
                );
                return Err(ApiError::Forbidden);
            }

            // Create new user
            tracing::info!(email = %email, "Creating new user via OAuth");

            // Build profile from OAuth user info
            let profile = serde_json::json!({
                "name": user_info.name,
                "given_name": user_info.given_name,
                "family_name": user_info.family_name,
                "picture": user_info.picture,
                "oauth_provider": provider_enum.name(),
                "oauth_id": user_info.id,
            });

            let create_req = vault_core::db::users::CreateUserRequest {
                tenant_id: tenant_id.clone(),
                email: email.clone(),
                password_hash: None, // No password for OAuth users
                email_verified: user_info.email_verified,
                profile: Some(profile),
                metadata: None,
            };

            state.db.users().create(create_req).await.map_err(|e| {
                tracing::error!("Failed to create OAuth user: {}", e);
                ApiError::internal()
            })?
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error looking up user");
            return Err(ApiError::internal());
        }
    };

    // Check if user account is active
    use vault_core::models::user::UserStatus;
    if user.status != UserStatus::Active {
        tracing::warn!(user_id = %user.id, email = %email, "OAuth login attempt for inactive account");
        audit.log_oauth_login(
            &tenant_id,
            &user.id,
            provider_enum.name(),
            context.clone(),
            false,
            Some("Account not active"),
        );
        return Err(ApiError::Forbidden);
    }

    // Check if user is locked
    if user.is_locked() {
        tracing::warn!(user_id = %user.id, email = %email, "OAuth login attempt for locked account");
        audit.log_oauth_login(
            &tenant_id,
            &user.id,
            provider_enum.name(),
            context.clone(),
            false,
            Some("Account locked"),
        );
        return Err(ApiError::Forbidden);
    }

    // Check session limits before creating session
    match state
        .check_session_limits(&tenant_id, &user.id, Some(&ip_str))
        .await
    {
        Ok(Ok(())) => {
            // Session limits passed, continue with login
        }
        Ok(Err(limit_err)) => {
            // Session limit reached - deny login
            tracing::warn!(
                user_id = %user.id,
                current_sessions = limit_err.current_sessions,
                max_sessions = limit_err.max_sessions,
                "Session limit reached for user"
            );

            audit.log_oauth_login(
                &tenant_id,
                &user.id,
                provider_enum.name(),
                context.clone(),
                false,
                Some("SESSION_LIMIT_REACHED"),
            );

            return Err(ApiError::SessionLimitReached(limit_err));
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to check session limits");
            return Err(ApiError::internal());
        }
    }

    // Record successful login
    let ip = addr.ip();
    state
        .db
        .users()
        .record_login_success(&tenant_id, &user.id, Some(ip))
        .await
        .ok();

    // Create session for the user
    let session = state
        .auth_service
        .create_session_for_oauth_user(&user, Some(addr.to_string()), None)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create session: {}", e);
            ApiError::internal()
        })?;

    // Store session in database
    let session_req = vault_core::db::sessions::CreateSessionRequest {
        tenant_id: tenant_id.clone(),
        user_id: user.id.clone(),
        access_token_jti: session.access_token_jti.clone(),
        refresh_token_hash: session.refresh_token_hash.clone(),
        token_family: session.token_family.clone(),
        ip_address: Some(ip),
        user_agent: None,
        device_fingerprint: None,
        device_info: serde_json::json!({
            "oauth_provider": provider_enum.name(),
        }),
        location: None,
        mfa_verified: false, // OAuth users don't need MFA on first login
        expires_at: session.expires_at,
        bind_to_ip: state.config.security.session_binding.bind_to_ip,
        bind_to_device: state.config.security.session_binding.bind_to_device,
    };

    state.db.sessions().create(session_req).await.map_err(|e| {
        tracing::error!("Failed to store session: {}", e);
        ApiError::internal()
    })?;

    // Generate tokens
    let token_pair = state
        .auth_service
        .generate_tokens(&user, &session.id)
        .map_err(|e| {
            tracing::error!("Failed to generate tokens: {}", e);
            ApiError::internal()
        })?;

    let access_token = apply_token_issue_actions(
        &state,
        &tenant_id,
        &user.id,
        &token_pair.access_token,
    )
    .await?;

    tracing::info!(
        provider = provider_enum.name(),
        user_id = %user.id,
        email = %email,
        "OAuth login successful"
    );

    // Log successful OAuth login
    audit.log_oauth_login(
        &tenant_id,
        &user.id,
        provider_enum.name(),
        context.clone(),
        true,
        None,
    );

    // Get session limit status for response
    let limit_status = state
        .get_session_limit_status(&tenant_id, &user.id)
        .await
        .unwrap_or(SessionLimitStatus {
            current_sessions: 1,
            max_sessions: state.config.security.session_limits.max_concurrent_sessions,
            warning: None,
        });

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: token_pair.refresh_token,
        user: UserResponse {
            id: user.id,
            email: user.email,
            email_verified: user.email_verified,
            name: user.profile.name.clone(),
            mfa_enabled: user.mfa_enabled,
        },
        mfa_required: false,
        session_info: Some(SessionInfoResponse {
            session_id: session.id.clone(),
            current_sessions: limit_status.current_sessions,
            max_sessions: limit_status.max_sessions,
            warning: limit_status.warning,
        }),
    }))
}

/// Apple OAuth callback - handles form_post from Apple
/// Apple uses form_post response mode which sends data as POST body
#[tracing::instrument(
    skip(state, form),
    fields(
        tenant_id = tracing::field::Empty,
        ip_address = %addr.ip(),
        action = "apple_oauth_callback",
        success = tracing::field::Empty,
    )
)]
async fn apple_oauth_callback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::Form(form): axum::extract::Form<AppleOAuthCallbackForm>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Parse Apple user info if present (only on first authorization)
    let apple_user: Option<AppleUserInfo> = if let Some(user_str) = &form.user {
        serde_json::from_str(user_str).ok()
    } else {
        None
    };

    // Check for OAuth error
    if let Some(error) = form.error {
        tracing::warn!(oauth_error = %error, "Apple OAuth callback error");
        return Err(ApiError::BadRequest(format!("OAuth error: {}", error)));
    }

    // Get OAuth config for Apple
    let (oauth_config, provider_enum) = get_oauth_config(&state, "apple")
        .map_err(|_| ApiError::BadRequest("Apple OAuth not configured".to_string()))?;
    let apple_client_id = oauth_config.client_id.clone();

    // Verify state parameter
    let (tenant_id, stored_provider, code_verifier, _is_link_mode) =
        verify_oauth_state(&state, &form.state)
            .await
            .map_err(|_| ApiError::BadRequest("Invalid OAuth state".to_string()))?;

    // Verify provider matches
    if stored_provider != "apple" {
        tracing::warn!(
            expected = "apple",
            got = stored_provider,
            "OAuth provider mismatch"
        );
        return Err(ApiError::BadRequest("OAuth provider mismatch".to_string()));
    }

    // Exchange code for tokens
    let oauth_service = vault_core::auth::oauth::OAuthService::new(oauth_config);
    let token_response = oauth_service
        .exchange_code(&form.code, code_verifier.as_deref())
        .await
        .map_err(|e| {
            tracing::error!("Apple OAuth token exchange failed: {}", e);
            ApiError::internal()
        })?;

    // Get user info from ID token (Apple doesn't have a userinfo endpoint)
    // The ID token is a JWT that contains the user claims
    let mut user_info = if let Some(id_token) = &token_response.id_token {
        // Decode and verify the ID token to get user info
        decode_apple_id_token(id_token, &apple_client_id).await?
    } else {
        return Err(ApiError::BadRequest("Missing ID token from Apple".to_string()));
    };

    // Merge Apple user info from form (only on first auth) with ID token claims
    if let Some(apple_user_info) = apple_user {
        if user_info.email.is_none() && apple_user_info.email.is_some() {
            user_info.email = apple_user_info.email;
            user_info.email_verified = true;
        }
        if let Some(name) = apple_user_info.name {
            let first = name.first_name.clone().unwrap_or_default();
            let last = name.last_name.clone().unwrap_or_default();
            let full = format!("{} {}", first, last).trim().to_string();
            if !full.is_empty() {
                user_info.name = Some(full);
            }
            user_info.given_name = name.first_name;
            user_info.family_name = name.last_name;
        }
    }

    // Extract email - required for account creation/linking
    let email = user_info.email.clone().ok_or_else(|| {
        tracing::warn!("Apple OAuth did not return email");
        ApiError::BadRequest("Email not provided by Apple".to_string())
    })?;

    tracing::info!(email = %email, "Apple OAuth login attempt");

    let audit = AuditLogger::new(state.db.clone());
    let context = Some(RequestContext::from_request(
        &axum::http::HeaderMap::new(),
        Some(&ConnectInfo(addr)),
    ));

    // Process the OAuth login (same logic as generic callback)
    process_oauth_login(
        &state,
        &tenant_id,
        &email,
        &user_info,
        provider_enum,
        &addr,
        &context,
        &audit,
    )
    .await
}

/// Decode and verify Apple ID token (JWT) to extract user info
/// 
/// SECURITY: This function verifies the token signature using Apple's public keys.
/// The keys are fetched from Apple's JWKS endpoint and cached.
async fn decode_apple_id_token(
    token: &str,
    expected_audience: &str,
) -> Result<vault_core::auth::oauth::OAuthUserInfo, ApiError> {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
    use serde::{Deserialize, Serialize};

    /// Apple JWKS response
    #[derive(Debug, Deserialize)]
    struct AppleJwks {
        keys: Vec<AppleJwk>,
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    struct AppleJwk {
        kty: String,
        kid: String,
        use_: Option<String>,
        #[serde(rename = "use")]
        key_use: Option<String>,
        n: String,
        e: String,
    }

    // Parse the token header to get the key ID
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ApiError::BadRequest("Invalid ID token format".to_string()));
    }

    // Decode header to get key ID
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|e| ApiError::BadRequest(format!("Invalid ID token header: {}", e)))?;
    
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| ApiError::BadRequest(format!("Invalid ID token header JSON: {}", e)))?;
    
    let kid = header["kid"].as_str()
        .ok_or_else(|| ApiError::BadRequest("Missing key ID in token header".to_string()))?;

    // Fetch Apple's JWKS
    let jwks: AppleJwks = reqwest::get("https://appleid.apple.com/auth/keys")
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to fetch Apple JWKS: {}", e)))?
        .json()
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to parse Apple JWKS: {}", e)))?;

    // Find the matching key
    let jwk = jwks.keys.iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| ApiError::BadRequest("Unknown key ID in token".to_string()))?;

    // Create decoding key from JWK
    let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| ApiError::internal_error(format!("Failed to create decoding key: {}", e)))?;

    // Verify and decode the token
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["https://appleid.apple.com"]);
    validation.set_audience(&[expected_audience]);
    
    let token_data = decode::<serde_json::Value>(token, &decoding_key, &validation)
        .map_err(|e| ApiError::BadRequest(format!("Token verification failed: {}", e)))?;

    let claims = token_data.claims;

    let user_info = vault_core::auth::oauth::OAuthUserInfo {
        id: claims["sub"].as_str().unwrap_or("").to_string(),
        email: claims["email"].as_str().map(String::from),
        email_verified: claims["email_verified"].as_bool().unwrap_or(false),
        name: None, // Name is only provided on first authorization via form data
        given_name: None,
        family_name: None,
        picture: None,
        username: None,
        locale: None,
        provider: Some(vault_core::auth::oauth::OAuthProvider::Apple),
        raw: claims,
    };

    Ok(user_info)
}

/// Process OAuth login - shared logic between GET and POST callbacks
async fn process_oauth_login(
    state: &AppState,
    tenant_id: &str,
    email: &str,
    user_info: &vault_core::auth::oauth::OAuthUserInfo,
    provider_enum: vault_core::auth::oauth::OAuthProvider,
    addr: &SocketAddr,
    context: &Option<RequestContext>,
    audit: &AuditLogger,
) -> Result<Json<AuthResponse>, ApiError> {
    let ip_str = addr.ip().to_string();

    // Check if user exists by email
    let user = match state.db.users().find_by_email(tenant_id, email).await {
        Ok(Some(existing_user)) => {
            tracing::info!("Existing user logging in via OAuth: {}", email);
            existing_user
        }
        Ok(None) => {
            // Check if OAuth signup is enabled
            if !state.config.features.enable_oauth_signup {
                tracing::warn!("OAuth signup disabled, rejecting new user: {}", email);
                audit.log_oauth_login(
                    tenant_id,
                    "unknown",
                    provider_enum.name(),
                    context.clone(),
                    false,
                    Some("OAuth signup disabled"),
                );
                return Err(ApiError::Forbidden);
            }

            // Create new user
            tracing::info!("Creating new user via OAuth: {}", email);

            let profile = serde_json::json!({
                "name": user_info.name,
                "given_name": user_info.given_name,
                "family_name": user_info.family_name,
                "oauth_provider": provider_enum.name(),
                "oauth_id": user_info.id,
            });

            let create_req = vault_core::db::users::CreateUserRequest {
                tenant_id: tenant_id.to_string(),
                email: email.to_string(),
                password_hash: None,
                email_verified: user_info.email_verified,
                profile: Some(profile),
                metadata: None,
            };

            state.db.users().create(create_req).await.map_err(|e| {
                tracing::error!("Failed to create OAuth user: {}", e);
                ApiError::internal()
            })?
        }
        Err(e) => {
            tracing::error!("Database error looking up user: {}", e);
            return Err(ApiError::internal());
        }
    };

    // Check if user account is active
    use vault_core::models::user::UserStatus;
    if user.status != UserStatus::Active {
        tracing::warn!("OAuth login attempt for inactive account: {}", email);
        audit.log_oauth_login(
            tenant_id,
            &user.id,
            provider_enum.name(),
            context.clone(),
            false,
            Some("Account not active"),
        );
        return Err(ApiError::Forbidden);
    }

    // Check if user is locked
    if user.is_locked() {
        tracing::warn!("OAuth login attempt for locked account: {}", email);
        audit.log_oauth_login(
            tenant_id,
            &user.id,
            provider_enum.name(),
            context.clone(),
            false,
            Some("Account locked"),
        );
        return Err(ApiError::Forbidden);
    }

    // Check session limits
    match state
        .check_session_limits(tenant_id, &user.id, Some(&ip_str))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(limit_err)) => {
            tracing::warn!(
                "Session limit reached for user {}: {}/{} sessions",
                user.id,
                limit_err.current_sessions,
                limit_err.max_sessions
            );
            audit.log_oauth_login(
                tenant_id,
                &user.id,
                provider_enum.name(),
                context.clone(),
                false,
                Some("SESSION_LIMIT_REACHED"),
            );
            return Err(ApiError::SessionLimitReached(limit_err));
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to check session limits");
            return Err(ApiError::internal());
        }
    }

    // Record successful login
    let ip = addr.ip();
    state
        .db
        .users()
        .record_login_success(tenant_id, &user.id, Some(ip))
        .await
        .ok();

    // Create session
    let session = state
        .auth_service
        .create_session_for_oauth_user(&user, Some(addr.to_string()), None)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create session: {}", e);
            ApiError::internal()
        })?;

    // Store session in database
    let session_req = vault_core::db::sessions::CreateSessionRequest {
        tenant_id: tenant_id.to_string(),
        user_id: user.id.clone(),
        access_token_jti: session.access_token_jti.clone(),
        refresh_token_hash: session.refresh_token_hash.clone(),
        token_family: session.token_family.clone(),
        ip_address: Some(ip),
        user_agent: None,
        device_fingerprint: None,
        device_info: serde_json::json!({
            "oauth_provider": provider_enum.name(),
        }),
        location: None,
        mfa_verified: false,
        expires_at: session.expires_at,
        bind_to_ip: state.config.security.session_binding.bind_to_ip,
        bind_to_device: state.config.security.session_binding.bind_to_device,
    };

    state.db.sessions().create(session_req).await.map_err(|e| {
        tracing::error!("Failed to store session: {}", e);
        ApiError::internal()
    })?;

    // Generate tokens
    let token_pair = state
        .auth_service
        .generate_tokens(&user, &session.id)
        .map_err(|e| {
            tracing::error!("Failed to generate tokens: {}", e);
            ApiError::internal()
        })?;

    let access_token = apply_token_issue_actions(
        &state,
        tenant_id,
        &user.id,
        &token_pair.access_token,
    )
    .await?;

    tracing::info!(
        "OAuth login successful: provider={}, email={}",
        provider_enum.name(),
        email
    );

    audit.log_oauth_login(
        tenant_id,
        &user.id,
        provider_enum.name(),
        context.clone(),
        true,
        None,
    );

    let limit_status = state
        .get_session_limit_status(tenant_id, &user.id)
        .await
        .unwrap_or(SessionLimitStatus {
            current_sessions: 1,
            max_sessions: state.config.security.session_limits.max_concurrent_sessions,
            warning: None,
        });

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: token_pair.refresh_token,
        user: UserResponse {
            id: user.id,
            email: user.email,
            email_verified: user.email_verified,
            name: user.profile.name.clone(),
            mfa_enabled: user.mfa_enabled,
        },
        mfa_required: false,
        session_info: Some(SessionInfoResponse {
            session_id: session.id.clone(),
            current_sessions: limit_status.current_sessions,
            max_sessions: limit_status.max_sessions,
            warning: limit_status.warning,
        }),
    }))
}

/// Get OAuth configuration for a provider
fn get_oauth_config(
    state: &AppState,
    provider: &str,
) -> Result<
    (
        vault_core::auth::oauth::OAuthConfig,
        vault_core::auth::oauth::OAuthProvider,
    ),
    ApiError,
> {
    let provider_lower = provider.to_lowercase();

    let provider_config = match provider_lower.as_str() {
        "google" => state.config.oauth.google.clone(),
        "github" => state.config.oauth.github.clone(),
        "microsoft" => state.config.oauth.microsoft.clone(),
        "apple" => state.config.oauth.apple.clone(),
        _ => {
            tracing::warn!("Unsupported OAuth provider: {}", provider);
            return Err(ApiError::BadRequest(format!(
                "Unsupported OAuth provider: {}",
                provider
            )));
        }
    };

    let config = provider_config.ok_or_else(|| {
        tracing::warn!("OAuth provider not configured: {}", provider);
        ApiError::internal()
    })?;

    let provider_enum = match provider_lower.as_str() {
        "google" => vault_core::auth::oauth::OAuthProvider::Google,
        "github" => vault_core::auth::oauth::OAuthProvider::GitHub,
        "microsoft" => vault_core::auth::oauth::OAuthProvider::Microsoft,
        "apple" => vault_core::auth::oauth::OAuthProvider::Apple,
        _ => {
            return Err(ApiError::BadRequest(format!(
                "Unsupported OAuth provider: {}",
                provider
            )))
        }
    };

    // Build Apple credentials if this is Apple OAuth
    let apple_credentials = if provider_enum == vault_core::auth::oauth::OAuthProvider::Apple {
        config
            .apple_config
            .map(|apple| vault_core::auth::oauth::AppleOAuthCredentials {
                client_id: config.client_id.clone(),
                team_id: apple.team_id,
                key_id: apple.key_id,
                private_key: apple.private_key,
                redirect_uri: config.redirect_uri.clone(),
            })
    } else {
        None
    };

    let oauth_config = vault_core::auth::oauth::OAuthConfig {
        provider: provider_enum.clone(),
        client_id: config.client_id,
        client_secret: config.client_secret,
        redirect_uri: config.redirect_uri,
        scopes: vec![],
        pkce_enabled: true, // Enable PKCE by default for security
        apple_credentials,
        extra_config: None,
    };

    Ok((oauth_config, provider_enum))
}

/// Verify OAuth state parameter and return stored data
/// Returns: (tenant_id, provider, code_verifier, is_link_mode)
async fn verify_oauth_state(
    state: &AppState,
    state_param: &str,
) -> Result<(String, String, Option<String>, bool), ApiError> {
    // Try Redis first
    if let Some(ref redis) = state.redis {
        let mut conn = redis.clone();
        let redis_key = format!("oauth:state:{}", state_param);

        let stored: Option<String> = redis::cmd("GET")
            .arg(&redis_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("Redis error reading OAuth state: {}", e);
                ApiError::internal()
            })?;

        let stored = stored.ok_or_else(|| {
            tracing::warn!("OAuth state not found or expired");
            ApiError::BadRequest("OAuth state not found or expired".to_string())
        })?;

        // Delete the state to prevent replay attacks
        let _: Result<(), _> = redis::cmd("DEL")
            .arg(&redis_key)
            .query_async(&mut conn)
            .await;

        // Parse stored data: tenant_id:provider:code_verifier:link_mode
        let parts: Vec<&str> = stored.splitn(4, ':').collect();
        if parts.len() < 2 {
            return Err(ApiError::BadRequest(
                "Invalid OAuth state format".to_string(),
            ));
        }

        let tenant_id = parts[0].to_string();
        let provider = parts[1].to_string();
        let code_verifier = if parts.len() > 2 && !parts[2].is_empty() {
            Some(parts[2].to_string())
        } else {
            None
        };
        let is_link_mode = parts.len() > 3 && parts[3] == "link";

        return Ok((tenant_id, provider, code_verifier, is_link_mode));
    }

    // Without Redis, we can't properly verify state
    // This is a fallback that should not be used in production
    tracing::error!("Redis not available for OAuth state verification");
    Err(ApiError::internal())
}

/// SSO redirect - returns provider redirect URL
async fn sso_redirect(
    State(_state): State<AppState>,
    Query(params): Query<SsoRedirectQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let target = params
        .domain
        .or(params.connection_id)
        .unwrap_or_else(|| "sso".to_string());
    Ok(Json(serde_json::json!({
        "url": format!("https://sso.example.com/redirect/{}", target)
    })))
}

/// SSO callback - handles IdP response
/// 
/// SECURITY: This endpoint validates the SAML/OAuth response from the identity provider,
/// verifies the signature, and exchanges it for local authentication tokens.
/// 
/// NOTE: This is a security-critical endpoint. The previous placeholder implementation
/// that returned hardcoded fake tokens has been removed as it was a critical 
/// authentication bypass vulnerability.
async fn sso_callback(
    State(_state): State<AppState>,
    Json(_req): Json<SsoCallbackRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    // CRITICAL SECURITY FIX: Previous implementation returned hardcoded fake tokens
    // which would have allowed complete authentication bypass. This endpoint must
    // be properly implemented before enabling SSO functionality.
    tracing::error!("SSO callback invoked but not implemented - rejecting request");
    Err(StatusCode::NOT_IMPLEMENTED)
}

/// SSO metadata (SAML)
async fn sso_metadata(
    State(_state): State<AppState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<(StatusCode, [(&'static str, &'static str); 1], String), StatusCode> {
    let connection_id = params
        .get("connection_id")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let xml = format!(
        "<EntityDescriptor entityID=\"vault:{}\"><IDPSSODescriptor/></EntityDescriptor>",
        connection_id
    );
    Ok((StatusCode::OK, [("Content-Type", "application/xml")], xml))
}

// ============ WebAuthn/Passkey Types ============

#[derive(Debug, Deserialize)]
struct WebAuthnRegisterBeginRequest {
    /// Whether to create a passkey (discoverable credential)
    #[serde(rename = "isPasskey")]
    is_passkey: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct WebAuthnRegisterFinishRequest {
    /// Credential response from authenticator
    credential: vault_core::webauthn::RegistrationCredentialResponse,
}

#[derive(Debug, Deserialize)]
struct WebAuthnAuthenticateBeginRequest {
    /// User ID for non-discoverable credentials (optional for passkeys)
    #[serde(rename = "userId")]
    user_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebAuthnAuthenticateFinishRequest {
    /// Credential response from authenticator
    credential: vault_core::webauthn::AuthenticationCredentialResponse,
}

#[derive(Debug, Serialize)]
struct WebAuthnCredentialResponse {
    id: String,
    #[serde(rename = "credentialId")]
    credential_id: String,
    name: Option<String>,
    #[serde(rename = "isPasskey")]
    is_passkey: bool,
    #[serde(rename = "createdAt")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "lastUsedAt")]
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<vault_core::webauthn::StoredCredential> for WebAuthnCredentialResponse {
    fn from(cred: vault_core::webauthn::StoredCredential) -> Self {
        Self {
            id: cred.credential_id.clone(),
            credential_id: cred.credential_id,
            name: cred.name,
            is_passkey: cred.is_passkey,
            created_at: cred.created_at,
            last_used_at: cred.last_used_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct WebAuthnCredentialsListResponse {
    credentials: Vec<WebAuthnCredentialResponse>,
}

// ============ WebAuthn/Passkey Handlers ============

/// Begin WebAuthn registration
///
/// Starts the registration process for a new WebAuthn credential.
/// For authenticated users, this adds a new credential to their account.
/// For new passkey registrations, user authentication may not be required.
#[tracing::instrument(
    skip(state, headers, user, req),
    fields(
        tenant_id = tracing::field::Empty,
        user_id = %user.user_id,
        ip_address = %addr.ip(),
        action = "webauthn_register_begin",
    )
)]
async fn webauthn_register_begin(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<WebAuthnRegisterBeginRequest>,
) -> Result<Json<vault_core::webauthn::CredentialCreationOptions>, StatusCode> {
    let tenant_id = extract_tenant_id(&headers);
    let audit = AuditLogger::new(state.db.clone());

    // Get user info for the registration
    let user_result = state
        .auth_service
        .get_current_user(&tenant_id, &user.user_id)
        .await;
    let user_info = match user_result {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "Failed to get user info for WebAuthn registration");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Begin registration
    match state
        .webauthn_service
        .begin_registration(
            &user.user_id,
            &tenant_id,
            &user_info.profile.name.as_ref().unwrap_or(&user_info.email),
            &user_info.email,
        )
        .await
    {
        Ok(options) => {
            tracing::info!(
                is_passkey = ?req.is_passkey,
                "WebAuthn registration started"
            );
            Ok(Json(options))
        }
        Err(e) => {
            tracing::error!(error = %e, "WebAuthn registration begin failed");
            audit.log_webauthn_registration_failed(
                &tenant_id,
                &user.user_id,
                Some(RequestContext::from_request(
                    &headers,
                    Some(&ConnectInfo(addr)),
                )),
                &e.to_string(),
            );
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Finish WebAuthn registration
///
/// Completes the registration process by verifying the authenticator response
/// and storing the credential.
#[tracing::instrument(
    skip(state, headers, user, req),
    fields(
        tenant_id = tracing::field::Empty,
        user_id = %user.user_id,
        ip_address = %addr.ip(),
        action = "webauthn_register_finish",
        success = tracing::field::Empty,
    )
)]
async fn webauthn_register_finish(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<WebAuthnRegisterFinishRequest>,
) -> Result<Json<WebAuthnCredentialResponse>, StatusCode> {
    let tenant_id = extract_tenant_id(&headers);
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());

    match state
        .webauthn_service
        .finish_registration(req.credential)
        .await
    {
        Ok(credential) => {
            tracing::info!(
                credential_id = %credential.credential_id,
                "WebAuthn credential registered"
            );

            // Log successful registration
            audit.log_webauthn_registered(
                &tenant_id,
                &user.user_id,
                &credential.credential_id,
                context,
                credential.is_passkey,
            );

            Ok(Json(credential.into()))
        }
        Err(e) => {
            tracing::warn!(error = %e, "WebAuthn registration finish failed");
            audit.log_webauthn_registration_failed(
                &tenant_id,
                &user.user_id,
                context,
                &e.to_string(),
            );
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

/// Begin WebAuthn authentication
///
/// Starts the authentication process. For passkeys (discoverable credentials),
/// user_id can be omitted. For security keys, user_id is required to look up
/// the allowed credentials.
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        user_id = tracing::field::Empty,
        action = "webauthn_authenticate_begin",
    )
)]
async fn webauthn_authenticate_begin(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WebAuthnAuthenticateBeginRequest>,
) -> Result<Json<vault_core::webauthn::CredentialRequestOptions>, StatusCode> {
    let tenant_id = extract_tenant_id(&headers);
    if let Some(ref uid) = req.user_id {
        tracing::Span::current().record("user_id", uid.as_str());
    }

    match state
        .webauthn_service
        .begin_authentication(Some(&tenant_id), req.user_id.as_deref())
        .await
    {
        Ok(options) => {
            tracing::debug!("WebAuthn authentication started");
            Ok(Json(options))
        }
        Err(e) => {
            tracing::error!(error = %e, "WebAuthn authentication begin failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Finish WebAuthn authentication
///
/// Completes the WebAuthn authentication and returns tokens on success.
/// This can be used as a primary authentication method (passwordless) or
/// as an MFA step.
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        ip_address = %addr.ip(),
        action = "webauthn_authenticate_finish",
        success = tracing::field::Empty,
        user_id = tracing::field::Empty,
    )
)]
async fn webauthn_authenticate_finish(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WebAuthnAuthenticateFinishRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&headers);
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());
    let ip_str = addr.ip().to_string();

    // Finish authentication with WebAuthn service
    let auth_result = match state
        .webauthn_service
        .finish_authentication(req.credential)
        .await
    {
        Ok(result) => {
            tracing::Span::current().record("user_id", result.user_id.as_str());
            result
        }
        Err(e) => {
            tracing::warn!(error = %e, "WebAuthn authentication finish failed");
            audit.log_webauthn_authentication_failed(
                &tenant_id,
                None,
                context.clone(),
                &e.to_string(),
            );
            return Err(ApiError::Unauthorized);
        }
    };

    // Set tenant context
    if let Err(e) = state.set_tenant_context(&auth_result.tenant_id).await {
        tracing::error!("Failed to set tenant context: {}", e);
        return Err(ApiError::internal());
    }

    // Get user from database
    let user = match state
        .auth_service
        .get_current_user(&auth_result.tenant_id, &auth_result.user_id)
        .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("User not found after WebAuthn authentication: {}", e);
            return Err(ApiError::internal());
        }
    };

    // Check if user is active
    if user.status != vault_core::models::user::UserStatus::Active {
        tracing::warn!(
            "WebAuthn login attempt for inactive account: {}",
            auth_result.user_id
        );
        audit.log_webauthn_authentication_failed(
            &tenant_id,
            Some(&auth_result.credential_id),
            context.clone(),
            "Account not active",
        );
        return Err(ApiError::Forbidden);
    }

    // Check if user is locked
    if user.is_locked() {
        tracing::warn!(
            "WebAuthn login attempt for locked account: {}",
            auth_result.user_id
        );
        audit.log_webauthn_authentication_failed(
            &tenant_id,
            Some(&auth_result.credential_id),
            context.clone(),
            "Account locked",
        );
        return Err(ApiError::Forbidden);
    }

    // Check session limits before creating session
    match state
        .check_session_limits(&tenant_id, &user.id, Some(&ip_str))
        .await
    {
        Ok(Ok(())) => {
            // Session limits passed, continue with login
        }
        Ok(Err(limit_err)) => {
            // Session limit reached - deny login
            tracing::warn!(
                "Session limit reached for user {}: {}/{} sessions",
                user.id,
                limit_err.current_sessions,
                limit_err.max_sessions
            );

            audit.log_webauthn_authentication_failed(
                &tenant_id,
                Some(&auth_result.credential_id),
                context.clone(),
                "SESSION_LIMIT_REACHED",
            );

            return Err(ApiError::SessionLimitReached(limit_err));
        }
        Err(e) => {
            tracing::error!("Failed to check session limits: {}", e);
            return Err(ApiError::internal());
        }
    }

    // Create session for the user
    let session = match state
        .auth_service
        .create_session_for_oauth_user(&user, Some(addr.to_string()), None)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to create session: {}", e);
            return Err(ApiError::internal());
        }
    };

    // Store session in database
    let session_req = vault_core::db::sessions::CreateSessionRequest {
        tenant_id: tenant_id.clone(),
        user_id: user.id.clone(),
        access_token_jti: session.access_token_jti.clone(),
        refresh_token_hash: session.refresh_token_hash.clone(),
        token_family: session.token_family.clone(),
        ip_address: Some(addr.ip()),
        user_agent: context.as_ref().and_then(|c| c.user_agent.as_ref().map(|s| s.to_string())),
        device_fingerprint: None,
        device_info: serde_json::json!({
            "auth_method": "webauthn",
            "credential_id": auth_result.credential_id,
        }),
        location: None,
        mfa_verified: auth_result.user_verified,
        expires_at: session.expires_at,
        bind_to_ip: state.config.security.session_binding.bind_to_ip,
        bind_to_device: state.config.security.session_binding.bind_to_device,
    };

    if let Err(e) = state.db.sessions().create(session_req).await {
        tracing::error!("Failed to store session: {}", e);
        return Err(ApiError::internal());
    }

    // Generate tokens
    let token_pair = match state.auth_service.generate_tokens(&user, &session.id) {
        Ok(tp) => tp,
        Err(e) => {
            tracing::error!("Failed to generate tokens: {}", e);
            return Err(ApiError::internal());
        }
    };

    let access_token = apply_token_issue_actions(
        &state,
        &tenant_id,
        &user.id,
        &token_pair.access_token,
    )
    .await?;

    tracing::info!(
        "WebAuthn authentication successful for user: {}",
        auth_result.user_id
    );

    // Log successful authentication
    audit.log_webauthn_authenticated(
        &tenant_id,
        &auth_result.user_id,
        Some(&session.id),
        &auth_result.credential_id,
        context.clone(),
        auth_result.user_verified,
    );

    // Trigger webhook events
    let ip = context.as_ref().and_then(|c| c.ip_address.clone());
    let ua = context.as_ref().and_then(|c| c.user_agent.clone());

    crate::webhooks::events::trigger_session_created(
        &state,
        &tenant_id,
        &auth_result.user_id,
        &session.id,
        &user.email,
        ip.as_deref(),
        ua.as_deref(),
        "webauthn",
    )
    .await;

    crate::webhooks::events::trigger_user_login(
        &state,
        &tenant_id,
        &auth_result.user_id,
        &user.email,
        ip.as_deref(),
        ua.as_deref(),
        "webauthn",
        true,
    )
    .await;

    // Get session limit status for response
    let limit_status = state
        .get_session_limit_status(&tenant_id, &user.id)
        .await
        .unwrap_or(SessionLimitStatus {
            current_sessions: 1,
            max_sessions: state.config.security.session_limits.max_concurrent_sessions,
            warning: None,
        });

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: token_pair.refresh_token,
        user: UserResponse {
            id: user.id,
            email: user.email,
            email_verified: user.email_verified,
            name: user.profile.name,
            mfa_enabled: user.mfa_enabled,
        },
        mfa_required: false,
        session_info: Some(SessionInfoResponse {
            session_id: session.id.clone(),
            current_sessions: limit_status.current_sessions,
            max_sessions: limit_status.max_sessions,
            warning: limit_status.warning,
        }),
    }))
}

/// List user's WebAuthn credentials
///
/// Returns all WebAuthn credentials registered for the current user.
#[tracing::instrument(
    skip(state, user),
    fields(
        user_id = %user.user_id,
        tenant_id = %user.tenant_id,
        action = "list_webauthn_credentials",
    )
)]
async fn list_webauthn_credentials(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<WebAuthnCredentialsListResponse>, StatusCode> {
    match state
        .webauthn_service
        .get_credentials_for_user(&user.user_id)
        .await
    {
        Ok(credentials) => {
            let response: Vec<WebAuthnCredentialResponse> =
                credentials.into_iter().map(Into::into).collect();
            Ok(Json(WebAuthnCredentialsListResponse {
                credentials: response,
            }))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list WebAuthn credentials");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Delete a WebAuthn credential
///
/// Removes a credential from the user's account. This is useful when
/// a security key is lost or no longer needed.
#[tracing::instrument(
    skip(state, user, credential_id),
    fields(
        user_id = %user.user_id,
        tenant_id = %user.tenant_id,
        credential_id = %credential_id,
        action = "delete_webauthn_credential",
        success = tracing::field::Empty,
    )
)]
async fn delete_webauthn_credential(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(credential_id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let audit = AuditLogger::new(state.db.clone());

    // First verify the credential belongs to this user
    let credentials = match state
        .webauthn_service
        .get_credentials_for_user(&user.user_id)
        .await
    {
        Ok(creds) => creds,
        Err(e) => {
            tracing::error!("Failed to get credentials: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let credential_exists = credentials.iter().any(|c| c.credential_id == credential_id);
    if !credential_exists {
        return Err(StatusCode::NOT_FOUND);
    }

    // Delete the credential
    match state
        .webauthn_service
        .delete_credential(&credential_id)
        .await
    {
        Ok(_) => {
            tracing::info!("WebAuthn credential deleted");

            audit.log_webauthn_credential_deleted(&user.tenant_id, &user.user_id, &credential_id);

            Ok(Json(MessageResponse {
                message: "Credential deleted successfully".to_string(),
            }))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to delete WebAuthn credential");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ============ Step-up Authentication ============

/// Step-up authentication handler
///
/// Initiates step-up authentication (sudo mode) for sensitive operations.
/// Returns a short-lived elevated token upon successful verification.
///
/// # Request Body
/// ```json
/// {
///   "method": "password" | "totp" | "webauthn" | "backup_code",
///   "credentials": {
///     "password": "current_password"  // for password method
///     // or
///     "code": "123456"  // for totp or backup_code method
///     // or
///     "assertion": {...}  // for webauthn method
///   }
/// }
/// ```
///
/// # Response
/// ```json
/// {
///   "accessToken": "eyJ...",
///   "tokenType": "Bearer",
///   "expiresIn": 600,
///   "level": "elevated",
///   "stepUpExpiresAt": "2026-02-08T16:30:00Z"
/// }
/// ```
async fn step_up(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<StepUpRequest>,
) -> Result<Json<StepUpTokenResponse>, ApiError> {
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());
    let step_up_service = StepUpService::new();

    // Set tenant context
    state
        .set_tenant_context(&user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Verify the step-up authentication based on method
    let result = match req.method {
        StepUpAuthMethod::Password => {
            verify_password_step_up(&state, &user, &req.credentials).await
        }
        StepUpAuthMethod::Totp => verify_totp_step_up(&state, &user, &req.credentials).await,
        StepUpAuthMethod::Webauthn => {
            verify_webauthn_step_up(&state, &user, &req.credentials).await
        }
        StepUpAuthMethod::BackupCode => {
            verify_backup_code_step_up(&state, &user, &req.credentials).await
        }
    };

    match result {
        Ok((level, methods)) => {
            // Create step-up session
            let session = step_up_service.create_session(
                level.clone(),
                state.step_up_max_age_minutes,
                methods.clone(),
            );

            // Generate elevated token
            let token = generate_step_up_token(&state, &user, &session, &methods).await?;
            let access_token = apply_token_issue_actions(
                &state,
                &user.tenant_id,
                &user.user_id,
                &token,
            )
            .await?;

            // Log successful step-up
            audit.log(
                &user.tenant_id,
                crate::audit::AuditAction::StepUpSuccess,
                crate::audit::ResourceType::Session,
                &user.user_id,
                Some(user.user_id.clone()),
                user.session_id.clone(),
                context,
                true,
                None,
                Some(serde_json::json!({
                    "level": format!("{:?}", level).to_lowercase(),
                    "methods": methods.iter().map(|m| m.as_str()).collect::<Vec<_>>(),
                })),
            );

            let expires_at = chrono::DateTime::from_timestamp(session.expires_at, 0)
                .unwrap_or_else(|| chrono::Utc::now());

            Ok(Json(StepUpTokenResponse {
                access_token,
                token_type: "Bearer".to_string(),
                expires_in: (state.step_up_max_age_minutes * 60) as u64,
                level: format!("{:?}", level).to_lowercase(),
                step_up_expires_at: expires_at.to_rfc3339(),
            }))
        }
        Err(failure_reason) => {
            // Log failed step-up
            audit.log(
                &user.tenant_id,
                crate::audit::AuditAction::StepUpFailed,
                crate::audit::ResourceType::Session,
                &user.user_id,
                Some(user.user_id.clone()),
                user.session_id.clone(),
                context,
                false,
                Some(failure_reason.message()),
                Some(serde_json::json!({
                    "code": failure_reason.code(),
                    "method": format!("{:?}", req.method).to_lowercase(),
                })),
            );

            Err(ApiError::Forbidden)
        }
    }
}

/// Verify password for step-up
async fn verify_password_step_up(
    state: &AppState,
    user: &CurrentUser,
    credentials: &StepUpCredentials,
) -> Result<(StepUpLevel, Vec<AuthMethod>), StepUpFailureReason> {
    let password = match credentials {
        StepUpCredentials::Password { password } => password,
        _ => return Err(StepUpFailureReason::InvalidCredentials),
    };

    // Get user with password hash
    let (_, password_hash) = state
        .db
        .users()
        .find_by_email_with_password_legacy(&user.tenant_id, &user.email)
        .await
        .map_err(|e| StepUpFailureReason::InternalError(e.to_string()))?;

    // Verify password
    if let Some(hash) = password_hash {
        let valid = vault_core::crypto::VaultPasswordHasher::verify(password, &hash)
            .map_err(|e| StepUpFailureReason::InternalError(e.to_string()))?;

        if !valid {
            return Err(StepUpFailureReason::InvalidCredentials);
        }
    } else {
        // User doesn't have a password (e.g., OAuth-only user)
        return Err(StepUpFailureReason::MethodNotAvailable);
    }

    // Determine level based on MFA status
    let methods = vec![AuthMethod::Pwd];
    let level = if user.mfa_authenticated {
        StepUpLevel::Elevated
    } else {
        StepUpLevel::Standard
    };

    Ok((level, methods))
}

/// Verify TOTP for step-up
async fn verify_totp_step_up(
    state: &AppState,
    user: &CurrentUser,
    credentials: &StepUpCredentials,
) -> Result<(StepUpLevel, Vec<AuthMethod>), StepUpFailureReason> {
    let code = match credentials {
        StepUpCredentials::Totp { code } => code,
        _ => return Err(StepUpFailureReason::InvalidCredentials),
    };

    // Get TOTP secret
    let secret_encrypted = state
        .db
        .mfa()
        .get_totp_secret(&user.tenant_id, &user.user_id)
        .await
        .map_err(|e| StepUpFailureReason::InternalError(e.to_string()))?
        .ok_or(StepUpFailureReason::MfaNotConfigured)?;

    let key = state
        .tenant_key_service
        .get_data_key(&user.tenant_id)
        .await
        .map_err(|e| {
            StepUpFailureReason::InternalError(format!(
                "Failed to load tenant data key: {}",
                e
            ))
        })?;
    let secret = crate::security::encryption::decrypt_from_base64(&key, &secret_encrypted)
        .map_err(|_| StepUpFailureReason::InternalError("Failed to decrypt secret".to_string()))?;
    let secret = String::from_utf8(secret)
        .map_err(|_| StepUpFailureReason::InternalError("Invalid secret format".to_string()))?;

    // Verify TOTP code
    let totp_config = vault_core::auth::mfa::TotpConfig {
        secret,
        issuer: "Vault".to_string(),
        account_name: user.email.clone(),
        algorithm: "SHA1".to_string(),
        digits: 6,
        period: 30,
    };

    if !totp_config.verify(code, 1) {
        return Err(StepUpFailureReason::InvalidCredentials);
    }

    // Mark as used
    state
        .db
        .mfa()
        .mark_method_used(
            &user.tenant_id,
            &user.user_id,
            vault_core::db::mfa::MfaMethodType::Totp,
        )
        .await
        .ok();

    Ok((StepUpLevel::Elevated, vec![AuthMethod::Totp]))
}

/// Verify WebAuthn for step-up
async fn verify_webauthn_step_up(
    state: &AppState,
    user: &CurrentUser,
    credentials: &StepUpCredentials,
) -> Result<(StepUpLevel, Vec<AuthMethod>), StepUpFailureReason> {
    let assertion = match credentials {
        StepUpCredentials::Webauthn { assertion } => assertion,
        _ => return Err(StepUpFailureReason::InvalidCredentials),
    };

    // Parse credential response
    let credential_response: vault_core::webauthn::AuthenticationCredentialResponse =
        serde_json::from_value(assertion.clone())
            .map_err(|_| StepUpFailureReason::InvalidCredentials)?;

    // Verify WebAuthn authentication
    let auth_result = state
        .webauthn_service
        .finish_authentication(credential_response)
        .await
        .map_err(|_| StepUpFailureReason::InvalidCredentials)?;

    // Verify the authentication belongs to this user
    if auth_result.user_id != user.user_id {
        return Err(StepUpFailureReason::InvalidCredentials);
    }

    Ok((StepUpLevel::HighAssurance, vec![AuthMethod::Webauthn]))
}

/// Verify backup code for step-up
async fn verify_backup_code_step_up(
    state: &AppState,
    user: &CurrentUser,
    credentials: &StepUpCredentials,
) -> Result<(StepUpLevel, Vec<AuthMethod>), StepUpFailureReason> {
    let code = match credentials {
        StepUpCredentials::BackupCode { code } => code,
        _ => return Err(StepUpFailureReason::InvalidCredentials),
    };

    // Verify backup code
    let valid = state
        .db
        .mfa()
        .verify_backup_code(&user.tenant_id, &user.user_id, code)
        .await
        .map_err(|e| StepUpFailureReason::InternalError(e.to_string()))?;

    if !valid {
        return Err(StepUpFailureReason::InvalidCredentials);
    }

    Ok((StepUpLevel::Elevated, vec![AuthMethod::Otp]))
}

/// Generate step-up token
async fn generate_step_up_token(
    state: &AppState,
    user: &CurrentUser,
    session: &vault_core::crypto::StepUpSession,
    methods: &[AuthMethod],
) -> Result<String, ApiError> {
    use vault_core::crypto::{Claims, HybridJwt};

    let claims = Claims::new(
        &user.user_id,
        &user.tenant_id,
        TokenType::StepUp,
        &state.config.jwt.issuer,
        &state.config.jwt.audience,
    )
    .with_email(&user.email, user.email_verified)
    .with_step_up_session(session)
    .with_auth_methods(methods.to_vec());

    let token = HybridJwt::encode(&claims, state.auth_service.signing_key())
        .map_err(|_| ApiError::internal())?;

    Ok(token)
}

/// Base64 decode helper
fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(input)
}

// ============ OAuth Account Linking ============

/// Request to link OAuth account
#[derive(Debug, Deserialize)]
struct OAuthLinkRequest {
    /// Provider user ID from OAuth
    #[serde(rename = "providerUserId")]
    provider_user_id: String,
    /// Provider account name
    name: Option<String>,
    /// Additional provider data
    #[serde(rename = "providerData")]
    provider_data: Option<serde_json::Value>,
}

/// OAuth account linking response
#[derive(Debug, Serialize)]
struct OAuthLinkResponse {
    id: String,
    provider: String,
    #[serde(rename = "providerAccountId")]
    provider_account_id: String,
    #[serde(rename = "isPrimary")]
    is_primary: bool,
    #[serde(rename = "linkedAt")]
    linked_at: chrono::DateTime<chrono::Utc>,
}

// ============ Web3 Authentication ============

/// Request a nonce for SIWE authentication
#[derive(Debug, Deserialize)]
struct Web3NonceRequest {
    /// Optional chain ID (defaults to Ethereum mainnet)
    #[serde(rename = "chainId")]
    chain_id: Option<u64>,
}

/// Nonce response
#[derive(Debug, Serialize)]
struct Web3NonceResponse {
    /// The nonce to use in SIWE message
    nonce: String,
    /// When the nonce expires
    #[serde(rename = "expiresAt")]
    expires_at: String,
    /// Domain for SIWE message
    domain: String,
    /// Chain ID to use
    #[serde(rename = "chainId")]
    chain_id: u64,
}

/// Generate nonce for Web3 authentication
#[tracing::instrument(
    skip(state, _headers, req),
    fields(
        ip_address = %addr.ip(),
        chain_id = tracing::field::Empty,
        action = "web3_nonce",
    )
)]
async fn web3_nonce(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    _headers: HeaderMap,
    Json(req): Json<Web3NonceRequest>,
) -> Result<Json<Web3NonceResponse>, ApiError> {
    let client_ip = addr.ip().to_string();
    let chain_id = req.chain_id.unwrap_or(1); // Default to Ethereum mainnet
    tracing::Span::current().record("chain_id", chain_id);

    // Check if Web3 auth is enabled
    if !state.config.web3_auth.enabled {
        return Err(ApiError::Forbidden);
    }

    // Check if chain ID is supported
    if !state.config.web3_auth.supported_chains.contains(&chain_id) {
        return Err(ApiError::Validation(format!(
            "Chain ID {} is not supported",
            chain_id
        )));
    }

    // Generate nonce
    let nonce_data = state
        .web3_auth
        .generate_nonce(Some(client_ip), Some(chain_id))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to generate nonce");
            ApiError::internal()
        })?;

    Ok(Json(Web3NonceResponse {
        nonce: nonce_data.nonce.clone(),
        expires_at: nonce_data.expires_at.to_rfc3339(),
        domain: state.web3_auth.domain().to_string(),
        chain_id,
    }))
}

/// Verify Web3 authentication request
#[derive(Debug, Deserialize)]
struct Web3VerifyRequest {
    /// The SIWE message that was signed
    message: String,
    /// The signature (hex encoded)
    signature: String,
}

/// Web3 authentication response
#[derive(Debug, Serialize)]
struct Web3AuthResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    user: UserResponse,
    #[serde(rename = "mfaRequired")]
    mfa_required: bool,
    /// Session information
    #[serde(rename = "sessionInfo")]
    session_info: Option<SessionInfoResponse>,
    /// Wallet address
    #[serde(rename = "walletAddress")]
    wallet_address: String,
    /// Chain ID
    #[serde(rename = "chainId")]
    chain_id: u64,
    /// Whether this is a new user
    #[serde(rename = "isNewUser")]
    is_new_user: bool,
}

/// Verify Web3 signature and authenticate
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        ip_address = %addr.ip(),
        action = "web3_verify",
        success = tracing::field::Empty,
        wallet_address = tracing::field::Empty,
    )
)]
async fn web3_verify(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<Web3VerifyRequest>,
) -> Result<Json<Web3AuthResponse>, ApiError> {
    // Check if Web3 auth is enabled
    if !state.config.web3_auth.enabled {
        return Err(ApiError::Forbidden);
    }

    let tenant_id = extract_tenant_id(&headers);
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());
    let ip_str = addr.ip().to_string();

    // Verify signature
    let auth_result = state
        .web3_auth
        .verify_signature(&req.message, &req.signature)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Web3 signature verification failed");
            audit.log(
                &tenant_id,
                crate::audit::AuditAction::LoginFailed,
                crate::audit::ResourceType::User,
                "web3",
                None,
                None,
                context.clone(),
                false,
                Some(format!("Web3 auth failed: {}", e)),
                Some(serde_json::json!({
                    "error": e.to_string(),
                })),
            );
            ApiError::Unauthorized
        })?;

    let wallet_address = auth_result.wallet_address.clone();
    let chain_id = auth_result.chain_id;

    // Check if user exists with this wallet address
    let (user, is_new_user) = match state
        .db
        .users()
        .find_by_wallet(&tenant_id, &wallet_address)
        .await
    {
        Ok(Some(existing_user)) => {
            // Existing user - update wallet verification time
            tracing::info!(
                user_id = %existing_user.id,
                wallet = %wallet_address,
                "Web3 login for existing user"
            );
            (existing_user, false)
        }
        Ok(None) => {
            // Create new user from Web3 authentication
            if !state.config.features.enable_oauth_signup {
                tracing::warn!(
                    wallet = %wallet_address,
                    "Web3 signup disabled, rejecting new user"
                );
                audit.log(
                    &tenant_id,
                    crate::audit::AuditAction::RegistrationFailed,
                    crate::audit::ResourceType::User,
                    &wallet_address,
                    None,
                    None,
                    context.clone(),
                    false,
                    Some("Web3 signup disabled".to_string()),
                    None,
                );
                return Err(ApiError::Forbidden);
            }

            tracing::info!(wallet = %wallet_address, "Creating new user from Web3 auth");

            let new_user = state
                .db
                .users()
                .create_from_web3(&tenant_id, &wallet_address, chain_id as i32, None)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to create Web3 user: {}", e);
                    ApiError::internal()
                })?;

            // Trigger webhook for new user
            crate::webhooks::events::trigger_user_created(
                &state,
                &tenant_id,
                &new_user.id,
                &new_user.email,
                new_user.profile.name.as_deref(),
            )
            .await;

            (new_user, true)
        }
        Err(e) => {
            tracing::error!(error = %e, "Database error looking up Web3 user");
            return Err(ApiError::internal());
        }
    };

    // Check if user account is active
    use vault_core::models::user::UserStatus;
    if user.status != UserStatus::Active {
        tracing::warn!(
            wallet = %wallet_address,
            "Web3 login attempt for inactive account"
        );
        audit.log(
            &tenant_id,
            crate::audit::AuditAction::LoginFailed,
            crate::audit::ResourceType::User,
            &user.id,
            None,
            None,
            context.clone(),
            false,
            Some("Account not active".to_string()),
            None,
        );
        return Err(ApiError::Forbidden);
    }

    // Check if user is locked
    if user.is_locked() {
        tracing::warn!(
            wallet = %wallet_address,
            "Web3 login attempt for locked account"
        );
        audit.log(
            &tenant_id,
            crate::audit::AuditAction::LoginFailed,
            crate::audit::ResourceType::User,
            &user.id,
            None,
            None,
            context.clone(),
            false,
            Some("Account locked".to_string()),
            None,
        );
        return Err(ApiError::Forbidden);
    }

    // Check session limits
    match state
        .check_session_limits(&tenant_id, &user.id, Some(&ip_str))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(limit_err)) => {
            return Err(ApiError::SessionLimitReached(limit_err));
        }
        Err(e) => {
            tracing::error!("Failed to check session limits: {}", e);
            return Err(ApiError::internal());
        }
    }

    // Record successful login
    let ip = addr.ip();
    state
        .db
        .users()
        .record_login_success(&tenant_id, &user.id, Some(ip))
        .await
        .ok();

    // Create session for the user
    let session = state
        .auth_service
        .create_session_for_oauth_user(&user, Some(addr.to_string()), None)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to create Web3 session");
            ApiError::internal()
        })?;

    // Store session in database
    let session_req = vault_core::db::sessions::CreateSessionRequest {
        tenant_id: tenant_id.clone(),
        user_id: user.id.clone(),
        access_token_jti: session.access_token_jti.clone(),
        refresh_token_hash: session.refresh_token_hash.clone(),
        token_family: session.token_family.clone(),
        ip_address: Some(ip),
        user_agent: context.as_ref().and_then(|c| c.user_agent.as_ref().map(|s| s.to_string())),
        device_fingerprint: None,
        device_info: serde_json::json!({
            "auth_method": "web3",
            "wallet_address": wallet_address,
            "chain_id": chain_id,
        }),
        location: None,
        mfa_verified: false,
        expires_at: session.expires_at,
        bind_to_ip: state.config.security.session_binding.bind_to_ip,
        bind_to_device: state.config.security.session_binding.bind_to_device,
    };

    state.db.sessions().create(session_req).await.map_err(|e| {
        tracing::error!("Failed to store Web3 session: {}", e);
        ApiError::internal()
    })?;

    // Generate tokens
    let token_pair = state
        .auth_service
        .generate_tokens(&user, &session.id)
        .map_err(|e| {
            tracing::error!("Failed to generate Web3 tokens: {}", e);
            ApiError::internal()
        })?;

    let access_token = apply_token_issue_actions(
        &state,
        &tenant_id,
        &user.id,
        &token_pair.access_token,
    )
    .await?;

    tracing::Span::current().record("wallet_address", wallet_address.as_str());
    tracing::info!(
        user_id = %user.id,
        chain_id = chain_id,
        "Web3 login successful"
    );

    // Log successful login
    audit.log(
        &tenant_id,
        crate::audit::AuditAction::Login,
        crate::audit::ResourceType::User,
        &user.id,
        Some(user.id.clone()),
        Some(session.id.clone()),
        context.clone(),
        true,
        None,
        Some(serde_json::json!({
            "auth_method": "web3",
            "wallet_address": wallet_address,
            "chain_id": chain_id,
        })),
    );

    // Trigger webhooks
    let ip = context.as_ref().and_then(|c| c.ip_address.clone());
    let ua = context.as_ref().and_then(|c| c.user_agent.clone());

    crate::webhooks::events::trigger_session_created(
        &state,
        &tenant_id,
        &user.id,
        &session.id,
        &user.email,
        ip.as_deref(),
        ua.as_deref(),
        "web3",
    )
    .await;

    crate::webhooks::events::trigger_user_login(
        &state,
        &tenant_id,
        &user.id,
        &user.email,
        ip.as_deref(),
        ua.as_deref(),
        "web3",
        true,
    )
    .await;

    // Get session limit status
    let limit_status = state
        .get_session_limit_status(&tenant_id, &user.id)
        .await
        .unwrap_or(SessionLimitStatus {
            current_sessions: 1,
            max_sessions: state.config.security.session_limits.max_concurrent_sessions,
            warning: None,
        });

    Ok(Json(Web3AuthResponse {
        access_token,
        refresh_token: token_pair.refresh_token,
        user: UserResponse {
            id: user.id,
            email: user.email,
            email_verified: user.email_verified,
            name: user.profile.name,
            mfa_enabled: user.mfa_enabled,
        },
        mfa_required: false,
        session_info: Some(SessionInfoResponse {
            session_id: session.id,
            current_sessions: limit_status.current_sessions,
            max_sessions: limit_status.max_sessions,
            warning: limit_status.warning,
        }),
        wallet_address,
        chain_id,
        is_new_user,
    }))
}

/// Link OAuth account to authenticated user
///
/// This endpoint is used to link an OAuth provider to an existing authenticated user.
/// The user must have already completed the OAuth flow and obtained the authorization code.
async fn oauth_link_account(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Json(req): Json<OAuthLinkRequest>,
) -> Result<Json<OAuthLinkResponse>, ApiError> {
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());

    // Set tenant context
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Parse provider
    let provider_enum = provider
        .parse::<AuthProvider>()
        .map_err(|e| ApiError::Validation(e))?;

    // Check if this provider account is already linked to another user
    let existing = state
        .account_linking_service
        .find_account_by_provider(
            &current_user.tenant_id,
            provider_enum,
            &req.provider_user_id,
        )
        .await
        .map_err(|_| ApiError::internal())?;

    if existing.is_some() {
        audit.log_account_linked(
            &current_user.tenant_id,
            &current_user.user_id,
            &provider,
            &req.provider_user_id,
            context,
            false,
            Some("Account already linked"),
        );
        return Err(ApiError::Conflict(
            "This OAuth account is already linked to a user".to_string(),
        ));
    }

    // Build provider data
    let mut provider_data = req.provider_data.unwrap_or_else(|| serde_json::json!({}));
    if let Some(name) = &req.name {
        if let Some(obj) = provider_data.as_object_mut() {
            obj.insert("name".to_string(), serde_json::json!(name));
        }
    }

    // Link the account
    let link_req = LinkAccountRequest {
        tenant_id: current_user.tenant_id.clone(),
        user_id: current_user.user_id.clone(),
        provider: provider_enum,
        provider_account_id: req.provider_user_id.clone(),
        provider_data: Some(provider_data),
        is_verified: true,
    };

    match state.account_linking_service.link_account(link_req).await {
        Ok(account) => {
            audit.log_account_linked(
                &current_user.tenant_id,
                &current_user.user_id,
                &provider,
                &req.provider_user_id,
                context,
                true,
                None,
            );

            Ok(Json(OAuthLinkResponse {
                id: account.id,
                provider: account.provider,
                provider_account_id: account.provider_account_id,
                is_primary: account.is_primary,
                linked_at: account.linked_at,
            }))
        }
        Err(e) => {
            tracing::warn!("Failed to link OAuth account: {}", e);
            let error_msg = e.to_string();
            audit.log_account_linked(
                &current_user.tenant_id,
                &current_user.user_id,
                &provider,
                &req.provider_user_id,
                context,
                false,
                Some(&error_msg),
            );

            match e {
                crate::auth::AccountLinkingError::AlreadyLinked => Err(ApiError::Conflict(
                    "Account already linked to another user".to_string(),
                )),
                crate::auth::AccountLinkingError::AlreadyLinkedToUser => Err(ApiError::Conflict(
                    "Account already linked to this user".to_string(),
                )),
                _ => Err(ApiError::internal()),
            }
        }
    }
}


/// Record consents during user registration
async fn record_registration_consents(
    state: &AppState,
    user_id: &str,
    _tenant_id: &str,
    terms_accepted: bool,
    privacy_accepted: bool,
    marketing_consent: bool,
    analytics_consent: bool,
    cookies_consent: bool,
    context: crate::consent::ConsentContext,
) -> anyhow::Result<()> {
    use crate::consent::{ConsentManager, ConsentConfig, ConsentRepository, ConsentType, SubmitConsentRequest};

    let repository = ConsentRepository::new(state.db.pool().clone());
    let config = ConsentConfig::default();
    let manager = ConsentManager::new(repository, config);

    // Record Terms of Service consent
    if terms_accepted {
        let request = SubmitConsentRequest {
            consent_type: ConsentType::TermsOfService,
            granted: true,
            version_id: None,
        };
        if let Err(e) = manager.submit_consent(user_id, request, context.clone()).await {
            tracing::warn!("Failed to record ToS consent for user {}: {}", user_id, e);
        }
    }

    // Record Privacy Policy consent
    if privacy_accepted {
        let request = SubmitConsentRequest {
            consent_type: ConsentType::PrivacyPolicy,
            granted: true,
            version_id: None,
        };
        if let Err(e) = manager.submit_consent(user_id, request, context.clone()).await {
            tracing::warn!("Failed to record Privacy consent for user {}: {}", user_id, e);
        }
    }

    // Record Marketing consent (optional)
    let request = SubmitConsentRequest {
        consent_type: ConsentType::Marketing,
        granted: marketing_consent,
        version_id: None,
    };
    if let Err(e) = manager.submit_consent(user_id, request, context.clone()).await {
        tracing::warn!("Failed to record Marketing consent for user {}: {}", user_id, e);
    }

    // Record Analytics consent (optional)
    let request = SubmitConsentRequest {
        consent_type: ConsentType::Analytics,
        granted: analytics_consent,
        version_id: None,
    };
    if let Err(e) = manager.submit_consent(user_id, request, context.clone()).await {
        tracing::warn!("Failed to record Analytics consent for user {}: {}", user_id, e);
    }

    // Record Cookies consent (optional)
    let request = SubmitConsentRequest {
        consent_type: ConsentType::Cookies,
        granted: cookies_consent,
        version_id: None,
    };
    if let Err(e) = manager.submit_consent(user_id, request, context).await {
        tracing::warn!("Failed to record Cookies consent for user {}: {}", user_id, e);
    }

    Ok(())
}


// ============ Anonymous/Guest Authentication Handlers ============

/// Create an anonymous/guest session
///
/// Allows users to use the app without registering.
/// Returns an access token and anonymous session ID.
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        ip_address = %addr.ip(),
        action = "create_anonymous_session",
        success = tracing::field::Empty,
    )
)]
async fn create_anonymous_session_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateAnonymousSessionRequest>,
) -> Result<Json<crate::auth::AnonymousSessionResponse>, ApiError> {
    // Validate request
    if let Err(e) = req.validate() {
        tracing::warn!(validation_error = %e, "Anonymous session validation failed");
        return Err(ApiError::Validation(e.to_string()));
    }

    let tenant_id = extract_tenant_id(&headers);
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let ip = addr.ip();
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let audit = AuditLogger::new(state.db.clone());

    match create_anonymous_session(&state, &tenant_id, Some(ip), user_agent).await {
        Ok(response) => {
            // Log successful anonymous session creation
            audit.log(
                &tenant_id,
                crate::audit::AuditAction::AnonymousSessionCreated,
                crate::audit::ResourceType::Session,
                &response.anonymous_id,
                None,
                None,
                context,
                true,
                None,
                Some(serde_json::json!({
                    "expires_at": response.expires_at,
                    "ip": ip.to_string(),
                })),
            );

            Ok(Json(response))
        }
        Err(e) => {
            tracing::warn!(error = %e, "Anonymous session creation failed");
            
            // Log failure
            audit.log(
                &tenant_id,
                crate::audit::AuditAction::AnonymousSessionFailed,
                crate::audit::ResourceType::Session,
                "unknown",
                None,
                None,
                context,
                false,
                Some(e.to_string()),
                None,
            );

            if e.to_string().contains("rate limit") {
                return Err(ApiError::TooManyRequests(
                    "Anonymous session creation rate limit exceeded".to_string(),
                ));
            }

            Err(ApiError::internal())
        }
    }
}

/// Convert anonymous session to full account
///
/// Transfers all anonymous user data to a new full account.
/// Invalidates the anonymous session and returns new tokens for the full account.
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        ip_address = %addr.ip(),
        action = "convert_anonymous",
        success = tracing::field::Empty,
    )
)]
async fn convert_anonymous_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ConvertAnonymousRequest>,
) -> Result<Json<crate::auth::AnonymousConversionResponse>, ApiError> {
    // Validate request
    if let Err(e) = req.validate() {
        tracing::warn!(validation_error = %e, "Anonymous conversion validation failed");
        return Err(ApiError::Validation(e.to_string()));
    }

    // Validate required consents
    if !req.terms_accepted {
        return Err(ApiError::Validation(
            "You must accept the Terms of Service".to_string(),
        ));
    }
    if !req.privacy_accepted {
        return Err(ApiError::Validation(
            "You must accept the Privacy Policy".to_string(),
        ));
    }

    let tenant_id = extract_tenant_id(&headers);
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let ip = addr.ip();
    let audit = AuditLogger::new(state.db.clone());

    match convert_to_full_account(&state, &tenant_id, req, Some(ip)).await {
        Ok(response) => {
            // Log successful conversion
            audit.log(
                &tenant_id,
                crate::audit::AuditAction::AnonymousConverted,
                crate::audit::ResourceType::User,
                &response.user.id,
                None,
                None,
                context.clone(),
                true,
                None,
                Some(serde_json::json!({
                    "previous_anonymous_id": response.user.previous_anonymous_id,
                    "data_migrated": response.data_migrated,
                })),
            );

            // Record consents for the new full account
            let consent_context = crate::consent::ConsentContext {
                ip_address: Some(ip.to_string()),
                user_agent: headers.get("user-agent").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
                jurisdiction: headers.get("cf-ipcountry").and_then(|h| h.to_str().ok()).map(|s| s.to_string()),
            };

            // Get the consents from the request (using defaults for optional ones)
            let _ = record_registration_consents(
                &state,
                &response.user.id,
                &tenant_id,
                true, // terms_accepted (required)
                true, // privacy_accepted (required)
                false, // marketing_consent - default to false for anonymous conversion
                false, // analytics_consent - default to false for anonymous conversion
                false, // cookies_consent - default to false for anonymous conversion
                consent_context,
            ).await;

            // Trigger webhook event
            crate::webhooks::events::trigger_user_created(
                &state,
                &tenant_id,
                &response.user.id,
                &response.user.email,
                response.user.name.as_deref(),
            )
            .await;

            Ok(Json(response))
        }
        Err(e) => {
            tracing::warn!(error = %e, "Anonymous conversion failed");

            // Log failure
            audit.log(
                &tenant_id,
                crate::audit::AuditAction::AnonymousConversionFailed,
                crate::audit::ResourceType::User,
                "unknown",
                None,
                None,
                context,
                false,
                Some(e.to_string()),
                None,
            );

            if e.to_string().contains("already registered") {
                return Err(ApiError::Conflict(
                    "Email address is already registered".to_string(),
                ));
            }
            if e.to_string().contains("already been converted") {
                return Err(ApiError::Conflict(
                    "Anonymous session has already been converted".to_string(),
                ));
            }

            Err(ApiError::BadRequest(e.to_string()))
        }
    }
}

// ============ Biometric Authentication Types ============

/// Request to register a biometric key
#[derive(Debug, Deserialize)]
struct BiometricRegisterRequest {
    /// ECDSA P-256 public key (SEC1 format, base64 encoded)
    #[serde(rename = "publicKey")]
    public_key: String,
    /// Unique identifier for the key (client-generated)
    #[serde(rename = "keyId")]
    key_id: String,
    /// Human-readable device name
    #[serde(rename = "deviceName")]
    device_name: String,
    /// Type of biometric (face_id, touch_id, fingerprint, face_unlock, iris)
    #[serde(rename = "biometricType")]
    biometric_type: String,
}

/// Biometric key response
#[derive(Debug, Serialize)]
struct BiometricKeyResponse {
    id: String,
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(rename = "deviceName")]
    device_name: String,
    #[serde(rename = "biometricType")]
    biometric_type: String,
    #[serde(rename = "createdAt")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "lastUsedAt")]
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<vault_core::auth::BiometricKey> for BiometricKeyResponse {
    fn from(key: vault_core::auth::BiometricKey) -> Self {
        Self {
            id: key.id,
            key_id: key.key_id,
            device_name: key.device_name,
            biometric_type: key.biometric_type.as_str().to_string(),
            created_at: key.created_at,
            last_used_at: key.last_used_at,
        }
    }
}

/// Challenge response
#[derive(Debug, Serialize)]
struct BiometricChallengeResponse {
    challenge: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
}

/// Authenticate request
#[derive(Debug, Deserialize)]
struct BiometricAuthenticateRequest {
    /// Key ID to authenticate with
    #[serde(rename = "keyId")]
    key_id: String,
    /// ECDSA signature of the challenge (DER format, base64 encoded)
    signature: String,
    /// The challenge that was signed
    challenge: String,
}

// ============ Biometric Authentication Handlers ============

/// Register a new biometric key
///
/// This endpoint is called after the user has authenticated with password/MFA
/// and the device has generated a key pair (private key stays in Secure Enclave/Keystore).
#[tracing::instrument(
    skip(state, user, req),
    fields(
        tenant_id = %user.tenant_id,
        user_id = %user.user_id,
        key_id = %req.key_id,
        biometric_type = %req.biometric_type,
        action = "biometric_register_key",
        success = tracing::field::Empty,
    )
)]
async fn biometric_register_key(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(req): Json<BiometricRegisterRequest>,
) -> Result<Json<BiometricKeyResponse>, ApiError> {
    use vault_core::auth::BiometricType;

    // Parse biometric type
    let biometric_type = match req.biometric_type.as_str() {
        "face_id" => BiometricType::FaceId,
        "touch_id" => BiometricType::TouchId,
        "fingerprint" => BiometricType::Fingerprint,
        "face_unlock" => BiometricType::FaceUnlock,
        "iris" => BiometricType::Iris,
        _ => {
            return Err(ApiError::Validation(format!(
                "Invalid biometric type: {}",
                req.biometric_type
            )));
        }
    };

    // Decode public key from base64
    let public_key = base64_decode(&req.public_key).map_err(|e| {
        tracing::warn!(error = %e, "Invalid base64 public key");
        ApiError::Validation("Invalid public key format".to_string())
    })?;

    // Create biometric service with database repositories
    let biometric_repo = state.db.biometric();
    let biometric_service = vault_core::auth::BiometricAuthService::new(
        Box::new(biometric_repo.clone()),
        Box::new(biometric_repo),
    );

    // Register the key
    match biometric_service
        .register_key(
            &user.user_id,
            &user.tenant_id,
            public_key,
            &req.key_id,
            &req.device_name,
            biometric_type,
        )
        .await
    {
        Ok(key) => {
            tracing::info!("Biometric key registered successfully");
            Ok(Json(key.into()))
        }
        Err(e) => {
            tracing::warn!(error = %e, "Biometric key registration failed");
            Err(ApiError::from(e))
        }
    }
}

/// Generate a challenge for biometric authentication
///
/// This should be called before the client attempts to authenticate,
/// to get a challenge that the client will sign with their private key.
#[tracing::instrument(
    skip(state, req),
    fields(
        action = "biometric_challenge",
    )
)]
async fn biometric_challenge(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<BiometricChallengeResponse>, ApiError> {
    let key_id = req["keyId"]
        .as_str()
        .ok_or_else(|| ApiError::Validation("keyId is required".to_string()))?;

    // Create biometric service with database repositories
    let biometric_repo = state.db.biometric();
    let biometric_service = vault_core::auth::BiometricAuthService::new(
        Box::new(biometric_repo.clone()),
        Box::new(biometric_repo),
    );

    // Generate challenge
    match biometric_service.generate_challenge(key_id).await {
        Ok(challenge) => Ok(Json(BiometricChallengeResponse {
            challenge: challenge.challenge,
            expires_at: challenge.expires_at.to_rfc3339(),
        })),
        Err(e) => {
            tracing::warn!(error = %e, "Biometric challenge generation failed");
            Err(ApiError::from(e))
        }
    }
}

/// Authenticate with a biometric key
///
/// The client signs the challenge with the private key stored in the
/// Secure Enclave (iOS) or Keystore (Android), and sends the signature
/// to this endpoint for verification.
#[tracing::instrument(
    skip(state, headers, req),
    fields(
        tenant_id = tracing::field::Empty,
        ip_address = %addr.ip(),
        key_id = %req.key_id,
        action = "biometric_authenticate",
        success = tracing::field::Empty,
        user_id = tracing::field::Empty,
    )
)]
async fn biometric_authenticate(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<BiometricAuthenticateRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&headers);
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());
    let ip_str = addr.ip().to_string();

    // Decode signature from base64
    let signature = base64_decode(&req.signature).map_err(|e| {
        tracing::warn!(error = %e, "Invalid base64 signature");
        ApiError::Validation("Invalid signature format".to_string())
    })?;

    // Create biometric service with database repositories
    let biometric_repo = state.db.biometric();
    let biometric_service = vault_core::auth::BiometricAuthService::new(
        Box::new(biometric_repo.clone()),
        Box::new(biometric_repo),
    );

    // Authenticate with biometric
    let auth_result = match biometric_service
        .authenticate(&req.key_id, signature, &req.challenge)
        .await
    {
        Ok(result) => {
            tracing::Span::current().record("user_id", result.user_id.as_str());
            result
        }
        Err(e) => {
            tracing::warn!(error = %e, "Biometric authentication failed");
            audit.log(
                &tenant_id,
                crate::audit::AuditAction::LoginFailed,
                crate::audit::ResourceType::User,
                "unknown",
                None,
                None,
                context,
                false,
                Some(format!("Biometric auth failed: {}", e)),
                None,
            );
            return Err(ApiError::from(e));
        }
    };

    // Get user from database
    let user = match state
        .auth_service
        .get_current_user(&auth_result.tenant_id, &auth_result.user_id)
        .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("User not found after biometric authentication: {}", e);
            return Err(ApiError::internal());
        }
    };

    // Check if user is active
    if user.status != vault_core::models::user::UserStatus::Active {
        tracing::warn!(
            "Biometric login attempt for inactive account: {}",
            auth_result.user_id
        );
        audit.log(
            &tenant_id,
            crate::audit::AuditAction::LoginFailed,
            crate::audit::ResourceType::User,
            &user.id,
            None,
            None,
            context.clone(),
            false,
            Some("Account not active".to_string()),
            None,
        );
        return Err(ApiError::Forbidden);
    }

    // Check if user is locked
    if user.is_locked() {
        tracing::warn!(
            "Biometric login attempt for locked account: {}",
            auth_result.user_id
        );
        audit.log(
            &tenant_id,
            crate::audit::AuditAction::LoginFailed,
            crate::audit::ResourceType::User,
            &user.id,
            None,
            None,
            context.clone(),
            false,
            Some("Account locked".to_string()),
            None,
        );
        return Err(ApiError::Forbidden);
    }

    // Check session limits before creating session
    match state
        .check_session_limits(&tenant_id, &user.id, Some(&ip_str))
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(limit_err)) => {
            tracing::warn!(
                "Session limit reached for user {}: {}/{} sessions",
                user.id,
                limit_err.current_sessions,
                limit_err.max_sessions
            );
            audit.log(
                &tenant_id,
                crate::audit::AuditAction::LoginFailed,
                crate::audit::ResourceType::User,
                &user.id,
                None,
                None,
                context.clone(),
                false,
                Some("SESSION_LIMIT_REACHED".to_string()),
                Some(serde_json::json!({
                    "current_sessions": limit_err.current_sessions,
                    "max_sessions": limit_err.max_sessions
                })),
            );
            return Err(ApiError::SessionLimitReached(limit_err));
        }
        Err(e) => {
            tracing::error!("Failed to check session limits: {}", e);
            return Err(ApiError::internal());
        }
    }

    // Create session for the user
    let session = match state
        .auth_service
        .create_session_for_oauth_user(&user, Some(addr.to_string()), None)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to create session: {}", e);
            return Err(ApiError::internal());
        }
    };

    // Store session in database
    let session_req = vault_core::db::sessions::CreateSessionRequest {
        tenant_id: tenant_id.clone(),
        user_id: user.id.clone(),
        access_token_jti: session.access_token_jti.clone(),
        refresh_token_hash: session.refresh_token_hash.clone(),
        token_family: session.token_family.clone(),
        ip_address: Some(addr.ip()),
        user_agent: context.as_ref().and_then(|c| c.user_agent.as_ref().map(|s| s.to_string())),
        device_fingerprint: None,
        device_info: serde_json::json!({
            "auth_method": "biometric",
            "biometric_type": auth_result.biometric_type.as_str(),
            "key_id": auth_result.key_id,
        }),
        location: None,
        mfa_verified: true, // Biometric is considered strong authentication
        expires_at: session.expires_at,
        bind_to_ip: state.config.security.session_binding.bind_to_ip,
        bind_to_device: state.config.security.session_binding.bind_to_device,
    };

    if let Err(e) = state.db.sessions().create(session_req).await {
        tracing::error!("Failed to store session: {}", e);
        return Err(ApiError::internal());
    }

    // Generate tokens
    let token_pair = match state.auth_service.generate_tokens(&user, &session.id) {
        Ok(tp) => tp,
        Err(e) => {
            tracing::error!("Failed to generate tokens: {}", e);
            return Err(ApiError::internal());
        }
    };

    let access_token = apply_token_issue_actions(
        &state,
        &tenant_id,
        &user.id,
        &token_pair.access_token,
    )
    .await?;

    tracing::info!(
        "Biometric authentication successful for user: {} (type: {:?})",
        auth_result.user_id,
        auth_result.biometric_type
    );

    // Log successful login
    audit.log(
        &tenant_id,
        crate::audit::AuditAction::Login,
        crate::audit::ResourceType::User,
        &auth_result.user_id,
        Some(auth_result.user_id.clone()),
        Some(session.id.clone()),
        context.clone(),
        true,
        None,
        Some(serde_json::json!({
            "auth_method": "biometric",
            "biometric_type": auth_result.biometric_type.as_str(),
            "key_id": auth_result.key_id,
        })),
    );

    // Trigger webhook events
    let ip = context.as_ref().and_then(|c| c.ip_address.clone());
    let ua = context.as_ref().and_then(|c| c.user_agent.clone());

    crate::webhooks::events::trigger_session_created(
        &state,
        &tenant_id,
        &auth_result.user_id,
        &session.id,
        &user.email,
        ip.as_deref(),
        ua.as_deref(),
        "biometric",
    )
    .await;

    crate::webhooks::events::trigger_user_login(
        &state,
        &tenant_id,
        &auth_result.user_id,
        &user.email,
        ip.as_deref(),
        ua.as_deref(),
        "biometric",
        true,
    )
    .await;

    // Get session limit status for response
    let limit_status = state
        .get_session_limit_status(&tenant_id, &user.id)
        .await
        .unwrap_or(SessionLimitStatus {
            current_sessions: 1,
            max_sessions: state.config.security.session_limits.max_concurrent_sessions,
            warning: None,
        });

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: token_pair.refresh_token,
        user: UserResponse {
            id: user.id,
            email: user.email,
            email_verified: user.email_verified,
            name: user.profile.name,
            mfa_enabled: user.mfa_enabled,
        },
        mfa_required: false,
        session_info: Some(SessionInfoResponse {
            session_id: session.id.clone(),
            current_sessions: limit_status.current_sessions,
            max_sessions: limit_status.max_sessions,
            warning: limit_status.warning,
        }),
    }))
}

/// List biometric keys for the authenticated user
#[tracing::instrument(
    skip(state, user),
    fields(
        user_id = %user.user_id,
        tenant_id = %user.tenant_id,
        action = "biometric_list_keys",
    )
)]
async fn biometric_list_keys(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<Vec<BiometricKeyResponse>>, ApiError> {
    // Create biometric service with database repositories
    let biometric_repo = state.db.biometric();
    let biometric_service = vault_core::auth::BiometricAuthService::new(
        Box::new(biometric_repo.clone()),
        Box::new(biometric_repo),
    );

    match biometric_service
        .list_keys(&user.user_id, &user.tenant_id)
        .await
    {
        Ok(keys) => {
            let response: Vec<BiometricKeyResponse> = keys.into_iter().map(Into::into).collect();
            Ok(Json(response))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to list biometric keys");
            Err(ApiError::from(e))
        }
    }
}

/// Revoke a biometric key
#[tracing::instrument(
    skip(state, user, key_id),
    fields(
        user_id = %user.user_id,
        tenant_id = %user.tenant_id,
        key_id = %key_id,
        action = "biometric_revoke_key",
        success = tracing::field::Empty,
    )
)]
async fn biometric_revoke_key(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(key_id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    let audit = AuditLogger::new(state.db.clone());

    // Create biometric service with database repositories
    let biometric_repo = state.db.biometric();
    let biometric_service = vault_core::auth::BiometricAuthService::new(
        Box::new(biometric_repo.clone()),
        Box::new(biometric_repo),
    );

    // First verify the key belongs to this user by listing keys
    let keys = match biometric_service.list_keys(&user.user_id, &user.tenant_id).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "Failed to list biometric keys");
            return Err(ApiError::from(e));
        }
    };

    let key_exists = keys.iter().any(|k| k.key_id == key_id);
    if !key_exists {
        return Err(ApiError::NotFound);
    }

    match biometric_service.revoke_key(&key_id).await {
        Ok(_) => {
            tracing::info!("Biometric key revoked");

            audit.log(
                &user.tenant_id,
                crate::audit::AuditAction::MfaDisabled,
                crate::audit::ResourceType::User,
                &user.user_id,
                Some(user.user_id.clone()),
                None,
                None,
                true,
                Some(format!("Biometric key revoked: {}", key_id)),
                None,
            );

            Ok(Json(MessageResponse {
                message: "Biometric key revoked successfully".to_string(),
            }))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to revoke biometric key");
            Err(ApiError::from(e))
        }
    }
}

impl From<vault_core::auth::BiometricError> for ApiError {
    fn from(err: vault_core::auth::BiometricError) -> Self {
        use vault_core::auth::BiometricError;

        match err {
            BiometricError::KeyNotFound => ApiError::NotFound,
            BiometricError::InvalidPublicKey | BiometricError::InvalidSignature => {
                ApiError::Validation("Invalid biometric credentials".to_string())
            }
            BiometricError::ChallengeExpired => {
                ApiError::Validation("Challenge expired".to_string())
            }
            BiometricError::ChallengeNotFound => ApiError::Validation("Challenge not found".to_string()),
            BiometricError::InvalidChallenge => {
                ApiError::Validation("Invalid challenge response".to_string())
            }
            BiometricError::KeyAlreadyExists => {
                ApiError::Conflict("Biometric key already exists".to_string())
            }
            BiometricError::RateLimited => ApiError::TooManyRequests("Rate limit exceeded".to_string()),
            BiometricError::DatabaseError(msg) => {
                tracing::error!("Biometric database error: {}", msg);
                ApiError::internal()
            }
            BiometricError::Internal(msg) => {
                tracing::error!("Biometric internal error: {}", msg);
                ApiError::internal()
            }
        }
    }
}
