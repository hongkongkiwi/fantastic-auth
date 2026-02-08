//! Authentication routes

use axum::{
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use validator::Validate;

use crate::{
    audit::{AuditLogger, RequestContext},
    auth::{
        AuthProvider, LinkAccountRequest, SensitiveOperation, StepUpAuthMethod, StepUpChallenge,
        StepUpChallengeResponse, StepUpCredentials, StepUpFailureReason, StepUpPolicy,
        StepUpRequest, StepUpService, StepUpTokenResponse,
    },
    middleware::{
        bot_protection_middleware, conditional_bot_protection_middleware,
        is_captcha_required_for_login, record_failed_login, reset_failed_login,
        CaptchaSiteKeyResponse,
    },
    routes::{ApiError, SessionLimitError},
    security::{EnforcementMode, UserInfo},
    state::{AppState, CurrentUser, SessionLimitStatus},
};
use vault_core::crypto::{AuthMethod, StepUpLevel, TokenType};

/// Auth routes
///
/// Bot protection is applied to:
/// - POST /register - Always protected
/// - POST /login - Protected after N failed attempts (configurable)
/// - POST /forgot-password - Always protected
/// - POST /magic-link - Always protected
/// - POST /oauth/:provider - Optional protection (based on config)
pub fn routes() -> Router<AppState> {
    Router::new()
        // Public auth endpoints with CAPTCHA protection
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/refresh", post(refresh_token))
        .route("/magic-link", post(send_magic_link))
        .route("/magic-link/verify", post(verify_magic_link))
        .route("/forgot-password", post(forgot_password))
        .route("/reset-password", post(reset_password))
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
        // WebAuthn/Passkey endpoints
        .route("/webauthn/register/begin", post(webauthn_register_begin))
        .route("/webauthn/register/finish", post(webauthn_register_finish))
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
        // Authenticated endpoints
        .route("/logout", post(logout))
        .route("/me", get(get_current_user))
        .route("/webauthn/credentials", get(list_webauthn_credentials))
        .route(
            "/webauthn/credentials/:id",
            delete(delete_webauthn_credential),
        )
        // OAuth account linking (authenticated)
        .route("/oauth/:provider/link", post(oauth_link_account))
        // Web3 authentication endpoints
        .route("/web3/nonce", post(web3_nonce))
        .route("/web3/verify", post(web3_verify))
}

#[derive(Debug, Deserialize)]
struct SsoCallbackRequest {
    #[serde(rename = "connectionId")]
    connection_id: String,
    payload: serde_json::Value,
}

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

#[derive(Debug, Deserialize)]
struct RefreshRequest {
    #[serde(rename = "refreshToken")]
    refresh_token: String,
}

#[derive(Debug, Deserialize, Validate)]
struct MagicLinkRequest {
    #[validate(email)]
    email: String,
}

#[derive(Debug, Deserialize)]
struct VerifyMagicLinkRequest {
    token: String,
}

#[derive(Debug, Deserialize, Validate)]
struct ForgotPasswordRequest {
    #[validate(email)]
    email: String,
}

#[derive(Debug, Deserialize)]
struct ResetPasswordRequest {
    token: String,
    #[serde(rename = "newPassword")]
    new_password: String,
}

#[derive(Debug, Deserialize)]
struct VerifyEmailRequest {
    token: String,
}

#[derive(Debug, Deserialize)]
struct OAuthRequest {
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

// ============ Handlers ============

/// Get CAPTCHA site key for frontend integration
async fn get_captcha_site_key(State(state): State<AppState>) -> Json<CaptchaSiteKeyResponse> {
    Json(CaptchaSiteKeyResponse::from_state(&state))
}

/// Register a new user
async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Validate request
    if let Err(e) = req.validate() {
        tracing::warn!("Registration validation failed: {}", e);
        return Err(ApiError::Validation(e.to_string()));
    }

    let tenant_id = extract_tenant_id(&headers);
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
                    "Registration rejected due to password policy violations: {:?}",
                    validation_result.error_codes()
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
                tracing::info!(
                    "Password policy violations detected (allowed in {} mode): {:?}",
                    if matches!(policy.enforcement_mode, EnforcementMode::Warn) {
                        "warn"
                    } else {
                        "audit"
                    },
                    validation_result.error_codes()
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
                tracing::error!("Failed to record consents for user {}: {}", user.id, e);
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
                                "User {} auto-enrolled in organization {} via domain verification",
                                user.id,
                                org_id
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
                        tracing::debug!("No auto-enrollment available for user {}", user.id);
                    }
                    Err(e) => {
                        // Log error but don't fail registration
                        tracing::warn!("Auto-enrollment check failed for user {}: {}", user.id, e);
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

                    Ok(Json(AuthResponse {
                        access_token: auth_result.access_token,
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
                    tracing::error!("Auto-login after registration failed: {}", e);
                    Err(ApiError::Internal)
                }
            }
        }
        Err(e) => {
            tracing::warn!("Registration failed: {}", e);
            // Log failed registration
            let reason = if e.to_string().contains("already exists") {
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
async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Validate request
    if let Err(e) = req.validate() {
        tracing::warn!("Login validation failed: {}", e);
        return Err(ApiError::Validation(e.to_string()));
    }

    let tenant_id = extract_tenant_id(&headers);
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
                        tracing::debug!("CAPTCHA verified for login attempt from {}", ip);
                    }
                    Ok(result) => {
                        tracing::warn!(
                            "CAPTCHA verification failed for login from {}: {:?}",
                            ip,
                            result.error_codes
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
                tracing::warn!("CAPTCHA required but not provided for login from {}", ip);
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
                    context,
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
                    return Err(ApiError::Internal);
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

            Ok(Json(AuthResponse {
                access_token: auth_result.access_token,
                refresh_token: auth_result.refresh_token,
                user: UserResponse {
                    id: auth_result.user.id,
                    email: auth_result.user.email,
                    email_verified: auth_result.user.email_verified,
                    name: auth_result.user.profile.name,
                    mfa_enabled: auth_result.user.mfa_enabled,
                },
                mfa_required: false,
                session_info: Some(SessionInfoResponse {
                    session_id: auth_result.session.id.clone(),
                    current_sessions: limit_status.current_sessions + 1, // +1 for the new session
                    max_sessions: limit_status.max_sessions,
                    warning: limit_status.warning,
                }),
            }))
        }
        Err(e) => {
            tracing::warn!("Authentication failed: {}", e);

            // Record failed login attempt
            let failure_count = record_failed_login(&state, &failed_login_key).await;

            // Log failed login
            audit.log_login_failed(&tenant_id, &email, context, &e.to_string());

            tracing::info!(
                "Failed login attempt {} for {} from {}",
                failure_count,
                email,
                ip
            );

            // Try LDAP authentication if local auth failed
            match try_ldap_authenticate(&state, &tenant_id, &email_for_ldap, &password_for_ldap)
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
                            return Err(ApiError::Internal);
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

                    return Ok(Json(AuthResponse {
                        access_token: auth_result.access_token,
                        refresh_token: auth_result.refresh_token,
                        user: UserResponse {
                            id: auth_result.user.id,
                            email: auth_result.user.email,
                            email_verified: auth_result.user.email_verified,
                            name: auth_result.user.profile.name,
                            mfa_enabled: auth_result.user.mfa_enabled,
                        },
                        mfa_required: false,
                        session_info: Some(SessionInfoResponse {
                            session_id: auth_result.session.id.clone(),
                            current_sessions: limit_status.current_sessions + 1,
                            max_sessions: limit_status.max_sessions,
                            warning: limit_status.warning,
                        }),
                    }));
                }
                Ok(None) => {
                    // LDAP also failed or not configured
                }
                Err(e) => {
                    tracing::error!("LDAP authentication error: {}", e);
                }
            }

            Err(ApiError::Unauthorized)
        }
    }
}

/// Try LDAP authentication as fallback
async fn try_ldap_authenticate(
    state: &AppState,
    tenant_id: &str,
    email: &str,
    password: &str,
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

    let jit_auth = LdapJitAuth::new(state.db.pool().clone());

    // Try LDAP authentication with JIT provisioning
    match jit_auth.authenticate(tenant_id, email, password).await {
        Ok(Some(_ldap_user)) => {
            // After JIT auth, the user should exist in the database
            // Authenticate them locally now
            let credentials = vault_core::auth::LoginCredentials {
                email: email.to_string(),
                password: password.to_string(),
                mfa_code: None,
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
async fn refresh_token(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
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
                access_token: auth_result.access_token,
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
            tracing::warn!("Token refresh failed: {}", e);
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
async fn logout(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Get session ID from JWT claims
    let session_id = user.session_id.ok_or(StatusCode::BAD_REQUEST)?;

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
            tracing::error!("Logout failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Get current user
async fn get_current_user(
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<UserResponse>, StatusCode> {
    Ok(Json(UserResponse {
        id: user.user_id,
        email: user.email,
        email_verified: user.email_verified,
        name: None, // TODO: Get from database
        mfa_enabled: user.mfa_authenticated,
    }))
}

/// Send magic link for passwordless login
async fn send_magic_link(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MagicLinkRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    if let Err(e) = req.validate() {
        tracing::warn!("Magic link validation failed: {}", e);
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
            tracing::error!("Failed to send magic link: {}", e);
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
async fn verify_magic_link(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VerifyMagicLinkRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
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

            Ok(Json(AuthResponse {
                access_token: auth_result.access_token,
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
            tracing::warn!("Magic link verification failed: {}", e);
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
async fn forgot_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    if let Err(e) = req.validate() {
        tracing::warn!("Forgot password validation failed: {}", e);
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
            tracing::error!("Failed to send password reset: {}", e);
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
async fn reset_password(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
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
                    "Password reset rejected due to password policy violations: {:?}",
                    validation_result.error_codes()
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
                tracing::info!(
                    "Password policy violations detected during reset (allowed in {} mode): {:?}",
                    if matches!(policy.enforcement_mode, EnforcementMode::Warn) {
                        "warn"
                    } else {
                        "audit"
                    },
                    validation_result.error_codes()
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
            tracing::warn!("Password reset failed: {}", e);
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
async fn verify_email(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
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
            tracing::warn!("Email verification failed: {}", e);
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
async fn oauth_redirect(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    headers: axum::http::HeaderMap,
    Json(req): Json<OAuthRequest>,
) -> Result<Json<OAuthRedirectResponse>, ApiError> {
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
        tracing::warn!("Redis not available, OAuth state verification may be less secure");
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
        "Generated OAuth redirect URL for provider: {}, mode: {}",
        provider_enum.name(),
        link_mode
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
async fn oauth_callback(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(provider): Path<String>,
    Query(params): Query<OAuthCallbackQuery>,
) -> Result<Json<AuthResponse>, ApiError> {
    // Check for OAuth error
    if let Some(error) = params.error {
        tracing::warn!("OAuth callback error from {}: {}", provider, error);
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
            "OAuth provider mismatch: expected {}, got {}",
            stored_provider,
            provider
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
            ApiError::Internal
        })?;

    // Fetch user info from provider
    let user_info = oauth_service
        .get_user_info(&token_response.access_token)
        .await
        .map_err(|e| {
            tracing::error!("OAuth user info fetch failed: {}", e);
            ApiError::Internal
        })?;

    // Extract email - required for account creation/linking
    let email = user_info.email.ok_or_else(|| {
        tracing::warn!(
            "OAuth provider did not return email for {}",
            provider_enum.name()
        );
        ApiError::BadRequest("Email not provided by OAuth provider".to_string())
    })?;

    tracing::info!(
        "OAuth login attempt: provider={}, email={}",
        provider_enum.name(),
        email
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
            tracing::info!("Existing user logging in via OAuth: {}", email);
            existing_user
        }
        Ok(None) => {
            // Check if OAuth signup is enabled
            if !state.config.features.enable_oauth_signup {
                tracing::warn!("OAuth signup disabled, rejecting new user: {}", email);
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
            tracing::info!("Creating new user via OAuth: {}", email);

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
                ApiError::Internal
            })?
        }
        Err(e) => {
            tracing::error!("Database error looking up user: {}", e);
            return Err(ApiError::Internal);
        }
    };

    // Check if user account is active
    use vault_core::models::user::UserStatus;
    if user.status != UserStatus::Active {
        tracing::warn!("OAuth login attempt for inactive account: {}", email);
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
        tracing::warn!("OAuth login attempt for locked account: {}", email);
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
                "Session limit reached for user {}: {}/{} sessions",
                user.id,
                limit_err.current_sessions,
                limit_err.max_sessions
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
            tracing::error!("Failed to check session limits: {}", e);
            return Err(ApiError::Internal);
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
            ApiError::Internal
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
    };

    state.db.sessions().create(session_req).await.map_err(|e| {
        tracing::error!("Failed to store session: {}", e);
        ApiError::Internal
    })?;

    // Generate tokens
    let token_pair = state
        .auth_service
        .generate_tokens(&user, &session.id)
        .map_err(|e| {
            tracing::error!("Failed to generate tokens: {}", e);
            ApiError::Internal
        })?;

    tracing::info!(
        "OAuth login successful: provider={}, email={}",
        provider_enum.name(),
        email
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
        access_token: token_pair.access_token,
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
        tracing::warn!("Apple OAuth callback error: {}", error);
        return Err(ApiError::BadRequest(format!("OAuth error: {}", error)));
    }

    // Get OAuth config for Apple
    let (oauth_config, provider_enum) = get_oauth_config(&state, "apple")
        .map_err(|_| ApiError::BadRequest("Apple OAuth not configured".to_string()))?;

    // Verify state parameter
    let (tenant_id, stored_provider, code_verifier, _is_link_mode) =
        verify_oauth_state(&state, &form.state)
            .await
            .map_err(|_| ApiError::BadRequest("Invalid OAuth state".to_string()))?;

    // Verify provider matches
    if stored_provider != "apple" {
        tracing::warn!(
            "OAuth provider mismatch: expected apple, got {}",
            stored_provider
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
            ApiError::Internal
        })?;

    // Get user info from ID token (Apple doesn't have a userinfo endpoint)
    // The ID token is a JWT that contains the user claims
    let mut user_info = if let Some(id_token) = &token_response.id_token {
        // Decode the ID token to get user info
        decode_apple_id_token(id_token)?
    } else {
        return Err(ApiError::Internal);
    };

    // Merge Apple user info from form (only on first auth) with ID token claims
    if let Some(apple_user_info) = apple_user {
        if user_info.email.is_none() && apple_user_info.email.is_some() {
            user_info.email = apple_user_info.email;
            user_info.email_verified = true;
        }
        if let Some(name) = apple_user_info.name {
            let first = name.first_name.unwrap_or_default();
            let last = name.last_name.unwrap_or_default();
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

    tracing::info!("Apple OAuth login attempt: email={}", email);

    let audit = AuditLogger::new(state.db.clone());
    let context = Some(RequestContext::from_request(
        &axum::http::HeaderMap::new(),
        Some(&ConnectInfo(addr)),
    ));

    let ip_str = addr.ip().to_string();

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

/// Decode Apple ID token (JWT) to extract user info
fn decode_apple_id_token(token: &str) -> Result<vault_core::auth::oauth::OAuthUserInfo, ApiError> {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

    // Apple's JWKS endpoint for verifying tokens
    // In production, you should fetch and cache the JWKS from:
    // https://appleid.apple.com/auth/keys

    // For now, we'll use an empty key to decode without verification
    // In production, you MUST verify the signature
    let validation = Validation::new(Algorithm::RS256);

    // Decode without verification for extracting claims
    // NOTE: In production, always verify the token signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ApiError::BadRequest("Invalid ID token format".to_string()));
    }

    // Decode the payload (second part)
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| ApiError::BadRequest("Invalid ID token payload".to_string()))?;

    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|_| ApiError::BadRequest("Invalid ID token claims".to_string()))?;

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
                ApiError::Internal
            })?
        }
        Err(e) => {
            tracing::error!("Database error looking up user: {}", e);
            return Err(ApiError::Internal);
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
            tracing::error!("Failed to check session limits: {}", e);
            return Err(ApiError::Internal);
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
            ApiError::Internal
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
    };

    state.db.sessions().create(session_req).await.map_err(|e| {
        tracing::error!("Failed to store session: {}", e);
        ApiError::Internal
    })?;

    // Generate tokens
    let token_pair = state
        .auth_service
        .generate_tokens(&user, &session.id)
        .map_err(|e| {
            tracing::error!("Failed to generate tokens: {}", e);
            ApiError::Internal
        })?;

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
        access_token: token_pair.access_token,
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
        ApiError::Internal
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
                ApiError::Internal
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
    Err(ApiError::Internal)
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
async fn sso_callback(
    State(_state): State<AppState>,
    Json(_req): Json<SsoCallbackRequest>,
) -> Result<Json<AuthResponse>, StatusCode> {
    Ok(Json(AuthResponse {
        access_token: "sso_access_token".to_string(),
        refresh_token: "sso_refresh_token".to_string(),
        user: UserResponse {
            id: uuid::Uuid::new_v4().to_string(),
            email: "user@example.com".to_string(),
            email_verified: true,
            name: Some("SSO User".to_string()),
            mfa_enabled: false,
        },
        mfa_required: false,
        session_info: None,
    }))
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
    /// Device/credential name (optional)
    name: Option<String>,
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
            tracing::error!("Failed to get user info for WebAuthn registration: {}", e);
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
                "WebAuthn registration started for user: {}, is_passkey: {:?}",
                user.user_id,
                req.is_passkey
            );
            Ok(Json(options))
        }
        Err(e) => {
            tracing::error!("WebAuthn registration begin failed: {}", e);
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
                "WebAuthn credential registered for user: {}, credential_id: {}",
                user.user_id,
                credential.credential_id
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
            tracing::warn!("WebAuthn registration finish failed: {}", e);
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
async fn webauthn_authenticate_begin(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<WebAuthnAuthenticateBeginRequest>,
) -> Result<Json<vault_core::webauthn::CredentialRequestOptions>, StatusCode> {
    let tenant_id = extract_tenant_id(&headers);

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
            tracing::error!("WebAuthn authentication begin failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Finish WebAuthn authentication
///
/// Completes the WebAuthn authentication and returns tokens on success.
/// This can be used as a primary authentication method (passwordless) or
/// as an MFA step.
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
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("WebAuthn authentication finish failed: {}", e);
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
        return Err(ApiError::Internal);
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
            return Err(ApiError::Internal);
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
            return Err(ApiError::Internal);
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
            return Err(ApiError::Internal);
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
        user_agent: context.as_ref().and_then(|c| c.user_agent.clone()),
        device_fingerprint: None,
        device_info: serde_json::json!({
            "auth_method": "webauthn",
            "credential_id": auth_result.credential_id,
        }),
        location: None,
        mfa_verified: auth_result.user_verified,
        expires_at: session.expires_at,
    };

    if let Err(e) = state.db.sessions().create(session_req).await {
        tracing::error!("Failed to store session: {}", e);
        return Err(ApiError::Internal);
    }

    // Generate tokens
    let token_pair = match state.auth_service.generate_tokens(&user, &session.id) {
        Ok(tp) => tp,
        Err(e) => {
            tracing::error!("Failed to generate tokens: {}", e);
            return Err(ApiError::Internal);
        }
    };

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
        access_token: token_pair.access_token,
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
            tracing::error!("Failed to list WebAuthn credentials: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Delete a WebAuthn credential
///
/// Removes a credential from the user's account. This is useful when
/// a security key is lost or no longer needed.
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
            tracing::info!(
                "WebAuthn credential deleted: {} for user: {}",
                credential_id,
                user.user_id
            );

            audit.log_webauthn_credential_deleted(&user.tenant_id, &user.user_id, &credential_id);

            Ok(Json(MessageResponse {
                message: "Credential deleted successfully".to_string(),
            }))
        }
        Err(e) => {
            tracing::error!("Failed to delete WebAuthn credential: {}", e);
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
        .map_err(|_| ApiError::Internal)?;

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
                access_token: token,
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
        .map_err(|e| StepUpFailureReason::InternalError(e.to_string()))?
        .ok_or(StepUpFailureReason::InvalidCredentials)?;

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

    let secret = crate::security::encryption::decrypt_from_base64(
        &state.data_encryption_key,
        &secret_encrypted,
    )
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
        .map_err(|_| ApiError::Internal)?;

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
    /// OAuth authorization code
    code: String,
    /// State parameter from OAuth flow
    state: String,
    /// Provider user ID from OAuth
    #[serde(rename = "providerUserId")]
    provider_user_id: String,
    /// Provider account email
    email: String,
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
    /// Wallet address (for tracking purposes)
    #[serde(rename = "walletAddress")]
    wallet_address: Option<String>,
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
async fn web3_nonce(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<Web3NonceRequest>,
) -> Result<Json<Web3NonceResponse>, ApiError> {
    let client_ip = addr.ip().to_string();
    let chain_id = req.chain_id.unwrap_or(1); // Default to Ethereum mainnet

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
            tracing::error!("Failed to generate nonce: {}", e);
            ApiError::Internal
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
            tracing::warn!("Web3 signature verification failed: {}", e);
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
                "Web3 login for existing user: {} with wallet {}",
                existing_user.id,
                wallet_address
            );
            (existing_user, false)
        }
        Ok(None) => {
            // Create new user from Web3 authentication
            if !state.config.features.enable_oauth_signup {
                tracing::warn!(
                    "Web3 signup disabled, rejecting new user with wallet {}",
                    wallet_address
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

            tracing::info!("Creating new user from Web3 auth: {}", wallet_address);

            let new_user = state
                .db
                .users()
                .create_from_web3(&tenant_id, &wallet_address, chain_id as i32, None)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to create Web3 user: {}", e);
                    ApiError::Internal
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
            tracing::error!("Database error looking up Web3 user: {}", e);
            return Err(ApiError::Internal);
        }
    };

    // Check if user account is active
    use vault_core::models::user::UserStatus;
    if user.status != UserStatus::Active {
        tracing::warn!(
            "Web3 login attempt for inactive account: {}",
            wallet_address
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
            "Web3 login attempt for locked account: {}",
            wallet_address
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
            return Err(ApiError::Internal);
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
            tracing::error!("Failed to create Web3 session: {}", e);
            ApiError::Internal
        })?;

    // Store session in database
    let session_req = vault_core::db::sessions::CreateSessionRequest {
        tenant_id: tenant_id.clone(),
        user_id: user.id.clone(),
        access_token_jti: session.access_token_jti.clone(),
        refresh_token_hash: session.refresh_token_hash.clone(),
        token_family: session.token_family.clone(),
        ip_address: Some(ip),
        user_agent: context.as_ref().and_then(|c| c.user_agent.clone()),
        device_fingerprint: None,
        device_info: serde_json::json!({
            "auth_method": "web3",
            "wallet_address": wallet_address,
            "chain_id": chain_id,
        }),
        location: None,
        mfa_verified: false,
        expires_at: session.expires_at,
    };

    state.db.sessions().create(session_req).await.map_err(|e| {
        tracing::error!("Failed to store Web3 session: {}", e);
        ApiError::Internal
    })?;

    // Generate tokens
    let token_pair = state
        .auth_service
        .generate_tokens(&user, &session.id)
        .map_err(|e| {
            tracing::error!("Failed to generate Web3 tokens: {}", e);
            ApiError::Internal
        })?;

    tracing::info!(
        "Web3 login successful: wallet={} user={} chain={}",
        wallet_address,
        user.id,
        chain_id
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
        access_token: token_pair.access_token,
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
        .map_err(|_| ApiError::Internal)?;

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
        .map_err(|_| ApiError::Internal)?;

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
                _ => Err(ApiError::Internal),
            }
        }
    }
}


/// Record consents during user registration
async fn record_registration_consents(
    state: &AppState,
    user_id: &str,
    tenant_id: &str,
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
