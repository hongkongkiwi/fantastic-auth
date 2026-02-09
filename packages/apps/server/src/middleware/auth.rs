//! Authentication middleware

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;
use vault_core::crypto::{Claims, HybridJwt, TokenType};

use crate::audit::{AuditLogger, RequestContext};
use crate::security::{
    parse_device_info, BindingAction, BindingRequestContext, BindingResult, SessionBindingChecker,
    SessionBindingConfig, SessionBindingInfo,
};
use crate::state::{AppState, CurrentUser};

/// Extract JWT token from Authorization header
/// 
/// SECURITY: Uses constant-time prefix comparison to prevent timing attacks.
/// Standard string comparison (`starts_with`) can leak information about the
/// prefix through timing side channels. This implementation compares all bytes
/// regardless of mismatches to ensure constant-time execution.
fn extract_token(request: &Request) -> Option<&str> {
    use subtle::ConstantTimeEq;
    
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;

    // SECURITY: Constant-time Bearer prefix check to prevent timing attacks
    // that could reveal information about the expected header format.
    const BEARER_PREFIX: &str = "Bearer ";
    const PREFIX_LEN: usize = BEARER_PREFIX.len();
    
    // Check if header is long enough to contain a token
    if auth_header.len() <= PREFIX_LEN {
        return None;
    }
    
    // Constant-time comparison of the "Bearer " prefix
    let header_prefix = &auth_header.as_bytes()[..PREFIX_LEN.min(auth_header.len())];
    let expected_prefix = BEARER_PREFIX.as_bytes();
    
    // Use subtle crate for constant-time comparison
    let prefix_matches = header_prefix.ct_eq(expected_prefix).into();
    
    if prefix_matches {
        // SECURITY: After constant-time prefix check, extract token
        // The token portion is returned only after successful prefix validation
        Some(&auth_header[PREFIX_LEN..])
    } else {
        None
    }
}

/// Authentication middleware
///
/// Extracts JWT from Authorization header and validates it.
/// Adds CurrentUser to request extensions if valid.
pub async fn auth_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract tenant ID from headers for audit logging
    let tenant_id = request
        .headers()
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("default");

    // Create request context for audit logging
    let context = RequestContext::from_request(request.headers(), Some(&ConnectInfo(addr)));

    // Extract token
    let token = match extract_token(&request) {
        Some(t) => t,
        None => {
            // Log failed session validation (no token)
            let audit = AuditLogger::new(state.db.clone());
            audit.log_session_validation(
                tenant_id,
                None,
                None,
                Some(context),
                false,
                Some("No authentication token provided"),
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Validate token
    let claims = match validate_token(token, &state).await {
        Some(c) => c,
        None => {
            // Log failed session validation (invalid token)
            let audit = AuditLogger::new(state.db.clone());
            audit.log_session_validation(
                tenant_id,
                None,
                None,
                Some(context),
                false,
                Some("Invalid or expired token"),
            );
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Extract impersonation info from custom claims
    let impersonator_id = claims
        .custom
        .get("impersonator_id")
        .and_then(|v| v.as_str().map(|s| s.to_string()));
    let is_impersonation = claims
        .custom
        .get("is_impersonation")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Create current user
    let current_user = CurrentUser {
        user_id: claims.sub.clone(),
        tenant_id: claims.tenant_id.clone(),
        session_id: claims.session_id.clone(),
        email: claims.email.clone().unwrap_or_default(),
        email_verified: claims.email_verified.unwrap_or(false),
        mfa_authenticated: claims.mfa_authenticated.unwrap_or(false),
        claims,
        impersonator_id,
        is_impersonation,
    };

    // Set tenant context for database queries
    if let Err(_) = state.set_tenant_context(&current_user.tenant_id).await {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // Check session binding if session ID is present
    if let Some(ref session_id) = current_user.session_id {
        let ip = addr.ip();
        match check_session_binding(
            &state,
            &current_user.tenant_id,
            session_id,
            &current_user.user_id,
            ip,
            request.headers(),
        )
        .await
        {
            Ok(BindingAction::Allow) => {
                // Continue normally
            }
            Ok(BindingAction::Block) => {
                // Session binding violation - force re-login
                tracing::warn!(
                    "Session binding violation blocked for user {} session {}",
                    current_user.user_id,
                    session_id
                );

                // Log the violation
                let audit = AuditLogger::new(state.db.clone());
                audit.log(
                    &current_user.tenant_id,
                    crate::audit::AuditAction::SessionValidationFailed,
                    crate::audit::ResourceType::Session,
                    session_id,
                    Some(current_user.user_id.clone()),
                    Some(session_id.clone()),
                    Some(context.clone()),
                    false,
                    Some("Session binding violation".to_string()),
                    Some(serde_json::json!({
                        "ip": ip.to_string(),
                    })),
                );

                return Err(StatusCode::UNAUTHORIZED);
            }
            Ok(BindingAction::RequireVerification) => {
                // In strict mode, we might require step-up auth
                // For now, log and allow (advisory mode)
                tracing::info!(
                    "Session binding verification required for user {} session {}",
                    current_user.user_id,
                    session_id
                );
            }
            Err(e) => {
                // Error during binding check - fail securely
                tracing::error!("Session binding check error: {}", e);
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
    }

    // Log successful session validation
    let audit = AuditLogger::new(state.db.clone());
    audit.log_session_validation(
        &current_user.tenant_id,
        Some(&current_user.user_id),
        current_user.session_id.as_deref(),
        Some(context),
        true,
        None,
    );

    // Add user to request extensions
    request.extensions_mut().insert(current_user.clone());

    let role = current_user.claims.roles.as_ref().and_then(|roles| {
        if roles
            .iter()
            .any(|r| r == "admin" || r == "owner" || r == "support" || r == "viewer")
        {
            Some("admin".to_string())
        } else {
            Some("member".to_string())
        }
    });

    let ctx = vault_core::db::RequestContext {
        tenant_id: Some(current_user.tenant_id.clone()),
        user_id: Some(current_user.user_id.clone()),
        role,
    };

    Ok(vault_core::db::with_request_context(ctx, next.run(request)).await)
}

/// Optional authentication middleware
///
/// Same as auth_middleware but doesn't fail if no token is present.
/// Adds CurrentUser to request extensions if token is valid.
pub async fn optional_auth_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // Try to extract token
    if let Some(token) = extract_token(&request) {
        if let Some(claims) = validate_token(token, &state).await {
            // Extract impersonation info from custom claims
            let impersonator_id = claims
                .custom
                .get("impersonator_id")
                .and_then(|v| v.as_str().map(|s| s.to_string()));
            let is_impersonation = claims
                .custom
                .get("is_impersonation")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let current_user = CurrentUser {
                user_id: claims.sub.clone(),
                tenant_id: claims.tenant_id.clone(),
                session_id: claims.session_id.clone(),
                email: claims.email.clone().unwrap_or_default(),
                email_verified: claims.email_verified.unwrap_or(false),
                mfa_authenticated: claims.mfa_authenticated.unwrap_or(false),
                claims,
                impersonator_id,
                is_impersonation,
            };

            // Set tenant context
            let _ = state.set_tenant_context(&current_user.tenant_id).await;

            // Add user to request extensions
            request.extensions_mut().insert(current_user.clone());

            let role = current_user.claims.roles.as_ref().and_then(|roles| {
                if roles
                    .iter()
                    .any(|r| r == "admin" || r == "owner" || r == "support" || r == "viewer")
                {
                    Some("admin".to_string())
                } else {
                    Some("member".to_string())
                }
            });

            let ctx = vault_core::db::RequestContext {
                tenant_id: Some(current_user.tenant_id.clone()),
                user_id: Some(current_user.user_id.clone()),
                role,
            };

            return vault_core::db::with_request_context(ctx, next.run(request)).await;
        }
    }

    // Note: We don't log optional auth attempts to avoid noise in audit logs
    // since this middleware is used for endpoints where auth is truly optional

    let ctx = vault_core::db::RequestContext::default();
    vault_core::db::with_request_context(ctx, next.run(request)).await
}

/// Validate JWT token
///
/// Uses the AuthService's verifying key to validate the token.
/// Returns None if the token is invalid or expired.
async fn validate_token(token: &str, state: &AppState) -> Option<vault_core::crypto::Claims> {
    // Get the verifying key from the auth service
    let verifying_key = state.auth_service.verifying_key();

    // Decode and validate the token
    match HybridJwt::decode(token, verifying_key) {
        Ok(claims) => {
            // Verify it's an access token
            if claims.token_type != TokenType::Access {
                tracing::warn!("Token validation failed: not an access token");
                return None;
            }

            // Check expiration (HybridJwt::decode should already check this,
            // but let's be extra safe)
            let now = chrono::Utc::now().timestamp();
            if claims.exp < now {
                tracing::warn!("Token validation failed: token expired");
                return None;
            }

            // Check not-before time
            if claims.nbf > now {
                tracing::warn!("Token validation failed: token not yet valid");
                return None;
            }

            Some(claims)
        }
        Err(e) => {
            tracing::warn!("Token validation failed: {}", e);
            None
        }
    }
}

/// Require MFA middleware
///
/// Must be used after auth_middleware.
/// Checks if the user has completed MFA authentication.
pub async fn require_mfa_middleware(request: Request, next: Next) -> Result<Response, StatusCode> {
    // Get current user from extensions
    let user = request
        .extensions()
        .get::<CurrentUser>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if MFA is authenticated
    if !user.mfa_authenticated {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// Admin role middleware
///
/// Must be used after auth_middleware.
/// Checks if the user has admin role in their claims.
pub async fn admin_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get current user from extensions
    let user = request
        .extensions()
        .get::<CurrentUser>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if user has admin role in claims
    let is_admin = user
        .claims
        .roles
        .as_ref()
        .map(|roles| {
            roles.iter().any(|r| {
                r == "admin" || r == "owner" || r == "support" || r == "viewer" || r == "superadmin"
            })
        })
        .unwrap_or(false);

    // Log admin access check
    let audit = AuditLogger::new(state.db.clone());
    audit.log_admin_access(&user.tenant_id, &user.user_id, is_admin);

    if !is_admin {
        tracing::warn!(
            "Admin access denied for user {} (tenant: {})",
            user.user_id,
            user.tenant_id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// Superadmin middleware
///
/// Must be used after auth_middleware.
/// Checks if the user has superadmin role.
pub async fn superadmin_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get current user from extensions
    let user = request
        .extensions()
        .get::<CurrentUser>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if user has superadmin role in claims
    let is_superadmin = user
        .claims
        .roles
        .as_ref()
        .map(|roles| roles.iter().any(|r| r == "superadmin"))
        .unwrap_or(false);

    // Log superadmin access check
    let audit = AuditLogger::new(state.db.clone());
    audit.log_superadmin_access(&user.tenant_id, &user.user_id, is_superadmin);

    if !is_superadmin {
        tracing::warn!(
            "Superadmin access denied for user {} (tenant: {})",
            user.user_id,
            user.tenant_id
        );
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// Internal API authentication middleware
///
/// Accepts either:
/// - `X-API-Key` header matching `internal_api_key`
/// - `Authorization: Bearer <token>` with `superadmin` role
///
/// Injects a CurrentUser into extensions and sets request context.
pub async fn internal_auth_middleware(mut request: Request, next: Next) -> Response {
    let state = match request.extensions().get::<AppState>().cloned() {
        Some(state) => state,
        None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let addr = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

    // API key auth (preferred for internal UI)
    if let Some(api_key_header) = request.headers().get("X-API-Key") {
        let required_key = match &state.config.internal_api_key {
            Some(key) => key.as_bytes(),
            None => return StatusCode::UNAUTHORIZED.into_response(),
        };

        if let Ok(provided) = api_key_header.to_str() {
            use subtle::ConstantTimeEq;
            if provided.as_bytes().ct_eq(required_key).into() {
                let tenant_id = match &state.config.internal_admin_tenant_id {
                    Some(id) => id.clone(),
                    None => return StatusCode::UNAUTHORIZED.into_response(),
                };

                let mut claims = Claims::new(
                    "internal-api-key",
                    tenant_id.clone(),
                    TokenType::ApiKey,
                    state.config.jwt.issuer.clone(),
                    state.config.jwt.audience.clone(),
                );
                claims.roles = Some(vec!["superadmin".to_string()]);
                claims.mfa_authenticated = Some(true);

                let current_user = CurrentUser {
                    user_id: claims.sub.clone(),
                    tenant_id: tenant_id.clone(),
                    session_id: None,
                    email: String::new(),
                    email_verified: false,
                    mfa_authenticated: true,
                    claims: claims.clone(),
                    impersonator_id: None,
                    is_impersonation: false,
                };

                let audit = AuditLogger::new(state.db.clone());
                audit.log_superadmin_access(&tenant_id, &current_user.user_id, true);

                request.extensions_mut().insert(current_user);

                let ctx = vault_core::db::RequestContext {
                    tenant_id: Some(tenant_id),
                    user_id: Some(claims.sub),
                    role: Some("superadmin".to_string()),
                };

                return vault_core::db::with_request_context(ctx, next.run(request)).await;
            }
        }

        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Bearer token auth
    if let Some(token) = extract_token(&request) {
        if let Ok(claims) = HybridJwt::decode(token, state.auth_service.verifying_key()) {
            if !matches!(claims.token_type, TokenType::Access | TokenType::ApiKey) {
                return StatusCode::UNAUTHORIZED.into_response();
            }
            let is_superadmin = claims
                .roles
                .as_ref()
                .map(|roles| roles.iter().any(|r| r == "superadmin"))
                .unwrap_or(false);

            if !is_superadmin {
                let audit = AuditLogger::new(state.db.clone());
                audit.log_superadmin_access(&claims.tenant_id, &claims.sub, false);
                return StatusCode::FORBIDDEN.into_response();
            }

            let current_user = CurrentUser {
                user_id: claims.sub.clone(),
                tenant_id: claims.tenant_id.clone(),
                session_id: claims.session_id.clone(),
                email: claims.email.clone().unwrap_or_default(),
                email_verified: claims.email_verified.unwrap_or(false),
                mfa_authenticated: claims.mfa_authenticated.unwrap_or(false),
                claims: claims.clone(),
                impersonator_id: claims
                    .custom
                    .get("impersonator_id")
                    .and_then(|v| v.as_str().map(|s| s.to_string())),
                is_impersonation: claims
                    .custom
                    .get("is_impersonation")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            };

            let audit = AuditLogger::new(state.db.clone());
            audit.log_superadmin_access(&current_user.tenant_id, &current_user.user_id, true);

            request.extensions_mut().insert(current_user.clone());

            let role = current_user
                .claims
                .roles
                .as_ref()
                .and_then(|roles| {
                    if roles.iter().any(|r| r == "superadmin") {
                        Some("superadmin".to_string())
                    } else {
                        None
                    }
                });

            let ctx = vault_core::db::RequestContext {
                tenant_id: Some(current_user.tenant_id),
                user_id: Some(current_user.user_id),
                role,
            };

            return vault_core::db::with_request_context(ctx, next.run(request)).await;
        }
    }

    tracing::warn!("Internal auth failed from {}", addr);
    StatusCode::UNAUTHORIZED.into_response()
}

/// Check session binding for potential hijacking
///
/// Returns the action that should be taken based on the binding check
async fn check_session_binding(
    state: &AppState,
    tenant_id: &str,
    session_id: &str,
    user_id: &str,
    ip: std::net::IpAddr,
    headers: &axum::http::HeaderMap,
) -> anyhow::Result<BindingAction> {
    // Get session from database
    let session = match state.db.sessions().find_by_id(tenant_id, session_id).await {
        Ok(s) => s,
        Err(e) => {
            // SECURITY: Fail closed - block request if we can't verify session binding
            // This prevents session hijacking during database outages
            tracing::error!(
                "SECURITY: Session binding check failed, blocking request. Session: {}, Error: {}",
                session_id, e
            );
            return Ok(BindingAction::Block);
        }
    };

    // Build session binding info
    let binding_info = SessionBindingInfo {
        session_id: session.id,
        user_id: session.user_id,
        tenant_id: session.tenant_id,
        created_ip: session.created_ip,
        created_device_hash: session.created_device_hash,
        bind_to_ip: session.bind_to_ip,
        bind_to_device: session.bind_to_device,
        violation_count: session.binding_violation_count as u32,
    };

    // Build request context
    let binding_context = BindingRequestContext::new(Some(ip), headers.clone());

    // Get binding level from config
    let config = SessionBindingConfig::default();
    let checker = SessionBindingChecker::with_config(config);

    // Perform binding check
    match checker.check_binding(&binding_info, &binding_context) {
        BindingResult::Valid => Ok(BindingAction::Allow),
        BindingResult::Violation {
            violation_type,
            action,
            details,
        } => {
            tracing::warn!(
                "Session binding violation: {:?} for session {} (action: {:?})",
                violation_type,
                session_id,
                action
            );

            // Increment violation count
            if let Err(e) = state
                .db
                .sessions()
                .increment_violation_count(tenant_id, session_id)
                .await
            {
                tracing::warn!("Failed to increment violation count: {}", e);
            }

            // Send notification if configured
            if details.is_suspicious || details.risk_score > 50 {
                // Notification would be sent here
                tracing::info!(
                    "High risk binding violation detected for user {}: score {}",
                    user_id,
                    details.risk_score
                );
            }

            Ok(action)
        }
    }
}
