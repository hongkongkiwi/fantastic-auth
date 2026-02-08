//! Authentication middleware

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;
use vault_core::crypto::{HybridJwt, TokenType};

use crate::audit::{AuditLogger, RequestContext};
use crate::security::{
    parse_device_info, BindingAction, BindingRequestContext, BindingResult, SessionBindingChecker,
    SessionBindingConfig, SessionBindingInfo,
};
use crate::state::{AppState, CurrentUser};

/// Extract JWT token from Authorization header
fn extract_token(request: &Request) -> Option<&str> {
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;

    // Check for Bearer token
    if auth_header.starts_with("Bearer ") {
        Some(&auth_header[7..])
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
                    Some(&current_user.user_id),
                    Some(session_id),
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
                // Error during binding check - log but don't fail
                tracing::warn!("Session binding check error: {}", e);
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
        .map(|roles| roles.iter().any(|r| r == "admin" || r == "superadmin"))
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
            tracing::warn!("Failed to find session for binding check: {}", e);
            return Ok(BindingAction::Allow); // Allow on error (fail open for availability)
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
