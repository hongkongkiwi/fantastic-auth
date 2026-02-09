//! Client User Routes
//!
//! End-user profile management endpoints.

use axum::{
    extract::{ConnectInfo, FromRequestParts, State},
    http::{request::Parts, StatusCode},
    http::HeaderMap,
    middleware,
    routing::{delete, get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::audit::{AuditLogger, RequestContext};
use crate::auth::{AuthProvider, LinkAccountRequest};
use crate::middleware::StepUpUserExt;
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser, SessionLimitStatus};
use axum::extract::Path;

/// User routes
///
/// Sensitive operations (change password, delete account) require step-up authentication.
pub fn routes() -> Router<AppState> {
    // Standard routes
    let standard_routes = Router::new()
        .route("/me", get(get_current_user).patch(update_current_user))
        .route(
            "/me/sessions",
            get(list_my_sessions).delete(revoke_all_my_sessions),
        )
        .route("/me/sessions/:session_id", delete(revoke_my_session))
        // Linked accounts endpoints
        .route(
            "/me/linked-accounts",
            get(list_linked_accounts).post(link_account),
        )
        .route("/me/linked-accounts/:provider", delete(unlink_account))
        .route(
            "/me/linked-accounts/:provider/primary",
            post(set_primary_account),
        );
        // Note: Wallet endpoints (get_wallet_info, link_wallet, unlink_wallet) 
        // are planned but not yet implemented

    // Routes requiring elevated step-up (change password)
    let elevated_routes = Router::new()
        .route("/me/password", post(change_password))
        .route_layer(middleware::from_extractor::<RequireStepUpChangePassword>());

    // Routes requiring high assurance step-up (delete account)
    let high_assurance_routes = Router::new()
        .route("/me", delete(delete_current_user))
        .route_layer(middleware::from_extractor::<RequireStepUpDeleteAccount>());

    // Combine all routes
    Router::new()
        .merge(standard_routes)
        .merge(elevated_routes)
        .merge(high_assurance_routes)
}

struct RequireStepUpChangePassword;
struct RequireStepUpDeleteAccount;

#[axum::async_trait]
impl<S> FromRequestParts<S> for RequireStepUpChangePassword
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user = parts
            .extensions
            .get::<CurrentUser>()
            .ok_or(StatusCode::UNAUTHORIZED)?;
        if !user.has_step_up(&vault_core::crypto::StepUpLevel::Elevated) || user.is_step_up_expired()
        {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(Self)
    }
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for RequireStepUpDeleteAccount
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user = parts
            .extensions
            .get::<CurrentUser>()
            .ok_or(StatusCode::UNAUTHORIZED)?;
        if !user.has_step_up(&vault_core::crypto::StepUpLevel::HighAssurance)
            || user.is_step_up_expired()
        {
            return Err(StatusCode::FORBIDDEN);
        }
        Ok(Self)
    }
}

#[derive(Debug, Deserialize)]
struct UpdateUserRequest {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    id: String,
    email: String,
    name: Option<String>,
    #[serde(rename = "emailVerified")]
    email_verified: bool,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

/// Session response for listing sessions
#[derive(Debug, Serialize)]
struct SessionResponse {
    id: String,
    #[serde(rename = "createdAt")]
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "lastActivityAt")]
    last_activity_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "expiresAt")]
    expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "ipAddress")]
    ip_address: Option<String>,
    #[serde(rename = "userAgent")]
    user_agent: Option<String>,
    #[serde(rename = "deviceInfo")]
    device_info: serde_json::Value,
    #[serde(rename = "mfaVerified")]
    mfa_verified: bool,
    current: bool,
}

/// Session list response with limit info
#[derive(Debug, Serialize)]
struct SessionListResponse {
    sessions: Vec<SessionResponse>,
    #[serde(rename = "currentSessions")]
    current_sessions: usize,
    #[serde(rename = "maxSessions")]
    max_sessions: usize,
    warning: Option<String>,
}

/// Get current user profile
async fn get_current_user(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<UserResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let user = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(UserResponse {
        id: user.id,
        email: user.email,
        name: user.profile.name,
        email_verified: user.email_verified,
    }))
}

/// Update current user
async fn update_current_user(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let mut user = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    if let Some(name) = req.name {
        user.profile.name = Some(name);
    }

    let user = state
        .db
        .users()
        .update(&current_user.tenant_id, &user)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Trigger webhook event
    crate::webhooks::events::trigger_user_updated(
        &state,
        &current_user.tenant_id,
        &user.id,
        &user.email,
        vec!["profile".to_string()],
    )
    .await;

    Ok(Json(UserResponse {
        id: user.id,
        email: user.email,
        name: user.profile.name,
        email_verified: user.email_verified,
    }))
}

/// Delete current user
async fn delete_current_user(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Get user info before deletion for webhook
    let user = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    state
        .db
        .users()
        .delete(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Trigger webhook event
    if let Some(user) = user {
        crate::webhooks::events::trigger_user_deleted(
            &state,
            &current_user.tenant_id,
            &current_user.user_id,
            &user.email,
        )
        .await;
    }

    Ok(Json(MessageResponse {
        message: "Account deleted".to_string(),
    }))
}

/// Change password
async fn change_password(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());

    let (_user, password_hash) = state
        .db
        .users()
        .find_by_email_with_password_legacy(&current_user.tenant_id, &current_user.email)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Verify current password
    if let Some(hash) = password_hash {
        if !vault_core::crypto::VaultPasswordHasher::verify(&req.current_password, &hash)
            .map_err(|_| ApiError::Internal)?
        {
            // Log failed password change
            audit.log_password_change(
                &current_user.tenant_id,
                &current_user.user_id,
                current_user.session_id.as_deref(),
                context,
                false,
                Some("Current password verification failed"),
            );
            return Err(ApiError::Unauthorized);
        }
    }

    // Hash new password
    let new_hash = vault_core::crypto::VaultPasswordHasher::hash(&req.new_password)
        .map_err(|_| ApiError::Internal)?;

    state
        .db
        .users()
        .update_password(&current_user.tenant_id, &current_user.user_id, &new_hash)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Log successful password change
    audit.log_password_change(
        &current_user.tenant_id,
        &current_user.user_id,
        current_user.session_id.as_deref(),
        context,
        true,
        None,
    );

    // Trigger webhook event
    crate::webhooks::events::trigger_password_changed(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        &current_user.email,
    )
    .await;

    Ok(Json(MessageResponse {
        message: "Password changed".to_string(),
    }))
}

/// List current user's active sessions
async fn list_my_sessions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SessionListResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Get all active sessions for the user
    let sessions = state
        .db
        .sessions()
        .list_by_user(&current_user.tenant_id, &current_user.user_id, true)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Get session limit status
    let limit_status = state
        .get_session_limit_status(&current_user.tenant_id, &current_user.user_id)
        .await
        .unwrap_or(SessionLimitStatus {
            current_sessions: sessions.len(),
            max_sessions: state.config.security.session_limits.max_concurrent_sessions,
            warning: None,
        });

    // Convert sessions to response format
    let session_responses: Vec<SessionResponse> = sessions
        .into_iter()
        .map(|s| SessionResponse {
            id: s.id.clone(),
            created_at: s.created_at,
            last_activity_at: s.last_activity_at,
            expires_at: s.expires_at,
            ip_address: s.ip_address,
            user_agent: s.user_agent,
            device_info: s.device_info,
            mfa_verified: s.mfa_verified,
            current: current_user.session_id.as_ref() == Some(&s.id),
        })
        .collect();

    Ok(Json(SessionListResponse {
        sessions: session_responses,
        current_sessions: limit_status.current_sessions,
        max_sessions: limit_status.max_sessions,
        warning: limit_status.warning,
    }))
}

/// Revoke a specific session
async fn revoke_my_session(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(session_id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Verify the session belongs to the current user
    let session = state
        .db
        .sessions()
        .find_by_id(&current_user.tenant_id, &session_id)
        .await
        .map_err(|_| ApiError::NotFound)?;

    if session.user_id != current_user.user_id {
        return Err(ApiError::Forbidden);
    }

    // Revoke the session
    state
        .db
        .sessions()
        .revoke(&current_user.tenant_id, &session_id, Some("user_revoked"))
        .await
        .map_err(|_| ApiError::Internal)?;

    // Trigger webhook
    crate::webhooks::events::trigger_session_revoked(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        &session_id,
        Some("user_revoked"),
    )
    .await;

    Ok(Json(MessageResponse {
        message: "Session revoked".to_string(),
    }))
}

/// Revoke all sessions except current
async fn revoke_all_my_sessions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let current_session_id = current_user
        .session_id
        .as_deref()
        .ok_or(ApiError::BadRequest("No active session".to_string()))?;

    // Revoke all sessions except current
    let revoked_count = state
        .db
        .sessions()
        .revoke_all_except(
            &current_user.tenant_id,
            &current_user.user_id,
            current_session_id,
            Some("user_revoked_all"),
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    // Trigger webhook
    crate::webhooks::events::trigger_session_revoked(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        "all_except_current",
        Some("user_revoked_all"),
    )
    .await;

    Ok(Json(MessageResponse {
        message: format!("Revoked {} sessions", revoked_count),
    }))
}

// ============ Linked Accounts ============

/// Linked account response
#[derive(Debug, Serialize)]
struct LinkedAccountResponse {
    id: String,
    provider: String,
    #[serde(rename = "providerAccountId")]
    provider_account_id: String,
    #[serde(rename = "providerData")]
    provider_data: serde_json::Value,
    #[serde(rename = "isVerified")]
    is_verified: bool,
    #[serde(rename = "isPrimary")]
    is_primary: bool,
    #[serde(rename = "linkedAt")]
    linked_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "lastUsedAt")]
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request to link a new account
#[derive(Debug, Deserialize)]
struct LinkAccountRequestBody {
    provider: String,
    #[serde(rename = "providerAccountId")]
    provider_account_id: String,
    #[serde(rename = "providerData")]
    provider_data: Option<serde_json::Value>,
}

/// List linked accounts for the current user
async fn list_linked_accounts(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<LinkedAccountResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let accounts = state
        .account_linking_service
        .list_linked_accounts(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list linked accounts: {}", e);
            ApiError::Internal
        })?;

    let responses: Vec<LinkedAccountResponse> = accounts
        .into_iter()
        .map(|a| LinkedAccountResponse {
            id: a.id,
            provider: a.provider,
            provider_account_id: a.provider_account_id,
            provider_data: a.provider_data,
            is_verified: a.is_verified,
            is_primary: a.is_primary,
            linked_at: a.linked_at,
            last_used_at: a.last_used_at,
        })
        .collect();

    Ok(Json(responses))
}

/// Link a new authentication method to the current user
async fn link_account(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LinkAccountRequestBody>,
) -> Result<Json<LinkedAccountResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());

    // Parse provider
    let provider = req
        .provider
        .parse::<AuthProvider>()
        .map_err(|e| ApiError::Validation(e))?;

    let link_req = LinkAccountRequest {
        tenant_id: current_user.tenant_id.clone(),
        user_id: current_user.user_id.clone(),
        provider,
        provider_account_id: req.provider_account_id.clone(),
        provider_data: req.provider_data,
        is_verified: true, // In production, verify via OAuth/token
    };

    match state.account_linking_service.link_account(link_req).await {
        Ok(account) => {
            // Log successful linking
            audit.log_account_linked(
                &current_user.tenant_id,
                &current_user.user_id,
                &req.provider,
                &req.provider_account_id,
                context,
                true,
                None,
            );

            Ok(Json(LinkedAccountResponse {
                id: account.id,
                provider: account.provider,
                provider_account_id: account.provider_account_id,
                provider_data: account.provider_data,
                is_verified: account.is_verified,
                is_primary: account.is_primary,
                linked_at: account.linked_at,
                last_used_at: account.last_used_at,
            }))
        }
        Err(e) => {
            tracing::warn!("Failed to link account: {}", e);

            let error_msg = e.to_string();
            audit.log_account_linked(
                &current_user.tenant_id,
                &current_user.user_id,
                &req.provider,
                &req.provider_account_id,
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
                crate::auth::AccountLinkingError::Validation(msg) => Err(ApiError::Validation(msg)),
                _ => Err(ApiError::Internal),
            }
        }
    }
}

/// Unlink an authentication method from the current user
async fn unlink_account(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());

    // Parse provider
    let provider = provider
        .parse::<AuthProvider>()
        .map_err(|e| ApiError::Validation(e))?;

    match state
        .account_linking_service
        .unlink_account(&current_user.tenant_id, &current_user.user_id, provider)
        .await
    {
        Ok(()) => {
            audit.log_account_unlinked(
                &current_user.tenant_id,
                &current_user.user_id,
                provider.as_str(),
                context,
                true,
                None,
            );

            Ok(Json(MessageResponse {
                message: "Account unlinked successfully".to_string(),
            }))
        }
        Err(e) => {
            tracing::warn!("Failed to unlink account: {}", e);

            let error_msg = e.to_string();
            audit.log_account_unlinked(
                &current_user.tenant_id,
                &current_user.user_id,
                provider.as_str(),
                context,
                false,
                Some(&error_msg),
            );

            match e {
                crate::auth::AccountLinkingError::CannotUnlinkLast => Err(ApiError::BadRequest(
                    "Cannot unlink the last authentication method".to_string(),
                )),
                crate::auth::AccountLinkingError::CannotUnlinkPrimary => Err(ApiError::BadRequest(
                    "Cannot unlink primary authentication method. Set another as primary first."
                        .to_string(),
                )),
                crate::auth::AccountLinkingError::NotFound => Err(ApiError::NotFound),
                _ => Err(ApiError::Internal),
            }
        }
    }
}

/// Set a linked account as the primary authentication method
async fn set_primary_account(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));
    let audit = AuditLogger::new(state.db.clone());

    // Parse provider
    let provider = provider
        .parse::<AuthProvider>()
        .map_err(|e| ApiError::Validation(e))?;

    match state
        .account_linking_service
        .set_primary_account(&current_user.tenant_id, &current_user.user_id, provider)
        .await
    {
        Ok(()) => {
            audit.log_primary_account_changed(
                &current_user.tenant_id,
                &current_user.user_id,
                provider.as_str(),
                context,
            );

            Ok(Json(MessageResponse {
                message: "Primary account updated".to_string(),
            }))
        }
        Err(e) => {
            tracing::warn!("Failed to set primary account: {}", e);

            match e {
                crate::auth::AccountLinkingError::NotFound => Err(ApiError::NotFound),
                _ => Err(ApiError::Internal),
            }
        }
    }
}
