//! Admin Impersonation Routes
//!
//! Provides endpoints for admin user impersonation:
//! - POST /api/v1/admin/users/:user_id/impersonate - Start impersonating a user
//! - DELETE /api/v1/admin/impersonation - End current impersonation
//! - GET /api/v1/admin/impersonations - List active impersonations
//!
//! # Security
//!
//! All endpoints require admin privileges. Impersonation is restricted by
//! privilege levels and all actions are audited.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use validator::Validate;

use crate::audit::{AuditLogger, RequestContext};
use crate::impersonation::{CreateImpersonationRequest, ImpersonationService};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::models::user::UserStatus;

/// Impersonation routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/users/:user_id/impersonate", post(start_impersonation))
        .route("/impersonation", delete(end_impersonation))
        .route("/impersonations", get(list_impersonations))
}

// ============ Request/Response Types ============

/// Start impersonation request
#[derive(Debug, Deserialize, Validate)]
pub struct StartImpersonationRequest {
    /// Reason for impersonation (required for audit)
    #[validate(length(min = 5, max = 500, message = "Reason must be between 5 and 500 characters"))]
    pub reason: String,
    /// Duration in minutes (default: 30, max: 60)
    #[validate(range(min = 5, max = 60, message = "Duration must be between 5 and 60 minutes"))]
    #[serde(default = "default_impersonation_duration")]
    pub duration_minutes: i64,
}

fn default_impersonation_duration() -> i64 {
    30
}

/// Impersonation response
#[derive(Debug, Serialize)]
pub struct ImpersonationResponse {
    /// Access token for the impersonated user
    pub access_token: String,
    /// Refresh token for the impersonated user
    pub refresh_token: String,
    /// Token type (always "Bearer")
    pub token_type: String,
    /// Token expiration time in seconds
    pub expires_in: i64,
    /// Information about the impersonated user
    pub impersonated_user: ImpersonatedUserInfo,
    /// ID of the admin who is impersonating
    pub impersonator_id: String,
    /// When the impersonation expires
    pub impersonation_expires_at: String,
    /// Session ID for the impersonation
    pub session_id: String,
}

/// Impersonated user information
#[derive(Debug, Serialize)]
pub struct ImpersonatedUserInfo {
    pub id: String,
    pub email: String,
    pub name: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: bool,
}

/// List impersonations query parameters
#[derive(Debug, Deserialize)]
pub struct ListImpersonationsQuery {
    /// Page number (1-based)
    #[serde(default = "default_page")]
    pub page: i64,
    /// Items per page (max 100)
    #[serde(default = "default_per_page")]
    pub per_page: i64,
    /// Filter by admin user ID
    pub admin_id: Option<String>,
    /// Filter by target user ID
    pub target_user_id: Option<String>,
}

fn default_page() -> i64 {
    1
}

fn default_per_page() -> i64 {
    20
}

/// List impersonations response
#[derive(Debug, Serialize)]
pub struct ListImpersonationsResponse {
    pub sessions: Vec<ImpersonationSessionResponse>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

/// Single impersonation session response
#[derive(Debug, Serialize)]
pub struct ImpersonationSessionResponse {
    pub id: String,
    #[serde(rename = "adminId")]
    pub admin_id: String,
    #[serde(rename = "targetUserId")]
    pub target_user_id: String,
    #[serde(rename = "targetEmail")]
    pub target_email: String,
    #[serde(rename = "targetName")]
    pub target_name: Option<String>,
    pub reason: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(rename = "isActive")]
    pub is_active: bool,
}

/// Message response
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ============ Handlers ============

/// Start impersonating a user
///
/// POST /api/v1/admin/users/:user_id/impersonate
///
/// # Security
/// - Only admins/superadmins can impersonate
/// - Cannot impersonate users with higher or equal privileges
/// - Cannot impersonate superadmins (unless you're superadmin)
/// - Impersonation reason is required
async fn start_impersonation(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(user_id): Path<String>,
    Json(req): Json<StartImpersonationRequest>,
) -> Result<(StatusCode, Json<ImpersonationResponse>), ApiError> {
    // Validate request
    req.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let audit = AuditLogger::new(state.db.clone());
    let context = Some(RequestContext::from_request(
        &headers,
        Some(&ConnectInfo(addr)),
    ));

    // Security check 1: Cannot impersonate yourself
    if current_user.user_id == user_id {
        audit.log_impersonation_denied(
            &current_user.tenant_id,
            &current_user.user_id,
            &user_id,
            "Cannot impersonate yourself",
        );
        return Err(ApiError::Forbidden);
    }

    // Get impersonator roles from claims
    let impersonator_roles = current_user.claims.roles.clone().unwrap_or_default();

    // Verify admin has permission to impersonate
    let is_admin = impersonator_roles.iter().any(|r| r == "admin" || r == "superadmin");
    if !is_admin {
        audit.log_impersonation_denied(
            &current_user.tenant_id,
            &current_user.user_id,
            &user_id,
            "User does not have admin privileges",
        );
        return Err(ApiError::Forbidden);
    }

    // Security check 2: Get target user and verify they exist
    let target_user = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    // Get target user roles
    let target_roles: Vec<String> = target_user
        .metadata
        .get("roles")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Security check 3: Use impersonation service to validate privilege levels
    let impersonation_service = ImpersonationService::new(state.db.clone());
    
    if !impersonation_service.is_impersonation_allowed(&impersonator_roles, &target_roles) {
        audit.log_impersonation_denied(
            &current_user.tenant_id,
            &current_user.user_id,
            &user_id,
            "Cannot impersonate users with equal or higher privileges",
        );
        return Err(ApiError::Forbidden);
    }

    // Security check 4: Target user must be active
    if target_user.status != UserStatus::Active {
        audit.log_impersonation_denied(
            &current_user.tenant_id,
            &current_user.user_id,
            &user_id,
            "Cannot impersonate inactive users",
        );
        return Err(ApiError::Forbidden);
    }

    // Create impersonation session record
    let ip_address = addr.ip().to_string();
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let impersonation_session = impersonation_service
        .create_session(CreateImpersonationRequest {
            admin_id: current_user.user_id.clone(),
            target_user_id: target_user.id.clone(),
            tenant_id: current_user.tenant_id.clone(),
            reason: req.reason.clone(),
            duration_minutes: req.duration_minutes,
        })
        .await
        .map_err(|_| ApiError::internal())?;

    // Create user session for the impersonated user
    let session = state
        .auth_service
        .create_session_for_oauth_user(&target_user, Some(ip_address.clone()), user_agent.clone())
        .await
        .map_err(|_| ApiError::internal())?;

    // Store session in database with impersonation metadata
    let session_req = vault_core::db::sessions::CreateSessionRequest {
        tenant_id: current_user.tenant_id.clone(),
        user_id: target_user.id.clone(),
        access_token_jti: session.access_token_jti.clone(),
        refresh_token_hash: session.refresh_token_hash.clone(),
        token_family: session.token_family.clone(),
        ip_address: Some(ip_address.parse().map_err(|_| ApiError::internal())?),
        user_agent,
        device_fingerprint: None,
        device_info: serde_json::json!({
            "is_impersonation": true,
            "impersonator_id": current_user.user_id,
            "impersonation_reason": &req.reason,
            "impersonation_session_id": &impersonation_session.id,
        }),
        location: None,
        mfa_verified: true, // Admin bypasses MFA for impersonation
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(req.duration_minutes),
        bind_to_ip: state.config.security.session_binding.bind_to_ip,
        bind_to_device: state.config.security.session_binding.bind_to_device,
    };

    state
        .db
        .sessions()
        .create(session_req)
        .await
        .map_err(|_| ApiError::internal())?;

    // Generate impersonation tokens with limited duration
    let token_pair = state
        .auth_service
        .generate_impersonation_tokens(
            &target_user,
            &current_user.user_id,
            &session.id,
            req.duration_minutes,
        )
        .map_err(|_| ApiError::internal())?;

    // Log impersonation start
    audit.log_impersonation_started(
        &current_user.tenant_id,
        &current_user.user_id,
        &target_user.id,
        &session.id,
        &req.reason,
        req.duration_minutes,
    );

    tracing::info!(
        impersonation_session_id = %impersonation_session.id,
        admin_id = %current_user.user_id,
        target_user_id = %target_user.id,
        duration_minutes = %req.duration_minutes,
        reason = %req.reason,
        "Admin started impersonating user"
    );

    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(req.duration_minutes);

    Ok((
        StatusCode::CREATED,
        Json(ImpersonationResponse {
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: token_pair.expires_in,
            impersonated_user: ImpersonatedUserInfo {
                id: target_user.id,
                email: target_user.email,
                name: target_user.profile.name,
                email_verified: target_user.email_verified,
            },
            impersonator_id: current_user.user_id,
            impersonation_expires_at: expires_at.to_rfc3339(),
            session_id: session.id,
        }),
    ))
}

/// End current impersonation
///
/// DELETE /api/v1/admin/impersonation
///
/// Revokes the current impersonation session. The admin must re-authenticate
/// with their own credentials after stopping impersonation.
async fn end_impersonation(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<MessageResponse>, ApiError> {
    // Check if this is actually an impersonation session
    if !current_user.is_impersonation {
        return Err(ApiError::BadRequest(
            "Not currently impersonating".to_string(),
        ));
    }

    let session_id = current_user
        .session_id
        .as_ref()
        .ok_or(ApiError::BadRequest("No session ID found".to_string()))?;

    let impersonator_id = current_user
        .impersonator_id
        .as_ref()
        .ok_or(ApiError::BadRequest("No impersonator ID found".to_string()))?;

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // End the impersonation session record
    let impersonation_service = ImpersonationService::new(state.db.clone());
    
    // Try to find and end the impersonation session by looking up the user session
    if let Ok(Some(impersonation_session)) = impersonation_service
        .get_by_target_session(&current_user.tenant_id, session_id)
        .await
    {
        impersonation_service
            .end_session(&impersonation_session.id, Some(&current_user.user_id))
            .await
            .ok();
    }

    // Revoke the user session
    state
        .db
        .sessions()
        .revoke(
            &current_user.tenant_id,
            session_id,
            Some("impersonation_ended"),
        )
        .await
        .map_err(|_| ApiError::internal())?;

    // Log impersonation end
    let audit = AuditLogger::new(state.db.clone());
    audit.log_impersonation_ended(
        &current_user.tenant_id,
        impersonator_id,
        &current_user.user_id,
        session_id,
    );

    tracing::info!(
        session_id = %session_id,
        impersonator_id = %impersonator_id,
        target_user_id = %current_user.user_id,
        "Admin stopped impersonating user"
    );

    Ok(Json(MessageResponse {
        message: "Impersonation ended successfully".to_string(),
    }))
}

/// List active impersonation sessions
///
/// GET /api/v1/admin/impersonations
///
/// Returns a paginated list of all active impersonation sessions.
/// Can be filtered by admin_id or target_user_id.
async fn list_impersonations(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListImpersonationsQuery>,
) -> Result<Json<ListImpersonationsResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let page = query.page.max(1);
    let per_page = query.per_page.clamp(1, 100);

    let impersonation_service = ImpersonationService::new(state.db.clone());
    
    let (sessions, total) = impersonation_service
        .list_active_sessions(
            &current_user.tenant_id,
            page,
            per_page,
            query.admin_id.as_deref(),
            query.target_user_id.as_deref(),
        )
        .await
        .map_err(|_| ApiError::internal())?;

    let session_responses: Vec<ImpersonationSessionResponse> = sessions
        .into_iter()
        .map(|s| ImpersonationSessionResponse {
            id: s.id,
            admin_id: s.admin_id,
            target_user_id: s.target_user_id,
            target_email: s.target_email,
            target_name: s.target_name,
            reason: s.reason,
            created_at: s.created_at.to_rfc3339(),
            expires_at: s.expires_at.to_rfc3339(),
            is_active: s.is_active,
        })
        .collect();

    Ok(Json(ListImpersonationsResponse {
        sessions: session_responses,
        total,
        page,
        per_page,
    }))
}
