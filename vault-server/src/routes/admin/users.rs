//! Admin User Management Routes
//!
//! Full CRUD operations for managing users within a tenant.
//! Includes user suspension, session revocation, etc.

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use validator::Validate;

use crate::audit::{AuditLogger, RequestContext};
use crate::impersonation::{CreateImpersonationRequest, ImpersonationService};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser, SessionLimitStatus};
use vault_core::models::user::{User, UserStatus};

/// User management routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users).post(create_user))
        .route(
            "/users/:user_id",
            get(get_user).patch(update_user).delete(delete_user),
        )
        .route("/users/:user_id/suspend", post(suspend_user))
        .route("/users/:user_id/activate", post(activate_user))
        .route("/users/:user_id/revoke-sessions", post(revoke_all_sessions))
        .route(
            "/users/:user_id/sessions",
            get(list_user_sessions).delete(revoke_all_user_sessions),
        )
        .route(
            "/users/:user_id/sessions/:session_id",
            get(get_user_session).delete(revoke_user_session),
        )
        .route("/users/:user_id/impersonate", post(impersonate_user))
        .route("/impersonation", delete(stop_impersonation))
}

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
struct ListUsersQuery {
    page: Option<i64>,
    per_page: Option<i64>,
    status: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserListResponse {
    users: Vec<UserSummary>,
    total: i64,
    page: i64,
    per_page: i64,
}

#[derive(Debug, Serialize)]
struct UserSummary {
    id: String,
    email: String,
    name: String,
    status: UserStatus,
    email_verified: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    organization_count: i64,
}

impl From<User> for UserSummary {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            name: user.profile.name.unwrap_or_default(),
            status: user.status,
            email_verified: user.email_verified,
            created_at: user.created_at,
            last_login_at: user.last_login_at,
            organization_count: 0, // Will be populated separately if needed
        }
    }
}

#[derive(Debug, Deserialize, Validate)]
struct CreateUserRequest {
    #[validate(email)]
    email: String,
    #[validate(length(min = 1))]
    name: String,
    #[serde(default)]
    email_verified: bool,
}

#[derive(Debug, Deserialize, Validate)]
struct UpdateUserRequest {
    #[validate(length(min = 1))]
    name: Option<String>,
    status: Option<UserStatus>,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

/// Admin session response
#[derive(Debug, Serialize)]
struct AdminSessionResponse {
    id: String,
    #[serde(rename = "userId")]
    user_id: String,
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
    status: String,
}

/// Admin session list response with limit info
#[derive(Debug, Serialize)]
struct AdminSessionListResponse {
    sessions: Vec<AdminSessionResponse>,
    #[serde(rename = "currentSessions")]
    current_sessions: usize,
    #[serde(rename = "maxSessions")]
    max_sessions: usize,
}

/// Impersonation request
#[derive(Debug, Deserialize, Validate)]
struct ImpersonateRequest {
    /// Reason for impersonation (required for audit)
    #[validate(length(min = 1, max = 500))]
    reason: String,
    /// Duration in minutes (default: 30, max: 60)
    #[validate(range(min = 5, max = 60))]
    #[serde(default = "default_impersonation_duration")]
    duration_minutes: i64,
}

fn default_impersonation_duration() -> i64 {
    30
}

/// Impersonation response
#[derive(Debug, Serialize)]
struct ImpersonateResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    #[serde(rename = "expiresIn")]
    expires_in: i64,
    user: ImpersonatedUserResponse,
    #[serde(rename = "isImpersonation")]
    is_impersonation: bool,
    #[serde(rename = "impersonatorId")]
    impersonator_id: String,
    #[serde(rename = "sessionId")]
    session_id: String,
}

/// Impersonated user info
#[derive(Debug, Serialize)]
struct ImpersonatedUserResponse {
    id: String,
    email: String,
    #[serde(rename = "emailVerified")]
    email_verified: bool,
    name: Option<String>,
}

// ============ Handlers ============

/// List users with pagination and filters
async fn list_users(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<UserListResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);

    let (users, total) = state
        .db
        .users()
        .list(
            &current_user.tenant_id,
            page,
            per_page,
            query.status.as_deref(),
            query.email.as_deref(),
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    let user_summaries: Vec<UserSummary> = users.into_iter().map(UserSummary::from).collect();

    Ok(Json(UserListResponse {
        users: user_summaries,
        total,
        page,
        per_page,
    }))
}

/// Get a single user by ID
async fn get_user(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<UserSummary>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let user = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(UserSummary::from(user)))
}

/// Create a new user
async fn create_user(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserSummary>), ApiError> {
    // Validate request
    req.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if email already exists
    let existing = state
        .db
        .users()
        .find_by_email(&current_user.tenant_id, &req.email)
        .await
        .map_err(|_| ApiError::Internal)?;

    if existing.is_some() {
        return Err(ApiError::Conflict("Email already exists".to_string()));
    }

    // Create profile with name
    let profile = serde_json::json!({
        "name": req.name,
    });

    // Create user request for the repository
    let create_req = vault_core::db::users::CreateUserRequest {
        tenant_id: current_user.tenant_id.clone(),
        email: req.email.clone(),
        password_hash: None, // No password initially
        email_verified: req.email_verified,
        profile: Some(profile),
        metadata: None,
    };

    let user = state
        .db
        .users()
        .create(create_req)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Log user creation
    let audit = AuditLogger::new(state.db.clone());
    audit.log_user_created(
        &current_user.tenant_id,
        &current_user.user_id,
        &user.id,
        &req.email,
    );

    // Trigger webhook event
    crate::webhooks::events::trigger_user_created(
        &state,
        &current_user.tenant_id,
        &user.id,
        &user.email,
        user.profile.name.as_deref(),
    )
    .await;

    Ok((StatusCode::CREATED, Json(UserSummary::from(user))))
}

/// Update a user
async fn update_user(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserSummary>, ApiError> {
    // Validate request
    if let Some(ref name) = req.name {
        if name.is_empty() {
            return Err(ApiError::Validation("Name cannot be empty".to_string()));
        }
    }

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Get existing user
    let mut user = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    // Track changes for audit log
    let mut changes = serde_json::Map::new();

    // Update name if provided
    if let Some(name) = req.name {
        if user.profile.name != Some(name.clone()) {
            changes.insert("name".to_string(), serde_json::json!(name));
            user.profile.name = Some(name);
        }
    }

    // Update status if provided
    if let Some(status) = req.status {
        if user.status != status {
            changes.insert(
                "status".to_string(),
                serde_json::json!(format!("{:?}", status)),
            );
            user.status = status;
        }
    }

    // Save updated user
    let updated_user = state
        .db
        .users()
        .update(&current_user.tenant_id, &user)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Log user update if there were changes
    if !changes.is_empty() {
        let audit = AuditLogger::new(state.db.clone());
        audit.log_user_updated(
            &current_user.tenant_id,
            &current_user.user_id,
            &user_id,
            serde_json::Value::Object(changes.clone()),
        );

        // Trigger webhook event
        let change_keys: Vec<String> = changes.keys().cloned().collect();
        crate::webhooks::events::trigger_user_updated(
            &state,
            &current_user.tenant_id,
            &user_id,
            &updated_user.email,
            change_keys,
        )
        .await;
    }

    Ok(Json(UserSummary::from(updated_user)))
}

/// Delete a user (soft delete)
async fn delete_user(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if user exists
    let user_exists = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !user_exists {
        return Err(ApiError::NotFound);
    }

    // Get user info before deletion
    let user = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Soft delete user
    state
        .db
        .users()
        .delete(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Log user deletion
    let audit = AuditLogger::new(state.db.clone());
    audit.log_user_deleted(&current_user.tenant_id, &current_user.user_id, &user_id);

    // Trigger webhook event
    if let Some(user) = user {
        crate::webhooks::events::trigger_user_deleted(
            &state,
            &current_user.tenant_id,
            &user_id,
            &user.email,
        )
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Suspend a user (set status to suspended)
async fn suspend_user(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<UserSummary>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if user exists
    let user_exists = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !user_exists {
        return Err(ApiError::NotFound);
    }

    // Update status to suspended
    let updated_user = state
        .db
        .users()
        .update_status(&current_user.tenant_id, &user_id, UserStatus::Suspended)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Revoke all sessions for the suspended user
    let _ = state
        .db
        .sessions()
        .revoke_all_for_user(&current_user.tenant_id, &user_id, Some("user_suspended"))
        .await;

    // Log user suspension
    let audit = AuditLogger::new(state.db.clone());
    audit.log_user_suspended(&current_user.tenant_id, &current_user.user_id, &user_id);

    // Trigger session revoked webhooks for all sessions
    crate::webhooks::events::trigger_session_revoked(
        &state,
        &current_user.tenant_id,
        &user_id,
        "all",
        Some("user_suspended"),
    )
    .await;

    Ok(Json(UserSummary::from(updated_user)))
}

/// Activate a user (set status to active)
async fn activate_user(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<UserSummary>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if user exists
    let user_exists = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !user_exists {
        return Err(ApiError::NotFound);
    }

    // Update status to active
    let updated_user = state
        .db
        .users()
        .update_status(&current_user.tenant_id, &user_id, UserStatus::Active)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Log user activation
    let audit = AuditLogger::new(state.db.clone());
    audit.log_user_activated(&current_user.tenant_id, &current_user.user_id, &user_id);

    Ok(Json(UserSummary::from(updated_user)))
}

/// Revoke all sessions for a user
async fn revoke_all_sessions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if user exists
    let user_exists = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !user_exists {
        return Err(ApiError::NotFound);
    }

    // Revoke all sessions
    let revoked_count = state
        .db
        .sessions()
        .revoke_all_for_user(&current_user.tenant_id, &user_id, Some("admin_action"))
        .await
        .map_err(|_| ApiError::Internal)?;

    // Log session revocation
    let audit = AuditLogger::new(state.db.clone());
    audit.log_sessions_revoked(
        &current_user.tenant_id,
        &current_user.user_id,
        &user_id,
        revoked_count,
    );

    // Trigger session revoked webhook
    crate::webhooks::events::trigger_session_revoked(
        &state,
        &current_user.tenant_id,
        &user_id,
        "all",
        Some("admin_action"),
    )
    .await;

    Ok(Json(MessageResponse {
        message: format!("Revoked {} sessions for user {}", revoked_count, user_id),
    }))
}

/// Start impersonating a user (admin only)
///
/// Creates a new session for the target user and returns tokens with impersonation claims.
/// All actions performed with these tokens will be audited with impersonation metadata.
async fn impersonate_user(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(user_id): Path<String>,
    Json(req): Json<ImpersonateRequest>,
) -> Result<Json<ImpersonateResponse>, ApiError> {
    // Validate request
    req.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

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

    // Security check 2: Get target user and verify they exist
    let target_user = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    // Security check 3: Use impersonation service to validate privilege levels
    let target_roles = target_user
        .metadata
        .get("roles")
        .and_then(|r| r.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let impersonator_roles = current_user.claims.roles.clone().unwrap_or_default();

    if !state
        .impersonation_service
        .is_impersonation_allowed(&impersonator_roles, &target_roles)
    {
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

    // Create impersonation session
    let ip_address = addr.ip().to_string();
    let user_agent = headers
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let session = state
        .auth_service
        .create_session_for_oauth_user(&target_user, Some(ip_address.clone()), user_agent.clone())
        .await
        .map_err(|_| ApiError::Internal)?;

    // Store session in database with impersonation metadata
    let session_req = vault_core::db::sessions::CreateSessionRequest {
        tenant_id: current_user.tenant_id.clone(),
        user_id: target_user.id.clone(),
        access_token_jti: session.access_token_jti.clone(),
        refresh_token_hash: session.refresh_token_hash.clone(),
        token_family: session.token_family.clone(),
        ip_address: Some(ip_address.parse().map_err(|_| ApiError::Internal)?),
        user_agent,
        device_fingerprint: None,
        device_info: serde_json::json!({
            "is_impersonation": true,
            "impersonator_id": current_user.user_id,
            "impersonation_reason": &req.reason,
        }),
        location: None,
        mfa_verified: true, // Admin bypasses MFA for impersonation
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(req.duration_minutes),
    };

    state
        .db
        .sessions()
        .create(session_req)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Generate impersonation tokens with limited duration
    let token_pair = state
        .auth_service
        .generate_impersonation_tokens(
            &target_user,
            &current_user.user_id,
            &session.id,
            req.duration_minutes,
        )
        .map_err(|_| ApiError::Internal)?;

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
        "Admin {} started impersonating user {} for {} minutes. Reason: {}",
        current_user.user_id,
        target_user.id,
        req.duration_minutes,
        req.reason
    );

    Ok(Json(ImpersonateResponse {
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
        expires_in: token_pair.expires_in,
        user: ImpersonatedUserResponse {
            id: target_user.id,
            email: target_user.email,
            email_verified: target_user.email_verified,
            name: target_user.profile.name,
        },
        is_impersonation: true,
        impersonator_id: current_user.user_id.clone(),
        session_id: session.id.clone(),
    }))
}

/// Stop impersonation and revoke the impersonation session
///
/// Revokes the current impersonation session. The admin must re-authenticate
/// with their own credentials after stopping impersonation.
async fn stop_impersonation(
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
        .ok_or(ApiError::BadRequest("No session ID found".to_string()))?;

    let impersonator_id = current_user
        .impersonator_id
        .ok_or(ApiError::BadRequest("No impersonator ID found".to_string()))?;

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Revoke the impersonation session
    state
        .db
        .sessions()
        .revoke(
            &current_user.tenant_id,
            &session_id,
            Some("impersonation_ended"),
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    // Log impersonation end
    let audit = AuditLogger::new(state.db.clone());
    audit.log_impersonation_ended(
        &current_user.tenant_id,
        &impersonator_id,
        &current_user.user_id,
        &session_id,
    );

    tracing::info!(
        "Admin {} stopped impersonating user {}",
        impersonator_id,
        current_user.user_id
    );

    Ok(Json(MessageResponse {
        message: "Impersonation ended successfully".to_string(),
    }))
}

/// List all sessions for a specific user (admin)
async fn list_user_sessions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<AdminSessionListResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if user exists
    let user_exists = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !user_exists {
        return Err(ApiError::NotFound);
    }

    // Get all sessions (including inactive for admin visibility)
    let sessions = state
        .db
        .sessions()
        .list_by_user(&current_user.tenant_id, &user_id, false)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Get session limit status
    let limit_status = state
        .get_session_limit_status(&current_user.tenant_id, &user_id)
        .await
        .unwrap_or(SessionLimitStatus {
            current_sessions: sessions.len(),
            max_sessions: state.config.security.session_limits.max_concurrent_sessions,
            warning: None,
        });

    // Convert sessions to response format
    let session_responses: Vec<AdminSessionResponse> = sessions
        .into_iter()
        .map(|s| AdminSessionResponse {
            id: s.id,
            user_id: s.user_id,
            created_at: s.created_at,
            last_activity_at: s.last_activity_at,
            expires_at: s.expires_at,
            ip_address: s.ip_address,
            user_agent: s.user_agent,
            device_info: s.device_info,
            mfa_verified: s.mfa_verified,
            status: s.status.to_string(),
        })
        .collect();

    Ok(Json(AdminSessionListResponse {
        sessions: session_responses,
        current_sessions: limit_status.current_sessions,
        max_sessions: limit_status.max_sessions,
    }))
}

/// Get a specific session for a user (admin)
async fn get_user_session(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((user_id, session_id)): Path<(String, String)>,
) -> Result<Json<AdminSessionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if user exists
    let user_exists = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !user_exists {
        return Err(ApiError::NotFound);
    }

    // Get the session
    let session = state
        .db
        .sessions()
        .find_by_id(&current_user.tenant_id, &session_id)
        .await
        .map_err(|_| ApiError::NotFound)?;

    // Verify session belongs to the user
    if session.user_id != user_id {
        return Err(ApiError::NotFound);
    }

    Ok(Json(AdminSessionResponse {
        id: session.id,
        user_id: session.user_id,
        created_at: session.created_at,
        last_activity_at: session.last_activity_at,
        expires_at: session.expires_at,
        ip_address: session.ip_address,
        user_agent: session.user_agent,
        device_info: session.device_info,
        mfa_verified: session.mfa_verified,
        status: session.status.to_string(),
    }))
}

/// Revoke a specific session for a user (admin)
async fn revoke_user_session(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((user_id, session_id)): Path<(String, String)>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if user exists
    let user_exists = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !user_exists {
        return Err(ApiError::NotFound);
    }

    // Get the session
    let session = state
        .db
        .sessions()
        .find_by_id(&current_user.tenant_id, &session_id)
        .await
        .map_err(|_| ApiError::NotFound)?;

    // Verify session belongs to the user
    if session.user_id != user_id {
        return Err(ApiError::NotFound);
    }

    // Revoke the session
    state
        .db
        .sessions()
        .revoke(&current_user.tenant_id, &session_id, Some("admin_revoked"))
        .await
        .map_err(|_| ApiError::Internal)?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        crate::audit::AuditAction::SessionRevoked,
        crate::audit::ResourceType::Session,
        &session_id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        Some(format!("Admin revoked session for user {}", user_id)),
        Some(serde_json::json!({
            "target_user_id": user_id,
            "session_id": session_id,
        })),
    );

    // Trigger webhook
    crate::webhooks::events::trigger_session_revoked(
        &state,
        &current_user.tenant_id,
        &user_id,
        &session_id,
        Some("admin_revoked"),
    )
    .await;

    Ok(Json(MessageResponse {
        message: format!("Session {} revoked for user {}", session_id, user_id),
    }))
}

/// Revoke all sessions for a specific user (admin)
async fn revoke_all_user_sessions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Check if user exists
    let user_exists = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .is_some();

    if !user_exists {
        return Err(ApiError::NotFound);
    }

    // Revoke all sessions
    let revoked_count = state
        .db
        .sessions()
        .revoke_all_for_user(&current_user.tenant_id, &user_id, Some("admin_revoked_all"))
        .await
        .map_err(|_| ApiError::Internal)?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        crate::audit::AuditAction::SessionsRevoked,
        crate::audit::ResourceType::Session,
        &user_id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        Some(format!(
            "Admin revoked all {} sessions for user {}",
            revoked_count, user_id
        )),
        Some(serde_json::json!({
            "target_user_id": user_id,
            "revoked_count": revoked_count,
        })),
    );

    // Trigger webhook
    crate::webhooks::events::trigger_session_revoked(
        &state,
        &current_user.tenant_id,
        &user_id,
        "all",
        Some("admin_revoked_all"),
    )
    .await;

    Ok(Json(MessageResponse {
        message: format!("Revoked {} sessions for user {}", revoked_count, user_id),
    }))
}
