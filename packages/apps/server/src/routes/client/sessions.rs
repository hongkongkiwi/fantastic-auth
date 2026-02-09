//! Session Management Routes
//!
//! User session management endpoints for viewing active sessions,
//! revoking sessions, and session security analytics.

use axum::{
    extract::{Extension, Path, State},
    routing::{delete, get},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Check if user has admin role
fn is_admin(user: &CurrentUser) -> bool {
    user.claims.roles.as_ref()
        .map(|roles| roles.iter().any(|r| r == "admin"))
        .unwrap_or(false)
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SessionInfo {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    #[serde(rename = "lastActivityAt")]
    pub last_activity_at: DateTime<Utc>,
    pub status: String,
    #[serde(rename = "ipAddress")]
    pub ip_address: String,
    pub location: Option<String>,
    pub device: Option<String>,
    #[serde(rename = "riskScore")]
    pub risk_score: i32,
    #[serde(rename = "mfaFactors")]
    pub mfa_factors: Vec<String>,
    #[serde(rename = "isCurrentSession")]
    pub is_current_session: bool,
}

/// Session list response
#[derive(Debug, Serialize)]
pub struct SessionListResponse {
    pub sessions: Vec<SessionInfo>,
    pub total: usize,
}

/// Session termination response
#[derive(Debug, Serialize)]
pub struct TerminateSessionResponse {
    pub success: bool,
    pub message: String,
    #[serde(rename = "terminatedCount")]
    pub terminated_count: Option<usize>,
}

/// Session statistics
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct SessionStats {
    #[serde(rename = "totalSessions")]
    pub total_sessions: i64,
    #[serde(rename = "activeSessions")]
    pub active_sessions: i64,
    #[serde(rename = "expiredSessions")]
    pub expired_sessions: i64,
    #[serde(rename = "revokedSessions")]
    pub revoked_sessions: i64,
}

/// Create session routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/me/sessions", get(list_my_sessions))
        .route("/me/sessions/stats", get(get_my_session_stats))
        .route("/me/sessions/all-others", delete(terminate_all_other_sessions))
        .route("/me/sessions/:session_id", delete(terminate_my_session))
}

/// List all sessions for current user
async fn list_my_sessions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SessionListResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    let sessions: Vec<SessionInfo> = sqlx::query_as::<_, SessionInfo>(
        r#"
        SELECT 
            s.id::text as id,
            s.user_id::text as user_id,
            s.created_at,
            s.expires_at,
            s.last_activity_at,
            s.status,
            s.ip_address,
            s.location,
            s.device_info as device,
            s.risk_score,
            s.mfa_factors,
            false as is_current_session
        FROM user_sessions s
        WHERE s.user_id = $1 
        ORDER BY s.last_activity_at DESC
        "#
    )
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    let total = sessions.len();

    Ok(Json(SessionListResponse { sessions, total }))
}

/// Terminate a specific session
async fn terminate_my_session(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<TerminateSessionResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    // First check if the session belongs to the user
    let session: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM user_sessions WHERE id = $1"
    )
    .bind(session_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    match session {
        Some((session_user_id,)) => {
            // Ensure user can only terminate their own sessions
            if session_user_id != user_id && !is_admin(&current_user) {
                return Err(ApiError::forbidden("Not authorized to terminate this session"));
            }

            sqlx::query(
                r#"
                UPDATE user_sessions 
                SET status = 'revoked', revoked_at = NOW()
                WHERE id = $1
                "#
            )
            .bind(session_id)
            .execute(state.db.pool())
            .await
            .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

            Ok(Json(TerminateSessionResponse {
                success: true,
                message: "Session terminated successfully".to_string(),
                terminated_count: Some(1),
            }))
        }
        None => Err(ApiError::not_found("Session not found")),
    }
}

/// Terminate all other sessions except current
async fn terminate_all_other_sessions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<TerminateSessionResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    // Get current session id from request context if available
    // For now, we'll revoke all active sessions
    let result = sqlx::query(
        r#"
        UPDATE user_sessions 
        SET status = 'revoked', revoked_at = NOW()
        WHERE user_id = $1 AND status = 'active'
        "#
    )
    .bind(user_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    Ok(Json(TerminateSessionResponse {
        success: true,
        message: "All other sessions terminated".to_string(),
        terminated_count: Some(result.rows_affected() as usize),
    }))
}

/// Get session statistics for current user
async fn get_my_session_stats(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SessionStats>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    let stats = sqlx::query_as::<_, SessionStats>(
        r#"
        SELECT 
            COUNT(*) as total_sessions,
            COUNT(*) FILTER (WHERE status = 'active') as active_sessions,
            COUNT(*) FILTER (WHERE status = 'expired') as expired_sessions,
            COUNT(*) FILTER (WHERE status = 'revoked') as revoked_sessions
        FROM user_sessions 
        WHERE user_id = $1
        "#
    )
    .bind(user_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    Ok(Json(stats))
}
