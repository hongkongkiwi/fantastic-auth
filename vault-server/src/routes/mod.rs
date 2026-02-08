//! API Routes Module
//!
//! Routes are organized into three distinct namespaces:
//! - `/api/v1/*` - Client API (end-user operations within a tenant)
//! - `/api/v1/admin/*` - Admin API (admin operations within a tenant)
//! - `/api/v1/internal/*` - Internal API (cross-tenant platform operations)
//! - `/scim/v2/*` - SCIM 2.0 API (RFC 7644 protocol endpoints)

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json, Router};
use serde::Serialize;

pub mod admin;
pub mod client;
pub mod health;
pub mod hosted;
pub mod internal;
pub mod oidc;

use crate::state::AppState;
use crate::i18n::{Language, t};

/// Session limit reached error details
#[derive(Debug, Clone)]
pub struct SessionLimitError {
    pub current_sessions: usize,
    pub max_sessions: usize,
    pub message: String,
}

/// API Error type for consistent error responses
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict(String),
    Validation(String),
    Internal,
    NotImplemented,
    SessionLimitReached(SessionLimitError),
    TooManyRequests(String),
    MfaRequired(String),
}

impl ApiError {
    /// Create a bad request error
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }

    /// Create a forbidden error
    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self::Forbidden
    }

    /// Create a not found error
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound
    }

    /// Create an internal error
    pub fn internal_error(msg: impl Into<String>) -> Self {
        Self::Internal
    }

    /// Create an MFA required error
    pub fn mfa_required(msg: impl Into<String>) -> Self {
        Self::MfaRequired(msg.into())
    }
}

/// Localized API Error that includes language information
#[derive(Debug)]
pub struct LocalizedApiError {
    pub error: ApiError,
    pub lang: Language,
}

impl LocalizedApiError {
    pub fn new(error: ApiError, lang: Language) -> Self {
        Self { error, lang }
    }

    /// Get localized error message
    fn localize(&self, key: &str) -> String {
        t(key, self.lang)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        match &self {
            ApiError::SessionLimitReached(err) => {
                let body = Json(serde_json::json!({
                    "error": {
                        "code": "SESSION_LIMIT_REACHED",
                        "message": err.message,
                        "details": {
                            "current_sessions": err.current_sessions,
                            "max_sessions": err.max_sessions
                        }
                    }
                }));
                (StatusCode::TOO_MANY_REQUESTS, body).into_response()
            }
            _ => {
                let (status, code, message) = match &self {
                    ApiError::BadRequest(msg) => {
                        (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg.clone())
                    }
                    ApiError::Unauthorized => (
                        StatusCode::UNAUTHORIZED,
                        "UNAUTHORIZED",
                        "Authentication required".to_string(),
                    ),
                    ApiError::Forbidden => (
                        StatusCode::FORBIDDEN,
                        "FORBIDDEN",
                        "Access denied".to_string(),
                    ),
                    ApiError::NotFound => (
                        StatusCode::NOT_FOUND,
                        "NOT_FOUND",
                        "Resource not found".to_string(),
                    ),
                    ApiError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg.clone()),
                    ApiError::Validation(msg) => {
                        (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg.clone())
                    }
                    ApiError::Internal => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "INTERNAL_ERROR",
                        "An internal error occurred".to_string(),
                    ),
                    ApiError::NotImplemented => (
                        StatusCode::NOT_IMPLEMENTED,
                        "NOT_IMPLEMENTED",
                        "This feature is not yet implemented".to_string(),
                    ),
                    ApiError::SessionLimitReached(_) => unreachable!(),
                    ApiError::TooManyRequests(msg) => (
                        StatusCode::TOO_MANY_REQUESTS,
                        "TOO_MANY_REQUESTS",
                        msg.clone(),
                    ),
                    ApiError::MfaRequired(msg) => (
                        StatusCode::UNAUTHORIZED,
                        "MFA_REQUIRED",
                        msg.clone(),
                    ),
                };

                let body = Json(serde_json::json!({
                    "error": {
                        "code": code,
                        "message": message
                    }
                }));

                (status, body).into_response()
            }
        }
    }
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    #[serde(rename = "serverTime")]
    pub server_time: String,
}

/// Health check endpoint
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: vault_core::VERSION.to_string(),
        server_time: chrono::Utc::now().to_rfc3339(),
    })
}

/// 404 Not Found handler
pub async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": {
                "code": "NOT_FOUND",
                "message": "The requested resource was not found"
            }
        })),
    )
}

/// Prometheus metrics handler
pub async fn metrics_handler() -> impl IntoResponse {
    // Simple metrics response for now
    // In production, this would collect real metrics
    let metrics = format!(
        "# HELP vault_auth_build_info Build information\n\
         # TYPE vault_auth_build_info gauge\n\
         vault_auth_build_info{{version=\"{}\"}} 1\n\
         # HELP vault_audit_rotations_total Total audit log rotations\n\
         # TYPE vault_audit_rotations_total counter\n\
         vault_audit_rotations_total {}\n\
         # HELP vault_audit_rotation_errors_total Total audit log rotation errors\n\
         # TYPE vault_audit_rotation_errors_total counter\n\
         vault_audit_rotation_errors_total {}\n\
         # HELP vault_audit_prunes_total Total audit log prune runs\n\
         # TYPE vault_audit_prunes_total counter\n\
         vault_audit_prunes_total {}\n\
         # HELP vault_audit_prune_errors_total Total audit log prune errors\n\
         # TYPE vault_audit_prune_errors_total counter\n\
         vault_audit_prune_errors_total {}\n",
        vault_core::VERSION,
        crate::metrics_internal::audit_rotation_count(),
        crate::metrics_internal::audit_rotation_error_count(),
        crate::metrics_internal::audit_prune_count(),
        crate::metrics_internal::audit_prune_error_count(),
    );

    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4")],
        metrics,
    )
}

/// Create all API routes
///
/// Structure:
/// - `/api/v1/*` - Client API
/// - `/api/v1/admin/*` - Admin API  
/// - `/api/v1/internal/*` - Internal/Privileged API (superadmin only)
pub fn api_routes() -> Router<AppState> {
    Router::new()
        .merge(client::routes())
        .nest("/admin", admin::routes())
        .nest("/internal", internal::routes())
}

/// Create SCIM 2.0 API routes
///
/// Mounted at `/scim/v2`
/// Follows RFC 7644 (SCIM Protocol) specification
pub fn scim_routes() -> Router<AppState> {
    use crate::scim::auth::{optional_scim_auth_middleware, scim_auth_middleware};
    use crate::scim::handlers::*;
    use axum::middleware;
    use axum::routing::{delete, get, patch, post, put};

    // Discovery endpoints - optionally authenticated
    let discovery_routes = Router::new()
        .route("/ServiceProviderConfig", get(get_service_provider_config))
        .route("/ResourceTypes", get(list_resource_types))
        .route("/ResourceTypes/:id", get(get_resource_type))
        .route("/Schemas", get(list_schemas))
        .route("/Schemas/:id", get(get_schema))
        .layer(middleware::from_fn(optional_scim_auth_middleware));

    // User endpoints - require authentication
    let user_routes = Router::new()
        .route("/Users", get(list_users).post(create_user))
        .route(
            "/Users/:id",
            get(get_user)
                .put(update_user)
                .patch(patch_user)
                .delete(delete_user),
        );

    // Group endpoints - require authentication
    let group_routes = Router::new()
        .route("/Groups", get(list_groups).post(create_group))
        .route(
            "/Groups/:id",
            get(get_group)
                .put(update_group)
                .patch(patch_group)
                .delete(delete_group),
        );

    // Bulk endpoints (if implemented)
    // let bulk_routes = Router::new()
    //     .route("/Bulk", post(bulk_operation));

    // Combine all routes with authentication middleware
    Router::new()
        .merge(discovery_routes)
        .merge(user_routes)
        .merge(group_routes)
        .layer(middleware::from_fn(scim_auth_middleware))
        .layer(middleware::from_fn(inject_state_middleware))
}

/// Middleware to inject AppState into request extensions
/// This allows the SCIM auth middleware to access state
async fn inject_state_middleware(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    request.extensions_mut().insert(state);
    next.run(request).await
}
