//! Anonymous user restriction middleware
//!
//! Provides middleware to restrict what anonymous users can do.
//! Anonymous users have limited permissions compared to registered users.

use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use crate::state::CurrentUser;

/// Check if the current user is an anonymous user
///
/// Examines the JWT claims to determine if this is an anonymous session
pub fn is_anonymous_user(request: &Request) -> bool {
    request
        .extensions()
        .get::<CurrentUser>()
        .and_then(|user| {
            user.claims
                .custom
                .get("is_anonymous")
                .and_then(|v| v.as_bool())
        })
        .unwrap_or(false)
}

/// Middleware that rejects anonymous users
///
/// Use this for endpoints that require a full registered user account.
/// Anonymous users will receive a 403 Forbidden response.
///
/// # Example
/// ```rust
/// use axum::{routing::get, Router};
/// use axum::middleware;
///
/// let app = Router::new()
///     .route("/sensitive-data", get(get_sensitive_data))
///     .layer(middleware::from_fn(reject_anonymous_users));
/// ```
pub async fn reject_anonymous_users(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if is_anonymous_user(&request) {
        tracing::warn!(
            "Anonymous user attempted to access restricted endpoint"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// Middleware that allows only anonymous users
///
/// Use this for endpoints specifically designed for anonymous users.
/// Registered users will receive a 403 Forbidden response.
///
/// # Example
/// ```rust
/// use axum::{routing::post, Router};
/// use axum::middleware;
///
/// let app = Router::new()
///     .route("/anonymous/extend", post(extend_anonymous_session))
///     .layer(middleware::from_fn(require_anonymous_user));
/// ```
pub async fn require_anonymous_user(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if !is_anonymous_user(&request) {
        tracing::warn!(
            "Registered user attempted to access anonymous-only endpoint"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// List of endpoints that anonymous users cannot access
const ANONYMOUS_RESTRICTED_ENDPOINTS: &[&str] = &[
    // Admin operations
    "/api/v1/admin",
    "/api/v1/users/admin",
    "/api/v1/settings/admin",
    
    // Sensitive user operations
    "/api/v1/users/delete-account",
    "/api/v1/users/export-data",
    "/api/v1/users/close-account",
    
    // Billing/subscription
    "/api/v1/billing",
    "/api/v1/subscriptions",
    "/api/v1/payments",
    
    // Organization management
    "/api/v1/organizations/create",
    "/api/v1/organizations/delete",
    "/api/v1/organizations/transfer-ownership",
    
    // API keys
    "/api/v1/api-keys",
    
    // Webhooks
    "/api/v1/webhooks",
    
    // SCIM
    "/scim/v2",
];

/// Check if the request path is restricted for anonymous users
pub fn is_anonymous_restricted_path(path: &str) -> bool {
    ANONYMOUS_RESTRICTED_ENDPOINTS
        .iter()
        .any(|restricted| path.starts_with(restricted))
}

/// Middleware that blocks anonymous users from restricted paths
///
/// This checks the request path against a list of endpoints that
/// anonymous users should not be able to access.
///
/// # Example
/// ```rust
/// use axum::{routing::get, Router};
/// use axum::middleware;
///
/// let app = Router::new()
///     .layer(middleware::from_fn(anonymous_path_restrictions));
/// ```
pub async fn anonymous_path_restrictions(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if is_anonymous_user(&request) {
        let path = request.uri().path();
        
        if is_anonymous_restricted_path(path) {
            tracing::warn!(
                path = %path,
                "Anonymous user attempted to access restricted path"
            );
            return Err(StatusCode::FORBIDDEN);
        }
    }

    Ok(next.run(request).await)
}

/// Anonymous user limits configuration
#[derive(Debug, Clone)]
pub struct AnonymousLimits {
    /// Maximum number of API calls per hour for anonymous users
    pub max_api_calls_per_hour: u32,
    /// Maximum session duration in hours
    pub max_session_duration_hours: i64,
    /// Maximum number of items they can create
    pub max_items_created: u32,
    /// Whether they can upload files
    pub can_upload_files: bool,
    /// Maximum file upload size in MB
    pub max_upload_size_mb: u32,
}

impl Default for AnonymousLimits {
    fn default() -> Self {
        Self {
            max_api_calls_per_hour: 100,
            max_session_duration_hours: 24,
            max_items_created: 50,
            can_upload_files: false,
            max_upload_size_mb: 0,
        }
    }
}

/// Get anonymous limits from configuration
pub fn get_anonymous_limits() -> AnonymousLimits {
    // In production, this could be loaded from config
    AnonymousLimits::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn test_is_anonymous_restricted_path() {
        assert!(is_anonymous_restricted_path("/api/v1/admin/users"));
        assert!(is_anonymous_restricted_path("/api/v1/billing/subscription"));
        assert!(is_anonymous_restricted_path("/api/v1/api-keys"));
        assert!(!is_anonymous_restricted_path("/api/v1/auth/me"));
        assert!(!is_anonymous_restricted_path("/api/v1/public/data"));
    }

    #[test]
    fn test_anonymous_limits_default() {
        let limits = AnonymousLimits::default();
        assert_eq!(limits.max_api_calls_per_hour, 100);
        assert_eq!(limits.max_session_duration_hours, 24);
        assert_eq!(limits.max_items_created, 50);
        assert!(!limits.can_upload_files);
        assert_eq!(limits.max_upload_size_mb, 0);
    }
}
