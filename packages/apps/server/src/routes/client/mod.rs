//! Client API Routes
//!
//! These routes are designed for end-user client applications.
//! All routes are prefixed with `/api/v1` (or `/` relative to that prefix).

use axum::Router;

pub mod auth;
pub mod consent;
pub mod devices;
pub mod m2m_auth;
pub mod mfa;
pub mod organizations;
pub mod privacy;
pub mod push_mfa;
pub mod security_dashboard;
pub mod sessions;
pub mod tenant_admins;
pub mod users;

use crate::state::AppState;

/// Create client API routes
/// Mounted at `/api/v1`
pub fn routes() -> Router<AppState> {
    // Combine user and MFA routes before nesting to avoid duplicate nesting
    let user_routes = Router::new()
        .merge(users::routes())
        .merge(mfa::routes());

    Router::new()
        .nest("/auth", auth::routes())
        .nest("/users", user_routes)
        .nest("/organizations", organizations::routes())
        .nest("/mfa/push", push_mfa::routes())
        .nest("/oauth", m2m_auth::routes())
        .nest("/devices", devices::routes())
        .nest("/sessions", sessions::routes())
        .nest("/privacy", privacy::routes())
        .merge(security_dashboard::routes())
        .merge(tenant_admins::routes())
        .merge(consent::routes())
}
