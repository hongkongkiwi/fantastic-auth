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
pub mod sessions;
pub mod tenant_admins;
pub mod users;

use crate::state::AppState;

/// Create client API routes
/// Mounted at `/api/v1`
pub fn routes() -> Router<AppState> {
    Router::new()
        .nest("/auth", auth::routes())
        .nest("/users", users::routes())
        .nest("/organizations", organizations::routes())
        .nest("/users", mfa::routes())
        .nest("/mfa/push", push_mfa::routes())
        .nest("/oauth", m2m_auth::routes())
        .nest("/devices", devices::routes())
        .nest("/sessions", sessions::routes())
        .nest("/privacy", privacy::routes())
        .merge(tenant_admins::routes())
        .merge(consent::routes())
}
