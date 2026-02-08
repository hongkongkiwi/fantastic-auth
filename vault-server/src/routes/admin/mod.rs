//! Admin API Routes
//!
//! These routes are designed for administrative dashboards and management tools.
//! All routes are prefixed with `/api/v1/admin`.
//!
//! All endpoints require:
//! 1. Valid JWT Bearer token
//! 2. Admin role (`admin` or `owner`)

use axum::Router;

pub mod analytics;
pub mod audit_exports;
pub mod consent;
pub mod audit_logs;
pub mod billing;
pub mod branding;
pub mod bulk;
pub mod custom_domains;
pub mod dashboard;
pub mod directory;
pub mod domains;
pub mod i18n;
pub mod organizations;
pub mod password_policy;
pub mod permissions;
pub mod risk;
pub mod roles;
pub mod scim;
pub mod security;
pub mod security_policies;
pub mod settings;
pub mod sso;
pub mod system;
pub mod users;
pub mod webhooks;

use crate::state::AppState;

/// Create admin API routes
/// Mounted at `/api/v1/admin`
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(dashboard::routes())
        .merge(users::routes())
        .merge(organizations::routes())
        .merge(audit_logs::routes())
        .merge(audit_exports::routes())
        .merge(branding::routes())
        .merge(domains::routes())
        .merge(custom_domains::routes())
        .merge(roles::routes())
        .merge(sso::routes())
        .merge(scim::routes())
        .merge(directory::routes())
        .merge(security::routes())
        .merge(security_policies::routes())
        .merge(settings::routes())
        .merge(system::routes())
        .merge(webhooks::routes())
        .merge(billing::routes())
        .merge(password_policy::routes())
        .merge(permissions::routes())
        .merge(bulk::routes())
        .merge(analytics::routes())
        .merge(consent::routes())
        .nest("/risk", risk::routes())
        .nest("/i18n", i18n::routes())
}
