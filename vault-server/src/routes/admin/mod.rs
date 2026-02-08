//! Admin API Routes
//!
//! These routes are designed for administrative dashboards and management tools.
//! All routes are prefixed with `/api/v1/admin`.
//!
//! All endpoints require:
//! 1. Valid JWT Bearer token
//! 2. Admin role (`admin` or `owner`)

use axum::{middleware, Router};

pub mod actions;
pub mod analytics;
pub mod audit_exports;
pub mod audit_logs;
pub mod billing;
pub mod branding;
pub mod bulk;
pub mod consent;
pub mod custom_domains;
pub mod dashboard;
pub mod directory;
pub mod domains;
pub mod i18n;
pub mod impersonation;
pub mod log_streams;
pub mod m2m;
pub mod oidc;
pub mod organizations;
pub mod password_policy;
pub mod permissions;
pub mod risk;
pub mod roles;
pub mod scim;
pub mod security;
pub mod security_policies;
pub mod settings;
pub mod settings_v2;
pub mod sso;
pub mod system;
pub mod tenant_admins;
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
        .merge(actions::routes())
        .merge(branding::routes())
        .merge(log_streams::routes())
        .merge(oidc::routes())
        .merge(domains::routes())
        .merge(custom_domains::routes())
        .merge(roles::routes())
        .merge(sso::routes())
        .merge(scim::routes())
        .merge(directory::routes())
        .merge(security::routes())
        .merge(security_policies::routes())
        .merge(settings::routes())
        .merge(settings_v2::routes())
        .merge(system::routes())
        .merge(webhooks::routes())
        .merge(billing::routes())
        .merge(password_policy::routes())
        .merge(permissions::routes())
        .merge(bulk::routes())
        .merge(analytics::routes())
        .merge(consent::routes())
        .merge(tenant_admins::routes())
        .merge(m2m::routes())
        .nest("/risk", risk::routes())
        .nest("/i18n", i18n::routes())
        .layer(middleware::from_fn(crate::middleware::admin_roles::admin_role_middleware))
}
