//! Internal/Privileged API Routes
//!
//! These routes are designed for:
//! - SaaS platform website (tenant signup, billing)
//! - Internal services and automation
//! - Super admin operations across tenants
//!
//! All routes are prefixed with `/api/v1/internal`.
//!
//! Authentication: API Key (`X-API-Key` header) or Internal JWT with super_admin role
//!
//! TODO: Add authentication and superadmin middleware. Currently these routes
//! are functional but require manual authentication/authorization before use.

use axum::Router;

pub mod analytics;
pub mod billing;
pub mod config;
pub mod maintenance;
pub mod platform_users;
pub mod tenants;

use crate::state::AppState;

/// Create internal API routes
/// Mounted at `/api/v1/internal`
///
/// These routes bypass tenant RLS and operate at platform level.
pub fn routes() -> Router<AppState> {
    Router::new()
        .merge(tenants::routes())
        .merge(platform_users::routes())
        .merge(billing::routes())
        .merge(analytics::routes())
        .merge(config::routes())
        .merge(maintenance::routes())
}
