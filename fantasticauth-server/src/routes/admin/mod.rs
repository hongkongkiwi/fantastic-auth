//! Admin API Routes
//!
//! These routes are designed for administrative dashboards and management tools.
//! All routes are prefixed with `/api/v1/admin`.
//!
//! All endpoints require:
//! 1. Valid JWT Bearer token
//! 2. Admin role (`admin` or `owner`)
//!
//! ## Enhanced Admin Features
//!
//! ### AI Security Dashboard
//! - `GET /analytics/security` - Security analytics with AI insights
//! - `GET /analytics/risk-scores` - Risk score distribution
//! - `GET /analytics/threats` - Active threats detection
//! - `GET /analytics/user-behavior` - User behavior analytics
//!
//! ### Security Center
//! - `GET /security/overview` - Security score and status
//! - `POST /security/actions` - Execute security actions
//! - `GET /security/recommendations` - Security recommendations
//!
//! ### Impersonation Interface
//! - `POST /users/:id/impersonate` - Start impersonation
//! - `POST /impersonation/end` - End impersonation
//! - `GET /impersonation/sessions` - List impersonation sessions
//!
//! ### Bulk Operations
//! - `POST /bulk/import` - Bulk import users/organizations
//! - `POST /bulk/export` - Bulk export data
//! - `GET /bulk/jobs` - List bulk operation jobs
//!
//! ### Advanced Audit
//! - `GET /audit/advanced` - Advanced audit log querying
//! - `GET /audit/export` - Export audit logs
//! - `GET /audit/insights` - AI-powered audit insights
//!
//! ### API Key Management
//! - `GET /api-keys` - List API keys
//! - `POST /api-keys` - Create API key
//! - `GET /api-keys/:id` - Get API key details
//! - `PUT /api-keys/:id` - Update API key
//! - `DELETE /api-keys/:id` - Revoke API key
//! - `GET /api-keys/:id/stats` - Get API key usage stats
//! - `POST /api-keys/:id/rotate` - Rotate API key
//!
//! ### Email Template Editor
//! - `GET /email-templates` - List email templates
//! - `GET /email-templates/:type` - Get template
//! - `PUT /email-templates/:type` - Update template
//! - `POST /email-templates/:type/preview` - Preview template
//! - `POST /email-templates/:type/send-test` - Send test email
//! - `GET /email-templates/variables` - List available variables
//!
//! ### Rate Limiting Dashboard
//! - `GET /rate-limits` - Get rate limit configuration
//! - `PUT /rate-limits/config` - Update rate limits
//! - `GET /rate-limits/violations` - View violations
//! - `GET /rate-limits/blocked-ips` - List blocked IPs
//! - `POST /rate-limits/block-ip` - Block an IP
//! - `DELETE /rate-limits/block-ip/:ip` - Unblock an IP
//!
//! ### Custom Domain Management
//! - `GET /domains` - List custom domains
//! - `POST /domains` - Add custom domain
//! - `GET /domains/:id` - Get domain details
//! - `DELETE /domains/:id` - Remove domain
//! - `POST /domains/:id/verify` - Verify domain
//! - `GET /domains/:id/health` - Domain health check
//! - `POST /domains/:id/renew-ssl` - Renew SSL certificate

use axum::{middleware, Router};

pub mod actions;
pub mod analytics;
pub mod api_keys;
pub mod audit_exports;
pub mod audit_logs;
pub mod billing;
pub mod branding;
pub mod bulk;
pub mod consent;
pub mod custom_domains;
pub mod dashboard;
pub mod device_flow;
pub mod directory;
pub mod domains;
pub mod email_templates;
pub mod federation;
pub mod groups;
pub mod i18n;
pub mod idp;
pub mod impersonation;
pub mod log_streams;
pub mod m2m;
pub mod keys;
pub mod migrations;
pub mod organizations;
pub mod org_settings;
pub mod password_policy;
pub mod permissions;
pub mod projects;
pub mod applications;
pub mod push_mfa;
pub mod rate_limits;
pub mod risk;
pub mod roles;
pub mod scim;
pub mod sessions;
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
        // Dashboard & Analytics
        .merge(dashboard::routes())
        .merge(analytics::routes())
        // User & Organization Management
        .merge(users::routes())
        .merge(organizations::routes())
        .merge(groups::routes())
        .merge(org_settings::routes())
        .merge(projects::routes())
        .merge(applications::routes())
        .merge(roles::routes())
        .merge(permissions::routes())
        // Security & Compliance
        .merge(security::routes())
        .merge(security_policies::routes())
        .merge(risk::routes())
        .merge(password_policy::routes())
        .merge(consent::routes())
        // Authentication & SSO
        .merge(sso::routes())
        .merge(federation::routes())
        .merge(idp::routes())
        .merge(scim::routes())
        .merge(directory::routes())
        .merge(impersonation::routes())
        .merge(sessions::routes())
        // API & Access Management
        .merge(api_keys::routes())
        .merge(m2m::routes())
        .merge(keys::routes())
        .merge(rate_limits::routes())
        // Push MFA
        .merge(push_mfa::routes())
        // Configuration & Settings
        .merge(settings::routes())
        .merge(settings_v2::routes())
        .merge(branding::routes())
        .merge(email_templates::routes())
        // Domain Management
        .merge(domains::routes())
        .merge(custom_domains::routes())
        // Operations
        .merge(bulk::routes())
        .merge(actions::routes())
        .merge(device_flow::routes())
        // Monitoring & Logging
        .merge(audit_logs::routes())
        .merge(audit_exports::routes())
        .merge(log_streams::routes())
        .merge(webhooks::routes())
        // System & Admin
        .merge(system::routes())
        .merge(tenant_admins::routes())
        .merge(billing::routes())
        // i18n
        .nest("/i18n", i18n::routes())
        // Admin role middleware applied to all routes
        .layer(middleware::from_fn(crate::middleware::admin_roles::admin_role_middleware))
}
