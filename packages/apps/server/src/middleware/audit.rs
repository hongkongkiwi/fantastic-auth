//! Audit logging middleware
//!
//! Automatically logs all API requests to the audit log.

use axum::{
    extract::{ConnectInfo, Request, State},
    middleware::Next,
    response::Response,
};
use std::net::SocketAddr;

use crate::db::{AuditRepository, CreateAuditLogRequest};
use crate::state::{AppState, CurrentUser};

const PLATFORM_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";

/// Audit logging configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Whether to log successful requests
    pub log_success: bool,
    /// Whether to log failed requests
    pub log_failure: bool,
    /// Actions to exclude from logging
    pub exclude_actions: Vec<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_success: true,
            log_failure: true,
            exclude_actions: vec!["health.check".to_string(), "metrics.get".to_string()],
        }
    }
}

/// Log an action to the audit log
pub async fn log_action(
    audit: &AuditRepository,
    tenant_id: &str,
    user_id: Option<&str>,
    session_id: Option<&str>,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    success: bool,
    error_message: Option<String>,
    metadata: Option<serde_json::Value>,
) {
    let req = CreateAuditLogRequest {
        tenant_id: tenant_id.to_string(),
        user_id: user_id.map(|s| s.to_string()),
        session_id: session_id.map(|s| s.to_string()),
        action: action.to_string(),
        resource_type: resource_type.to_string(),
        resource_id: resource_id.to_string(),
        ip_address: ip_address.map(|s| s.to_string()),
        user_agent: user_agent.map(|s| s.to_string()),
        success,
        error_message,
        metadata,
    };

    if let Err(e) = audit.create(req).await {
        tracing::error!("Failed to create audit log: {}", e);
    }
}

/// Middleware to audit all requests
pub async fn audit_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let headers = request.headers().clone();

    // Extract user info from extensions if available
    let user_info = request.extensions().get::<CurrentUser>().cloned();

    // Get user agent
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Get IP address
    let ip_address = addr.ip().to_string();

    // Process request
    let response = next.run(request).await;
    let status = response.status();

    // Determine if we should log this request
    let action = format!("{}.{}", method.as_str().to_lowercase(), uri.path());

    // Skip health checks and metrics
    if uri.path() == "/health" || uri.path() == "/metrics" {
        return response;
    }

    // Build metadata including impersonation info if applicable
    let mut metadata = serde_json::json!({
        "method": method.as_str(),
        "path": uri.path(),
        "status": status.as_u16(),
    });

    // Add impersonation metadata if the request is being made during impersonation
    if let Some(ref user) = user_info {
        if user.is_impersonation {
            if let Some(ref impersonator_id) = user.impersonator_id {
                metadata["impersonation"] = serde_json::json!({
                    "is_impersonation": true,
                    "impersonator_id": impersonator_id,
                    "impersonated_user_id": user.user_id,
                });
            }
        }
    }

    // Determine resource type and ID from path
    let (resource_type, resource_id) = parse_resource_from_path(&uri.path());

    // Log the action
    let tenant_id = user_info
        .as_ref()
        .map(|u| u.tenant_id.clone())
        .unwrap_or_else(|| PLATFORM_TENANT_ID.to_string());

    log_action(
        &state.db.audit(),
        &tenant_id,
        user_info.as_ref().map(|u| u.user_id.as_str()),
        user_info.as_ref().and_then(|u| u.session_id.as_deref()),
        &action,
        &resource_type,
        &resource_id,
        Some(&ip_address),
        user_agent.as_deref(),
        status.is_success(),
        if status.is_server_error() {
            Some(format!("HTTP {}", status.as_u16()))
        } else {
            None
        },
        Some(metadata),
    )
    .await;

    response
}

/// Parse resource type and ID from URL path
fn parse_resource_from_path(path: &str) -> (String, String) {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

    if parts.len() >= 2 {
        // Check if second part looks like an ID (uuid or numeric)
        let potential_id = parts[1];
        let is_id = uuid::Uuid::parse_str(potential_id).is_ok()
            || potential_id.chars().all(|c| c.is_numeric());

        if is_id {
            return (parts[0].to_string(), potential_id.to_string());
        }
    }

    if parts.len() >= 1 {
        (parts[0].to_string(), "-".to_string())
    } else {
        ("unknown".to_string(), "-".to_string())
    }
}

/// Helper function to log auth events
pub async fn log_auth_event(
    state: &AppState,
    tenant_id: &str,
    user_id: Option<&str>,
    event_type: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    success: bool,
    error_message: Option<String>,
) {
    log_action(
        &state.db.audit(),
        tenant_id,
        user_id,
        None, // session_id
        &format!("auth.{}", event_type),
        "user",
        user_id.unwrap_or("-"),
        ip_address,
        user_agent,
        success,
        error_message,
        None,
    )
    .await;
}

/// Helper function to log admin events
pub async fn log_admin_event(
    state: &AppState,
    admin_user: &CurrentUser,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    metadata: Option<serde_json::Value>,
    success: bool,
) {
    log_action(
        &state.db.audit(),
        &admin_user.tenant_id,
        Some(&admin_user.user_id),
        admin_user.session_id.as_deref(),
        &format!("admin.{}", action),
        resource_type,
        resource_id,
        None, // IP will be captured by middleware
        None, // User agent will be captured by middleware
        success,
        None,
        metadata,
    )
    .await;
}
