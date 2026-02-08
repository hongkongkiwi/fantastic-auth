//! Webhook Event Triggers
//!
//! Helper functions for triggering webhook events from various parts of the application.
//! These functions handle the asynchronous delivery and error handling.

use serde_json::json;
use tracing::{debug, error};

use crate::state::AppState;

/// Trigger a user.created webhook event
pub async fn trigger_user_created(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    email: &str,
    name: Option<&str>,
) {
    let payload = json!({
        "id": user_id,
        "email": email,
        "name": name,
        "created_at": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "user.created", payload).await;
}

/// Trigger a user.updated webhook event
pub async fn trigger_user_updated(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    email: &str,
    changes: Vec<String>,
) {
    let payload = json!({
        "id": user_id,
        "email": email,
        "changes": changes,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "user.updated", payload).await;
}

/// Trigger a user.deleted webhook event
pub async fn trigger_user_deleted(state: &AppState, tenant_id: &str, user_id: &str, email: &str) {
    let payload = json!({
        "id": user_id,
        "email": email,
        "deleted_at": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "user.deleted", payload).await;
}

/// Trigger a session.created webhook event (login)
pub async fn trigger_session_created(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    session_id: &str,
    email: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    method: &str,
) {
    let payload = json!({
        "user_id": user_id,
        "session_id": session_id,
        "email": email,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "method": method,
        "created_at": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "session.created", payload).await;
}

/// Trigger a session.revoked webhook event (logout)
pub async fn trigger_session_revoked(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    session_id: &str,
    reason: Option<&str>,
) {
    let payload = json!({
        "user_id": user_id,
        "session_id": session_id,
        "reason": reason,
        "revoked_at": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "session.revoked", payload).await;
}

/// Trigger a user.password_changed webhook event
pub async fn trigger_password_changed(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    email: &str,
) {
    let payload = json!({
        "id": user_id,
        "email": email,
        "changed_at": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "user.password_changed", payload).await;
}

/// Trigger a user.email_verified webhook event
pub async fn trigger_email_verified(state: &AppState, tenant_id: &str, user_id: &str, email: &str) {
    let payload = json!({
        "id": user_id,
        "email": email,
        "verified_at": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "user.email_verified", payload).await;
}

/// Trigger a user.mfa_enabled webhook event
pub async fn trigger_mfa_enabled(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    email: &str,
    method: &str,
) {
    let payload = json!({
        "id": user_id,
        "email": email,
        "method": method,
        "enabled_at": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "user.mfa_enabled", payload).await;
}

/// Trigger a user.mfa_disabled webhook event
pub async fn trigger_mfa_disabled(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    email: &str,
    method: &str,
) {
    let payload = json!({
        "id": user_id,
        "email": email,
        "method": method,
        "disabled_at": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "user.mfa_disabled", payload).await;
}

/// Trigger a user.login webhook event
pub async fn trigger_user_login(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    email: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    method: &str,
    success: bool,
) {
    let payload = json!({
        "id": user_id,
        "email": email,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "method": method,
        "success": success,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "user.login", payload).await;
}

/// Trigger a user.logout webhook event
pub async fn trigger_user_logout(state: &AppState, tenant_id: &str, user_id: &str, email: &str) {
    let payload = json!({
        "id": user_id,
        "email": email,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "user.logout", payload).await;
}

/// Trigger a user.joined_organization webhook event
pub async fn trigger_user_joined_organization(
    state: &AppState,
    tenant_id: &str,
    user_id: &str,
    email: &str,
    organization_id: &str,
    role: Option<&str>,
    auto_enrolled: bool,
) {
    let payload = json!({
        "user_id": user_id,
        "email": email,
        "organization_id": organization_id,
        "role": role,
        "auto_enrolled": auto_enrolled,
        "joined_at": chrono::Utc::now().to_rfc3339(),
    });

    trigger_event(state, tenant_id, "user.joined_organization", payload).await;
}

/// Generic helper to trigger any webhook event
async fn trigger_event(
    state: &AppState,
    tenant_id: &str,
    event_type: &str,
    payload: serde_json::Value,
) {
    if !state.config.webhook.enabled {
        debug!(
            "Webhook processing is disabled, skipping event: {}",
            event_type
        );
        return;
    }

    match state
        .webhook_service
        .trigger_event(tenant_id, event_type, payload)
        .await
    {
        Ok(deliveries) => {
            debug!(
                event_type = event_type,
                delivery_count = deliveries.len(),
                "Webhook event triggered"
            );
        }
        Err(e) => {
            error!(
                event_type = event_type,
                error = %e,
                "Failed to trigger webhook event"
            );
        }
    }
}
