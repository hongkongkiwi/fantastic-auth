//! Webhook events
//!
//! Standard events emitted by the system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Webhook event trait
pub trait WebhookEvent: Send + Sync {
    /// Get event type
    fn event_type(&self) -> String;
    
    /// Convert to JSON value
    fn to_json(&self) -> serde_json::Value;
}

/// User created event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCreatedEvent {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

impl WebhookEvent for UserCreatedEvent {
    fn event_type(&self) -> String {
        "user.created".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// User updated event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserUpdatedEvent {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub changes: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

impl WebhookEvent for UserUpdatedEvent {
    fn event_type(&self) -> String {
        "user.updated".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// User deleted event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDeletedEvent {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub deleted_at: DateTime<Utc>,
}

impl WebhookEvent for UserDeletedEvent {
    fn event_type(&self) -> String {
        "user.deleted".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// User login event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLoginEvent {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub method: String,
    pub success: bool,
    pub timestamp: DateTime<Utc>,
}

impl WebhookEvent for UserLoginEvent {
    fn event_type(&self) -> String {
        "user.login".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// User logout event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserLogoutEvent {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub timestamp: DateTime<Utc>,
}

impl WebhookEvent for UserLogoutEvent {
    fn event_type(&self) -> String {
        "user.logout".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Password changed event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordChangedEvent {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub changed_at: DateTime<Utc>,
}

impl WebhookEvent for PasswordChangedEvent {
    fn event_type(&self) -> String {
        "user.password_changed".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Email verified event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerifiedEvent {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub verified_at: DateTime<Utc>,
}

impl WebhookEvent for EmailVerifiedEvent {
    fn event_type(&self) -> String {
        "user.email_verified".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// MFA enabled event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaEnabledEvent {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub method: String,
    pub enabled_at: DateTime<Utc>,
}

impl WebhookEvent for MfaEnabledEvent {
    fn event_type(&self) -> String {
        "user.mfa_enabled".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// MFA disabled event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaDisabledEvent {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub method: String,
    pub disabled_at: DateTime<Utc>,
}

impl WebhookEvent for MfaDisabledEvent {
    fn event_type(&self) -> String {
        "user.mfa_disabled".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Organization created event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationCreatedEvent {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub slug: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

impl WebhookEvent for OrganizationCreatedEvent {
    fn event_type(&self) -> String {
        "organization.created".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Organization updated event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationUpdatedEvent {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub changes: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

impl WebhookEvent for OrganizationUpdatedEvent {
    fn event_type(&self) -> String {
        "organization.updated".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Organization deleted event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationDeletedEvent {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub deleted_at: DateTime<Utc>,
}

impl WebhookEvent for OrganizationDeletedEvent {
    fn event_type(&self) -> String {
        "organization.deleted".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Member joined event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberJoinedEvent {
    pub organization_id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub joined_at: DateTime<Utc>,
}

impl WebhookEvent for MemberJoinedEvent {
    fn event_type(&self) -> String {
        "organization.member.joined".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Member left event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberLeftEvent {
    pub organization_id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub email: String,
    pub left_at: DateTime<Utc>,
}

impl WebhookEvent for MemberLeftEvent {
    fn event_type(&self) -> String {
        "organization.member.left".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Invitation created event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationCreatedEvent {
    pub id: String,
    pub organization_id: String,
    pub tenant_id: String,
    pub email: String,
    pub role: String,
    pub invited_by: String,
    pub invited_at: DateTime<Utc>,
}

impl WebhookEvent for InvitationCreatedEvent {
    fn event_type(&self) -> String {
        "organization.invitation.created".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Invitation accepted event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationAcceptedEvent {
    pub id: String,
    pub organization_id: String,
    pub tenant_id: String,
    pub email: String,
    pub user_id: String,
    pub accepted_at: DateTime<Utc>,
}

impl WebhookEvent for InvitationAcceptedEvent {
    fn event_type(&self) -> String {
        "organization.invitation.accepted".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Session revoked event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRevokedEvent {
    pub user_id: String,
    pub tenant_id: String,
    pub session_id: String,
    pub revoked_at: DateTime<Utc>,
}

impl WebhookEvent for SessionRevokedEvent {
    fn event_type(&self) -> String {
        "session.revoked".to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// Generic event wrapper for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EventWrapper {
    UserCreated(UserCreatedEvent),
    UserUpdated(UserUpdatedEvent),
    UserDeleted(UserDeletedEvent),
    UserLogin(UserLoginEvent),
    UserLogout(UserLogoutEvent),
    PasswordChanged(PasswordChangedEvent),
    EmailVerified(EmailVerifiedEvent),
    MfaEnabled(MfaEnabledEvent),
    MfaDisabled(MfaDisabledEvent),
    OrganizationCreated(OrganizationCreatedEvent),
    OrganizationUpdated(OrganizationUpdatedEvent),
    OrganizationDeleted(OrganizationDeletedEvent),
    MemberJoined(MemberJoinedEvent),
    MemberLeft(MemberLeftEvent),
    InvitationCreated(InvitationCreatedEvent),
    InvitationAccepted(InvitationAcceptedEvent),
    SessionRevoked(SessionRevokedEvent),
}

impl WebhookEvent for EventWrapper {
    fn event_type(&self) -> String {
        match self {
            EventWrapper::UserCreated(_) => "user.created",
            EventWrapper::UserUpdated(_) => "user.updated",
            EventWrapper::UserDeleted(_) => "user.deleted",
            EventWrapper::UserLogin(_) => "user.login",
            EventWrapper::UserLogout(_) => "user.logout",
            EventWrapper::PasswordChanged(_) => "user.password_changed",
            EventWrapper::EmailVerified(_) => "user.email_verified",
            EventWrapper::MfaEnabled(_) => "user.mfa_enabled",
            EventWrapper::MfaDisabled(_) => "user.mfa_disabled",
            EventWrapper::OrganizationCreated(_) => "organization.created",
            EventWrapper::OrganizationUpdated(_) => "organization.updated",
            EventWrapper::OrganizationDeleted(_) => "organization.deleted",
            EventWrapper::MemberJoined(_) => "organization.member.joined",
            EventWrapper::MemberLeft(_) => "organization.member.left",
            EventWrapper::InvitationCreated(_) => "organization.invitation.created",
            EventWrapper::InvitationAccepted(_) => "organization.invitation.accepted",
            EventWrapper::SessionRevoked(_) => "session.revoked",
        }.to_string()
    }
    
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_user_created_event() {
        let event = UserCreatedEvent {
            id: "user_123".to_string(),
            tenant_id: "tenant_456".to_string(),
            email: "test@example.com".to_string(),
            created_at: Utc::now(),
        };
        
        assert_eq!(event.event_type(), "user.created");
        
        let json = event.to_json();
        assert!(json.get("id").is_some());
        assert!(json.get("email").is_some());
    }
    
    #[test]
    fn test_event_wrapper() {
        let event = UserLoginEvent {
            id: "user_123".to_string(),
            tenant_id: "tenant_456".to_string(),
            email: "test@example.com".to_string(),
            ip_address: Some("192.168.1.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            method: "password".to_string(),
            success: true,
            timestamp: Utc::now(),
        };
        
        let wrapper = EventWrapper::UserLogin(event);
        assert_eq!(wrapper.event_type(), "user.login");
    }
}
