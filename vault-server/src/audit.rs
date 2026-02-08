//! Audit Logging Service
//!
//! Provides comprehensive audit logging for compliance and security monitoring.
//! All audit logs are written asynchronously to the database and failures
//! are logged but don't block request processing.
//!
//! # Usage
//!
//! ```rust
//! use crate::audit::{AuditLogger, RequestContext};
//!
//! // Create an audit logger
//! let audit = AuditLogger::new(state.db.clone());
//!
//! // Log a simple event
//! audit.log_login_success(
//!     tenant_id,
//!     user_id,
//!     Some(session_id),
//!     email,
//!     Some(RequestContext::from_request(&headers, Some(&ConnectInfo(addr)))),
//!     "password",
//! );
//!
//! // Log a custom event
//! audit.log(
//!     tenant_id,
//!     AuditAction::UserCreated,
//!     ResourceType::User,
//!     user_id,
//!     Some(admin_user_id),
//!     None,
//!     None,
//!     true,
//!     None,
//!     Some(json!({ "created_by": admin_email })),
//! );
//! ```
//!
//! # Important Notes
//!
//! - Audit logging is fire-and-forget by default (async, non-blocking)
//! - Use `log_sync()` for critical security events that must be recorded
//! - All methods handle errors internally and log them via tracing
//! - The `RequestContext` extracts IP address, user agent, and tenant ID from requests
//! - Tenant context is automatically set for RLS (Row Level Security) compliance

use async_trait::async_trait;
use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::Database;
use crate::state::CurrentUser;

/// Trait for webhook event triggering
#[async_trait::async_trait]
pub trait WebhookNotifier: Send + Sync {
    async fn trigger_event(&self, tenant_id: &str, event_type: &str, payload: serde_json::Value);
}

/// Default webhook notifier implementation
#[derive(Clone)]
pub struct DefaultWebhookNotifier {
    db: Database,
}

impl DefaultWebhookNotifier {
    pub fn new(db: Database) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl WebhookNotifier for DefaultWebhookNotifier {
    async fn trigger_event(&self, tenant_id: &str, event_type: &str, payload: serde_json::Value) {
        // Get active endpoints for this event
        let endpoints = match self
            .db
            .webhooks()
            .get_active_endpoints_for_event(tenant_id, event_type)
            .await
        {
            Ok(eps) => eps,
            Err(e) => {
                tracing::error!(error = %e, "Failed to get webhook endpoints");
                return;
            }
        };

        let endpoint_count = endpoints.len();

        // Create deliveries for each endpoint
        for endpoint in endpoints {
            let payload_size = payload.to_string().len() as i32;
            if let Err(e) = self
                .db
                .webhooks()
                .create_delivery(
                    &endpoint.id,
                    tenant_id,
                    event_type,
                    payload.clone(),
                    payload_size,
                )
                .await
            {
                tracing::error!(error = %e, endpoint_id = %endpoint.id, "Failed to create webhook delivery");
            }
        }

        tracing::debug!(
            tenant_id = tenant_id,
            event_type = event_type,
            endpoint_count = endpoint_count,
            "Webhook events triggered"
        );
    }
}

/// Audit action types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    // Custom action for dynamic actions
    Custom(&'static str),
    // Authentication actions
    Login,
    LoginFailed,
    Logout,
    TokenRefresh,
    TokenRefreshFailed,

    // Password actions
    PasswordChange,
    PasswordChangeFailed,
    PasswordReset,
    PasswordResetFailed,
    PasswordResetRequested,

    // MFA actions
    MfaEnabled,
    MfaDisabled,
    MfaVerified,

    // Step-up authentication actions
    StepUpSuccess,
    StepUpFailed,
    MfaVerificationFailed,

    // Registration
    UserRegistered,
    RegistrationFailed,
    EmailVerified,
    EmailVerificationFailed,

    // Magic link
    MagicLinkSent,
    MagicLinkFailed,
    MagicLinkUsed,

    // OAuth
    OAuthLogin,
    OAuthLoginFailed,

    // User management (admin)
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserSuspended,
    UserActivated,

    // Session management
    SessionsRevoked,
    SessionRevoked,

    // Session validation
    SessionValidated,
    SessionValidationFailed,
    
    // Risk-based authentication
    RiskAssessmentCreated,
    LoginBlockedRisk,

    // Admin access
    AdminAccessGranted,
    AdminAccessDenied,
    SuperadminAccessGranted,
    SuperadminAccessDenied,

    // Impersonation
    ImpersonationStarted,
    ImpersonationEnded,
    ImpersonationDenied,

    // Webhook actions
    WebhookCreated,
    WebhookUpdated,
    WebhookDeleted,
    WebhookSecretRotated,
    WebhookTested,

    // WebAuthn/Passkey actions
    WebAuthnRegistered,
    WebAuthnRegistrationFailed,
    WebAuthnAuthenticated,
    WebAuthnAuthenticationFailed,
    WebAuthnCredentialDeleted,
    WebAuthnCredentialUpdated,

    // Account linking actions
    AccountLinked,
    AccountLinkFailed,
    AccountUnlinked,
    AccountUnlinkFailed,
    PrimaryAccountChanged,
    AccountMerged,

    // Domain verification actions
    DomainCreated,
    DomainDeleted,
    DomainUpdated,
    DomainVerified,
    DomainVerificationFailed,

    // Bulk operations
    BulkImportStarted,
    BulkExportStarted,
    BulkJobDeleted,
    
    // Consent and privacy
    ConsentGranted,
    ConsentWithdrawn,
    ConsentVersionCreated,
    ConsentVersionUpdated,
    DataExportRequested,
    DataExportCompleted,
    DataExportFailed,
    AccountDeletionRequested,
    AccountDeletionCancelled,
    AccountDeletionCompleted,

    // Anonymous/guest authentication
    AnonymousSessionCreated,
    AnonymousSessionFailed,
    AnonymousConverted,
    AnonymousConversionFailed,
}

impl AuditAction {
    /// Get the action name as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::Login => "user.login",
            AuditAction::LoginFailed => "user.login_failed",
            AuditAction::Logout => "user.logout",
            AuditAction::TokenRefresh => "token.refresh",
            AuditAction::TokenRefreshFailed => "token.refresh_failed",
            AuditAction::PasswordChange => "password.change",
            AuditAction::PasswordChangeFailed => "password.change_failed",
            AuditAction::PasswordReset => "password.reset",
            AuditAction::PasswordResetFailed => "password.reset_failed",
            AuditAction::PasswordResetRequested => "password.reset_requested",
            AuditAction::MfaEnabled => "mfa.enabled",
            AuditAction::MfaDisabled => "mfa.disabled",
            AuditAction::MfaVerified => "mfa.verified",
            AuditAction::MfaVerificationFailed => "mfa.verification_failed",
            AuditAction::StepUpSuccess => "step_up.success",
            AuditAction::StepUpFailed => "step_up.failed",
            AuditAction::UserRegistered => "user.registered",
            AuditAction::RegistrationFailed => "user.registration_failed",
            AuditAction::EmailVerified => "email.verified",
            AuditAction::EmailVerificationFailed => "email.verification_failed",
            AuditAction::MagicLinkSent => "magic_link.sent",
            AuditAction::MagicLinkFailed => "magic_link.failed",
            AuditAction::MagicLinkUsed => "magic_link.used",
            AuditAction::OAuthLogin => "oauth.login",
            AuditAction::OAuthLoginFailed => "oauth.login_failed",
            AuditAction::UserCreated => "user.created",
            AuditAction::UserUpdated => "user.updated",
            AuditAction::UserDeleted => "user.deleted",
            AuditAction::UserSuspended => "user.suspended",
            AuditAction::UserActivated => "user.activated",
            AuditAction::SessionsRevoked => "sessions.revoked_all",
            AuditAction::SessionRevoked => "session.revoked",
            AuditAction::SessionValidated => "session.validated",
            AuditAction::SessionValidationFailed => "session.validation_failed",
            AuditAction::RiskAssessmentCreated => "risk.assessment_created",
            AuditAction::LoginBlockedRisk => "risk.login_blocked",
            AuditAction::AdminAccessGranted => "admin.access_granted",
            AuditAction::AdminAccessDenied => "admin.access_denied",
            AuditAction::SuperadminAccessGranted => "superadmin.access_granted",
            AuditAction::SuperadminAccessDenied => "superadmin.access_denied",
            AuditAction::ImpersonationStarted => "impersonation.started",
            AuditAction::ImpersonationEnded => "impersonation.ended",
            AuditAction::ImpersonationDenied => "impersonation.denied",
            AuditAction::WebhookCreated => "webhook.created",
            AuditAction::WebhookUpdated => "webhook.updated",
            AuditAction::WebhookDeleted => "webhook.deleted",
            AuditAction::WebhookSecretRotated => "webhook.secret_rotated",
            AuditAction::WebhookTested => "webhook.tested",
            AuditAction::WebAuthnRegistered => "webauthn.registered",
            AuditAction::WebAuthnRegistrationFailed => "webauthn.registration_failed",
            AuditAction::WebAuthnAuthenticated => "webauthn.authenticated",
            AuditAction::WebAuthnAuthenticationFailed => "webauthn.authentication_failed",
            AuditAction::WebAuthnCredentialDeleted => "webauthn.credential_deleted",
            AuditAction::WebAuthnCredentialUpdated => "webauthn.credential_updated",
            AuditAction::AccountLinked => "account.linked",
            AuditAction::AccountLinkFailed => "account.link_failed",
            AuditAction::AccountUnlinked => "account.unlinked",
            AuditAction::AccountUnlinkFailed => "account.unlink_failed",
            AuditAction::PrimaryAccountChanged => "account.primary_changed",
            AuditAction::AccountMerged => "account.merged",
            AuditAction::Custom(action) => action,
            AuditAction::DomainCreated => "domain.created",
            AuditAction::DomainDeleted => "domain.deleted",
            AuditAction::DomainUpdated => "domain.updated",
            AuditAction::DomainVerified => "domain.verified",
            AuditAction::DomainVerificationFailed => "domain.verification_failed",
            AuditAction::BulkImportStarted => "bulk.import_started",
            AuditAction::BulkExportStarted => "bulk.export_started",
            AuditAction::BulkJobDeleted => "bulk.job_deleted",
            AuditAction::ConsentGranted => "consent.granted",
            AuditAction::ConsentWithdrawn => "consent.withdrawn",
            AuditAction::ConsentVersionCreated => "consent.version_created",
            AuditAction::ConsentVersionUpdated => "consent.version_updated",
            AuditAction::DataExportRequested => "data_export.requested",
            AuditAction::DataExportCompleted => "data_export.completed",
            AuditAction::DataExportFailed => "data_export.failed",
            AuditAction::AccountDeletionRequested => "account_deletion.requested",
            AuditAction::AccountDeletionCancelled => "account_deletion.cancelled",
            AuditAction::AccountDeletionCompleted => "account_deletion.completed",
        }
    }
}

/// Resource types for audit logs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    User,
    Session,
    Token,
    Password,
    Mfa,
    Email,
    MagicLink,
    OAuth,
    Admin,
    Webhook,
    WebAuthn,
    LinkedAccount,
    Organization,
    Domain,
    BulkJob,
    Consent,
    RiskAssessment,
}

impl ResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceType::User => "user",
            ResourceType::Session => "session",
            ResourceType::Token => "token",
            ResourceType::Password => "password",
            ResourceType::Mfa => "mfa",
            ResourceType::Email => "email",
            ResourceType::MagicLink => "magic_link",
            ResourceType::OAuth => "oauth",
            ResourceType::Admin => "admin",
            ResourceType::Webhook => "webhook",
            ResourceType::WebAuthn => "webauthn",
            ResourceType::LinkedAccount => "linked_account",
            ResourceType::Organization => "organization",
            ResourceType::Domain => "domain",
            ResourceType::BulkJob => "bulk_job",
            ResourceType::Consent => "consent",
            ResourceType::RiskAssessment => "risk_assessment",
        }
    }
}

impl From<&str> for AuditAction {
    fn from(action: &str) -> Self {
        match action {
            "consent_submitted" => AuditAction::ConsentGranted,
            "consent_withdrawn" => AuditAction::ConsentWithdrawn,
            "consent_version_created" => AuditAction::ConsentVersionCreated,
            "consent_version_updated" => AuditAction::ConsentVersionUpdated,
            "data_export_requested" => AuditAction::DataExportRequested,
            "deletion_requested" => AuditAction::AccountDeletionRequested,
            "deletion_cancelled" => AuditAction::AccountDeletionCancelled,
            _ => AuditAction::Custom(action),
        }
    }
}

/// Context information extracted from an HTTP request
#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub tenant_id: Option<String>,
}

impl RequestContext {
    /// Extract context from request headers and connection info
    pub fn from_request(headers: &HeaderMap, addr: Option<&ConnectInfo<SocketAddr>>) -> Self {
        let ip_address = addr.map(|a| a.0.ip().to_string()).or_else(|| {
            headers
                .get("x-forwarded-for")
                .or_else(|| headers.get("x-real-ip"))
                .and_then(|h| h.to_str().ok())
                .map(|s| s.split(',').next().unwrap_or(s).trim().to_string())
        });

        let user_agent = headers
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        let tenant_id = headers
            .get("x-tenant-id")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        Self {
            ip_address,
            user_agent,
            tenant_id,
        }
    }

    /// Extract just IP and user agent from headers (for when ConnectInfo isn't available)
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Self::from_request(headers, None)
    }
}

/// Audit logger for recording security and compliance events
#[derive(Clone)]
pub struct AuditLogger {
    db: Database,
    webhook_notifier: Option<Arc<dyn WebhookNotifier>>,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(db: Database) -> Self {
        Self {
            db,
            webhook_notifier: None,
        }
    }

    /// Create a new audit logger with webhook notifier
    pub fn with_webhook_notifier(db: Database, notifier: Arc<dyn WebhookNotifier>) -> Self {
        Self {
            db,
            webhook_notifier: Some(notifier),
        }
    }

    /// Enable webhook notifications
    pub fn enable_webhooks(&mut self, notifier: Arc<dyn WebhookNotifier>) {
        self.webhook_notifier = Some(notifier);
    }

    /// Log an audit event
    ///
    /// This is a fire-and-forget operation - failures are logged but don't
    /// block the request. Use `log_sync` if you need to wait for completion.
    pub fn log(
        &self,
        tenant_id: impl Into<String>,
        action: AuditAction,
        resource_type: ResourceType,
        resource_id: impl Into<String>,
        user_id: Option<String>,
        session_id: Option<String>,
        context: Option<RequestContext>,
        success: bool,
        error_message: Option<String>,
        metadata: Option<serde_json::Value>,
    ) {
        let db = self.db.clone();
        let tenant_id = tenant_id.into();
        let resource_id = resource_id.into();
        let action_str = action.as_str().to_string();
        let resource_type_str = resource_type.as_str().to_string();
        let ip_address = context.as_ref().and_then(|c| c.ip_address.clone());
        let user_agent = context.as_ref().and_then(|c| c.user_agent.clone());

        // Spawn async task to write to database
        tokio::spawn(async move {
            if let Err(e) = Self::write_to_db(
                &db,
                &tenant_id,
                action_str,
                resource_type_str,
                resource_id,
                user_id,
                session_id,
                ip_address,
                user_agent,
                success,
                error_message,
                metadata,
            )
            .await
            {
                tracing::error!(error = %e, "Failed to write audit log to database");
            }
        });
    }

    /// Log an audit event and wait for completion
    ///
    /// Use this when you need to ensure the audit log is written before
    /// continuing (e.g., for critical security events).
    pub async fn log_sync(
        &self,
        tenant_id: impl Into<String>,
        action: AuditAction,
        resource_type: ResourceType,
        resource_id: impl Into<String>,
        user_id: Option<String>,
        session_id: Option<String>,
        context: Option<RequestContext>,
        success: bool,
        error_message: Option<String>,
        metadata: Option<serde_json::Value>,
    ) {
        let tenant_id = tenant_id.into();
        let resource_id = resource_id.into();
        let action_str = action.as_str().to_string();
        let resource_type_str = resource_type.as_str().to_string();
        let ip_address = context.as_ref().and_then(|c| c.ip_address.clone());
        let user_agent = context.as_ref().and_then(|c| c.user_agent.clone());

        if let Err(e) = Self::write_to_db(
            &self.db,
            &tenant_id,
            action_str,
            resource_type_str,
            resource_id,
            user_id,
            session_id,
            ip_address,
            user_agent,
            success,
            error_message,
            metadata,
        )
        .await
        {
            tracing::error!(error = %e, "Failed to write audit log to database");
        }
    }

    /// Trigger webhook for audit event
    fn trigger_webhook(&self, tenant_id: String, event_type: String, payload: serde_json::Value) {
        if let Some(ref notifier) = self.webhook_notifier {
            let notifier = notifier.clone();
            tokio::spawn(async move {
                notifier
                    .trigger_event(&tenant_id, &event_type, payload)
                    .await;
            });
        }
    }

    /// Write audit log entry to database
    async fn write_to_db(
        db: &Database,
        tenant_id: &str,
        action: String,
        resource_type: String,
        resource_id: String,
        user_id: Option<String>,
        session_id: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        success: bool,
        error: Option<String>,
        metadata: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        // Set tenant context for RLS
        let mut conn = db.pool().acquire().await?;
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id)
            .execute(&mut *conn)
            .await?;

        // Insert audit log
        sqlx::query(
            r#"INSERT INTO audit_logs 
               (id, tenant_id, user_id, session_id, action, resource_type, resource_id,
                ip_address, user_agent, success, error, metadata, timestamp)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())"#,
        )
        .bind(Uuid::new_v4().to_string())
        .bind(tenant_id)
        .bind(user_id)
        .bind(session_id)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(ip_address)
        .bind(user_agent)
        .bind(success)
        .bind(error)
        .bind(metadata)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    // ===== Convenience methods for common events =====

    /// Log successful login
    pub fn log_login_success(
        &self,
        tenant_id: &str,
        user_id: &str,
        session_id: Option<&str>,
        email: &str,
        context: Option<RequestContext>,
        method: &str,
    ) {
        let ip_address = context.as_ref().and_then(|c| c.ip_address.clone());
        let user_agent = context.as_ref().and_then(|c| c.user_agent.clone());

        self.log(
            tenant_id,
            AuditAction::Login,
            ResourceType::User,
            user_id,
            Some(user_id.to_string()),
            session_id.map(|s| s.to_string()),
            context,
            true,
            None,
            Some(json!({ "email": email, "method": method })),
        );

        // Trigger webhook
        self.trigger_webhook(
            tenant_id.to_string(),
            "user.login".to_string(),
            json!({
                "id": user_id,
                "tenant_id": tenant_id,
                "email": email,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "method": method,
                "success": true,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    /// Log failed login
    pub fn log_login_failed(
        &self,
        tenant_id: &str,
        email: &str,
        context: Option<RequestContext>,
        reason: &str,
    ) {
        self.log(
            tenant_id,
            AuditAction::LoginFailed,
            ResourceType::User,
            email,
            None,
            None,
            context,
            false,
            Some(reason.to_string()),
            Some(json!({ "email": email })),
        );
    }

    /// Log logout
    pub fn log_logout(&self, tenant_id: &str, user_id: &str, session_id: &str) {
        self.log(
            tenant_id,
            AuditAction::Logout,
            ResourceType::Session,
            session_id,
            Some(user_id.to_string()),
            Some(session_id.to_string()),
            None,
            true,
            None,
            None,
        );

        // Trigger webhook
        self.trigger_webhook(
            tenant_id.to_string(),
            "user.logout".to_string(),
            json!({
                "id": user_id,
                "tenant_id": tenant_id,
                "session_id": session_id,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    /// Log password change
    pub fn log_password_change(
        &self,
        tenant_id: &str,
        user_id: &str,
        session_id: Option<&str>,
        context: Option<RequestContext>,
        success: bool,
        error: Option<&str>,
    ) {
        self.log(
            tenant_id,
            if success {
                AuditAction::PasswordChange
            } else {
                AuditAction::PasswordChangeFailed
            },
            ResourceType::Password,
            user_id,
            Some(user_id.to_string()),
            session_id.map(|s| s.to_string()),
            context,
            success,
            error.map(|s| s.to_string()),
            None,
        );
    }

    /// Log MFA verification
    pub fn log_mfa_verification(
        &self,
        tenant_id: &str,
        user_id: &str,
        session_id: Option<&str>,
        context: Option<RequestContext>,
        success: bool,
        method: &str,
    ) {
        self.log(
            tenant_id,
            if success {
                AuditAction::MfaVerified
            } else {
                AuditAction::MfaVerificationFailed
            },
            ResourceType::Mfa,
            user_id,
            Some(user_id.to_string()),
            session_id.map(|s| s.to_string()),
            context,
            success,
            if success {
                None
            } else {
                Some("MFA verification failed".to_string())
            },
            Some(json!({ "method": method })),
        );
    }

    /// Log user registration
    pub fn log_user_registered(
        &self,
        tenant_id: &str,
        user_id: &str,
        email: &str,
        context: Option<RequestContext>,
    ) {
        self.log(
            tenant_id,
            AuditAction::UserRegistered,
            ResourceType::User,
            user_id,
            Some(user_id.to_string()),
            None,
            context.clone(),
            true,
            None,
            Some(json!({ "email": email })),
        );

        // Trigger webhook
        self.trigger_webhook(
            tenant_id.to_string(),
            "user.created".to_string(),
            json!({
                "id": user_id,
                "tenant_id": tenant_id,
                "email": email,
                "ip_address": context.as_ref().and_then(|c| c.ip_address.clone()),
                "user_agent": context.as_ref().and_then(|c| c.user_agent.clone()),
                "created_at": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    /// Log registration failure
    pub fn log_registration_failed(
        &self,
        tenant_id: &str,
        email: &str,
        context: Option<RequestContext>,
        reason: &str,
    ) {
        self.log(
            tenant_id,
            AuditAction::RegistrationFailed,
            ResourceType::User,
            email,
            None,
            None,
            context,
            false,
            Some(reason.to_string()),
            Some(json!({ "email": email })),
        );
    }

    /// Log token refresh
    pub fn log_token_refresh(
        &self,
        tenant_id: &str,
        user_id: &str,
        session_id: &str,
        success: bool,
        error: Option<&str>,
    ) {
        self.log(
            tenant_id,
            if success {
                AuditAction::TokenRefresh
            } else {
                AuditAction::TokenRefreshFailed
            },
            ResourceType::Token,
            session_id,
            Some(user_id.to_string()),
            Some(session_id.to_string()),
            None,
            success,
            error.map(|s| s.to_string()),
            None,
        );
    }

    /// Log session validation (from middleware)
    pub fn log_session_validation(
        &self,
        tenant_id: &str,
        user_id: Option<&str>,
        session_id: Option<&str>,
        context: Option<RequestContext>,
        success: bool,
        error: Option<&str>,
    ) {
        self.log(
            tenant_id,
            if success {
                AuditAction::SessionValidated
            } else {
                AuditAction::SessionValidationFailed
            },
            ResourceType::Session,
            session_id.unwrap_or("unknown"),
            user_id.map(|s| s.to_string()),
            session_id.map(|s| s.to_string()),
            context,
            success,
            error.map(|s| s.to_string()),
            None,
        );
    }

    /// Log admin user creation
    pub fn log_user_created(
        &self,
        tenant_id: &str,
        admin_user_id: &str,
        created_user_id: &str,
        email: &str,
    ) {
        self.log(
            tenant_id,
            AuditAction::UserCreated,
            ResourceType::User,
            created_user_id,
            Some(admin_user_id.to_string()),
            None,
            None,
            true,
            None,
            Some(json!({ "created_user_email": email })),
        );

        // Trigger webhook
        self.trigger_webhook(
            tenant_id.to_string(),
            "user.created".to_string(),
            json!({
                "id": created_user_id,
                "tenant_id": tenant_id,
                "email": email,
                "created_by": admin_user_id,
                "created_at": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    /// Log admin user update
    pub fn log_user_updated(
        &self,
        tenant_id: &str,
        admin_user_id: &str,
        updated_user_id: &str,
        changes: serde_json::Value,
    ) {
        self.log(
            tenant_id,
            AuditAction::UserUpdated,
            ResourceType::User,
            updated_user_id,
            Some(admin_user_id.to_string()),
            None,
            None,
            true,
            None,
            Some(changes),
        );
    }

    /// Log admin user deletion
    pub fn log_user_deleted(&self, tenant_id: &str, admin_user_id: &str, deleted_user_id: &str) {
        self.log(
            tenant_id,
            AuditAction::UserDeleted,
            ResourceType::User,
            deleted_user_id,
            Some(admin_user_id.to_string()),
            None,
            None,
            true,
            None,
            None,
        );

        // Trigger webhook
        self.trigger_webhook(
            tenant_id.to_string(),
            "user.deleted".to_string(),
            json!({
                "id": deleted_user_id,
                "tenant_id": tenant_id,
                "deleted_by": admin_user_id,
                "deleted_at": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    /// Log user suspension
    pub fn log_user_suspended(
        &self,
        tenant_id: &str,
        admin_user_id: &str,
        suspended_user_id: &str,
    ) {
        self.log(
            tenant_id,
            AuditAction::UserSuspended,
            ResourceType::User,
            suspended_user_id,
            Some(admin_user_id.to_string()),
            None,
            None,
            true,
            None,
            None,
        );
    }

    /// Log user activation
    pub fn log_user_activated(
        &self,
        tenant_id: &str,
        admin_user_id: &str,
        activated_user_id: &str,
    ) {
        self.log(
            tenant_id,
            AuditAction::UserActivated,
            ResourceType::User,
            activated_user_id,
            Some(admin_user_id.to_string()),
            None,
            None,
            true,
            None,
            None,
        );
    }

    /// Log session revocation
    pub fn log_sessions_revoked(
        &self,
        tenant_id: &str,
        admin_user_id: &str,
        target_user_id: &str,
        count: u64,
    ) {
        self.log(
            tenant_id,
            AuditAction::SessionsRevoked,
            ResourceType::Session,
            target_user_id,
            Some(admin_user_id.to_string()),
            None,
            None,
            true,
            None,
            Some(json!({ "revoked_count": count, "target_user_id": target_user_id })),
        );
    }

    /// Log admin access check
    pub fn log_admin_access(&self, tenant_id: &str, user_id: &str, granted: bool) {
        self.log(
            tenant_id,
            if granted {
                AuditAction::AdminAccessGranted
            } else {
                AuditAction::AdminAccessDenied
            },
            ResourceType::Admin,
            user_id,
            Some(user_id.to_string()),
            None,
            None,
            granted,
            if granted {
                None
            } else {
                Some("Admin access denied".to_string())
            },
            None,
        );
    }

    /// Log superadmin access check
    pub fn log_superadmin_access(&self, tenant_id: &str, user_id: &str, granted: bool) {
        self.log(
            tenant_id,
            if granted {
                AuditAction::SuperadminAccessGranted
            } else {
                AuditAction::SuperadminAccessDenied
            },
            ResourceType::Admin,
            user_id,
            Some(user_id.to_string()),
            None,
            None,
            granted,
            if granted {
                None
            } else {
                Some("Superadmin access denied".to_string())
            },
            None,
        );
    }

    /// Log impersonation started
    pub fn log_impersonation_started(
        &self,
        tenant_id: &str,
        admin_user_id: &str,
        target_user_id: &str,
        session_id: &str,
        reason: &str,
        duration_minutes: i64,
    ) {
        self.log(
            tenant_id,
            AuditAction::ImpersonationStarted,
            ResourceType::Admin,
            target_user_id,
            Some(admin_user_id.to_string()),
            Some(session_id.to_string()),
            None,
            true,
            None,
            Some(json!({
                "target_user_id": target_user_id,
                "reason": reason,
                "duration_minutes": duration_minutes,
                "impersonator_id": admin_user_id,
            })),
        );

        // Trigger webhook
        self.trigger_webhook(
            tenant_id.to_string(),
            "impersonation.started".to_string(),
            json!({
                "impersonator_id": admin_user_id,
                "target_user_id": target_user_id,
                "session_id": session_id,
                "reason": reason,
                "duration_minutes": duration_minutes,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    /// Log impersonation ended
    pub fn log_impersonation_ended(
        &self,
        tenant_id: &str,
        admin_user_id: &str,
        target_user_id: &str,
        session_id: &str,
    ) {
        self.log(
            tenant_id,
            AuditAction::ImpersonationEnded,
            ResourceType::Admin,
            target_user_id,
            Some(admin_user_id.to_string()),
            Some(session_id.to_string()),
            None,
            true,
            None,
            Some(json!({
                "target_user_id": target_user_id,
                "impersonator_id": admin_user_id,
            })),
        );

        // Trigger webhook
        self.trigger_webhook(
            tenant_id.to_string(),
            "impersonation.ended".to_string(),
            json!({
                "impersonator_id": admin_user_id,
                "target_user_id": target_user_id,
                "session_id": session_id,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    /// Log impersonation denied
    pub fn log_impersonation_denied(
        &self,
        tenant_id: &str,
        admin_user_id: &str,
        target_user_id: &str,
        reason: &str,
    ) {
        self.log(
            tenant_id,
            AuditAction::ImpersonationDenied,
            ResourceType::Admin,
            target_user_id,
            Some(admin_user_id.to_string()),
            None,
            None,
            false,
            Some(reason.to_string()),
            Some(json!({
                "target_user_id": target_user_id,
                "impersonator_id": admin_user_id,
                "reason": reason,
            })),
        );
    }

    /// Log OAuth login
    pub fn log_oauth_login(
        &self,
        tenant_id: &str,
        user_id: &str,
        provider: &str,
        context: Option<RequestContext>,
        success: bool,
        error: Option<&str>,
    ) {
        self.log(
            tenant_id,
            if success {
                AuditAction::OAuthLogin
            } else {
                AuditAction::OAuthLoginFailed
            },
            ResourceType::OAuth,
            user_id,
            Some(user_id.to_string()),
            None,
            context,
            success,
            error.map(|s| s.to_string()),
            Some(json!({ "provider": provider })),
        );
    }

    /// Log magic link usage
    pub fn log_magic_link(
        &self,
        tenant_id: &str,
        user_id: Option<&str>,
        email: &str,
        context: Option<RequestContext>,
        action: AuditAction,
        success: bool,
        error: Option<&str>,
    ) {
        self.log(
            tenant_id,
            action,
            ResourceType::MagicLink,
            user_id.unwrap_or(email),
            user_id.map(|s| s.to_string()),
            None,
            context,
            success,
            error.map(|s| s.to_string()),
            Some(json!({ "email": email })),
        );
    }

    /// Log email verification
    pub fn log_email_verification(
        &self,
        tenant_id: &str,
        user_id: &str,
        context: Option<RequestContext>,
        success: bool,
        error: Option<&str>,
    ) {
        self.log(
            tenant_id,
            if success {
                AuditAction::EmailVerified
            } else {
                AuditAction::EmailVerificationFailed
            },
            ResourceType::Email,
            user_id,
            Some(user_id.to_string()),
            None,
            context,
            success,
            error.map(|s| s.to_string()),
            None,
        );
    }

    /// Log password reset request
    pub fn log_password_reset_requested(
        &self,
        tenant_id: &str,
        email: &str,
        context: Option<RequestContext>,
    ) {
        self.log(
            tenant_id,
            AuditAction::PasswordResetRequested,
            ResourceType::Password,
            email,
            None,
            None,
            context,
            true,
            None,
            Some(json!({ "email": email })),
        );
    }

    /// Log password reset completion
    pub fn log_password_reset(
        &self,
        tenant_id: &str,
        user_id: &str,
        context: Option<RequestContext>,
        success: bool,
        error: Option<&str>,
    ) {
        self.log(
            tenant_id,
            if success {
                AuditAction::PasswordReset
            } else {
                AuditAction::PasswordResetFailed
            },
            ResourceType::Password,
            user_id,
            Some(user_id.to_string()),
            None,
            context,
            success,
            error.map(|s| s.to_string()),
            None,
        );
    }

    /// Log WebAuthn credential registration
    pub fn log_webauthn_registered(
        &self,
        tenant_id: &str,
        user_id: &str,
        credential_id: &str,
        context: Option<RequestContext>,
        is_passkey: bool,
    ) {
        self.log(
            tenant_id,
            AuditAction::WebAuthnRegistered,
            ResourceType::WebAuthn,
            credential_id,
            Some(user_id.to_string()),
            None,
            context,
            true,
            None,
            Some(json!({
                "credential_id": credential_id,
                "is_passkey": is_passkey
            })),
        );

        // Trigger webhook
        self.trigger_webhook(
            tenant_id.to_string(),
            "webauthn.registered".to_string(),
            json!({
                "user_id": user_id,
                "credential_id": credential_id,
                "is_passkey": is_passkey,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    /// Log WebAuthn registration failure
    pub fn log_webauthn_registration_failed(
        &self,
        tenant_id: &str,
        user_id: &str,
        context: Option<RequestContext>,
        error: &str,
    ) {
        self.log(
            tenant_id,
            AuditAction::WebAuthnRegistrationFailed,
            ResourceType::WebAuthn,
            user_id,
            Some(user_id.to_string()),
            None,
            context,
            false,
            Some(error.to_string()),
            None,
        );
    }

    /// Log WebAuthn authentication success
    pub fn log_webauthn_authenticated(
        &self,
        tenant_id: &str,
        user_id: &str,
        session_id: Option<&str>,
        credential_id: &str,
        context: Option<RequestContext>,
        user_verified: bool,
    ) {
        self.log(
            tenant_id,
            AuditAction::WebAuthnAuthenticated,
            ResourceType::WebAuthn,
            credential_id,
            Some(user_id.to_string()),
            session_id.map(|s| s.to_string()),
            context.clone(),
            true,
            None,
            Some(json!({
                "credential_id": credential_id,
                "user_verified": user_verified
            })),
        );

        // Trigger webhook
        self.trigger_webhook(
            tenant_id.to_string(),
            "user.login".to_string(),
            json!({
                "id": user_id,
                "tenant_id": tenant_id,
                "credential_id": credential_id,
                "ip_address": context.as_ref().and_then(|c| c.ip_address.clone()),
                "user_agent": context.as_ref().and_then(|c| c.user_agent.clone()),
                "method": "webauthn",
                "success": true,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    /// Log WebAuthn authentication failure
    pub fn log_webauthn_authentication_failed(
        &self,
        tenant_id: &str,
        credential_id: Option<&str>,
        context: Option<RequestContext>,
        error: &str,
    ) {
        self.log(
            tenant_id,
            AuditAction::WebAuthnAuthenticationFailed,
            ResourceType::WebAuthn,
            credential_id.unwrap_or("unknown"),
            None,
            None,
            context,
            false,
            Some(error.to_string()),
            credential_id.map(|id| json!({ "credential_id": id })),
        );
    }

    /// Log WebAuthn credential deletion
    pub fn log_webauthn_credential_deleted(
        &self,
        tenant_id: &str,
        user_id: &str,
        credential_id: &str,
    ) {
        self.log(
            tenant_id,
            AuditAction::WebAuthnCredentialDeleted,
            ResourceType::WebAuthn,
            credential_id,
            Some(user_id.to_string()),
            None,
            None,
            true,
            None,
            Some(json!({ "credential_id": credential_id })),
        );
    }

    /// Log account linking
    pub fn log_account_linked(
        &self,
        tenant_id: &str,
        user_id: &str,
        provider: &str,
        provider_account_id: &str,
        context: Option<RequestContext>,
        success: bool,
        error: Option<&str>,
    ) {
        self.log(
            tenant_id,
            if success {
                AuditAction::AccountLinked
            } else {
                AuditAction::AccountLinkFailed
            },
            ResourceType::LinkedAccount,
            user_id,
            Some(user_id.to_string()),
            None,
            context.clone(),
            success,
            error.map(|s| s.to_string()),
            Some(json!({
                "provider": provider,
                "provider_account_id": provider_account_id,
            })),
        );

        if success {
            // Trigger webhook
            self.trigger_webhook(
                tenant_id.to_string(),
                "account.linked".to_string(),
                json!({
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "provider": provider,
                    "ip_address": context.as_ref().and_then(|c| c.ip_address.clone()),
                    "user_agent": context.as_ref().and_then(|c| c.user_agent.clone()),
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                }),
            );
        }
    }

    /// Log account unlinking
    pub fn log_account_unlinked(
        &self,
        tenant_id: &str,
        user_id: &str,
        provider: &str,
        context: Option<RequestContext>,
        success: bool,
        error: Option<&str>,
    ) {
        self.log(
            tenant_id,
            if success {
                AuditAction::AccountUnlinked
            } else {
                AuditAction::AccountUnlinkFailed
            },
            ResourceType::LinkedAccount,
            user_id,
            Some(user_id.to_string()),
            None,
            context.clone(),
            success,
            error.map(|s| s.to_string()),
            Some(json!({ "provider": provider })),
        );

        if success {
            // Trigger webhook
            self.trigger_webhook(
                tenant_id.to_string(),
                "account.unlinked".to_string(),
                json!({
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "provider": provider,
                    "ip_address": context.as_ref().and_then(|c| c.ip_address.clone()),
                    "user_agent": context.as_ref().and_then(|c| c.user_agent.clone()),
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                }),
            );
        }
    }

    /// Log primary account change
    pub fn log_primary_account_changed(
        &self,
        tenant_id: &str,
        user_id: &str,
        provider: &str,
        context: Option<RequestContext>,
    ) {
        self.log(
            tenant_id,
            AuditAction::PrimaryAccountChanged,
            ResourceType::LinkedAccount,
            user_id,
            Some(user_id.to_string()),
            None,
            context.clone(),
            true,
            None,
            Some(json!({ "provider": provider })),
        );

        // Trigger webhook
        self.trigger_webhook(
            tenant_id.to_string(),
            "account.primary_changed".to_string(),
            json!({
                "user_id": user_id,
                "tenant_id": tenant_id,
                "provider": provider,
                "ip_address": context.as_ref().and_then(|c| c.ip_address.clone()),
                "user_agent": context.as_ref().and_then(|c| c.user_agent.clone()),
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }

    /// Log account merge
    pub fn log_account_merged(
        &self,
        tenant_id: &str,
        source_user_id: &str,
        target_user_id: &str,
        admin_user_id: Option<&str>,
        context: Option<RequestContext>,
    ) {
        self.log(
            tenant_id,
            AuditAction::AccountMerged,
            ResourceType::User,
            target_user_id,
            admin_user_id.map(|s| s.to_string()),
            None,
            context.clone(),
            true,
            None,
            Some(json!({
                "source_user_id": source_user_id,
                "target_user_id": target_user_id,
                "merged_by": admin_user_id,
            })),
        );

        // Trigger webhook
        self.trigger_webhook(
            tenant_id.to_string(),
            "account.merged".to_string(),
            json!({
                "source_user_id": source_user_id,
                "target_user_id": target_user_id,
                "merged_by": admin_user_id,
                "tenant_id": tenant_id,
                "ip_address": context.as_ref().and_then(|c| c.ip_address.clone()),
                "user_agent": context.as_ref().and_then(|c| c.user_agent.clone()),
                "timestamp": chrono::Utc::now().to_rfc3339(),
            }),
        );
    }
}

/// Extension trait to add audit logger to AppState
pub trait AuditLoggerExt {
    fn audit(&self) -> AuditLogger;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_action_as_str() {
        assert_eq!(AuditAction::Login.as_str(), "user.login");
        assert_eq!(AuditAction::LoginFailed.as_str(), "user.login_failed");
        assert_eq!(AuditAction::Logout.as_str(), "user.logout");
        assert_eq!(AuditAction::UserCreated.as_str(), "user.created");
    }

    #[test]
    fn test_resource_type_as_str() {
        assert_eq!(ResourceType::User.as_str(), "user");
        assert_eq!(ResourceType::Session.as_str(), "session");
    }
}
