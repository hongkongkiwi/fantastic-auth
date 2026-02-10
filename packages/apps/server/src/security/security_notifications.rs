//! Security notification service
//!
//! Sends security alerts to users and tenant admins via email/SMS/WhatsApp.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use chrono::Utc;
use vault_core::auth::AuthService;
use vault_core::email::{EmailRequest, TemplateEngine};
use vault_core::email::templates::{SecurityAlertEmail, SecurityAlertType};
use vault_core::sms::OtpChannel;

use crate::audit::{AuditAction, RequestContext};
use crate::communications::TenantCommunicationResolver;
use crate::settings::models::{NotificationChannel, SecurityNotificationEvent, SecurityNotificationSettings};
use crate::settings::SettingsService;

#[derive(Clone)]
pub struct SecurityNotificationService {
    auth_service: Arc<AuthService>,
    settings_service: Arc<SettingsService>,
    communications: Arc<TenantCommunicationResolver>,
    base_url: String,
}

impl SecurityNotificationService {
    pub fn new(
        auth_service: Arc<AuthService>,
        settings_service: Arc<SettingsService>,
        communications: Arc<TenantCommunicationResolver>,
        base_url: String,
    ) -> Self {
        Self {
            auth_service,
            settings_service,
            communications,
            base_url,
        }
    }

    pub async fn notify_audit_action(
        &self,
        tenant_id: &str,
        action: AuditAction,
        user_id: Option<&str>,
        context: Option<RequestContext>,
        success: bool,
    ) {
        let Some(event) = map_action_to_event(action, success) else {
            return;
        };

        let settings = match self.settings_service.get_settings(tenant_id).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = ?e, "Failed to load settings for security notifications");
                return;
            }
        };

        let notification_settings = settings.security.notifications;

        if let Some(user_id) = user_id {
            self.notify_user_if_enabled(tenant_id, user_id, &event, &notification_settings, context.clone())
                .await;
        }

        self.notify_admins_if_enabled(tenant_id, user_id, &event, &notification_settings, context)
            .await;
    }

    async fn notify_user_if_enabled(
        &self,
        tenant_id: &str,
        user_id: &str,
        event: &SecurityNotificationEvent,
        settings: &SecurityNotificationSettings,
        context: Option<RequestContext>,
    ) {
        if !settings.user.enabled || !settings.user.events.contains(event) {
            return;
        }

        let user = match self.auth_service.db().users().find_by_id(tenant_id, user_id).await {
            Ok(Some(u)) => u,
            _ => return,
        };

        let ip: Option<String> = context.as_ref().and_then(|c| c.ip_address.as_ref().map(|s| s.to_string()));
        let user_agent: Option<String> = context.as_ref().and_then(|c| c.user_agent.as_ref().map(|s| s.to_string()));

        for channel in &settings.user.channels {
            match channel {
                NotificationChannel::Email => {
                    self.send_user_email(tenant_id, &user.email, event, ip.clone(), user_agent.clone()).await;
                }
                NotificationChannel::Sms => {
                    if let Some(phone) = self.auth_service.db().users().get_phone_number(tenant_id, user_id).await.ok().flatten() {
                        self.send_sms(tenant_id, &phone, event, NotificationRecipient::User).await;
                    }
                }
                NotificationChannel::Whatsapp => {
                    if let Some(phone) = self.auth_service.db().users().get_phone_number(tenant_id, user_id).await.ok().flatten() {
                        self.send_whatsapp(tenant_id, &phone, event, settings).await;
                    }
                }
            }
        }
    }

    async fn notify_admins_if_enabled(
        &self,
        tenant_id: &str,
        subject_user_id: Option<&str>,
        event: &SecurityNotificationEvent,
        settings: &SecurityNotificationSettings,
        context: Option<RequestContext>,
    ) {
        if !settings.admin.enabled || !settings.admin.events.contains(event) {
            return;
        }

        let admins = match self.auth_service.db().tenant_admins().list_admins(tenant_id).await {
            Ok(a) => a,
            Err(_) => return,
        };

        let mut unique_admins = HashSet::new();
        let mut admin_users = Vec::new();

        for admin in admins {
            if admin.status != "active" {
                continue;
            }
            if !settings.admin_roles.iter().any(|r| r == &admin.role) {
                continue;
            }
            if !unique_admins.insert(admin.user_id.clone()) {
                continue;
            }
            if let Ok(Some(user)) = self.auth_service.db().users().find_by_id(tenant_id, &admin.user_id).await {
                admin_users.push(user);
            }
        }

        let subject_user = if let Some(id) = subject_user_id {
            self.auth_service.db().users().find_by_id(tenant_id, id).await.ok().flatten()
        } else {
            None
        };

        let ip: Option<String> = context.as_ref().and_then(|c| c.ip_address.as_ref().map(|s| s.to_string()));
        let user_agent: Option<String> = context.as_ref().and_then(|c| c.user_agent.as_ref().map(|s| s.to_string()));

        for admin in admin_users {
            for channel in &settings.admin.channels {
                match channel {
                    NotificationChannel::Email => {
                        self.send_admin_email(tenant_id, &admin.email, event, &subject_user, ip.clone(), user_agent.clone()).await;
                    }
                    NotificationChannel::Sms => {
                        if let Ok(Some(phone)) = self.auth_service.db().users().get_phone_number(tenant_id, &admin.id).await {
                            self.send_sms(tenant_id, &phone, event, NotificationRecipient::Admin).await;
                        }
                    }
                    NotificationChannel::Whatsapp => {
                        if let Ok(Some(phone)) = self.auth_service.db().users().get_phone_number(tenant_id, &admin.id).await {
                            self.send_whatsapp(tenant_id, &phone, event, settings).await;
                        }
                    }
                }
            }
        }
    }

    async fn send_user_email(
        &self,
        tenant_id: &str,
        to: &str,
        event: &SecurityNotificationEvent,
        ip: Option<String>,
        user_agent: Option<String>,
    ) {
        let Some(sender) = self.communications.resolve_email_sender(tenant_id).await else {
            return;
        };

        if let Some(alert_type) = map_event_to_alert_type(event) {
            let template = SecurityAlertEmail {
                name: to.to_string(),
                alert_type,
                timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                ip_address: ip.unwrap_or_else(|| "Unknown".to_string()),
                location: None,
                device: user_agent.unwrap_or_else(|| "Unknown".to_string()),
            };

            let engine = TemplateEngine::new(self.base_url.clone(), sender.from_name.clone(), None);
            let rendered = match engine.render(&template) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to render security alert email");
                    return;
                }
            };

            let _ = sender
                .service
                .send_email(EmailRequest {
                    to: to.to_string(),
                    to_name: None,
                    subject: rendered.subject,
                    html_body: rendered.html_body,
                    text_body: rendered.text_body,
                    from: sender.from_address.clone(),
                    from_name: sender.from_name.clone(),
                    reply_to: sender.reply_to.clone(),
                    headers: HashMap::new(),
                })
                .await;
            return;
        }

        let subject = format!("Security alert: {}", event_label(event));
        let body = format!(
            "We detected a security event on your account: {}.\n\nIP: {}\nDevice: {}\nTime: {}\n",
            event_label(event),
            ip.unwrap_or_else(|| "Unknown".to_string()),
            user_agent.unwrap_or_else(|| "Unknown".to_string()),
            Utc::now().to_rfc3339(),
        );

        let _ = sender
            .service
            .send_email(EmailRequest {
                to: to.to_string(),
                to_name: None,
                subject,
                html_body: body.clone(),
                text_body: body,
                from: sender.from_address.clone(),
                from_name: sender.from_name.clone(),
                reply_to: sender.reply_to.clone(),
                headers: HashMap::new(),
            })
            .await;
    }

    async fn send_admin_email(
        &self,
        tenant_id: &str,
        to: &str,
        event: &SecurityNotificationEvent,
        subject_user: &Option<vault_core::models::user::User>,
        ip: Option<String>,
        user_agent: Option<String>,
    ) {
        let Some(sender) = self.communications.resolve_email_sender(tenant_id).await else {
            return;
        };

        let subject = format!("Tenant security alert: {}", event_label(event));
        let user_line = subject_user
            .as_ref()
            .map(|u| format!("User: {} ({})", u.email, u.id))
            .unwrap_or_else(|| "User: Unknown".to_string());

        let body = format!(
            "A security event was detected for your tenant.\n\n{}\nEvent: {}\nIP: {}\nDevice: {}\nTime: {}\n",
            user_line,
            event_label(event),
            ip.unwrap_or_else(|| "Unknown".to_string()),
            user_agent.unwrap_or_else(|| "Unknown".to_string()),
            Utc::now().to_rfc3339(),
        );

        let _ = sender
            .service
            .send_email(EmailRequest {
                to: to.to_string(),
                to_name: None,
                subject,
                html_body: body.clone(),
                text_body: body,
                from: sender.from_address.clone(),
                from_name: sender.from_name.clone(),
                reply_to: sender.reply_to.clone(),
                headers: HashMap::new(),
            })
            .await;
    }

    async fn send_sms(
        &self,
        tenant_id: &str,
        phone: &str,
        event: &SecurityNotificationEvent,
        recipient: NotificationRecipient,
    ) {
        let Some(sms_service) = self.communications.resolve_sms_service(tenant_id).await else {
            return;
        };

        let message = match recipient {
            NotificationRecipient::User => format!(
                "Security alert: {} on your account. If this wasn't you, reset your password.",
                event_label(event)
            ),
            NotificationRecipient::Admin => format!(
                "Tenant security alert: {}. Review audit logs for details.",
                event_label(event)
            ),
        };

        let _ = sms_service.send_message(phone, &message, OtpChannel::Sms).await;
    }

    async fn send_whatsapp(
        &self,
        tenant_id: &str,
        phone: &str,
        event: &SecurityNotificationEvent,
        settings: &SecurityNotificationSettings,
    ) {
        let Some(sms_service) = self.communications.resolve_sms_service(tenant_id).await else {
            return;
        };

        let Some(template_name) = settings.whatsapp_template_name.as_deref() else {
            return;
        };

        let message = format!("Security alert: {}", event_label(event));
        let params = vec![message];
        let _ = sms_service.send_template_message(phone, template_name, &params).await;
    }
}

#[derive(Clone, Copy)]
enum NotificationRecipient {
    User,
    Admin,
}

fn map_action_to_event(action: AuditAction, success: bool) -> Option<SecurityNotificationEvent> {
    match action {
        AuditAction::LoginFailed => Some(SecurityNotificationEvent::LoginFailed),
        AuditAction::LoginBlockedRisk => Some(SecurityNotificationEvent::LoginBlockedRisk),
        AuditAction::PasswordChange if success => Some(SecurityNotificationEvent::PasswordChanged),
        AuditAction::PasswordReset if success => Some(SecurityNotificationEvent::PasswordReset),
        AuditAction::MfaEnabled => Some(SecurityNotificationEvent::MfaEnabled),
        AuditAction::MfaDisabled => Some(SecurityNotificationEvent::MfaDisabled),
        AuditAction::SecurityPolicyUpdated => Some(SecurityNotificationEvent::SecurityPolicyUpdated),
        AuditAction::ImpersonationStarted => Some(SecurityNotificationEvent::ImpersonationStarted),
        _ => None,
    }
}

fn map_event_to_alert_type(event: &SecurityNotificationEvent) -> Option<SecurityAlertType> {
    match event {
        SecurityNotificationEvent::PasswordChanged => Some(SecurityAlertType::PasswordChanged),
        SecurityNotificationEvent::MfaEnabled => Some(SecurityAlertType::MfaEnabled),
        SecurityNotificationEvent::MfaDisabled => Some(SecurityAlertType::MfaDisabled),
        SecurityNotificationEvent::LoginFailed | SecurityNotificationEvent::LoginBlockedRisk | SecurityNotificationEvent::SuspiciousLogin => {
            Some(SecurityAlertType::SuspiciousLogin)
        }
        SecurityNotificationEvent::AccountLocked => Some(SecurityAlertType::AccountLocked),
        _ => None,
    }
}

fn event_label(event: &SecurityNotificationEvent) -> &'static str {
    match event {
        SecurityNotificationEvent::LoginFailed => "Login failed",
        SecurityNotificationEvent::LoginBlockedRisk => "Login blocked (risk)",
        SecurityNotificationEvent::PasswordChanged => "Password changed",
        SecurityNotificationEvent::PasswordReset => "Password reset",
        SecurityNotificationEvent::MfaEnabled => "MFA enabled",
        SecurityNotificationEvent::MfaDisabled => "MFA disabled",
        SecurityNotificationEvent::SuspiciousLogin => "Suspicious login",
        SecurityNotificationEvent::AccountLocked => "Account locked",
        SecurityNotificationEvent::ImpersonationStarted => "Impersonation started",
        SecurityNotificationEvent::SecurityPolicyUpdated => "Security policy updated",
    }
}
