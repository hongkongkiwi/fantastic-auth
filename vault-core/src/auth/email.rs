//! Email sending utilities
//!
//! Supports transactional emails for:
//! - Email verification
//! - Password reset
//! - Magic links
//! - MFA OTP
//! - Security alerts

use crate::error::{Result, VaultError};

/// Email template types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailTemplate {
    /// Email address verification
    Verification,
    /// Password reset
    PasswordReset,
    /// Magic link for passwordless login
    MagicLink,
    /// MFA OTP code
    MfaOtp,
    /// Security alert (new login, password changed, etc.)
    SecurityAlert,
    /// Welcome email
    Welcome,
    /// Organization invitation
    OrgInvitation,
}

impl EmailTemplate {
    /// Get template subject
    pub fn subject(&self) -> &'static str {
        match self {
            EmailTemplate::Verification => "Verify your email address",
            EmailTemplate::PasswordReset => "Reset your password",
            EmailTemplate::MagicLink => "Your magic link to sign in",
            EmailTemplate::MfaOtp => "Your verification code",
            EmailTemplate::SecurityAlert => "Security alert",
            EmailTemplate::Welcome => "Welcome to Vault",
            EmailTemplate::OrgInvitation => "You've been invited to join an organization",
        }
    }
}

/// Email data for templating
#[derive(Debug, Clone, Default)]
pub struct EmailData {
    /// Recipient name
    pub name: Option<String>,
    /// Recipient email
    pub email: String,
    /// Verification/reset token
    pub token: Option<String>,
    /// Magic link URL
    pub magic_link: Option<String>,
    /// OTP code
    pub otp_code: Option<String>,
    /// Organization name (for invitations)
    pub org_name: Option<String>,
    /// Organization invitation link
    pub invitation_link: Option<String>,
    /// IP address (for security alerts)
    pub ip_address: Option<String>,
    /// Device info (for security alerts)
    pub device_info: Option<String>,
    /// Timestamp (for security alerts)
    pub timestamp: Option<String>,
    /// Action taken (for security alerts)
    pub action: Option<String>,
}

/// Email sender trait
#[async_trait::async_trait]
pub trait EmailSender: Send + Sync {
    /// Send email
    async fn send(&self, to: &str, subject: &str, html: &str, text: &str) -> Result<()>;
}

/// SMTP email sender
pub struct SmtpSender {
    // SMTP configuration
    host: String,
    port: u16,
    username: String,
    password: String,
    from_address: String,
    from_name: String,
}

impl SmtpSender {
    /// Create new SMTP sender
    pub fn new(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
        from_address: impl Into<String>,
        from_name: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            username: username.into(),
            password: password.into(),
            from_address: from_address.into(),
            from_name: from_name.into(),
        }
    }
}

#[async_trait::async_trait]
impl EmailSender for SmtpSender {
    async fn send(&self, _to: &str, _subject: &str, _html: &str, _text: &str) -> Result<()> {
        // SMTP implementation requires the lettre crate
        // For now, this is a placeholder - integrate lettre when ready
        tracing::warn!("SMTP email sending not implemented - lettre integration needed");
        Ok(())
    }
}

/// Mock email sender for testing
#[derive(Clone)]
pub struct MockSender {
    sent_emails: std::sync::Arc<tokio::sync::Mutex<Vec<(String, String, String)>>>,
}

impl MockSender {
    /// Create new mock sender
    pub fn new() -> Self {
        Self {
            sent_emails: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    /// Get sent emails
    pub async fn get_sent_emails(&self) -> Vec<(String, String, String)> {
        self.sent_emails.lock().await.clone()
    }

    /// Clear sent emails
    pub async fn clear(&self) {
        self.sent_emails.lock().await.clear();
    }
}

#[async_trait::async_trait]
impl EmailSender for MockSender {
    async fn send(&self, to: &str, subject: &str, html: &str, _text: &str) -> Result<()> {
        self.sent_emails
            .lock()
            .await
            .push((to.to_string(), subject.to_string(), html.to_string()));
        Ok(())
    }
}

/// Email service
pub struct EmailService {
    sender: Box<dyn EmailSender>,
    base_url: String,
}

impl EmailService {
    /// Create new email service
    pub fn new(sender: Box<dyn EmailSender>, base_url: impl Into<String>) -> Self {
        Self {
            sender,
            base_url: base_url.into(),
        }
    }

    /// Send verification email
    pub async fn send_verification(&self, data: EmailData) -> Result<()> {
        let token = data
            .token
            .ok_or_else(|| VaultError::validation("Token required"))?;
        let verify_url = format!("{}/verify-email?token={}", self.base_url, token);

        let html = format!(
            r#"
            <h1>Verify your email address</h1>
            <p>Hi {},</p>
            <p>Please click the link below to verify your email address:</p>
            <p><a href="{}" style="padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
            <p>Or copy and paste this link: {}</p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't create an account, you can safely ignore this email.</p>
            "#,
            data.name.as_deref().unwrap_or("there"),
            verify_url,
            verify_url
        );

        let text = format!(
            "Verify your email address\n\nHi {},\n\nPlease visit this link to verify your email:\n{}\n\nThis link will expire in 24 hours.",
            data.name.as_deref().unwrap_or("there"),
            verify_url
        );

        self.sender
            .send(
                &data.email,
                EmailTemplate::Verification.subject(),
                &html,
                &text,
            )
            .await
    }

    /// Send password reset email
    pub async fn send_password_reset(&self, data: EmailData) -> Result<()> {
        let token = data
            .token
            .ok_or_else(|| VaultError::validation("Token required"))?;
        let reset_url = format!("{}/reset-password?token={}", self.base_url, token);

        let html = format!(
            r#"
            <h1>Reset your password</h1>
            <p>Hi {},</p>
            <p>We received a request to reset your password. Click the link below to set a new password:</p>
            <p><a href="{}" style="padding: 10px 20px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
            <p>Or copy and paste this link: {}</p>
            <p>This link will expire in 1 hour.</p>
            <p>If you didn't request this, you can safely ignore this email.</p>
            "#,
            data.name.as_deref().unwrap_or("there"),
            reset_url,
            reset_url
        );

        let text = format!(
            "Reset your password\n\nHi {},\n\nVisit this link to reset your password:\n{}\n\nThis link will expire in 1 hour.",
            data.name.as_deref().unwrap_or("there"),
            reset_url
        );

        self.sender
            .send(
                &data.email,
                EmailTemplate::PasswordReset.subject(),
                &html,
                &text,
            )
            .await
    }

    /// Send magic link email
    pub async fn send_magic_link(&self, data: EmailData) -> Result<()> {
        let link = data
            .magic_link
            .ok_or_else(|| VaultError::validation("Magic link required"))?;

        let html = format!(
            r#"
            <h1>Sign in to Vault</h1>
            <p>Hi {},</p>
            <p>Click the link below to sign in (no password needed):</p>
            <p><a href="{}" style="padding: 10px 20px; background: #28a745; color: white; text-decoration: none; border-radius: 5px;">Sign In</a></p>
            <p>Or copy and paste this link: {}</p>
            <p>This link will expire in 15 minutes and can only be used once.</p>
            <p>If you didn't request this, you can safely ignore this email.</p>
            "#,
            data.name.as_deref().unwrap_or("there"),
            link,
            link
        );

        let text = format!(
            "Sign in to Vault\n\nHi {},\n\nVisit this link to sign in:\n{}\n\nThis link expires in 15 minutes.",
            data.name.as_deref().unwrap_or("there"),
            link
        );

        self.sender
            .send(
                &data.email,
                EmailTemplate::MagicLink.subject(),
                &html,
                &text,
            )
            .await
    }

    /// Send MFA OTP email
    pub async fn send_mfa_otp(&self, data: EmailData) -> Result<()> {
        let code = data
            .otp_code
            .ok_or_else(|| VaultError::validation("OTP code required"))?;

        let html = format!(
            r#"
            <h1>Your verification code</h1>
            <p>Hi {},</p>
            <p>Your verification code is:</p>
            <h2 style="font-size: 32px; letter-spacing: 5px; background: #f8f9fa; padding: 15px; text-align: center; border-radius: 5px;">{}</h2>
            <p>This code will expire in 10 minutes.</p>
            <p>If you didn't request this code, someone may be trying to access your account.</p>
            "#,
            data.name.as_deref().unwrap_or("there"),
            code
        );

        let text = format!(
            "Your verification code\n\nHi {},\n\nYour code is: {}\n\nThis code expires in 10 minutes.",
            data.name.as_deref().unwrap_or("there"),
            code
        );

        self.sender
            .send(&data.email, EmailTemplate::MfaOtp.subject(), &html, &text)
            .await
    }

    /// Send security alert
    pub async fn send_security_alert(&self, data: EmailData) -> Result<()> {
        let action = data.action.unwrap_or_else(|| "activity".to_string());
        let ip = data.ip_address.as_deref().unwrap_or("unknown");
        let device = data.device_info.as_deref().unwrap_or("unknown device");
        let time = data.timestamp.unwrap_or_else(|| "recently".to_string());

        let html = format!(
            r#"
            <h1>Security Alert</h1>
            <p>Hi {},</p>
            <p>We detected {} on your account:</p>
            <ul>
                <li><strong>Time:</strong> {}</li>
                <li><strong>IP Address:</strong> {}</li>
                <li><strong>Device:</strong> {}</li>
            </ul>
            <p>If this was you, you can ignore this email.</p>
            <p>If you didn't do this, please change your password immediately and review your account security.</p>
            "#,
            data.name.as_deref().unwrap_or("there"),
            action,
            time,
            ip,
            device
        );

        let text = format!(
            "Security Alert\n\nHi {},\n\nWe detected {} on your account:\n\nTime: {}\nIP: {}\nDevice: {}\n\nIf this wasn't you, change your password immediately.",
            data.name.as_deref().unwrap_or("there"),
            action,
            time,
            ip,
            device
        );

        self.sender
            .send(
                &data.email,
                EmailTemplate::SecurityAlert.subject(),
                &html,
                &text,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_sender() {
        let sender = MockSender::new();
        let service = EmailService::new(Box::new(sender.clone()), "https://example.com");

        let data = EmailData {
            email: "test@example.com".to_string(),
            name: Some("Test User".to_string()),
            token: Some("abc123".to_string()),
            ..Default::default()
        };

        service.send_verification(data).await.unwrap();

        let emails = sender.get_sent_emails().await;
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0].0, "test@example.com");
        assert!(emails[0].1.contains("Verify"));
    }
}
