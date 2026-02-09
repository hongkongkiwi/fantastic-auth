//! Email templates for authentication and user management

use super::{EmailError, TemplateEngine};
use serde::Serialize;

/// Trait for email templates
pub trait EmailTemplate {
    /// Get the email subject
    fn subject(&self) -> String;

    /// Render HTML version
    fn render_html(&self, engine: &TemplateEngine) -> Result<String, EmailError>;

    /// Render plain text version
    fn render_text(&self, engine: &TemplateEngine) -> Result<String, EmailError>;
}

/// Email verification template
#[derive(Serialize)]
pub struct VerificationEmail {
    /// User's name
    pub name: String,
    /// Verification URL
    pub verification_url: String,
    /// Expiry time in hours
    pub expires_in_hours: i32,
}

impl EmailTemplate for VerificationEmail {
    fn subject(&self) -> String {
        "Verify your email address".to_string()
    }

    fn render_html(&self, engine: &TemplateEngine) -> Result<String, EmailError> {
        let content = format!(
            r#"<p>Hi {},</p>
            <p>Thanks for signing up! Please verify your email address by clicking the button below. This link will expire in {} hours.</p>
            <p>If you didn't create an account, you can safely ignore this email.</p>"#,
            self.name, self.expires_in_hours
        );

        Ok(engine.wrap_layout(
            "Verify Your Email",
            &content,
            Some(("Verify Email", &self.verification_url)),
        ))
    }

    fn render_text(&self, _engine: &TemplateEngine) -> Result<String, EmailError> {
        Ok(format!(
            r#"Hi {},

Thanks for signing up! Please verify your email address by visiting the link below:

{}

This link will expire in {} hours.

If you didn't create an account, you can safely ignore this email."#,
            self.name, self.verification_url, self.expires_in_hours
        ))
    }
}

impl VerificationEmail {
    /// Simple HTML rendering without template engine
    pub fn render_html_simple(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <h1>Verify Your Email</h1>
    <p>Hi {},</p>
    <p>Thanks for signing up! Please verify your email address by clicking the link below:</p>
    <p><a href="{}" style="background: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Verify Email</a></p>
    <p>Or copy and paste this link: {}</p>
    <p>This link will expire in {} hours.</p>
    <p>If you didn't create an account, you can safely ignore this email.</p>
</body>
</html>"#,
            self.name, self.verification_url, self.verification_url, self.expires_in_hours
        )
    }

    /// Simple text rendering
    pub fn render_text_simple(&self) -> String {
        format!(
            r#"Hi {},

Thanks for signing up! Please verify your email address by visiting the link below:

{}

This link will expire in {} hours.

If you didn't create an account, you can safely ignore this email."#,
            self.name, self.verification_url, self.expires_in_hours
        )
    }
}

/// Password reset template
#[derive(Serialize)]
pub struct PasswordResetEmail {
    /// User's name
    pub name: String,
    /// Reset URL
    pub reset_url: String,
    /// Expiry time in hours
    pub expires_in_hours: i32,
}

impl EmailTemplate for PasswordResetEmail {
    fn subject(&self) -> String {
        "Reset your password".to_string()
    }

    fn render_html(&self, engine: &TemplateEngine) -> Result<String, EmailError> {
        let content = format!(
            r#"<p>Hi {},</p>
            <p>We received a request to reset your password. Click the button below to create a new password. This link will expire in {} hours.</p>
            <p>If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>"#,
            self.name, self.expires_in_hours
        );

        Ok(engine.wrap_layout(
            "Reset Your Password",
            &content,
            Some(("Reset Password", &self.reset_url)),
        ))
    }

    fn render_text(&self, _engine: &TemplateEngine) -> Result<String, EmailError> {
        Ok(format!(
            r#"Hi {},

We received a request to reset your password. Click the link below to create a new password:

{}

This link will expire in {} hours.

If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged."#,
            self.name, self.reset_url, self.expires_in_hours
        ))
    }
}

impl PasswordResetEmail {
    /// Simple HTML rendering
    pub fn render_html_simple(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <h1>Reset Your Password</h1>
    <p>Hi {},</p>
    <p>We received a request to reset your password. Click the link below to create a new password:</p>
    <p><a href="{}" style="background: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Reset Password</a></p>
    <p>Or copy and paste this link: {}</p>
    <p>This link will expire in {} hours.</p>
    <p>If you didn't request a password reset, you can safely ignore this email.</p>
</body>
</html>"#,
            self.name, self.reset_url, self.reset_url, self.expires_in_hours
        )
    }

    /// Simple text rendering
    pub fn render_text_simple(&self) -> String {
        format!(
            r#"Hi {},

We received a request to reset your password. Click the link below to create a new password:

{}

This link will expire in {} hours.

If you didn't request a password reset, you can safely ignore this email."#,
            self.name, self.reset_url, self.expires_in_hours
        )
    }
}

/// Magic link login template
#[derive(Serialize)]
pub struct MagicLinkEmail {
    /// User's name
    pub name: String,
    /// Magic login URL
    pub login_url: String,
    /// Expiry time in minutes
    pub expires_in_minutes: i32,
}

impl EmailTemplate for MagicLinkEmail {
    fn subject(&self) -> String {
        "Your magic link to sign in".to_string()
    }

    fn render_html(&self, engine: &TemplateEngine) -> Result<String, EmailError> {
        let content = format!(
            r#"<p>Hi {},</p>
            <p>Click the button below to sign in to your account. This link will expire in {} minutes and can only be used once.</p>
            <p>If you didn't request this link, you can safely ignore this email.</p>"#,
            self.name, self.expires_in_minutes
        );

        Ok(engine.wrap_layout(
            "Sign In to Your Account",
            &content,
            Some(("Sign In", &self.login_url)),
        ))
    }

    fn render_text(&self, _engine: &TemplateEngine) -> Result<String, EmailError> {
        Ok(format!(
            r#"Hi {},

Click the link below to sign in to your account:

{}

This link will expire in {} minutes and can only be used once.

If you didn't request this link, you can safely ignore this email."#,
            self.name, self.login_url, self.expires_in_minutes
        ))
    }
}

impl MagicLinkEmail {
    /// Simple HTML rendering
    pub fn render_html_simple(&self) -> String {
        format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
    <h1>Sign In to Your Account</h1>
    <p>Hi {},</p>
    <p>Click the link below to sign in to your account:</p>
    <p><a href="{}" style="background: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Sign In</a></p>
    <p>Or copy and paste this link: {}</p>
    <p>This link will expire in {} minutes and can only be used once.</p>
    <p>If you didn't request this link, you can safely ignore this email.</p>
</body>
</html>"#,
            self.name, self.login_url, self.login_url, self.expires_in_minutes
        )
    }

    /// Simple text rendering
    pub fn render_text_simple(&self) -> String {
        format!(
            r#"Hi {},

Click the link below to sign in to your account:

{}

This link will expire in {} minutes and can only be used once.

If you didn't request this link, you can safely ignore this email."#,
            self.name, self.login_url, self.expires_in_minutes
        )
    }
}

/// Organization invitation template
#[derive(Serialize)]
pub struct OrganizationInvitationEmail {
    /// Invitee's name
    pub invitee_name: String,
    /// Organization name
    pub organization_name: String,
    /// Inviter's name
    pub inviter_name: String,
    /// Invitation URL
    pub invitation_url: String,
    /// Role being offered
    pub role: String,
    /// Expiry time in days
    pub expires_in_days: i32,
}

impl EmailTemplate for OrganizationInvitationEmail {
    fn subject(&self) -> String {
        format!("You've been invited to join {}", self.organization_name)
    }

    fn render_html(&self, engine: &TemplateEngine) -> Result<String, EmailError> {
        let content = format!(
            r#"<p>Hi {},</p>
            <p><strong>{}</strong> has invited you to join <strong>{}</strong> as a <strong>{}</strong>.</p>
            <p>Click the button below to accept the invitation. This link will expire in {} days.</p>"#,
            self.invitee_name,
            self.inviter_name,
            self.organization_name,
            self.role,
            self.expires_in_days
        );

        Ok(engine.wrap_layout(
            &format!("Join {}", self.organization_name),
            &content,
            Some(("Accept Invitation", &self.invitation_url)),
        ))
    }

    fn render_text(&self, _engine: &TemplateEngine) -> Result<String, EmailError> {
        Ok(format!(
            r#"Hi {},

{} has invited you to join {} as a {}.

Click the link below to accept the invitation:

{}

This link will expire in {} days."#,
            self.invitee_name,
            self.inviter_name,
            self.organization_name,
            self.role,
            self.invitation_url,
            self.expires_in_days
        ))
    }
}

/// MFA backup codes template
#[derive(Serialize)]
pub struct BackupCodesEmail {
    /// User's name
    pub name: String,
    /// Backup codes (should be displayed securely)
    pub backup_codes: Vec<String>,
}

impl EmailTemplate for BackupCodesEmail {
    fn subject(&self) -> String {
        "Your backup codes".to_string()
    }

    fn render_html(&self, engine: &TemplateEngine) -> Result<String, EmailError> {
        let codes_html = self.backup_codes
            .iter()
            .map(|code| format!("<code style='background: #f4f4f4; padding: 4px 8px; margin: 2px; display: inline-block; font-family: monospace;'>{}</code>", code))
            .collect::<Vec<_>>()
            .join(" ");

        let content = format!(
            r#"<p>Hi {},</p>
            <p>You've enabled two-factor authentication on your account. Here are your backup codes:</p>
            <div style="background: #f9f9f9; border: 1px solid #e5e5e5; padding: 16px; margin: 16px 0; border-radius: 4px;">
                {}
            </div>
            <p><strong>Important:</strong> Save these codes in a secure place. Each code can only be used once. If you lose access to your authenticator app, you'll need these codes to sign in.</p>
            <p>Never share these codes with anyone.</p>"#,
            self.name, codes_html
        );

        Ok(engine.wrap_layout("Your Backup Codes", &content, None))
    }

    fn render_text(&self, _engine: &TemplateEngine) -> Result<String, EmailError> {
        let codes_text = self.backup_codes.join("\n");

        Ok(format!(
            r#"Hi {},

You've enabled two-factor authentication on your account. Here are your backup codes:

{}

IMPORTANT: Save these codes in a secure place. Each code can only be used once. 
If you lose access to your authenticator app, you'll need these codes to sign in.

Never share these codes with anyone."#,
            self.name, codes_text
        ))
    }
}

/// Security alert template
#[derive(Serialize)]
pub struct SecurityAlertEmail {
    /// User's name
    pub name: String,
    /// Type of alert
    pub alert_type: SecurityAlertType,
    /// Timestamp of the event
    pub timestamp: String,
    /// IP address
    pub ip_address: String,
    /// Location (if available)
    pub location: Option<String>,
    /// Device info
    pub device: String,
}

/// Types of security alerts
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityAlertType {
    NewDevice,
    PasswordChanged,
    EmailChanged,
    MfaEnabled,
    MfaDisabled,
    SuspiciousLogin,
    AccountLocked,
}

impl SecurityAlertType {
    fn title(&self) -> &'static str {
        match self {
            SecurityAlertType::NewDevice => "New Device Sign In",
            SecurityAlertType::PasswordChanged => "Password Changed",
            SecurityAlertType::EmailChanged => "Email Address Changed",
            SecurityAlertType::MfaEnabled => "Two-Factor Authentication Enabled",
            SecurityAlertType::MfaDisabled => "Two-Factor Authentication Disabled",
            SecurityAlertType::SuspiciousLogin => "Suspicious Login Attempt",
            SecurityAlertType::AccountLocked => "Account Temporarily Locked",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            SecurityAlertType::NewDevice => {
                "We noticed a sign in to your account from a new device."
            }
            SecurityAlertType::PasswordChanged => "Your password was recently changed.",
            SecurityAlertType::EmailChanged => "Your email address was recently changed.",
            SecurityAlertType::MfaEnabled => {
                "Two-factor authentication was enabled on your account."
            }
            SecurityAlertType::MfaDisabled => {
                "Two-factor authentication was disabled on your account."
            }
            SecurityAlertType::SuspiciousLogin => {
                "We detected a suspicious login attempt on your account."
            }
            SecurityAlertType::AccountLocked => {
                "Your account has been temporarily locked due to multiple failed sign-in attempts."
            }
        }
    }
}

impl EmailTemplate for SecurityAlertEmail {
    fn subject(&self) -> String {
        format!("Security alert: {}", self.alert_type.title())
    }

    fn render_html(&self, engine: &TemplateEngine) -> Result<String, EmailError> {
        let location_info = self
            .location
            .as_ref()
            .map(|loc| format!("<p><strong>Location:</strong> {}</p>", loc))
            .unwrap_or_default();

        let link_html = "<a href=\"#\">secure your account</a>";
        let content = format!(
            r#"<p>Hi {},</p>
            <p>{}</p>
            <div style="background: #f9f9f9; border: 1px solid #e5e5e5; padding: 16px; margin: 16px 0; border-radius: 4px;">
                <p><strong>Time:</strong> {}</p>
                <p><strong>IP Address:</strong> {}</p>
                {}
                <p><strong>Device:</strong> {}</p>
            </div>
            <p>If this was you, you can ignore this email. If you don't recognize this activity, please {} immediately.</p>"#,
            self.name,
            self.alert_type.description(),
            self.timestamp,
            self.ip_address,
            location_info,
            self.device,
            link_html
        );

        Ok(engine.wrap_layout(self.alert_type.title(), &content, None))
    }

    fn render_text(&self, _engine: &TemplateEngine) -> Result<String, EmailError> {
        let location_info = self
            .location
            .as_ref()
            .map(|loc| format!("Location: {}\n", loc))
            .unwrap_or_default();

        Ok(format!(
            r#"Hi {},

{}

Time: {}
IP Address: {}
{}Device: {}

If this was you, you can ignore this email. If you don't recognize this activity, please secure your account immediately."#,
            self.name,
            self.alert_type.description(),
            self.timestamp,
            self.ip_address,
            location_info,
            self.device
        ))
    }
}

/// Welcome email template
#[derive(Serialize)]
pub struct WelcomeEmail {
    /// User's name
    pub name: String,
    /// Dashboard/login URL
    pub login_url: String,
    /// Documentation/getting started URL
    pub docs_url: Option<String>,
}

impl EmailTemplate for WelcomeEmail {
    fn subject(&self) -> String {
        "Welcome to your account!".to_string()
    }

    fn render_html(&self, engine: &TemplateEngine) -> Result<String, EmailError> {
        let docs_section = self.docs_url.as_ref()
            .map(|url| format!("<p>Need help getting started? Check out our <a href='{}'>documentation</a>.</p>", url))
            .unwrap_or_default();

        let content = format!(
            r#"<p>Hi {},</p>
            <p>Welcome! Your account has been created successfully. We're excited to have you on board.</p>
            {}
            <p>If you have any questions, feel free to reach out to our support team.</p>"#,
            self.name, docs_section
        );

        Ok(engine.wrap_layout(
            "Welcome!",
            &content,
            Some(("Go to Dashboard", &self.login_url)),
        ))
    }

    fn render_text(&self, _engine: &TemplateEngine) -> Result<String, EmailError> {
        let docs_section = self
            .docs_url
            .as_ref()
            .map(|url| {
                format!(
                    "Need help getting started? Check out our documentation: {}\n\n",
                    url
                )
            })
            .unwrap_or_default();

        Ok(format!(
            r#"Hi {},

Welcome! Your account has been created successfully. We're excited to have you on board.

{}{}
If you have any questions, feel free to reach out to our support team."#,
            self.name, docs_section, self.login_url
        ))
    }
}

/// New device detection email template
/// Sent when a login is detected from a new device/location
#[derive(Serialize)]
pub struct NewDeviceEmail {
    /// User's name
    pub name: String,
    /// Device description (e.g., "Chrome on Windows")
    pub device: String,
    /// Location (city, country)
    pub location: Option<String>,
    /// IP address
    pub ip_address: String,
    /// Timestamp
    pub timestamp: String,
    /// URL to trust/verify this device
    pub trust_url: String,
    /// URL to revoke the session
    pub revoke_url: String,
}

impl EmailTemplate for NewDeviceEmail {
    fn subject(&self) -> String {
        "New device signed in to your account".to_string()
    }

    fn render_html(&self, engine: &TemplateEngine) -> Result<String, EmailError> {
        let location_html = self
            .location
            .as_ref()
            .map(|loc| format!("<p><strong>Location:</strong> {}</p>", loc))
            .unwrap_or_default();

        let content = format!(
            r#"<p>Hi {},</p>
            <p>We noticed a new device signed in to your account:</p>
            <div style="background: #f9f9f9; border: 1px solid #e5e5e5; padding: 16px; margin: 16px 0; border-radius: 4px;">
                <p><strong>Device:</strong> {}</p>
                <p><strong>Time:</strong> {}</p>
                <p><strong>IP Address:</strong> {}</p>
                {}
            </div>
            <p><strong>Was this you?</strong></p>
            <p>
                <a href="{}" style="background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; margin-right: 10px;">Yes, Trust This Device</a>
                <a href="{}" style="background: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">No, Revoke Access</a>
            </p>
            <p style="color: #666; font-size: 14px; margin-top: 24px;">
                If the buttons don't work, copy and paste these links:<br>
                Trust: {}<br>
                Revoke: {}
            </p>"#,
            self.name,
            self.device,
            self.timestamp,
            self.ip_address,
            location_html,
            self.trust_url,
            self.revoke_url,
            self.trust_url,
            self.revoke_url
        );

        Ok(engine.wrap_layout("New Device Sign In", &content, None))
    }

    fn render_text(&self, _engine: &TemplateEngine) -> Result<String, EmailError> {
        let location_text = self
            .location
            .as_ref()
            .map(|loc| format!("Location: {}\n", loc))
            .unwrap_or_default();

        Ok(format!(
            r#"Hi {},

We noticed a new device signed in to your account:

Device: {}
Time: {}
IP Address: {}
{}
Was this you?

If this was you, trust this device:
{}

If you don't recognize this activity, revoke access immediately:
{}

If the links don't work, copy and paste them into your browser."#,
            self.name,
            self.device,
            self.timestamp,
            self.ip_address,
            location_text,
            self.trust_url,
            self.revoke_url
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> TemplateEngine {
        TemplateEngine::new(
            "https://app.example.com".to_string(),
            "Test App".to_string(),
            None,
        )
    }

    #[test]
    fn test_verification_email() {
        let engine = test_engine();
        let email = VerificationEmail {
            name: "Alice".to_string(),
            verification_url: "https://app.example.com/verify?token=abc123".to_string(),
            expires_in_hours: 24,
        };

        assert_eq!(email.subject(), "Verify your email address");

        let html = email.render_html(&engine).unwrap();
        assert!(html.contains("Verify Your Email"));
        assert!(html.contains("Alice"));
        assert!(html.contains("https://app.example.com/verify?token=abc123"));

        let text = email.render_text(&engine).unwrap();
        assert!(text.contains("Alice"));
        assert!(text.contains("https://app.example.com/verify?token=abc123"));
    }

    #[test]
    fn test_password_reset_email() {
        let engine = test_engine();
        let email = PasswordResetEmail {
            name: "Bob".to_string(),
            reset_url: "https://app.example.com/reset?token=xyz789".to_string(),
            expires_in_hours: 1,
        };

        assert_eq!(email.subject(), "Reset your password");

        let html = email.render_html(&engine).unwrap();
        assert!(html.contains("Reset Your Password"));
    }

    #[test]
    fn test_magic_link_email() {
        let engine = test_engine();
        let email = MagicLinkEmail {
            name: "Charlie".to_string(),
            login_url: "https://app.example.com/magic?token=magic123".to_string(),
            expires_in_minutes: 15,
        };

        assert_eq!(email.subject(), "Your magic link to sign in");
    }

    #[test]
    fn test_organization_invitation_email() {
        let engine = test_engine();
        let email = OrganizationInvitationEmail {
            invitee_name: "David".to_string(),
            organization_name: "Acme Corp".to_string(),
            inviter_name: "Eve".to_string(),
            invitation_url: "https://app.example.com/invite?token=invite456".to_string(),
            role: "Member".to_string(),
            expires_in_days: 7,
        };

        assert_eq!(email.subject(), "You've been invited to join Acme Corp");
    }
}
