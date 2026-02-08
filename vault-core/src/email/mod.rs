//! Email service with templating support
//!
//! Supports multiple backends: SMTP, AWS SES, SendGrid

use async_trait::async_trait;
use lettre::AsyncTransport;
use serde::Serialize;
use std::collections::HashMap;

pub mod templates;
pub mod templates_i18n;

pub use templates::EmailTemplate;
pub use templates_i18n::{EmailLanguage, I18nEmailTemplate, EmailContext, I18nVerificationEmail, I18nPasswordResetEmail};

/// Email service trait for sending transactional emails
#[async_trait]
pub trait EmailService: Send + Sync {
    /// Send an email
    async fn send_email(&self, request: EmailRequest) -> Result<(), EmailError>;

    /// Verify email service connectivity
    async fn health_check(&self) -> Result<(), EmailError>;
}

/// Trait for sending templated emails (separate from base trait for dyn compatibility)
#[async_trait]
pub trait TemplatedEmailService: EmailService {
    /// Send a templated email
    async fn send_template<T: EmailTemplate + Serialize + Send>(
        &self,
        to: String,
        template: T,
    ) -> Result<(), EmailError>;
}

/// Email request
#[derive(Debug, Clone)]
pub struct EmailRequest {
    /// Recipient email address
    pub to: String,
    /// Recipient name (optional)
    pub to_name: Option<String>,
    /// Subject line
    pub subject: String,
    /// HTML content
    pub html_body: String,
    /// Plain text content
    pub text_body: String,
    /// From address
    pub from: String,
    /// From name
    pub from_name: String,
    /// Reply-to address
    pub reply_to: Option<String>,
    /// Custom headers
    pub headers: HashMap<String, String>,
}

/// Email errors
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("SMTP error: {0}")]
    Smtp(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Template error: {0}")]
    Template(String),
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Rate limited")]
    RateLimited,
}

/// SMTP email service implementation
pub struct SmtpEmailService {
    mailer: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    /// From address for emails
    pub from_address: String,
    /// From name for emails
    pub from_name: String,
    template_engine: TemplateEngine,
}

/// Template engine for email rendering
pub struct TemplateEngine {
    /// Base URL for links
    base_url: String,
    /// Company/app name
    app_name: String,
    /// Logo URL
    logo_url: Option<String>,
}

impl TemplateEngine {
    pub fn new(base_url: String, app_name: String, logo_url: Option<String>) -> Self {
        Self {
            base_url,
            app_name,
            logo_url,
        }
    }

    /// Render a template with data
    pub fn render<T: EmailTemplate + Serialize>(
        &self,
        template: &T,
    ) -> Result<RenderedEmail, EmailError> {
        let html = template.render_html(self)?;
        let text = template.render_text(self)?;
        let subject = template.subject();

        Ok(RenderedEmail {
            subject,
            html_body: html,
            text_body: text,
        })
    }

    /// Wrap content in standard email layout
    pub fn wrap_layout(&self, title: &str, content: &str, cta: Option<(&str, &str)>) -> String {
        let logo_html = self
            .logo_url
            .as_ref()
            .map(|url| {
                format!(
                    r#"<img src="{}" alt="{}" style="max-width: 200px; margin-bottom: 24px;" />"#,
                    url, self.app_name
                )
            })
            .unwrap_or_default();

        let cta_html = cta.map(|(text, url)| format!(r#"
            <tr>
                <td style="padding: 32px 0;">
                    <a href="{}" style="background-color: #0066cc; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: 600;">{}</a>
                </td>
            </tr>
        "#, url, text)).unwrap_or_default();

        format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{}</title>
</head>
<body style="margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif; background-color: #f5f5f5;">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f5f5f5;">
        <tr>
            <td align="center" style="padding: 40px 20px;">
                <table width="600" cellpadding="0" cellspacing="0" border="0" style="background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                    <tr>
                        <td style="padding: 40px;">
                            {}
                            <h1 style="color: #1a1a1a; font-size: 24px; margin: 0 0 16px 0; font-weight: 600;">{}</h1>
                            <div style="color: #4a4a4a; font-size: 16px; line-height: 1.6;">
                                {}
                            </div>
                            {}
                            <tr>
                                <td style="padding-top: 32px; border-top: 1px solid #e5e5e5; color: #888888; font-size: 14px;">
                                    <p>If you didn't request this email, you can safely ignore it.</p>
                                    <p>&copy; {}. All rights reserved.</p>
                                </td>
                            </tr>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>"#,
            title, logo_html, title, content, cta_html, self.app_name
        )
    }
}

/// Rendered email content
pub struct RenderedEmail {
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}

impl SmtpEmailService {
    /// Create new SMTP email service
    pub fn new(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        from_address: String,
        from_name: String,
        base_url: String,
        app_name: String,
    ) -> Result<Self, EmailError> {
        let creds = lettre::transport::smtp::authentication::Credentials::new(
            username.to_string(),
            password.to_string(),
        );

        let mailer = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(host)
            .map_err(|e| EmailError::Configuration(e.to_string()))?
            .port(port)
            .credentials(creds)
            .build();

        let template_engine = TemplateEngine::new(base_url, app_name, None);

        Ok(Self {
            mailer,
            from_address,
            from_name,
            template_engine,
        })
    }

    /// Create for local development (Mailhog, etc.)
    pub fn new_local(
        host: &str,
        port: u16,
        from_address: String,
        from_name: String,
        base_url: String,
        app_name: String,
    ) -> Result<Self, EmailError> {
        let mailer = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .build();

        let template_engine = TemplateEngine::new(base_url, app_name, None);

        Ok(Self {
            mailer,
            from_address,
            from_name,
            template_engine,
        })
    }

    /// Send a templated email
    pub async fn send_template<T: EmailTemplate + Serialize + Send>(
        &self,
        to: String,
        template: T,
    ) -> Result<(), EmailError> {
        let rendered = self.template_engine.render(&template)?;

        let request = EmailRequest {
            to,
            to_name: None,
            subject: rendered.subject,
            html_body: rendered.html_body,
            text_body: rendered.text_body,
            from: self.from_address.clone(),
            from_name: self.from_name.clone(),
            reply_to: None,
            headers: HashMap::new(),
        };

        self.send_email(request).await
    }
}

#[async_trait]
impl EmailService for SmtpEmailService {
    async fn send_email(&self, request: EmailRequest) -> Result<(), EmailError> {
        let from = lettre::message::Mailbox::new(
            Some(request.from_name),
            request
                .from
                .parse()
                .map_err(|e| EmailError::Configuration(format!("Invalid from address: {}", e)))?,
        );

        let to = lettre::message::Mailbox::new(
            request.to_name,
            request
                .to
                .parse()
                .map_err(|e| EmailError::Configuration(format!("Invalid to address: {}", e)))?,
        );

        let mut email_builder = lettre::Message::builder()
            .from(from)
            .to(to)
            .subject(request.subject);

        if let Some(reply_to) = request.reply_to {
            email_builder = email_builder.reply_to(
                reply_to
                    .parse()
                    .map_err(|e| EmailError::Configuration(format!("Invalid reply-to: {}", e)))?,
            );
        }

        // TODO: Add custom headers when lettre supports it
        // for (key, value) in request.headers {
        //     email_builder = email_builder.header(...);
        // }

        let email = email_builder
            .multipart(
                lettre::message::MultiPart::alternative()
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(lettre::message::header::ContentType::TEXT_PLAIN)
                            .body(request.text_body),
                    )
                    .singlepart(
                        lettre::message::SinglePart::builder()
                            .header(lettre::message::header::ContentType::TEXT_HTML)
                            .body(request.html_body),
                    ),
            )
            .map_err(|e| EmailError::SendFailed(e.to_string()))?;

        self.mailer
            .send(email)
            .await
            .map_err(|e| EmailError::SendFailed(e.to_string()))?;

        Ok(())
    }

    async fn health_check(&self) -> Result<(), EmailError> {
        // Try to connect to SMTP server
        // For now, just return Ok as lettre doesn't expose a simple health check
        Ok(())
    }
}

/// Mock email service for testing
pub struct MockEmailService {
    pub sent_emails: std::sync::Arc<tokio::sync::Mutex<Vec<EmailRequest>>>,
}

impl MockEmailService {
    pub fn new() -> Self {
        Self {
            sent_emails: std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    pub async fn get_sent_emails(&self) -> Vec<EmailRequest> {
        self.sent_emails.lock().await.clone()
    }

    /// Send a templated email
    pub async fn send_template<T: EmailTemplate + Serialize + Send>(
        &self,
        to: String,
        template: T,
    ) -> Result<(), EmailError> {
        // Just record that a template email was sent
        let request = EmailRequest {
            to,
            to_name: None,
            subject: template.subject(),
            html_body: "[Template HTML]".to_string(),
            text_body: "[Template Text]".to_string(),
            from: "test@example.com".to_string(),
            from_name: "Test".to_string(),
            reply_to: None,
            headers: HashMap::new(),
        };
        self.sent_emails.lock().await.push(request);
        Ok(())
    }
}

#[async_trait]
impl EmailService for MockEmailService {
    async fn send_email(&self, request: EmailRequest) -> Result<(), EmailError> {
        self.sent_emails.lock().await.push(request);
        Ok(())
    }

    async fn health_check(&self) -> Result<(), EmailError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct TestTemplate {
        name: String,
    }

    impl EmailTemplate for TestTemplate {
        fn subject(&self) -> String {
            format!("Hello, {}!", self.name)
        }

        fn render_html(&self, _engine: &TemplateEngine) -> Result<String, EmailError> {
            Ok(format!("<p>Hello, {}!</p>", self.name))
        }

        fn render_text(&self, _engine: &TemplateEngine) -> Result<String, EmailError> {
            Ok(format!("Hello, {}!", self.name))
        }
    }

    #[tokio::test]
    async fn test_mock_email_service() {
        let service = MockEmailService::new();

        let template = TestTemplate {
            name: "Alice".to_string(),
        };

        service
            .send_template("alice@example.com".to_string(), template)
            .await
            .unwrap();

        let emails = service.get_sent_emails().await;
        assert_eq!(emails.len(), 1);
        assert_eq!(emails[0].to, "alice@example.com");
        assert_eq!(emails[0].subject, "Hello, Alice!");
    }
}
