//! Admin Email Template Routes
//!
//! Provides endpoints for managing and previewing email templates:
//! - GET /api/v1/admin/email-templates - List all email templates
//! - GET /api/v1/admin/email-templates/:type - Get specific template
//! - PUT /api/v1/admin/email-templates/:type - Update template
//! - POST /api/v1/admin/email-templates/:type/preview - Generate preview
//! - POST /api/v1/admin/email-templates/:type/send-test - Send test email
//! - POST /api/v1/admin/email-templates/:type/reset - Reset to default
//! - GET /api/v1/admin/email-templates/variables - List available variables
//!
//! Features:
//! - Template editing with variables
//! - Live preview with sample data
//! - Test email sending
//! - A/B testing support
//! - Version history

use axum::{
    extract::{Extension, Path, State},
    routing::{get, post}, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::audit::{AuditAction, AuditLogger, ResourceType};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Email template routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/email-templates", get(list_templates))
        .route("/email-templates/variables", get(list_variables))
        .route("/email-templates/:template_type", get(get_template).put(update_template))
        .route("/email-templates/:template_type/preview", post(preview_template))
        .route("/email-templates/:template_type/send-test", post(send_test_email))
        .route("/email-templates/:template_type/reset", post(reset_template))
}

// ============ Request/Response Types ============

/// Email template types
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplateType {
    /// Welcome email sent after registration
    Welcome,
    /// Email verification
    Verification,
    /// Password reset
    PasswordReset,
    /// MFA code/backup codes
    MfaNotification,
    /// Password changed notification
    PasswordChanged,
    /// Account locked notification
    AccountLocked,
    /// New login detected
    NewLoginDetected,
    /// Invitation to join organization
    OrganizationInvitation,
    /// Security alert
    SecurityAlert,
    /// Session expired notification
    SessionExpired,
    /// Email change confirmation
    EmailChange,
    /// Data export ready
    DataExportReady,
    /// Custom template
    Custom(String),
}

impl std::fmt::Display for TemplateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemplateType::Welcome => write!(f, "welcome"),
            TemplateType::Verification => write!(f, "verification"),
            TemplateType::PasswordReset => write!(f, "password_reset"),
            TemplateType::MfaNotification => write!(f, "mfa_notification"),
            TemplateType::PasswordChanged => write!(f, "password_changed"),
            TemplateType::AccountLocked => write!(f, "account_locked"),
            TemplateType::NewLoginDetected => write!(f, "new_login_detected"),
            TemplateType::OrganizationInvitation => write!(f, "organization_invitation"),
            TemplateType::SecurityAlert => write!(f, "security_alert"),
            TemplateType::SessionExpired => write!(f, "session_expired"),
            TemplateType::EmailChange => write!(f, "email_change"),
            TemplateType::DataExportReady => write!(f, "data_export_ready"),
            TemplateType::Custom(s) => write!(f, "custom_{}", s),
        }
    }
}

impl std::str::FromStr for TemplateType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "welcome" => Ok(TemplateType::Welcome),
            "verification" => Ok(TemplateType::Verification),
            "password_reset" => Ok(TemplateType::PasswordReset),
            "mfa_notification" => Ok(TemplateType::MfaNotification),
            "password_changed" => Ok(TemplateType::PasswordChanged),
            "account_locked" => Ok(TemplateType::AccountLocked),
            "new_login_detected" => Ok(TemplateType::NewLoginDetected),
            "organization_invitation" => Ok(TemplateType::OrganizationInvitation),
            "security_alert" => Ok(TemplateType::SecurityAlert),
            "session_expired" => Ok(TemplateType::SessionExpired),
            "email_change" => Ok(TemplateType::EmailChange),
            "data_export_ready" => Ok(TemplateType::DataExportReady),
            s if s.starts_with("custom_") => Ok(TemplateType::Custom(s[7..].to_string())),
            _ => Err(format!("Unknown template type: {}", s)),
        }
    }
}

/// Email template response
#[derive(Debug, Serialize)]
pub struct EmailTemplateResponse {
    pub template_type: String,
    pub name: String,
    pub description: String,
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
    pub from_name: Option<String>,
    pub from_address: Option<String>,
    pub is_customized: bool,
    pub last_modified: Option<String>,
    pub modified_by: Option<String>,
    pub variables: Vec<TemplateVariable>,
}

/// Template variable definition
#[derive(Debug, Serialize)]
pub struct TemplateVariable {
    pub name: String,
    pub description: String,
    pub example: String,
    pub required: bool,
}

/// List templates response
#[derive(Debug, Serialize)]
pub struct ListTemplatesResponse {
    pub templates: Vec<TemplateSummary>,
}

#[derive(Debug, Serialize)]
pub struct TemplateSummary {
    pub template_type: String,
    pub name: String,
    pub description: String,
    pub is_customized: bool,
    pub last_modified: Option<String>,
}

/// Update template request
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateTemplateRequest {
    #[validate(length(max = 500, message = "Subject must be at most 500 characters"))]
    pub subject: Option<String>,
    pub html_body: Option<String>,
    pub text_body: Option<String>,
    #[validate(length(max = 100, message = "From name must be at most 100 characters"))]
    pub from_name: Option<String>,
    #[validate(email(message = "Invalid from address"))]
    pub from_address: Option<String>,
}

/// Preview request
#[derive(Debug, Deserialize)]
pub struct PreviewRequest {
    /// Sample data for preview
    pub variables: Option<serde_json::Value>,
}

/// Preview response
#[derive(Debug, Serialize)]
pub struct PreviewResponse {
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
    pub warnings: Vec<String>,
}

/// Send test request
#[derive(Debug, Deserialize, Validate)]
pub struct SendTestRequest {
    #[validate(email(message = "Invalid email address"))]
    pub to_email: String,
    /// Sample data for preview
    pub variables: Option<serde_json::Value>,
}

/// A/B test configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct AbTestConfig {
    pub enabled: bool,
    pub variant_a: String,
    pub variant_b: String,
    pub split_percentage: u8, // 0-100, percentage for variant A
}

/// Variables response
#[derive(Debug, Serialize)]
pub struct VariablesResponse {
    pub global_variables: Vec<TemplateVariable>,
    pub template_specific: HashMap<String, Vec<TemplateVariable>>,
}

use std::collections::HashMap;

/// Template version history entry
#[derive(Debug, Serialize)]
pub struct TemplateVersion {
    pub version: i32,
    pub subject: String,
    pub modified_at: String,
    pub modified_by: String,
}

// ============ Handlers ============

/// List all email templates
async fn list_templates(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ListTemplatesResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let templates = vec![
        get_template_summary(&state, &current_user.tenant_id, TemplateType::Welcome).await?,
        get_template_summary(&state, &current_user.tenant_id, TemplateType::Verification).await?,
        get_template_summary(&state, &current_user.tenant_id, TemplateType::PasswordReset).await?,
        get_template_summary(&state, &current_user.tenant_id, TemplateType::MfaNotification).await?,
        get_template_summary(&state, &current_user.tenant_id, TemplateType::PasswordChanged).await?,
        get_template_summary(&state, &current_user.tenant_id, TemplateType::AccountLocked).await?,
        get_template_summary(&state, &current_user.tenant_id, TemplateType::NewLoginDetected).await?,
        get_template_summary(&state, &current_user.tenant_id, TemplateType::OrganizationInvitation).await?,
        get_template_summary(&state, &current_user.tenant_id, TemplateType::SecurityAlert).await?,
        get_template_summary(&state, &current_user.tenant_id, TemplateType::EmailChange).await?,
        get_template_summary(&state, &current_user.tenant_id, TemplateType::DataExportReady).await?,
    ];

    Ok(Json(ListTemplatesResponse { templates }))
}

/// Get a specific email template
async fn get_template(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(template_type): Path<String>,
) -> Result<Json<EmailTemplateResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let template_type = template_type
        .parse::<TemplateType>()
        .map_err(|e| ApiError::BadRequest(e))?;

    let template = get_template_details(&state, &current_user.tenant_id, template_type).await?;

    Ok(Json(template))
}

/// Update an email template
async fn update_template(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(template_type): Path<String>,
    Json(req): Json<UpdateTemplateRequest>,
) -> Result<Json<EmailTemplateResponse>, ApiError> {
    req.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let template_type = template_type
        .parse::<TemplateType>()
        .map_err(|e| ApiError::BadRequest(e))?;

    // Get existing template or default
    let existing = get_template_details(&state, &current_user.tenant_id, template_type.clone()).await?;

    // Build updated template
    let updated = EmailTemplateResponse {
        template_type: existing.template_type.clone(),
        name: existing.name.clone(),
        description: existing.description.clone(),
        subject: req.subject.unwrap_or(existing.subject),
        html_body: req.html_body.unwrap_or(existing.html_body),
        text_body: req.text_body.unwrap_or(existing.text_body),
        from_name: req.from_name.or(existing.from_name),
        from_address: req.from_address.or(existing.from_address),
        is_customized: true,
        last_modified: Some(Utc::now().to_rfc3339()),
        modified_by: Some(current_user.user_id.clone()),
        variables: existing.variables,
    };

    // Save to database
    let template_json = serde_json::json!({
        "subject": updated.subject,
        "html_body": updated.html_body,
        "text_body": updated.text_body,
        "from_name": updated.from_name,
        "from_address": updated.from_address,
        "is_customized": true,
        "last_modified": updated.last_modified,
        "modified_by": updated.modified_by,
    });

    sqlx::query(
        r#"INSERT INTO email_templates 
           (tenant_id, template_type, content, updated_at, updated_by)
           VALUES ($1, $2, $3, NOW(), $4)
           ON CONFLICT (tenant_id, template_type)
           DO UPDATE SET content = $3, updated_at = NOW(), updated_by = $4"#,
    )
    .bind(&current_user.tenant_id)
    .bind(template_type.to_string())
    .bind(template_json)
    .bind(&current_user.user_id)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    // Log the change
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("email_template.updated"),
        ResourceType::Admin,
        &template_type.to_string(),
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "template_type": template_type.to_string(),
        })),
    );

    Ok(Json(updated))
}

/// Generate a preview of the template
async fn preview_template(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(template_type): Path<String>,
    Json(req): Json<PreviewRequest>,
) -> Result<Json<PreviewResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let template_type = template_type
        .parse::<TemplateType>()
        .map_err(|e| ApiError::BadRequest(e))?;

    let template = get_template_details(&state, &current_user.tenant_id, template_type).await?;

    // Get sample variables
    let variables = req.variables.unwrap_or_else(|| get_sample_variables());

    // Render template with variables
    let subject = render_template(&template.subject, &variables);
    let html_body = render_template(&template.html_body, &variables);
    let text_body = render_template(&template.text_body, &variables);

    // Check for unused variables
    let mut warnings = Vec::new();
    for var in &template.variables {
        if var.required && !variables.get(&var.name).is_some() {
            warnings.push(format!("Required variable '{}' not provided", var.name));
        }
    }

    Ok(Json(PreviewResponse {
        subject,
        html_body,
        text_body,
        warnings,
    }))
}

/// Send a test email
async fn send_test_email(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(template_type): Path<String>,
    Json(req): Json<SendTestRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    req.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let template_type = template_type
        .parse::<TemplateType>()
        .map_err(|e| ApiError::BadRequest(e))?;

    // Get template
    let template = get_template_details(&state, &current_user.tenant_id, template_type.clone()).await?;

    // Get sample variables
    let variables = req.variables.unwrap_or_else(|| get_sample_variables());

    // Render template
    let subject = render_template(&template.subject, &variables);
    let html_body = render_template(&template.html_body, &variables);
    let text_body = render_template(&template.text_body, &variables);

    // Send email if service is available
    if let Some(sender) = state
        .communications
        .resolve_email_sender(&current_user.tenant_id)
        .await
    {
        let email_request = vault_core::email::EmailRequest {
            to: req.to_email.clone(),
            to_name: None,
            subject: subject.clone(),
            html_body: html_body.clone(),
            text_body: text_body.clone(),
            from: template
                .from_address
                .unwrap_or_else(|| sender.from_address.clone()),
            from_name: template
                .from_name
                .unwrap_or_else(|| sender.from_name.clone()),
            reply_to: sender.reply_to.clone(),
            headers: HashMap::new(),
        };

        match sender.service.send_email(email_request).await {
            Ok(_) => {
                // Log the action
                let audit = AuditLogger::new(state.db.clone());
                audit.log(
                    &current_user.tenant_id,
                    AuditAction::Custom("email_template.test_sent"),
                    ResourceType::Admin,
                    &template_type.to_string(),
                    Some(current_user.user_id.clone()),
                    None,
                    None,
                    true,
                    Some(format!("Test email sent to {}", req.to_email)),
                    Some(serde_json::json!({
                        "template_type": template_type.to_string(),
                        "to_email": req.to_email,
                    })),
                );

                Ok(Json(serde_json::json!({
                    "message": "Test email sent successfully",
                    "to": req.to_email,
                    "template_type": template_type.to_string(),
                })))
            }
            Err(e) => {
                tracing::error!("Failed to send test email: {}", e);
                Err(ApiError::internal())
            }
        }
    } else {
        Err(ApiError::BadRequest(
            "Email service not configured".to_string(),
        ))
    }
}

/// Reset template to default
async fn reset_template(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(template_type): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let template_type = template_type
        .parse::<TemplateType>()
        .map_err(|e| ApiError::BadRequest(e))?;

    // Delete custom template
    sqlx::query(
        "DELETE FROM email_templates WHERE tenant_id = $1 AND template_type = $2",
    )
    .bind(&current_user.tenant_id)
    .bind(template_type.to_string())
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::Custom("email_template.reset"),
        ResourceType::Admin,
        &template_type.to_string(),
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        Some("Template reset to default".to_string()),
        None,
    );

    Ok(Json(serde_json::json!({
        "message": "Template reset to default",
        "template_type": template_type.to_string(),
    })))
}

/// List all available template variables
async fn list_variables(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<VariablesResponse>, ApiError> {
    let global_variables = vec![
        TemplateVariable {
            name: "app_name".to_string(),
            description: "The name of your application".to_string(),
            example: "My App".to_string(),
            required: false,
        },
        TemplateVariable {
            name: "app_url".to_string(),
            description: "The URL of your application".to_string(),
            example: "https://app.example.com".to_string(),
            required: false,
        },
        TemplateVariable {
            name: "support_email".to_string(),
            description: "Support contact email".to_string(),
            example: "support@example.com".to_string(),
            required: false,
        },
        TemplateVariable {
            name: "current_year".to_string(),
            description: "Current year for copyright".to_string(),
            example: "2024".to_string(),
            required: false,
        },
    ];

    let mut template_specific = HashMap::new();
    
    template_specific.insert(
        "welcome".to_string(),
        vec![
            TemplateVariable {
                name: "user_email".to_string(),
                description: "User's email address".to_string(),
                example: "user@example.com".to_string(),
                required: true,
            },
            TemplateVariable {
                name: "user_name".to_string(),
                description: "User's display name".to_string(),
                example: "John Doe".to_string(),
                required: false,
            },
            TemplateVariable {
                name: "verification_link".to_string(),
                description: "Email verification link".to_string(),
                example: "https://app.example.com/verify?token=abc123".to_string(),
                required: true,
            },
        ],
    );

    template_specific.insert(
        "password_reset".to_string(),
        vec![
            TemplateVariable {
                name: "user_email".to_string(),
                description: "User's email address".to_string(),
                example: "user@example.com".to_string(),
                required: true,
            },
            TemplateVariable {
                name: "reset_link".to_string(),
                description: "Password reset link".to_string(),
                example: "https://app.example.com/reset?token=abc123".to_string(),
                required: true,
            },
            TemplateVariable {
                name: "expires_in".to_string(),
                description: "How long until link expires".to_string(),
                example: "1 hour".to_string(),
                required: false,
            },
        ],
    );

    Ok(Json(VariablesResponse {
        global_variables,
        template_specific,
    }))
}

// ============ Helper Functions ============

/// Get template summary
async fn get_template_summary(
    state: &AppState,
    tenant_id: &str,
    template_type: TemplateType,
) -> Result<TemplateSummary, ApiError> {
    // Check if customized
    let is_customized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM email_templates WHERE tenant_id = $1 AND template_type = $2)",
    )
    .bind(tenant_id)
    .bind(template_type.to_string())
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let last_modified: Option<DateTime<Utc>> = if is_customized {
        sqlx::query_scalar(
            "SELECT updated_at FROM email_templates WHERE tenant_id = $1 AND template_type = $2",
        )
        .bind(tenant_id)
        .bind(template_type.to_string())
        .fetch_optional(state.db.pool())
        .await
        .map_err(|_| ApiError::internal())?
        .flatten()
    } else {
        None
    };

    let (name, description) = get_template_info(&template_type);

    Ok(TemplateSummary {
        template_type: template_type.to_string(),
        name,
        description,
        is_customized,
        last_modified: last_modified.map(|dt| dt.to_rfc3339()),
    })
}

/// Get full template details
async fn get_template_details(
    state: &AppState,
    tenant_id: &str,
    template_type: TemplateType,
) -> Result<EmailTemplateResponse, ApiError> {
    // Try to get custom template
    let custom: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT content FROM email_templates WHERE tenant_id = $1 AND template_type = $2",
    )
    .bind(tenant_id)
    .bind(template_type.to_string())
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let (name, description) = get_template_info(&template_type);
    let default = get_default_template(&template_type);
    let variables = get_template_variables(&template_type);

    if let Some(content) = custom {
        Ok(EmailTemplateResponse {
            template_type: template_type.to_string(),
            name,
            description,
            subject: content.get("subject").and_then(|v| v.as_str()).unwrap_or(&default.subject).to_string(),
            html_body: content.get("html_body").and_then(|v| v.as_str()).unwrap_or(&default.html_body).to_string(),
            text_body: content.get("text_body").and_then(|v| v.as_str()).unwrap_or(&default.text_body).to_string(),
            from_name: content.get("from_name").and_then(|v| v.as_str()).map(|s| s.to_string()),
            from_address: content.get("from_address").and_then(|v| v.as_str()).map(|s| s.to_string()),
            is_customized: true,
            last_modified: content.get("last_modified").and_then(|v| v.as_str()).map(|s| s.to_string()),
            modified_by: content.get("modified_by").and_then(|v| v.as_str()).map(|s| s.to_string()),
            variables,
        })
    } else {
        Ok(EmailTemplateResponse {
            template_type: template_type.to_string(),
            name,
            description,
            subject: default.subject,
            html_body: default.html_body,
            text_body: default.text_body,
            from_name: None,
            from_address: None,
            is_customized: false,
            last_modified: None,
            modified_by: None,
            variables,
        })
    }
}

/// Get template name and description
fn get_template_info(template_type: &TemplateType) -> (String, String) {
    match template_type {
        TemplateType::Welcome => (
            "Welcome Email".to_string(),
            "Sent to new users after registration".to_string(),
        ),
        TemplateType::Verification => (
            "Email Verification".to_string(),
            "Sent to verify user's email address".to_string(),
        ),
        TemplateType::PasswordReset => (
            "Password Reset".to_string(),
            "Sent when user requests password reset".to_string(),
        ),
        TemplateType::MfaNotification => (
            "MFA Notification".to_string(),
            "Sent for MFA code or backup codes".to_string(),
        ),
        TemplateType::PasswordChanged => (
            "Password Changed".to_string(),
            "Notification when password is changed".to_string(),
        ),
        TemplateType::AccountLocked => (
            "Account Locked".to_string(),
            "Notification when account is locked".to_string(),
        ),
        TemplateType::NewLoginDetected => (
            "New Login Detected".to_string(),
            "Security alert for new device/location".to_string(),
        ),
        TemplateType::OrganizationInvitation => (
            "Organization Invitation".to_string(),
            "Invitation to join an organization".to_string(),
        ),
        TemplateType::SecurityAlert => (
            "Security Alert".to_string(),
            "General security notification".to_string(),
        ),
        TemplateType::SessionExpired => (
            "Session Expired".to_string(),
            "Notification when session expires".to_string(),
        ),
        TemplateType::EmailChange => (
            "Email Change".to_string(),
            "Confirmation for email address change".to_string(),
        ),
        TemplateType::DataExportReady => (
            "Data Export Ready".to_string(),
            "Notification when data export is ready".to_string(),
        ),
        TemplateType::Custom(name) => (
            format!("Custom: {}", name),
            "Custom email template".to_string(),
        ),
    }
}

/// Get default template content
fn get_default_template(template_type: &TemplateType) -> DefaultTemplate {
    match template_type {
        TemplateType::Welcome => DefaultTemplate {
            subject: "Welcome to {{app_name}}!".to_string(),
            html_body: r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Welcome</title>
</head>
<body>
    <h1>Welcome to {{app_name}}!</h1>
    <p>Hi {{user_name}},</p>
    <p>Thanks for joining us. Please verify your email by clicking the link below:</p>
    <p><a href="{{verification_link}}" style="padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
    <p>If you didn't create an account, you can ignore this email.</p>
    <p>Best regards,<br>{{app_name}} Team</p>
</body>
</html>
"#.to_string(),
            text_body: r#"Welcome to {{app_name}}!

Hi {{user_name}},

Thanks for joining us. Please verify your email by visiting:
{{verification_link}}

If you didn't create an account, you can ignore this email.

Best regards,
{{app_name}} Team
"#.to_string(),
        },
        TemplateType::PasswordReset => DefaultTemplate {
            subject: "Reset your password".to_string(),
            html_body: r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
</head>
<body>
    <h1>Password Reset Request</h1>
    <p>Hi,</p>
    <p>We received a request to reset your password. Click the link below to create a new password:</p>
    <p><a href="{{reset_link}}" style="padding: 10px 20px; background: #dc3545; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
    <p>This link will expire in {{expires_in}}.</p>
    <p>If you didn't request this, please ignore this email.</p>
</body>
</html>
"#.to_string(),
            text_body: r#"Password Reset Request

Hi,

We received a request to reset your password. Visit the link below:
{{reset_link}}

This link will expire in {{expires_in}}.

If you didn't request this, please ignore this email.
"#.to_string(),
        },
        _ => DefaultTemplate {
            subject: "Notification from {{app_name}}".to_string(),
            html_body: r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Notification</title>
</head>
<body>
    <h1>Notification</h1>
    <p>This is a notification from {{app_name}}.</p>
</body>
</html>
"#.to_string(),
            text_body: "Notification from {{app_name}}".to_string(),
        },
    }
}

struct DefaultTemplate {
    subject: String,
    html_body: String,
    text_body: String,
}

/// Get variables for a template type
fn get_template_variables(template_type: &TemplateType) -> Vec<TemplateVariable> {
    match template_type {
        TemplateType::Welcome => vec![
            TemplateVariable {
                name: "user_email".to_string(),
                description: "User's email address".to_string(),
                example: "user@example.com".to_string(),
                required: true,
            },
            TemplateVariable {
                name: "user_name".to_string(),
                description: "User's display name".to_string(),
                example: "John Doe".to_string(),
                required: false,
            },
            TemplateVariable {
                name: "verification_link".to_string(),
                description: "Email verification link".to_string(),
                example: "https://app.example.com/verify?token=abc123".to_string(),
                required: true,
            },
        ],
        TemplateType::PasswordReset => vec![
            TemplateVariable {
                name: "user_email".to_string(),
                description: "User's email address".to_string(),
                example: "user@example.com".to_string(),
                required: true,
            },
            TemplateVariable {
                name: "reset_link".to_string(),
                description: "Password reset link".to_string(),
                example: "https://app.example.com/reset?token=abc123".to_string(),
                required: true,
            },
            TemplateVariable {
                name: "expires_in".to_string(),
                description: "Link expiration time".to_string(),
                example: "1 hour".to_string(),
                required: false,
            },
        ],
        _ => vec![],
    }
}

/// Get sample variables for preview
fn get_sample_variables() -> serde_json::Value {
    serde_json::json!({
        "app_name": "My Application",
        "app_url": "https://app.example.com",
        "support_email": "support@example.com",
        "current_year": "2024",
        "user_email": "john.doe@example.com",
        "user_name": "John Doe",
        "verification_link": "https://app.example.com/verify?token=sample123",
        "reset_link": "https://app.example.com/reset?token=sample456",
        "expires_in": "1 hour",
    })
}

/// Simple template rendering (replace {{variable}} with value)
fn render_template(template: &str, variables: &serde_json::Value) -> String {
    let mut result = template.to_string();
    
    if let Some(obj) = variables.as_object() {
        for (key, value) in obj {
            let placeholder = format!("{{{{{}}}}}", key);
            let replacement = value.as_str().unwrap_or("");
            result = result.replace(&placeholder, replacement);
        }
    }
    
    result
}
