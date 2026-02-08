//! Settings Validation
//!
//! Validation logic for tenant settings to ensure values are within acceptable ranges.

use crate::settings::models::*;
use crate::routes::ApiError;

/// Validate auth settings
pub fn validate_auth_settings(settings: &AuthSettings) -> Result<(), ApiError> {
    // Ensure default auth method is in allowed methods
    if !settings.allowed_auth_methods.contains(&settings.default_auth_method) {
        return Err(ApiError::BadRequest(
            "Default auth method must be in allowed auth methods".to_string()
        ));
    }

    // Require at least one auth method
    if settings.allowed_auth_methods.is_empty() {
        return Err(ApiError::BadRequest(
            "At least one authentication method must be enabled".to_string()
        ));
    }

    // Validate step-up auth rules
    for rule in &settings.step_up_auth_rules {
        if rule.action.is_empty() {
            return Err(ApiError::BadRequest(
                "Step-up auth rule action cannot be empty".to_string()
            ));
        }
    }

    Ok(())
}

/// Validate security settings
pub fn validate_security_settings(settings: &SecuritySettings) -> Result<(), ApiError> {
    let policy = &settings.password_policy;

    // Password length validation
    if policy.min_length < 8 {
        return Err(ApiError::BadRequest(
            "Minimum password length must be at least 8".to_string()
        ));
    }

    if policy.max_length > 256 {
        return Err(ApiError::BadRequest(
            "Maximum password length cannot exceed 256".to_string()
        ));
    }

    if policy.min_length > policy.max_length {
        return Err(ApiError::BadRequest(
            "Minimum password length cannot exceed maximum length".to_string()
        ));
    }

    // Entropy validation
    if policy.min_entropy < 0.0 || policy.min_entropy > 100.0 {
        return Err(ApiError::BadRequest(
            "Password entropy must be between 0 and 100".to_string()
        ));
    }

    // History count validation
    if policy.history_count > 20 {
        return Err(ApiError::BadRequest(
            "Password history count cannot exceed 20".to_string()
        ));
    }

    // Session lifetime validation
    let lifetime = &settings.session_lifetime;
    if lifetime.access_token_minutes < 1 {
        return Err(ApiError::BadRequest(
            "Access token lifetime must be at least 1 minute".to_string()
        ));
    }

    if lifetime.access_token_minutes > 1440 {
        return Err(ApiError::BadRequest(
            "Access token lifetime cannot exceed 24 hours".to_string()
        ));
    }

    if lifetime.refresh_token_days < 1 {
        return Err(ApiError::BadRequest(
            "Refresh token lifetime must be at least 1 day".to_string()
        ));
    }

    if lifetime.refresh_token_days > 365 {
        return Err(ApiError::BadRequest(
            "Refresh token lifetime cannot exceed 365 days".to_string()
        ));
    }

    // Session limits validation
    let limits = &settings.session_limits;
    if limits.max_concurrent_sessions == 0 {
        return Err(ApiError::BadRequest(
            "Maximum concurrent sessions must be at least 1".to_string()
        ));
    }

    if limits.max_concurrent_sessions > 100 {
        return Err(ApiError::BadRequest(
            "Maximum concurrent sessions cannot exceed 100".to_string()
        ));
    }

    // MFA settings validation
    let mfa = &settings.mfa_settings;
    if mfa.grace_period_days < 0 || mfa.grace_period_days > 30 {
        return Err(ApiError::BadRequest(
            "MFA grace period must be between 0 and 30 days".to_string()
        ));
    }

    // Lockout policy validation
    let lockout = &settings.lockout_policy;
    if lockout.max_failed_attempts < 1 {
        return Err(ApiError::BadRequest(
            "Max failed attempts must be at least 1".to_string()
        ));
    }

    if lockout.max_failed_attempts > 10 {
        return Err(ApiError::BadRequest(
            "Max failed attempts cannot exceed 10".to_string()
        ));
    }

    Ok(())
}

/// Validate organization settings
pub fn validate_org_settings(settings: &OrgSettings) -> Result<(), ApiError> {
    if settings.max_organizations_per_user < 1 {
        return Err(ApiError::BadRequest(
            "Max organizations per user must be at least 1".to_string()
        ));
    }

    if settings.max_organizations_per_user > 1000 {
        return Err(ApiError::BadRequest(
            "Max organizations per user cannot exceed 1000".to_string()
        ));
    }

    if settings.default_membership_limit < 1 {
        return Err(ApiError::BadRequest(
            "Default membership limit must be at least 1".to_string()
        ));
    }

    if settings.default_membership_limit > 10000 {
        return Err(ApiError::BadRequest(
            "Default membership limit cannot exceed 10000".to_string()
        ));
    }

    // Validate role names are not empty
    if settings.default_org_role.is_empty() {
        return Err(ApiError::BadRequest(
            "Default org role cannot be empty".to_string()
        ));
    }

    if settings.creator_role.is_empty() {
        return Err(ApiError::BadRequest(
            "Creator role cannot be empty".to_string()
        ));
    }

    // If membership is required, personal accounts should be disabled
    if settings.membership_required && settings.allow_personal_accounts {
        return Err(ApiError::BadRequest(
            "Personal accounts must be disabled when membership is required".to_string()
        ));
    }

    Ok(())
}

/// Validate branding settings
pub fn validate_branding_settings(settings: &BrandingSettings) -> Result<(), ApiError> {
    // Validate brand name
    if settings.brand_name.is_empty() {
        return Err(ApiError::BadRequest(
            "Brand name cannot be empty".to_string()
        ));
    }

    if settings.brand_name.len() > 100 {
        return Err(ApiError::BadRequest(
            "Brand name cannot exceed 100 characters".to_string()
        ));
    }

    // Validate hex colors
    if !is_valid_hex_color(&settings.primary_color) {
        return Err(ApiError::BadRequest(
            "Primary color must be a valid hex color (e.g., #0066FF)".to_string()
        ));
    }

    if !is_valid_hex_color(&settings.accent_color) {
        return Err(ApiError::BadRequest(
            "Accent color must be a valid hex color (e.g., #00D4AA)".to_string()
        ));
    }

    // Validate URLs if provided
    if let Some(ref logo_url) = settings.brand_logo_url {
        if !is_valid_url(logo_url) {
            return Err(ApiError::BadRequest(
                "Brand logo URL must be a valid URL".to_string()
            ));
        }
    }

    if let Some(ref favicon_url) = settings.brand_favicon_url {
        if !is_valid_url(favicon_url) {
            return Err(ApiError::BadRequest(
                "Favicon URL must be a valid URL".to_string()
            ));
        }
    }

    if let Some(ref tos_url) = settings.terms_of_service_url {
        if !is_valid_url(tos_url) {
            return Err(ApiError::BadRequest(
                "Terms of service URL must be a valid URL".to_string()
            ));
        }
    }

    if let Some(ref privacy_url) = settings.privacy_policy_url {
        if !is_valid_url(privacy_url) {
            return Err(ApiError::BadRequest(
                "Privacy policy URL must be a valid URL".to_string()
            ));
        }
    }

    if let Some(ref support_url) = settings.support_url {
        if !is_valid_url(support_url) {
            return Err(ApiError::BadRequest(
                "Support URL must be a valid URL".to_string()
            ));
        }
    }

    Ok(())
}

/// Validate email settings
pub fn validate_email_settings(settings: &EmailSettings) -> Result<(), ApiError> {
    // Validate from address
    if settings.from_address.is_empty() {
        return Err(ApiError::BadRequest(
            "From address cannot be empty".to_string()
        ));
    }

    if !is_valid_email(&settings.from_address) {
        return Err(ApiError::BadRequest(
            "From address must be a valid email".to_string()
        ));
    }

    // Validate from name
    if settings.from_name.is_empty() {
        return Err(ApiError::BadRequest(
            "From name cannot be empty".to_string()
        ));
    }

    // Validate reply-to if provided
    if let Some(ref reply_to) = settings.reply_to {
        if !reply_to.is_empty() && !is_valid_email(reply_to) {
            return Err(ApiError::BadRequest(
                "Reply-to must be a valid email".to_string()
            ));
        }
    }

    // Validate custom SMTP if provided
    if let Some(ref smtp) = settings.custom_smtp {
        if smtp.host.is_empty() {
            return Err(ApiError::BadRequest(
                "SMTP host cannot be empty".to_string()
            ));
        }

        if smtp.port == 0 || smtp.port > 65535 {
            return Err(ApiError::BadRequest(
                "SMTP port must be between 1 and 65535".to_string()
            ));
        }

        if smtp.username.is_empty() {
            return Err(ApiError::BadRequest(
                "SMTP username cannot be empty".to_string()
            ));
        }
    }

    Ok(())
}

/// Validate OAuth settings
pub fn validate_oauth_settings(settings: &OAuthSettings) -> Result<(), ApiError> {
    // Validate provider configurations
    for provider in &settings.oauth_providers {
        if provider.provider_id.is_empty() {
            return Err(ApiError::BadRequest(
                "OAuth provider ID cannot be empty".to_string()
            ));
        }

        if provider.display_name.is_empty() {
            return Err(ApiError::BadRequest(
                "OAuth provider display name cannot be empty".to_string()
            ));
        }

        if provider.client_id.is_empty() {
            return Err(ApiError::BadRequest(
                format!("Client ID is required for provider {}", provider.provider_id)
            ));
        }
    }

    Ok(())
}

/// Validate localization settings
pub fn validate_localization_settings(settings: &LocalizationSettings) -> Result<(), ApiError> {
    // Validate language codes (ISO 639-1)
    if settings.default_language.len() != 2 {
        return Err(ApiError::BadRequest(
            "Default language must be a valid ISO 639-1 code (2 letters)".to_string()
        ));
    }

    // Ensure default language is in supported languages
    if !settings.supported_languages.contains(&settings.default_language) {
        return Err(ApiError::BadRequest(
            "Default language must be in supported languages".to_string()
        ));
    }

    // Validate supported languages
    for lang in &settings.supported_languages {
        if lang.len() != 2 {
            return Err(ApiError::BadRequest(
                format!("Invalid language code: {}. Must be ISO 639-1 (2 letters)", lang)
            ));
        }
    }

    // Validate timezone (basic check)
    if settings.timezone.is_empty() {
        return Err(ApiError::BadRequest(
            "Timezone cannot be empty".to_string()
        ));
    }

    Ok(())
}

/// Validate webhook settings
pub fn validate_webhook_settings(settings: &WebhookSettings) -> Result<(), ApiError> {
    // Validate retry configuration
    let retries = &settings.webhook_retries;
    if retries.max_attempts < 0 || retries.max_attempts > 10 {
        return Err(ApiError::BadRequest(
            "Webhook max attempts must be between 0 and 10".to_string()
        ));
    }

    if retries.timeout_seconds < 1 || retries.timeout_seconds > 300 {
        return Err(ApiError::BadRequest(
            "Webhook timeout must be between 1 and 300 seconds".to_string()
        ));
    }

    // Validate endpoint URLs
    for endpoint in &settings.webhook_endpoints {
        if !is_valid_url(&endpoint.url) {
            return Err(ApiError::BadRequest(
                format!("Invalid webhook URL: {}", endpoint.url)
            ));
        }

        // Block localhost/loopback for webhooks in production
        if is_localhost_url(&endpoint.url) {
            return Err(ApiError::BadRequest(
                "Webhook URLs cannot point to localhost in production".to_string()
            ));
        }

        if endpoint.events.is_empty() {
            return Err(ApiError::BadRequest(
                format!("Webhook '{}' must subscribe to at least one event", endpoint.name)
            ));
        }
    }

    // Validate rotation days
    if settings.signing_secret_rotation_days < 1 || settings.signing_secret_rotation_days > 365 {
        return Err(ApiError::BadRequest(
            "Signing secret rotation days must be between 1 and 365".to_string()
        ));
    }

    Ok(())
}

/// Validate privacy settings
pub fn validate_privacy_settings(settings: &PrivacySettings) -> Result<(), ApiError> {
    // Validate data retention
    if settings.data_retention_days < 1 {
        return Err(ApiError::BadRequest(
            "Data retention days must be at least 1".to_string()
        ));
    }

    if settings.data_retention_days > 2555 { // ~7 years
        return Err(ApiError::BadRequest(
            "Data retention days cannot exceed 2555 (7 years)".to_string()
        ));
    }

    // Validate deletion grace period
    if settings.deletion_grace_period_days < 0 || settings.deletion_grace_period_days > 90 {
        return Err(ApiError::BadRequest(
            "Deletion grace period must be between 0 and 90 days".to_string()
        ));
    }

    // Validate minimum age
    if settings.min_age_requirement < 13 || settings.min_age_requirement > 21 {
        return Err(ApiError::BadRequest(
            "Minimum age requirement must be between 13 and 21".to_string()
        ));
    }

    Ok(())
}

/// Validate advanced settings
pub fn validate_advanced_settings(settings: &AdvancedSettings) -> Result<(), ApiError> {
    // Validate callback URLs
    for url in &settings.allowed_callback_urls {
        if url != "*" && !is_valid_callback_url(url) {
            return Err(ApiError::BadRequest(
                format!("Invalid callback URL: {}", url)
            ));
        }
    }

    // Validate logout URLs
    for url in &settings.allowed_logout_urls {
        if url != "*" && !is_valid_callback_url(url) {
            return Err(ApiError::BadRequest(
                format!("Invalid logout URL: {}", url)
            ));
        }
    }

    // Validate API version
    if settings.api_version != "v1" {
        return Err(ApiError::BadRequest(
            "Only API version 'v1' is currently supported".to_string()
        ));
    }

    Ok(())
}

/// Validate all settings at once
pub fn validate_all_settings(settings: &TenantSettings) -> Result<(), ApiError> {
    validate_auth_settings(&settings.auth)?;
    validate_security_settings(&settings.security)?;
    validate_org_settings(&settings.org)?;
    validate_branding_settings(&settings.branding)?;
    validate_email_settings(&settings.email)?;
    validate_oauth_settings(&settings.oauth)?;
    validate_localization_settings(&settings.localization)?;
    validate_webhook_settings(&settings.webhook)?;
    validate_privacy_settings(&settings.privacy)?;
    validate_advanced_settings(&settings.advanced)?;
    
    Ok(())
}

// ============================================
// Helper Functions
// ============================================

fn is_valid_hex_color(color: &str) -> bool {
    if color.len() != 7 && color.len() != 4 {
        return false;
    }
    
    if !color.starts_with('#') {
        return false;
    }
    
    color[1..].chars().all(|c| c.is_ascii_hexdigit())
}

fn is_valid_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

fn is_localhost_url(url: &str) -> bool {
    let lowercase = url.to_lowercase();
    lowercase.contains("localhost") 
        || lowercase.contains("127.0.0.1")
        || lowercase.contains("::1")
        || lowercase.contains("0.0.0.0")
}

fn is_valid_email(email: &str) -> bool {
    // Basic email validation
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }
    
    let local = parts[0];
    let domain = parts[1];
    
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    
    domain.contains('.')
}

fn is_valid_callback_url(url: &str) -> bool {
    // Allow custom app schemes for mobile
    if url.contains("://") {
        let scheme: &str = url.split("://").next().unwrap_or("");
        return !scheme.is_empty();
    }
    
    false
}
