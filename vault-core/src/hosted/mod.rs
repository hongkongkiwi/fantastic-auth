//! Hosted UI Configuration Module
//!
//! This module provides types and functions for managing hosted UI configuration,
//! allowing tenants to customize the appearance and behavior of pre-built
//! authentication pages.

use serde::{Deserialize, Serialize};

/// OAuth providers supported by the hosted UI
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthProvider {
    Google,
    Github,
    Apple,
    Microsoft,
    Slack,
    Discord,
}

impl std::fmt::Display for OAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthProvider::Google => write!(f, "google"),
            OAuthProvider::Github => write!(f, "github"),
            OAuthProvider::Apple => write!(f, "apple"),
            OAuthProvider::Microsoft => write!(f, "microsoft"),
            OAuthProvider::Slack => write!(f, "slack"),
            OAuthProvider::Discord => write!(f, "discord"),
        }
    }
}

/// Hosted UI configuration for a tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostedUiConfig {
    /// Tenant ID this config belongs to
    pub tenant_id: String,

    // Branding
    /// URL to the tenant's logo
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,

    /// URL to the tenant's favicon
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favicon_url: Option<String>,

    /// Primary brand color (hex format, e.g., "#4f46e5")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,

    /// Background color for hosted pages
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,

    // Content
    /// Company/organization name
    pub company_name: String,

    /// Custom title for sign-in page
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_in_title: Option<String>,

    /// Custom title for sign-up page
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_up_title: Option<String>,

    // Features
    /// Enabled OAuth providers
    #[serde(default)]
    pub oauth_providers: Vec<OAuthProvider>,

    /// Whether to show magic link option
    #[serde(default = "default_true")]
    pub show_magic_link: bool,

    /// Whether to show WebAuthn/Passkey option
    #[serde(default = "default_true")]
    pub show_web_authn: bool,

    /// Whether email verification is required for new accounts
    #[serde(default = "default_true")]
    pub require_email_verification: bool,

    /// Whether new sign-ups are allowed
    #[serde(default = "default_true")]
    pub allow_sign_up: bool,

    // URLs
    /// URL to redirect to after successful sign-in
    pub after_sign_in_url: String,

    /// URL to redirect to after successful sign-up
    pub after_sign_up_url: String,

    /// URL to redirect to after sign-out
    pub after_sign_out_url: String,

    // Legal
    /// URL to terms of service
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_url: Option<String>,

    /// URL to privacy policy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_url: Option<String>,

    // Advanced
    /// Custom CSS to inject into hosted pages
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_css: Option<String>,

    /// Custom JavaScript to inject into hosted pages
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_js: Option<String>,

    // Security
    /// List of allowed redirect URLs
    #[serde(default)]
    pub allowed_redirect_urls: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl HostedUiConfig {
    /// Create a new hosted UI config with default values
    pub fn new(tenant_id: String, company_name: String) -> Self {
        Self {
            tenant_id,
            logo_url: None,
            favicon_url: None,
            primary_color: None,
            background_color: None,
            company_name,
            sign_in_title: None,
            sign_up_title: None,
            oauth_providers: vec![OAuthProvider::Google, OAuthProvider::Github],
            show_magic_link: true,
            show_web_authn: true,
            require_email_verification: true,
            allow_sign_up: true,
            after_sign_in_url: "/dashboard".to_string(),
            after_sign_up_url: "/welcome".to_string(),
            after_sign_out_url: "/hosted/sign-in".to_string(),
            terms_url: None,
            privacy_url: None,
            custom_css: None,
            custom_js: None,
            allowed_redirect_urls: vec![],
        }
    }

    /// Validate a redirect URL against the allowlist
    pub fn validate_redirect_url(&self, url: &str) -> bool {
        // Allow relative URLs
        if url.starts_with('/') && !url.starts_with("//") {
            return true;
        }

        // Check against allowed URLs
        for allowed in &self.allowed_redirect_urls {
            if url.starts_with(allowed) {
                return true;
            }
        }

        // Check if URL matches the default redirects
        if url == self.after_sign_in_url
            || url == self.after_sign_up_url
            || url == self.after_sign_out_url
        {
            return true;
        }

        false
    }

    /// Get the effective sign-in title
    pub fn sign_in_title(&self) -> String {
        self.sign_in_title
            .clone()
            .unwrap_or_else(|| format!("Sign in to {}", self.company_name))
    }

    /// Get the effective sign-up title
    pub fn sign_up_title(&self) -> String {
        self.sign_up_title
            .clone()
            .unwrap_or_else(|| format!("Create your {} account", self.company_name))
    }

    /// Check if a specific OAuth provider is enabled
    pub fn is_oauth_provider_enabled(&self, provider: OAuthProvider) -> bool {
        self.oauth_providers.contains(&provider)
    }
}

/// Request to update hosted UI configuration
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateHostedUiConfigRequest {
    #[serde(flatten)]
    pub config: HostedUiConfig,
}

/// Response containing hosted UI configuration
#[derive(Debug, Clone, Serialize)]
pub struct HostedUiConfigResponse {
    #[serde(flatten)]
    pub config: HostedUiConfig,
}

/// Input for validating a redirect URL
#[derive(Debug, Clone, Deserialize)]
pub struct ValidateRedirectRequest {
    pub url: String,
}

/// Response for redirect validation
#[derive(Debug, Clone, Serialize)]
pub struct ValidateRedirectResponse {
    pub valid: bool,
    pub sanitized_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HostedUiConfig::new("tenant-123".to_string(), "Acme Inc".to_string());

        assert_eq!(config.tenant_id, "tenant-123");
        assert_eq!(config.company_name, "Acme Inc");
        assert!(config.show_magic_link);
        assert!(config.allow_sign_up);
    }

    #[test]
    fn test_validate_redirect_url_relative() {
        let config = HostedUiConfig::new("tenant-123".to_string(), "Acme".to_string());

        assert!(config.validate_redirect_url("/dashboard"));
        assert!(config.validate_redirect_url("/profile"));
        assert!(!config.validate_redirect_url("//evil.com"));
    }

    #[test]
    fn test_validate_redirect_url_allowed() {
        let mut config = HostedUiConfig::new("tenant-123".to_string(), "Acme".to_string());
        config
            .allowed_redirect_urls
            .push("https://app.example.com".to_string());

        assert!(config.validate_redirect_url("https://app.example.com/callback"));
        assert!(!config.validate_redirect_url("https://evil.com/callback"));
    }

    #[test]
    fn test_titles() {
        let config = HostedUiConfig::new("tenant-123".to_string(), "Acme".to_string());

        assert_eq!(config.sign_in_title(), "Sign in to Acme");
        assert_eq!(config.sign_up_title(), "Create your Acme account");
    }
}
