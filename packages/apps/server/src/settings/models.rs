//! Tenant Settings Models
//!
//! All the data structures for per-tenant configuration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;

// ============================================
// Main Settings Container
// ============================================

/// Complete tenant settings
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TenantSettings {
    pub auth: AuthSettings,
    pub security: SecuritySettings,
    pub org: OrgSettings,
    pub branding: BrandingSettings,
    pub email: EmailSettings,
    pub sms: SmsSettings,
    pub oauth: OAuthSettings,
    pub localization: LocalizationSettings,
    pub webhook: WebhookSettings,
    pub privacy: PrivacySettings,
    pub advanced: AdvancedSettings,
}

/// Database row for tenant settings
#[derive(Debug, Clone, FromRow)]
pub struct TenantSettingsRow {
    pub tenant_id: String,
    pub auth_settings: serde_json::Value,
    pub security_settings: serde_json::Value,
    pub org_settings: serde_json::Value,
    pub branding_settings: serde_json::Value,
    pub email_settings: serde_json::Value,
    pub sms_settings: serde_json::Value,
    pub oauth_settings: serde_json::Value,
    pub localization_settings: serde_json::Value,
    pub webhook_settings: serde_json::Value,
    pub privacy_settings: serde_json::Value,
    pub advanced_settings: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: Option<String>,
}

// ============================================
// 1. Authentication Settings
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthSettings {
    /// Allow new user registration
    pub allow_registration: bool,
    /// Require email verification before login
    pub require_email_verification: bool,
    /// Enabled authentication methods
    pub allowed_auth_methods: Vec<AuthMethod>,
    /// Default method shown to users
    pub default_auth_method: AuthMethod,
    /// Allow anonymous/guest sessions
    pub allow_anonymous_auth: bool,
    /// Enable passwordless options
    pub allow_passwordless: bool,
    /// Require MFA for all users
    pub require_strong_auth: bool,
    /// When to require step-up authentication
    pub step_up_auth_rules: Vec<StepUpAuthRule>,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            allow_registration: true,
            require_email_verification: true,
            allowed_auth_methods: vec![
                AuthMethod::Password,
                AuthMethod::MagicLink,
                AuthMethod::OtpEmail,
            ],
            default_auth_method: AuthMethod::Password,
            allow_anonymous_auth: false,
            allow_passwordless: true,
            require_strong_auth: false,
            step_up_auth_rules: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Password,
    MagicLink,
    OtpEmail,
    OtpSms,
    OAuth,
    WebAuthn,
    Sso,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpAuthRule {
    /// Action that triggers step-up
    pub action: String,
    /// Required authentication level
    pub required_level: AuthLevel,
    /// Allowed MFA methods for step-up
    pub allowed_methods: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthLevel {
    Password,
    Mfa,
    Biometric,
}

// ============================================
// 2. Security Settings
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecuritySettings {
    /// Password policy configuration
    pub password_policy: TenantPasswordPolicy,
    /// Session token lifetimes
    pub session_lifetime: SessionLifetime,
    /// Session limits and eviction
    pub session_limits: SessionLimits,
    /// MFA configuration
    pub mfa_settings: MfaSettings,
    /// Account lockout policy
    pub lockout_policy: LockoutPolicy,
    /// Security notifications (user/admin)
    pub notifications: SecurityNotificationSettings,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            password_policy: TenantPasswordPolicy::default(),
            session_lifetime: SessionLifetime::default(),
            session_limits: SessionLimits::default(),
            mfa_settings: MfaSettings::default(),
            lockout_policy: LockoutPolicy::default(),
            notifications: SecurityNotificationSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    Email,
    Sms,
    Whatsapp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecurityNotificationEvent {
    LoginFailed,
    LoginBlockedRisk,
    PasswordChanged,
    PasswordReset,
    MfaEnabled,
    MfaDisabled,
    SuspiciousLogin,
    AccountLocked,
    ImpersonationStarted,
    SecurityPolicyUpdated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityNotificationAudience {
    pub enabled: bool,
    pub events: Vec<SecurityNotificationEvent>,
    pub channels: Vec<NotificationChannel>,
}

impl Default for SecurityNotificationAudience {
    fn default() -> Self {
        Self {
            enabled: true,
            events: vec![
                SecurityNotificationEvent::LoginFailed,
                SecurityNotificationEvent::LoginBlockedRisk,
                SecurityNotificationEvent::PasswordChanged,
                SecurityNotificationEvent::PasswordReset,
                SecurityNotificationEvent::MfaEnabled,
                SecurityNotificationEvent::MfaDisabled,
            ],
            channels: vec![NotificationChannel::Email],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityNotificationSettings {
    pub user: SecurityNotificationAudience,
    pub admin: SecurityNotificationAudience,
    /// Tenant admin roles to notify (owner/admin)
    pub admin_roles: Vec<String>,
    /// Optional WhatsApp template name for security alerts (must be pre-approved)
    pub whatsapp_template_name: Option<String>,
}

impl Default for SecurityNotificationSettings {
    fn default() -> Self {
        Self {
            user: SecurityNotificationAudience::default(),
            admin: SecurityNotificationAudience {
                enabled: true,
                events: vec![
                    SecurityNotificationEvent::LoginBlockedRisk,
                    SecurityNotificationEvent::SuspiciousLogin,
                    SecurityNotificationEvent::AccountLocked,
                    SecurityNotificationEvent::MfaDisabled,
                    SecurityNotificationEvent::SecurityPolicyUpdated,
                    SecurityNotificationEvent::ImpersonationStarted,
                ],
                channels: vec![NotificationChannel::Email],
            },
            admin_roles: vec!["owner".to_string(), "admin".to_string()],
            whatsapp_template_name: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantPasswordPolicy {
    pub min_length: usize,
    pub max_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special: bool,
    pub special_chars: String,
    pub max_consecutive_chars: usize,
    pub prevent_common_passwords: bool,
    pub history_count: usize,
    pub expiry_days: Option<u32>,
    pub check_breach: bool,
    pub enforcement_mode: EnforcementMode,
    pub min_entropy: f64,
    pub prevent_user_info: bool,
}

impl Default for TenantPasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
            special_chars: "!@#$%^&*()_+-=[]{}|;:,.<>?".to_string(),
            max_consecutive_chars: 3,
            prevent_common_passwords: true,
            history_count: 5,
            expiry_days: None,
            check_breach: true,
            enforcement_mode: EnforcementMode::Block,
            min_entropy: 50.0,
            prevent_user_info: true,
        }
    }
}

impl TenantPasswordPolicy {
    /// Convert to the security module's PasswordPolicy
    pub fn to_security_policy(&self) -> crate::security::PasswordPolicy {
        crate::security::PasswordPolicy {
            min_length: self.min_length,
            max_length: self.max_length,
            require_uppercase: self.require_uppercase,
            require_lowercase: self.require_lowercase,
            require_numbers: self.require_numbers,
            require_special_chars: self.require_special,
            special_chars: self.special_chars.clone(),
            max_consecutive_chars: self.max_consecutive_chars,
            prevent_common_passwords: self.prevent_common_passwords,
            password_history_count: self.history_count,
            expiry_days: self.expiry_days,
            check_breach_database: self.check_breach,
            enforcement_mode: match self.enforcement_mode {
                EnforcementMode::Block => crate::security::EnforcementMode::Block,
                EnforcementMode::Warn => crate::security::EnforcementMode::Warn,
                EnforcementMode::Audit => crate::security::EnforcementMode::Audit,
            },
            min_entropy: self.min_entropy,
            prevent_user_info: self.prevent_user_info,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Block,
    Warn,
    Audit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionLifetime {
    /// Access token lifetime in minutes
    pub access_token_minutes: i64,
    /// Refresh token lifetime in days
    pub refresh_token_days: i64,
    /// Absolute session timeout in hours
    pub absolute_timeout_hours: i64,
    /// Idle timeout in minutes
    pub idle_timeout_minutes: i64,
}

impl Default for SessionLifetime {
    fn default() -> Self {
        Self {
            access_token_minutes: 15,
            refresh_token_days: 7,
            absolute_timeout_hours: 24,
            idle_timeout_minutes: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionLimits {
    /// Maximum concurrent sessions per user
    pub max_concurrent_sessions: usize,
    /// Eviction policy when limit reached
    pub eviction_policy: EvictionPolicy,
    /// Enforce per-IP limits
    pub enforce_for_ip: bool,
    /// Maximum sessions per IP address
    pub max_sessions_per_ip: usize,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: 5,
            eviction_policy: EvictionPolicy::OldestFirst,
            enforce_for_ip: false,
            max_sessions_per_ip: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictionPolicy {
    OldestFirst,
    NewestFirst,
    DenyNew,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MfaSettings {
    /// Require MFA for all users
    pub require_mfa: bool,
    /// Allowed MFA methods
    pub allowed_methods: Vec<String>,
    /// Grace period for MFA setup (days)
    pub grace_period_days: i32,
    /// Require MFA for specific roles
    pub require_mfa_for_roles: Vec<String>,
}

impl Default for MfaSettings {
    fn default() -> Self {
        Self {
            require_mfa: false,
            allowed_methods: vec![
                "totp".to_string(),
                "email".to_string(),
                "sms".to_string(),
                "webauthn".to_string(),
            ],
            grace_period_days: 7,
            require_mfa_for_roles: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LockoutPolicy {
    /// Maximum failed attempts before lockout
    pub max_failed_attempts: i32,
    /// Lockout duration in minutes
    pub lockout_duration_minutes: i32,
    /// Reset counter after minutes of no attempts
    pub reset_after_minutes: i32,
}

impl Default for LockoutPolicy {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration_minutes: 30,
            reset_after_minutes: 60,
        }
    }
}

// ============================================
// 3. Organization Settings
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OrgSettings {
    /// Enable organization/team feature
    pub organizations_enabled: bool,
    /// Users must belong to an organization
    pub membership_required: bool,
    /// Max organizations a user can create
    pub max_organizations_per_user: i32,
    /// Default role for new members
    pub default_org_role: String,
    /// Role assigned to organization creator
    pub creator_role: String,
    /// Allow users to create organizations
    pub allow_user_created_orgs: bool,
    /// Auto-create org for new users
    pub auto_create_first_org: bool,
    /// Enable domain-based auto-join
    pub verified_domains_enabled: bool,
    /// Default member limit per organization
    pub default_membership_limit: i32,
    /// Allow personal accounts (B2C mode)
    pub allow_personal_accounts: bool,
    /// Require approval for org creation
    pub org_creation_approval_required: bool,
}

impl Default for OrgSettings {
    fn default() -> Self {
        Self {
            organizations_enabled: false,
            membership_required: false,
            max_organizations_per_user: 100,
            default_org_role: "member".to_string(),
            creator_role: "admin".to_string(),
            allow_user_created_orgs: true,
            auto_create_first_org: false,
            verified_domains_enabled: false,
            default_membership_limit: 5,
            allow_personal_accounts: true,
            org_creation_approval_required: false,
        }
    }
}

// ============================================
// 4. Branding Settings
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BrandingSettings {
    /// Display name for emails/UI
    pub brand_name: String,
    /// URL to logo
    pub brand_logo_url: Option<String>,
    /// Favicon URL
    pub brand_favicon_url: Option<String>,
    /// Brand primary color (hex)
    pub primary_color: String,
    /// Accent color (hex)
    pub accent_color: String,
    /// Enable dark mode option
    pub dark_mode_enabled: bool,
    /// Custom CSS for hosted pages
    pub custom_css: Option<String>,
    /// Login page layout
    pub login_page_layout: LoginPageLayout,
    /// Custom domain for white-label
    pub custom_domain: Option<String>,
    /// Terms of service URL
    pub terms_of_service_url: Option<String>,
    /// Privacy policy URL
    pub privacy_policy_url: Option<String>,
    /// Support/help link
    pub support_url: Option<String>,
    /// Show "Powered by Vault" branding
    pub show_powered_by: bool,
}

impl Default for BrandingSettings {
    fn default() -> Self {
        Self {
            brand_name: "Vault".to_string(),
            brand_logo_url: None,
            brand_favicon_url: None,
            primary_color: "#0066FF".to_string(),
            accent_color: "#00D4AA".to_string(),
            dark_mode_enabled: true,
            custom_css: None,
            login_page_layout: LoginPageLayout::Centered,
            custom_domain: None,
            terms_of_service_url: None,
            privacy_policy_url: None,
            support_url: None,
            show_powered_by: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginPageLayout {
    Centered,
    Split,
    Sidebar,
}

impl Default for LoginPageLayout {
    fn default() -> Self {
        LoginPageLayout::Centered
    }
}

// ============================================
// 5. Email Settings
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailSettings {
    /// From email address
    pub from_address: String,
    /// From display name
    pub from_name: String,
    /// Reply-to address
    pub reply_to: Option<String>,
    /// Send welcome email on registration
    pub welcome_email_enabled: bool,
    /// Send verification emails
    pub verification_email_enabled: bool,
    /// Allow password reset via email
    pub password_reset_enabled: bool,
    /// Send MFA codes via email
    pub mfa_email_enabled: bool,
    /// Send organization invitation emails
    pub org_invite_email_enabled: bool,
    /// Send security alert emails
    pub security_alert_emails: bool,
    /// Custom email templates
    pub email_templates: HashMap<String, EmailTemplate>,
    /// Custom SMTP configuration
    pub custom_smtp: Option<CustomSmtpConfig>,
}

impl Default for EmailSettings {
    fn default() -> Self {
        Self {
            from_address: "noreply@example.com".to_string(),
            from_name: "Vault".to_string(),
            reply_to: None,
            welcome_email_enabled: true,
            verification_email_enabled: true,
            password_reset_enabled: true,
            mfa_email_enabled: true,
            org_invite_email_enabled: true,
            security_alert_emails: true,
            email_templates: HashMap::new(),
            custom_smtp: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailTemplate {
    pub subject: String,
    pub html_body: Option<String>,
    pub text_body: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password_encrypted: String, // Encrypted
    pub use_tls: bool,
}

// ============================================
// 6. SMS & WhatsApp Settings
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmsProviderType {
    Disabled,
    Twilio,
    AwsSns,
    Mock,
}

impl Default for SmsProviderType {
    fn default() -> Self {
        SmsProviderType::Disabled
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SmsSettings {
    /// Override provider (None = inherit platform)
    pub provider: Option<SmsProviderType>,
    /// Twilio account SID
    pub twilio_account_sid: Option<String>,
    /// Twilio auth token (encrypted)
    pub twilio_auth_token_encrypted: Option<String>,
    /// Twilio from phone number
    pub twilio_from_number: Option<String>,
    /// Override rate limiting (None = inherit)
    pub max_sends_per_phone: Option<u32>,
    pub rate_limit_window_secs: Option<u64>,
    pub code_expiry_minutes: Option<i64>,
    pub code_length: Option<usize>,
    /// WhatsApp overrides (None = inherit platform)
    pub whatsapp: Option<WhatsAppSettings>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WhatsAppSettings {
    pub enabled: Option<bool>,
    pub phone_number_id: Option<String>,
    pub access_token_encrypted: Option<String>,
    pub api_version: Option<String>,
    pub template_name: Option<String>,
    pub language_code: Option<String>,
    pub fallback_to_sms: Option<bool>,
}

// ============================================
// 6. OAuth & SSO Settings
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OAuthSettings {
    /// Configured OAuth providers
    pub oauth_providers: Vec<TenantOAuthProvider>,
    /// Enable SAML/OIDC SSO
    pub sso_enabled: bool,
    /// SSO configuration
    pub sso_settings: SsoSettings,
    /// Auto-redirect to IdP by domain
    pub auto_redirect_sso: bool,
    /// Allow social OAuth
    pub allow_social_logins: bool,
    /// Account linking behavior
    pub account_linking: AccountLinkingMode,
    /// Require verified email for linking
    pub require_verified_email_for_linking: bool,
}

impl Default for OAuthSettings {
    fn default() -> Self {
        Self {
            oauth_providers: vec![],
            sso_enabled: false,
            sso_settings: SsoSettings::default(),
            auto_redirect_sso: false,
            allow_social_logins: true,
            account_linking: AccountLinkingMode::Automatic,
            require_verified_email_for_linking: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantOAuthProvider {
    pub provider_id: String,
    pub display_name: String,
    pub enabled: bool,
    pub client_id: String,
    // client_secret is stored separately/encrypted
    pub scopes: Vec<String>,
    pub custom_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SsoSettings {
    pub saml_enabled: bool,
    pub oidc_enabled: bool,
    pub force_sso_for_domains: Vec<String>,
    pub jit_provisioning: bool,
    pub default_role_on_provision: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountLinkingMode {
    #[default]
    Automatic,
    Manual,
    Disabled,
}

// ============================================
// 7. Localization Settings
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LocalizationSettings {
    /// ISO 639-1 language code
    pub default_language: String,
    /// Available UI languages
    pub supported_languages: Vec<String>,
    /// Default timezone
    pub timezone: String,
    /// Date format preference
    pub date_format: DateFormat,
    /// Time format preference
    pub time_format: TimeFormat,
    /// Enhanced GDPR features
    pub gdpr_compliance_mode: bool,
    /// Data residency region
    pub data_residency_region: Option<DataResidencyRegion>,
}

impl Default for LocalizationSettings {
    fn default() -> Self {
        Self {
            default_language: "en".to_string(),
            supported_languages: vec!["en".to_string()],
            timezone: "UTC".to_string(),
            date_format: DateFormat::Iso,
            time_format: TimeFormat::H24,
            gdpr_compliance_mode: false,
            data_residency_region: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DateFormat {
    #[default]
    Iso,
    Us,
    Eu,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeFormat {
    #[default]
    H24,
    H12,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataResidencyRegion {
    Eu,
    Us,
    Apac,
}

// ============================================
// 8. Webhook Settings
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookSettings {
    /// Enable webhook delivery
    pub webhooks_enabled: bool,
    /// Global webhook endpoints
    pub webhook_endpoints: Vec<WebhookEndpointConfig>,
    /// Default subscribed events
    pub webhook_events: Vec<String>,
    /// Retry configuration
    pub webhook_retries: WebhookRetryConfig,
    /// Signing secret rotation period
    pub signing_secret_rotation_days: i32,
}

impl Default for WebhookSettings {
    fn default() -> Self {
        Self {
            webhooks_enabled: true,
            webhook_endpoints: vec![],
            webhook_events: vec![
                "user.created".to_string(),
                "user.updated".to_string(),
                "user.deleted".to_string(),
                "session.created".to_string(),
                "session.revoked".to_string(),
            ],
            webhook_retries: WebhookRetryConfig::default(),
            signing_secret_rotation_days: 90,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookRetryConfig {
    pub max_attempts: i32,
    pub retry_schedule: Vec<i64>,
    pub timeout_seconds: i64,
}

impl Default for WebhookRetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            retry_schedule: vec![60, 300, 900, 3600],
            timeout_seconds: 30,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpointConfig {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub events: Vec<String>,
    pub secret: String, // Should be encrypted
}

// ============================================
// 9. Privacy Settings
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivacySettings {
    /// Track login analytics
    pub analytics_enabled: bool,
    /// Record session replays
    pub session_recording: bool,
    /// Require explicit consent
    pub consent_required: bool,
    /// Types of consent to collect
    pub consent_types: Vec<String>,
    /// Audit log retention in days
    pub data_retention_days: i64,
    /// Anonymize IP in analytics
    pub anonymize_ip: bool,
    /// Allow data export
    pub allow_data_export: bool,
    /// Allow account deletion
    pub allow_account_deletion: bool,
    /// Grace period before deletion
    pub deletion_grace_period_days: i32,
    /// Require cookie consent
    pub cookie_consent_required: bool,
    /// Minimum age requirement
    pub min_age_requirement: i32,
}

impl Default for PrivacySettings {
    fn default() -> Self {
        Self {
            analytics_enabled: true,
            session_recording: false,
            consent_required: true,
            consent_types: vec!["tos".to_string(), "privacy".to_string()],
            data_retention_days: 365,
            anonymize_ip: false,
            allow_data_export: true,
            allow_account_deletion: true,
            deletion_grace_period_days: 30,
            cookie_consent_required: true,
            min_age_requirement: 13,
        }
    }
}

// ============================================
// 10. Advanced/Developer Settings
// ============================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AdvancedSettings {
    /// Custom JWT claims
    pub jwt_claims: HashMap<String, serde_json::Value>,
    /// Token format
    pub token_format: TokenFormat,
    /// Refresh token rotation policy
    pub refresh_token_rotation: RefreshTokenRotation,
    /// Cookie SameSite attribute
    pub cookie_same_site: CookieSameSite,
    /// Custom cookie domain
    pub cookie_domain: Option<String>,
    /// Secure cookie flag
    pub cookie_secure: bool,
    /// Valid redirect URIs
    pub allowed_callback_urls: Vec<String>,
    /// Valid logout redirect URIs
    pub allowed_logout_urls: Vec<String>,
    /// Validation schema for user metadata
    pub custom_metadata_schema: Option<serde_json::Value>,
    /// Feature flags
    pub feature_flags: HashMap<String, bool>,
    /// API version
    pub api_version: String,
    /// Strict mode (reject unknown fields)
    pub strict_mode: bool,
    /// Enable log streaming for tenant
    pub log_streaming_enabled: bool,
}

impl Default for AdvancedSettings {
    fn default() -> Self {
        Self {
            jwt_claims: HashMap::new(),
            token_format: TokenFormat::Jwt,
            refresh_token_rotation: RefreshTokenRotation::Always,
            cookie_same_site: CookieSameSite::Lax,
            cookie_domain: None,
            cookie_secure: true,
            allowed_callback_urls: vec!["*".to_string()],
            allowed_logout_urls: vec!["*".to_string()],
            custom_metadata_schema: None,
            feature_flags: HashMap::new(),
            api_version: "v1".to_string(),
            strict_mode: false,
            log_streaming_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenFormat {
    #[default]
    Jwt,
    Opaque,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshTokenRotation {
    #[default]
    Always,
    OnDetection,
    Never,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CookieSameSite {
    Strict,
    #[default]
    Lax,
    None,
}

// ============================================
// Settings History
// ============================================

#[derive(Debug, Clone, FromRow)]
pub struct SettingsHistoryRow {
    pub id: String,
    pub tenant_id: String,
    pub changed_by: Option<String>,
    pub change_type: String,
    pub previous_value: serde_json::Value,
    pub new_value: serde_json::Value,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

// ============================================
// Update Request Types
// ============================================

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "category", rename_all = "snake_case")]
pub enum UpdateSettingsRequest {
    Auth { settings: AuthSettings },
    Security { settings: SecuritySettings },
    Org { settings: OrgSettings },
    Branding { settings: BrandingSettings },
    Email { settings: EmailSettings },
    Sms { settings: SmsSettings },
    Oauth { settings: OAuthSettings },
    Localization { settings: LocalizationSettings },
    Webhook { settings: WebhookSettings },
    Privacy { settings: PrivacySettings },
    Advanced { settings: AdvancedSettings },
}

/// Partial update for a single settings category
#[derive(Debug, Clone, Deserialize)]
pub struct PartialUpdateRequest {
    pub category: String,
    pub settings: serde_json::Value,
    pub reason: Option<String>,
}

// ============================================
// Response Types
// ============================================

#[derive(Debug, Clone, Serialize)]
pub struct SettingsResponse {
    pub tenant_id: String,
    pub settings: TenantSettings,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsCategoryResponse<T> {
    pub tenant_id: String,
    pub category: String,
    pub settings: T,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsHistoryResponse {
    pub changes: Vec<SettingsHistoryItem>,
    pub total: i64,
    pub page: i32,
    pub per_page: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsHistoryItem {
    pub id: String,
    pub change_type: String,
    pub changed_by: Option<String>,
    pub reason: Option<String>,
    pub created_at: DateTime<Utc>,
}
