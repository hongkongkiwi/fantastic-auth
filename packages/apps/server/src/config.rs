//! Server configuration

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    /// Server bind address
    #[serde(default = "default_server_host")]
    pub host: String,
    /// Server port
    #[serde(default = "default_server_port")]
    pub port: u16,
    /// Public base URL
    #[serde(default = "default_base_url")]
    pub base_url: String,
    /// Database URL
    pub database_url: String,
    /// Database connection pool settings
    #[serde(default)]
    pub db_pool: DbPoolConfig,
    /// Redis URL
    pub redis_url: Option<String>,
    /// Require TLS for Redis connections (enforces rediss:// scheme)
    #[serde(default)]
    pub redis_require_tls: bool,
    /// JWT configuration
    #[serde(default)]
    pub jwt: JwtConfig,
    /// CORS origins
    #[serde(default)]
    pub cors_origins: Vec<String>,
    /// Rate limiting configuration
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// SMTP configuration
    pub smtp: Option<SmtpConfig>,
    /// OAuth provider configurations
    #[serde(default)]
    pub oauth: OAuthConfigs,
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Security settings
    #[serde(default)]
    pub security: SecurityConfig,
    /// Webhook configuration
    #[serde(default)]
    pub webhook: WebhookConfig,
    /// Feature flags
    #[serde(default)]
    pub features: FeatureFlags,
    /// Observability settings
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// Background job settings
    #[serde(default)]
    pub background_jobs: BackgroundJobsConfig,
    /// TLS configuration
    #[serde(default)]
    pub tls: TlsConfig,
    /// LDAP configuration
    #[serde(default)]
    pub ldap: LdapConfigs,
    /// Custom domain (white-label) configuration
    #[serde(default)]
    pub custom_domains: CustomDomainConfig,
    /// SMS configuration for MFA
    #[serde(default)]
    pub sms: SmsConfig,
    /// WhatsApp configuration for MFA
    #[serde(default)]
    pub whatsapp: WhatsAppConfig,
    /// Web3 authentication configuration
    #[serde(default)]
    pub web3_auth: Web3AuthConfig,
    /// Internal API key for /api/v1/internal routes (superadmin only)
    #[serde(default)]
    pub internal_api_key: Option<String>,
    /// Tenant ID used for internal admin context (must be a valid tenant UUID)
    #[serde(default)]
    pub internal_admin_tenant_id: Option<String>,
}

/// Database pool configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DbPoolConfig {
    #[serde(default = "default_db_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_db_min_connections")]
    pub min_connections: u32,
    #[serde(default = "default_db_connect_timeout")]
    pub connect_timeout: u64,
}

impl Default for DbPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: default_db_max_connections(),
            min_connections: default_db_min_connections(),
            connect_timeout: default_db_connect_timeout(),
        }
    }
}

/// JWT configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    #[serde(default = "default_jwt_issuer")]
    pub issuer: String,
    #[serde(default = "default_jwt_audience")]
    pub audience: String,
    #[serde(default = "default_access_token_expiry")]
    pub access_token_expiry_minutes: i64,
    #[serde(default = "default_refresh_token_expiry")]
    pub refresh_token_expiry_days: i64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            issuer: default_jwt_issuer(),
            audience: default_jwt_audience(),
            access_token_expiry_minutes: default_access_token_expiry(),
            refresh_token_expiry_days: default_refresh_token_expiry(),
        }
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    /// Requests per minute for auth endpoints
    #[serde(default = "default_auth_rate_limit")]
    pub auth_per_minute: u32,
    /// Requests per minute for general API
    #[serde(default = "default_api_rate_limit")]
    pub api_per_minute: u32,
    /// Requests per hour for anonymous session creation (per IP)
    #[serde(default = "default_anonymous_rate_limit")]
    pub anonymous_per_hour: u32,
    /// Window size in seconds
    #[serde(default = "default_rate_limit_window")]
    pub window_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            auth_per_minute: default_auth_rate_limit(),
            api_per_minute: default_api_rate_limit(),
            anonymous_per_hour: default_anonymous_rate_limit(),
            window_seconds: default_rate_limit_window(),
        }
    }
}

/// SMTP configuration
#[derive(Clone, Deserialize, Serialize)]
pub struct SmtpConfig {
    /// SMTP host
    pub host: String,
    /// SMTP port
    pub port: u16,
    /// SMTP username
    pub username: String,
    /// SMTP password
    pub password: String,
    /// From address
    pub from_address: String,
    /// From name
    #[serde(default = "default_from_name")]
    pub from_name: String,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for SmtpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("from_address", &"[REDACTED]")
            .field("from_name", &self.from_name)
            .finish()
    }
}

/// OAuth provider configurations - 30+ providers supported
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct OAuthConfigs {
    // Existing providers
    pub google: Option<OAuthProviderConfig>,
    pub github: Option<OAuthProviderConfig>,
    pub microsoft: Option<OAuthProviderConfig>,
    pub apple: Option<OAuthProviderConfig>,
    pub discord: Option<OAuthProviderConfig>,
    pub slack: Option<OAuthProviderConfig>,
    
    // Social/Consumer
    pub facebook: Option<OAuthProviderConfig>,
    pub twitter: Option<OAuthProviderConfig>,
    pub instagram: Option<OAuthProviderConfig>,
    pub tiktok: Option<OAuthProviderConfig>,
    pub snapchat: Option<OAuthProviderConfig>,
    pub pinterest: Option<OAuthProviderConfig>,
    pub reddit: Option<OAuthProviderConfig>,
    pub twitch: Option<OAuthProviderConfig>,
    pub spotify: Option<OAuthProviderConfig>,
    
    // Professional
    pub linkedin: Option<OAuthProviderConfig>,
    
    // Developer/Tech
    pub gitlab: Option<OAuthProviderConfig>,
    pub bitbucket: Option<OAuthProviderConfig>,
    pub digitalocean: Option<OAuthProviderConfig>,
    pub heroku: Option<OAuthProviderConfig>,
    pub vercel: Option<OAuthProviderConfig>,
    pub netlify: Option<OAuthProviderConfig>,
    pub cloudflare: Option<OAuthProviderConfig>,
    
    // Enterprise
    pub salesforce: Option<OAuthProviderConfig>,
    pub hubspot: Option<OAuthProviderConfig>,
    pub zendesk: Option<OAuthProviderConfig>,
    pub notion: Option<OAuthProviderConfig>,
    pub figma: Option<OAuthProviderConfig>,
    pub linear: Option<OAuthProviderConfig>,
    pub atlassian: Option<OAuthProviderConfig>,
    pub okta: Option<OktaOAuthConfig>,
    
    // Regional
    pub wechat: Option<WeChatOAuthConfig>,
    pub line: Option<OAuthProviderConfig>,
    pub kakaotalk: Option<OAuthProviderConfig>,
    pub vkontakte: Option<OAuthProviderConfig>,
    pub yandex: Option<OAuthProviderConfig>,
}

/// Single OAuth provider configuration
#[derive(Clone, Deserialize, Serialize)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    /// Additional Apple-specific configuration (optional)
    #[serde(flatten)]
    pub apple_config: Option<AppleOAuthConfig>,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for OAuthProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthProviderConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("apple_config", &self.apple_config)
            .finish()
    }
}

/// Apple Sign-In specific configuration
#[derive(Clone, Deserialize, Serialize)]
pub struct AppleOAuthConfig {
    /// Apple Team ID
    pub team_id: String,
    /// Private Key ID
    pub key_id: String,
    /// Private Key contents (PEM format)
    pub private_key: String,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for AppleOAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleOAuthConfig")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Okta OAuth configuration
/// Okta requires a custom domain for each organization
#[derive(Clone, Deserialize, Serialize)]
pub struct OktaOAuthConfig {
    /// Okta domain (e.g., "dev-123456.okta.com")
    pub domain: String,
    /// Client ID
    pub client_id: String,
    /// Client Secret
    pub client_secret: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Authorization server ID (optional, defaults to "default")
    pub auth_server_id: Option<String>,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for OktaOAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OktaOAuthConfig")
            .field("domain", &self.domain)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("auth_server_id", &self.auth_server_id)
            .finish()
    }
}

/// WeChat OAuth configuration
/// WeChat uses different endpoints for web vs mobile
#[derive(Clone, Deserialize, Serialize)]
pub struct WeChatOAuthConfig {
    /// App ID (acts as client_id)
    pub app_id: String,
    /// App Secret
    pub app_secret: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Use QR code login (web) vs mobile login
    #[serde(default = "default_true")]
    pub use_qr_login: bool,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for WeChatOAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WeChatOAuthConfig")
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("use_qr_login", &self.use_qr_login)
            .finish()
    }
}

/// Zendesk OAuth configuration
/// Zendesk uses subdomain-based endpoints
#[derive(Clone, Deserialize, Serialize)]
pub struct ZendeskOAuthConfig {
    /// Zendesk subdomain (e.g., "mycompany" for mycompany.zendesk.com)
    pub subdomain: String,
    /// Client ID
    pub client_id: String,
    /// Client Secret
    pub client_secret: String,
    /// Redirect URI
    pub redirect_uri: String,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for ZendeskOAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZendeskOAuthConfig")
            .field("subdomain", &self.subdomain)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// Bot protection provider type
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BotProtectionProvider {
    /// Disabled (for development)
    #[default]
    Disabled,
    /// Cloudflare Turnstile
    Turnstile,
    /// hCaptcha
    Hcaptcha,
}

/// Session eviction policy when limit is reached
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EvictionPolicy {
    /// Revoke oldest session(s) to make room
    #[default]
    OldestFirst,
    /// Revoke newest (current login fails)
    NewestFirst,
    /// Deny new login if limit reached
    DenyNew,
}

impl std::str::FromStr for EvictionPolicy {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "oldest_first" | "oldestfirst" => Ok(Self::OldestFirst),
            "newest_first" | "newestfirst" => Ok(Self::NewestFirst),
            "deny_new" | "denynew" => Ok(Self::DenyNew),
            _ => Err(format!("Unknown eviction policy: {}", s)),
        }
    }
}

/// Session limits configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionLimitsConfig {
    /// Maximum concurrent sessions per user (default: 5)
    #[serde(default = "default_max_concurrent_sessions")]
    pub max_concurrent_sessions: usize,
    /// Eviction policy when limit reached (default: OldestFirst)
    #[serde(default)]
    pub eviction_policy: EvictionPolicy,
    /// Whether to enforce per-IP limits (default: false)
    #[serde(default = "default_enforce_for_ip")]
    pub enforce_for_ip: bool,
    /// Maximum sessions per IP address (default: 3)
    #[serde(default = "default_max_sessions_per_ip")]
    pub max_sessions_per_ip: usize,
}

impl Default for SessionLimitsConfig {
    fn default() -> Self {
        Self {
            max_concurrent_sessions: default_max_concurrent_sessions(),
            eviction_policy: EvictionPolicy::default(),
            enforce_for_ip: default_enforce_for_ip(),
            max_sessions_per_ip: default_max_sessions_per_ip(),
        }
    }
}

/// Bot protection endpoint settings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BotProtectionEndpoints {
    /// Require CAPTCHA for registration
    #[serde(default = "default_bot_protection_enabled")]
    pub register: bool,
    /// Require CAPTCHA for login after failed attempts
    #[serde(default = "default_bot_protection_enabled")]
    pub login: bool,
    /// Require CAPTCHA for forgot password
    #[serde(default = "default_bot_protection_enabled")]
    pub forgot_password: bool,
    /// Require CAPTCHA for magic link
    #[serde(default = "default_bot_protection_enabled")]
    pub magic_link: bool,
    /// Require CAPTCHA for OAuth
    #[serde(default = "default_bot_protection_disabled")]
    pub oauth: bool,
}

impl Default for BotProtectionEndpoints {
    fn default() -> Self {
        Self {
            register: default_bot_protection_enabled(),
            login: default_bot_protection_enabled(),
            forgot_password: default_bot_protection_enabled(),
            magic_link: default_bot_protection_enabled(),
            oauth: default_bot_protection_disabled(),
        }
    }
}

/// Bot protection configuration
#[derive(Clone, Deserialize, Serialize)]
pub struct BotProtectionConfig {
    /// Provider type (disabled, turnstile, hcaptcha)
    #[serde(default)]
    pub provider: BotProtectionProvider,
    /// Secret key for verification
    pub secret_key: Option<String>,
    /// Site key for frontend
    pub site_key: Option<String>,
    /// Endpoint-specific settings
    #[serde(default)]
    pub endpoints: BotProtectionEndpoints,
    /// Failed login attempts before requiring CAPTCHA (0 = always required if enabled)
    #[serde(default = "default_login_attempts_before_captcha")]
    pub login_attempts_before_captcha: u32,
    /// Window for failed login attempts in seconds
    #[serde(default = "default_failed_login_window_seconds")]
    pub failed_login_window_seconds: u64,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for BotProtectionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BotProtectionConfig")
            .field("provider", &self.provider)
            .field("secret_key", &"[REDACTED]")
            .field("site_key", &self.site_key)
            .field("endpoints", &self.endpoints)
            .field("login_attempts_before_captcha", &self.login_attempts_before_captcha)
            .field("failed_login_window_seconds", &self.failed_login_window_seconds)
            .finish()
    }
}

impl Default for BotProtectionConfig {
    fn default() -> Self {
        Self {
            provider: BotProtectionProvider::default(),
            secret_key: None,
            site_key: None,
            endpoints: BotProtectionEndpoints::default(),
            login_attempts_before_captcha: default_login_attempts_before_captcha(),
            failed_login_window_seconds: default_failed_login_window_seconds(),
        }
    }
}

impl BotProtectionConfig {
    /// Check if bot protection is enabled
    pub fn is_enabled(&self) -> bool {
        self.provider != BotProtectionProvider::Disabled
            && self.secret_key.is_some()
            && self.site_key.is_some()
    }

    /// Get site key (returns empty string if not configured)
    pub fn site_key(&self) -> &str {
        self.site_key.as_deref().unwrap_or("")
    }

    /// Get secret key (returns empty string if not configured)
    pub fn secret_key(&self) -> &str {
        self.secret_key.as_deref().unwrap_or("")
    }
}

/// Geographic restriction policy type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoRestrictionPolicy {
    /// Only allow countries in the list
    AllowList,
    /// Block countries in the list
    BlockList,
}

impl Default for GeoRestrictionPolicy {
    fn default() -> Self {
        GeoRestrictionPolicy::BlockList
    }
}

/// Geographic restriction configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeoRestrictionConfig {
    /// Whether geo restrictions are enabled
    #[serde(default)]
    pub enabled: bool,
    /// Policy type: allow_list or block_list
    #[serde(default)]
    pub policy: GeoRestrictionPolicy,
    /// List of country codes (ISO 3166-1 alpha-2)
    #[serde(default)]
    pub country_list: Vec<String>,
    /// Whether to allow VPN/proxy connections
    #[serde(default = "default_allow_vpn")]
    pub allow_vpn: bool,
    /// Whether to block anonymous proxies
    #[serde(default = "default_block_anonymous_proxies")]
    pub block_anonymous_proxies: bool,
    /// Path to MaxMind GeoIP2 database file
    #[serde(default = "default_geoip_db_path")]
    pub geoip_db_path: String,
    /// Redis cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u64,
}

impl Default for GeoRestrictionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            policy: GeoRestrictionPolicy::default(),
            country_list: Vec::new(),
            allow_vpn: default_allow_vpn(),
            block_anonymous_proxies: default_block_anonymous_proxies(),
            geoip_db_path: default_geoip_db_path(),
            cache_ttl_seconds: default_cache_ttl(),
        }
    }
}

fn default_allow_vpn() -> bool {
    true
}

fn default_block_anonymous_proxies() -> bool {
    false
}

fn default_geoip_db_path() -> String {
    "/var/lib/GeoIP/GeoLite2-Country.mmdb".to_string()
}

fn default_cache_ttl() -> u64 {
    86400 // 24 hours
}

/// Session binding level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionBindingLevel {
    /// No binding
    #[default]
    None,
    /// Advisory - log and notify but allow
    Advisory,
    /// Strict - terminate session on mismatch
    Strict,
}

impl SessionBindingLevel {
    /// Convert to string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Advisory => "advisory",
            Self::Strict => "strict",
        }
    }
}

/// Session binding configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionBindingConfig {
    /// Binding level (none, advisory, strict)
    #[serde(default)]
    pub level: SessionBindingLevel,
    /// Whether to bind sessions to IP address
    #[serde(default = "default_bind_to_ip")]
    pub bind_to_ip: bool,
    /// Whether to bind sessions to device fingerprint
    #[serde(default = "default_bind_to_device")]
    pub bind_to_device: bool,
    /// Notify user on new device detection
    #[serde(default = "default_notify_on_new_device")]
    pub notify_on_new_device: bool,
    /// Require email verification for new devices
    #[serde(default = "default_require_verification_new_device")]
    pub require_verification_new_device: bool,
    /// Ignore private IP changes
    #[serde(default = "default_ignore_private_ip")]
    pub ignore_private_ip_changes: bool,
    /// Maximum violations before auto-revocation
    #[serde(default = "default_max_violations")]
    pub max_violations_before_revoke: u32,
}

impl Default for SessionBindingConfig {
    fn default() -> Self {
        Self {
            level: SessionBindingLevel::default(),
            bind_to_ip: default_bind_to_ip(),
            bind_to_device: default_bind_to_device(),
            notify_on_new_device: default_notify_on_new_device(),
            require_verification_new_device: default_require_verification_new_device(),
            ignore_private_ip_changes: default_ignore_private_ip(),
            max_violations_before_revoke: default_max_violations(),
        }
    }
}

fn default_bind_to_ip() -> bool { true }
fn default_bind_to_device() -> bool { true }
fn default_notify_on_new_device() -> bool { true }
fn default_require_verification_new_device() -> bool { false }
fn default_ignore_private_ip() -> bool { true }
fn default_max_violations() -> u32 { 5 }
fn default_data_encryption_provider() -> DataEncryptionProvider { DataEncryptionProvider::Local }
fn default_kms_context_key() -> String { "tenant_id".to_string() }

/// Security configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    #[serde(default = "default_password_min_length")]
    pub password_min_length: usize,
    #[serde(default = "default_session_expiry_hours")]
    pub session_expiry_hours: i64,
    #[serde(default = "default_secure_cookies")]
    pub secure_cookies: bool,
    #[serde(default = "default_bcrypt_cost")]
    pub bcrypt_cost: u32,
    /// Bot protection configuration
    #[serde(default)]
    pub bot_protection: BotProtectionConfig,
    /// Session limits configuration
    #[serde(default)]
    pub session_limits: SessionLimitsConfig,
    /// Password policy configuration
    #[serde(default)]
    pub password_policy: PasswordPolicyConfig,
    /// Geographic restriction configuration
    #[serde(default)]
    pub geo_restriction: GeoRestrictionConfig,
    /// Session binding configuration
    #[serde(default)]
    pub session_binding: SessionBindingConfig,
    /// Data encryption configuration (per-tenant DEKs)
    #[serde(default)]
    pub data_encryption: DataEncryptionConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            password_min_length: default_password_min_length(),
            session_expiry_hours: default_session_expiry_hours(),
            secure_cookies: default_secure_cookies(),
            bcrypt_cost: default_bcrypt_cost(),
            bot_protection: BotProtectionConfig::default(),
            session_limits: SessionLimitsConfig::default(),
            password_policy: PasswordPolicyConfig::default(),
            geo_restriction: GeoRestrictionConfig::default(),
            session_binding: SessionBindingConfig::default(),
            data_encryption: DataEncryptionConfig::default(),
        }
    }
}

/// Data encryption configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DataEncryptionConfig {
    #[serde(default = "default_data_encryption_provider")]
    pub provider: DataEncryptionProvider,
    #[serde(default)]
    pub aws_kms: AwsKmsConfig,
    #[serde(default)]
    pub azure_kv: AzureKeyVaultConfig,
    #[serde(default)]
    pub gcp_kms: GcpKmsConfig,
    #[serde(default)]
    pub alicloud_kms: AlicloudKmsConfig,
    #[serde(default)]
    pub oracle_kms: OracleKmsConfig,
    #[serde(default)]
    pub dek_cache: DekCacheConfig,
}

impl Default for DataEncryptionConfig {
    fn default() -> Self {
        Self {
            provider: default_data_encryption_provider(),
            aws_kms: AwsKmsConfig::default(),
            azure_kv: AzureKeyVaultConfig::default(),
            gcp_kms: GcpKmsConfig::default(),
            alicloud_kms: AlicloudKmsConfig::default(),
            oracle_kms: OracleKmsConfig::default(),
            dek_cache: DekCacheConfig::default(),
        }
    }
}

/// Data encryption provider (envelope-wrapped DEK)
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DataEncryptionProvider {
    #[serde(alias = "kms_emulator")]
    #[default]
    Local,
    AwsKms,
    AzureKv,
    GcpKms,
    AlicloudKms,
    OracleKms,
}

/// AWS KMS configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AwsKmsConfig {
    pub key_id: Option<String>,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    #[serde(default = "default_kms_context_key")]
    pub tenant_context_key: String,
}

impl Default for AwsKmsConfig {
    fn default() -> Self {
        Self {
            key_id: None,
            region: None,
            endpoint: None,
            tenant_context_key: default_kms_context_key(),
        }
    }
}

/// Azure Key Vault configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AzureKeyVaultConfig {
    pub vault_url: Option<String>,
    pub key_name: Option<String>,
    pub key_version: Option<String>,
    #[serde(default = "default_kms_context_key")]
    pub tenant_context_key: String,
}

impl Default for AzureKeyVaultConfig {
    fn default() -> Self {
        Self {
            vault_url: None,
            key_name: None,
            key_version: None,
            tenant_context_key: default_kms_context_key(),
        }
    }
}

/// GCP KMS configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GcpKmsConfig {
    /// Full cryptoKey resource name
    /// Example: projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY
    pub key_name: Option<String>,
    #[serde(default = "default_kms_context_key")]
    pub tenant_context_key: String,
}

impl Default for GcpKmsConfig {
    fn default() -> Self {
        Self {
            key_name: None,
            tenant_context_key: default_kms_context_key(),
        }
    }
}

/// Alibaba Cloud KMS configuration
#[derive(Clone, Deserialize, Serialize)]
pub struct AlicloudKmsConfig {
    pub key_id: Option<String>,
    pub access_key_id: Option<String>,
    pub access_key_secret: Option<String>,
    pub region: Option<String>,
    pub endpoint: Option<String>,
    #[serde(default = "default_kms_context_key")]
    pub tenant_context_key: String,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for AlicloudKmsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlicloudKmsConfig")
            .field("key_id", &self.key_id)
            .field("access_key_id", &self.access_key_id)
            .field("access_key_secret", &"[REDACTED]")
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("tenant_context_key", &"[REDACTED]")
            .finish()
    }
}

impl Default for AlicloudKmsConfig {
    fn default() -> Self {
        Self {
            key_id: None,
            access_key_id: None,
            access_key_secret: None,
            region: None,
            endpoint: None,
            tenant_context_key: default_kms_context_key(),
        }
    }
}

/// Oracle OCI Vault KMS configuration
#[derive(Clone, Deserialize, Serialize)]
pub struct OracleKmsConfig {
    /// Crypto endpoint (data plane), e.g. https://<vault>.crypto.kms.<region>.oraclecloud.com
    pub crypto_endpoint: Option<String>,
    /// Key OCID
    pub key_id: Option<String>,
    /// Optional key version OCID
    pub key_version_id: Option<String>,
    /// Tenancy OCID
    pub tenancy_ocid: Option<String>,
    /// User OCID
    pub user_ocid: Option<String>,
    /// Fingerprint for API key
    pub key_fingerprint: Option<String>,
    /// Private key PEM contents
    pub private_key_pem: Option<String>,
    #[serde(default = "default_kms_context_key")]
    pub tenant_context_key: String,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for OracleKmsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OracleKmsConfig")
            .field("crypto_endpoint", &self.crypto_endpoint)
            .field("key_id", &self.key_id)
            .field("key_version_id", &self.key_version_id)
            .field("tenancy_ocid", &self.tenancy_ocid)
            .field("user_ocid", &self.user_ocid)
            .field("key_fingerprint", &"[REDACTED]")
            .field("private_key_pem", &"[REDACTED]")
            .field("tenant_context_key", &"[REDACTED]")
            .finish()
    }
}

impl Default for OracleKmsConfig {
    fn default() -> Self {
        Self {
            crypto_endpoint: None,
            key_id: None,
            key_version_id: None,
            tenancy_ocid: None,
            user_ocid: None,
            key_fingerprint: None,
            private_key_pem: None,
            tenant_context_key: default_kms_context_key(),
        }
    }
}

/// DEK cache configuration (in-memory + Redis)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DekCacheConfig {
    #[serde(default = "default_dek_cache_ttl_minutes")]
    pub ttl_minutes: u64,
    #[serde(default = "default_dek_cache_redis_enabled")]
    pub redis_enabled: bool,
}

impl Default for DekCacheConfig {
    fn default() -> Self {
        Self {
            ttl_minutes: default_dek_cache_ttl_minutes(),
            redis_enabled: default_dek_cache_redis_enabled(),
        }
    }
}

fn default_dek_cache_ttl_minutes() -> u64 {
    15
}
fn default_dek_cache_redis_enabled() -> bool {
    true
}

/// Webhook configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookConfig {
    #[serde(default = "default_webhook_retry_attempts")]
    pub retry_attempts: u32,
    /// Retry schedule in seconds (per attempt)
    #[serde(default = "default_webhook_retry_schedule_seconds")]
    pub retry_schedule_seconds: Vec<u64>,
    /// Retry jitter factor (0.0 - 1.0)
    #[serde(default = "default_webhook_retry_jitter")]
    pub retry_jitter: f32,
    /// Overload penalty in seconds for timeouts/429s
    #[serde(default = "default_webhook_overload_penalty_seconds")]
    pub overload_penalty_seconds: u64,
    #[serde(default = "default_webhook_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_webhook_batch_size")]
    pub batch_size: usize,
    /// Worker poll interval in seconds
    #[serde(default = "default_webhook_worker_poll_interval_seconds")]
    pub worker_poll_interval_seconds: u64,
    /// Maximum payload size in bytes
    #[serde(default = "default_webhook_max_payload_size")]
    pub max_payload_size: usize,
    /// Maximum response body size in bytes to store
    #[serde(default = "default_webhook_max_response_body_bytes")]
    pub max_response_body_bytes: usize,
    /// In-progress lease timeout in seconds
    #[serde(default = "default_webhook_in_progress_timeout_seconds")]
    pub in_progress_timeout_seconds: u64,
    /// Enable webhook worker
    #[serde(default = "default_webhook_enabled")]
    pub enabled: bool,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            retry_attempts: default_webhook_retry_attempts(),
            retry_schedule_seconds: default_webhook_retry_schedule_seconds(),
            retry_jitter: default_webhook_retry_jitter(),
            overload_penalty_seconds: default_webhook_overload_penalty_seconds(),
            timeout_seconds: default_webhook_timeout_seconds(),
            batch_size: default_webhook_batch_size(),
            worker_poll_interval_seconds: default_webhook_worker_poll_interval_seconds(),
            max_payload_size: default_webhook_max_payload_size(),
            max_response_body_bytes: default_webhook_max_response_body_bytes(),
            in_progress_timeout_seconds: default_webhook_in_progress_timeout_seconds(),
            enabled: default_webhook_enabled(),
        }
    }
}

/// Feature flags
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeatureFlags {
    #[serde(default = "default_enable_email_verification")]
    pub enable_email_verification: bool,
    #[serde(default = "default_enable_mfa_default")]
    pub enable_mfa_default: bool,
    #[serde(default = "default_enable_oauth_signup")]
    pub enable_oauth_signup: bool,
    #[serde(default = "default_dev_skip_email")]
    pub dev_skip_email: bool,
    #[serde(default = "default_dev_auto_verify_email")]
    pub dev_auto_verify_email: bool,
}

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            enable_email_verification: default_enable_email_verification(),
            enable_mfa_default: default_enable_mfa_default(),
            enable_oauth_signup: default_enable_oauth_signup(),
            dev_skip_email: default_dev_skip_email(),
            dev_auto_verify_email: default_dev_auto_verify_email(),
        }
    }
}

/// Observability configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    #[serde(default = "default_otel_service_name")]
    pub otel_service_name: String,
    #[serde(default = "default_otel_service_version")]
    pub otel_service_version: String,
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
}

/// Background job configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BackgroundJobsConfig {
    #[serde(default)]
    pub audit_log_rotation: Option<AuditLogRotationConfig>,
    #[serde(default)]
    pub audit_log_prune: Option<AuditLogPruneConfig>,
    #[serde(default)]
    pub audit_log_retention: Option<AuditLogRetentionConfig>,
    #[serde(default)]
    pub data_encryption_migration: Option<DataEncryptionMigrationConfig>,
}

impl Default for BackgroundJobsConfig {
    fn default() -> Self {
        Self {
            audit_log_rotation: None,
            audit_log_prune: None,
            audit_log_retention: Some(AuditLogRetentionConfig {
                interval_minutes: default_audit_log_retention_interval_minutes(),
            }),
            data_encryption_migration: None,
        }
    }
}

/// Audit log retention cleanup configuration (database audit_logs)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditLogRetentionConfig {
    /// Interval in minutes between cleanup runs
    #[serde(default = "default_audit_log_retention_interval_minutes")]
    pub interval_minutes: u64,
}

/// Audit log rotation configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditLogRotationConfig {
    /// Path to audit log file (JSONL)
    pub path: String,
    /// Max size in MB before rotation
    #[serde(default = "default_audit_log_max_size_mb")]
    pub max_size_mb: u64,
    /// Rotation interval in minutes
    #[serde(default = "default_audit_log_interval_minutes")]
    pub interval_minutes: u64,
    /// Number of rotated files to keep
    #[serde(default = "default_audit_log_keep_files")]
    pub keep_files: usize,
}

/// Audit log prune configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditLogPruneConfig {
    /// Path to audit log file (JSONL)
    pub path: String,
    /// Retention in days
    #[serde(default = "default_audit_log_retention_days")]
    pub retention_days: u64,
    /// Prune interval in minutes
    #[serde(default = "default_audit_log_prune_interval_minutes")]
    pub interval_minutes: u64,
}

/// Data encryption migration configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DataEncryptionMigrationConfig {
    /// Run migration job (default: false when not configured)
    #[serde(default = "default_data_encryption_migration_enabled")]
    pub enabled: bool,
    /// Interval in minutes between runs
    #[serde(default = "default_data_encryption_migration_interval_minutes")]
    pub interval_minutes: u64,
}

fn default_data_encryption_migration_enabled() -> bool {
    true
}
fn default_data_encryption_migration_interval_minutes() -> u64 {
    60
}

fn default_audit_log_max_size_mb() -> u64 {
    50
}
fn default_audit_log_interval_minutes() -> u64 {
    10
}
fn default_audit_log_keep_files() -> usize {
    5
}
fn default_audit_log_retention_days() -> u64 {
    30
}
fn default_audit_log_prune_interval_minutes() -> u64 {
    60
}

fn default_audit_log_retention_interval_minutes() -> u64 {
    1440
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            otel_service_name: default_otel_service_name(),
            otel_service_version: default_otel_service_version(),
            metrics_port: default_metrics_port(),
        }
    }
}

// Default functions
fn default_server_host() -> String {
    "0.0.0.0".to_string()
}
fn default_server_port() -> u16 {
    3000
}
fn default_base_url() -> String {
    "http://localhost:3000".to_string()
}
fn default_jwt_issuer() -> String {
    "vault".to_string()
}
fn default_jwt_audience() -> String {
    "vault-api".to_string()
}
fn default_access_token_expiry() -> i64 {
    15
}
fn default_refresh_token_expiry() -> i64 {
    7
}
fn default_auth_rate_limit() -> u32 {
    5
}
fn default_api_rate_limit() -> u32 {
    100
}
fn default_anonymous_rate_limit() -> u32 {
    10 // 10 anonymous sessions per hour per IP
}
fn default_rate_limit_window() -> u64 {
    60
}
fn default_from_name() -> String {
    "Vault".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_db_max_connections() -> u32 {
    20
}
fn default_db_min_connections() -> u32 {
    5
}
fn default_db_connect_timeout() -> u64 {
    30
}
fn default_password_min_length() -> usize {
    12
}
fn default_session_expiry_hours() -> i64 {
    168
}
fn default_secure_cookies() -> bool {
    true
}
fn default_bcrypt_cost() -> u32 {
    12
}
fn default_webhook_retry_attempts() -> u32 {
    5
}
fn default_webhook_retry_schedule_seconds() -> Vec<u64> {
    vec![60, 300, 900, 3600]
}
fn default_webhook_retry_jitter() -> f32 {
    0.2
}
fn default_webhook_overload_penalty_seconds() -> u64 {
    60
}
fn default_webhook_timeout_seconds() -> u64 {
    30
}
fn default_webhook_batch_size() -> usize {
    100
}
fn default_webhook_worker_poll_interval_seconds() -> u64 {
    30
}
fn default_webhook_max_payload_size() -> usize {
    1_000_000
}
fn default_webhook_max_response_body_bytes() -> usize {
    20_000
}
fn default_webhook_in_progress_timeout_seconds() -> u64 {
    300
}
fn default_webhook_enabled() -> bool {
    true
}
fn default_enable_email_verification() -> bool {
    true
}
fn default_enable_mfa_default() -> bool {
    false
}
fn default_enable_oauth_signup() -> bool {
    true
}
fn default_dev_skip_email() -> bool {
    false
}
fn default_dev_auto_verify_email() -> bool {
    false
}
fn default_otel_service_name() -> String {
    "vault-auth".to_string()
}
fn default_otel_service_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
fn default_metrics_port() -> u16 {
    9090
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> anyhow::Result<Self> {
        // Load from .env file if present
        dotenvy::dotenv().ok();

        // Build config with environment variables
        let mut builder = config::Config::builder()
            .add_source(config::Environment::with_prefix("VAULT").separator("_"));

        // Load from file if specified
        if let Ok(config_file) = std::env::var("VAULT_CONFIG_FILE") {
            builder = builder.add_source(config::File::with_name(&config_file));
        }

        let cfg = builder.build()?;
        let config: Config = cfg.try_deserialize()?;

        // Validate
        config.validate()?;

        Ok(config)
    }

    /// Validate configuration
    fn validate(&self) -> anyhow::Result<()> {
        // Required fields
        if self.database_url.is_empty() {
            anyhow::bail!("DATABASE_URL is required");
        }

        if self.security.password_min_length < 8 {
            anyhow::bail!("password_min_length must be at least 8");
        }

        // Validate SMTP if configured
        if let Some(ref smtp) = self.smtp {
            if smtp.host.is_empty() {
                anyhow::bail!("SMTP host is required when SMTP is configured");
            }
        }

        if self.webhook.retry_schedule_seconds.is_empty() {
            anyhow::bail!("webhook.retry_schedule_seconds must not be empty");
        }

        if !(0.0..=1.0).contains(&self.webhook.retry_jitter) {
            anyhow::bail!("webhook.retry_jitter must be between 0.0 and 1.0");
        }

        match self.security.data_encryption.provider {
            DataEncryptionProvider::Local => {}
            DataEncryptionProvider::AwsKms => {
                if self.security.data_encryption.aws_kms.key_id.is_none() {
                    anyhow::bail!("security.data_encryption.aws_kms.key_id is required for AWS KMS");
                }
            }
            DataEncryptionProvider::AzureKv => {
                if self.security.data_encryption.azure_kv.vault_url.is_none() {
                    anyhow::bail!(
                        "security.data_encryption.azure_kv.vault_url is required for Azure Key Vault"
                    );
                }
                if self.security.data_encryption.azure_kv.key_name.is_none() {
                    anyhow::bail!(
                        "security.data_encryption.azure_kv.key_name is required for Azure Key Vault"
                    );
                }
            }
            DataEncryptionProvider::GcpKms => {
                if self.security.data_encryption.gcp_kms.key_name.is_none() {
                    anyhow::bail!(
                        "security.data_encryption.gcp_kms.key_name is required for GCP KMS"
                    );
                }
            }
            DataEncryptionProvider::AlicloudKms => {
                if self.security.data_encryption.alicloud_kms.key_id.is_none() {
                    anyhow::bail!(
                        "security.data_encryption.alicloud_kms.key_id is required for Alicloud KMS"
                    );
                }
                if self.security.data_encryption.alicloud_kms.access_key_id.is_none()
                    || self.security.data_encryption.alicloud_kms.access_key_secret.is_none()
                {
                    anyhow::bail!(
                        "security.data_encryption.alicloud_kms.access_key_id and access_key_secret are required"
                    );
                }
            }
            DataEncryptionProvider::OracleKms => {
                let oracle = &self.security.data_encryption.oracle_kms;
                if oracle.crypto_endpoint.is_none()
                    || oracle.key_id.is_none()
                    || oracle.tenancy_ocid.is_none()
                    || oracle.user_ocid.is_none()
                    || oracle.key_fingerprint.is_none()
                    || oracle.private_key_pem.is_none()
                {
                    anyhow::bail!(
                        "oracle_kms requires crypto_endpoint, key_id, tenancy_ocid, user_ocid, key_fingerprint, private_key_pem"
                    );
                }
            }
        }

        if self.internal_api_key.is_some() && self.internal_admin_tenant_id.is_none() {
            anyhow::bail!("internal_admin_tenant_id is required when internal_api_key is set");
        }

        // Validate Redis TLS configuration
        if self.redis_require_tls {
            if let Some(ref redis_url) = self.redis_url {
                if !redis_url.starts_with("rediss://") {
                    anyhow::bail!(
                        "redis_require_tls is enabled but REDIS_URL does not use rediss:// scheme. \
                         When redis_require_tls is true, the Redis URL must use the rediss:// scheme for TLS encryption."
                    );
                }
            } else {
                anyhow::bail!("redis_require_tls is enabled but no REDIS_URL is configured");
            }
        }

        if let Some(ref tenant_id) = self.internal_admin_tenant_id {
            if uuid::Uuid::parse_str(tenant_id).is_err() {
                anyhow::bail!("internal_admin_tenant_id must be a valid UUID");
            }
        }

        // Validate WhatsApp configuration
        self.whatsapp.validate()?;

        Ok(())
    }

    /// Get server socket address
    pub fn socket_addr(&self) -> anyhow::Result<SocketAddr> {
        format!("{}:{}", self.host, self.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid socket address '{}:{}': {}", self.host, self.port, e))
    }

    /// Get metrics socket address
    pub fn metrics_socket_addr(&self) -> anyhow::Result<SocketAddr> {
        format!("{}:{}", self.host, self.observability.metrics_port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid metrics socket address '{}:{}': {}", self.host, self.observability.metrics_port, e))
    }

    /// Check if in development mode
    pub fn is_development(&self) -> bool {
        self.base_url.contains("localhost") || self.base_url.contains("127.0.0.1")
    }
}

/// TLS configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    /// Enable TLS
    #[serde(default = "default_tls_enabled")]
    pub enabled: bool,
    /// Path to TLS certificate file
    pub cert_file: Option<String>,
    /// Path to TLS private key file
    pub key_file: Option<String>,
    /// Path to CA certificate file for client auth (optional)
    pub ca_file: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: default_tls_enabled(),
            cert_file: None,
            key_file: None,
            ca_file: None,
        }
    }
}

/// Default TLS enabled (false in development, true in production)
fn default_tls_enabled() -> bool {
    // Default to false for backward compatibility
    // Production should explicitly enable TLS
    false
}

fn default_bot_protection_enabled() -> bool {
    true
}
fn default_bot_protection_disabled() -> bool {
    false
}
fn default_login_attempts_before_captcha() -> u32 {
    3
}
fn default_failed_login_window_seconds() -> u64 {
    300
} // 5 minutes

/// Password policy configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PasswordPolicyConfig {
    /// Minimum password length (default: 12)
    #[serde(default = "default_password_policy_min_length")]
    pub min_length: usize,
    /// Maximum password length (default: 128)
    #[serde(default = "default_password_policy_max_length")]
    pub max_length: usize,
    /// Require uppercase letters (default: true)
    #[serde(default = "default_true")]
    pub require_uppercase: bool,
    /// Require lowercase letters (default: true)
    #[serde(default = "default_true")]
    pub require_lowercase: bool,
    /// Require numbers (default: true)
    #[serde(default = "default_true")]
    pub require_numbers: bool,
    /// Require special characters (default: true)
    #[serde(default = "default_true")]
    pub require_special: bool,
    /// Special characters allowed
    #[serde(default = "default_special_chars")]
    pub special_chars: String,
    /// Maximum consecutive identical characters (default: 3)
    #[serde(default = "default_max_consecutive")]
    pub max_consecutive_chars: usize,
    /// Prevent common passwords (default: true)
    #[serde(default = "default_true")]
    pub prevent_common_passwords: bool,
    /// Password history count to prevent reuse (default: 5)
    #[serde(default = "default_password_history_count")]
    pub history_count: usize,
    /// Password expiry in days (default: None)
    #[serde(default)]
    pub expiry_days: Option<u32>,
    /// Check breach database (Have I Been Pwned) (default: true)
    #[serde(default = "default_true")]
    pub check_breach: bool,
    /// Enforcement mode: block, warn, or audit (default: block)
    #[serde(default = "default_enforcement_mode")]
    pub enforcement_mode: PasswordEnforcementMode,
    /// Minimum entropy bits (default: 50.0)
    #[serde(default = "default_min_entropy")]
    pub min_entropy: f64,
    /// Prevent password from containing user info (default: true)
    #[serde(default = "default_true")]
    pub prevent_user_info: bool,
}

impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            min_length: default_password_policy_min_length(),
            max_length: default_password_policy_max_length(),
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special: true,
            special_chars: default_special_chars(),
            max_consecutive_chars: default_max_consecutive(),
            prevent_common_passwords: true,
            history_count: default_password_history_count(),
            expiry_days: None,
            check_breach: true,
            enforcement_mode: PasswordEnforcementMode::Block,
            min_entropy: default_min_entropy(),
            prevent_user_info: true,
        }
    }
}

/// Password policy enforcement mode
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PasswordEnforcementMode {
    /// Strict - reject passwords that don't meet policy
    Block,
    /// Lenient - allow but warn
    Warn,
    /// Audit only - log violations but allow
    Audit,
}

fn default_password_policy_min_length() -> usize {
    12
}
fn default_password_policy_max_length() -> usize {
    128
}
fn default_true() -> bool {
    true
}
fn default_special_chars() -> String {
    "!@#$%^&*()_+-=[]{}|;':\"\",./<>?`~".to_string()
}
fn default_max_consecutive() -> usize {
    3
}
fn default_password_history_count() -> usize {
    5
}
fn default_enforcement_mode() -> PasswordEnforcementMode {
    PasswordEnforcementMode::Block
}
fn default_min_entropy() -> f64 {
    50.0
}

impl PasswordPolicyConfig {
    /// Convert to security module's PasswordPolicy
    pub fn to_policy(&self) -> crate::security::PasswordPolicy {
        use crate::security::{EnforcementMode, PasswordPolicy};

        PasswordPolicy {
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
                PasswordEnforcementMode::Block => EnforcementMode::Block,
                PasswordEnforcementMode::Warn => EnforcementMode::Warn,
                PasswordEnforcementMode::Audit => EnforcementMode::Audit,
            },
            min_entropy: self.min_entropy,
            prevent_user_info: self.prevent_user_info,
        }
    }
}

// Session limits defaults
fn default_max_concurrent_sessions() -> usize {
    5
}
fn default_enforce_for_ip() -> bool {
    false
}
fn default_max_sessions_per_ip() -> usize {
    3
}

// ============================================
// LDAP Configuration
// ============================================

/// LDAP configurations container
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct LdapConfigs {
    /// Global LDAP enable/disable flag
    #[serde(default)]
    pub enabled: bool,
    /// Default LDAP configuration (optional - can be configured per-tenant via API)
    #[serde(default)]
    pub default: Option<LdapConfig>,
    /// LDAP attribute mappings
    #[serde(default)]
    pub attribute_mappings: LdapUserAttributes,
}

/// LDAP connection configuration
#[derive(Clone, Deserialize, Serialize)]
pub struct LdapConfig {
    /// Connection enabled
    pub enabled: bool,
    /// LDAP server URL (e.g., ldaps://ad.company.com:636)
    pub url: String,
    /// Bind DN for service account (e.g., CN=admin,DC=company,DC=com)
    pub bind_dn: String,
    /// Bind password for service account
    pub bind_password: String,
    /// Base DN for searches (e.g., DC=company,DC=com)
    pub base_dn: String,
    /// User search base (optional, defaults to base_dn)
    #[serde(default)]
    pub user_search_base: Option<String>,
    /// User search filter (e.g., (objectClass=user))
    #[serde(default = "default_ldap_user_search_filter")]
    pub user_search_filter: String,
    /// Group search base (optional, defaults to base_dn)
    #[serde(default)]
    pub group_search_base: Option<String>,
    /// Group search filter (e.g., (objectClass=group))
    #[serde(default = "default_ldap_group_search_filter")]
    pub group_search_filter: String,
    /// Attribute mappings
    #[serde(default)]
    pub user_attributes: LdapUserAttributes,
    /// Sync interval in minutes
    #[serde(default = "default_ldap_sync_interval")]
    pub sync_interval_minutes: u32,
    /// TLS verification
    #[serde(default = "default_true")]
    pub tls_verify_cert: bool,
    /// Custom CA certificate (optional)
    #[serde(default)]
    pub tls_ca_cert: Option<String>,
    /// Connection timeout in seconds
    #[serde(default = "default_ldap_connection_timeout")]
    pub connection_timeout_secs: u64,
    /// Search timeout in seconds
    #[serde(default = "default_ldap_search_timeout")]
    pub search_timeout_secs: u64,
    /// Page size for LDAP pagination
    #[serde(default = "default_ldap_page_size")]
    pub page_size: i32,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for LdapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapConfig")
            .field("enabled", &self.enabled)
            .field("url", &self.url)
            .field("bind_dn", &self.bind_dn)
            .field("bind_password", &"[REDACTED]")
            .field("base_dn", &self.base_dn)
            .field("user_search_base", &self.user_search_base)
            .field("user_search_filter", &self.user_search_filter)
            .field("group_search_base", &self.group_search_base)
            .field("group_search_filter", &self.group_search_filter)
            .field("user_attributes", &self.user_attributes)
            .field("sync_interval_minutes", &self.sync_interval_minutes)
            .field("tls_verify_cert", &self.tls_verify_cert)
            .field("tls_ca_cert", &"[REDACTED]")
            .field("connection_timeout_secs", &self.connection_timeout_secs)
            .field("search_timeout_secs", &self.search_timeout_secs)
            .field("page_size", &self.page_size)
            .finish()
    }
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            bind_dn: String::new(),
            bind_password: String::new(),
            base_dn: String::new(),
            user_search_base: None,
            group_search_base: None,
            user_search_filter: default_ldap_user_search_filter(),
            group_search_filter: default_ldap_group_search_filter(),
            user_attributes: LdapUserAttributes::default(),
            sync_interval_minutes: default_ldap_sync_interval(),
            tls_verify_cert: true,
            tls_ca_cert: None,
            connection_timeout_secs: default_ldap_connection_timeout(),
            search_timeout_secs: default_ldap_search_timeout(),
            page_size: default_ldap_page_size(),
        }
    }
}

/// LDAP user attribute mappings
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LdapUserAttributes {
    /// Email attribute (default: mail)
    #[serde(default = "default_attr_email")]
    pub email: String,
    /// Username attribute (default: sAMAccountName for AD, uid for OpenLDAP)
    #[serde(default = "default_attr_username")]
    pub username: String,
    /// First name attribute (default: givenName)
    #[serde(default = "default_attr_first_name")]
    pub first_name: String,
    /// Last name attribute (default: sn)
    #[serde(default = "default_attr_last_name")]
    pub last_name: String,
    /// Display name attribute (default: displayName)
    #[serde(default = "default_attr_display_name")]
    pub display_name: String,
    /// Phone number attribute (default: telephoneNumber)
    #[serde(default = "default_attr_phone")]
    pub phone: String,
    /// Department attribute (default: department)
    #[serde(default = "default_attr_department")]
    pub department: String,
    /// Job title attribute (default: title)
    #[serde(default = "default_attr_title")]
    pub title: String,
    /// Employee ID attribute (default: employeeID)
    #[serde(default = "default_attr_employee_id")]
    pub employee_id: String,
    /// Object GUID attribute (default: objectGUID for AD, entryUUID for OpenLDAP)
    #[serde(default = "default_attr_object_guid")]
    pub object_guid: String,
    /// Member of attribute for group membership (default: memberOf)
    #[serde(default = "default_attr_member_of")]
    pub member_of: String,
}

impl Default for LdapUserAttributes {
    fn default() -> Self {
        Self {
            email: default_attr_email(),
            username: default_attr_username(),
            first_name: default_attr_first_name(),
            last_name: default_attr_last_name(),
            display_name: default_attr_display_name(),
            phone: default_attr_phone(),
            department: default_attr_department(),
            title: default_attr_title(),
            employee_id: default_attr_employee_id(),
            object_guid: default_attr_object_guid(),
            member_of: default_attr_member_of(),
        }
    }
}

// LDAP default functions
fn default_ldap_user_search_filter() -> String {
    "(objectClass=user)".to_string()
}
fn default_ldap_group_search_filter() -> String {
    "(objectClass=group)".to_string()
}
fn default_ldap_sync_interval() -> u32 {
    60
}
fn default_ldap_connection_timeout() -> u64 {
    10
}
fn default_ldap_search_timeout() -> u64 {
    30
}
fn default_ldap_page_size() -> i32 {
    1000
}
fn default_attr_email() -> String {
    "mail".to_string()
}
fn default_attr_username() -> String {
    "sAMAccountName".to_string()
}
fn default_attr_first_name() -> String {
    "givenName".to_string()
}
fn default_attr_last_name() -> String {
    "sn".to_string()
}
fn default_attr_display_name() -> String {
    "displayName".to_string()
}
fn default_attr_phone() -> String {
    "telephoneNumber".to_string()
}
fn default_attr_department() -> String {
    "department".to_string()
}
fn default_attr_title() -> String {
    "title".to_string()
}
fn default_attr_employee_id() -> String {
    "employeeID".to_string()
}
fn default_attr_object_guid() -> String {
    "objectGUID".to_string()
}
fn default_attr_member_of() -> String {
    "memberOf".to_string()
}

// ============================================
// Custom Domain Configuration
// ============================================

/// Custom domain (white-label) configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomDomainConfig {
    /// Enable custom domains feature
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Base domain for CNAME targets (e.g., "vault.example.com")
    #[serde(default = "default_base_domain")]
    pub base_domain: String,
    /// SSL certificate storage path
    #[serde(default = "default_cert_storage_path")]
    pub cert_storage_path: String,
    /// Whether to automatically verify DNS on creation
    #[serde(default = "default_false")]
    pub auto_verify_dns: bool,
    /// Enable SSL/TLS management (set to false if behind reverse proxy)
    #[serde(default = "default_false")]
    pub enable_ssl: bool,
    /// Default SSL provider
    #[serde(default = "default_ssl_provider")]
    pub ssl_provider: SslProviderType,
    /// Whether to force HTTPS redirect
    #[serde(default = "default_true")]
    pub force_https: bool,
    /// ACME directory URL (Let's Encrypt)
    #[serde(default = "default_acme_directory_url")]
    pub acme_directory_url: String,
    /// ACME contact email for certificate notifications
    pub acme_contact_email: Option<String>,
    /// Certificate renewal check interval (hours)
    #[serde(default = "default_cert_renewal_interval_hours")]
    pub cert_renewal_interval_hours: u64,
}

impl Default for CustomDomainConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_domain: default_base_domain(),
            cert_storage_path: default_cert_storage_path(),
            auto_verify_dns: false,
            enable_ssl: false,
            ssl_provider: SslProviderType::LetsEncrypt,
            force_https: true,
            acme_directory_url: default_acme_directory_url(),
            acme_contact_email: None,
            cert_renewal_interval_hours: default_cert_renewal_interval_hours(),
        }
    }
}

/// SSL provider type
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SslProviderType {
    /// Let's Encrypt automatic SSL
    #[default]
    LetsEncrypt,
    /// Custom certificates
    Custom,
    /// No SSL (behind reverse proxy)
    None,
}

fn default_base_domain() -> String {
    "vault.example.com".to_string()
}
fn default_cert_storage_path() -> String {
    "/etc/vault/certs".to_string()
}
fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}
fn default_ssl_provider() -> SslProviderType {
    SslProviderType::LetsEncrypt
}
fn default_cert_renewal_interval_hours() -> u64 {
    24
}

// ============================================
// SMS Configuration for MFA
// ============================================

/// SMS provider type
#[derive(Debug, Clone, Copy, Deserialize, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SmsProviderType {
    /// Disabled (no SMS MFA)
    #[default]
    Disabled,
    /// Twilio provider
    Twilio,
    /// AWS SNS provider
    AwsSns,
    /// Mock provider for testing
    Mock,
}

/// SMS configuration
#[derive(Clone, Deserialize, Serialize)]
pub struct SmsConfig {
    /// SMS provider type
    #[serde(default)]
    pub provider: SmsProviderType,
    /// Twilio account SID
    #[serde(default)]
    pub twilio_account_sid: Option<String>,
    /// Twilio auth token
    #[serde(default)]
    pub twilio_auth_token: Option<String>,
    /// Twilio from phone number
    #[serde(default)]
    pub twilio_from_number: Option<String>,
    /// Maximum SMS sends per phone number per window (default: 3)
    #[serde(default = "default_sms_max_sends_per_phone")]
    pub max_sends_per_phone: u32,
    /// Rate limit window in seconds (default: 600 = 10 minutes)
    #[serde(default = "default_sms_rate_limit_window_secs")]
    pub rate_limit_window_secs: u64,
    /// OTP code expiry in minutes (default: 10)
    #[serde(default = "default_sms_code_expiry_minutes")]
    pub code_expiry_minutes: i64,
    /// OTP code length (default: 6)
    #[serde(default = "default_sms_code_length")]
    pub code_length: usize,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for SmsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmsConfig")
            .field("provider", &self.provider)
            .field("twilio_account_sid", &self.twilio_account_sid)
            .field("twilio_auth_token", &"[REDACTED]")
            .field("twilio_from_number", &self.twilio_from_number)
            .field("max_sends_per_phone", &self.max_sends_per_phone)
            .field("rate_limit_window_secs", &self.rate_limit_window_secs)
            .field("code_expiry_minutes", &self.code_expiry_minutes)
            .field("code_length", &self.code_length)
            .finish()
    }
}

impl Default for SmsConfig {
    fn default() -> Self {
        Self {
            provider: SmsProviderType::Disabled,
            twilio_account_sid: None,
            twilio_auth_token: None,
            twilio_from_number: None,
            max_sends_per_phone: default_sms_max_sends_per_phone(),
            rate_limit_window_secs: default_sms_rate_limit_window_secs(),
            code_expiry_minutes: default_sms_code_expiry_minutes(),
            code_length: default_sms_code_length(),
        }
    }
}

impl SmsConfig {
    /// Check if SMS MFA is enabled
    pub fn is_enabled(&self) -> bool {
        self.provider != SmsProviderType::Disabled
    }
    
    /// Validate configuration for the selected provider
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }
        
        match self.provider {
            SmsProviderType::Twilio => {
                if self.twilio_account_sid.is_none() || self.twilio_account_sid.as_ref().unwrap().is_empty() {
                    anyhow::bail!("Twilio account_sid is required when SMS provider is twilio");
                }
                if self.twilio_auth_token.is_none() || self.twilio_auth_token.as_ref().unwrap().is_empty() {
                    anyhow::bail!("Twilio auth_token is required when SMS provider is twilio");
                }
                if self.twilio_from_number.is_none() || self.twilio_from_number.as_ref().unwrap().is_empty() {
                    anyhow::bail!("Twilio from_number is required when SMS provider is twilio");
                }
            }
            SmsProviderType::AwsSns => {
                // AWS SNS uses IAM role or environment credentials
                // No explicit validation needed here
            }
            SmsProviderType::Mock => {
                // Mock provider doesn't need configuration
            }
            SmsProviderType::Disabled => {}
        }
        
        if self.max_sends_per_phone == 0 {
            anyhow::bail!("max_sends_per_phone must be greater than 0");
        }
        
        if self.code_length < 4 || self.code_length > 10 {
            anyhow::bail!("code_length must be between 4 and 10");
        }
        
        Ok(())
    }
    
    /// Get Twilio config if provider is Twilio
    pub fn twilio_config(&self) -> Option<vault_core::sms::twilio::TwilioConfig> {
        if self.provider == SmsProviderType::Twilio {
            Some(vault_core::sms::twilio::TwilioConfig {
                account_sid: self.twilio_account_sid.clone()?,
                auth_token: self.twilio_auth_token.clone()?,
                from_number: self.twilio_from_number.clone()?,
            })
        } else {
            None
        }
    }
}

fn default_sms_max_sends_per_phone() -> u32 {
    3
}
fn default_sms_rate_limit_window_secs() -> u64 {
    600
}
fn default_sms_code_expiry_minutes() -> i64 {
    10
}
fn default_sms_code_length() -> usize {
    6
}

// ============================================
// WhatsApp Configuration for MFA
// ============================================

/// WhatsApp configuration
#[derive(Clone, Deserialize, Serialize)]
pub struct WhatsAppConfig {
    /// Enable WhatsApp MFA
    #[serde(default = "default_false")]
    pub enabled: bool,
    /// WhatsApp Business phone number ID
    #[serde(default)]
    pub phone_number_id: Option<String>,
    /// Meta access token
    #[serde(default)]
    pub access_token: Option<String>,
    /// Graph API version (default: v18.0)
    #[serde(default = "default_whatsapp_api_version")]
    pub api_version: String,
    /// Template name for OTP messages (default: vault_otp_en)
    #[serde(default = "default_whatsapp_template_name")]
    pub template_name: String,
    /// Language code for template (default: en)
    #[serde(default = "default_whatsapp_language_code")]
    pub language_code: String,
    /// Fallback to SMS if WhatsApp fails
    #[serde(default = "default_true")]
    pub fallback_to_sms: bool,
}

/// SECURITY: Custom Debug implementation that redacts sensitive credentials
impl std::fmt::Debug for WhatsAppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WhatsAppConfig")
            .field("enabled", &self.enabled)
            .field("phone_number_id", &self.phone_number_id)
            .field("access_token", &"[REDACTED]")
            .field("api_version", &self.api_version)
            .field("template_name", &self.template_name)
            .field("language_code", &self.language_code)
            .field("fallback_to_sms", &self.fallback_to_sms)
            .finish()
    }
}

impl Default for WhatsAppConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            phone_number_id: None,
            access_token: None,
            api_version: default_whatsapp_api_version(),
            template_name: default_whatsapp_template_name(),
            language_code: default_whatsapp_language_code(),
            fallback_to_sms: true,
        }
    }
}

impl WhatsAppConfig {
    /// Check if WhatsApp MFA is enabled and configured
    pub fn is_enabled(&self) -> bool {
        self.enabled 
            && self.phone_number_id.is_some() 
            && self.access_token.is_some()
            && !self.phone_number_id.as_ref().unwrap().is_empty()
            && !self.access_token.as_ref().unwrap().is_empty()
    }
    
    /// Validate configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enabled {
            return Ok(());
        }
        
        if self.phone_number_id.is_none() || self.phone_number_id.as_ref().unwrap().is_empty() {
            anyhow::bail!("WhatsApp phone_number_id is required when WhatsApp is enabled");
        }
        
        if self.access_token.is_none() || self.access_token.as_ref().unwrap().is_empty() {
            anyhow::bail!("WhatsApp access_token is required when WhatsApp is enabled");
        }
        
        if self.template_name.is_empty() {
            anyhow::bail!("WhatsApp template_name cannot be empty");
        }
        
        Ok(())
    }
    
    /// Get WhatsApp config for core library
    pub fn core_config(&self) -> Option<vault_core::sms::whatsapp::WhatsAppConfig> {
        if self.is_enabled() {
            Some(vault_core::sms::whatsapp::WhatsAppConfig {
                phone_number_id: self.phone_number_id.clone()?,
                access_token: self.access_token.clone()?,
                api_version: self.api_version.clone(),
                template_name: self.template_name.clone(),
                fallback_to_sms: self.fallback_to_sms,
                language_code: self.language_code.clone(),
            })
        } else {
            None
        }
    }
}

fn default_whatsapp_api_version() -> String {
    "v18.0".to_string()
}
fn default_whatsapp_template_name() -> String {
    "vault_otp_en".to_string()
}
fn default_whatsapp_language_code() -> String {
    "en".to_string()
}

// ============================================
// Web3 Authentication Configuration
// ============================================

/// Web3 authentication (SIWE) configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Web3AuthConfig {
    /// Domain for SIWE messages (defaults to base_url hostname)
    pub domain: Option<String>,
    /// Enabled chain IDs (default: mainnet chains)
    #[serde(default = "default_supported_chains")]
    pub supported_chains: Vec<u64>,
    /// Nonce TTL in minutes (default: 5)
    #[serde(default = "default_web3_nonce_ttl")]
    pub nonce_ttl_minutes: i64,
    /// Message TTL in minutes (default: 5)
    #[serde(default = "default_web3_message_ttl")]
    pub message_ttl_minutes: i64,
    /// Whether to enable Web3 authentication
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Whether to enforce domain binding
    #[serde(default = "default_true")]
    pub enforce_domain_binding: bool,
    /// Enable NFT-based access control
    #[serde(default = "default_false")]
    pub enable_nft_access_control: bool,
    /// Required NFT contract addresses
    #[serde(default)]
    pub required_nft_contracts: Vec<String>,
    /// NFT verification RPC endpoints per chain
    #[serde(default)]
    pub nft_rpc_endpoints: std::collections::HashMap<u64, String>,
}

impl Default for Web3AuthConfig {
    fn default() -> Self {
        Self {
            domain: None,
            supported_chains: default_supported_chains(),
            nonce_ttl_minutes: default_web3_nonce_ttl(),
            message_ttl_minutes: default_web3_message_ttl(),
            enabled: true,
            enforce_domain_binding: true,
            enable_nft_access_control: false,
            required_nft_contracts: Vec::new(),
            nft_rpc_endpoints: std::collections::HashMap::new(),
        }
    }
}

fn default_supported_chains() -> Vec<u64> {
    vec![
        1,      // Ethereum Mainnet
        137,    // Polygon
        42161,  // Arbitrum
        10,     // Optimism
        8453,   // Base
        43114,  // Avalanche
        56,     // BSC
    ]
}

fn default_web3_nonce_ttl() -> i64 {
    5
}

fn default_web3_message_ttl() -> i64 {
    5
}

fn default_false() -> bool {
    false
}
