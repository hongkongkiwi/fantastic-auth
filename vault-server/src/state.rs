//! Server state shared across handlers

use std::sync::Arc;
use base64::Engine;
use vault_core::auth::AuthService;
use vault_core::email::{EmailRequest, EmailService, SmtpEmailService};
use vault_core::security::bot_protection::{
    BotProtection, CloudflareTurnstile, DisabledBotProtection, HCaptcha,
};
use vault_core::webauthn::{WebAuthnConfig, WebAuthnService};
use crate::i18n::I18n;

use crate::audit::{AuditLogger, DefaultWebhookNotifier};
use crate::auth::{AccountLinkingService, StepUpPolicy};
use crate::auth::web3::{create_web3_auth_in_memory, create_web3_auth_with_redis, Web3Auth};
use crate::billing::{BillingConfig, BillingService};
use crate::config::{BotProtectionProvider, Config, EvictionPolicy};
use crate::db::Database;
use crate::monitoring::{HealthRegistry, MetricsRegistry};
use crate::routes::SessionLimitError;
use crate::security::{RiskEngine, SecurityService};
use crate::webhooks::WebhookService;
use crate::webhooks::WebhookService as AppWebhookService;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    /// Configuration
    pub config: Arc<Config>,
    /// Database (connection pool + repositories)
    pub db: Database,
    /// Redis connection (optional)
    pub redis: Option<redis::aio::ConnectionManager>,
    /// Authentication service
    pub auth_service: Arc<AuthService>,
    /// WebAuthn service for passkey authentication
    pub webauthn_service: Arc<WebAuthnService>,
    /// SMS service for MFA
    pub sms_service: Option<Arc<vault_core::sms::SmsService>>,
    /// Rate limiter
    pub rate_limiter: Arc<RateLimiter>,
    /// Bot protection service
    pub bot_protection: Arc<dyn BotProtection>,
    /// Failed login attempt tracker for CAPTCHA triggering
    pub failed_login_tracker: Arc<FailedLoginTracker>,
    /// Health check registry
    pub health_registry: HealthRegistry,
    /// Metrics registry
    pub metrics_registry: MetricsRegistry,
    /// Billing service (optional)
    pub billing_service: BillingService,
    /// Webhook service for sending events
    pub webhook_service: WebhookService,
    /// Security service for password policy and breach detection
    pub security_service: Arc<SecurityService>,
    /// Account linking service for managing multiple authentication methods
    pub account_linking_service: Arc<AccountLinkingService>,
    /// Step-up authentication policy
    pub step_up_policy: StepUpPolicy,
    /// Default max age for step-up authentication (minutes)
    pub step_up_max_age_minutes: u32,
    /// Data encryption key (AES-256-GCM)
    pub data_encryption_key: Arc<Vec<u8>>,
    /// Email service for transactional emails
    pub email_service: Option<Arc<dyn EmailService>>,
    /// Web3 authentication service
    pub web3_auth: Arc<Web3Auth>,
    /// Consent manager for GDPR/CCPA compliance
    pub consent_manager: Arc<crate::consent::ConsentManager>,
    /// Risk engine for risk-based authentication
    pub risk_engine: Arc<RiskEngine>,
}

impl AppState {
    /// Create new app state with database
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        // Initialize database
        let db = Database::new(&config.database_url).await?;

        // Connect to Redis if configured
        let redis = if let Some(ref redis_url) = config.redis_url {
            let client = redis::Client::open(redis_url.as_str())?;
            Some(redis::aio::ConnectionManager::new(client).await?)
        } else {
            None
        };

        // Initialize email service if SMTP is configured
        // Initialize email service if SMTP is configured
        let email_service: Option<Arc<dyn EmailService>> =
            if let Some(ref smtp_config) = config.smtp {
                match SmtpEmailService::new(
                    &smtp_config.host,
                    smtp_config.port,
                    &smtp_config.username,
                    &smtp_config.password,
                    smtp_config.from_address.clone(),
                    smtp_config.from_name.clone(),
                    format!("https://{}:{}", config.host, config.port),
                    "Vault".to_string(),
                ) {
                    Ok(service) => {
                        tracing::info!("Email service initialized with SMTP: {}", smtp_config.host);
                        Some(Arc::new(service))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to initialize email service: {}", e);
                        None
                    }
                }
            } else {
                tracing::info!("No SMTP configuration - email service disabled");
                None
            };

        // Initialize SMS service if configured (used by AuthService for MFA)
        let sms_service = initialize_sms_service(&config, redis.clone()).await;

        let data_encryption_key = Arc::new(load_data_encryption_key()?);

        // Initialize auth service with database
        let db_context = Arc::new(vault_core::db::DbContext::new(db.pool().clone()));
        let base_url = format!("https://{}:{}", config.host, config.port);
        let mut auth_service = match &config.redis_url {
            Some(redis_url) => AuthService::with_redis(
                &config.jwt.issuer,
                &config.jwt.audience,
                db_context,
                &base_url,
                redis_url,
            )
            .await?,
            None => AuthService::new(
                &config.jwt.issuer,
                &config.jwt.audience,
                db_context,
                &base_url,
            ),
        };

        if let (Some(ref email_service), Some(ref smtp_config)) = (&email_service, &config.smtp) {
            let from_address = smtp_config.from_address.clone();
            let from_name = smtp_config.from_name.clone();
            let email_service = email_service.clone();
            auth_service = auth_service.with_email_sender(move |payload| {
                let email_service = email_service.clone();
                let from_address = from_address.clone();
                let from_name = from_name.clone();
                async move {
                    email_service
                        .send_email(EmailRequest {
                            to: payload.to,
                            to_name: None,
                            subject: payload.subject,
                            html_body: payload.html_body,
                            text_body: payload.text_body,
                            from: from_address,
                            from_name,
                            reply_to: None,
                            headers: std::collections::HashMap::new(),
                        })
                        .await
                        .map_err(|e| vault_core::error::VaultError::internal(format!(
                            "Failed to send email: {}",
                            e
                        )))
                }
            });
        }

        if let Some(ref sms_service) = sms_service {
            auth_service = auth_service.with_sms_service(sms_service.clone());
        }

        let auth_service = Arc::new(
            auth_service.with_data_encryption_key((*data_encryption_key).clone()),
        );

        // Initialize WebAuthn service
        let rp_id = config
            .base_url
            .replace("https://", "")
            .replace("http://", "")
            .split(':')
            .next()
            .unwrap_or("localhost")
            .to_string();

        let webauthn_config = WebAuthnConfig::new(rp_id, "Vault Authentication", &config.base_url);

        // Use Redis for challenges if available, otherwise memory store
        let challenge_store: Box<dyn vault_core::webauthn::ChallengeStore> =
            if let Some(ref redis_mgr) = redis {
                Box::new(vault_core::webauthn::challenge::RedisChallengeStore::new(
                    redis_mgr.clone(),
                ))
            } else {
                Box::new(vault_core::webauthn::challenge::MemoryChallengeStore::new())
            };

        // Use SQLx-backed credential store
        let credential_store: Box<dyn vault_core::webauthn::CredentialStore> = Box::new(
            vault_core::webauthn::credentials::SqlxCredentialStore::new(db.pool().clone()),
        );

        let webauthn_service = Arc::new(WebAuthnService::new(
            webauthn_config,
            challenge_store,
            credential_store,
        ));

        // Initialize rate limiter
        let rate_limiter = Arc::new(RateLimiter::new(redis.clone()));

        // Initialize bot protection based on configuration
        let bot_protection: Arc<dyn BotProtection> = if config.security.bot_protection.is_enabled()
        {
            let provider = &config.security.bot_protection.provider;
            let secret_key = config.security.bot_protection.secret_key().to_string();
            let site_key = config.security.bot_protection.site_key().to_string();

            match provider {
                BotProtectionProvider::Turnstile => {
                    tracing::info!("Bot protection enabled with Cloudflare Turnstile");
                    Arc::new(CloudflareTurnstile::new(secret_key, site_key))
                }
                BotProtectionProvider::Hcaptcha => {
                    tracing::info!("Bot protection enabled with hCaptcha");
                    Arc::new(HCaptcha::new(secret_key, site_key))
                }
                BotProtectionProvider::Disabled => {
                    tracing::info!("Bot protection disabled");
                    Arc::new(DisabledBotProtection)
                }
            }
        } else {
            tracing::info!("Bot protection disabled (no configuration)");
            Arc::new(DisabledBotProtection)
        };

        // Initialize failed login tracker
        let failed_login_tracker = Arc::new(FailedLoginTracker::new(redis.clone()));

        // Initialize monitoring
        let health_registry = HealthRegistry::new();
        let metrics_registry = MetricsRegistry::new();

        // Initialize billing service (optional)
        let billing_config = BillingConfig::from_env();
        let billing_service = BillingService::new(billing_config, db.clone());

        // Initialize webhook service
        let webhook_service = WebhookService::new(db.clone());

        // Initialize security service with password policy
        let password_policy = config.security.password_policy.to_policy();
        let security_service = Arc::new(SecurityService::new(
            password_policy,
            config.security.password_policy.check_breach,
        ));

        // Initialize account linking service
        let account_linking_service =
            Arc::new(AccountLinkingService::new(Arc::new(db.pool().clone())));

        // Initialize step-up policy (in production, this could be loaded from config/database)
        let step_up_policy = StepUpPolicy::new();
        let step_up_max_age_minutes = 10; // Default 10 minutes
        
        // Initialize i18n service
        let i18n = Arc::new(I18n::new()?);
        
        // Initialize consent manager
        let consent_repository = crate::consent::ConsentRepository::new(db.pool().clone());
        let consent_config = crate::consent::ConsentConfig::default();
        let consent_manager = Arc::new(crate::consent::ConsentManager::new(
            consent_repository,
            consent_config,
        ));

        // Initialize risk engine for risk-based authentication
        let risk_engine = Arc::new(RiskEngine::default_with_db(db.clone()));
        tracing::info!("Risk-based authentication engine initialized");

        Ok(Self {
            config: Arc::new(config),
            db,
            redis,
            auth_service,
            webauthn_service,
            sms_service,
            rate_limiter,
            bot_protection,
            failed_login_tracker,
            health_registry,
            metrics_registry,
            billing_service,
            webhook_service,
            security_service,
            account_linking_service,
            step_up_policy,
            step_up_max_age_minutes,
            data_encryption_key,
            email_service,
            i18n,
            web3_auth: {
                // Initialize Web3 authentication service
                let base_url = config.base_url.clone();
                let domain = config.web3_auth.domain.clone()
                    .unwrap_or_else(|| base_url.replace("https://", "").replace("http://", ""));
                
                let web3_auth = if let Some(ref redis_mgr) = redis {
                    create_web3_auth_with_redis(&domain, &base_url, redis_mgr.clone())
                } else {
                    create_web3_auth_in_memory(&domain, &base_url)
                };
                
                Arc::new(web3_auth)
            },
            consent_manager,
            risk_engine,
        })
    }

    /// Set tenant context for database queries
    pub async fn set_tenant_context(&self, tenant_id: &str) -> anyhow::Result<()> {
        let mut conn = self.db.pool().acquire().await?;

        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id)
            .execute(&mut *conn)
            .await?;

        // Reset to avoid leaking context across pooled connections.
        let _ = sqlx::query("RESET app.current_tenant_id")
            .execute(&mut *conn)
            .await;
        let _ = sqlx::query("RESET app.current_user_id")
            .execute(&mut *conn)
            .await;
        let _ = sqlx::query("RESET app.current_user_role")
            .execute(&mut *conn)
            .await;

        Ok(())
    }

    /// Create an audit logger with webhook support if enabled
    pub fn audit_logger(&self) -> AuditLogger {
        let mut logger = AuditLogger::new(self.db.clone());

        if self.config.webhook.enabled {
            let notifier = Arc::new(DefaultWebhookNotifier::new(self.db.clone()));
            logger.enable_webhooks(notifier);
        }

        logger
    }

    /// Check session limits for a user and apply eviction policy if needed
    /// Returns Ok(()) if the new session can proceed, Err if it should be denied
    pub async fn check_session_limits(
        &self,
        tenant_id: &str,
        user_id: &str,
        ip_address: Option<&str>,
    ) -> anyhow::Result<std::result::Result<(), SessionLimitError>> {
        let limits = &self.config.security.session_limits;

        // Get current active session count
        let current_count = self
            .db
            .sessions()
            .count_active_sessions_for_user(tenant_id, user_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to count sessions: {}", e))?;

        let current_count = current_count as usize;
        let max_sessions = limits.max_concurrent_sessions;

        // Check if we're at or over the limit
        if current_count >= max_sessions {
            match limits.eviction_policy {
                EvictionPolicy::DenyNew => {
                    // Deny the new login
                    return Ok(Err(SessionLimitError {
                        current_sessions: current_count,
                        max_sessions,
                        message: format!(
                            "Maximum concurrent sessions reached ({}). Please log out from another device.",
                            max_sessions
                        ),
                    }));
                }
                EvictionPolicy::NewestFirst => {
                    // Revoke the newest session (this shouldn't happen often as we're about to create a new one)
                    // For simplicity, deny the new login in this case
                    return Ok(Err(SessionLimitError {
                        current_sessions: current_count,
                        max_sessions,
                        message: format!(
                            "Maximum concurrent sessions reached ({}). Current login attempt cannot proceed.",
                            max_sessions
                        ),
                    }));
                }
                EvictionPolicy::OldestFirst => {
                    // Revoke oldest sessions to make room
                    let to_revoke = current_count - max_sessions + 1; // +1 to make room for new session
                    let revoked = self
                        .db
                        .sessions()
                        .revoke_oldest_sessions_for_user(tenant_id, user_id, max_sessions - 1)
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to revoke sessions: {}", e))?;

                    tracing::info!(
                        "Revoked {} oldest sessions for user {} (limit: {})",
                        revoked,
                        user_id,
                        max_sessions
                    );
                }
            }
        }

        // Check per-IP limit if enabled
        if limits.enforce_for_ip {
            if let Some(ip) = ip_address {
                let ip_count = self
                    .db
                    .sessions()
                    .count_active_sessions_for_user_by_ip(tenant_id, user_id, ip)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to count IP sessions: {}", e))?;

                let ip_count = ip_count as usize;
                if ip_count >= limits.max_sessions_per_ip {
                    return Ok(Err(SessionLimitError {
                        current_sessions: ip_count,
                        max_sessions: limits.max_sessions_per_ip,
                        message: format!(
                            "Maximum concurrent sessions per IP reached ({}). Please log out from another device on this network.",
                            limits.max_sessions_per_ip
                        ),
                    }));
                }
            }
        }

        Ok(Ok(()))
    }

    /// Get session limit status for a user
    pub async fn get_session_limit_status(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> anyhow::Result<SessionLimitStatus> {
        let limits = &self.config.security.session_limits;
        let current_count = self
            .db
            .sessions()
            .count_active_sessions_for_user(tenant_id, user_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to count sessions: {}", e))?;

        let current_count = current_count as usize;
        let max_sessions = limits.max_concurrent_sessions;

        // Determine warning level
        let warning = if current_count >= max_sessions {
            Some("limit_reached".to_string())
        } else if current_count >= max_sessions * 4 / 5 {
            Some("near_limit".to_string())
        } else {
            None
        };

        Ok(SessionLimitStatus {
            current_sessions: current_count,
            max_sessions,
            warning,
        })
    }
}

fn load_data_encryption_key() -> anyhow::Result<Vec<u8>> {
    if let Ok(path) = std::env::var("VAULT_MASTER_KEY_FILE")
        .or_else(|_| std::env::var("MASTER_KEY_FILE"))
    {
        let contents = std::fs::read(&path)?;
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(contents.trim()) {
            if decoded.len() == 32 {
                return Ok(decoded);
            }
        }
        if contents.len() == 32 {
            return Ok(contents);
        }
        anyhow::bail!("MASTER_KEY_FILE must contain 32 raw bytes or base64-encoded 32 bytes");
    }

    if let Ok(encoded) = std::env::var("VAULT_DATA_ENCRYPTION_KEY")
        .or_else(|_| std::env::var("DATA_ENCRYPTION_KEY"))
    {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|_| anyhow::anyhow!("DATA_ENCRYPTION_KEY must be base64"))?;
        if decoded.len() != 32 {
            anyhow::bail!("DATA_ENCRYPTION_KEY must decode to 32 bytes");
        }
        return Ok(decoded);
    }

    tracing::warn!("No data encryption key configured; generating ephemeral key for this process");
    Ok(vault_core::crypto::generate_random_bytes(32))
}

/// Session limit status information
#[derive(Debug, Clone)]
pub struct SessionLimitStatus {
    pub current_sessions: usize,
    pub max_sessions: usize,
    pub warning: Option<String>,
}

/// Rate limiter implementation
#[derive(Clone)]
pub struct RateLimiter {
    /// Redis connection for distributed rate limiting
    redis: Option<redis::aio::ConnectionManager>,
    /// Local in-memory rate limiting (fallback)
    local: Arc<dashmap::DashMap<String, RateLimitEntry>>,
}

#[derive(Clone)]
struct RateLimitEntry {
    count: u32,
    window_start: std::time::Instant,
}

impl RateLimiter {
    /// Create new rate limiter
    pub fn new(redis: Option<redis::aio::ConnectionManager>) -> Self {
        Self {
            redis,
            local: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Check if request is allowed
    pub async fn is_allowed(&self, key: &str, max_requests: u32, window_secs: u64) -> bool {
        // Try Redis first if available
        if let Some(ref redis) = self.redis {
            return self
                .is_allowed_redis(redis, key, max_requests, window_secs)
                .await;
        }

        // Fall back to local rate limiting
        self.is_allowed_local(key, max_requests, window_secs)
    }

    /// Check using Redis
    async fn is_allowed_redis(
        &self,
        redis: &redis::aio::ConnectionManager,
        key: &str,
        max_requests: u32,
        window_secs: u64,
    ) -> bool {
        let mut conn = redis.clone();
        let window_key = format!("rate_limit:{}", key);

        // Use Redis INCR and EXPIRE for atomic rate limiting
        let count: u32 = match redis::cmd("INCR")
            .arg(&window_key)
            .query_async::<_, u32>(&mut conn)
            .await
        {
            Ok(c) => c,
            Err(_) => return true, // Allow on error
        };

        // Set expiry on first request
        if count == 1 {
            let _: Result<(), _> = redis::cmd("EXPIRE")
                .arg(&window_key)
                .arg(window_secs)
                .query_async(&mut conn)
                .await;
        }

        count <= max_requests
    }

    /// Check using local in-memory store
    fn is_allowed_local(&self, key: &str, max_requests: u32, window_secs: u64) -> bool {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(window_secs);

        let mut entry = self.local.entry(key.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset if window expired
        if now.duration_since(entry.window_start) > window {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count < max_requests {
            entry.count += 1;
            true
        } else {
            false
        }
    }
}

/// Failed login tracker for CAPTCHA triggering
#[derive(Clone)]
pub struct FailedLoginTracker {
    /// Redis connection for distributed tracking
    redis: Option<redis::aio::ConnectionManager>,
    /// Local in-memory tracking (fallback)
    local: Arc<dashmap::DashMap<String, FailedLoginEntry>>,
}

#[derive(Clone)]
struct FailedLoginEntry {
    count: u32,
    window_start: std::time::Instant,
}

impl FailedLoginTracker {
    /// Create new failed login tracker
    pub fn new(redis: Option<redis::aio::ConnectionManager>) -> Self {
        Self {
            redis,
            local: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Record a failed login attempt
    pub async fn record_failure(&self, key: &str, window_secs: u64) -> u32 {
        if let Some(ref redis) = self.redis {
            self.record_failure_redis(redis, key, window_secs).await
        } else {
            self.record_failure_local(key, window_secs)
        }
    }

    /// Record failure using Redis
    async fn record_failure_redis(
        &self,
        redis: &redis::aio::ConnectionManager,
        key: &str,
        window_secs: u64,
    ) -> u32 {
        let mut conn = redis.clone();
        let window_key = format!("failed_login:{}", key);

        // Use Redis INCR and EXPIRE
        let count: u32 = match redis::cmd("INCR")
            .arg(&window_key)
            .query_async::<_, u32>(&mut conn)
            .await
        {
            Ok(c) => c,
            Err(_) => return 1, // Return minimum on error
        };

        // Set expiry on first request
        if count == 1 {
            let _: Result<(), _> = redis::cmd("EXPIRE")
                .arg(&window_key)
                .arg(window_secs)
                .query_async(&mut conn)
                .await;
        }

        count
    }

    /// Record failure using local in-memory store
    fn record_failure_local(&self, key: &str, window_secs: u64) -> u32 {
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(window_secs);

        let mut entry = self
            .local
            .entry(key.to_string())
            .or_insert(FailedLoginEntry {
                count: 0,
                window_start: now,
            });

        // Reset if window expired
        if now.duration_since(entry.window_start) > window {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;
        entry.count
    }

    /// Get current failure count
    pub async fn get_failure_count(&self, key: &str) -> u32 {
        if let Some(ref redis) = self.redis {
            let mut conn = redis.clone();
            let window_key = format!("failed_login:{}", key);

            match redis::cmd("GET")
                .arg(&window_key)
                .query_async::<_, Option<u32>>(&mut conn)
                .await
            {
                Ok(Some(count)) => count,
                _ => 0,
            }
        } else {
            self.local.get(key).map(|e| e.count).unwrap_or(0)
        }
    }

    /// Reset failure count (called on successful login)
    pub async fn reset(&self, key: &str) {
        if let Some(ref redis) = self.redis {
            let mut conn = redis.clone();
            let window_key = format!("failed_login:{}", key);
            let _: Result<(), _> = redis::cmd("DEL")
                .arg(&window_key)
                .query_async(&mut conn)
                .await;
        } else {
            self.local.remove(key);
        }
    }

    /// Check if CAPTCHA is required based on failure count
    pub async fn is_captcha_required(&self, key: &str, threshold: u32) -> bool {
        if threshold == 0 {
            // 0 means always require CAPTCHA
            return true;
        }
        let count = self.get_failure_count(key).await;
        count >= threshold
    }
}

/// Current user extracted from JWT
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// User ID
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Session ID
    pub session_id: Option<String>,
    /// Email
    pub email: String,
    /// Whether email is verified
    pub email_verified: bool,
    /// MFA authenticated
    pub mfa_authenticated: bool,
    /// JWT claims
    pub claims: vault_core::crypto::Claims,
    /// ID of the admin user who is impersonating (if applicable)
    pub impersonator_id: Option<String>,
    /// Whether this session is an impersonation session
    pub is_impersonation: bool,
}

/// Tenant context extracted from request
#[derive(Debug, Clone)]
pub struct TenantContext {
    /// Tenant ID
    pub tenant_id: String,
    /// Tenant slug
    pub tenant_slug: Option<String>,
}

/// Initialize SMS service based on configuration
async fn initialize_sms_service(
    config: &Config,
    redis: Option<redis::aio::ConnectionManager>,
) -> Option<Arc<vault_core::sms::SmsService>> {
    if !config.sms.is_enabled() {
        tracing::info!("SMS service disabled");
        return None;
    }
    
    // Validate config
    if let Err(e) = config.sms.validate() {
        tracing::warn!("SMS configuration invalid: {}", e);
        return None;
    }
    
    // Create code store
    let code_store: Box<dyn vault_core::sms::OtpCodeStore> = match redis {
        Some(redis_conn) => {
            tracing::info!("Using Redis for SMS OTP code storage");
            Box::new(vault_core::sms::RedisOtpCodeStore::new(redis_conn))
        }
        None => {
            tracing::warn!("Using in-memory store for SMS OTP codes (not recommended for production)");
            Box::new(vault_core::sms::InMemoryOtpCodeStore::new())
        }
    };
    
    // Create provider based on config
    let provider: Option<Box<dyn vault_core::sms::SmsProvider>> = match config.sms.provider {
        crate::config::SmsProviderType::Twilio => {
            if let Some(twilio_config) = config.sms.twilio_config() {
                let provider = vault_core::sms::TwilioProvider::new(
                    &twilio_config.account_sid,
                    &twilio_config.auth_token,
                    &twilio_config.from_number,
                );
                tracing::info!("Twilio SMS provider initialized");
                Some(Box::new(provider))
            } else {
                tracing::warn!("Twilio configuration incomplete");
                None
            }
        }
        crate::config::SmsProviderType::Mock => {
            tracing::info!("Mock SMS provider initialized (for testing)");
            Some(Box::new(vault_core::sms::MockSmsProvider::new()))
        }
        crate::config::SmsProviderType::AwsSns => {
            tracing::warn!("AWS SNS provider not yet implemented");
            None
        }
        crate::config::SmsProviderType::Disabled => None,
    };
    
    let sms_config = vault_core::sms::SmsConfig {
        max_sends_per_phone: config.sms.max_sends_per_phone,
        rate_limit_window_secs: config.sms.rate_limit_window_secs,
        code_expiry_minutes: config.sms.code_expiry_minutes,
        code_length: config.sms.code_length,
    };
    
    Some(Arc::new(vault_core::sms::SmsService::new(
        provider,
        code_store,
        sms_config,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_local() {
        let limiter = RateLimiter::new(None);
        let key = "test_key";

        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(limiter.is_allowed_local(key, 5, 60));
        }

        // Should block 6th request
        assert!(!limiter.is_allowed_local(key, 5, 60));
    }

    #[test]
    fn test_sms_service_initialization() {
        // Test that SMS service initializes correctly with disabled config
        let config = Config::default();
        assert!(!config.sms.is_enabled());
    }

    #[test]
    fn test_failed_login_tracker_local() {
        let tracker = FailedLoginTracker::new(None);
        let key = "test_user@example.com";

        // Initially should be 0
        assert_eq!(tracker.get_failure_count(key), 0);

        // Record some failures
        let count1 = tracker.record_failure_local(key, 300);
        assert_eq!(count1, 1);

        let count2 = tracker.record_failure_local(key, 300);
        assert_eq!(count2, 2);

        // Check count
        assert_eq!(tracker.get_failure_count(key), 2);

        // Reset should clear
        futures::executor::block_on(tracker.reset(key));
        assert_eq!(tracker.get_failure_count(key), 0);
    }
}
