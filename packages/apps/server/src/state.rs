//! Server state shared across handlers

use std::sync::Arc;
use base64::Engine;
use vault_core::auth::AuthService;
use vault_core::email::{EmailRequest, EmailService, SmtpEmailService};
use vault_core::security::bot_protection::{
    BotProtection, CloudflareTurnstile, DisabledBotProtection, HCaptcha,
};
use vault_core::webauthn::{WebAuthnConfig, WebAuthnService};

use crate::audit::{AuditLogger, DefaultWebhookNotifier};
use crate::auth::{AccountLinkingService, StepUpPolicy};
use crate::auth::web3::{create_web3_auth_in_memory, create_web3_auth_with_redis, Web3Auth};
use crate::billing::{BillingConfig, BillingService};
use crate::config::{BotProtectionProvider, Config, DataEncryptionProvider, EvictionPolicy};
use crate::communications::{SharedOtpCodeStore, TenantCommunicationResolver};
use crate::db::Database;
use crate::impersonation::ImpersonationService;
use crate::monitoring::{HealthRegistry, MetricsRegistry};
use crate::routes::SessionLimitError;
use crate::security::{
    KmsProviderKind, KmsRegistry, LocalMasterKeyProvider, RiskEngine, SecurityService,
    TenantKeyService,
};
use crate::settings::{SettingsRepository, SettingsService};
use crate::webhooks::WebhookService;

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
    /// Master key for wrapping per-tenant DEKs (AES-256-GCM)
    pub data_encryption_key: Arc<Vec<u8>>,
    /// Per-tenant data encryption keys (DEK service)
    pub tenant_key_service: Arc<TenantKeyService>,
    /// Email service for transactional emails
    pub email_service: Option<Arc<dyn EmailService>>,
    /// Tenant-aware communication resolver
    pub communications: Arc<TenantCommunicationResolver>,
    /// Web3 authentication service
    pub web3_auth: Arc<Web3Auth>,
    /// Consent manager for GDPR/CCPA compliance
    pub consent_manager: Arc<crate::consent::ConsentManager>,
    /// Risk engine for risk-based authentication
    pub risk_engine: Arc<RiskEngine>,
    /// Impersonation service for admin user impersonation
    pub impersonation_service: Arc<ImpersonationService>,
    /// Tenant settings service for per-tenant configuration
    pub settings_service: Arc<SettingsService>,
    /// Security notification service (email/SMS/WhatsApp)
    pub security_notification_service: Arc<crate::security::SecurityNotificationService>,
    /// M2M authentication service
    pub m2m_service: Arc<crate::m2m::M2mAuthService>,
    /// AI security engine for ML-based threat detection
    pub ai_engine: Option<Arc<vault_core::ai::AiSecurityEngine>>,
}

impl AppState {
    /// Create new app state with database
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        // Initialize database
        let db = Database::new(&config.database_url).await?;

        // Connect to Redis if configured
        let redis = if let Some(ref redis_url) = config.redis_url {
            // Validate TLS scheme if TLS is required
            if config.redis_require_tls && !redis_url.starts_with("rediss://") {
                anyhow::bail!(
                    "Redis TLS is required (redis_require_tls=true) but URL does not use rediss:// scheme. \
                     Current URL scheme indicates insecure connection. \
                     Please update REDIS_URL to use rediss:// for encrypted connections."
                );
            }
            
            let client = redis::Client::open(redis_url.as_str())
                .map_err(|e| anyhow::anyhow!("Failed to create Redis client: {}", e))?;
            
            match redis::aio::ConnectionManager::new(client).await {
                Ok(conn) => {
                    tracing::info!(
                        tls_enabled = redis_url.starts_with("rediss://"),
                        "Redis connection established"
                    );
                    Some(conn)
                }
                Err(e) => {
                    if redis_url.starts_with("rediss://") {
                        anyhow::bail!(
                            "Failed to establish TLS Redis connection: {}. \
                             Please verify your Redis server supports TLS and the certificate is valid.",
                            e
                        );
                    } else {
                        anyhow::bail!("Failed to establish Redis connection: {}", e);
                    }
                }
            }
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

        // Initialize shared SMS code store
        let sms_code_store: Arc<dyn vault_core::sms::OtpCodeStore> = if let Some(ref redis_mgr) = redis {
            Arc::new(vault_core::sms::RedisOtpCodeStore::new(redis_mgr.clone()))
        } else {
            Arc::new(vault_core::sms::InMemoryOtpCodeStore::new())
        };

        // Initialize SMS service if configured (used by AuthService for MFA)
        let sms_service = initialize_sms_service(&config, sms_code_store.clone()).await;

        let data_encryption_key = Arc::new(load_data_encryption_key()?);
        let default_provider = match config.security.data_encryption.provider {
            DataEncryptionProvider::Local => KmsProviderKind::Local,
            DataEncryptionProvider::AwsKms => KmsProviderKind::AwsKms,
            DataEncryptionProvider::AzureKv => KmsProviderKind::AzureKv,
            DataEncryptionProvider::GcpKms => KmsProviderKind::GcpKms,
            DataEncryptionProvider::AlicloudKms => KmsProviderKind::AlicloudKms,
            DataEncryptionProvider::OracleKms => KmsProviderKind::OracleKms,
        };

        let mut kms_registry = KmsRegistry::new(default_provider).with_provider(Arc::new(
            LocalMasterKeyProvider::new((*data_encryption_key).clone()),
        ));

        #[cfg(feature = "aws-kms")]
        {
            let aws_cfg = &config.security.data_encryption.aws_kms;
            if let Some(key_id) = aws_cfg.key_id.clone() {
                let provider = crate::security::tenant_keys::AwsKmsProvider::new(
                    aws_cfg.region.clone(),
                    key_id,
                    aws_cfg.endpoint.clone(),
                    aws_cfg.tenant_context_key.clone(),
                )
                .await?;
                kms_registry = kms_registry.with_provider(Arc::new(provider));
            }
        }

        #[cfg(not(feature = "aws-kms"))]
        {
            if default_provider == KmsProviderKind::AwsKms {
                anyhow::bail!("AWS KMS support is not enabled; build with feature `aws-kms`");
            }
        }

        #[cfg(feature = "azure-kv")]
        {
            let azure_cfg = &config.security.data_encryption.azure_kv;
            if let (Some(vault_url), Some(key_name)) =
                (azure_cfg.vault_url.clone(), azure_cfg.key_name.clone())
            {
                let provider = crate::security::tenant_keys::AzureKeyVaultProvider::new(
                    vault_url,
                    key_name,
                    azure_cfg.key_version.clone(),
                    azure_cfg.tenant_context_key.clone(),
                )?;
                kms_registry = kms_registry.with_provider(Arc::new(provider));
            }
        }

        #[cfg(not(feature = "azure-kv"))]
        {
            if default_provider == KmsProviderKind::AzureKv {
                anyhow::bail!("Azure Key Vault support is not enabled; build with feature `azure-kv`");
            }
        }

        #[cfg(feature = "gcp-kms")]
        {
            let gcp_cfg = &config.security.data_encryption.gcp_kms;
            if let Some(key_name) = gcp_cfg.key_name.clone() {
                let provider = crate::security::tenant_keys::GcpKmsProvider::new(
                    key_name,
                    gcp_cfg.tenant_context_key.clone(),
                )
                .await?;
                kms_registry = kms_registry.with_provider(Arc::new(provider));
            }
        }

        #[cfg(not(feature = "gcp-kms"))]
        {
            if default_provider == KmsProviderKind::GcpKms {
                anyhow::bail!("GCP KMS support is not enabled; build with feature `gcp-kms`");
            }
        }

        #[cfg(not(feature = "alicloud-kms"))]
        {
            if default_provider == KmsProviderKind::AlicloudKms {
                anyhow::bail!(
                    "Alicloud KMS support is not enabled; build with feature `alicloud-kms`"
                );
            }
        }

        #[cfg(not(feature = "oracle-kms"))]
        {
            if default_provider == KmsProviderKind::OracleKms {
                anyhow::bail!(
                    "Oracle KMS support is not enabled; build with feature `oracle-kms`"
                );
            }
        }

        let kms_registry = Arc::new(kms_registry);
        let dek_cache_ttl = std::time::Duration::from_secs(
            config.security.data_encryption.dek_cache.ttl_minutes * 60,
        );
        let dek_cache_redis = if config.security.data_encryption.dek_cache.redis_enabled {
            redis.clone()
        } else {
            None
        };
        let tenant_key_service = Arc::new(TenantKeyService::new(
            db.clone(),
            kms_registry,
            dek_cache_ttl,
            dek_cache_redis,
            data_encryption_key.clone(),
        ));

        // Initialize auth service with database
        let db_context = Arc::new(vault_core::db::DbContext::new(db.pool().clone()));
        let base_url = config.base_url.clone();
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

        auth_service = auth_service
            .with_data_encryption_key((*data_encryption_key).clone())
            .with_data_key_resolver(tenant_key_service.clone());

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
        let webhook_service = WebhookService::new(db.clone(), tenant_key_service.clone());

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

        let settings_service = Arc::new(SettingsService::new(
            Arc::new(SettingsRepository::new(db.pool().clone())),
            tenant_key_service.clone(),
        ));

        let communications = Arc::new(TenantCommunicationResolver::new(
            Arc::new(config.clone()),
            settings_service.clone(),
            tenant_key_service.clone(),
            sms_code_store.clone(),
        ));

        let communications_for_email = communications.clone();
        auth_service = auth_service.with_email_sender(move |payload| {
            let communications = communications_for_email.clone();
            async move {
                if let Some(sender) = communications.resolve_email_sender(&payload.tenant_id).await {
                    sender
                        .service
                        .send_email(EmailRequest {
                            to: payload.to,
                            to_name: None,
                            subject: payload.subject,
                            html_body: payload.html_body,
                            text_body: payload.text_body,
                            from: sender.from_address,
                            from_name: sender.from_name,
                            reply_to: sender.reply_to,
                            headers: std::collections::HashMap::new(),
                        })
                        .await
                        .map_err(|e| vault_core::error::VaultError::internal(format!(
                            "Failed to send email: {}",
                            e
                        )))
                } else {
                    tracing::info!("Email would be sent to {}: {}", payload.to, payload.subject);
                    Ok(())
                }
            }
        });

        auth_service = auth_service.with_sms_service_resolver(communications.clone());

        let auth_service = Arc::new(auth_service);

        let base_url = format!("https://{}:{}", config.host, config.port);
        let security_notification_service = Arc::new(
            crate::security::SecurityNotificationService::new(
                auth_service.clone(),
                settings_service.clone(),
                communications.clone(),
                base_url,
            ),
        );

        let web3_auth = {
            let base_url = config.base_url.clone();
            let domain = config
                .web3_auth
                .domain
                .clone()
                .unwrap_or_else(|| base_url.replace("https://", "").replace("http://", ""));

            let web3_auth = if let Some(ref redis_mgr) = redis {
                create_web3_auth_with_redis(&domain, &base_url, redis_mgr.clone())
            } else {
                create_web3_auth_in_memory(&domain, &base_url)
            };

            Arc::new(web3_auth)
        };

        let impersonation_service = Arc::new(ImpersonationService::new(db.clone()));
        let m2m_service = Arc::new(crate::m2m::M2mAuthService::new(
            db.clone(),
            config.jwt.issuer.clone(),
            config.jwt.audience.clone(),
        ));
        let ai_engine = if std::env::var("VAULT_AI_ENABLED").unwrap_or_else(|_| "true".to_string())
            == "true"
        {
            let ai_config = vault_core::ai::AiSecurityConfig::default();
            let db_context = vault_core::db::DbContext::new(db.pool().clone());
            match vault_core::ai::AiSecurityEngine::new(ai_config, db_context).await {
                Ok(engine) => {
                    tracing::info!("AI security engine initialized");
                    Some(Arc::new(engine))
                }
                Err(e) => {
                    tracing::warn!("Failed to initialize AI security engine: {}", e);
                    None
                }
            }
        } else {
            tracing::info!("AI security engine disabled via configuration");
            None
        };

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
            tenant_key_service,
            email_service,
            communications,
            web3_auth,
            consent_manager,
            risk_engine,
            impersonation_service,
            settings_service,
            security_notification_service,
            m2m_service,
            ai_engine,
        })
    }

    /// Set tenant context for database queries
    pub async fn set_tenant_context(&self, tenant_id: &str) -> anyhow::Result<()> {
        let mut conn = self.db.pool().acquire().await?;

        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }

    /// Create an audit logger with webhook support if enabled
    pub fn audit_logger(&self) -> AuditLogger {
        let mut logger = AuditLogger::new(self.db.clone());

        if self.config.webhook.enabled {
            let notifier = Arc::new(DefaultWebhookNotifier::new(self.db.clone()));
            logger.enable_webhooks(notifier);
        }

        logger.enable_security_notifications(self.security_notification_service.clone());

        logger
    }

    /// Check session limits for a user and apply eviction policy if needed
    /// 
    /// SECURITY: Uses atomic database operations with advisory locks to prevent
    /// race conditions where concurrent logins could exceed session limits.
    /// 
    /// Returns Ok(()) if the new session can proceed, Err if it should be denied
    pub async fn check_session_limits(
        &self,
        tenant_id: &str,
        user_id: &str,
        ip_address: Option<&str>,
    ) -> anyhow::Result<std::result::Result<(), SessionLimitError>> {
        let limits = &self.config.security.session_limits;

        // SECURITY: Use atomic check-and-enforce to prevent race conditions
        let eviction_policy = match limits.eviction_policy {
            EvictionPolicy::OldestFirst => "oldest_first",
            EvictionPolicy::DenyNew => "deny_new",
            EvictionPolicy::NewestFirst => "deny_new", // Treat as deny for now
        };

        let can_proceed = self
            .db
            .sessions()
            .check_and_enforce_session_limit(
                tenant_id,
                user_id,
                limits.max_concurrent_sessions,
                eviction_policy,
            )
            .await
            .map_err(|e| anyhow::anyhow!("Failed to check session limits: {}", e))?;

        if !can_proceed {
            // Get current count for error message
            let current_count = self
                .db
                .sessions()
                .count_active_sessions_for_user(tenant_id, user_id)
                .await
                .unwrap_or(0) as usize;

            return Ok(Err(SessionLimitError {
                current_sessions: current_count,
                max_sessions: limits.max_concurrent_sessions,
                message: format!(
                    "Maximum concurrent sessions reached ({}). Please log out from another device.",
                    limits.max_concurrent_sessions
                ),
            }));
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
    // SECURITY: In production, a persistent encryption key MUST be configured.
    // Ephemeral keys cause all sessions to be invalidated on restart.
    let is_production = std::env::var("ENVIRONMENT")
        .or_else(|_| std::env::var("RUST_ENV"))
        .map(|v| v == "production" || v == "prod")
        .unwrap_or(false);

    if let Ok(path) = std::env::var("VAULT_MASTER_KEY_FILE")
        .or_else(|_| std::env::var("MASTER_KEY_FILE"))
    {
        if let Ok(contents) = std::fs::read(&path) {
            let trimmed = String::from_utf8_lossy(&contents);
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed.trim()) {
                if decoded.len() == 32 {
                    return Ok(decoded);
                }
            }
            if contents.len() == 32 {
                return Ok(contents);
            }
            anyhow::bail!("MASTER_KEY_FILE must contain 32 raw bytes or base64-encoded 32 bytes");
        } else {
            // SECURITY: Only auto-generate keys in development
            if is_production {
                anyhow::bail!(
                    "SECURITY: VAULT_MASTER_KEY_FILE '{}' not found in production. \
                     You must provide a persistent encryption key. \
                     Set VAULT_MASTER_KEY_FILE to a path containing a 32-byte base64-encoded key, \
                     or set VAULT_DATA_ENCRYPTION_KEY directly.",
                    path
                );
            }
            let key = vault_core::crypto::generate_random_bytes(32);
            let encoded = base64::engine::general_purpose::STANDARD.encode(&key);
            std::fs::write(&path, encoded.as_bytes())?;
            tracing::warn!(
                path = %path,
                "Generated new platform master key and wrote to MASTER_KEY_FILE"
            );
            return Ok(key);
        }
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

    // SECURITY: In production, require explicit key configuration
    if is_production {
        anyhow::bail!(
            "SECURITY: No data encryption key configured in production. \
             You must set one of: \
             1. VAULT_MASTER_KEY_FILE (path to 32-byte base64-encoded key file) \
             2. VAULT_DATA_ENCRYPTION_KEY (32-byte base64-encoded key) \
             Ephemeral keys are not allowed in production as they invalidate all sessions on restart."
        );
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
    sms_code_store: Arc<dyn vault_core::sms::OtpCodeStore>,
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
    let code_store: Box<dyn vault_core::sms::OtpCodeStore> =
        Box::new(SharedOtpCodeStore::new(sms_code_store));
    
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
        fallback_to_sms: true, // Default fallback behavior
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
