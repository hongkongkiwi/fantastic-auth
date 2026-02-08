//! Tenant-aware email and SMS resolution helpers.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::warn;

use crate::config::{Config, SmsProviderType as PlatformSmsProviderType, WhatsAppConfig as PlatformWhatsAppConfig};
use crate::security::TenantKeyService;
use crate::settings::models::{SmsProviderType, WhatsAppSettings};
use crate::settings::SettingsService;

use vault_core::auth::SmsServiceResolver;
use vault_core::email::{EmailService, SmtpEmailService};
use vault_core::sms::{OtpCodeStore, SmsConfig as CoreSmsConfig, SmsService, SmsProvider, TwilioProvider, WhatsAppProvider};

const DEFAULT_TENANT_FROM_ADDRESS: &str = "noreply@example.com";
const DEFAULT_TENANT_FROM_NAME: &str = "Vault";

#[derive(Clone)]
pub struct ResolvedEmailSender {
    pub service: Arc<dyn EmailService>,
    pub from_address: String,
    pub from_name: String,
    pub reply_to: Option<String>,
}

#[derive(Clone)]
pub struct TenantCommunicationResolver {
    config: Arc<Config>,
    settings_service: Arc<SettingsService>,
    tenant_key_service: Arc<TenantKeyService>,
    sms_code_store: Arc<dyn OtpCodeStore>,
}

impl TenantCommunicationResolver {
    pub fn new(
        config: Arc<Config>,
        settings_service: Arc<SettingsService>,
        tenant_key_service: Arc<TenantKeyService>,
        sms_code_store: Arc<dyn OtpCodeStore>,
    ) -> Self {
        Self {
            config,
            settings_service,
            tenant_key_service,
            sms_code_store,
        }
    }

    pub async fn resolve_email_sender(&self, tenant_id: &str) -> Option<ResolvedEmailSender> {
        let settings = self.settings_service.get_settings(tenant_id).await.ok()?;
        let custom_smtp = settings.email.custom_smtp.clone();

        let (smtp_host, smtp_port, smtp_username, smtp_password) = if let Some(custom) = custom_smtp {
            let password = match decrypt_secret(&self.tenant_key_service, tenant_id, &custom.password_encrypted).await {
                Ok(value) => value,
                Err(e) => {
                    warn!(tenant_id = tenant_id, "Failed to decrypt tenant SMTP password: {:?}", e);
                    return None;
                }
            };
            (custom.host, custom.port, custom.username, password)
        } else {
            let platform = self.config.smtp.as_ref()?;
            (
                platform.host.clone(),
                platform.port,
                platform.username.clone(),
                platform.password.clone(),
            )
        };

        let (from_address, from_name) = select_from_address(&settings.email.from_address, &settings.email.from_name, &self.config);

        let base_url = self.config.base_url.clone();
        let app_name = settings.branding.brand_name.clone();
        let service = match SmtpEmailService::new(
            &smtp_host,
            smtp_port,
            &smtp_username,
            &smtp_password,
            from_address.clone(),
            from_name.clone(),
            base_url,
            app_name,
        ) {
            Ok(service) => Arc::new(service),
            Err(e) => {
                warn!(tenant_id = tenant_id, error = %e, "Failed to initialize SMTP email service");
                return None;
            }
        };

        Some(ResolvedEmailSender {
            service,
            from_address,
            from_name,
            reply_to: settings.email.reply_to.clone(),
        })
    }

    pub async fn resolve_sms_service(&self, tenant_id: &str) -> Option<Arc<SmsService>> {
        let settings = self.settings_service.get_settings(tenant_id).await.ok()?;
        let sms_settings = settings.sms;

        let provider = sms_settings
            .provider
            .clone()
            .map(map_sms_provider)
            .unwrap_or(self.config.sms.provider);

        let twilio_account_sid = sms_settings
            .twilio_account_sid
            .clone()
            .or_else(|| self.config.sms.twilio_account_sid.clone());

        let twilio_auth_token = match sms_settings.twilio_auth_token_encrypted.as_ref() {
            Some(value) => decrypt_secret(&self.tenant_key_service, tenant_id, value).await.ok(),
            None => self.config.sms.twilio_auth_token.clone(),
        };

        let twilio_from_number = sms_settings
            .twilio_from_number
            .clone()
            .or_else(|| self.config.sms.twilio_from_number.clone());

        let sms_provider = match provider {
            PlatformSmsProviderType::Disabled => None,
            PlatformSmsProviderType::Twilio => {
                let account_sid = twilio_account_sid?;
                let auth_token = twilio_auth_token?;
                let from_number = twilio_from_number?;
                Some(Box::new(TwilioProvider::new(
                    &account_sid,
                    &auth_token,
                    &from_number,
                )) as Box<dyn SmsProvider>)
            }
            PlatformSmsProviderType::Mock => {
                Some(Box::new(vault_core::sms::MockSmsProvider::new()) as Box<dyn SmsProvider>)
            }
            PlatformSmsProviderType::AwsSns => {
                warn!(tenant_id = tenant_id, "AWS SNS SMS provider not implemented");
                None
            }
        };

        let mut whatsapp = self.config.whatsapp.clone();
        if let Some(ref override_settings) = sms_settings.whatsapp {
            apply_whatsapp_overrides(&mut whatsapp, override_settings, &self.tenant_key_service, tenant_id).await;
        }

        let whatsapp_provider = if let Some(core_cfg) = whatsapp.core_config() {
            Some(Box::new(WhatsAppProvider::new(core_cfg)) as Box<dyn SmsProvider>)
        } else {
            None
        };

        if sms_provider.is_none() && whatsapp_provider.is_none() {
            return None;
        }

        let sms_config = CoreSmsConfig {
            max_sends_per_phone: sms_settings
                .max_sends_per_phone
                .unwrap_or(self.config.sms.max_sends_per_phone),
            rate_limit_window_secs: sms_settings
                .rate_limit_window_secs
                .unwrap_or(self.config.sms.rate_limit_window_secs),
            code_expiry_minutes: sms_settings
                .code_expiry_minutes
                .unwrap_or(self.config.sms.code_expiry_minutes),
            code_length: sms_settings
                .code_length
                .unwrap_or(self.config.sms.code_length),
            fallback_to_sms: whatsapp.fallback_to_sms,
        };

        let code_store: Box<dyn OtpCodeStore> = Box::new(SharedOtpCodeStore::new(self.sms_code_store.clone()));

        Some(Arc::new(SmsService::new_multi_channel(
            sms_provider,
            whatsapp_provider,
            code_store,
            sms_config,
        )))
    }
}

#[async_trait]
impl SmsServiceResolver for TenantCommunicationResolver {
    async fn resolve_sms_service(&self, tenant_id: &str) -> Option<Arc<SmsService>> {
        TenantCommunicationResolver::resolve_sms_service(self, tenant_id).await
    }
}

pub struct SharedOtpCodeStore {
    inner: Arc<dyn OtpCodeStore>,
}

impl SharedOtpCodeStore {
    pub fn new(inner: Arc<dyn OtpCodeStore>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl OtpCodeStore for SharedOtpCodeStore {
    async fn store_code(
        &self,
        phone: &str,
        code: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), vault_core::sms::SmsError> {
        self.inner.store_code(phone, code, expires_at).await
    }

    async fn retrieve_code(
        &self,
        phone: &str,
    ) -> Result<Option<(String, chrono::DateTime<chrono::Utc>)>, vault_core::sms::SmsError> {
        self.inner.retrieve_code(phone).await
    }

    async fn check_rate_limit(
        &self,
        phone: &str,
        max_attempts: u32,
        window_secs: u64,
    ) -> Result<bool, vault_core::sms::SmsError> {
        self.inner.check_rate_limit(phone, max_attempts, window_secs).await
    }

    async fn record_attempt(
        &self,
        phone: &str,
        window_secs: u64,
    ) -> Result<u32, vault_core::sms::SmsError> {
        self.inner.record_attempt(phone, window_secs).await
    }
}

fn map_sms_provider(provider: SmsProviderType) -> PlatformSmsProviderType {
    match provider {
        SmsProviderType::Disabled => PlatformSmsProviderType::Disabled,
        SmsProviderType::Twilio => PlatformSmsProviderType::Twilio,
        SmsProviderType::AwsSns => PlatformSmsProviderType::AwsSns,
        SmsProviderType::Mock => PlatformSmsProviderType::Mock,
    }
}

fn select_from_address(
    tenant_from_address: &str,
    tenant_from_name: &str,
    config: &Config,
) -> (String, String) {
    let tenant_is_default = tenant_from_address == DEFAULT_TENANT_FROM_ADDRESS
        && tenant_from_name == DEFAULT_TENANT_FROM_NAME;

    if !tenant_is_default {
        return (tenant_from_address.to_string(), tenant_from_name.to_string());
    }

    if let Some(ref smtp) = config.smtp {
        return (smtp.from_address.clone(), smtp.from_name.clone());
    }

    (tenant_from_address.to_string(), tenant_from_name.to_string())
}

async fn decrypt_secret(
    tenant_keys: &TenantKeyService,
    tenant_id: &str,
    encrypted: &str,
) -> Result<String, crate::routes::ApiError> {
    let key = tenant_keys
        .get_data_key(tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load tenant data key: {}", e);
            crate::routes::ApiError::Internal
        })?;

    let bytes = crate::security::encryption::decrypt_from_base64(&key, encrypted).map_err(|e| {
        tracing::error!("Failed to decrypt secret: {}", e);
        crate::routes::ApiError::Internal
    })?;

    String::from_utf8(bytes).map_err(|_| crate::routes::ApiError::Internal)
}

async fn apply_whatsapp_overrides(
    config: &mut PlatformWhatsAppConfig,
    overrides: &WhatsAppSettings,
    tenant_keys: &TenantKeyService,
    tenant_id: &str,
) {
    if let Some(enabled) = overrides.enabled {
        config.enabled = enabled;
    }
    if let Some(ref value) = overrides.phone_number_id {
        config.phone_number_id = Some(value.clone());
    }
    if let Some(ref value) = overrides.access_token_encrypted {
        if let Ok(decrypted) = decrypt_secret(tenant_keys, tenant_id, value).await {
            config.access_token = Some(decrypted);
        }
    }
    if let Some(ref value) = overrides.api_version {
        config.api_version = value.clone();
    }
    if let Some(ref value) = overrides.template_name {
        config.template_name = value.clone();
    }
    if let Some(ref value) = overrides.language_code {
        config.language_code = value.clone();
    }
    if let Some(value) = overrides.fallback_to_sms {
        config.fallback_to_sms = value;
    }
}
