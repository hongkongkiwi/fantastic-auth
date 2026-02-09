//! Settings Service
//!
//! Business logic for tenant settings management.

use crate::routes::ApiError;
use crate::settings::{models::*, repository::SettingsRepository, validation};
use std::sync::Arc;

const REDACTED_SECRET: &str = "********";

pub struct SettingsService {
    repository: Arc<SettingsRepository>,
    tenant_key_service: Arc<crate::security::TenantKeyService>,
}

impl SettingsService {
    pub fn new(
        repository: Arc<SettingsRepository>,
        tenant_key_service: Arc<crate::security::TenantKeyService>,
    ) -> Self {
        Self {
            repository,
            tenant_key_service,
        }
    }

    /// Get all settings for a tenant
    pub async fn get_settings(&self, tenant_id: &str) -> Result<TenantSettings, ApiError> {
        // Initialize if not exists
        if !self
            .repository
            .settings_exist(tenant_id)
            .await
            .map_err(|_| ApiError::Internal)?
        {
            self.repository
                .initialize_for_tenant(tenant_id)
                .await
                .map_err(|_| ApiError::Internal)?;
        }

        self.repository
            .get_settings(tenant_id)
            .await
            .map_err(|_| ApiError::Internal)
    }

    /// Update authentication settings
    pub async fn update_auth_settings(
        &self,
        tenant_id: &str,
        settings: AuthSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<AuthSettings, ApiError> {
        // Validate
        validation::validate_auth_settings(&settings)?;

        // Update
        self.repository
            .update_auth_settings(tenant_id, &settings, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update security settings
    pub async fn update_security_settings(
        &self,
        tenant_id: &str,
        settings: SecuritySettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<SecuritySettings, ApiError> {
        validation::validate_security_settings(&settings)?;

        self.repository
            .update_security_settings(tenant_id, &settings, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update organization settings
    pub async fn update_org_settings(
        &self,
        tenant_id: &str,
        settings: OrgSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<OrgSettings, ApiError> {
        validation::validate_org_settings(&settings)?;

        self.repository
            .update_org_settings(tenant_id, &settings, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update branding settings
    pub async fn update_branding_settings(
        &self,
        tenant_id: &str,
        settings: BrandingSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<BrandingSettings, ApiError> {
        validation::validate_branding_settings(&settings)?;

        self.repository
            .update_branding_settings(tenant_id, &settings, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update email settings
    pub async fn update_email_settings(
        &self,
        tenant_id: &str,
        mut settings: EmailSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<EmailSettings, ApiError> {
        self.merge_existing_email_secrets(tenant_id, &mut settings)
            .await?;
        validation::validate_email_settings(&settings)?;

        let settings = self.encrypt_email_settings(tenant_id, settings).await?;

        self.repository
            .update_email_settings(tenant_id, &settings, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update SMS settings
    pub async fn update_sms_settings(
        &self,
        tenant_id: &str,
        mut settings: SmsSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<SmsSettings, ApiError> {
        self.merge_existing_sms_secrets(tenant_id, &mut settings)
            .await?;
        validation::validate_sms_settings(&settings)?;

        let settings = self.encrypt_sms_settings(tenant_id, settings).await?;

        self.repository
            .update_sms_settings(tenant_id, &settings, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update OAuth settings
    pub async fn update_oauth_settings(
        &self,
        tenant_id: &str,
        settings: OAuthSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<OAuthSettings, ApiError> {
        validation::validate_oauth_settings(&settings)?;

        self.repository
            .update_oauth_settings(tenant_id, &settings, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// List retention settings for all tenants
    pub async fn list_privacy_retention(&self) -> Result<Vec<(String, i64)>, ApiError> {
        self.repository
            .list_privacy_retention()
            .await
            .map_err(|_| ApiError::Internal)
    }

    /// Update localization settings
    pub async fn update_localization_settings(
        &self,
        tenant_id: &str,
        settings: LocalizationSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<LocalizationSettings, ApiError> {
        validation::validate_localization_settings(&settings)?;

        self.repository
            .update_localization_settings(tenant_id, &settings, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update webhook settings
    pub async fn update_webhook_settings(
        &self,
        tenant_id: &str,
        mut settings: WebhookSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<WebhookSettings, ApiError> {
        self.merge_existing_webhook_secrets(tenant_id, &mut settings)
            .await?;
        validation::validate_webhook_settings(&settings)?;

        self.repository
            .update_webhook_settings(tenant_id, &settings, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update privacy settings
    pub async fn update_privacy_settings(
        &self,
        tenant_id: &str,
        settings: PrivacySettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<PrivacySettings, ApiError> {
        validation::validate_privacy_settings(&settings)?;

        self.repository
            .update_privacy_settings(tenant_id, &settings, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update advanced settings
    pub async fn update_advanced_settings(
        &self,
        tenant_id: &str,
        settings: AdvancedSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<AdvancedSettings, ApiError> {
        validation::validate_advanced_settings(&settings)?;

        self.repository
            .update_advanced_settings(tenant_id, &settings, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update all settings at once (use with caution)
    pub async fn update_all_settings(
        &self,
        tenant_id: &str,
        mut settings: TenantSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<TenantSettings, ApiError> {
        self.merge_existing_email_secrets(tenant_id, &mut settings.email)
            .await?;
        self.merge_existing_sms_secrets(tenant_id, &mut settings.sms)
            .await?;
        self.merge_existing_webhook_secrets(tenant_id, &mut settings.webhook)
            .await?;

        // Validate all
        validation::validate_all_settings(&settings)?;

        settings.email = self
            .encrypt_email_settings(tenant_id, settings.email)
            .await?;
        settings.sms = self.encrypt_sms_settings(tenant_id, settings.sms).await?;

        // Update each category
        self.repository
            .update_auth_settings(tenant_id, &settings.auth, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        self.repository
            .update_security_settings(tenant_id, &settings.security, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        self.repository
            .update_org_settings(tenant_id, &settings.org, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        self.repository
            .update_branding_settings(tenant_id, &settings.branding, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        self.repository
            .update_email_settings(tenant_id, &settings.email, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        self.repository
            .update_sms_settings(tenant_id, &settings.sms, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        self.repository
            .update_oauth_settings(tenant_id, &settings.oauth, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        self.repository
            .update_localization_settings(tenant_id, &settings.localization, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        self.repository
            .update_webhook_settings(tenant_id, &settings.webhook, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        self.repository
            .update_privacy_settings(tenant_id, &settings.privacy, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        self.repository
            .update_advanced_settings(tenant_id, &settings.advanced, changed_by, reason)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    async fn encrypt_email_settings(
        &self,
        tenant_id: &str,
        settings: EmailSettings,
    ) -> Result<EmailSettings, ApiError> {
        let mut settings = settings;
        if let Some(ref mut smtp) = settings.custom_smtp {
            smtp.password_encrypted = self
                .encrypt_secret_if_needed(tenant_id, &smtp.password_encrypted)
                .await?;
        }
        Ok(settings)
    }

    async fn encrypt_sms_settings(
        &self,
        tenant_id: &str,
        settings: SmsSettings,
    ) -> Result<SmsSettings, ApiError> {
        let mut settings = settings;
        if let Some(ref secret) = settings.twilio_auth_token_encrypted {
            let encrypted = self.encrypt_secret_if_needed(tenant_id, secret).await?;
            settings.twilio_auth_token_encrypted = Some(encrypted);
        }
        if let Some(ref mut whatsapp) = settings.whatsapp {
            if let Some(ref secret) = whatsapp.access_token_encrypted {
                let encrypted = self.encrypt_secret_if_needed(tenant_id, secret).await?;
                whatsapp.access_token_encrypted = Some(encrypted);
            }
        }
        Ok(settings)
    }

    async fn encrypt_secret_if_needed(
        &self,
        tenant_id: &str,
        value: &str,
    ) -> Result<String, ApiError> {
        let key = self
            .tenant_key_service
            .get_data_key(tenant_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to load tenant data key: {}", e);
                ApiError::Internal
            })?;

        let decrypted = crate::security::encryption::decrypt_from_base64(&key, value);
        if decrypted.is_ok() {
            return Ok(value.to_string());
        }

        crate::security::encryption::encrypt_to_base64(&key, value.as_bytes()).map_err(|e| {
            tracing::error!("Failed to encrypt secret: {}", e);
            ApiError::Internal
        })
    }

    /// Get settings change history
    pub async fn get_settings_history(
        &self,
        tenant_id: &str,
        category: Option<&str>,
        page: i64,
        per_page: i64,
    ) -> Result<(Vec<SettingsHistoryRow>, i64), ApiError> {
        let offset = (page - 1) * per_page;

        self.repository
            .get_settings_history(tenant_id, category, per_page, offset)
            .await
            .map_err(|_| ApiError::Internal)
    }

    /// Get settings with metadata
    pub async fn get_settings_response(
        &self,
        tenant_id: &str,
    ) -> Result<SettingsResponse, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        let row = self
            .repository
            .get_settings_row(tenant_id)
            .await
            .map_err(|_| ApiError::Internal)?;

        Ok(SettingsResponse {
            tenant_id: tenant_id.to_string(),
            settings,
            updated_at: row.updated_at,
        })
    }

    /// Get settings response with secret fields redacted for API responses.
    pub async fn get_settings_response_redacted(
        &self,
        tenant_id: &str,
    ) -> Result<SettingsResponse, ApiError> {
        let mut response = self.get_settings_response(tenant_id).await?;
        response.settings = Self::redact_tenant_settings(response.settings);
        Ok(response)
    }

    /// Get all settings with secret fields redacted for API responses.
    pub async fn get_settings_redacted(&self, tenant_id: &str) -> Result<TenantSettings, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(Self::redact_tenant_settings(settings))
    }

    pub fn redact_email_settings(mut settings: EmailSettings) -> EmailSettings {
        if let Some(ref mut smtp) = settings.custom_smtp {
            if !smtp.password_encrypted.is_empty() {
                smtp.password_encrypted = REDACTED_SECRET.to_string();
            }
        }
        settings
    }

    pub fn redact_sms_settings(mut settings: SmsSettings) -> SmsSettings {
        if settings.twilio_auth_token_encrypted.is_some() {
            settings.twilio_auth_token_encrypted = Some(REDACTED_SECRET.to_string());
        }
        if let Some(ref mut whatsapp) = settings.whatsapp {
            if whatsapp.access_token_encrypted.is_some() {
                whatsapp.access_token_encrypted = Some(REDACTED_SECRET.to_string());
            }
        }
        settings
    }

    pub fn redact_webhook_settings(mut settings: WebhookSettings) -> WebhookSettings {
        for endpoint in &mut settings.webhook_endpoints {
            if !endpoint.secret.is_empty() {
                endpoint.secret = REDACTED_SECRET.to_string();
            }
        }
        settings
    }

    pub fn redact_tenant_settings(mut settings: TenantSettings) -> TenantSettings {
        settings.email = Self::redact_email_settings(settings.email);
        settings.sms = Self::redact_sms_settings(settings.sms);
        settings.webhook = Self::redact_webhook_settings(settings.webhook);
        settings
    }

    // ============================================
    // Convenience Methods for Other Services
    // ============================================

    /// Check if an auth method is enabled for tenant
    pub async fn is_auth_method_enabled(
        &self,
        tenant_id: &str,
        method: AuthMethod,
    ) -> Result<bool, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.auth.allowed_auth_methods.contains(&method))
    }

    /// Get password policy for tenant
    pub async fn get_password_policy(
        &self,
        tenant_id: &str,
    ) -> Result<TenantPasswordPolicy, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.security.password_policy)
    }

    /// Get session configuration for tenant
    pub async fn get_session_config(
        &self,
        tenant_id: &str,
    ) -> Result<(SessionLifetime, SessionLimits), ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok((
            settings.security.session_lifetime,
            settings.security.session_limits,
        ))
    }

    /// Check if MFA is required for user
    pub async fn is_mfa_required(
        &self,
        tenant_id: &str,
        user_role: Option<&str>,
    ) -> Result<bool, ApiError> {
        let settings = self.get_settings(tenant_id).await?;

        if !settings.security.mfa_settings.require_mfa {
            return Ok(false);
        }

        // Check role-specific requirements
        if let Some(role) = user_role {
            if settings
                .security
                .mfa_settings
                .require_mfa_for_roles
                .is_empty()
            {
                return Ok(true); // Required for all
            }
            return Ok(settings
                .security
                .mfa_settings
                .require_mfa_for_roles
                .contains(&role.to_string()));
        }

        Ok(true)
    }

    /// Get branding settings for hosted pages
    pub async fn get_branding_for_hosted(
        &self,
        tenant_id: &str,
    ) -> Result<BrandingSettings, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.branding)
    }

    /// Get email configuration for sending
    pub async fn get_email_config(&self, tenant_id: &str) -> Result<EmailSettings, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.email)
    }

    /// Get localization settings
    pub async fn get_localization(
        &self,
        tenant_id: &str,
    ) -> Result<LocalizationSettings, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.localization)
    }

    /// Get effective callback URLs (or wildcard)
    pub async fn get_allowed_callbacks(&self, tenant_id: &str) -> Result<Vec<String>, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.advanced.allowed_callback_urls)
    }

    /// Check if feature flag is enabled
    pub async fn is_feature_enabled(&self, tenant_id: &str, flag: &str) -> Result<bool, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings
            .advanced
            .feature_flags
            .get(flag)
            .copied()
            .unwrap_or(false))
    }

    /// Get organization settings
    pub async fn get_org_settings(&self, tenant_id: &str) -> Result<OrgSettings, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.org)
    }

    /// Get privacy/consent settings
    pub async fn get_privacy_settings(&self, tenant_id: &str) -> Result<PrivacySettings, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.privacy)
    }

    /// Get webhook settings
    pub async fn get_webhook_settings(&self, tenant_id: &str) -> Result<WebhookSettings, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.webhook)
    }

    fn is_redacted_secret(value: &str) -> bool {
        value == REDACTED_SECRET
    }

    async fn merge_existing_email_secrets(
        &self,
        tenant_id: &str,
        settings: &mut EmailSettings,
    ) -> Result<(), ApiError> {
        let needs_existing = settings
            .custom_smtp
            .as_ref()
            .map(|smtp| {
                smtp.password_encrypted.trim().is_empty()
                    || Self::is_redacted_secret(smtp.password_encrypted.trim())
            })
            .unwrap_or(false);

        if !needs_existing {
            return Ok(());
        }

        let existing = self
            .repository
            .get_settings(tenant_id)
            .await
            .map_err(|_| ApiError::Internal)?;

        if let Some(ref mut smtp) = settings.custom_smtp {
            if let Some(existing_smtp) = existing.email.custom_smtp {
                smtp.password_encrypted = existing_smtp.password_encrypted;
            }
        }

        Ok(())
    }

    async fn merge_existing_sms_secrets(
        &self,
        tenant_id: &str,
        settings: &mut SmsSettings,
    ) -> Result<(), ApiError> {
        let twilio_needs_existing = settings
            .twilio_auth_token_encrypted
            .as_ref()
            .map(|v| v.trim().is_empty() || Self::is_redacted_secret(v.trim()))
            .unwrap_or(true);
        let whatsapp_needs_existing = settings
            .whatsapp
            .as_ref()
            .map(|w| {
                w.access_token_encrypted
                    .as_ref()
                    .map(|v| v.trim().is_empty() || Self::is_redacted_secret(v.trim()))
                    .unwrap_or(true)
            })
            .unwrap_or(false);

        if !twilio_needs_existing && !whatsapp_needs_existing {
            return Ok(());
        }

        let existing = self
            .repository
            .get_settings(tenant_id)
            .await
            .map_err(|_| ApiError::Internal)?;

        if twilio_needs_existing {
            settings.twilio_auth_token_encrypted = existing.sms.twilio_auth_token_encrypted;
        }
        if whatsapp_needs_existing {
            if let Some(ref mut incoming_whatsapp) = settings.whatsapp {
                if let Some(existing_whatsapp) = existing.sms.whatsapp {
                    incoming_whatsapp.access_token_encrypted =
                        existing_whatsapp.access_token_encrypted;
                }
            }
        }

        Ok(())
    }

    async fn merge_existing_webhook_secrets(
        &self,
        tenant_id: &str,
        settings: &mut WebhookSettings,
    ) -> Result<(), ApiError> {
        let needs_existing = settings.webhook_endpoints.iter().any(|endpoint| {
            endpoint.secret.trim().is_empty() || Self::is_redacted_secret(endpoint.secret.trim())
        });
        if !needs_existing {
            return Ok(());
        }

        let existing = self
            .repository
            .get_settings(tenant_id)
            .await
            .map_err(|_| ApiError::Internal)?;

        for endpoint in &mut settings.webhook_endpoints {
            if endpoint.secret.trim().is_empty() || Self::is_redacted_secret(endpoint.secret.trim())
            {
                if let Some(existing_endpoint) = existing
                    .webhook
                    .webhook_endpoints
                    .iter()
                    .find(|e| e.id == endpoint.id)
                {
                    endpoint.secret = existing_endpoint.secret.clone();
                }
            }
        }

        Ok(())
    }
}
