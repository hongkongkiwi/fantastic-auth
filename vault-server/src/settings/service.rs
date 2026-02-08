//! Settings Service
//!
//! Business logic for tenant settings management.

use crate::settings::{
    models::*,
    repository::SettingsRepository,
    validation,
};
use crate::routes::ApiError;
use std::sync::Arc;

pub struct SettingsService {
    repository: Arc<SettingsRepository>,
}

impl SettingsService {
    pub fn new(repository: Arc<SettingsRepository>) -> Self {
        Self { repository }
    }

    /// Get all settings for a tenant
    pub async fn get_settings(&self, tenant_id: &str) -> Result<TenantSettings, ApiError> {
        // Initialize if not exists
        if !self.repository.settings_exist(tenant_id).await
            .map_err(|_| ApiError::Internal)? 
        {
            self.repository.initialize_for_tenant(tenant_id).await
                .map_err(|_| ApiError::Internal)?;
        }

        self.repository.get_settings(tenant_id).await
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
        self.repository.update_auth_settings(tenant_id, &settings, changed_by, reason).await
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

        self.repository.update_security_settings(tenant_id, &settings, changed_by, reason).await
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

        self.repository.update_org_settings(tenant_id, &settings, changed_by, reason).await
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

        self.repository.update_branding_settings(tenant_id, &settings, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update email settings
    pub async fn update_email_settings(
        &self,
        tenant_id: &str,
        settings: EmailSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<EmailSettings, ApiError> {
        validation::validate_email_settings(&settings)?;

        self.repository.update_email_settings(tenant_id, &settings, changed_by, reason).await
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

        self.repository.update_oauth_settings(tenant_id, &settings, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
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

        self.repository.update_localization_settings(tenant_id, &settings, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update webhook settings
    pub async fn update_webhook_settings(
        &self,
        tenant_id: &str,
        settings: WebhookSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<WebhookSettings, ApiError> {
        validation::validate_webhook_settings(&settings)?;

        self.repository.update_webhook_settings(tenant_id, &settings, changed_by, reason).await
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

        self.repository.update_privacy_settings(tenant_id, &settings, changed_by, reason).await
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

        self.repository.update_advanced_settings(tenant_id, &settings, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
    }

    /// Update all settings at once (use with caution)
    pub async fn update_all_settings(
        &self,
        tenant_id: &str,
        settings: TenantSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<TenantSettings, ApiError> {
        // Validate all
        validation::validate_all_settings(&settings)?;

        // Update each category
        self.repository.update_auth_settings(tenant_id, &settings.auth, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;
        
        self.repository.update_security_settings(tenant_id, &settings.security, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;
        
        self.repository.update_org_settings(tenant_id, &settings.org, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;
        
        self.repository.update_branding_settings(tenant_id, &settings.branding, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;
        
        self.repository.update_email_settings(tenant_id, &settings.email, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;
        
        self.repository.update_oauth_settings(tenant_id, &settings.oauth, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;
        
        self.repository.update_localization_settings(tenant_id, &settings.localization, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;
        
        self.repository.update_webhook_settings(tenant_id, &settings.webhook, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;
        
        self.repository.update_privacy_settings(tenant_id, &settings.privacy, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;
        
        self.repository.update_advanced_settings(tenant_id, &settings.advanced, changed_by, reason).await
            .map_err(|_| ApiError::Internal)?;

        Ok(settings)
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
        
        self.repository.get_settings_history(tenant_id, category, per_page, offset).await
            .map_err(|_| ApiError::Internal)
    }

    /// Get settings with metadata
    pub async fn get_settings_response(
        &self,
        tenant_id: &str,
    ) -> Result<SettingsResponse, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        let row = self.repository.get_settings_row(tenant_id).await
            .map_err(|_| ApiError::Internal)?;

        Ok(SettingsResponse {
            tenant_id: tenant_id.to_string(),
            settings,
            updated_at: row.updated_at,
        })
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
        Ok((settings.security.session_lifetime, settings.security.session_limits))
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
            if settings.security.mfa_settings.require_mfa_for_roles.is_empty() {
                return Ok(true); // Required for all
            }
            return Ok(settings.security.mfa_settings.require_mfa_for_roles.contains(&role.to_string()));
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
    pub async fn get_email_config(
        &self,
        tenant_id: &str,
    ) -> Result<EmailSettings, ApiError> {
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
    pub async fn get_allowed_callbacks(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<String>, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.advanced.allowed_callback_urls)
    }

    /// Check if feature flag is enabled
    pub async fn is_feature_enabled(
        &self,
        tenant_id: &str,
        flag: &str,
    ) -> Result<bool, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.advanced.feature_flags.get(flag).copied().unwrap_or(false))
    }

    /// Get organization settings
    pub async fn get_org_settings(
        &self,
        tenant_id: &str,
    ) -> Result<OrgSettings, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.org)
    }

    /// Get privacy/consent settings
    pub async fn get_privacy_settings(
        &self,
        tenant_id: &str,
    ) -> Result<PrivacySettings, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.privacy)
    }

    /// Get webhook settings
    pub async fn get_webhook_settings(
        &self,
        tenant_id: &str,
    ) -> Result<WebhookSettings, ApiError> {
        let settings = self.get_settings(tenant_id).await?;
        Ok(settings.webhook)
    }
}
