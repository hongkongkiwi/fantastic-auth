//! Settings Repository
//!
//! Database operations for tenant settings.

use crate::settings::models::*;
use sqlx::{PgPool, Row};
use anyhow::Result;

pub struct SettingsRepository {
    pool: PgPool,
}

impl SettingsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Initialize default settings for a new tenant
    pub async fn initialize_for_tenant(&self, tenant_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO tenant_settings (tenant_id)
            VALUES ($1)
            ON CONFLICT (tenant_id) DO NOTHING
            "#
        )
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get all settings for a tenant
    pub async fn get_settings(&self, tenant_id: &str) -> Result<TenantSettings> {
        let row = sqlx::query(
            r#"
            SELECT 
                auth_settings,
                security_settings,
                org_settings,
                branding_settings,
                email_settings,
                oauth_settings,
                localization_settings,
                webhook_settings,
                privacy_settings,
                advanced_settings
            FROM tenant_settings
            WHERE tenant_id = $1
            "#
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let settings = TenantSettings {
            auth: serde_json::from_value(row.get("auth_settings"))?,
            security: serde_json::from_value(row.get("security_settings"))?,
            org: serde_json::from_value(row.get("org_settings"))?,
            branding: serde_json::from_value(row.get("branding_settings"))?,
            email: serde_json::from_value(row.get("email_settings"))?,
            oauth: serde_json::from_value(row.get("oauth_settings"))?,
            localization: serde_json::from_value(row.get("localization_settings"))?,
            webhook: serde_json::from_value(row.get("webhook_settings"))?,
            privacy: serde_json::from_value(row.get("privacy_settings"))?,
            advanced: serde_json::from_value(row.get("advanced_settings"))?,
        };

        Ok(settings)
    }

    /// Get settings row (for raw access)
    pub async fn get_settings_row(&self, tenant_id: &str) -> Result<TenantSettingsRow> {
        let row = sqlx::query_as::<_, TenantSettingsRow>(
            r#"
            SELECT 
                tenant_id,
                auth_settings,
                security_settings,
                org_settings,
                branding_settings,
                email_settings,
                oauth_settings,
                localization_settings,
                webhook_settings,
                privacy_settings,
                advanced_settings,
                created_at,
                updated_at,
                updated_by
            FROM tenant_settings
            WHERE tenant_id = $1
            "#
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Update authentication settings
    pub async fn update_auth_settings(
        &self,
        tenant_id: &str,
        settings: &AuthSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let json = serde_json::to_value(settings)?;
        
        sqlx::query(
            r#"
            SELECT update_tenant_setting($1, 'auth', $2, $3, $4)
            "#
        )
        .bind(tenant_id)
        .bind(json)
        .bind(changed_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update security settings
    pub async fn update_security_settings(
        &self,
        tenant_id: &str,
        settings: &SecuritySettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let json = serde_json::to_value(settings)?;
        
        sqlx::query(
            r#"
            SELECT update_tenant_setting($1, 'security', $2, $3, $4)
            "#
        )
        .bind(tenant_id)
        .bind(json)
        .bind(changed_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update organization settings
    pub async fn update_org_settings(
        &self,
        tenant_id: &str,
        settings: &OrgSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let json = serde_json::to_value(settings)?;
        
        sqlx::query(
            r#"
            SELECT update_tenant_setting($1, 'org', $2, $3, $4)
            "#
        )
        .bind(tenant_id)
        .bind(json)
        .bind(changed_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update branding settings
    pub async fn update_branding_settings(
        &self,
        tenant_id: &str,
        settings: &BrandingSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let json = serde_json::to_value(settings)?;
        
        sqlx::query(
            r#"
            SELECT update_tenant_setting($1, 'branding', $2, $3, $4)
            "#
        )
        .bind(tenant_id)
        .bind(json)
        .bind(changed_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update email settings
    pub async fn update_email_settings(
        &self,
        tenant_id: &str,
        settings: &EmailSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let json = serde_json::to_value(settings)?;
        
        sqlx::query(
            r#"
            SELECT update_tenant_setting($1, 'email', $2, $3, $4)
            "#
        )
        .bind(tenant_id)
        .bind(json)
        .bind(changed_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update OAuth settings
    pub async fn update_oauth_settings(
        &self,
        tenant_id: &str,
        settings: &OAuthSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let json = serde_json::to_value(settings)?;
        
        sqlx::query(
            r#"
            SELECT update_tenant_setting($1, 'oauth', $2, $3, $4)
            "#
        )
        .bind(tenant_id)
        .bind(json)
        .bind(changed_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update localization settings
    pub async fn update_localization_settings(
        &self,
        tenant_id: &str,
        settings: &LocalizationSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let json = serde_json::to_value(settings)?;
        
        sqlx::query(
            r#"
            SELECT update_tenant_setting($1, 'localization', $2, $3, $4)
            "#
        )
        .bind(tenant_id)
        .bind(json)
        .bind(changed_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update webhook settings
    pub async fn update_webhook_settings(
        &self,
        tenant_id: &str,
        settings: &WebhookSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let json = serde_json::to_value(settings)?;
        
        sqlx::query(
            r#"
            SELECT update_tenant_setting($1, 'webhook', $2, $3, $4)
            "#
        )
        .bind(tenant_id)
        .bind(json)
        .bind(changed_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update privacy settings
    pub async fn update_privacy_settings(
        &self,
        tenant_id: &str,
        settings: &PrivacySettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let json = serde_json::to_value(settings)?;
        
        sqlx::query(
            r#"
            SELECT update_tenant_setting($1, 'privacy', $2, $3, $4)
            "#
        )
        .bind(tenant_id)
        .bind(json)
        .bind(changed_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update advanced settings
    pub async fn update_advanced_settings(
        &self,
        tenant_id: &str,
        settings: &AdvancedSettings,
        changed_by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<()> {
        let json = serde_json::to_value(settings)?;
        
        sqlx::query(
            r#"
            SELECT update_tenant_setting($1, 'advanced', $2, $3, $4)
            "#
        )
        .bind(tenant_id)
        .bind(json)
        .bind(changed_by)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get settings change history
    pub async fn get_settings_history(
        &self,
        tenant_id: &str,
        category: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<SettingsHistoryRow>, i64)> {
        let mut query = String::from(
            r#"
            SELECT id, tenant_id, changed_by, change_type, 
                   previous_value, new_value, reason, created_at
            FROM tenant_settings_history
            WHERE tenant_id = $1
            "#
        );

        if category.is_some() {
            query.push_str(" AND change_type = $2");
        }

        query.push_str(" ORDER BY created_at DESC LIMIT $3 OFFSET $4");

        let rows = if let Some(cat) = category {
            sqlx::query_as::<_, SettingsHistoryRow>(&query)
                .bind(tenant_id)
                .bind(cat)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query_as::<_, SettingsHistoryRow>(&query)
                .bind(tenant_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
        };

        // Get total count
        let count_query = if category.is_some() {
            r#"
            SELECT COUNT(*) as count 
            FROM tenant_settings_history 
            WHERE tenant_id = $1 AND change_type = $2
            "#
        } else {
            r#"
            SELECT COUNT(*) as count 
            FROM tenant_settings_history 
            WHERE tenant_id = $1
            "#
        };

        let total: i64 = if let Some(cat) = category {
            sqlx::query_scalar(count_query)
                .bind(tenant_id)
                .bind(cat)
                .fetch_one(&self.pool)
                .await?
        } else {
            sqlx::query_scalar(count_query)
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?
        };

        Ok((rows, total))
    }

    /// Check if settings exist for tenant
    pub async fn settings_exist(&self, tenant_id: &str) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM tenant_settings WHERE tenant_id = $1
            )
            "#
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    /// Delete all settings for a tenant (for cleanup)
    pub async fn delete_settings(&self, tenant_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM tenant_settings WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}
