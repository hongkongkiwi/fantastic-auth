//! Notification Preferences Repository
//!
//! Database operations for user notification preferences.

use sqlx::PgPool;
use std::sync::Arc;

use crate::notifications::{
    NotificationChannel, NotificationFrequency, NotificationPreferences,
};

/// Repository for notification preferences
#[derive(Clone)]
pub struct NotificationPreferencesRepository {
    pool: Arc<PgPool>,
}

impl NotificationPreferencesRepository {
    /// Create a new repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
    
    /// Create a new repository from a pool reference
    pub fn from_pool(pool: &PgPool) -> Self {
        Self { pool: Arc::new(pool.clone()) }
    }
    
    /// Get the database pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
    
    /// Get preferences for a user
    pub async fn get_preferences(
        &self,
        user_id: &str,
    ) -> anyhow::Result<Option<NotificationPreferences>> {
        let row = sqlx::query!(
            r#"
            SELECT 
                user_id::text as user_id,
                security_alerts,
                suspicious_activity,
                password_changes,
                mfa_changes,
                email_verification,
                account_deletion,
                data_export,
                product_updates,
                feature_announcements,
                tips_tutorials,
                promotional_offers,
                primary_channel,
                secondary_channel,
                email_frequency,
                created_at,
                updated_at
            FROM user_notification_preferences
            WHERE user_id = $1::uuid
            "#,
            user_id
        )
        .fetch_optional(&*self.pool)
        .await?;
        
        match row {
            Some(row) => {
                let prefs = NotificationPreferences {
                    user_id: row.user_id.unwrap_or_default(),
                    security_alerts: row.security_alerts.unwrap_or(true),
                    suspicious_activity: row.suspicious_activity.unwrap_or(true),
                    password_changes: row.password_changes.unwrap_or(true),
                    mfa_changes: row.mfa_changes.unwrap_or(true),
                    email_verification: row.email_verification.unwrap_or(true),
                    account_deletion: row.account_deletion.unwrap_or(true),
                    data_export: row.data_export.unwrap_or(true),
                    product_updates: row.product_updates.unwrap_or(false),
                    feature_announcements: row.feature_announcements.unwrap_or(false),
                    tips_tutorials: row.tips_tutorials.unwrap_or(false),
                    promotional_offers: row.promotional_offers.unwrap_or(false),
                    primary_channel: parse_channel(&row.primary_channel),
                    secondary_channel: parse_channel(&row.secondary_channel),
                    email_frequency: parse_frequency(&row.email_frequency),
                    created_at: row.created_at.unwrap_or_else(chrono::Utc::now),
                    updated_at: row.updated_at.unwrap_or_else(chrono::Utc::now),
                };
                Ok(Some(prefs))
            }
            None => Ok(None),
        }
    }
    
    /// Create default preferences for a new user
    pub async fn create_default(&self, user_id: &str) -> anyhow::Result<NotificationPreferences> {
        let prefs = NotificationPreferences::for_user(user_id);
        
        sqlx::query!(
            r#"
            INSERT INTO user_notification_preferences (
                user_id, security_alerts, suspicious_activity, password_changes, mfa_changes,
                email_verification, account_deletion, data_export,
                product_updates, feature_announcements, tips_tutorials, promotional_offers,
                primary_channel, secondary_channel, email_frequency, created_at, updated_at
            ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW(), NOW())
            ON CONFLICT (user_id) DO NOTHING
            "#,
            user_id,
            prefs.security_alerts,
            prefs.suspicious_activity,
            prefs.password_changes,
            prefs.mfa_changes,
            prefs.email_verification,
            prefs.account_deletion,
            prefs.data_export,
            prefs.product_updates,
            prefs.feature_announcements,
            prefs.tips_tutorials,
            prefs.promotional_offers,
            prefs.primary_channel.as_str(),
            prefs.secondary_channel.as_str(),
            prefs.email_frequency.as_str(),
        )
        .execute(&*self.pool)
        .await?;
        
        Ok(prefs)
    }
    
    /// Update preferences
    pub async fn update_preferences(
        &self,
        prefs: &NotificationPreferences,
    ) -> anyhow::Result<()> {
        sqlx::query!(
            r#"
            INSERT INTO user_notification_preferences (
                user_id, security_alerts, suspicious_activity, password_changes, mfa_changes,
                email_verification, account_deletion, data_export,
                product_updates, feature_announcements, tips_tutorials, promotional_offers,
                primary_channel, secondary_channel, email_frequency, created_at, updated_at
            ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NOW(), NOW())
            ON CONFLICT (user_id) DO UPDATE SET
                security_alerts = EXCLUDED.security_alerts,
                suspicious_activity = EXCLUDED.suspicious_activity,
                password_changes = EXCLUDED.password_changes,
                mfa_changes = EXCLUDED.mfa_changes,
                email_verification = EXCLUDED.email_verification,
                account_deletion = EXCLUDED.account_deletion,
                data_export = EXCLUDED.data_export,
                product_updates = EXCLUDED.product_updates,
                feature_announcements = EXCLUDED.feature_announcements,
                tips_tutorials = EXCLUDED.tips_tutorials,
                promotional_offers = EXCLUDED.promotional_offers,
                primary_channel = EXCLUDED.primary_channel,
                secondary_channel = EXCLUDED.secondary_channel,
                email_frequency = EXCLUDED.email_frequency,
                updated_at = NOW()
            "#,
            prefs.user_id,
            prefs.security_alerts,
            prefs.suspicious_activity,
            prefs.password_changes,
            prefs.mfa_changes,
            prefs.email_verification,
            prefs.account_deletion,
            prefs.data_export,
            prefs.product_updates,
            prefs.feature_announcements,
            prefs.tips_tutorials,
            prefs.promotional_offers,
            prefs.primary_channel.as_str(),
            prefs.secondary_channel.as_str(),
            prefs.email_frequency.as_str(),
        )
        .execute(&*self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Delete preferences for a user (e.g., when user is deleted)
    pub async fn delete_preferences(&self, user_id: &str) -> anyhow::Result<()> {
        sqlx::query!(
            r#"DELETE FROM user_notification_preferences WHERE user_id = $1::uuid"#,
            user_id
        )
        .execute(&*self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Get users with marketing consent enabled
    pub async fn get_marketing_consent_users(
        &self,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<String>> {
        let rows: Vec<Option<String>> = sqlx::query_scalar!(
            r#"
            SELECT user_id::text
            FROM user_notification_preferences
            WHERE product_updates = true
               OR feature_announcements = true
               OR tips_tutorials = true
               OR promotional_offers = true
            ORDER BY user_id
            LIMIT $1 OFFSET $2
            "#,
            limit,
            offset
        )
        .fetch_all(&*self.pool)
        .await?;
        
        Ok(rows.into_iter().flatten().collect())
    }
    
    /// Get users who should receive a specific notification type
    pub async fn get_users_for_notification(
        &self,
        notification_type: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<String>> {
        // Map notification type to column
        let column = match notification_type {
            "security_alerts" => "security_alerts",
            "suspicious_activity" => "suspicious_activity",
            "password_changes" => "password_changes",
            "mfa_changes" => "mfa_changes",
            "email_verification" => "email_verification",
            "account_deletion" => "account_deletion",
            "data_export" => "data_export",
            "product_updates" => "product_updates",
            "feature_announcements" => "feature_announcements",
            "tips_tutorials" => "tips_tutorials",
            "promotional_offers" => "promotional_offers",
            _ => return Ok(vec![]),
        };
        
        // Build query dynamically
        let query = format!(
            r#"
            SELECT user_id::text
            FROM user_notification_preferences
            WHERE {} = true
            LIMIT $1
            "#,
            column
        );
        
        let rows: Vec<Option<String>> = sqlx::query_scalar(&query)
            .bind(limit)
            .fetch_all(&*self.pool)
            .await?;
        
        Ok(rows.into_iter().flatten().collect())
    }
}

/// Parse channel from string
fn parse_channel(s: &Option<String>) -> NotificationChannel {
    match s.as_deref() {
        Some("email") => NotificationChannel::Email,
        Some("sms") => NotificationChannel::Sms,
        Some("push") => NotificationChannel::Push,
        Some("in_app") => NotificationChannel::InApp,
        _ => NotificationChannel::Email,
    }
}

/// Parse frequency from string
fn parse_frequency(s: &Option<String>) -> NotificationFrequency {
    match s.as_deref() {
        Some("immediate") => NotificationFrequency::Immediate,
        Some("daily_digest") => NotificationFrequency::DailyDigest,
        Some("weekly_digest") => NotificationFrequency::WeeklyDigest,
        Some("never") => NotificationFrequency::Never,
        _ => NotificationFrequency::Immediate,
    }
}

/// SQL to create the notification preferences table
pub const CREATE_NOTIFICATION_PREFERENCES_TABLE_SQL: &str = r#"
-- User notification preferences table
CREATE TABLE IF NOT EXISTS user_notification_preferences (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    
    -- Security notifications (generally required)
    security_alerts BOOLEAN NOT NULL DEFAULT true,
    suspicious_activity BOOLEAN NOT NULL DEFAULT true,
    password_changes BOOLEAN NOT NULL DEFAULT true,
    mfa_changes BOOLEAN NOT NULL DEFAULT true,
    
    -- Account notifications
    email_verification BOOLEAN NOT NULL DEFAULT true,
    account_deletion BOOLEAN NOT NULL DEFAULT true,
    data_export BOOLEAN NOT NULL DEFAULT true,
    
    -- Marketing notifications (GDPR - explicit consent required)
    product_updates BOOLEAN NOT NULL DEFAULT false,
    feature_announcements BOOLEAN NOT NULL DEFAULT false,
    tips_tutorials BOOLEAN NOT NULL DEFAULT false,
    promotional_offers BOOLEAN NOT NULL DEFAULT false,
    
    -- Channel preferences
    primary_channel VARCHAR(20) NOT NULL DEFAULT 'email',
    secondary_channel VARCHAR(20) NOT NULL DEFAULT 'email',
    
    -- Frequency
    email_frequency VARCHAR(20) NOT NULL DEFAULT 'immediate',
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for marketing consent queries
CREATE INDEX IF NOT EXISTS idx_notification_prefs_marketing 
ON user_notification_preferences(product_updates, feature_announcements, tips_tutorials, promotional_offers);
"#;
