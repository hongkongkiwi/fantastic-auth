//! User Notification Preferences Module
//!
//! Provides user-configurable notification settings including:
//! - Email type preferences (security, marketing, updates)
//! - Channel preferences (email, SMS, push)
//! - Frequency preferences (immediate, digest, none)
//!
//! # GDPR Compliance
//!
//! This module supports GDPR Article 21 (Right to Object) by allowing users
//! to opt out of non-essential communications.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

pub mod repository;
pub mod routes;
pub mod service;

pub use repository::NotificationPreferencesRepository;
pub use routes::notification_routes;
pub use service::NotificationPreferencesService;

/// User notification preferences
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct NotificationPreferences {
    /// User ID
    pub user_id: String,
    
    // Security notifications
    /// New device/login alerts
    pub security_alerts: bool,
    /// Suspicious activity warnings
    pub suspicious_activity: bool,
    /// Password change confirmations
    pub password_changes: bool,
    /// MFA enrollment/changes
    pub mfa_changes: bool,
    
    // Account notifications
    /// Email verification reminders
    pub email_verification: bool,
    /// Account deletion confirmations
    pub account_deletion: bool,
    /// Data export ready notifications
    pub data_export: bool,
    
    // Marketing communications
    /// Product updates and newsletters
    pub product_updates: bool,
    /// Feature announcements
    pub feature_announcements: bool,
    /// Tips and tutorials
    pub tips_tutorials: bool,
    /// Promotional offers
    pub promotional_offers: bool,
    
    // Channel preferences
    /// Primary notification channel
    pub primary_channel: NotificationChannel,
    /// Secondary channel for critical alerts
    pub secondary_channel: NotificationChannel,
    
    // Frequency preferences
    /// Non-critical notification frequency
    pub email_frequency: NotificationFrequency,
    
    // Metadata
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            user_id: String::new(),
            // Security defaults to ON (cannot be disabled for compliance)
            security_alerts: true,
            suspicious_activity: true,
            password_changes: true,
            mfa_changes: true,
            // Account defaults to ON
            email_verification: true,
            account_deletion: true,
            data_export: true,
            // Marketing defaults to OFF (GDPR compliance)
            product_updates: false,
            feature_announcements: false,
            tips_tutorials: false,
            promotional_offers: false,
            // Channels
            primary_channel: NotificationChannel::Email,
            secondary_channel: NotificationChannel::Email,
            // Frequency
            email_frequency: NotificationFrequency::Immediate,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl NotificationPreferences {
    /// Create default preferences for a new user
    pub fn for_user(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            ..Default::default()
        }
    }
    
    /// Check if a specific notification type is enabled
    pub fn is_enabled(&self, notification_type: NotificationType) -> bool {
        match notification_type {
            // Security - always enabled (required for security)
            NotificationType::SecurityAlert => self.security_alerts,
            NotificationType::SuspiciousActivity => self.suspicious_activity,
            NotificationType::PasswordChange => self.password_changes,
            NotificationType::MfaChange => self.mfa_changes,
            
            // Account - user configurable
            NotificationType::EmailVerification => self.email_verification,
            NotificationType::AccountDeletion => self.account_deletion,
            NotificationType::DataExport => self.data_export,
            
            // Marketing - user configurable
            NotificationType::ProductUpdate => self.product_updates,
            NotificationType::FeatureAnnouncement => self.feature_announcements,
            NotificationType::TipsTutorial => self.tips_tutorials,
            NotificationType::PromotionalOffer => self.promotional_offers,
        }
    }
    
    /// Check if user has any marketing consents
    pub fn has_marketing_consent(&self) -> bool {
        self.product_updates
            || self.feature_announcements
            || self.tips_tutorials
            || self.promotional_offers
    }
}

/// Notification type categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    // Security notifications (critical)
    SecurityAlert,
    SuspiciousActivity,
    PasswordChange,
    MfaChange,
    
    // Account notifications (important)
    EmailVerification,
    AccountDeletion,
    DataExport,
    
    // Marketing notifications (optional)
    ProductUpdate,
    FeatureAnnouncement,
    TipsTutorial,
    PromotionalOffer,
}

impl NotificationType {
    /// Get the category of this notification
    pub fn category(&self) -> NotificationCategory {
        match self {
            NotificationType::SecurityAlert
            | NotificationType::SuspiciousActivity
            | NotificationType::PasswordChange
            | NotificationType::MfaChange => NotificationCategory::Security,
            
            NotificationType::EmailVerification
            | NotificationType::AccountDeletion
            | NotificationType::DataExport => NotificationCategory::Account,
            
            NotificationType::ProductUpdate
            | NotificationType::FeatureAnnouncement
            | NotificationType::TipsTutorial
            | NotificationType::PromotionalOffer => NotificationCategory::Marketing,
        }
    }
    
    /// Check if this notification is required (cannot be disabled)
    pub fn is_required(&self) -> bool {
        matches!(self.category(), NotificationCategory::Security)
    }
    
    /// Get default enabled state
    pub fn default_enabled(&self) -> bool {
        match self.category() {
            NotificationCategory::Security => true,
            NotificationCategory::Account => true,
            NotificationCategory::Marketing => false,
        }
    }
}

/// Notification category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationCategory {
    Security,
    Account,
    Marketing,
}

/// Notification channel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NotificationChannel {
    #[default]
    Email,
    Sms,
    Push,
    InApp,
}

impl NotificationChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotificationChannel::Email => "email",
            NotificationChannel::Sms => "sms",
            NotificationChannel::Push => "push",
            NotificationChannel::InApp => "in_app",
        }
    }
}

impl std::str::FromStr for NotificationChannel {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "email" => Ok(NotificationChannel::Email),
            "sms" => Ok(NotificationChannel::Sms),
            "push" => Ok(NotificationChannel::Push),
            "in_app" => Ok(NotificationChannel::InApp),
            _ => Err(format!("Unknown notification channel: {}", s)),
        }
    }
}

/// Notification frequency
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NotificationFrequency {
    #[default]
    Immediate,
    DailyDigest,
    WeeklyDigest,
    Never,
}

impl NotificationFrequency {
    pub fn as_str(&self) -> &'static str {
        match self {
            NotificationFrequency::Immediate => "immediate",
            NotificationFrequency::DailyDigest => "daily_digest",
            NotificationFrequency::WeeklyDigest => "weekly_digest",
            NotificationFrequency::Never => "never",
        }
    }
}

impl std::str::FromStr for NotificationFrequency {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "immediate" => Ok(NotificationFrequency::Immediate),
            "daily" | "daily_digest" => Ok(NotificationFrequency::DailyDigest),
            "weekly" | "weekly_digest" => Ok(NotificationFrequency::WeeklyDigest),
            "never" | "none" => Ok(NotificationFrequency::Never),
            _ => Err(format!("Unknown notification frequency: {}", s)),
        }
    }
}

/// Update preferences request
#[derive(Debug, Clone, Deserialize)]
pub struct UpdatePreferencesRequest {
    pub security_alerts: Option<bool>,
    pub suspicious_activity: Option<bool>,
    pub password_changes: Option<bool>,
    pub mfa_changes: Option<bool>,
    pub email_verification: Option<bool>,
    pub account_deletion: Option<bool>,
    pub data_export: Option<bool>,
    pub product_updates: Option<bool>,
    pub feature_announcements: Option<bool>,
    pub tips_tutorials: Option<bool>,
    pub promotional_offers: Option<bool>,
    pub primary_channel: Option<NotificationChannel>,
    pub secondary_channel: Option<NotificationChannel>,
    pub email_frequency: Option<NotificationFrequency>,
}

impl UpdatePreferencesRequest {
    /// Apply updates to preferences, respecting immutability of required fields
    pub fn apply_to(self, prefs: &mut NotificationPreferences) {
        // Security fields can only be toggled if not required
        // (they're required, so we don't allow disabling them)
        if let Some(v) = self.suspicious_activity { prefs.suspicious_activity = v; }
        if let Some(v) = self.password_changes { prefs.password_changes = v; }
        if let Some(v) = self.mfa_changes { prefs.mfa_changes = v; }
        
        // Account fields
        if let Some(v) = self.email_verification { prefs.email_verification = v; }
        if let Some(v) = self.account_deletion { prefs.account_deletion = v; }
        if let Some(v) = self.data_export { prefs.data_export = v; }
        
        // Marketing fields
        if let Some(v) = self.product_updates { prefs.product_updates = v; }
        if let Some(v) = self.feature_announcements { prefs.feature_announcements = v; }
        if let Some(v) = self.tips_tutorials { prefs.tips_tutorials = v; }
        if let Some(v) = self.promotional_offers { prefs.promotional_offers = v; }
        
        // Channel preferences
        if let Some(v) = self.primary_channel { prefs.primary_channel = v; }
        if let Some(v) = self.secondary_channel { prefs.secondary_channel = v; }
        
        // Frequency
        if let Some(v) = self.email_frequency { prefs.email_frequency = v; }
        
        prefs.updated_at = Utc::now();
    }
}

/// Preferences response for API
#[derive(Debug, Clone, Serialize)]
pub struct PreferencesResponse {
    pub user_id: String,
    pub security: SecurityPreferences,
    pub account: AccountPreferences,
    pub marketing: MarketingPreferences,
    pub channels: ChannelPreferences,
    pub frequency: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityPreferences {
    pub security_alerts: bool,
    pub suspicious_activity: bool,
    pub password_changes: bool,
    pub mfa_changes: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountPreferences {
    pub email_verification: bool,
    pub account_deletion: bool,
    pub data_export: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MarketingPreferences {
    pub product_updates: bool,
    pub feature_announcements: bool,
    pub tips_tutorials: bool,
    pub promotional_offers: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChannelPreferences {
    pub primary: String,
    pub secondary: String,
}

impl From<NotificationPreferences> for PreferencesResponse {
    fn from(p: NotificationPreferences) -> Self {
        Self {
            user_id: p.user_id.clone(),
            security: SecurityPreferences {
                security_alerts: p.security_alerts,
                suspicious_activity: p.suspicious_activity,
                password_changes: p.password_changes,
                mfa_changes: p.mfa_changes,
            },
            account: AccountPreferences {
                email_verification: p.email_verification,
                account_deletion: p.account_deletion,
                data_export: p.data_export,
            },
            marketing: MarketingPreferences {
                product_updates: p.product_updates,
                feature_announcements: p.feature_announcements,
                tips_tutorials: p.tips_tutorials,
                promotional_offers: p.promotional_offers,
            },
            channels: ChannelPreferences {
                primary: p.primary_channel.as_str().to_string(),
                secondary: p.secondary_channel.as_str().to_string(),
            },
            frequency: p.email_frequency.as_str().to_string(),
            updated_at: p.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    
    #[test]
    fn test_default_preferences() {
        let prefs = NotificationPreferences::default();
        
        // Security should be ON
        assert!(prefs.security_alerts);
        assert!(prefs.suspicious_activity);
        assert!(prefs.password_changes);
        assert!(prefs.mfa_changes);
        
        // Account should be ON
        assert!(prefs.email_verification);
        assert!(prefs.account_deletion);
        assert!(prefs.data_export);
        
        // Marketing should be OFF
        assert!(!prefs.product_updates);
        assert!(!prefs.feature_announcements);
        assert!(!prefs.tips_tutorials);
        assert!(!prefs.promotional_offers);
    }
    
    #[test]
    fn test_notification_type_category() {
        assert_eq!(
            NotificationType::SecurityAlert.category(),
            NotificationCategory::Security
        );
        assert_eq!(
            NotificationType::DataExport.category(),
            NotificationCategory::Account
        );
        assert_eq!(
            NotificationType::ProductUpdate.category(),
            NotificationCategory::Marketing
        );
    }
    
    #[test]
    fn test_notification_type_is_required() {
        assert!(NotificationType::SecurityAlert.is_required());
        assert!(NotificationType::PasswordChange.is_required());
        assert!(!NotificationType::ProductUpdate.is_required());
        assert!(!NotificationType::PromotionalOffer.is_required());
    }
    
    #[test]
    fn test_notification_channel_from_str() {
        assert_eq!(
            NotificationChannel::from_str("email").unwrap(),
            NotificationChannel::Email
        );
        assert_eq!(
            NotificationChannel::from_str("SMS").unwrap(),
            NotificationChannel::Sms
        );
        assert!(NotificationChannel::from_str("invalid").is_err());
    }
}
