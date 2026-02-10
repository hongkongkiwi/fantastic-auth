//! Notification Preferences Service
//!
//! Business logic for managing user notification preferences.

use std::sync::Arc;

use crate::notifications::{
    NotificationPreferences, NotificationPreferencesRepository,
    NotificationType, PreferencesResponse, UpdatePreferencesRequest,
};

/// Service for notification preferences
pub struct NotificationPreferencesService {
    repo: NotificationPreferencesRepository,
}

impl NotificationPreferencesService {
    /// Create a new service
    pub fn new(repo: NotificationPreferencesRepository) -> Self {
        Self { repo }
    }
    
    /// Get or create preferences for a user
    pub async fn get_preferences(
        &self,
        user_id: &str,
    ) -> anyhow::Result<NotificationPreferences> {
        match self.repo.get_preferences(user_id).await? {
            Some(prefs) => Ok(prefs),
            None => {
                // Create default preferences
                self.repo.create_default(user_id).await
            }
        }
    }
    
    /// Get preferences response for API
    pub async fn get_preferences_response(
        &self,
        user_id: &str,
    ) -> anyhow::Result<PreferencesResponse> {
        let prefs = self.get_preferences(user_id).await?;
        Ok(prefs.into())
    }
    
    /// Update preferences
    pub async fn update_preferences(
        &self,
        user_id: &str,
        request: UpdatePreferencesRequest,
    ) -> anyhow::Result<PreferencesResponse> {
        // Get current preferences
        let mut prefs = self.get_preferences(user_id).await?;
        
        // Apply updates
        request.apply_to(&mut prefs);
        
        // Save
        self.repo.update_preferences(&prefs).await?;
        
        Ok(prefs.into())
    }
    
    /// Check if user should receive a specific notification
    pub async fn should_notify(
        &self,
        user_id: &str,
        notification_type: NotificationType,
    ) -> anyhow::Result<bool> {
        // Get preferences (will create default if not exists)
        let prefs = self.get_preferences(user_id).await?;
        
        // Check if enabled
        let enabled = prefs.is_enabled(notification_type);
        
        // Security notifications are always required
        if notification_type.is_required() && !enabled {
            // Log warning - this shouldn't happen
            tracing::warn!(
                user_id = %user_id,
                notification_type = ?notification_type,
                "Required security notification is disabled"
            );
            return Ok(true); // Always send required notifications
        }
        
        Ok(enabled)
    }
    
    /// Check if user has marketing consent
    pub async fn has_marketing_consent(&self, user_id: &str) -> anyhow::Result<bool> {
        let prefs = self.get_preferences(user_id).await?;
        Ok(prefs.has_marketing_consent())
    }
    
    /// Subscribe to marketing emails
    pub async fn subscribe_marketing(
        &self,
        user_id: &str,
        categories: Vec<String>,
    ) -> anyhow::Result<PreferencesResponse> {
        let mut prefs = self.get_preferences(user_id).await?;
        
        for category in categories {
            match category.as_str() {
                "product_updates" => prefs.product_updates = true,
                "feature_announcements" => prefs.feature_announcements = true,
                "tips_tutorials" => prefs.tips_tutorials = true,
                "promotional_offers" => prefs.promotional_offers = true,
                "all" => {
                    prefs.product_updates = true;
                    prefs.feature_announcements = true;
                    prefs.tips_tutorials = true;
                    prefs.promotional_offers = true;
                }
                _ => {}
            }
        }
        
        prefs.updated_at = chrono::Utc::now();
        self.repo.update_preferences(&prefs).await?;
        
        Ok(prefs.into())
    }
    
    /// Unsubscribe from marketing emails
    pub async fn unsubscribe_marketing(
        &self,
        user_id: &str,
        categories: Option<Vec<String>>,
    ) -> anyhow::Result<PreferencesResponse> {
        let mut prefs = self.get_preferences(user_id).await?;
        
        match categories {
            Some(cats) => {
                // Unsubscribe from specific categories
                for category in cats {
                    match category.as_str() {
                        "product_updates" => prefs.product_updates = false,
                        "feature_announcements" => prefs.feature_announcements = false,
                        "tips_tutorials" => prefs.tips_tutorials = false,
                        "promotional_offers" => prefs.promotional_offers = false,
                        "all" => {
                            prefs.product_updates = false;
                            prefs.feature_announcements = false;
                            prefs.tips_tutorials = false;
                            prefs.promotional_offers = false;
                        }
                        _ => {}
                    }
                }
            }
            None => {
                // Unsubscribe from all marketing
                prefs.product_updates = false;
                prefs.feature_announcements = false;
                prefs.tips_tutorials = false;
                prefs.promotional_offers = false;
            }
        }
        
        prefs.updated_at = chrono::Utc::now();
        self.repo.update_preferences(&prefs).await?;
        
        Ok(prefs.into())
    }
    
    /// Get users who should receive a specific notification type
    pub async fn get_notification_recipients(
        &self,
        notification_type: NotificationType,
        limit: i64,
    ) -> anyhow::Result<Vec<String>> {
        let type_str = match notification_type {
            NotificationType::SecurityAlert => "security_alerts",
            NotificationType::SuspiciousActivity => "suspicious_activity",
            NotificationType::PasswordChange => "password_changes",
            NotificationType::MfaChange => "mfa_changes",
            NotificationType::EmailVerification => "email_verification",
            NotificationType::AccountDeletion => "account_deletion",
            NotificationType::DataExport => "data_export",
            NotificationType::ProductUpdate => "product_updates",
            NotificationType::FeatureAnnouncement => "feature_announcements",
            NotificationType::TipsTutorial => "tips_tutorials",
            NotificationType::PromotionalOffer => "promotional_offers",
        };
        
        self.repo.get_users_for_notification(type_str, limit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_notification_type_mapping() {
        assert_eq!(
            match_notification_type(NotificationType::SecurityAlert),
            "security_alerts"
        );
        assert_eq!(
            match_notification_type(NotificationType::ProductUpdate),
            "product_updates"
        );
    }
    
    fn match_notification_type(nt: NotificationType) -> &'static str {
        match nt {
            NotificationType::SecurityAlert => "security_alerts",
            NotificationType::SuspiciousActivity => "suspicious_activity",
            NotificationType::PasswordChange => "password_changes",
            NotificationType::MfaChange => "mfa_changes",
            NotificationType::EmailVerification => "email_verification",
            NotificationType::AccountDeletion => "account_deletion",
            NotificationType::DataExport => "data_export",
            NotificationType::ProductUpdate => "product_updates",
            NotificationType::FeatureAnnouncement => "feature_announcements",
            NotificationType::TipsTutorial => "tips_tutorials",
            NotificationType::PromotionalOffer => "promotional_offers",
        }
    }
}
