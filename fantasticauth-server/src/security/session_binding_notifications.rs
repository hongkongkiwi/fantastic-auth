//! Session binding notification service
//!
//! Handles sending notifications when new devices/locations are detected,
//! including security alerts and verification emails.

use crate::db::Database;
use chrono::Utc;
use std::sync::Arc;
use vault_core::email::templates::{NewDeviceEmail, SecurityAlertEmail, SecurityAlertType};
use vault_core::email::{EmailRequest, EmailService, EmailTemplate, TemplateEngine};

use super::session_binding::{ViolationDetails, ViolationType};

/// Notification service for session binding events
#[derive(Clone)]
pub struct SessionBindingNotificationService {
    db: Database,
    email_service: Option<Arc<dyn EmailService>>,
    base_url: String,
    from_address: String,
    from_name: String,
}

impl SessionBindingNotificationService {
    /// Create a new notification service
    pub fn new(db: Database, base_url: String) -> Self {
        Self {
            db,
            email_service: None,
            base_url,
            from_address: "no-reply@vault.local".to_string(),
            from_name: "Vault".to_string(),
        }
    }

    /// With email service configured
    pub fn with_email_service(mut self, service: Arc<dyn EmailService>) -> Self {
        self.email_service = Some(service);
        self
    }

    /// Optionally override the "from" address used for notifications
    pub fn with_from_address(mut self, from_address: String, from_name: String) -> Self {
        self.from_address = from_address;
        self.from_name = from_name;
        self
    }

    async fn send_templated_email<T: EmailTemplate + serde::Serialize + Send>(
        &self,
        to: &str,
        template: &T,
    ) -> anyhow::Result<()> {
        let Some(ref email_service) = self.email_service else {
            return Ok(());
        };

        let engine = TemplateEngine::new(self.base_url.clone(), self.from_name.clone(), None);
        let rendered = engine.render(template)?;

        email_service
            .send_email(EmailRequest {
                to: to.to_string(),
                to_name: None,
                subject: rendered.subject,
                html_body: rendered.html_body,
                text_body: rendered.text_body,
                from: self.from_address.clone(),
                from_name: self.from_name.clone(),
                reply_to: None,
                headers: std::collections::HashMap::new(),
            })
            .await?;

        Ok(())
    }

    /// Notify user of a new device/login
    pub async fn notify_new_device(
        &self,
        user_id: &str,
        email: &str,
        device: &str,
        location: Option<String>,
        ip_address: &str,
        trust_url: &str,
        revoke_url: &str,
    ) -> anyhow::Result<()> {
        // Send security alert email
        let alert = SecurityAlertEmail {
            name: email.to_string(),
            alert_type: SecurityAlertType::NewDevice,
            timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            ip_address: ip_address.to_string(),
            location: location.clone(),
            device: device.to_string(),
        };

        if let Err(e) = self.send_templated_email(email, &alert).await {
            tracing::warn!("Failed to send new device alert: {}", e);
        }

        // Also send "Was this you?" email with verification link
        let new_device_email = NewDeviceEmail {
            name: email.to_string(),
            device: device.to_string(),
            location,
            ip_address: ip_address.to_string(),
            timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            trust_url: trust_url.to_string(),
            revoke_url: revoke_url.to_string(),
        };

        if let Err(e) = self.send_templated_email(email, &new_device_email).await {
            tracing::warn!("Failed to send 'was this you' email: {}", e);
        }

        // Create security alert in database (for dashboard)
        tracing::info!(
            "Security alert: New device detected for user {} from {}",
            user_id,
            ip_address
        );

        Ok(())
    }

    /// Notify user of a binding violation
    pub async fn notify_violation(
        &self,
        user_id: &str,
        email: &str,
        violation_type: ViolationType,
        details: &ViolationDetails,
        action_taken: &str,
    ) -> anyhow::Result<()> {
        // Record the violation
        self.record_violation(user_id, violation_type, details, action_taken)
            .await?;

        // Send security alert for suspicious activity
        if details.is_suspicious || details.risk_score > 50 {
            let alert = SecurityAlertEmail {
                name: email.to_string(),
                alert_type: SecurityAlertType::SuspiciousLogin,
                timestamp: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                ip_address: details.actual_ip.clone().unwrap_or_default(),
                location: None, // Could add geolocation
                device: "Unknown".to_string(),
            };

            if let Err(e) = self.send_templated_email(email, &alert).await {
                tracing::warn!("Failed to send suspicious login alert: {}", e);
            }
        }

        Ok(())
    }

    /// Record a device access for the user
    pub async fn record_device_access(
        &self,
        user_id: &str,
        tenant_id: &str,
        device_hash: &str,
        device_name: &str,
        device_type: &str,
        browser: &str,
        os: &str,
        ip_address: &str,
    ) -> anyhow::Result<()> {
        let pool = self.db.pool();

        sqlx::query(
            r#"
            INSERT INTO user_known_devices (
                tenant_id, user_id, device_fingerprint, device_name,
                device_type, browser, os, ip_address, last_seen_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::inet, NOW())
            ON CONFLICT (tenant_id, user_id, device_fingerprint) 
            DO UPDATE SET 
                last_seen_at = NOW(),
                ip_address = EXCLUDED.ip_address
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_hash)
        .bind(device_name)
        .bind(device_type)
        .bind(browser)
        .bind(os)
        .bind(ip_address)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Check if a device is already trusted by the user
    pub async fn is_device_trusted(
        &self,
        user_id: &str,
        device_hash: &str,
    ) -> anyhow::Result<bool> {
        let pool = self.db.pool();

        let is_trusted: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM user_known_devices 
                WHERE user_id = $1 
                AND device_fingerprint = $2
                AND (is_trusted = true OR is_blocked = false)
            )
            "#,
        )
        .bind(user_id)
        .bind(device_hash)
        .fetch_one(pool)
        .await?;

        Ok(is_trusted)
    }

    /// Record a binding violation
    async fn record_violation(
        &self,
        user_id: &str,
        violation_type: ViolationType,
        details: &ViolationDetails,
        action_taken: &str,
    ) -> anyhow::Result<()> {
        let pool = self.db.pool();

        sqlx::query(
            r#"
            INSERT INTO session_binding_violations (
                tenant_id, session_id, user_id, violation_type,
                expected_ip, actual_ip, expected_device_hash, actual_device_hash,
                action_taken, created_at
            ) VALUES (
                (SELECT tenant_id FROM users WHERE id = $1),
                $2, $1, $3, $4::inet, $5::inet, $6, $7, $8, NOW()
            )
            "#,
        )
        .bind(user_id)
        .bind("unknown") // Session ID should be passed in
        .bind(violation_type.as_str())
        .bind(&details.expected_ip)
        .bind(&details.actual_ip)
        .bind(&details.expected_device)
        .bind(&details.actual_device)
        .bind(action_taken)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Get recent violations for a user
    pub async fn get_recent_violations(
        &self,
        user_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<ViolationRecord>> {
        let pool = self.db.pool();

        let violations = sqlx::query_as::<_, ViolationRecord>(
            r#"
            SELECT 
                id::text as id,
                violation_type,
                expected_ip,
                actual_ip,
                action_taken,
                created_at
            FROM session_binding_violations
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(pool)
        .await?;

        Ok(violations)
    }
}

/// Violation record from database
#[derive(sqlx::FromRow)]
pub struct ViolationRecord {
    pub id: String,
    pub violation_type: String,
    pub expected_ip: Option<String>,
    pub actual_ip: Option<String>,
    pub action_taken: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
