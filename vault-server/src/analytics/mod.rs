//! Advanced Analytics Module for Vault
//!
//! Provides comprehensive analytics tracking including:
//! - Login metrics (successful/failed attempts)
//! - User engagement (signups, active users, retention)
//! - MFA adoption rates
//! - Security events (breaches, lockouts)
//! - Device and geographic breakdowns

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn, instrument};
use uuid::Uuid;

// Sub-modules
pub mod metrics;
pub mod models;
pub mod repository;

// Re-export commonly used items
pub use metrics::*;
pub use models::*;
pub use repository::AnalyticsRepository;

/// Analytics service for tracking and querying metrics
#[derive(Clone)]
pub struct AnalyticsService {
    repository: AnalyticsRepository,
    /// In-memory buffer for high-frequency events before batch insert
    event_buffer: Arc<RwLock<Vec<AnalyticsEvent>>>,
    /// Buffer flush threshold
    buffer_threshold: usize,
}

impl AnalyticsService {
    /// Create a new analytics service
    pub fn new(pool: PgPool) -> Self {
        Self {
            repository: AnalyticsRepository::new(pool),
            event_buffer: Arc::new(RwLock::new(Vec::with_capacity(1000))),
            buffer_threshold: 100,
        }
    }

    /// Create with custom buffer threshold
    pub fn with_buffer_threshold(pool: PgPool, threshold: usize) -> Self {
        Self {
            repository: AnalyticsRepository::new(pool),
            event_buffer: Arc::new(RwLock::new(Vec::with_capacity(threshold))),
            buffer_threshold: threshold,
        }
    }

    /// Get repository reference
    pub fn repository(&self) -> &AnalyticsRepository {
        &self.repository
    }

    /// Track a single analytics event
    #[instrument(skip(self, event))]
    pub async fn track_event(&self, event: AnalyticsEvent) -> anyhow::Result<()> {
        let mut buffer = self.event_buffer.write().await;
        buffer.push(event);

        // Flush if threshold reached
        if buffer.len() >= self.buffer_threshold {
            let events_to_flush: Vec<AnalyticsEvent> = buffer.drain(..).collect();
            drop(buffer); // Release lock before async operation
            self.flush_events(events_to_flush).await?;
        }

        Ok(())
    }

    /// Track multiple events at once
    #[instrument(skip(self, events))]
    pub async fn track_events(&self, events: Vec<AnalyticsEvent>) -> anyhow::Result<()> {
        let mut buffer = self.event_buffer.write().await;
        buffer.extend(events);

        // Flush if threshold reached
        if buffer.len() >= self.buffer_threshold {
            let events_to_flush: Vec<AnalyticsEvent> = buffer.drain(..).collect();
            drop(buffer);
            self.flush_events(events_to_flush).await?;
        }

        Ok(())
    }

    /// Force flush all buffered events
    #[instrument(skip(self))]
    pub async fn flush(&self) -> anyhow::Result<()> {
        let mut buffer = self.event_buffer.write().await;
        if !buffer.is_empty() {
            let events_to_flush: Vec<AnalyticsEvent> = buffer.drain(..).collect();
            drop(buffer);
            self.flush_events(events_to_flush).await?;
        }
        Ok(())
    }

    /// Flush events to database
    #[instrument(skip(self, events))]
    async fn flush_events(&self, events: Vec<AnalyticsEvent>) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        self.repository.store_events_batch(&events).await?;
        
        debug!(event_count = events.len(), "Flushed analytics events to database");

        Ok(())
    }

    // ============ Convenience Tracking Methods ============

    /// Track a login event
    #[instrument(skip(self, metadata))]
    pub async fn track_login(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        session_id: Option<Uuid>,
        success: bool,
        method: LoginMethod,
        metadata: LoginMetadata,
    ) -> anyhow::Result<()> {
        let event = AnalyticsEvent::with_session(
            tenant_id,
            "login",
            user_id,
            session_id,
            LoginEventData {
                success,
                method: format!("{:?}", method).to_lowercase(),
                ip_address: metadata.ip_address,
                user_agent: metadata.user_agent,
                browser: metadata.browser,
                os: metadata.os,
                device_type: metadata.device_type,
                country: metadata.country,
                city: metadata.city,
                error_code: metadata.error_code,
            },
        )?;
        self.track_event(event).await
    }

    /// Track a signup event
    #[instrument(skip(self, metadata))]
    pub async fn track_signup(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        method: SignupMethod,
        metadata: SignupMetadata,
    ) -> anyhow::Result<()> {
        let event = AnalyticsEvent::new(
            tenant_id,
            "signup",
            Some(user_id),
            SignupEventData {
                method: format!("{:?}", method).to_lowercase(),
                ip_address: metadata.ip_address,
                user_agent: metadata.user_agent,
                browser: metadata.browser,
                os: metadata.os,
                has_referral: metadata.has_referral,
                referral_source: metadata.referral_source,
            },
        )?;
        self.track_event(event).await
    }

    /// Track an MFA event
    #[instrument(skip(self, metadata))]
    pub async fn track_mfa(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        method: MfaMethod,
        success: bool,
        metadata: MfaMetadata,
    ) -> anyhow::Result<()> {
        let event = AnalyticsEvent::new(
            tenant_id,
            "mfa",
            Some(user_id),
            MfaEventData {
                method: format!("{:?}", method).to_lowercase(),
                success,
                ip_address: metadata.ip_address,
                error_code: metadata.error_code,
                attempt_number: metadata.attempt_number,
            },
        )?;
        self.track_event(event).await
    }

    /// Track a security event
    #[instrument(skip(self, metadata))]
    pub async fn track_security_event(
        &self,
        tenant_id: Uuid,
        user_id: Option<Uuid>,
        event_type: SecurityEventType,
        metadata: SecurityMetadata,
    ) -> anyhow::Result<()> {
        let event = AnalyticsEvent::new(
            tenant_id,
            "security",
            user_id,
            SecurityEventData {
                event_type: format!("{:?}", event_type).to_lowercase(),
                ip_address: metadata.ip_address,
                details: metadata.details,
            },
        )?;
        self.track_event(event).await
    }

    /// Track a session event
    #[instrument(skip(self))]
    pub async fn track_session(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        session_id: Uuid,
        event_type: SessionEventType,
        duration_seconds: Option<i64>,
    ) -> anyhow::Result<()> {
        let event = AnalyticsEvent::with_session(
            tenant_id,
            "session",
            Some(user_id),
            Some(session_id),
            SessionEventData {
                event_type: format!("{:?}", event_type).to_lowercase(),
                duration_seconds,
            },
        )?;
        self.track_event(event).await
    }

    // ============ Query Methods ============

    /// Get login metrics for a time period
    #[instrument(skip(self))]
    pub async fn get_login_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<LoginMetrics> {
        self.repository.get_login_metrics(tenant_id, start_date, end_date).await
    }

    /// Get user metrics for a time period
    #[instrument(skip(self))]
    pub async fn get_user_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<UserMetrics> {
        self.repository.get_user_metrics(tenant_id, start_date, end_date).await
    }

    /// Get MFA metrics for a time period
    #[instrument(skip(self))]
    pub async fn get_mfa_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<MfaMetrics> {
        self.repository.get_mfa_metrics(tenant_id, start_date, end_date).await
    }

    /// Get security metrics for a time period
    #[instrument(skip(self))]
    pub async fn get_security_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<SecurityMetrics> {
        self.repository.get_security_metrics(tenant_id, start_date, end_date).await
    }

    /// Get device metrics for a time period
    #[instrument(skip(self))]
    pub async fn get_device_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<DeviceMetrics> {
        self.repository.get_device_metrics(tenant_id, start_date, end_date).await
    }

    /// Get geographic metrics for a time period
    #[instrument(skip(self))]
    pub async fn get_geographic_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<GeoMetrics> {
        self.repository.get_geo_metrics(tenant_id, start_date, end_date).await
    }

    /// Get dashboard overview
    #[instrument(skip(self))]
    pub async fn get_dashboard_overview(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<DashboardOverview> {
        let login_metrics = self.get_login_metrics(tenant_id, start_date, end_date).await?;
        let user_metrics = self.get_user_metrics(tenant_id, start_date, end_date).await?;
        let mfa_metrics = self.get_mfa_metrics(tenant_id, start_date, end_date).await?;
        let security_metrics = self.get_security_metrics(tenant_id, start_date, end_date).await?;

        // Get current active sessions count
        use sqlx::query_scalar;
        let current_active_sessions: i64 = query_scalar(
            r#"SELECT COUNT(*) FROM sessions 
               WHERE tenant_id = $1 
                 AND status = 'active' 
                 AND expires_at > NOW()"#,
        )
        .bind(tenant_id)
        .fetch_one(self.repository.repository())
        .await?;

        let days = (end_date - start_date).num_days().max(1);

        Ok(DashboardOverview {
            period: Period { start: start_date, end: end_date },
            summary: SummaryMetrics {
                total_logins: login_metrics.total,
                total_users: user_metrics.total_users,
                new_users: user_metrics.new_signups,
                avg_daily_active_users: user_metrics.active_users / days,
                login_success_rate: login_metrics.success_rate() * 100.0,
            },
            logins: LoginOverview {
                total: login_metrics.total,
                successful: login_metrics.successful,
                failed: login_metrics.failed,
                success_rate: login_metrics.success_rate() * 100.0,
                trend: login_metrics.trend,
                by_method: login_metrics.by_method,
            },
            users: UserOverview {
                new: user_metrics.new_signups,
                active: user_metrics.active_users,
                retention_rate: user_metrics.retention_rate * 100.0,
                trend: user_metrics.trend,
            },
            mfa: MfaOverview {
                adoption_rate: mfa_metrics.adoption_rate * 100.0,
                enrolled_users: mfa_metrics.total_enrollments,
                by_method: mfa_metrics.by_method,
            },
            security: SecurityOverview {
                failed_logins: security_metrics.failed_logins,
                account_lockouts: security_metrics.account_lockouts,
                suspicious_activities: security_metrics.suspicious_activities,
                risk_score: security_metrics.risk_score,
                risk_level: security_metrics.risk_level.to_string(),
            },
            current_active_sessions,
        })
    }
}

// ============ Event Data Structures ============

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoginEventData {
    success: bool,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    browser: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignupEventData {
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    browser: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    has_referral: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    referral_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MfaEventData {
    method: String,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt_number: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityEventData {
    event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionEventData {
    event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_seconds: Option<i64>,
}

// ============ Metadata Helpers ============

/// Login metadata helper
#[derive(Debug, Clone, Default)]
pub struct LoginMetadata {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub browser: Option<String>,
    pub os: Option<String>,
    pub device_type: Option<String>,
    pub country: Option<String>,
    pub city: Option<String>,
    pub error_code: Option<String>,
}

/// Signup metadata helper
#[derive(Debug, Clone, Default)]
pub struct SignupMetadata {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub browser: Option<String>,
    pub os: Option<String>,
    pub has_referral: Option<bool>,
    pub referral_source: Option<String>,
}

/// MFA metadata helper
#[derive(Debug, Clone, Default)]
pub struct MfaMetadata {
    pub ip_address: Option<String>,
    pub error_code: Option<String>,
    pub attempt_number: Option<i32>,
}

/// Security metadata helper
#[derive(Debug, Clone, Default)]
pub struct SecurityMetadata {
    pub ip_address: Option<String>,
    pub details: Option<serde_json::Value>,
}

// ============ Legacy Types (for backwards compatibility) ============

/// Login method
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginMethod {
    Password,
    OAuth { provider: String },
    Saml { provider: String },
    Webauthn,
    MagicLink,
    AppPassword,
}

/// Signup method
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignupMethod {
    Email,
    OAuth { provider: String },
    Saml { provider: String },
    Invitation,
    Scim,
}

/// MFA method
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfaMethod {
    Totp,
    Webauthn,
    Sms,
    Email,
    RecoveryCode,
}

/// Security event type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    SuspiciousActivity,
    BruteForceAttempt,
    AccountLockout,
    PasswordBreach,
    SessionHijackingAttempt,
    ImpossibleTravel,
}

/// Session event type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEventType {
    Created,
    Refreshed,
    Revoked,
    Expired,
}

/// Time interval for aggregation
pub type TimeInterval = models::TimeInterval;
