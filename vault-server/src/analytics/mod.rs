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
use sqlx::{postgres::PgPool, Row};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

pub mod metrics;

pub use metrics::*;

/// Analytics service for tracking and querying metrics
#[derive(Clone)]
pub struct AnalyticsService {
    pool: PgPool,
    /// In-memory buffer for high-frequency events before batch insert
    event_buffer: Arc<RwLock<Vec<AnalyticsEvent>>>,
    /// Buffer flush threshold
    buffer_threshold: usize,
}

impl AnalyticsService {
    /// Create a new analytics service
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            event_buffer: Arc::new(RwLock::new(Vec::with_capacity(1000))),
            buffer_threshold: 100,
        }
    }

    /// Create with custom buffer threshold
    pub fn with_buffer_threshold(pool: PgPool, threshold: usize) -> Self {
        Self {
            pool,
            event_buffer: Arc::new(RwLock::new(Vec::with_capacity(threshold))),
            buffer_threshold: threshold,
        }
    }

    /// Track a single analytics event
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
    async fn flush_events(&self, events: Vec<AnalyticsEvent>) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;

        for event in events {
            let metadata_json = serde_json::to_value(&event.metadata)?;

            sqlx::query(
                r#"INSERT INTO analytics_events 
                   (id, tenant_id, event_type, user_id, session_id, metadata, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            )
            .bind(&event.id)
            .bind(&event.tenant_id)
            .bind(&event.event_type)
            .bind(&event.user_id)
            .bind(&event.session_id)
            .bind(&metadata_json)
            .bind(&event.created_at)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        debug!(event_count = events.len(), "Flushed analytics events to database");

        Ok(())
    }

    // ============ Convenience Methods ============

    /// Track a login event
    pub async fn track_login(
        &self,
        tenant_id: &str,
        user_id: Option<&str>,
        session_id: Option<&str>,
        success: bool,
        method: LoginMethod,
        metadata: LoginMetadata,
    ) -> anyhow::Result<()> {
        let event = AnalyticsEvent::new_login(
            tenant_id,
            user_id,
            session_id,
            success,
            method,
            metadata,
        );
        self.track_event(event).await
    }

    /// Track a signup event
    pub async fn track_signup(
        &self,
        tenant_id: &str,
        user_id: &str,
        method: SignupMethod,
        metadata: SignupMetadata,
    ) -> anyhow::Result<()> {
        let event = AnalyticsEvent::new_signup(tenant_id, user_id, method, metadata);
        self.track_event(event).await
    }

    /// Track an MFA event
    pub async fn track_mfa(
        &self,
        tenant_id: &str,
        user_id: &str,
        method: MfaMethod,
        success: bool,
        metadata: MfaMetadata,
    ) -> anyhow::Result<()> {
        let event = AnalyticsEvent::new_mfa(tenant_id, user_id, method, success, metadata);
        self.track_event(event).await
    }

    /// Track a security event
    pub async fn track_security_event(
        &self,
        tenant_id: &str,
        user_id: Option<&str>,
        event_type: SecurityEventType,
        metadata: SecurityMetadata,
    ) -> anyhow::Result<()> {
        let event = AnalyticsEvent::new_security(tenant_id, user_id, event_type, metadata);
        self.track_event(event).await
    }

    /// Track a session event
    pub async fn track_session(
        &self,
        tenant_id: &str,
        user_id: &str,
        session_id: &str,
        event_type: SessionEventType,
        metadata: SessionMetadata,
    ) -> anyhow::Result<()> {
        let event = AnalyticsEvent::new_session(tenant_id, user_id, session_id, event_type, metadata);
        self.track_event(event).await
    }

    // ============ Query Methods ============

    /// Get login metrics for a time period
    pub async fn get_login_metrics(
        &self,
        tenant_id: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
        interval: TimeInterval,
    ) -> anyhow::Result<LoginMetrics> {
        let mut conn = self.pool.acquire().await?;

        // Get total counts from aggregated stats
        let stats = sqlx::query(
            r#"SELECT 
                metric_name,
                SUM(metric_value) as total
               FROM analytics_daily_stats
               WHERE tenant_id = $1 
                 AND date >= $2::date 
                 AND date <= $3::date
                 AND metric_name LIKE 'login_%'
               GROUP BY metric_name"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&mut *conn)
        .await?;

        let mut total_logins = 0i64;
        let mut successful_logins = 0i64;
        let mut failed_logins = 0i64;

        for row in stats {
            let name: String = row.try_get("metric_name")?;
            let value: i64 = row.try_get("total")?;

            match name.as_str() {
                "login_total" => total_logins = value,
                "login_success" => successful_logins = value,
                "login_failed" => failed_logins = value,
                _ => {}
            }
        }

        // Get trend data
        let trend = self.get_login_trend(tenant_id, start_date, end_date, interval).await?;

        // Get method breakdown
        let by_method = self.get_login_method_breakdown(tenant_id, start_date, end_date).await?;

        Ok(LoginMetrics {
            total: total_logins,
            successful: successful_logins,
            failed: failed_logins,
            trend,
            by_method,
        })
    }

    /// Get login trend data
    async fn get_login_trend(
        &self,
        tenant_id: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
        interval: TimeInterval,
    ) -> anyhow::Result<Vec<TrendDataPoint>> {
        let mut conn = self.pool.acquire().await?;

        let date_trunc = match interval {
            TimeInterval::Hour => "hour",
            TimeInterval::Day => "day",
            TimeInterval::Week => "week",
            TimeInterval::Month => "month",
        };

        let rows = sqlx::query(&format!(
            r#"SELECT 
                date_trunc('{}', date) as period,
                SUM(CASE WHEN metric_name = 'login_success' THEN metric_value ELSE 0 END) as successful,
                SUM(CASE WHEN metric_name = 'login_failed' THEN metric_value ELSE 0 END) as failed
               FROM analytics_daily_stats
               WHERE tenant_id = $1 
                 AND date >= $2::date 
                 AND date <= $3::date
                 AND metric_name LIKE 'login_%'
               GROUP BY date_trunc('{}', date)
               ORDER BY period"#,
            date_trunc, date_trunc
        ))
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&mut *conn)
        .await?;

        let mut trend = Vec::new();
        for row in rows {
            let period: DateTime<Utc> = row.try_get("period")?;
            let successful: i64 = row.try_get("successful")?;
            let failed: i64 = row.try_get("failed")?;

            trend.push(TrendDataPoint {
                timestamp: period,
                value: successful + failed,
                label: format!("{:?}", period),
                metadata: Some(serde_json::json!({
                    "successful": successful,
                    "failed": failed,
                })),
            });
        }

        Ok(trend)
    }

    /// Get login method breakdown
    async fn get_login_method_breakdown(
        &self,
        tenant_id: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<HashMap<String, i64>> {
        let mut conn = self.pool.acquire().await?;

        let rows = sqlx::query(
            r#"SELECT 
                metric_name,
                SUM(metric_value) as total
               FROM analytics_daily_stats
               WHERE tenant_id = $1 
                 AND date >= $2::date 
                 AND date <= $3::date
                 AND metric_name LIKE 'login_method_%'
               GROUP BY metric_name"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&mut *conn)
        .await?;

        let mut breakdown = HashMap::new();
        for row in rows {
            let name: String = row.try_get("metric_name")?;
            let value: i64 = row.try_get("total")?;

            // Extract method name from "login_method_password" -> "password"
            if let Some(method) = name.strip_prefix("login_method_") {
                breakdown.insert(method.to_string(), value);
            }
        }

        Ok(breakdown)
    }

    /// Get user metrics
    pub async fn get_user_metrics(
        &self,
        tenant_id: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<UserMetrics> {
        let mut conn = self.pool.acquire().await?;

        // Get new signups
        let new_signups: i64 = sqlx::query_scalar(
            r#"SELECT COALESCE(SUM(metric_value), 0)
               FROM analytics_daily_stats
               WHERE tenant_id = $1 
                 AND date >= $2::date 
                 AND date <= $3::date
                 AND metric_name = 'signup_total'"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_one(&mut *conn)
        .await?;

        // Get active users (distinct users who logged in)
        let active_users: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(DISTINCT user_id) 
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login'
                 AND created_at >= $2 
                 AND created_at <= $3"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_one(&mut *conn)
        .await?;

        // Calculate retention (users who logged in during period and also in previous period)
        let period_duration = end_date - start_date;
        let previous_start = start_date - period_duration;

        let retained_users: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(DISTINCT e1.user_id)
               FROM analytics_events e1
               INNER JOIN analytics_events e2 
                 ON e1.user_id = e2.user_id 
                 AND e1.tenant_id = e2.tenant_id
               WHERE e1.tenant_id = $1
                 AND e1.event_type = 'login'
                 AND e1.created_at >= $2 
                 AND e1.created_at <= $3
                 AND e2.event_type = 'login'
                 AND e2.created_at >= $4 
                 AND e2.created_at < $2"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .bind(&previous_start)
        .fetch_one(&mut *conn)
        .await?;

        let previous_active_users: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(DISTINCT user_id) 
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login'
                 AND created_at >= $2 
                 AND created_at < $3"#,
        )
        .bind(tenant_id)
        .bind(&previous_start)
        .bind(&start_date)
        .fetch_one(&mut *conn)
        .await?;

        let retention_rate = if previous_active_users > 0 {
            retained_users as f64 / previous_active_users as f64
        } else {
            0.0
        };

        // Get user trend
        let trend = self.get_user_trend(tenant_id, start_date, end_date).await?;

        Ok(UserMetrics {
            new_signups,
            active_users,
            retention_rate,
            trend,
        })
    }

    /// Get user trend data
    async fn get_user_trend(
        &self,
        tenant_id: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<Vec<TrendDataPoint>> {
        let mut conn = self.pool.acquire().await?;

        let rows = sqlx::query(
            r#"SELECT 
                date,
                SUM(CASE WHEN metric_name = 'signup_total' THEN metric_value ELSE 0 END) as signups,
                SUM(CASE WHEN metric_name = 'active_users' THEN metric_value ELSE 0 END) as active
               FROM analytics_daily_stats
               WHERE tenant_id = $1 
                 AND date >= $2::date 
                 AND date <= $3::date
                 AND (metric_name = 'signup_total' OR metric_name = 'active_users')
               GROUP BY date
               ORDER BY date"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&mut *conn)
        .await?;

        let mut trend = Vec::new();
        for row in rows {
            let date: chrono::NaiveDate = row.try_get("date")?;
            let signups: i64 = row.try_get("signups")?;
            let active: i64 = row.try_get("active")?;

            trend.push(TrendDataPoint {
                timestamp: date.and_hms_opt(0, 0, 0).unwrap().and_utc(),
                value: signups,
                label: date.to_string(),
                metadata: Some(serde_json::json!({
                    "signups": signups,
                    "active": active,
                })),
            });
        }

        Ok(trend)
    }

    /// Get MFA metrics
    pub async fn get_mfa_metrics(
        &self,
        tenant_id: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<MfaMetrics> {
        let mut conn = self.pool.acquire().await?;

        // Get MFA adoption (users with MFA enabled)
        let total_users: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM users WHERE tenant_id = $1"#,
        )
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        let mfa_users: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(DISTINCT user_id) 
               FROM user_mfa_config 
               WHERE tenant_id = $1 AND is_enabled = true"#,
        )
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        let adoption_rate = if total_users > 0 {
            mfa_users as f64 / total_users as f64
        } else {
            0.0
        };

        // Get MFA method breakdown
        let method_stats = sqlx::query(
            r#"SELECT 
                metric_name,
                SUM(metric_value) as total
               FROM analytics_daily_stats
               WHERE tenant_id = $1 
                 AND date >= $2::date 
                 AND date <= $3::date
                 AND metric_name LIKE 'mfa_%'
               GROUP BY metric_name"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&mut *conn)
        .await?;

        let mut by_method = HashMap::new();
        let mut total_attempts = 0i64;
        let mut successful_attempts = 0i64;

        for row in method_stats {
            let name: String = row.try_get("metric_name")?;
            let value: i64 = row.try_get("total")?;

            if name.starts_with("mfa_method_") {
                if let Some(method) = name.strip_prefix("mfa_method_") {
                    by_method.insert(method.to_string(), value);
                }
            } else if name == "mfa_attempt" {
                total_attempts = value;
            } else if name == "mfa_success" {
                successful_attempts = value;
            }
        }

        let success_rate = if total_attempts > 0 {
            successful_attempts as f64 / total_attempts as f64
        } else {
            0.0
        };

        Ok(MfaMetrics {
            adoption_rate,
            by_method,
            success_rate,
        })
    }

    /// Get security metrics
    pub async fn get_security_metrics(
        &self,
        tenant_id: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<SecurityMetrics> {
        let mut conn = self.pool.acquire().await?;

        let stats = sqlx::query(
            r#"SELECT 
                metric_name,
                SUM(metric_value) as total
               FROM analytics_daily_stats
               WHERE tenant_id = $1 
                 AND date >= $2::date 
                 AND date <= $3::date
                 AND (metric_name LIKE 'security_%' OR metric_name LIKE 'lockout_%')
               GROUP BY metric_name"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&mut *conn)
        .await?;

        let mut failed_logins = 0i64;
        let mut account_lockouts = 0i64;
        let mut suspicious_activities = 0i64;
        let mut password_breaches = 0i64;

        for row in stats {
            let name: String = row.try_get("metric_name")?;
            let value: i64 = row.try_get("total")?;

            match name.as_str() {
                "login_failed" => failed_logins = value,
                "lockout_total" => account_lockouts = value,
                "security_suspicious" => suspicious_activities = value,
                "security_password_breach" => password_breaches = value,
                _ => {}
            }
        }

        // Get top failed login IPs
        let top_failed_ips = sqlx::query(
            r#"SELECT 
                (metadata->>'ip_address') as ip,
                COUNT(*) as attempts
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login'
                 AND (metadata->>'success')::boolean = false
                 AND created_at >= $2 
                 AND created_at <= $3
               GROUP BY ip
               ORDER BY attempts DESC
               LIMIT 10"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&mut *conn)
        .await?;

        let mut failed_login_ips = Vec::new();
        for row in top_failed_ips {
            let ip: Option<String> = row.try_get("ip")?;
            let attempts: i64 = row.try_get("attempts")?;
            if let Some(ip) = ip {
                failed_login_ips.push((ip, attempts));
            }
        }

        Ok(SecurityMetrics {
            failed_logins,
            account_lockouts,
            suspicious_activities,
            password_breaches_detected: password_breaches,
            failed_login_ips,
        })
    }

    /// Get device metrics
    pub async fn get_device_metrics(
        &self,
        tenant_id: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<DeviceMetrics> {
        let mut conn = self.pool.acquire().await?;

        // Get browser breakdown
        let browser_stats = sqlx::query(
            r#"SELECT 
                COALESCE(metadata->>'browser', 'unknown') as browser,
                COUNT(*) as count
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login'
                 AND created_at >= $2 
                 AND created_at <= $3
               GROUP BY browser
               ORDER BY count DESC"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&mut *conn)
        .await?;

        let mut by_browser = HashMap::new();
        for row in browser_stats {
            let browser: String = row.try_get("browser")?;
            let count: i64 = row.try_get("count")?;
            by_browser.insert(browser, count);
        }

        // Get OS breakdown
        let os_stats = sqlx::query(
            r#"SELECT 
                COALESCE(metadata->>'os', 'unknown') as os,
                COUNT(*) as count
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login'
                 AND created_at >= $2 
                 AND created_at <= $3
               GROUP BY os
               ORDER BY count DESC"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&mut *conn)
        .await?;

        let mut by_os = HashMap::new();
        for row in os_stats {
            let os: String = row.try_get("os")?;
            let count: i64 = row.try_get("count")?;
            by_os.insert(os, count);
        }

        // Get device type breakdown
        let device_stats = sqlx::query(
            r#"SELECT 
                COALESCE(metadata->>'device_type', 'desktop') as device_type,
                COUNT(*) as count
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login'
                 AND created_at >= $2 
                 AND created_at <= $3
               GROUP BY device_type
               ORDER BY count DESC"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&mut *conn)
        .await?;

        let mut by_device_type = HashMap::new();
        for row in device_stats {
            let device_type: String = row.try_get("device_type")?;
            let count: i64 = row.try_get("count")?;
            by_device_type.insert(device_type, count);
        }

        Ok(DeviceMetrics {
            by_browser,
            by_os,
            by_device_type,
        })
    }

    /// Get geographic metrics
    pub async fn get_geographic_metrics(
        &self,
        tenant_id: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<GeographicMetrics> {
        let mut conn = self.pool.acquire().await?;

        // Get country breakdown
        let country_stats = sqlx::query(
            r#"SELECT 
                COALESCE(metadata->>'country', 'unknown') as country,
                COUNT(*) as logins,
                COUNT(DISTINCT user_id) as unique_users
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login'
                 AND created_at >= $2 
                 AND created_at <= $3
               GROUP BY country
               ORDER BY logins DESC"#,
        )
        .bind(tenant_id)
        .bind(&start_date)
        .bind(&end_date)
        .fetch_all(&mut *conn)
        .await?;

        let mut countries = Vec::new();
        for row in country_stats {
            let country: String = row.try_get("country")?;
            let logins: i64 = row.try_get("logins")?;
            let unique_users: i64 = row.try_get("unique_users")?;

            countries.push(CountryMetrics {
                country_code: country.clone(),
                country_name: country, // TODO: Map country codes to names
                login_count: logins,
                unique_users,
            });
        }

        Ok(GeographicMetrics { countries })
    }

    /// Get dashboard overview
    pub async fn get_dashboard_overview(
        &self,
        tenant_id: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<DashboardOverview> {
        let login_metrics = self.get_login_metrics(tenant_id, start_date, end_date, TimeInterval::Day).await?;
        let user_metrics = self.get_user_metrics(tenant_id, start_date, end_date).await?;
        let mfa_metrics = self.get_mfa_metrics(tenant_id, start_date, end_date).await?;
        let security_metrics = self.get_security_metrics(tenant_id, start_date, end_date).await?;

        // Get current active sessions count
        let current_active_sessions: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM sessions 
               WHERE tenant_id = $1 
                 AND status = 'active' 
                 AND expires_at > NOW()"#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(DashboardOverview {
            period: Period {
                start: start_date,
                end: end_date,
            },
            logins: LoginOverview {
                total: login_metrics.total,
                successful: login_metrics.successful,
                failed: login_metrics.failed,
                trend: login_metrics.trend,
            },
            users: UserOverview {
                new: user_metrics.new_signups,
                active: user_metrics.active_users,
                retention_7d: user_metrics.retention_rate,
            },
            mfa: MfaOverview {
                adoption_rate: mfa_metrics.adoption_rate,
                by_method: mfa_metrics.by_method,
            },
            security: SecurityOverview {
                failed_logins: security_metrics.failed_logins,
                account_lockouts: security_metrics.account_lockouts,
                suspicious_activities: security_metrics.suspicious_activities,
            },
            current_active_sessions,
        })
    }
}

/// Time interval for aggregation
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeInterval {
    Hour,
    Day,
    Week,
    Month,
}

impl std::str::FromStr for TimeInterval {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "hour" => Ok(TimeInterval::Hour),
            "day" => Ok(TimeInterval::Day),
            "week" => Ok(TimeInterval::Week),
            "month" => Ok(TimeInterval::Month),
            _ => Err(format!("Invalid time interval: {}", s)),
        }
    }
}

/// Analytics event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsEvent {
    pub id: String,
    pub tenant_id: Option<String>,
    pub event_type: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub metadata: EventMetadata,
    pub created_at: DateTime<Utc>,
}

impl AnalyticsEvent {
    /// Create a new analytics event
    pub fn new(
        tenant_id: &str,
        user_id: Option<&str>,
        session_id: Option<&str>,
        event_type: &str,
        metadata: EventMetadata,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            tenant_id: Some(tenant_id.to_string()),
            event_type: event_type.to_string(),
            user_id: user_id.map(|s| s.to_string()),
            session_id: session_id.map(|s| s.to_string()),
            metadata,
            created_at: Utc::now(),
        }
    }

    /// Create a login event
    pub fn new_login(
        tenant_id: &str,
        user_id: Option<&str>,
        session_id: Option<&str>,
        success: bool,
        method: LoginMethod,
        login_metadata: LoginMetadata,
    ) -> Self {
        let metadata = EventMetadata::Login {
            success,
            method,
            ip_address: login_metadata.ip_address,
            user_agent: login_metadata.user_agent,
            browser: login_metadata.browser,
            os: login_metadata.os,
            device_type: login_metadata.device_type,
            country: login_metadata.country,
            city: login_metadata.city,
            error_code: login_metadata.error_code,
        };

        Self::new(tenant_id, user_id, session_id, "login", metadata)
    }

    /// Create a signup event
    pub fn new_signup(
        tenant_id: &str,
        user_id: &str,
        method: SignupMethod,
        signup_metadata: SignupMetadata,
    ) -> Self {
        let metadata = EventMetadata::Signup {
            method,
            ip_address: signup_metadata.ip_address,
            user_agent: signup_metadata.user_agent,
            browser: signup_metadata.browser,
            os: signup_metadata.os,
            has_referral: signup_metadata.has_referral,
            referral_source: signup_metadata.referral_source,
        };

        Self::new(tenant_id, Some(user_id), None, "signup", metadata)
    }

    /// Create an MFA event
    pub fn new_mfa(
        tenant_id: &str,
        user_id: &str,
        method: MfaMethod,
        success: bool,
        mfa_metadata: MfaMetadata,
    ) -> Self {
        let metadata = EventMetadata::Mfa {
            method,
            success,
            ip_address: mfa_metadata.ip_address,
            error_code: mfa_metadata.error_code,
            attempt_number: mfa_metadata.attempt_number,
        };

        Self::new(tenant_id, Some(user_id), None, "mfa", metadata)
    }

    /// Create a security event
    pub fn new_security(
        tenant_id: &str,
        user_id: Option<&str>,
        event_type: SecurityEventType,
        security_metadata: SecurityMetadata,
    ) -> Self {
        let metadata = EventMetadata::Security {
            event_type,
            ip_address: security_metadata.ip_address,
            details: security_metadata.details,
        };

        Self::new(tenant_id, user_id, None, "security", metadata)
    }

    /// Create a session event
    pub fn new_session(
        tenant_id: &str,
        user_id: &str,
        session_id: &str,
        event_type: SessionEventType,
        session_metadata: SessionMetadata,
    ) -> Self {
        let metadata = EventMetadata::Session {
            event_type,
            duration_seconds: session_metadata.duration_seconds,
            ip_address: session_metadata.ip_address,
        };

        Self::new(tenant_id, Some(user_id), Some(session_id), "session", metadata)
    }
}

/// Event metadata variants
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_category", rename_all = "snake_case")]
pub enum EventMetadata {
    Login {
        success: bool,
        method: LoginMethod,
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
    },
    Signup {
        method: SignupMethod,
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
    },
    Mfa {
        method: MfaMethod,
        success: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        ip_address: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_code: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        attempt_number: Option<i32>,
    },
    Security {
        event_type: SecurityEventType,
        #[serde(skip_serializing_if = "Option::is_none")]
        ip_address: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<serde_json::Value>,
    },
    Session {
        event_type: SessionEventType,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration_seconds: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ip_address: Option<String>,
    },
}

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

/// Session metadata helper
#[derive(Debug, Clone, Default)]
pub struct SessionMetadata {
    pub duration_seconds: Option<i64>,
    pub ip_address: Option<String>,
}

/// Dashboard overview response
#[derive(Debug, Clone, Serialize)]
pub struct DashboardOverview {
    pub period: Period,
    pub logins: LoginOverview,
    pub users: UserOverview,
    pub mfa: MfaOverview,
    pub security: SecurityOverview,
    pub current_active_sessions: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Period {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginOverview {
    pub total: i64,
    pub successful: i64,
    pub failed: i64,
    pub trend: Vec<TrendDataPoint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserOverview {
    pub new: i64,
    pub active: i64,
    pub retention_7d: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MfaOverview {
    pub adoption_rate: f64,
    pub by_method: HashMap<String, i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityOverview {
    pub failed_logins: i64,
    pub account_lockouts: i64,
    pub suspicious_activities: i64,
}
