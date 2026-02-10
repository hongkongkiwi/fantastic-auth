//! Analytics Repository
//!
//! Database operations for analytics events and aggregated statistics.

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{postgres::PgPool, Row};
use std::collections::HashMap;
use tracing::{debug, instrument};
use uuid::Uuid;

use super::models::*;

// Re-export try_get for use in this module
use sqlx::Row as _;

/// Repository for analytics database operations
#[derive(Clone)]
pub struct AnalyticsRepository {
    pool: PgPool,
}

impl AnalyticsRepository {
    /// Create a new analytics repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // ============ Event Storage ============

    /// Store a single analytics event
    #[instrument(skip(self, event))]
    pub async fn store_event(&self, event: &AnalyticsEvent) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO analytics_events 
               (id, tenant_id, event_type, user_id, session_id, metadata, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
        )
        .bind(event.id)
        .bind(event.tenant_id)
        .bind(&event.event_type)
        .bind(event.user_id)
        .bind(event.session_id)
        .bind(&event.metadata)
        .bind(event.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Store multiple analytics events in a batch
    #[instrument(skip(self, events))]
    pub async fn store_events_batch(&self, events: &[AnalyticsEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;

        for event in events {
            sqlx::query(
                r#"INSERT INTO analytics_events 
                   (id, tenant_id, event_type, user_id, session_id, metadata, created_at)
                   VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            )
            .bind(event.id)
            .bind(event.tenant_id)
            .bind(&event.event_type)
            .bind(event.user_id)
            .bind(event.session_id)
            .bind(&event.metadata)
            .bind(event.created_at)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        
        debug!(event_count = events.len(), "Stored analytics events batch");
        Ok(())
    }

    /// Get events for a tenant within a time range
    #[instrument(skip(self))]
    pub async fn get_events(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
        event_type: Option<&str>,
        limit: i64,
    ) -> anyhow::Result<Vec<AnalyticsEvent>> {
        let events = if let Some(etype) = event_type {
            sqlx::query_as::<_, AnalyticsEventRow>(
                r#"SELECT id, tenant_id, event_type, user_id, session_id, metadata, created_at
                   FROM analytics_events
                   WHERE tenant_id = $1 
                     AND event_type = $2
                     AND created_at >= $3 
                     AND created_at <= $4
                   ORDER BY created_at DESC
                   LIMIT $5"#,
            )
            .bind(tenant_id)
            .bind(etype)
            .bind(start_date)
            .bind(end_date)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, AnalyticsEventRow>(
                r#"SELECT id, tenant_id, event_type, user_id, session_id, metadata, created_at
                   FROM analytics_events
                   WHERE tenant_id = $1 
                     AND created_at >= $2 
                     AND created_at <= $3
                   ORDER BY created_at DESC
                   LIMIT $4"#,
            )
            .bind(tenant_id)
            .bind(start_date)
            .bind(end_date)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };

        Ok(events.into_iter().map(|e| e.into()).collect())
    }

    // ============ Aggregated Statistics ============

    /// Get daily stats for a metric
    #[instrument(skip(self))]
    pub async fn get_daily_stats(
        &self,
        tenant_id: Uuid,
        metric_name: &str,
        start_date: NaiveDate,
        end_date: NaiveDate,
    ) -> anyhow::Result<Vec<DailyStats>> {
        let rows = sqlx::query_as::<_, DailyStatsRow>(
            r#"SELECT tenant_id, date, metric_name, metric_value, metadata, created_at, updated_at
               FROM analytics_daily_stats
               WHERE tenant_id = $1 
                 AND metric_name = $2
                 AND date >= $3 
                 AND date <= $4
               ORDER BY date"#,
        )
        .bind(tenant_id)
        .bind(metric_name)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Get aggregated metrics by name pattern
    #[instrument(skip(self))]
    pub async fn get_aggregated_metrics(
        &self,
        tenant_id: Uuid,
        metric_pattern: &str,
        start_date: NaiveDate,
        end_date: NaiveDate,
    ) -> anyhow::Result<HashMap<String, i64>> {
        let rows = sqlx::query(
            r#"SELECT 
                metric_name,
                SUM(metric_value) as total
               FROM analytics_daily_stats
               WHERE tenant_id = $1 
                 AND metric_name LIKE $2
                 AND date >= $3 
                 AND date <= $4
               GROUP BY metric_name"#,
        )
        .bind(tenant_id)
        .bind(metric_pattern)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let mut result = HashMap::new();
        for row in rows {
            let name: String = row.try_get("metric_name")?;
            let value: i64 = row.try_get("total")?;
            result.insert(name, value);
        }

        Ok(result)
    }

    /// Upsert daily stats
    #[instrument(skip(self))]
    pub async fn upsert_daily_stats(
        &self,
        tenant_id: Uuid,
        date: NaiveDate,
        metric_name: &str,
        metric_value: i64,
        metadata: Option<serde_json::Value>,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO analytics_daily_stats 
               (tenant_id, date, metric_name, metric_value, metadata, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
               ON CONFLICT (tenant_id, date, metric_name)
               DO UPDATE SET
                   metric_value = analytics_daily_stats.metric_value + EXCLUDED.metric_value,
                   metadata = COALESCE(analytics_daily_stats.metadata, '{}') || COALESCE(EXCLUDED.metadata, '{}'),
                   updated_at = NOW()"#,
        )
        .bind(tenant_id)
        .bind(date)
        .bind(metric_name)
        .bind(metric_value)
        .bind(metadata)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ============ Login Analytics ============

    /// Get login metrics for time period
    #[instrument(skip(self))]
    pub async fn get_login_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<LoginMetrics> {
        let start_naive = start_date.date_naive();
        let end_naive = end_date.date_naive();

        // Get aggregated stats
        let stats = self.get_aggregated_metrics(
            tenant_id,
            "login_%",
            start_naive,
            end_naive,
        ).await?;

        let total = stats.get("login_total").copied().unwrap_or(0);
        let successful = stats.get("login_success").copied().unwrap_or(0);
        let failed = stats.get("login_failed").copied().unwrap_or(0);

        // Get unique users count
        let unique_users: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(DISTINCT user_id) 
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login'
                 AND created_at >= $2 
                 AND created_at <= $3"#,
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_one(&self.pool)
        .await?;

        // Get trend data
        let trend = self.get_daily_trend(
            tenant_id,
            &["login_total", "login_success", "login_failed"],
            start_naive,
            end_naive,
        ).await?;

        // Get method breakdown
        let by_method = self.get_method_breakdown(
            tenant_id,
            "login",
            start_date,
            end_date,
        ).await?;

        // Get hourly breakdown
        let by_hour = self.get_hourly_breakdown(
            tenant_id,
            "login",
            start_date,
            end_date,
        ).await?;

        // Get day of week breakdown
        let by_day_of_week = self.get_day_of_week_breakdown(
            tenant_id,
            "login",
            start_date,
            end_date,
        ).await?;

        Ok(LoginMetrics {
            total,
            successful,
            failed,
            unique_users,
            trend,
            by_method,
            by_hour,
            by_day_of_week,
        })
    }

    // ============ User Analytics ============

    /// Get user metrics for time period
    #[instrument(skip(self))]
    pub async fn get_user_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<UserMetrics> {
        let start_naive = start_date.date_naive();
        let end_naive = end_date.date_naive();

        // Get total users
        let total_users: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        // Get new signups from aggregated stats
        let stats = self.get_aggregated_metrics(
            tenant_id,
            "signup_%",
            start_naive,
            end_naive,
        ).await?;

        let new_signups = stats.get("signup_total").copied().unwrap_or(0);

        // Get active users
        let active_users: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(DISTINCT user_id) 
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login'
                 AND created_at >= $2 
                 AND created_at <= $3"#,
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_one(&self.pool)
        .await?;

        // Calculate retention
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
        .bind(start_date)
        .bind(end_date)
        .bind(previous_start)
        .fetch_one(&self.pool)
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
        .bind(previous_start)
        .bind(start_date)
        .fetch_one(&self.pool)
        .await?;

        let retention_rate = if previous_active_users > 0 {
            retained_users as f64 / previous_active_users as f64
        } else {
            0.0
        };

        // Calculate growth rate
        let growth_rate = if total_users > 0 {
            new_signups as f64 / total_users as f64 * 100.0
        } else {
            0.0
        };

        // Get trend
        let trend = self.get_daily_trend(
            tenant_id,
            &["signup_total", "active_users"],
            start_naive,
            end_naive,
        ).await?;

        // Get signup sources
        let signup_sources = self.get_signup_sources(tenant_id, start_date, end_date).await?;

        // Calculate churn: users active in previous period but not in current period
        let churned_users: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(DISTINCT e1.user_id)
               FROM analytics_events e1
               LEFT JOIN analytics_events e2 
                 ON e1.user_id = e2.user_id 
                 AND e1.tenant_id = e2.tenant_id
                 AND e2.event_type = 'login'
                 AND e2.created_at >= $2 
                 AND e2.created_at <= $3
               WHERE e1.tenant_id = $1
                 AND e1.event_type = 'login'
                 AND e1.created_at >= $4 
                 AND e1.created_at < $2
                 AND e2.user_id IS NULL"#,
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .bind(previous_start)
        .fetch_one(&self.pool)
        .await?;

        Ok(UserMetrics {
            total_users,
            new_signups,
            active_users,
            retention_rate,
            churned_users,
            growth_rate,
            trend,
            signup_sources,
        })
    }

    // ============ MFA Analytics ============

    /// Get MFA metrics for time period
    #[instrument(skip(self))]
    pub async fn get_mfa_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<MfaMetrics> {
        let start_naive = start_date.date_naive();
        let end_naive = end_date.date_naive();

        // Get MFA adoption (users with MFA enabled)
        let total_users: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let mfa_users: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(DISTINCT user_id) 
               FROM user_mfa_config 
               WHERE tenant_id = $1 AND is_enabled = true"#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let adoption_rate = if total_users > 0 {
            mfa_users as f64 / total_users as f64
        } else {
            0.0
        };

        // Get MFA stats from aggregated data
        let stats = self.get_aggregated_metrics(
            tenant_id,
            "mfa_%",
            start_naive,
            end_naive,
        ).await?;

        let total_attempts = stats.get("mfa_attempt").copied().unwrap_or(0);
        let successful_attempts = stats.get("mfa_success").copied().unwrap_or(0);
        let failed_attempts = total_attempts - successful_attempts;

        let success_rate = if total_attempts > 0 {
            successful_attempts as f64 / total_attempts as f64
        } else {
            0.0
        };

        // Get method breakdown
        let mut by_method = HashMap::new();
        for (name, value) in &stats {
            if name.starts_with("mfa_method_") {
                if let Some(method) = name.strip_prefix("mfa_method_") {
                    by_method.insert(method.to_string(), *value);
                }
            }
        }

        Ok(MfaMetrics {
            total_enrollments: mfa_users,
            adoption_rate,
            by_method,
            success_rate,
            total_attempts,
            successful_attempts,
            failed_attempts,
        })
    }

    // ============ Security Analytics ============

    /// Get security metrics for time period
    #[instrument(skip(self))]
    pub async fn get_security_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<SecurityMetrics> {
        let start_naive = start_date.date_naive();
        let end_naive = end_date.date_naive();

        // Get security stats from aggregated data
        let stats = self.get_aggregated_metrics(
            tenant_id,
            "security_%",
            start_naive,
            end_naive,
        ).await?;

        let failed_logins = stats.get("login_failed").copied().unwrap_or(0);
        let account_lockouts = stats.get("lockout_total").copied().unwrap_or(0);
        let suspicious_activities = stats.get("security_suspicious").copied().unwrap_or(0);
        let password_breaches = stats.get("security_password_breach").copied().unwrap_or(0);

        // Get active lockouts
        let active_lockouts: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM account_lockouts 
               WHERE tenant_id = $1 AND locked_until > NOW()"#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        // Get top failed login IPs
        let failed_ips_rows = sqlx::query(
            r#"SELECT 
                COALESCE(metadata->>'ip_address', 'unknown') as ip,
                COUNT(*) as attempts,
                MAX(created_at) as last_attempt
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
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let mut failed_login_ips = Vec::new();
        for row in failed_ips_rows {
            failed_login_ips.push(FailedIpMetrics {
                ip_address: row.try_get("ip")?,
                failed_attempts: row.try_get("attempts")?,
                last_attempt: row.try_get("last_attempt")?,
            });
        }

        // Get failed logins by username
        let failed_username_rows = sqlx::query(
            r#"SELECT 
                COALESCE(metadata->>'username', 'unknown') as username,
                COUNT(*) as attempts
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login_failed'
                 AND created_at >= $2 
                 AND created_at <= $3
               GROUP BY username
               ORDER BY attempts DESC
               LIMIT 10"#,
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let mut failed_logins_by_username = Vec::new();
        for row in failed_username_rows {
            failed_logins_by_username.push(UsernameFailureMetrics {
                username: row.try_get("username")?,
                failed_attempts: row.try_get("attempts")?,
            });
        }

        let metrics = SecurityMetrics {
            failed_logins,
            account_lockouts,
            active_lockouts,
            suspicious_activities,
            password_breaches_detected: password_breaches,
            weak_passwords: 0,
            policy_violations: 0,
            failed_login_ips,
            failed_logins_by_username,
            risk_score: 0,
            risk_level: RiskLevel::Low,
        };

        let risk_score = metrics.calculate_risk_score();
        let risk_level = metrics.calculate_risk_level();

        Ok(SecurityMetrics {
            risk_score,
            risk_level,
            ..metrics
        })
    }

    // ============ Device Analytics ============

    /// Get device metrics for time period
    #[instrument(skip(self))]
    pub async fn get_device_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<DeviceMetrics> {
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
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
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
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
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
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let mut by_device_type = HashMap::new();
        for row in device_stats {
            let device_type: String = row.try_get("device_type")?;
            let count: i64 = row.try_get("count")?;
            by_device_type.insert(device_type, count);
        }

        // Get top device combinations
        let combo_stats = sqlx::query(
            r#"SELECT 
                COALESCE(metadata->>'browser', 'unknown') as browser,
                COALESCE(metadata->>'os', 'unknown') as os,
                COALESCE(metadata->>'device_type', 'desktop') as device_type,
                COUNT(*) as count
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login'
                 AND created_at >= $2 
                 AND created_at <= $3
               GROUP BY browser, os, device_type
               ORDER BY count DESC
               LIMIT 10"#,
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let mut top_combinations = Vec::new();
        for row in combo_stats {
            top_combinations.push(DeviceCombination {
                browser: row.try_get("browser")?,
                os: row.try_get("os")?,
                device_type: row.try_get("device_type")?,
                count: row.try_get("count")?,
            });
        }

        Ok(DeviceMetrics {
            by_browser,
            by_os,
            by_device_type,
            top_combinations,
        })
    }

    // ============ Geographic Analytics ============

    /// Get geographic metrics for time period
    #[instrument(skip(self))]
    pub async fn get_geo_metrics(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<GeoMetrics> {
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
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let total_logins: i64 = country_stats
            .iter()
            .map(|r| -> i64 { r.try_get::<i64, _>("logins").unwrap_or(0) })
            .sum();

        let mut countries = Vec::new();
        for row in country_stats {
            let country: String = row.try_get("country")?;
            let logins: i64 = row.try_get("logins")?;
            let unique_users: i64 = row.try_get("unique_users")?;

            countries.push(CountryMetrics {
                country_code: country.clone(),
                country_name: country,
                login_count: logins,
                unique_users,
                percentage: if total_logins > 0 {
                    logins as f64 / total_logins as f64 * 100.0
                } else {
                    0.0
                },
            });
        }

        // Get top cities
        let city_stats = sqlx::query(
            r#"SELECT 
                COALESCE(metadata->>'city', 'unknown') as city,
                COALESCE(metadata->>'country', 'unknown') as country,
                COUNT(*) as logins,
                COUNT(DISTINCT user_id) as unique_users
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'login'
                 AND created_at >= $2 
                 AND created_at <= $3
                 AND metadata->>'city' IS NOT NULL
               GROUP BY city, country
               ORDER BY logins DESC
               LIMIT 20"#,
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let mut top_cities = Vec::new();
        for row in city_stats {
            top_cities.push(CityMetrics {
                city_name: row.try_get("city")?,
                country_code: row.try_get("country")?,
                login_count: row.try_get("logins")?,
                unique_users: row.try_get("unique_users")?,
            });
        }

        let geo = GeoMetrics {
            countries: countries.clone(),
            top_cities,
            total_countries: countries.len(),
            concentration_index: 0.0,
        };

        let concentration_index = geo.calculate_concentration_index();

        Ok(GeoMetrics {
            concentration_index,
            ..geo
        })
    }

    // ============ Helper Methods ============

    /// Get daily trend data for metrics
    async fn get_daily_trend(
        &self,
        tenant_id: Uuid,
        metric_names: &[&str],
        start_date: NaiveDate,
        end_date: NaiveDate,
    ) -> anyhow::Result<Vec<TrendDataPoint>> {
        let names: Vec<String> = metric_names.iter().map(|s| s.to_string()).collect();
        
        let rows = sqlx::query(
            r#"SELECT 
                date,
                metric_name,
                metric_value
               FROM analytics_daily_stats
               WHERE tenant_id = $1 
                 AND metric_name = ANY($2)
                 AND date >= $3 
                 AND date <= $4
               ORDER BY date"#,
        )
        .bind(tenant_id)
        .bind(&names)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let mut trend = Vec::new();
        for row in rows {
            let date: NaiveDate = row.try_get("date")?;
            let metric_name: String = row.try_get("metric_name")?;
            let value: i64 = row.try_get("metric_value")?;

            trend.push(TrendDataPoint {
                timestamp: date.and_hms_opt(0, 0, 0).unwrap().and_utc(),
                value,
                label: format!("{}: {}", date, metric_name),
                metadata: Some(serde_json::json!({
                    "metric": metric_name,
                })),
            });
        }

        Ok(trend)
    }

    /// Get method breakdown from events
    async fn get_method_breakdown(
        &self,
        tenant_id: Uuid,
        event_type: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<HashMap<String, i64>> {
        let rows = sqlx::query(
            r#"SELECT 
                COALESCE(metadata->>'method', 'unknown') as method,
                COUNT(*) as count
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = $2
                 AND created_at >= $3 
                 AND created_at <= $4
               GROUP BY method"#,
        )
        .bind(tenant_id)
        .bind(event_type)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let mut result = HashMap::new();
        for row in rows {
            let method: String = row.try_get("method")?;
            let count: i64 = row.try_get("count")?;
            result.insert(method, count);
        }

        Ok(result)
    }

    /// Get hourly breakdown
    async fn get_hourly_breakdown(
        &self,
        tenant_id: Uuid,
        event_type: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<HashMap<u8, i64>> {
        let rows = sqlx::query(
            r#"SELECT 
                EXTRACT(HOUR FROM created_at)::int as hour,
                COUNT(*) as count
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = $2
                 AND created_at >= $3 
                 AND created_at <= $4
               GROUP BY hour
               ORDER BY hour"#,
        )
        .bind(tenant_id)
        .bind(event_type)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let mut result = HashMap::new();
        for row in rows {
            let hour: i32 = row.try_get("hour")?;
            let count: i64 = row.try_get("count")?;
            result.insert(hour as u8, count);
        }

        Ok(result)
    }

    /// Get day of week breakdown
    async fn get_day_of_week_breakdown(
        &self,
        tenant_id: Uuid,
        event_type: &str,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<HashMap<String, i64>> {
        let rows = sqlx::query(
            r#"SELECT 
                TO_CHAR(created_at, 'Day') as day_name,
                COUNT(*) as count
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = $2
                 AND created_at >= $3 
                 AND created_at <= $4
               GROUP BY TO_CHAR(created_at, 'Day')
               ORDER BY MIN(EXTRACT(DOW FROM created_at))"#,
        )
        .bind(tenant_id)
        .bind(event_type)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let mut result = HashMap::new();
        for row in rows {
            let day: String = row.try_get("day_name")?;
            let count: i64 = row.try_get("count")?;
            result.insert(day.trim().to_string(), count);
        }

        Ok(result)
    }

    /// Get signup sources
    async fn get_signup_sources(
        &self,
        tenant_id: Uuid,
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<HashMap<String, i64>> {
        let rows = sqlx::query(
            r#"SELECT 
                COALESCE(metadata->>'referral_source', 'organic') as source,
                COUNT(*) as count
               FROM analytics_events
               WHERE tenant_id = $1 
                 AND event_type = 'signup'
                 AND created_at >= $2 
                 AND created_at <= $3
               GROUP BY source"#,
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.pool)
        .await?;

        let mut result = HashMap::new();
        for row in rows {
            let source: String = row.try_get("source")?;
            let count: i64 = row.try_get("count")?;
            result.insert(source, count);
        }

        Ok(result)
    }

    // ============ Aggregation Jobs ============

    /// Create aggregation job record
    #[instrument(skip(self))]
    pub async fn create_job_record(
        &self,
        job_type: &str,
    ) -> anyhow::Result<Uuid> {
        let job_id = Uuid::new_v4();

        sqlx::query(
            r#"INSERT INTO analytics_aggregation_jobs (id, job_type, status, started_at)
               VALUES ($1, $2, 'running', NOW())"#,
        )
        .bind(job_id)
        .bind(job_type)
        .execute(&self.pool)
        .await?;

        Ok(job_id)
    }

    /// Complete job record
    #[instrument(skip(self))]
    pub async fn complete_job_record(
        &self,
        job_id: Uuid,
        records_processed: i64,
        error: Option<&str>,
    ) -> anyhow::Result<()> {
        if let Some(err) = error {
            sqlx::query(
                r#"UPDATE analytics_aggregation_jobs 
                   SET status = 'failed', 
                       error_message = $1, 
                       completed_at = NOW()
                   WHERE id = $2"#,
            )
            .bind(err)
            .bind(job_id)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                r#"UPDATE analytics_aggregation_jobs 
                   SET status = 'completed', 
                       records_processed = $1, 
                       completed_at = NOW()
                   WHERE id = $2"#,
            )
            .bind(records_processed)
            .bind(job_id)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    /// Run daily aggregation using database function
    #[instrument(skip(self))]
    pub async fn run_daily_aggregation(
        &self,
        date: NaiveDate,
        tenant_id: Option<Uuid>,
    ) -> anyhow::Result<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT * FROM aggregate_daily_stats($1, $2)"
        )
        .bind(date)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let mut results = Vec::new();
        for row in rows {
            let metric_name: String = row.try_get("metric_name")?;
            let metric_value: i64 = row.try_get("metric_value")?;
            results.push((metric_name, metric_value));
        }

        Ok(results)
    }

    /// Cleanup old analytics data
    #[instrument(skip(self))]
    pub async fn cleanup_old_data(
        &self,
        raw_retention_days: i32,
        stats_retention_days: i32,
    ) -> anyhow::Result<(i64, i64, i64)> {
        let row = sqlx::query(
            "SELECT * FROM cleanup_old_analytics_data($1, $2)"
        )
        .bind(raw_retention_days)
        .bind(stats_retention_days)
        .fetch_one(&self.pool)
        .await?;

        let deleted_raw: i64 = row.try_get("deleted_raw_events")?;
        let deleted_hourly: i64 = row.try_get("deleted_hourly_stats")?;
        let deleted_snapshots: i64 = row.try_get("deleted_snapshots")?;

        Ok((deleted_raw, deleted_hourly, deleted_snapshots))
    }
}

// ============ Database Row Types ============

#[derive(sqlx::FromRow)]
struct AnalyticsEventRow {
    id: Uuid,
    tenant_id: Option<Uuid>,
    event_type: String,
    user_id: Option<Uuid>,
    session_id: Option<Uuid>,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
}

impl From<AnalyticsEventRow> for AnalyticsEvent {
    fn from(row: AnalyticsEventRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            event_type: row.event_type,
            user_id: row.user_id,
            session_id: row.session_id,
            metadata: row.metadata,
            created_at: row.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct DailyStatsRow {
    tenant_id: Uuid,
    date: NaiveDate,
    metric_name: String,
    metric_value: i64,
    metadata: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<DailyStatsRow> for DailyStats {
    fn from(row: DailyStatsRow) -> Self {
        Self {
            tenant_id: row.tenant_id,
            date: row.date,
            metric_name: row.metric_name,
            metric_value: row.metric_value,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}
