//! Analytics Metrics Types
//!
//! Defines the various metric structures used for analytics reporting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trend data point for time-series data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendDataPoint {
    pub timestamp: DateTime<Utc>,
    pub value: i64,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Login metrics for a time period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginMetrics {
    /// Total login attempts
    pub total: i64,
    /// Successful logins
    pub successful: i64,
    /// Failed login attempts
    pub failed: i64,
    /// Time-series trend data
    pub trend: Vec<TrendDataPoint>,
    /// Breakdown by authentication method
    pub by_method: HashMap<String, i64>,
}

impl LoginMetrics {
    /// Calculate success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.total > 0 {
            self.successful as f64 / self.total as f64
        } else {
            0.0
        }
    }

    /// Calculate failure rate as percentage
    pub fn failure_rate(&self) -> f64 {
        if self.total > 0 {
            self.failed as f64 / self.total as f64
        } else {
            0.0
        }
    }
}

/// User engagement metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMetrics {
    /// New user signups
    pub new_signups: i64,
    /// Active users (logged in during period)
    pub active_users: i64,
    /// Retention rate (0.0 to 1.0)
    pub retention_rate: f64,
    /// Time-series trend data
    pub trend: Vec<TrendDataPoint>,
}

/// MFA adoption and usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaMetrics {
    /// MFA adoption rate (0.0 to 1.0)
    pub adoption_rate: f64,
    /// Breakdown by MFA method
    pub by_method: HashMap<String, i64>,
    /// MFA verification success rate
    pub success_rate: f64,
}

impl MfaMetrics {
    /// Get total MFA enrollments across all methods
    pub fn total_enrollments(&self) -> i64 {
        self.by_method.values().sum()
    }

    /// Get the most popular MFA method
    pub fn most_popular_method(&self) -> Option<(String, i64)> {
        self.by_method
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(method, count)| (method.clone(), *count))
    }
}

/// Security-related metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    /// Total failed login attempts
    pub failed_logins: i64,
    /// Number of account lockouts
    pub account_lockouts: i64,
    /// Suspicious activities detected
    pub suspicious_activities: i64,
    /// Password breaches detected
    pub password_breaches_detected: i64,
    /// Top IPs with failed login attempts
    pub failed_login_ips: Vec<(String, i64)>,
}

impl SecurityMetrics {
    /// Calculate risk score (0-100) based on security metrics
    pub fn risk_score(&self) -> u32 {
        let mut score = 0u32;

        // Failed logins contribute up to 30 points
        score += (self.failed_logins.min(1000) as u32 * 30) / 1000;

        // Account lockouts contribute up to 25 points
        score += (self.account_lockouts.min(100) as u32 * 25) / 100;

        // Suspicious activities contribute up to 25 points
        score += (self.suspicious_activities.min(50) as u32 * 25) / 50;

        // Password breaches contribute up to 20 points
        score += (self.password_breaches_detected.min(10) as u32 * 20) / 10;

        score.min(100)
    }

    /// Get risk level based on score
    pub fn risk_level(&self) -> RiskLevel {
        match self.risk_score() {
            0..=20 => RiskLevel::Low,
            21..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
}

/// Risk level categories
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Device metrics (browsers, OS, device types)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceMetrics {
    /// Breakdown by browser
    pub by_browser: HashMap<String, i64>,
    /// Breakdown by operating system
    pub by_os: HashMap<String, i64>,
    /// Breakdown by device type (desktop, mobile, tablet)
    pub by_device_type: HashMap<String, i64>,
}

impl DeviceMetrics {
    /// Get the most popular browser
    pub fn top_browser(&self) -> Option<(String, i64)> {
        self.by_browser
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(browser, count)| (browser.clone(), *count))
    }

    /// Get the most popular OS
    pub fn top_os(&self) -> Option<(String, i64)> {
        self.by_os
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(os, count)| (os.clone(), *count))
    }

    /// Get total device counts
    pub fn total_devices(&self) -> i64 {
        self.by_device_type.values().sum()
    }

    /// Get mobile vs desktop ratio
    pub fn mobile_ratio(&self) -> f64 {
        let total = self.total_devices();
        if total == 0 {
            return 0.0;
        }

        let mobile = self.by_device_type.get("mobile").copied().unwrap_or(0);
        let tablet = self.by_device_type.get("tablet").copied().unwrap_or(0);

        (mobile + tablet) as f64 / total as f64
    }
}

/// Geographic metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeographicMetrics {
    /// Metrics by country
    pub countries: Vec<CountryMetrics>,
}

/// Country-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountryMetrics {
    /// ISO country code
    pub country_code: String,
    /// Full country name
    pub country_name: String,
    /// Number of logins from this country
    pub login_count: i64,
    /// Number of unique users from this country
    pub unique_users: i64,
}

impl GeographicMetrics {
    /// Get top countries by login count
    pub fn top_countries(&self, limit: usize) -> Vec<&CountryMetrics> {
        self.countries.iter().take(limit).collect()
    }

    /// Get total unique countries
    pub fn total_countries(&self) -> usize {
        self.countries.len()
    }

    /// Calculate concentration (Herfindahl index) of logins
    /// 0 = evenly distributed, 1 = all from one country
    pub fn concentration_index(&self) -> f64 {
        let total_logins: i64 = self.countries.iter().map(|c| c.login_count).sum();
        if total_logins == 0 {
            return 0.0;
        }

        let mut hhi = 0.0;
        for country in &self.countries {
            let share = country.login_count as f64 / total_logins as f64;
            hhi += share * share;
        }

        hhi
    }
}

/// Session metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetrics {
    /// Total sessions created
    pub total_sessions: i64,
    /// Currently active sessions
    pub active_sessions: i64,
    /// Average session duration in seconds
    pub avg_duration_seconds: f64,
    /// Median session duration in seconds
    pub median_duration_seconds: f64,
    /// Sessions revoked by admin action
    pub admin_revoked: i64,
    /// Sessions expired naturally
    pub expired: i64,
    /// Session trend over time
    pub trend: Vec<TrendDataPoint>,
}

/// Export format options
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Csv,
    Json,
}

impl std::str::FromStr for ExportFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "csv" => Ok(ExportFormat::Csv),
            "json" => Ok(ExportFormat::Json),
            _ => Err(format!("Invalid export format: {}", s)),
        }
    }
}

/// Analytics export configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticsExport {
    /// Export format
    pub format: ExportFormat,
    /// Start date for export range
    pub start_date: DateTime<Utc>,
    /// End date for export range
    pub end_date: DateTime<Utc>,
    /// Metrics to include
    pub metrics: Vec<String>,
    /// Tenant ID filter
    pub tenant_id: Option<String>,
}

/// Real-time metrics snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealTimeMetrics {
    /// Timestamp of the snapshot
    pub timestamp: DateTime<Utc>,
    /// Current active sessions
    pub active_sessions: i64,
    /// Logins in the last minute
    pub logins_last_minute: i64,
    /// Logins in the last 5 minutes
    pub logins_last_5_minutes: i64,
    /// Logins in the last hour
    pub logins_last_hour: i64,
    /// Current authentication rate (logins per minute)
    pub current_auth_rate: f64,
    /// Top active users by session count
    pub top_active_users: Vec<ActiveUser>,
}

/// Active user for real-time metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveUser {
    pub user_id: String,
    pub email: String,
    pub session_count: i32,
    pub last_activity: DateTime<Utc>,
}

/// Aggregation job configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationConfig {
    /// Enable hourly aggregation
    pub hourly_enabled: bool,
    /// Enable daily aggregation
    pub daily_enabled: bool,
    /// Enable weekly aggregation
    pub weekly_enabled: bool,
    /// Enable monthly aggregation
    pub monthly_enabled: bool,
    /// Days to retain raw events
    pub raw_event_retention_days: i32,
    /// Days to retain daily stats
    pub daily_stats_retention_days: i32,
}

impl Default for AggregationConfig {
    fn default() -> Self {
        Self {
            hourly_enabled: true,
            daily_enabled: true,
            weekly_enabled: true,
            monthly_enabled: true,
            raw_event_retention_days: 30,
            daily_stats_retention_days: 365,
        }
    }
}

/// Aggregation job status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationStatus {
    pub job_type: AggregationJobType,
    pub last_run: Option<DateTime<Utc>>,
    pub last_success: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub records_processed: i64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationJobType {
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Cleanup,
}

/// External analytics integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAnalyticsConfig {
    /// Enable Segment integration
    pub segment_enabled: bool,
    /// Segment write key
    pub segment_write_key: Option<String>,
    /// Enable Mixpanel integration
    pub mixpanel_enabled: bool,
    /// Mixpanel token
    pub mixpanel_token: Option<String>,
    /// Enable custom webhook
    pub webhook_enabled: bool,
    /// Custom webhook URL
    pub webhook_url: Option<String>,
    /// Events to forward (empty = all)
    pub event_filter: Vec<String>,
}

impl Default for ExternalAnalyticsConfig {
    fn default() -> Self {
        Self {
            segment_enabled: false,
            segment_write_key: None,
            mixpanel_enabled: false,
            mixpanel_token: None,
            webhook_enabled: false,
            webhook_url: None,
            event_filter: Vec::new(),
        }
    }
}

/// Comparison period for trend analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonPeriod {
    /// Current period metrics
    pub current: MetricSnapshot,
    /// Previous period metrics
    pub previous: MetricSnapshot,
    /// Percentage change (-1.0 to 1.0)
    pub change_percent: f64,
}

/// Snapshot of key metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSnapshot {
    pub timestamp: DateTime<Utc>,
    pub total_logins: i64,
    pub unique_users: i64,
    pub new_signups: i64,
    pub failed_logins: i64,
}

impl MetricSnapshot {
    /// Compare with another snapshot
    pub fn compare_with(&self, other: &MetricSnapshot) -> ComparisonPeriod {
        let change_percent = if other.total_logins > 0 {
            (self.total_logins as f64 - other.total_logins as f64) / other.total_logins as f64
        } else {
            0.0
        };

        ComparisonPeriod {
            current: self.clone(),
            previous: other.clone(),
            change_percent,
        }
    }
}
