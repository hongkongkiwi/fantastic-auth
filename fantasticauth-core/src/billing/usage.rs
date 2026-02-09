//! Usage-based billing utilities
//!
//! This module provides types and utilities for metered/usage-based billing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Usage metric types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsageMetric {
    /// Number of API calls
    ApiCalls,
    /// Storage used in bytes
    StorageBytes,
    /// Number of users
    Users,
    /// Number of teams/organizations
    Teams,
    /// Compute time in seconds
    ComputeSeconds,
    /// Bandwidth in bytes
    BandwidthBytes,
    /// Number of events processed
    EventsProcessed,
    /// Number of emails sent
    EmailsSent,
    /// Number of SMS sent
    SmsSent,
    /// Number of webhooks delivered
    WebhooksDelivered,
    /// Custom metric
    Custom(String),
}

impl std::fmt::Display for UsageMetric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UsageMetric::ApiCalls => write!(f, "api_calls"),
            UsageMetric::StorageBytes => write!(f, "storage_bytes"),
            UsageMetric::Users => write!(f, "users"),
            UsageMetric::Teams => write!(f, "teams"),
            UsageMetric::ComputeSeconds => write!(f, "compute_seconds"),
            UsageMetric::BandwidthBytes => write!(f, "bandwidth_bytes"),
            UsageMetric::EventsProcessed => write!(f, "events_processed"),
            UsageMetric::EmailsSent => write!(f, "emails_sent"),
            UsageMetric::SmsSent => write!(f, "sms_sent"),
            UsageMetric::WebhooksDelivered => write!(f, "webhooks_delivered"),
            UsageMetric::Custom(name) => write!(f, "{}", name),
        }
    }
}

/// Usage aggregation method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AggregationMethod {
    /// Sum all values in the period
    Sum,
    /// Use the last value in the period
    LastDuringPeriod,
    /// Use the maximum value during the period
    Maximum,
    /// Unique count
    UniqueCount,
}

/// Usage record for reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageReport {
    pub id: String,
    pub tenant_id: String,
    pub metric: UsageMetric,
    pub quantity: i64,
    pub timestamp: DateTime<Utc>,
    pub action: UsageAction,
    pub metadata: Option<serde_json::Value>,
}

/// Action for usage reporting
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsageAction {
    /// Increment the usage by the quantity
    Increment,
    /// Set the usage to the quantity
    Set,
}

impl Default for UsageAction {
    fn default() -> Self {
        UsageAction::Increment
    }
}

/// Usage quota for a metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageQuota {
    pub metric: UsageMetric,
    pub limit: i64,
    pub warning_threshold: Option<f64>, // Percentage (0.0 - 1.0)
}

impl UsageQuota {
    /// Create a new quota
    pub fn new(metric: UsageMetric, limit: i64) -> Self {
        Self {
            metric,
            limit,
            warning_threshold: Some(0.8), // 80% by default
        }
    }

    /// Set warning threshold
    pub fn with_warning_threshold(mut self, threshold: f64) -> Self {
        self.warning_threshold = Some(threshold.clamp(0.0, 1.0));
        self
    }

    /// Check if usage exceeds limit
    pub fn is_exceeded(&self, usage: i64) -> bool {
        usage > self.limit
    }

    /// Check if usage is near limit (warning threshold)
    pub fn is_near_limit(&self, usage: i64) -> bool {
        self.warning_threshold.map_or(false, |threshold| {
            let usage_ratio = usage as f64 / self.limit as f64;
            usage_ratio >= threshold && !self.is_exceeded(usage)
        })
    }

    /// Get remaining quota
    pub fn remaining(&self, usage: i64) -> i64 {
        (self.limit - usage).max(0)
    }

    /// Get usage percentage
    pub fn usage_percentage(&self, usage: i64) -> f64 {
        if self.limit == 0 {
            return 0.0;
        }
        ((usage as f64 / self.limit as f64) * 100.0).min(100.0)
    }
}

/// Usage summary for a period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsagePeriodSummary {
    pub metric: UsageMetric,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_usage: i64,
    pub quota: Option<UsageQuota>,
}

impl UsagePeriodSummary {
    /// Check if quota is exceeded
    pub fn is_quota_exceeded(&self) -> bool {
        self.quota.as_ref().map_or(false, |q| q.is_exceeded(self.total_usage))
    }

    /// Check if near quota limit
    pub fn is_near_quota(&self) -> bool {
        self.quota.as_ref().map_or(false, |q| q.is_near_limit(self.total_usage))
    }

    /// Get remaining quota
    pub fn remaining_quota(&self) -> Option<i64> {
        self.quota.as_ref().map(|q| q.remaining(self.total_usage))
    }

    /// Get usage percentage
    pub fn usage_percentage(&self) -> Option<f64> {
        self.quota.as_ref().map(|q| q.usage_percentage(self.total_usage))
    }
}

/// Usage tracker for in-memory tracking
pub struct UsageTracker {
    reports: Vec<UsageReport>,
}

impl UsageTracker {
    /// Create a new usage tracker
    pub fn new() -> Self {
        Self {
            reports: Vec::new(),
        }
    }

    /// Record usage
    pub fn record(&mut self, report: UsageReport) {
        self.reports.push(report);
    }

    /// Get total usage for a metric in a period
    pub fn get_total_usage(
        &self,
        metric: &UsageMetric,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> i64 {
        self.reports
            .iter()
            .filter(|r| &r.metric == metric && r.timestamp >= start && r.timestamp <= end)
            .map(|r| r.quantity)
            .sum()
    }

    /// Clear old reports
    pub fn clear_before(&mut self, cutoff: DateTime<Utc>) {
        self.reports.retain(|r| r.timestamp >= cutoff);
    }

    /// Get all reports for a metric
    pub fn get_reports(&self, metric: &UsageMetric) -> Vec<&UsageReport> {
        self.reports
            .iter()
            .filter(|r| &r.metric == metric)
            .collect()
    }
}

impl Default for UsageTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Metered price configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeteredPrice {
    pub metric: UsageMetric,
    pub unit_amount: i64, // Price per unit in cents
    pub currency: String,
    pub tiers: Vec<PriceTier>,
    pub aggregation: AggregationMethod,
}

/// Price tier for graduated pricing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceTier {
    pub up_to: Option<i64>, // None means unlimited
    pub unit_amount: i64,
    pub flat_amount: Option<i64>,
}

impl MeteredPrice {
    /// Calculate cost for usage
    pub fn calculate_cost(&self, usage: i64) -> i64 {
        if self.tiers.is_empty() {
            // Simple per-unit pricing
            return usage * self.unit_amount;
        }

        // Tiered pricing
        let mut cost = 0i64;
        let mut remaining = usage;
        let mut previous_up_to = 0i64;

        for tier in &self.tiers {
            let tier_usage = if let Some(up_to) = tier.up_to {
                (up_to - previous_up_to).min(remaining)
            } else {
                remaining
            };

            if tier_usage <= 0 {
                break;
            }

            if let Some(flat) = tier.flat_amount {
                cost += flat;
            }
            cost += tier_usage * tier.unit_amount;

            remaining -= tier_usage;
            previous_up_to = tier.up_to.unwrap_or(previous_up_to);

            if remaining <= 0 {
                break;
            }
        }

        cost
    }
}

/// Billing period configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingPeriod {
    pub interval: BillingInterval,
    pub interval_count: i32,
    pub anchor_date: Option<DateTime<Utc>>,
}

/// Billing interval
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BillingInterval {
    Day,
    Week,
    Month,
    Year,
}

impl BillingPeriod {
    /// Create a monthly billing period
    pub fn monthly() -> Self {
        Self {
            interval: BillingInterval::Month,
            interval_count: 1,
            anchor_date: None,
        }
    }

    /// Create a yearly billing period
    pub fn yearly() -> Self {
        Self {
            interval: BillingInterval::Year,
            interval_count: 1,
            anchor_date: None,
        }
    }

    /// Set interval count
    pub fn with_count(mut self, count: i32) -> Self {
        self.interval_count = count;
        self
    }

    /// Set anchor date
    pub fn with_anchor_date(mut self, date: DateTime<Utc>) -> Self {
        self.anchor_date = Some(date);
        self
    }

    /// Get duration for this period
    pub fn duration(&self) -> chrono::Duration {
        match self.interval {
            BillingInterval::Day => chrono::Duration::days(self.interval_count as i64),
            BillingInterval::Week => chrono::Duration::weeks(self.interval_count as i64),
            BillingInterval::Month => chrono::Duration::days(30 * self.interval_count as i64), // Approximate
            BillingInterval::Year => chrono::Duration::days(365 * self.interval_count as i64), // Approximate
        }
    }

    /// Get next billing date from a given date
    pub fn next_billing_date(&self, from: DateTime<Utc>) -> DateTime<Utc> {
        match self.interval {
            BillingInterval::Day => from + chrono::Duration::days(self.interval_count as i64),
            BillingInterval::Week => from + chrono::Duration::weeks(self.interval_count as i64),
            BillingInterval::Month => {
                from + chrono::Duration::days(30 * self.interval_count as i64)
            } // Approximate
            BillingInterval::Year => {
                from + chrono::Duration::days(365 * self.interval_count as i64)
            } // Approximate
        }
    }
}

/// Format bytes to human readable
pub fn format_bytes(bytes: i64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let exp = (bytes as f64).log(1024.0).min(UNITS.len() as f64 - 1.0) as usize;
    let value = bytes as f64 / 1024f64.powi(exp as i32);
    
    if exp == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", value, UNITS[exp])
    }
}

/// Format number with commas
pub fn format_number(num: i64) -> String {
    num.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap()
        .join(",")
}
