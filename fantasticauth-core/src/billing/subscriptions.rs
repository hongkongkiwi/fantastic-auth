//! Subscription management utilities
//!
//! This module provides utilities for working with subscriptions.

use chrono::{DateTime, Duration, Utc};

use super::{Plan, Subscription, SubscriptionStatus};

/// Check if a subscription is active (can access paid features)
pub fn is_subscription_active(subscription: &Subscription) -> bool {
    matches!(
        subscription.status,
        SubscriptionStatus::Active | SubscriptionStatus::Trialing
    )
}

/// Check if a subscription is in a grace period (past_due but not canceled)
pub fn is_subscription_in_grace_period(subscription: &Subscription) -> bool {
    subscription.status == SubscriptionStatus::PastDue
}

/// Check if a subscription is canceled (at period end or already ended)
pub fn is_subscription_canceled(subscription: &Subscription) -> bool {
    subscription.cancel_at_period_end
        || matches!(
            subscription.status,
            SubscriptionStatus::Canceled | SubscriptionStatus::Unpaid
        )
}

/// Check if subscription is in trial period
pub fn is_subscription_trialing(subscription: &Subscription) -> bool {
    subscription.status == SubscriptionStatus::Trialing
}

/// Get days until subscription renewal
pub fn days_until_renewal(subscription: &Subscription) -> i64 {
    let now = Utc::now();
    let end = subscription.current_period_end;
    
    if end > now {
        (end - now).num_days()
    } else {
        0
    }
}

/// Get days left in trial
pub fn days_left_in_trial(subscription: &Subscription) -> Option<i64> {
    if subscription.status != SubscriptionStatus::Trialing {
        return None;
    }
    
    subscription.trial_end.map(|end| {
        let now = Utc::now();
        if end > now {
            (end - now).num_days()
        } else {
            0
        }
    })
}

/// Check if subscription will renew automatically
pub fn will_subscription_renew(subscription: &Subscription) -> bool {
    matches!(
        subscription.status,
        SubscriptionStatus::Active | SubscriptionStatus::Trialing
    ) && !subscription.cancel_at_period_end
}

/// Calculate proration for plan change
pub fn calculate_proration(
    current_plan: &Plan,
    new_plan: &Plan,
    days_remaining: i64,
    billing_period_days: i64,
) -> i64 {
    // Simple proration: refund unused portion of current plan, charge for remaining days of new plan
    let current_daily_rate = current_plan.amount / billing_period_days;
    let new_daily_rate = new_plan.amount / billing_period_days;
    
    let refund_amount = current_daily_rate * days_remaining;
    let charge_amount = new_daily_rate * days_remaining;
    
    charge_amount - refund_amount
}

/// Subscription tier comparison
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SubscriptionTier {
    Free = 0,
    Starter = 1,
    Pro = 2,
    Enterprise = 3,
}

impl From<&str> for SubscriptionTier {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "free" => SubscriptionTier::Free,
            "starter" => SubscriptionTier::Starter,
            "pro" => SubscriptionTier::Pro,
            "enterprise" => SubscriptionTier::Enterprise,
            _ => SubscriptionTier::Free,
        }
    }
}

impl std::fmt::Display for SubscriptionTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionTier::Free => write!(f, "free"),
            SubscriptionTier::Starter => write!(f, "starter"),
            SubscriptionTier::Pro => write!(f, "pro"),
            SubscriptionTier::Enterprise => write!(f, "enterprise"),
        }
    }
}

/// Determine if a plan change is an upgrade
pub fn is_upgrade(current_tier: SubscriptionTier, new_tier: SubscriptionTier) -> bool {
    new_tier > current_tier
}

/// Determine if a plan change is a downgrade
pub fn is_downgrade(current_tier: SubscriptionTier, new_tier: SubscriptionTier) -> bool {
    new_tier < current_tier
}

/// Subscription limits and quotas
#[derive(Debug, Clone)]
pub struct SubscriptionLimits {
    pub max_users: Option<i32>,
    pub max_storage_gb: Option<i32>,
    pub max_api_calls_per_month: Option<i64>,
    pub max_projects: Option<i32>,
    pub features: Vec<String>,
}

impl SubscriptionLimits {
    /// Create limits for free tier
    pub fn free() -> Self {
        Self {
            max_users: Some(3),
            max_storage_gb: Some(1),
            max_api_calls_per_month: Some(1000),
            max_projects: Some(1),
            features: vec!["basic_auth".to_string()],
        }
    }

    /// Create limits for starter tier
    pub fn starter() -> Self {
        Self {
            max_users: Some(10),
            max_storage_gb: Some(10),
            max_api_calls_per_month: Some(10000),
            max_projects: Some(5),
            features: vec![
                "basic_auth".to_string(),
                "mfa".to_string(),
                "oauth".to_string(),
                "webhooks".to_string(),
            ],
        }
    }

    /// Create limits for pro tier
    pub fn pro() -> Self {
        Self {
            max_users: Some(100),
            max_storage_gb: Some(100),
            max_api_calls_per_month: Some(100000),
            max_projects: Some(50),
            features: vec![
                "basic_auth".to_string(),
                "mfa".to_string(),
                "oauth".to_string(),
                "webhooks".to_string(),
                "sso".to_string(),
                "audit_logs".to_string(),
                "custom_branding".to_string(),
            ],
        }
    }

    /// Create limits for enterprise tier
    pub fn enterprise() -> Self {
        Self {
            max_users: None, // Unlimited
            max_storage_gb: None, // Unlimited
            max_api_calls_per_month: None, // Unlimited
            max_projects: None, // Unlimited
            features: vec![
                "basic_auth".to_string(),
                "mfa".to_string(),
                "oauth".to_string(),
                "webhooks".to_string(),
                "sso".to_string(),
                "audit_logs".to_string(),
                "custom_branding".to_string(),
                "sla".to_string(),
                "dedicated_support".to_string(),
                "custom_contract".to_string(),
            ],
        }
    }

    /// Get limits for a tier
    pub fn for_tier(tier: SubscriptionTier) -> Self {
        match tier {
            SubscriptionTier::Free => Self::free(),
            SubscriptionTier::Starter => Self::starter(),
            SubscriptionTier::Pro => Self::pro(),
            SubscriptionTier::Enterprise => Self::enterprise(),
        }
    }

    /// Check if a feature is included
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    /// Check if user count is within limit
    pub fn is_user_count_allowed(&self, count: i32) -> bool {
        self.max_users.map_or(true, |max| count <= max)
    }

    /// Check if storage is within limit
    pub fn is_storage_allowed(&self, storage_gb: i32) -> bool {
        self.max_storage_gb.map_or(true, |max| storage_gb <= max)
    }
}

/// Builder for subscription limits
pub struct SubscriptionLimitsBuilder {
    limits: SubscriptionLimits,
}

impl SubscriptionLimitsBuilder {
    /// Create a new builder from an existing tier
    pub fn new(tier: SubscriptionTier) -> Self {
        Self {
            limits: SubscriptionLimits::for_tier(tier),
        }
    }

    /// Set max users
    pub fn max_users(mut self, max: Option<i32>) -> Self {
        self.limits.max_users = max;
        self
    }

    /// Set max storage
    pub fn max_storage_gb(mut self, max: Option<i32>) -> Self {
        self.limits.max_storage_gb = max;
        self
    }

    /// Set max API calls
    pub fn max_api_calls(mut self, max: Option<i64>) -> Self {
        self.limits.max_api_calls_per_month = max;
        self
    }

    /// Set max projects
    pub fn max_projects(mut self, max: Option<i32>) -> Self {
        self.limits.max_projects = max;
        self
    }

    /// Add a feature
    pub fn with_feature(mut self, feature: impl Into<String>) -> Self {
        let feature = feature.into();
        if !self.limits.features.contains(&feature) {
            self.limits.features.push(feature);
        }
        self
    }

    /// Remove a feature
    pub fn without_feature(mut self, feature: &str) -> Self {
        self.limits.features.retain(|f| f != feature);
        self
    }

    /// Build the limits
    pub fn build(self) -> SubscriptionLimits {
        self.limits
    }
}

/// Format price for display
pub fn format_price(amount: i64, currency: &str) -> String {
    let major_units = amount as f64 / 100.0;
    let symbol = match currency.to_uppercase().as_str() {
        "USD" => "$",
        "EUR" => "€",
        "GBP" => "£",
        "JPY" => "¥",
        _ => currency,
    };
    
    format!("{}{:.2}", symbol, major_units)
}

/// Format interval for display
pub fn format_interval(interval: &str, count: i32) -> String {
    match (interval, count) {
        ("month", 1) => "month".to_string(),
        ("month", n) => format!("{} months", n),
        ("year", 1) => "year".to_string(),
        ("year", n) => format!("{} years", n),
        ("week", 1) => "week".to_string(),
        ("week", n) => format!("{} weeks", n),
        ("day", 1) => "day".to_string(),
        ("day", n) => format!("{} days", n),
        _ => format!("{} {}", count, interval),
    }
}
