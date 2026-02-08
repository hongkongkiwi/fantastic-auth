//! Billing and subscription management
//!
//! Optional Stripe integration for subscription billing.
//! If Stripe API key is not configured, billing features are disabled.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

mod stripe;
mod types;
pub mod webhooks;

pub use stripe::*;
pub use types::*;
pub use webhooks::*;

/// Billing configuration
#[derive(Debug, Clone)]
pub struct BillingConfig {
    pub enabled: bool,
    pub stripe_secret_key: Option<String>,
    pub stripe_webhook_secret: Option<String>,
    pub default_plan_id: Option<String>,
    pub trial_days: i64,
}

impl BillingConfig {
    /// Create billing config from environment variables
    pub fn from_env() -> Self {
        let stripe_secret_key = std::env::var("STRIPE_SECRET_KEY").ok();
        let stripe_webhook_secret = std::env::var("STRIPE_WEBHOOK_SECRET").ok();

        let enabled = stripe_secret_key.is_some();

        let trial_days = std::env::var("BILLING_TRIAL_DAYS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(14);

        let default_plan_id = std::env::var("BILLING_DEFAULT_PLAN_ID").ok();

        if enabled {
            tracing::info!("Stripe billing integration enabled");
        } else {
            tracing::info!("Stripe billing integration disabled - set STRIPE_SECRET_KEY to enable");
        }

        Self {
            enabled,
            stripe_secret_key,
            stripe_webhook_secret,
            default_plan_id,
            trial_days,
        }
    }
}

/// Billing service - wraps Stripe client with optional disabling
#[derive(Clone)]
pub struct BillingService {
    inner: Option<Arc<StripeBillingService>>,
    config: BillingConfig,
}

impl BillingService {
    /// Create new billing service (may be disabled)
    pub fn new(config: BillingConfig, db: crate::db::Database) -> Self {
        let inner = if config.enabled {
            match StripeBillingService::new(
                config.stripe_secret_key.clone().unwrap(),
                config.stripe_webhook_secret.clone(),
                db,
            ) {
                Ok(service) => {
                    tracing::info!("Stripe billing service initialized");
                    Some(Arc::new(service))
                }
                Err(e) => {
                    tracing::error!("Failed to initialize Stripe billing: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Self { inner, config }
    }

    /// Check if billing is enabled
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Get subscription for tenant
    pub async fn get_subscription(&self, tenant_id: &str) -> Result<Option<Subscription>> {
        match &self.inner {
            Some(service) => service
                .get_subscription(tenant_id)
                .await
                .map_err(|e| anyhow::anyhow!(e)),
            None => Ok(None),
        }
    }

    /// Create checkout session for subscription
    pub async fn create_checkout_session(
        &self,
        tenant_id: &str,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<Option<CheckoutSession>> {
        match &self.inner {
            Some(service) => {
                let session = service
                    .create_checkout_session(tenant_id, price_id, success_url, cancel_url)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Create customer portal session
    pub async fn create_portal_session(
        &self,
        tenant_id: &str,
        return_url: &str,
    ) -> Result<Option<PortalSession>> {
        match &self.inner {
            Some(service) => {
                let session = service
                    .create_portal_session(tenant_id, return_url)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Handle Stripe webhook
    pub async fn handle_webhook(
        &self,
        payload: &str,
        signature: &str,
    ) -> Result<Option<WebhookResult>> {
        match &self.inner {
            Some(service) => {
                let result = service
                    .handle_webhook(payload, signature)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// List available plans
    pub async fn list_plans(&self) -> Result<Vec<BillingPlan>> {
        match &self.inner {
            Some(service) => service.list_plans().await.map_err(|e| anyhow::anyhow!(e)),
            None => Ok(vec![]),
        }
    }

    /// Get invoices for tenant
    pub async fn list_invoices(&self, tenant_id: &str) -> Result<Vec<Invoice>> {
        match &self.inner {
            Some(service) => service
                .list_invoices(tenant_id)
                .await
                .map_err(|e| anyhow::anyhow!(e)),
            None => Ok(vec![]),
        }
    }

    /// Cancel subscription at period end
    pub async fn cancel_subscription(&self, tenant_id: &str) -> Result<Option<Subscription>> {
        match &self.inner {
            Some(service) => {
                let sub = service.cancel_subscription(tenant_id).await?;
                Ok(Some(sub))
            }
            None => Ok(None),
        }
    }

    /// Resume canceled subscription
    pub async fn resume_subscription(&self, tenant_id: &str) -> Result<Option<Subscription>> {
        match &self.inner {
            Some(service) => {
                let sub = service.resume_subscription(tenant_id).await?;
                Ok(Some(sub))
            }
            None => Ok(None),
        }
    }

    /// Update subscription to new plan
    pub async fn update_subscription_plan(
        &self,
        tenant_id: &str,
        new_price_id: &str,
    ) -> Result<Option<Subscription>> {
        match &self.inner {
            Some(service) => {
                let sub = service
                    .update_subscription_plan(tenant_id, new_price_id)
                    .await?;
                Ok(Some(sub))
            }
            None => Ok(None),
        }
    }

    /// Record usage for metered billing
    pub async fn record_usage(&self, tenant_id: &str, quantity: i64) -> Result<()> {
        match &self.inner {
            Some(service) => service
                .record_usage(tenant_id, quantity)
                .await
                .map_err(|e| anyhow::anyhow!(e)),
            None => Ok(()),
        }
    }
}

/// Result of webhook processing
#[derive(Debug, Clone)]
pub struct WebhookResult {
    pub event_type: String,
    pub tenant_id: Option<String>,
    pub processed: bool,
}

/// Checkout session for Stripe
#[derive(Debug, Clone, Serialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: String,
    pub customer_id: Option<String>,
    pub subscription_id: Option<String>,
}

/// Customer portal session
#[derive(Debug, Clone, Serialize)]
pub struct PortalSession {
    pub url: String,
}

/// Billing error types
#[derive(Debug, thiserror::Error)]
pub enum BillingError {
    #[error("Billing is not enabled")]
    NotEnabled,

    #[error("Stripe error: {0}")]
    StripeError(String),

    #[error("Customer not found")]
    CustomerNotFound,

    #[error("Subscription not found")]
    SubscriptionNotFound,

    #[error("Plan not found")]
    PlanNotFound,

    #[error("Invalid webhook signature")]
    InvalidWebhookSignature,

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
}

// Note: When stripe integration is enabled, add:
// impl From<stripe::StripeError> for BillingError {
//     fn from(err: stripe::StripeError) -> Self {
//         BillingError::StripeError(err.to_string())
//     }
// }
