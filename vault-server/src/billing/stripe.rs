//! Stripe billing service implementation (STUB)
//!
//! This is a stub implementation. The actual Stripe integration requires
//! the async-stripe crate which has compilation issues with the current
//! version. To enable Stripe billing:
//!
//! 1. Add to Cargo.toml:
//!    async-stripe = { version = "0.38", default-features = false,
//!                     features = ["runtime-tokio-hyper-rustls", "checkout", "billing", "webhook-events"] }
//!
//! 2. Uncomment the stripe feature in [features] section
//!
//! 3. Replace this stub with the full implementation from git history

use anyhow::Result;

use crate::billing::{
    BillingError, BillingPlan, CheckoutSession, Invoice, PaymentMethod, PortalSession,
    Subscription, WebhookResult,
};

/// Internal Stripe billing service (STUB)
pub struct StripeBillingService {
    _client: (), // Placeholder - would be stripe::Client
    _webhook_secret: Option<String>,
    db: crate::db::Database,
}

impl StripeBillingService {
    /// Create new Stripe billing service (STUB)
    pub fn new(
        _secret_key: String,
        webhook_secret: Option<String>,
        db: crate::db::Database,
    ) -> Result<Self> {
        tracing::warn!("Stripe billing service is a STUB - billing features are disabled");

        Ok(Self {
            _client: (),
            _webhook_secret: webhook_secret,
            db,
        })
    }

    /// Get or create Stripe customer for tenant (STUB)
    pub async fn get_or_create_customer(&self, _tenant_id: &str) -> Result<String, BillingError> {
        Err(BillingError::NotEnabled)
    }

    /// Get subscription for tenant (STUB)
    pub async fn get_subscription(
        &self,
        tenant_id: &str,
    ) -> Result<Option<Subscription>, BillingError> {
        // Check if we have a local subscription record
        let row = sqlx::query_as::<_, SubscriptionRow>(
            r#"SELECT s.id, s.tenant_id, s.stripe_customer_id, s.stripe_subscription_id,
                      s.stripe_price_id, s.status, s.current_period_start, s.current_period_end,
                      s.trial_start, s.trial_end, s.cancel_at, s.canceled_at, s.ended_at,
                      s.created_at, s.updated_at, p.id as plan_id, p.name as plan_name,
                      p.stripe_product_id, p.stripe_price_id as plan_price_id, p.tier,
                      p.price_cents, p.interval
               FROM subscriptions s
               LEFT JOIN billing_plans p ON p.stripe_price_id = s.stripe_price_id
               WHERE s.tenant_id = $1"#,
        )
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        Ok(row.map(|r| r.into()))
    }

    /// Create checkout session for subscription (STUB)
    pub async fn create_checkout_session(
        &self,
        _tenant_id: &str,
        _price_id: &str,
        _success_url: &str,
        _cancel_url: &str,
    ) -> Result<CheckoutSession, BillingError> {
        Err(BillingError::NotEnabled)
    }

    /// Create customer portal session (STUB)
    pub async fn create_portal_session(
        &self,
        _tenant_id: &str,
        _return_url: &str,
    ) -> Result<PortalSession, BillingError> {
        Err(BillingError::NotEnabled)
    }

    /// Handle Stripe webhook (STUB)
    pub async fn handle_webhook(
        &self,
        _payload: &str,
        _signature: &str,
    ) -> Result<WebhookResult, BillingError> {
        Err(BillingError::NotEnabled)
    }

    /// List available plans (STUB - returns from DB)
    pub async fn list_plans(&self) -> Result<Vec<BillingPlan>, BillingError> {
        let rows = sqlx::query_as::<_, BillingPlanRow>(
            r#"SELECT id, stripe_product_id, stripe_price_id, name, description, tier,
                      price_cents, interval, features, is_active, created_at, updated_at
               FROM billing_plans
               WHERE is_active = TRUE
               ORDER BY price_cents ASC"#,
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Get invoices for tenant (STUB)
    pub async fn list_invoices(&self, tenant_id: &str) -> Result<Vec<Invoice>, BillingError> {
        let rows = sqlx::query_as::<_, InvoiceRow>(
            r#"SELECT id, tenant_id, stripe_invoice_id, status, total_cents, subtotal_cents,
                      tax_cents, currency, invoice_pdf_url, hosted_invoice_url,
                      period_start, period_end, paid_at, created_at
               FROM invoices
               WHERE tenant_id = $1
               ORDER BY created_at DESC"#,
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// List invoices across all tenants
    pub async fn list_all_invoices(&self) -> Result<Vec<Invoice>, BillingError> {
        let rows = sqlx::query_as::<_, InvoiceRow>(
            r#"SELECT id, tenant_id, stripe_invoice_id, status, total_cents, subtotal_cents,
                      tax_cents, currency, invoice_pdf_url, hosted_invoice_url,
                      period_start, period_end, paid_at, created_at
               FROM invoices
               ORDER BY created_at DESC"#,
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Cancel subscription at period end (STUB)
    pub async fn cancel_subscription(
        &self,
        _tenant_id: &str,
    ) -> Result<Subscription, BillingError> {
        Err(BillingError::NotEnabled)
    }

    /// Resume canceled subscription (STUB)
    pub async fn resume_subscription(
        &self,
        _tenant_id: &str,
    ) -> Result<Subscription, BillingError> {
        Err(BillingError::NotEnabled)
    }

    /// Update subscription to new plan (STUB)
    pub async fn update_subscription_plan(
        &self,
        _tenant_id: &str,
        _new_price_id: &str,
    ) -> Result<Subscription, BillingError> {
        Err(BillingError::NotEnabled)
    }

    /// Record usage for metered billing (STUB)
    pub async fn record_usage(&self, _tenant_id: &str, _quantity: i64) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("Stripe billing not enabled"))
    }
}

// === Database Row Types ===

use crate::billing::{BillingInterval, InvoiceStatus, PlanTier, SubscriptionStatus};
use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(sqlx::FromRow)]
struct SubscriptionRow {
    id: String,
    tenant_id: String,
    stripe_customer_id: Option<String>,
    stripe_subscription_id: Option<String>,
    status: String,
    current_period_start: Option<DateTime<Utc>>,
    current_period_end: Option<DateTime<Utc>>,
    trial_start: Option<DateTime<Utc>>,
    trial_end: Option<DateTime<Utc>>,
    cancel_at: Option<DateTime<Utc>>,
    canceled_at: Option<DateTime<Utc>>,
    ended_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    plan_id: Option<String>,
    plan_name: Option<String>,
    stripe_product_id: Option<String>,
    plan_price_id: Option<String>,
    tier: Option<String>,
    price_cents: Option<i32>,
    interval: Option<String>,
}

impl From<SubscriptionRow> for Subscription {
    fn from(row: SubscriptionRow) -> Self {
        let plan = if row.plan_id.is_some() {
            Some(BillingPlan {
                id: row.plan_id.unwrap_or_default(),
                stripe_product_id: row.stripe_product_id.unwrap_or_default(),
                stripe_price_id: row.plan_price_id.unwrap_or_default(),
                name: row.plan_name.unwrap_or_default(),
                description: None,
                tier: row
                    .tier
                    .as_deref()
                    .map(|t| match t {
                        "free" => PlanTier::Free,
                        "starter" => PlanTier::Starter,
                        "pro" => PlanTier::Pro,
                        _ => PlanTier::Enterprise,
                    })
                    .unwrap_or(PlanTier::Free),
                price_cents: row.price_cents.unwrap_or(0),
                interval: row
                    .interval
                    .as_deref()
                    .map(|i| match i {
                        "year" => BillingInterval::Year,
                        _ => BillingInterval::Month,
                    })
                    .unwrap_or(BillingInterval::Month),
                features: vec![],
                is_active: true,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
        } else {
            None
        };

        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            stripe_customer_id: row.stripe_customer_id,
            stripe_subscription_id: row.stripe_subscription_id,
            plan,
            status: match row.status.as_str() {
                "incomplete" => SubscriptionStatus::Incomplete,
                "incomplete_expired" => SubscriptionStatus::IncompleteExpired,
                "trialing" => SubscriptionStatus::Trialing,
                "active" => SubscriptionStatus::Active,
                "past_due" => SubscriptionStatus::PastDue,
                "canceled" => SubscriptionStatus::Canceled,
                "unpaid" => SubscriptionStatus::Unpaid,
                "paused" => SubscriptionStatus::Paused,
                _ => SubscriptionStatus::Incomplete,
            },
            current_period_start: row.current_period_start,
            current_period_end: row.current_period_end,
            trial_start: row.trial_start,
            trial_end: row.trial_end,
            cancel_at: row.cancel_at,
            canceled_at: row.canceled_at,
            ended_at: row.ended_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct BillingPlanRow {
    id: String,
    stripe_product_id: String,
    stripe_price_id: String,
    name: String,
    description: Option<String>,
    tier: String,
    price_cents: i32,
    interval: String,
    features: Value,
    is_active: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<BillingPlanRow> for BillingPlan {
    fn from(row: BillingPlanRow) -> Self {
        Self {
            id: row.id,
            stripe_product_id: row.stripe_product_id,
            stripe_price_id: row.stripe_price_id,
            name: row.name,
            description: row.description,
            tier: match row.tier.as_str() {
                "free" => PlanTier::Free,
                "starter" => PlanTier::Starter,
                "pro" => PlanTier::Pro,
                _ => PlanTier::Enterprise,
            },
            price_cents: row.price_cents,
            interval: match row.interval.as_str() {
                "year" => BillingInterval::Year,
                _ => BillingInterval::Month,
            },
            features: serde_json::from_value(row.features).unwrap_or_default(),
            is_active: row.is_active,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct InvoiceRow {
    id: String,
    tenant_id: String,
    stripe_invoice_id: String,
    status: String,
    total_cents: i32,
    subtotal_cents: i32,
    tax_cents: i32,
    currency: String,
    invoice_pdf_url: Option<String>,
    hosted_invoice_url: Option<String>,
    period_start: Option<DateTime<Utc>>,
    period_end: Option<DateTime<Utc>>,
    paid_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<InvoiceRow> for Invoice {
    fn from(row: InvoiceRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            stripe_invoice_id: row.stripe_invoice_id,
            status: match row.status.as_str() {
                "draft" => InvoiceStatus::Draft,
                "open" => InvoiceStatus::Open,
                "paid" => InvoiceStatus::Paid,
                "uncollectible" => InvoiceStatus::Uncollectible,
                "void" => InvoiceStatus::Void,
                _ => InvoiceStatus::Draft,
            },
            total_cents: row.total_cents,
            subtotal_cents: row.subtotal_cents,
            tax_cents: row.tax_cents,
            currency: row.currency,
            invoice_pdf_url: row.invoice_pdf_url,
            hosted_invoice_url: row.hosted_invoice_url,
            period_start: row.period_start,
            period_end: row.period_end,
            paid_at: row.paid_at,
            created_at: row.created_at,
        }
    }
}
