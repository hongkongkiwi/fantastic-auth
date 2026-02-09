//! Billing types and models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Billing plan definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingPlan {
    pub id: String,
    pub stripe_product_id: String,
    pub stripe_price_id: String,
    pub name: String,
    pub description: Option<String>,
    pub tier: PlanTier,
    pub price_cents: i32,
    pub interval: BillingInterval,
    pub features: Vec<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Plan tier levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlanTier {
    Free,
    Starter,
    Pro,
    Enterprise,
}

impl std::fmt::Display for PlanTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanTier::Free => write!(f, "free"),
            PlanTier::Starter => write!(f, "starter"),
            PlanTier::Pro => write!(f, "pro"),
            PlanTier::Enterprise => write!(f, "enterprise"),
        }
    }
}

/// Billing interval
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BillingInterval {
    Month,
    Year,
}

impl std::fmt::Display for BillingInterval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BillingInterval::Month => write!(f, "month"),
            BillingInterval::Year => write!(f, "year"),
        }
    }
}

/// Subscription status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Incomplete,
    IncompleteExpired,
    Trialing,
    Active,
    PastDue,
    Canceled,
    Unpaid,
    Paused,
}

impl std::fmt::Display for SubscriptionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionStatus::Incomplete => write!(f, "incomplete"),
            SubscriptionStatus::IncompleteExpired => write!(f, "incomplete_expired"),
            SubscriptionStatus::Trialing => write!(f, "trialing"),
            SubscriptionStatus::Active => write!(f, "active"),
            SubscriptionStatus::PastDue => write!(f, "past_due"),
            SubscriptionStatus::Canceled => write!(f, "canceled"),
            SubscriptionStatus::Unpaid => write!(f, "unpaid"),
            SubscriptionStatus::Paused => write!(f, "paused"),
        }
    }
}

/// Tenant subscription
#[derive(Debug, Clone, Serialize)]
pub struct Subscription {
    pub id: String,
    pub tenant_id: String,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub plan: Option<BillingPlan>,
    pub status: SubscriptionStatus,
    pub current_period_start: Option<DateTime<Utc>>,
    pub current_period_end: Option<DateTime<Utc>>,
    pub trial_start: Option<DateTime<Utc>>,
    pub trial_end: Option<DateTime<Utc>>,
    pub cancel_at: Option<DateTime<Utc>>,
    pub canceled_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Payment method
#[derive(Debug, Clone, Serialize)]
pub struct PaymentMethod {
    pub id: String,
    pub tenant_id: String,
    pub type_: String,
    pub is_default: bool,
    pub card_brand: Option<String>,
    pub card_last4: Option<String>,
    pub card_exp_month: Option<i32>,
    pub card_exp_year: Option<i32>,
    pub billing_email: Option<String>,
    pub billing_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Invoice record
#[derive(Debug, Clone, Serialize)]
pub struct Invoice {
    pub id: String,
    pub tenant_id: String,
    pub stripe_invoice_id: String,
    pub status: InvoiceStatus,
    pub total_cents: i32,
    pub subtotal_cents: i32,
    pub tax_cents: i32,
    pub currency: String,
    pub invoice_pdf_url: Option<String>,
    pub hosted_invoice_url: Option<String>,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
    pub paid_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Invoice status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    Draft,
    Open,
    Paid,
    Uncollectible,
    Void,
}

impl std::fmt::Display for InvoiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvoiceStatus::Draft => write!(f, "draft"),
            InvoiceStatus::Open => write!(f, "open"),
            InvoiceStatus::Paid => write!(f, "paid"),
            InvoiceStatus::Uncollectible => write!(f, "uncollectible"),
            InvoiceStatus::Void => write!(f, "void"),
        }
    }
}

/// Request to create checkout session
#[derive(Debug, Deserialize)]
pub struct CreateCheckoutRequest {
    pub price_id: String,
    pub success_url: String,
    pub cancel_url: String,
}

/// Request to update subscription
#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionRequest {
    pub new_price_id: String,
}

/// Billing summary for tenant
#[derive(Debug, Serialize)]
pub struct BillingSummary {
    pub subscription: Option<Subscription>,
    pub payment_methods: Vec<PaymentMethod>,
    pub recent_invoices: Vec<Invoice>,
    pub usage_this_period: Option<UsageSummary>,
}

/// Usage summary
#[derive(Debug, Serialize)]
pub struct UsageSummary {
    pub quantity: i64,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
}

/// Usage record for metered billing
#[derive(Debug, Clone)]
pub struct UsageRecord {
    pub id: String,
    pub tenant_id: String,
    pub stripe_subscription_item_id: String,
    pub quantity: i32,
    pub timestamp: DateTime<Utc>,
    pub action: UsageAction,
    pub created_at: DateTime<Utc>,
}

/// Usage record action type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsageAction {
    Increment,
    Set,
}

/// Billing event log entry
#[derive(Debug, Clone, Serialize)]
pub struct BillingEvent {
    pub id: String,
    pub tenant_id: String,
    pub event_type: String,
    pub stripe_event_id: Option<String>,
    pub data: Value,
    pub created_at: DateTime<Utc>,
}

/// Response for subscription creation
#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    pub subscription: Subscription,
    pub checkout_url: Option<String>,
}

/// Response for customer portal
#[derive(Debug, Serialize)]
pub struct PortalResponse {
    pub url: String,
}

/// Checkout session for Stripe
#[derive(Debug, Clone, Serialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: String,
    pub status: String,
    pub customer_id: Option<String>,
    pub subscription_id: Option<String>,
}

/// Customer portal session
#[derive(Debug, Clone, Serialize)]
pub struct PortalSession {
    pub id: String,
    pub url: String,
    pub customer_id: String,
}

/// Request to setup usage-based billing
#[derive(Debug, Deserialize)]
pub struct SetupMeteredBillingRequest {
    pub stripe_price_id: String,
}
