//! Billing and subscription management for Vault Core
//!
//! This module provides core types and traits for billing functionality.
//! The actual Stripe integration is implemented in vault-server.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Billing plan definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub name: String,
    pub description: String,
    pub stripe_price_id: String,
    pub amount: i64,
    pub currency: String,
    pub interval: String,
    pub features: Vec<String>,
    pub metadata: serde_json::Value,
}

impl Plan {
    /// Create a new billing plan
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        stripe_price_id: impl Into<String>,
        amount: i64,
        interval: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            stripe_price_id: stripe_price_id.into(),
            amount,
            currency: "usd".to_string(),
            interval: interval.into(),
            features: Vec::new(),
            metadata: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    /// Set description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set currency
    pub fn with_currency(mut self, currency: impl Into<String>) -> Self {
        self.currency = currency.into();
        self
    }

    /// Add a feature
    pub fn with_feature(mut self, feature: impl Into<String>) -> Self {
        self.features.push(feature.into());
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
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

impl fmt::Display for SubscriptionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl std::str::FromStr for SubscriptionStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "incomplete" => Ok(SubscriptionStatus::Incomplete),
            "incomplete_expired" => Ok(SubscriptionStatus::IncompleteExpired),
            "trialing" => Ok(SubscriptionStatus::Trialing),
            "active" => Ok(SubscriptionStatus::Active),
            "past_due" => Ok(SubscriptionStatus::PastDue),
            "canceled" => Ok(SubscriptionStatus::Canceled),
            "unpaid" => Ok(SubscriptionStatus::Unpaid),
            "paused" => Ok(SubscriptionStatus::Paused),
            _ => Err(format!("Unknown subscription status: {}", s)),
        }
    }
}

/// Tenant subscription
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub tenant_id: String,
    pub stripe_subscription_id: String,
    pub stripe_customer_id: String,
    pub status: SubscriptionStatus,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub plan_id: String,
    pub quantity: i32,
    pub cancel_at_period_end: bool,
    pub trial_start: Option<DateTime<Utc>>,
    pub trial_end: Option<DateTime<Utc>>,
    pub canceled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Usage record for metered billing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    pub id: String,
    pub tenant_id: String,
    pub subscription_item_id: String,
    pub quantity: i64,
    pub timestamp: DateTime<Utc>,
    pub action: String,
}

/// Customer billing information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Customer {
    pub id: String,
    pub tenant_id: String,
    pub stripe_customer_id: String,
    pub email: String,
    pub name: Option<String>,
    pub phone: Option<String>,
    pub address: Option<Address>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Billing address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    pub line1: Option<String>,
    pub line2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

/// Invoice record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub id: String,
    pub tenant_id: String,
    pub stripe_invoice_id: String,
    pub subscription_id: Option<String>,
    pub status: InvoiceStatus,
    pub total: i64,
    pub subtotal: i64,
    pub tax: i64,
    pub currency: String,
    pub invoice_pdf: Option<String>,
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

impl fmt::Display for InvoiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvoiceStatus::Draft => write!(f, "draft"),
            InvoiceStatus::Open => write!(f, "open"),
            InvoiceStatus::Paid => write!(f, "paid"),
            InvoiceStatus::Uncollectible => write!(f, "uncollectible"),
            InvoiceStatus::Void => write!(f, "void"),
        }
    }
}

/// Checkout session for Stripe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: String,
    pub customer_id: Option<String>,
    pub subscription_id: Option<String>,
    pub price_id: String,
    pub mode: CheckoutMode,
}

/// Checkout session mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckoutMode {
    Payment,
    Setup,
    Subscription,
}

/// Customer portal session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalSession {
    pub url: String,
}

/// Payment method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentMethod {
    pub id: String,
    pub tenant_id: String,
    pub stripe_payment_method_id: String,
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

    #[error("Checkout session expired")]
    CheckoutExpired,

    #[error("Payment failed: {0}")]
    PaymentFailed(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Trait for billing storage operations
#[async_trait::async_trait]
pub trait BillingStore: Send + Sync {
    /// Get a plan by ID
    async fn get_plan(&self, plan_id: &str) -> Result<Option<Plan>, BillingError>;

    /// List all active plans
    async fn list_plans(&self) -> Result<Vec<Plan>, BillingError>;

    /// Get subscription for tenant
    async fn get_subscription(&self, tenant_id: &str)
        -> Result<Option<Subscription>, BillingError>;

    /// Create or update subscription
    async fn upsert_subscription(&self, subscription: &Subscription) -> Result<(), BillingError>;

    /// Get customer for tenant
    async fn get_customer(&self, tenant_id: &str) -> Result<Option<Customer>, BillingError>;

    /// Create or update customer
    async fn upsert_customer(&self, customer: &Customer) -> Result<(), BillingError>;

    /// Record usage
    async fn record_usage(&self, record: &UsageRecord) -> Result<(), BillingError>;

    /// List invoices for tenant
    async fn list_invoices(&self, tenant_id: &str) -> Result<Vec<Invoice>, BillingError>;

    /// Create or update invoice
    async fn upsert_invoice(&self, invoice: &Invoice) -> Result<(), BillingError>;
}

/// Billing service trait - to be implemented by vault-server
#[async_trait::async_trait]
pub trait BillingService: Send + Sync {
    /// Create a new customer
    async fn create_customer(
        &self,
        tenant_id: &str,
        email: &str,
        name: Option<&str>,
    ) -> Result<String, BillingError>;

    /// Create a checkout session for subscription
    async fn create_checkout_session(
        &self,
        tenant_id: &str,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<CheckoutSession, BillingError>;

    /// Create a customer portal session
    async fn create_portal_session(
        &self,
        tenant_id: &str,
        return_url: &str,
    ) -> Result<PortalSession, BillingError>;

    /// Get current subscription
    async fn get_subscription(&self, tenant_id: &str)
        -> Result<Option<Subscription>, BillingError>;

    /// Cancel subscription
    async fn cancel_subscription(&self, tenant_id: &str) -> Result<Subscription, BillingError>;

    /// Update subscription (upgrade/downgrade)
    async fn update_subscription(
        &self,
        tenant_id: &str,
        new_price_id: &str,
    ) -> Result<Subscription, BillingError>;

    /// Report usage for metered billing
    async fn report_usage(&self, tenant_id: &str, quantity: i64) -> Result<(), BillingError>;

    /// List available plans
    async fn list_plans(&self) -> Result<Vec<Plan>, BillingError>;

    /// List invoices for tenant
    async fn list_invoices(&self, tenant_id: &str) -> Result<Vec<Invoice>, BillingError>;

    /// Handle Stripe webhook
    async fn handle_webhook(
        &self,
        payload: &str,
        signature: &str,
    ) -> Result<WebhookEvent, BillingError>;
}

/// Webhook event result
#[derive(Debug, Clone)]
pub struct WebhookEvent {
    pub event_type: String,
    pub tenant_id: Option<String>,
    pub processed: bool,
    pub data: Option<serde_json::Value>,
}

/// Request to create checkout session
#[derive(Debug, Deserialize)]
pub struct CreateCheckoutRequest {
    pub price_id: String,
    pub success_url: String,
    pub cancel_url: String,
}

/// Request to create portal session
#[derive(Debug, Deserialize)]
pub struct CreatePortalRequest {
    pub return_url: String,
}

/// Request to update subscription
#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionRequest {
    pub new_price_id: String,
}

/// Request to report usage
#[derive(Debug, Deserialize)]
pub struct ReportUsageRequest {
    pub quantity: i64,
    pub action: Option<String>,
}

/// Response for subscription creation
#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    pub subscription: Subscription,
    pub checkout_url: Option<String>,
}

/// Response for portal session
#[derive(Debug, Serialize)]
pub struct PortalResponse {
    pub url: String,
}

/// Billing summary for tenant
#[derive(Debug, Serialize)]
pub struct BillingSummary {
    pub subscription: Option<Subscription>,
    pub invoices: Vec<Invoice>,
    pub payment_methods: Vec<PaymentMethod>,
    pub usage_this_period: Option<UsageSummary>,
}

/// Usage summary
#[derive(Debug, Serialize)]
pub struct UsageSummary {
    pub quantity: i64,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
}
