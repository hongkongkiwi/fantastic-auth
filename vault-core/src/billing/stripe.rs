//! Stripe integration types and utilities
//!
//! This module provides types and utilities for Stripe integration.
//! The actual API client implementation is in vault-server.

use serde::{Deserialize, Serialize};

/// Stripe webhook event types that we handle
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StripeEventType {
    CheckoutSessionCompleted,
    CheckoutSessionExpired,
    InvoicePaid,
    InvoicePaymentFailed,
    InvoiceFinalized,
    CustomerSubscriptionCreated,
    CustomerSubscriptionUpdated,
    CustomerSubscriptionDeleted,
    CustomerSubscriptionTrialWillEnd,
    PaymentIntentSucceeded,
    PaymentIntentPaymentFailed,
    CustomerCreated,
    CustomerUpdated,
    CustomerDeleted,
    ChargeSucceeded,
    ChargeFailed,
    ChargeRefunded,
    #[serde(other)]
    Unknown,
}

impl std::fmt::Display for StripeEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StripeEventType::CheckoutSessionCompleted => write!(f, "checkout.session.completed"),
            StripeEventType::CheckoutSessionExpired => write!(f, "checkout.session.expired"),
            StripeEventType::InvoicePaid => write!(f, "invoice.paid"),
            StripeEventType::InvoicePaymentFailed => write!(f, "invoice.payment_failed"),
            StripeEventType::InvoiceFinalized => write!(f, "invoice.finalized"),
            StripeEventType::CustomerSubscriptionCreated => write!(f, "customer.subscription.created"),
            StripeEventType::CustomerSubscriptionUpdated => write!(f, "customer.subscription.updated"),
            StripeEventType::CustomerSubscriptionDeleted => write!(f, "customer.subscription.deleted"),
            StripeEventType::CustomerSubscriptionTrialWillEnd => write!(f, "customer.subscription.trial_will_end"),
            StripeEventType::PaymentIntentSucceeded => write!(f, "payment_intent.succeeded"),
            StripeEventType::PaymentIntentPaymentFailed => write!(f, "payment_intent.payment_failed"),
            StripeEventType::CustomerCreated => write!(f, "customer.created"),
            StripeEventType::CustomerUpdated => write!(f, "customer.updated"),
            StripeEventType::CustomerDeleted => write!(f, "customer.deleted"),
            StripeEventType::ChargeSucceeded => write!(f, "charge.succeeded"),
            StripeEventType::ChargeFailed => write!(f, "charge.failed"),
            StripeEventType::ChargeRefunded => write!(f, "charge.refunded"),
            StripeEventType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Stripe webhook event payload structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeWebhookPayload {
    pub id: String,
    pub object: String,
    #[serde(rename = "type")]
    pub event_type: StripeEventType,
    pub api_version: Option<String>,
    pub created: i64,
    pub livemode: bool,
    pub pending_webhooks: i32,
    pub request: Option<StripeRequest>,
    pub data: StripeEventData,
}

/// Stripe request info in webhook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeRequest {
    pub id: Option<String>,
    pub idempotency_key: Option<String>,
}

/// Stripe event data wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeEventData {
    pub object: serde_json::Value,
    #[serde(rename = "previous_attributes")]
    pub previous_attributes: Option<serde_json::Value>,
}

/// Stripe customer object (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeCustomer {
    pub id: String,
    pub object: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub phone: Option<String>,
    pub address: Option<StripeAddress>,
    pub created: i64,
    pub metadata: serde_json::Value,
}

/// Stripe address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeAddress {
    pub line1: Option<String>,
    pub line2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

/// Stripe subscription object (simplified)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSubscription {
    pub id: String,
    pub object: String,
    pub customer: String,
    pub status: String,
    pub current_period_start: i64,
    pub current_period_end: i64,
    pub items: StripeList<StripeSubscriptionItem>,
    pub trial_start: Option<i64>,
    pub trial_end: Option<i64>,
    pub cancel_at: Option<i64>,
    pub canceled_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub cancel_at_period_end: bool,
    pub created: i64,
    pub metadata: serde_json::Value,
}

/// Stripe list wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeList<T> {
    pub object: String,
    pub data: Vec<T>,
    pub has_more: bool,
    pub url: String,
}

/// Stripe subscription item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeSubscriptionItem {
    pub id: String,
    pub object: String,
    pub price: StripePrice,
    pub quantity: i32,
    pub subscription: String,
}

/// Stripe price object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripePrice {
    pub id: String,
    pub object: String,
    pub product: String,
    pub unit_amount: i64,
    pub currency: String,
    #[serde(rename = "type")]
    pub price_type: String,
    pub recurring: Option<StripeRecurring>,
}

/// Stripe recurring info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeRecurring {
    pub aggregate_usage: Option<String>,
    pub interval: String,
    pub interval_count: i32,
    pub trial_period_days: Option<i32>,
    pub usage_type: String,
}

/// Stripe checkout session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeCheckoutSession {
    pub id: String,
    pub object: String,
    pub customer: Option<String>,
    pub subscription: Option<String>,
    pub status: Option<String>,
    pub url: Option<String>,
    pub success_url: Option<String>,
    pub cancel_url: Option<String>,
    pub mode: String,
    pub line_items: Option<StripeList<StripeLineItem>>,
    pub metadata: serde_json::Value,
    pub client_reference_id: Option<String>,
    pub customer_email: Option<String>,
}

/// Stripe line item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeLineItem {
    pub id: String,
    pub object: String,
    pub price: Option<StripePrice>,
    pub quantity: i32,
}

/// Stripe invoice object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeInvoice {
    pub id: String,
    pub object: String,
    pub customer: String,
    pub subscription: Option<String>,
    pub status: String,
    pub total: i64,
    pub subtotal: i64,
    pub tax: Option<i64>,
    pub currency: String,
    pub invoice_pdf: Option<String>,
    pub hosted_invoice_url: Option<String>,
    pub period_start: i64,
    pub period_end: i64,
    pub paid: bool,
    pub created: i64,
}

/// Stripe payment intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripePaymentIntent {
    pub id: String,
    pub object: String,
    pub customer: Option<String>,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub invoice: Option<String>,
    pub subscription: Option<String>,
    pub metadata: serde_json::Value,
}

/// Stripe charge object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeCharge {
    pub id: String,
    pub object: String,
    pub customer: Option<String>,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub refunded: bool,
    pub receipt_url: Option<String>,
}

/// Stripe payment method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripePaymentMethod {
    pub id: String,
    pub object: String,
    pub customer: Option<String>,
    #[serde(rename = "type")]
    pub pm_type: String,
    pub card: Option<StripeCard>,
    pub billing_details: StripeBillingDetails,
}

/// Stripe card info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeCard {
    pub brand: String,
    pub last4: String,
    pub exp_month: i32,
    pub exp_year: i32,
}

/// Stripe billing details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeBillingDetails {
    pub email: Option<String>,
    pub name: Option<String>,
    pub phone: Option<String>,
    pub address: Option<StripeAddress>,
}

/// Utility functions for Stripe
pub mod utils {
    use super::*;

    /// Convert Stripe timestamp to DateTime
    pub fn timestamp_to_datetime(timestamp: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(timestamp, 0)
            .unwrap_or_else(|| chrono::Utc::now())
    }

    /// Convert DateTime to Stripe timestamp
    pub fn datetime_to_timestamp(dt: chrono::DateTime<chrono::Utc>) -> i64 {
        dt.timestamp()
    }

    /// Parse webhook payload
    pub fn parse_webhook_payload(payload: &str) -> Result<StripeWebhookPayload, serde_json::Error> {
        serde_json::from_str(payload)
    }

    /// Extract customer ID from metadata or customer field
    pub fn extract_tenant_id(metadata: &serde_json::Value) -> Option<String> {
        metadata
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

pub use utils::*;
