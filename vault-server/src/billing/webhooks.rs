//! Stripe Webhook Handler
//!
//! Handles incoming Stripe webhook events for billing integration.

use crate::billing::{
    BillingError, BillingPlan, CheckoutSession, Invoice, InvoiceStatus, PortalSession,
    Subscription, SubscriptionStatus,
};
use chrono::Utc;
use serde_json::Value;
use vault_core::billing::WebhookEvent;

/// Stripe webhook payload structure
#[derive(Debug, Clone, serde::Deserialize)]
pub struct WebhookPayload {
    pub id: String,
    pub object: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: EventData,
    pub created: i64,
    pub livemode: bool,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct EventData {
    pub object: Value,
    #[serde(rename = "previous_attributes")]
    pub previous_attributes: Option<Value>,
}

/// Stripe customer object
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StripeCustomer {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub metadata: Value,
}

/// Stripe subscription object
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StripeSubscription {
    pub id: String,
    pub customer: String,
    pub status: String,
    #[serde(rename = "current_period_start")]
    pub current_period_start: i64,
    #[serde(rename = "current_period_end")]
    pub current_period_end: i64,
    pub items: StripeList<StripeSubscriptionItem>,
    #[serde(rename = "cancel_at_period_end")]
    pub cancel_at_period_end: bool,
    #[serde(rename = "cancel_at")]
    pub cancel_at: Option<i64>,
    #[serde(rename = "trial_start")]
    pub trial_start: Option<i64>,
    #[serde(rename = "trial_end")]
    pub trial_end: Option<i64>,
    #[serde(rename = "canceled_at")]
    pub canceled_at: Option<i64>,
    pub metadata: Value,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StripeList<T> {
    pub data: Vec<T>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StripeSubscriptionItem {
    pub id: String,
    pub price: StripePrice,
    pub quantity: i32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StripePrice {
    pub id: String,
    pub product: String,
}

/// Stripe checkout session
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StripeCheckoutSession {
    pub id: String,
    pub customer: Option<String>,
    pub subscription: Option<String>,
    pub status: Option<String>,
    pub url: Option<String>,
    #[serde(rename = "client_reference_id")]
    pub client_reference_id: Option<String>,
    pub metadata: Value,
}

/// Stripe invoice
#[derive(Debug, Clone, serde::Deserialize)]
pub struct StripeInvoice {
    pub id: String,
    pub customer: String,
    pub subscription: Option<String>,
    pub status: String,
    pub total: i64,
    pub subtotal: i64,
    pub tax: Option<i64>,
    pub currency: String,
    #[serde(rename = "invoice_pdf")]
    pub invoice_pdf: Option<String>,
    #[serde(rename = "hosted_invoice_url")]
    pub hosted_invoice_url: Option<String>,
    #[serde(rename = "period_start")]
    pub period_start: i64,
    #[serde(rename = "period_end")]
    pub period_end: i64,
    pub paid: bool,
    pub created: i64,
}

/// Stripe charge
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StripeCharge {
    pub id: String,
    pub customer: Option<String>,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    pub refunded: bool,
}

/// Webhook handler trait
#[async_trait::async_trait]
pub trait WebhookHandler: Send + Sync {
    /// Verify webhook signature
    fn verify_signature(&self, payload: &str, signature: &str, secret: &str) -> Result<bool, BillingError>;
    
    /// Parse webhook payload
    fn parse_payload(&self, payload: &str) -> Result<WebhookPayload, BillingError>;
    
    /// Handle checkout.session.completed
    async fn handle_checkout_completed(&self, session: StripeCheckoutSession) -> Result<WebhookEvent, BillingError>;
    
    /// Handle customer.subscription.created
    async fn handle_subscription_created(&self, subscription: StripeSubscription) -> Result<WebhookEvent, BillingError>;
    
    /// Handle customer.subscription.updated
    async fn handle_subscription_updated(&self, subscription: StripeSubscription) -> Result<WebhookEvent, BillingError>;
    
    /// Handle customer.subscription.deleted
    async fn handle_subscription_deleted(&self, subscription: StripeSubscription) -> Result<WebhookEvent, BillingError>;
    
    /// Handle invoice.paid
    async fn handle_invoice_paid(&self, invoice: StripeInvoice) -> Result<WebhookEvent, BillingError>;
    
    /// Handle invoice.payment_failed
    async fn handle_invoice_payment_failed(&self, invoice: StripeInvoice) -> Result<WebhookEvent, BillingError>;
    
    /// Handle payment_intent.succeeded
    async fn handle_payment_intent_succeeded(&self, payment_intent: Value) -> Result<WebhookEvent, BillingError>;
    
    /// Handle payment_intent.payment_failed
    async fn handle_payment_intent_failed(&self, payment_intent: Value) -> Result<WebhookEvent, BillingError>;
    
    /// Handle charge.succeeded
    async fn handle_charge_succeeded(&self, charge: StripeCharge) -> Result<WebhookEvent, BillingError>;
    
    /// Handle charge.failed
    async fn handle_charge_failed(&self, charge: StripeCharge) -> Result<WebhookEvent, BillingError>;
    
    /// Handle charge.refunded
    async fn handle_charge_refunded(&self, charge: StripeCharge) -> Result<WebhookEvent, BillingError>;
}

/// Default webhook handler implementation
pub struct DefaultWebhookHandler {
    db: crate::db::Database,
}

impl DefaultWebhookHandler {
    pub fn new(db: crate::db::Database) -> Self {
        Self { db }
    }

    /// Extract tenant ID from metadata
    fn extract_tenant_id(&self, metadata: &Value) -> Option<String> {
        metadata.get("tenant_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    fn cancel_at_timestamp(&self, subscription: &StripeSubscription) -> Option<chrono::DateTime<chrono::Utc>> {
        let cancel_at = subscription
            .cancel_at
            .or_else(|| {
                if subscription.cancel_at_period_end {
                    Some(subscription.current_period_end)
                } else {
                    None
                }
            });
        cancel_at.and_then(|t| chrono::DateTime::from_timestamp(t, 0))
    }
}

#[async_trait::async_trait]
impl WebhookHandler for DefaultWebhookHandler {
    fn verify_signature(&self, payload: &str, signature: &str, secret: &str) -> Result<bool, BillingError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Parse signature header
        let parts: Vec<&str> = signature.split(',').collect();
        let mut timestamp = "";
        let mut signature_value = "";

        for part in parts {
            let kv: Vec<&str> = part.split('=').collect();
            if kv.len() == 2 {
                match kv[0].trim() {
                    "t" => timestamp = kv[1],
                    "v1" => signature_value = kv[1],
                    _ => {}
                }
            }
        }

        if timestamp.is_empty() || signature_value.is_empty() {
            return Err(BillingError::InvalidWebhookSignature);
        }

        // Construct signed payload
        let signed_payload = format!("{}.{}", timestamp, payload);

        // Compute HMAC
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|_| BillingError::InvalidWebhookSignature)?;
        mac.update(signed_payload.as_bytes());
        let result = mac.finalize();
        let expected_signature = hex::encode(result.into_bytes());

        // Compare signatures
        Ok(expected_signature == signature_value)
    }

    fn parse_payload(&self, payload: &str) -> Result<WebhookPayload, BillingError> {
        serde_json::from_str(payload)
            .map_err(|e| BillingError::StripeError(format!("Failed to parse webhook: {}", e)))
    }

    async fn handle_checkout_completed(&self, session: StripeCheckoutSession) -> Result<WebhookEvent, BillingError> {
        tracing::info!(
            checkout_session_id = %session.id,
            customer_id = ?session.customer,
            "Checkout session completed"
        );

        // Extract tenant ID from metadata or client_reference_id
        let tenant_id = self.extract_tenant_id(&session.metadata)
            .or(session.client_reference_id)
            .ok_or_else(|| BillingError::StripeError("No tenant ID in checkout session".to_string()))?;

        // Update subscription with Stripe customer ID if needed
        if let Some(customer_id) = &session.customer {
            sqlx::query(
                r#"UPDATE subscriptions 
                   SET stripe_customer_id = $1, 
                       status = 'active',
                       updated_at = NOW()
                   WHERE tenant_id = $2"#
            )
            .bind(customer_id)
            .bind(&tenant_id)
            .execute(self.db.pool())
            .await
            .map_err(|e| BillingError::DatabaseError(e))?;
        }

        Ok(WebhookEvent {
            event_type: "checkout.session.completed".to_string(),
            tenant_id: Some(tenant_id),
            processed: true,
            data: Some(serde_json::to_value(session).unwrap_or_default()),
        })
    }

    async fn handle_subscription_created(&self, subscription: StripeSubscription) -> Result<WebhookEvent, BillingError> {
        tracing::info!(
            subscription_id = %subscription.id,
            customer_id = %subscription.customer,
            status = %subscription.status,
            "Subscription created"
        );

        // Get tenant ID from metadata
        let tenant_id = self.extract_tenant_id(&subscription.metadata)
            .ok_or_else(|| BillingError::StripeError("No tenant ID in subscription".to_string()))?;

        // Get the price ID from the first subscription item
        let price_id = subscription.items.data
            .first()
            .map(|item| item.price.id.clone())
            .ok_or_else(|| BillingError::StripeError("No price in subscription".to_string()))?;

        // Insert or update subscription in database
        sqlx::query(
            r#"INSERT INTO subscriptions (
                tenant_id, stripe_customer_id, stripe_subscription_id, stripe_price_id,
                status, current_period_start, current_period_end, cancel_at,
                trial_start, trial_end, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
            ON CONFLICT (tenant_id) DO UPDATE SET
                stripe_subscription_id = $3,
                stripe_price_id = $4,
                status = $5,
                current_period_start = $6,
                current_period_end = $7,
                cancel_at = $8,
                trial_start = $9,
                trial_end = $10,
                updated_at = NOW()"#
        )
        .bind(&tenant_id)
        .bind(&subscription.customer)
        .bind(&subscription.id)
        .bind(&price_id)
        .bind(&subscription.status)
        .bind(chrono::DateTime::from_timestamp(subscription.current_period_start, 0))
        .bind(chrono::DateTime::from_timestamp(subscription.current_period_end, 0))
        .bind(self.cancel_at_timestamp(&subscription))
        .bind(subscription.trial_start.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(subscription.trial_end.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .execute(self.db.pool())
        .await
        .map_err(|e| BillingError::DatabaseError(e))?;

        // Log billing event
        sqlx::query(
            r#"INSERT INTO billing_events (tenant_id, event_type, stripe_event_id, data, created_at)
            VALUES ($1, $2, $3, $4, NOW())"#
        )
        .bind(&tenant_id)
        .bind("subscription.created")
        .bind(&subscription.id)
        .bind(serde_json::to_value(&subscription).unwrap_or_default())
        .execute(self.db.pool())
        .await
        .map_err(|e| BillingError::DatabaseError(e))?;

        Ok(WebhookEvent {
            event_type: "customer.subscription.created".to_string(),
            tenant_id: Some(tenant_id),
            processed: true,
            data: Some(serde_json::to_value(subscription).unwrap_or_default()),
        })
    }

    async fn handle_subscription_updated(&self, subscription: StripeSubscription) -> Result<WebhookEvent, BillingError> {
        tracing::info!(
            subscription_id = %subscription.id,
            status = %subscription.status,
            "Subscription updated"
        );

        // Get tenant ID from metadata
        let tenant_id = self.extract_tenant_id(&subscription.metadata)
            .ok_or_else(|| BillingError::StripeError("No tenant ID in subscription".to_string()))?;

        // Get the price ID from the first subscription item
        let price_id = subscription.items.data
            .first()
            .map(|item| item.price.id.clone())
            .unwrap_or_default();

        // Update subscription in database
        sqlx::query(
            r#"UPDATE subscriptions SET
                status = $1,
                current_period_start = $2,
                current_period_end = $3,
                cancel_at = $4,
                trial_start = $5,
                trial_end = $6,
                canceled_at = $7,
                updated_at = NOW()
            WHERE stripe_subscription_id = $8"#
        )
        .bind(&subscription.status)
        .bind(chrono::DateTime::from_timestamp(subscription.current_period_start, 0))
        .bind(chrono::DateTime::from_timestamp(subscription.current_period_end, 0))
        .bind(self.cancel_at_timestamp(&subscription))
        .bind(subscription.trial_start.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(subscription.trial_end.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(subscription.canceled_at.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(&subscription.id)
        .execute(self.db.pool())
        .await
        .map_err(|e| BillingError::DatabaseError(e))?;

        // Log billing event
        sqlx::query(
            r#"INSERT INTO billing_events (tenant_id, event_type, stripe_event_id, data, created_at)
            VALUES ($1, $2, $3, $4, NOW())"#
        )
        .bind(&tenant_id)
        .bind("subscription.updated")
        .bind(&subscription.id)
        .bind(serde_json::to_value(&subscription).unwrap_or_default())
        .execute(self.db.pool())
        .await
        .map_err(|e| BillingError::DatabaseError(e))?;

        Ok(WebhookEvent {
            event_type: "customer.subscription.updated".to_string(),
            tenant_id: Some(tenant_id),
            processed: true,
            data: Some(serde_json::to_value(subscription).unwrap_or_default()),
        })
    }

    async fn handle_subscription_deleted(&self, subscription: StripeSubscription) -> Result<WebhookEvent, BillingError> {
        tracing::info!(
            subscription_id = %subscription.id,
            "Subscription deleted"
        );

        let tenant_id = self.extract_tenant_id(&subscription.metadata)
            .ok_or_else(|| BillingError::StripeError("No tenant ID in subscription".to_string()))?;

        // Update subscription status to canceled
        sqlx::query(
            r#"UPDATE subscriptions SET
                status = 'canceled',
                ended_at = NOW(),
                updated_at = NOW()
            WHERE stripe_subscription_id = $1"#
        )
        .bind(&subscription.id)
        .execute(self.db.pool())
        .await
        .map_err(|e| BillingError::DatabaseError(e))?;

        // Log billing event
        sqlx::query(
            r#"INSERT INTO billing_events (tenant_id, event_type, stripe_event_id, data, created_at)
            VALUES ($1, $2, $3, $4, NOW())"#
        )
        .bind(&tenant_id)
        .bind("subscription.deleted")
        .bind(&subscription.id)
        .bind(serde_json::to_value(&subscription).unwrap_or_default())
        .execute(self.db.pool())
        .await
        .map_err(|e| BillingError::DatabaseError(e))?;

        Ok(WebhookEvent {
            event_type: "customer.subscription.deleted".to_string(),
            tenant_id: Some(tenant_id),
            processed: true,
            data: Some(serde_json::to_value(subscription).unwrap_or_default()),
        })
    }

    async fn handle_invoice_paid(&self, invoice: StripeInvoice) -> Result<WebhookEvent, BillingError> {
        tracing::info!(
            invoice_id = %invoice.id,
            amount = invoice.total,
            "Invoice paid"
        );

        // Get tenant ID from customer mapping
        let tenant_id: Option<String> = sqlx::query_scalar(
            r#"SELECT tenant_id FROM subscriptions WHERE stripe_customer_id = $1 LIMIT 1"#
        )
        .bind(&invoice.customer)
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| BillingError::DatabaseError(e))?;

        if let Some(tenant_id) = &tenant_id {
            // Insert or update invoice
            sqlx::query(
                r#"INSERT INTO invoices (
                    tenant_id, stripe_invoice_id, stripe_subscription_id, status,
                    total_cents, subtotal_cents, tax_cents, currency,
                    invoice_pdf_url, hosted_invoice_url, period_start, period_end, paid_at, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW())
                ON CONFLICT (stripe_invoice_id) DO UPDATE SET
                    status = $4,
                    paid_at = NOW(),
                    updated_at = NOW()"#
            )
            .bind(tenant_id)
            .bind(&invoice.id)
            .bind(&invoice.subscription)
            .bind("paid")
            .bind((invoice.total / 100) as i32)
            .bind((invoice.subtotal / 100) as i32)
            .bind(invoice.tax.map(|t| (t / 100) as i32).unwrap_or(0))
            .bind(&invoice.currency)
            .bind(&invoice.invoice_pdf)
            .bind(&invoice.hosted_invoice_url)
            .bind(chrono::DateTime::from_timestamp(invoice.period_start, 0))
            .bind(chrono::DateTime::from_timestamp(invoice.period_end, 0))
            .execute(self.db.pool())
            .await
            .map_err(|e| BillingError::DatabaseError(e))?;
        }

        Ok(WebhookEvent {
            event_type: "invoice.paid".to_string(),
            tenant_id,
            processed: true,
            data: Some(serde_json::to_value(invoice).unwrap_or_default()),
        })
    }

    async fn handle_invoice_payment_failed(&self, invoice: StripeInvoice) -> Result<WebhookEvent, BillingError> {
        tracing::warn!(
            invoice_id = %invoice.id,
            amount = invoice.total,
            "Invoice payment failed"
        );

        // Get tenant ID from customer mapping
        let tenant_id: Option<String> = sqlx::query_scalar(
            r#"SELECT tenant_id FROM subscriptions WHERE stripe_customer_id = $1 LIMIT 1"#
        )
        .bind(&invoice.customer)
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| BillingError::DatabaseError(e))?;

        if let Some(tenant_id) = &tenant_id {
            // Update invoice status
            sqlx::query(
                r#"INSERT INTO invoices (
                    tenant_id, stripe_invoice_id, stripe_subscription_id, status,
                    total_cents, subtotal_cents, tax_cents, currency,
                    invoice_pdf_url, hosted_invoice_url, period_start, period_end, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
                ON CONFLICT (stripe_invoice_id) DO UPDATE SET
                    status = $4,
                    updated_at = NOW()"#
            )
            .bind(tenant_id)
            .bind(&invoice.id)
            .bind(&invoice.subscription)
            .bind("open")
            .bind((invoice.total / 100) as i32)
            .bind((invoice.subtotal / 100) as i32)
            .bind(invoice.tax.map(|t| (t / 100) as i32).unwrap_or(0))
            .bind(&invoice.currency)
            .bind(&invoice.invoice_pdf)
            .bind(&invoice.hosted_invoice_url)
            .bind(chrono::DateTime::from_timestamp(invoice.period_start, 0))
            .bind(chrono::DateTime::from_timestamp(invoice.period_end, 0))
            .execute(self.db.pool())
            .await
            .map_err(|e| BillingError::DatabaseError(e))?;
        }

        Ok(WebhookEvent {
            event_type: "invoice.payment_failed".to_string(),
            tenant_id,
            processed: true,
            data: Some(serde_json::to_value(invoice).unwrap_or_default()),
        })
    }

    async fn handle_payment_intent_succeeded(&self, payment_intent: Value) -> Result<WebhookEvent, BillingError> {
        tracing::info!("Payment intent succeeded");
        Ok(WebhookEvent {
            event_type: "payment_intent.succeeded".to_string(),
            tenant_id: None,
            processed: true,
            data: Some(payment_intent),
        })
    }

    async fn handle_payment_intent_failed(&self, payment_intent: Value) -> Result<WebhookEvent, BillingError> {
        tracing::warn!("Payment intent failed");
        Ok(WebhookEvent {
            event_type: "payment_intent.payment_failed".to_string(),
            tenant_id: None,
            processed: true,
            data: Some(payment_intent),
        })
    }

    async fn handle_charge_succeeded(&self, charge: StripeCharge) -> Result<WebhookEvent, BillingError> {
        tracing::info!(charge_id = %charge.id, "Charge succeeded");
        Ok(WebhookEvent {
            event_type: "charge.succeeded".to_string(),
            tenant_id: None,
            processed: true,
            data: Some(serde_json::to_value(charge).unwrap_or_default()),
        })
    }

    async fn handle_charge_failed(&self, charge: StripeCharge) -> Result<WebhookEvent, BillingError> {
        tracing::warn!(charge_id = %charge.id, "Charge failed");
        Ok(WebhookEvent {
            event_type: "charge.failed".to_string(),
            tenant_id: None,
            processed: true,
            data: Some(serde_json::to_value(charge).unwrap_or_default()),
        })
    }

    async fn handle_charge_refunded(&self, charge: StripeCharge) -> Result<WebhookEvent, BillingError> {
        tracing::info!(charge_id = %charge.id, "Charge refunded");
        Ok(WebhookEvent {
            event_type: "charge.refunded".to_string(),
            tenant_id: None,
            processed: true,
            data: Some(serde_json::to_value(charge).unwrap_or_default()),
        })
    }
}

/// Main webhook processing function
pub async fn process_webhook(
    handler: &dyn WebhookHandler,
    payload: &str,
    signature: &str,
    secret: &str,
) -> Result<WebhookEvent, BillingError> {
    // Verify signature
    if !handler.verify_signature(payload, signature, secret)? {
        return Err(BillingError::InvalidWebhookSignature);
    }

    // Parse payload
    let payload = handler.parse_payload(payload)?;

    // Handle event based on type
    let result = match payload.event_type.as_str() {
        "checkout.session.completed" => {
            let session: StripeCheckoutSession = serde_json::from_value(payload.data.object)
                .map_err(|e| BillingError::StripeError(format!("Failed to parse checkout session: {}", e)))?;
            handler.handle_checkout_completed(session).await
        }
        "customer.subscription.created" => {
            let subscription: StripeSubscription = serde_json::from_value(payload.data.object)
                .map_err(|e| BillingError::StripeError(format!("Failed to parse subscription: {}", e)))?;
            handler.handle_subscription_created(subscription).await
        }
        "customer.subscription.updated" => {
            let subscription: StripeSubscription = serde_json::from_value(payload.data.object)
                .map_err(|e| BillingError::StripeError(format!("Failed to parse subscription: {}", e)))?;
            handler.handle_subscription_updated(subscription).await
        }
        "customer.subscription.deleted" => {
            let subscription: StripeSubscription = serde_json::from_value(payload.data.object)
                .map_err(|e| BillingError::StripeError(format!("Failed to parse subscription: {}", e)))?;
            handler.handle_subscription_deleted(subscription).await
        }
        "invoice.paid" => {
            let invoice: StripeInvoice = serde_json::from_value(payload.data.object)
                .map_err(|e| BillingError::StripeError(format!("Failed to parse invoice: {}", e)))?;
            handler.handle_invoice_paid(invoice).await
        }
        "invoice.payment_failed" => {
            let invoice: StripeInvoice = serde_json::from_value(payload.data.object)
                .map_err(|e| BillingError::StripeError(format!("Failed to parse invoice: {}", e)))?;
            handler.handle_invoice_payment_failed(invoice).await
        }
        "payment_intent.succeeded" => {
            handler.handle_payment_intent_succeeded(payload.data.object).await
        }
        "payment_intent.payment_failed" => {
            handler.handle_payment_intent_failed(payload.data.object).await
        }
        "charge.succeeded" => {
            let charge: StripeCharge = serde_json::from_value(payload.data.object)
                .map_err(|e| BillingError::StripeError(format!("Failed to parse charge: {}", e)))?;
            handler.handle_charge_succeeded(charge).await
        }
        "charge.failed" => {
            let charge: StripeCharge = serde_json::from_value(payload.data.object)
                .map_err(|e| BillingError::StripeError(format!("Failed to parse charge: {}", e)))?;
            handler.handle_charge_failed(charge).await
        }
        "charge.refunded" => {
            let charge: StripeCharge = serde_json::from_value(payload.data.object)
                .map_err(|e| BillingError::StripeError(format!("Failed to parse charge: {}", e)))?;
            handler.handle_charge_refunded(charge).await
        }
        _ => {
            tracing::debug!(event_type = %payload.event_type, "Unhandled webhook event type");
            Ok(WebhookEvent {
                event_type: payload.event_type,
                tenant_id: None,
                processed: false,
                data: Some(payload.data.object),
            })
        }
    };

    result
}
