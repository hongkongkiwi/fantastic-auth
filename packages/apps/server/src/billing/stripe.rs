//! Stripe billing service implementation
//!
//! Full Stripe integration using HTTP API calls.
//! Supports: Customers, Subscriptions, Checkout Sessions, Customer Portal, Webhooks

use anyhow::{Context, Result};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::billing::{
    BillingError, BillingInterval, BillingPlan, CheckoutSession, Invoice, InvoiceStatus,
    PaymentMethod, PlanTier, PortalSession, Subscription, SubscriptionStatus, WebhookResult,
};

const STRIPE_API_BASE: &str = "https://api.stripe.com/v1";

/// Stripe billing service
#[derive(Clone)]
pub struct StripeBillingService {
    client: Client,
    api_key: String,
    webhook_secret: Option<String>,
    db: crate::db::Database,
}

impl StripeBillingService {
    /// Create new Stripe billing service
    pub fn new(
        api_key: String,
        webhook_secret: Option<String>,
        db: crate::db::Database,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            api_key,
            webhook_secret,
            db,
        })
    }

    /// Make authenticated request to Stripe API
    async fn request<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        endpoint: &str,
        params: Option<serde_json::Value>,
    ) -> Result<T, BillingError> {
        let url = format!("{}{}", STRIPE_API_BASE, endpoint);
        
        let mut request = self
            .client
            .request(method, &url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Stripe-Version", "2023-10-16");

        if let Some(params) = params {
            // Convert JSON to form-encoded for Stripe API
            let form_params = json_to_form_params(params);
            request = request.header("Content-Type", "application/x-www-form-urlencoded")
                .body(form_params);
        }

        let response = request
            .send()
            .await
            .map_err(|e| BillingError::StripeError(format!("Request failed: {}", e)))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| BillingError::StripeError(format!("Failed to read response: {}", e)))?;

        if !status.is_success() {
            // Try to parse Stripe error
            if let Ok(error_resp) = serde_json::from_str::<StripeErrorResponse>(&body) {
                return Err(BillingError::StripeError(
                    error_resp.error.message
                ));
            }
            return Err(BillingError::StripeError(format!(
                "HTTP {}: {}",
                status, body
            )));
        }

        serde_json::from_str(&body)
            .map_err(|e| BillingError::StripeError(format!("Failed to parse response: {}", e)))
    }

    /// Get or create Stripe customer for tenant
    pub async fn get_or_create_customer(&self, tenant_id: &str) -> Result<String, BillingError> {
        // Check if tenant already has a Stripe customer ID
        if let Some(customer_id) = self.get_customer_id_from_db(tenant_id).await? {
            // Verify customer still exists in Stripe
            match self.get_customer(&customer_id).await {
                Ok(_) => return Ok(customer_id),
                Err(_) => {
                    // Customer was deleted in Stripe, create new one
                    tracing::warn!("Stripe customer {} not found, creating new one", customer_id);
                }
            }
        }

        // Get tenant info from database
        #[derive(sqlx::FromRow)]
        struct TenantRow {
            name: String,
            slug: String,
        }
        let tenant = sqlx::query_as::<_, TenantRow>(
            "SELECT name, slug FROM tenants WHERE id = $1::uuid"
        )
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?
        .ok_or_else(|| BillingError::CustomerNotFound)?;

        // Create new customer in Stripe
        let params = json!({
            "name": tenant.name,
            "metadata": {
                "tenant_id": tenant_id,
                "tenant_slug": tenant.slug,
            }
        });

        let customer: StripeCustomer = self
            .request(Method::POST, "/customers", Some(params))
            .await?;

        // Store customer ID in database
        self.store_customer_id(tenant_id, &customer.id).await?;

        Ok(customer.id)
    }

    /// Get customer from Stripe
    async fn get_customer(&self, customer_id: &str) -> Result<StripeCustomer, BillingError> {
        self.request(Method::GET, &format!("/customers/{}", customer_id), None)
            .await
    }

    /// Get customer ID from database
    async fn get_customer_id_from_db(&self, tenant_id: &str) -> Result<Option<String>, BillingError> {
        let row = sqlx::query_scalar::<_, Option<String>>(
            "SELECT stripe_customer_id FROM tenant_billing WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        Ok(row.flatten())
    }

    /// Store customer ID in database
    async fn store_customer_id(&self, tenant_id: &str, customer_id: &str) -> Result<(), BillingError> {
        sqlx::query(
            r#"
            INSERT INTO tenant_billing (tenant_id, stripe_customer_id, created_at, updated_at)
            VALUES ($1, $2, NOW(), NOW())
            ON CONFLICT (tenant_id) DO UPDATE SET
                stripe_customer_id = EXCLUDED.stripe_customer_id,
                updated_at = NOW()
            "#
        )
        .bind(tenant_id)
        .bind(customer_id)
        .execute(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        Ok(())
    }

    /// Get subscription for tenant
    pub async fn get_subscription(
        &self,
        tenant_id: &str,
    ) -> Result<Option<Subscription>, BillingError> {
        // First check local database
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

        if let Some(row) = row {
            // Sync with Stripe to get latest status
            if let Some(stripe_subscription_id) = row.stripe_subscription_id.clone() {
                if let Ok(stripe_sub) = self.get_stripe_subscription(&stripe_subscription_id).await {
                    let subscription = self.row_to_subscription(row, Some(&stripe_sub)).await?;
                    return Ok(Some(subscription));
                }
            }
            return Ok(Some(self.row_to_subscription(row, None).await?));
        }

        Ok(None)
    }

    /// Get subscription from Stripe
    async fn get_stripe_subscription(&self, subscription_id: &str) -> Result<StripeSubscription, BillingError> {
        self.request(Method::GET, &format!("/subscriptions/{}", subscription_id), None)
            .await
    }

    /// Create checkout session for subscription
    pub async fn create_checkout_session(
        &self,
        tenant_id: &str,
        price_id: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<CheckoutSession, BillingError> {
        let customer_id = self.get_or_create_customer(tenant_id).await?;

        let params = json!({
            "customer": customer_id,
            "mode": "subscription",
            "line_items[0][price]": price_id,
            "line_items[0][quantity]": 1,
            "success_url": success_url,
            "cancel_url": cancel_url,
            "subscription_data[metadata][tenant_id]": tenant_id,
        });

        let session: StripeCheckoutSession = self
            .request(Method::POST, "/checkout/sessions", Some(params))
            .await?;

        Ok(CheckoutSession {
            id: session.id,
            url: session.url.ok_or_else(|| BillingError::StripeError("No checkout URL".to_string()))?,
            status: session.status,
            customer_id: session.customer,
            subscription_id: session.subscription,
        })
    }

    /// Create customer portal session
    pub async fn create_portal_session(
        &self,
        tenant_id: &str,
        return_url: &str,
    ) -> Result<PortalSession, BillingError> {
        let customer_id = self.get_or_create_customer(tenant_id).await?;

        let params = json!({
            "customer": customer_id,
            "return_url": return_url,
        });

        let session: StripePortalSession = self
            .request(Method::POST, "/billing_portal/sessions", Some(params))
            .await?;

        Ok(PortalSession {
            id: session.id,
            url: session.url,
            customer_id: session.customer,
        })
    }

    /// Handle Stripe webhook
    pub async fn handle_webhook(
        &self,
        payload: &str,
        signature: &str,
    ) -> Result<WebhookResult, BillingError> {
        // Verify webhook signature if secret is configured
        if let Some(secret) = &self.webhook_secret {
            if !self.verify_webhook_signature(payload, signature, secret) {
                return Err(BillingError::InvalidRequest("Invalid webhook signature".to_string()));
            }
        }

        // Parse webhook event
        let event: StripeEvent = serde_json::from_str(payload)
            .map_err(|e| BillingError::StripeError(format!("Failed to parse webhook: {}", e)))?;

        tracing::info!("Processing Stripe webhook: {} ({})", event.type_, event.id);

        let processed = match event.type_.as_str() {
            "checkout.session.completed" => {
                self.handle_checkout_completed(&event.data.object).await?
            }
            "invoice.payment_succeeded" => {
                self.handle_invoice_payment_succeeded(&event.data.object).await?
            }
            "invoice.payment_failed" => {
                self.handle_invoice_payment_failed(&event.data.object).await?
            }
            "customer.subscription.updated" => {
                self.handle_subscription_updated(&event.data.object).await?
            }
            "customer.subscription.deleted" => {
                self.handle_subscription_deleted(&event.data.object).await?
            }
            _ => {
                tracing::debug!("Unhandled webhook event type: {}", event.type_);
                false
            }
        };

        // Extract tenant ID from event data
        let tenant_id = self.extract_tenant_id_from_event(&event).await.ok();

        Ok(WebhookResult {
            event_type: event.type_,
            tenant_id,
            processed,
        })
    }

    /// Verify Stripe webhook signature
    fn verify_webhook_signature(&self, payload: &str, signature: &str, secret: &str) -> bool {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let sig_parts: std::collections::HashMap<&str, &str> = signature
            .split(',')
            .filter_map(|part| {
                let mut kv = part.splitn(2, '=');
                Some((kv.next()?, kv.next()?))
            })
            .collect();

        let timestamp = match sig_parts.get("t") {
            Some(t) => *t,
            None => return false,
        };
        let sig = match sig_parts.get("v1") {
            Some(s) => *s,
            None => return false,
        };

        // Construct signed payload
        let signed_payload = format!("{}.{}", timestamp, payload);

        // Calculate HMAC
        let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(signed_payload.as_bytes());
        let result = mac.finalize();
        let expected_sig = hex::encode(result.into_bytes());

        // Constant-time comparison
        use subtle::ConstantTimeEq;
        expected_sig.as_bytes().ct_eq(sig.as_bytes()).into()
    }

    /// Handle checkout.session.completed
    async fn handle_checkout_completed(&self, data: &serde_json::Value) -> Result<bool, BillingError> {
        let session: StripeCheckoutSession = serde_json::from_value(data.clone())
            .map_err(|e| BillingError::StripeError(format!("Failed to parse session: {}", e)))?;

        if let Some(subscription_id) = &session.subscription {
            // Get subscription details from Stripe
            let subscription = self.get_stripe_subscription(subscription_id).await?;
            
            // Extract tenant ID from metadata
            if let Some(tenant_id) = session.metadata.as_ref().and_then(|m| m.get("tenant_id")) {
                self.sync_subscription_to_db(tenant_id, &subscription).await?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Handle invoice.payment_succeeded
    async fn handle_invoice_payment_succeeded(&self, data: &serde_json::Value) -> Result<bool, BillingError> {
        let invoice: StripeInvoice = serde_json::from_value(data.clone())
            .map_err(|e| BillingError::StripeError(format!("Failed to parse invoice: {}", e)))?;

        self.sync_invoice_to_db(&invoice).await?;
        Ok(true)
    }

    /// Handle invoice.payment_failed
    async fn handle_invoice_payment_failed(&self, data: &serde_json::Value) -> Result<bool, BillingError> {
        let invoice: StripeInvoice = serde_json::from_value(data.clone())
            .map_err(|e| BillingError::StripeError(format!("Failed to parse invoice: {}", e)))?;

        self.sync_invoice_to_db(&invoice).await?;
        Ok(true)
    }

    /// Handle customer.subscription.updated
    async fn handle_subscription_updated(&self, data: &serde_json::Value) -> Result<bool, BillingError> {
        let subscription: StripeSubscription = serde_json::from_value(data.clone())
            .map_err(|e| BillingError::StripeError(format!("Failed to parse subscription: {}", e)))?;

        // Try to find tenant by subscription ID
        let row = sqlx::query_scalar::<_, String>(
            "SELECT tenant_id FROM subscriptions WHERE stripe_subscription_id = $1"
        )
        .bind(&subscription.id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        if let Some(tenant_id) = row {
            self.sync_subscription_to_db(&tenant_id, &subscription).await?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Handle customer.subscription.deleted
    async fn handle_subscription_deleted(&self, data: &serde_json::Value) -> Result<bool, BillingError> {
        let subscription: StripeSubscription = serde_json::from_value(data.clone())
            .map_err(|e| BillingError::StripeError(format!("Failed to parse subscription: {}", e)))?;

        // Update subscription status in database
        sqlx::query(
            "UPDATE subscriptions SET status = 'canceled', ended_at = NOW(), updated_at = NOW() WHERE stripe_subscription_id = $1"
        )
        .bind(&subscription.id)
        .execute(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        Ok(true)
    }

    /// Extract tenant ID from Stripe event
    async fn extract_tenant_id_from_event(&self, event: &StripeEvent) -> Result<String, BillingError> {
        // Try metadata first
        if let Some(metadata) = event.data.object.get("metadata") {
            if let Some(tenant_id) = metadata.get("tenant_id").and_then(|v| v.as_str()) {
                return Ok(tenant_id.to_string());
            }
        }

        // Try to find by subscription ID
        if let Some(sub_id) = event.data.object.get("id").and_then(|v| v.as_str()) {
            let row = sqlx::query_scalar::<_, String>(
                "SELECT tenant_id FROM subscriptions WHERE stripe_subscription_id = $1"
            )
            .bind(sub_id)
            .fetch_optional(self.db.pool())
            .await
            .map_err(BillingError::DatabaseError)?;

            if let Some(tenant_id) = row {
                return Ok(tenant_id);
            }
        }

        Err(BillingError::CustomerNotFound)
    }

    /// Sync subscription to database
    async fn sync_subscription_to_db(
        &self,
        tenant_id: &str,
        subscription: &StripeSubscription,
    ) -> Result<(), BillingError> {
        let item = subscription.items.data.first()
            .ok_or_else(|| BillingError::StripeError("No subscription items".to_string()))?;

        sqlx::query(
            r#"
            INSERT INTO subscriptions (
                id, tenant_id, stripe_customer_id, stripe_subscription_id, stripe_price_id,
                status, current_period_start, current_period_end, trial_start, trial_end,
                cancel_at, canceled_at, ended_at, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW())
            ON CONFLICT (stripe_subscription_id) DO UPDATE SET
                status = EXCLUDED.status,
                current_period_start = EXCLUDED.current_period_start,
                current_period_end = EXCLUDED.current_period_end,
                trial_start = EXCLUDED.trial_start,
                trial_end = EXCLUDED.trial_end,
                cancel_at = EXCLUDED.cancel_at,
                canceled_at = EXCLUDED.canceled_at,
                ended_at = EXCLUDED.ended_at,
                updated_at = NOW()
            "#
        )
        .bind(&uuid::Uuid::new_v4().to_string())
        .bind(tenant_id)
        .bind(&subscription.customer)
        .bind(&subscription.id)
        .bind(&item.price.id)
        .bind(&subscription.status)
        .bind(subscription.current_period_start.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(subscription.current_period_end.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(subscription.trial_start.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(subscription.trial_end.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(subscription.cancel_at.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(subscription.canceled_at.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(subscription.ended_at.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .execute(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        Ok(())
    }

    /// Sync invoice to database
    async fn sync_invoice_to_db(&self, invoice: &StripeInvoice) -> Result<(), BillingError> {
        // Find tenant by customer ID
        let row = sqlx::query_scalar::<_, String>(
            "SELECT tenant_id FROM tenant_billing WHERE stripe_customer_id = $1"
        )
        .bind(&invoice.customer)
        .fetch_optional(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        let tenant_id = match row {
            Some(id) => id,
            None => return Ok(()), // Unknown customer, skip
        };

        sqlx::query(
            r#"
            INSERT INTO invoices (
                id, tenant_id, stripe_invoice_id, status, total_cents, subtotal_cents,
                tax_cents, currency, invoice_pdf_url, hosted_invoice_url,
                period_start, period_end, paid_at, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW())
            ON CONFLICT (stripe_invoice_id) DO UPDATE SET
                status = EXCLUDED.status,
                paid_at = EXCLUDED.paid_at,
                invoice_pdf_url = EXCLUDED.invoice_pdf_url
            "#
        )
        .bind(&uuid::Uuid::new_v4().to_string())
        .bind(&tenant_id)
        .bind(&invoice.id)
        .bind(&invoice.status)
        .bind(invoice.total)
        .bind(invoice.subtotal)
        .bind(invoice.tax)
        .bind(&invoice.currency)
        .bind(invoice.invoice_pdf.as_ref())
        .bind(invoice.hosted_invoice_url.as_ref())
        .bind(invoice.period_start.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(invoice.period_end.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .bind(invoice.status_transitions.paid_at.map(|t| chrono::DateTime::from_timestamp(t, 0)))
        .execute(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        Ok(())
    }

    /// List available plans
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

    /// Get invoices for tenant
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

    /// Cancel subscription at period end
    pub async fn cancel_subscription(&self, tenant_id: &str) -> Result<Subscription, BillingError> {
        let row = sqlx::query_as::<_, SubscriptionRow>(
            "SELECT * FROM subscriptions WHERE tenant_id = $1 AND status IN ('active', 'trialing')"
        )
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        let row = row.ok_or(BillingError::SubscriptionNotFound)?;
        let stripe_subscription_id = row
            .stripe_subscription_id
            .clone()
            .ok_or(BillingError::SubscriptionNotFound)?;

        // Cancel in Stripe
        let params = json!({
            "cancel_at_period_end": true
        });

        let subscription: StripeSubscription = self
            .request(
                Method::POST,
                &format!("/subscriptions/{}", stripe_subscription_id),
                Some(params),
            )
            .await?;

        self.sync_subscription_to_db(tenant_id, &subscription).await?;
        self.get_subscription(tenant_id)
            .await?
            .ok_or(BillingError::SubscriptionNotFound)
    }

    /// Resume canceled subscription
    pub async fn resume_subscription(&self, tenant_id: &str) -> Result<Subscription, BillingError> {
        let row = sqlx::query_as::<_, SubscriptionRow>(
            "SELECT * FROM subscriptions WHERE tenant_id = $1 AND status = 'active' AND cancel_at IS NOT NULL"
        )
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        let row = row.ok_or(BillingError::SubscriptionNotFound)?;
        let stripe_subscription_id = row
            .stripe_subscription_id
            .clone()
            .ok_or(BillingError::SubscriptionNotFound)?;

        // Resume in Stripe
        let params = json!({
            "cancel_at_period_end": false
        });

        let subscription: StripeSubscription = self
            .request(
                Method::POST,
                &format!("/subscriptions/{}", stripe_subscription_id),
                Some(params),
            )
            .await?;

        self.sync_subscription_to_db(tenant_id, &subscription).await?;
        self.get_subscription(tenant_id)
            .await?
            .ok_or(BillingError::SubscriptionNotFound)
    }

    /// Update subscription to new plan
    pub async fn update_subscription_plan(
        &self,
        tenant_id: &str,
        new_price_id: &str,
    ) -> Result<Subscription, BillingError> {
        let row = sqlx::query_as::<_, SubscriptionRow>(
            "SELECT * FROM subscriptions WHERE tenant_id = $1 AND status IN ('active', 'trialing')"
        )
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(BillingError::DatabaseError)?;

        let row = row.ok_or(BillingError::SubscriptionNotFound)?;
        let stripe_subscription_id = row
            .stripe_subscription_id
            .clone()
            .ok_or(BillingError::SubscriptionNotFound)?;

        // Update in Stripe
        let params = json!({
            "items[0][id]": row.stripe_subscription_id,
            "items[0][price]": new_price_id
        });

        let subscription: StripeSubscription = self
            .request(
                Method::POST,
                &format!("/subscriptions/{}", stripe_subscription_id),
                Some(params),
            )
            .await?;

        self.sync_subscription_to_db(tenant_id, &subscription).await?;
        self.get_subscription(tenant_id)
            .await?
            .ok_or(BillingError::SubscriptionNotFound)
    }

    /// Record usage for metered billing
    pub async fn record_usage(&self, _tenant_id: &str, _quantity: i64) -> anyhow::Result<()> {
        // NOTE: Usage-based billing is a planned feature for future implementation.
        // This requires setting up metered prices in Stripe and integrating with usage tracking.
        Ok(())
    }

    /// Convert database row to Subscription
    async fn row_to_subscription(
        &self,
        row: SubscriptionRow,
        stripe_sub: Option<&StripeSubscription>,
    ) -> Result<Subscription, BillingError> {
        let plan = if row.plan_id.is_some() {
            Some(BillingPlan {
                id: row.plan_id.unwrap_or_default(),
                stripe_product_id: row.stripe_product_id.unwrap_or_default(),
                stripe_price_id: row.plan_price_id.unwrap_or_default(),
                name: row.plan_name.unwrap_or_default(),
                description: None,
                tier: match row.tier.as_deref() {
                    Some("free") => PlanTier::Free,
                    Some("starter") => PlanTier::Starter,
                    Some("pro") => PlanTier::Pro,
                    _ => PlanTier::Enterprise,
                },
                price_cents: row.price_cents.unwrap_or(0),
                interval: match row.interval.as_deref() {
                    Some("year") => BillingInterval::Year,
                    _ => BillingInterval::Month,
                },
                features: vec![],
                is_active: true,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
        } else {
            None
        };

        // Use Stripe data if available, otherwise use DB data
        let status = if let Some(s) = stripe_sub {
            match s.status.as_str() {
                "incomplete" => SubscriptionStatus::Incomplete,
                "incomplete_expired" => SubscriptionStatus::IncompleteExpired,
                "trialing" => SubscriptionStatus::Trialing,
                "active" => SubscriptionStatus::Active,
                "past_due" => SubscriptionStatus::PastDue,
                "canceled" => SubscriptionStatus::Canceled,
                "unpaid" => SubscriptionStatus::Unpaid,
                "paused" => SubscriptionStatus::Paused,
                _ => SubscriptionStatus::Incomplete,
            }
        } else {
            match row.status.as_str() {
                "incomplete" => SubscriptionStatus::Incomplete,
                "incomplete_expired" => SubscriptionStatus::IncompleteExpired,
                "trialing" => SubscriptionStatus::Trialing,
                "active" => SubscriptionStatus::Active,
                "past_due" => SubscriptionStatus::PastDue,
                "canceled" => SubscriptionStatus::Canceled,
                "unpaid" => SubscriptionStatus::Unpaid,
                "paused" => SubscriptionStatus::Paused,
                _ => SubscriptionStatus::Incomplete,
            }
        };

        Ok(Subscription {
            id: row.id,
            tenant_id: row.tenant_id,
            stripe_customer_id: row.stripe_customer_id,
            stripe_subscription_id: row.stripe_subscription_id,
            plan,
            status,
            current_period_start: row.current_period_start,
            current_period_end: row.current_period_end,
            trial_start: row.trial_start,
            trial_end: row.trial_end,
            cancel_at: row.cancel_at,
            canceled_at: row.canceled_at,
            ended_at: row.ended_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

// === Helper Functions ===

/// Convert JSON to form-urlencoded format for Stripe API
fn json_to_form_params(value: serde_json::Value) -> String {
    let mut params = Vec::new();
    flatten_json("", &value, &mut params);
    params.join("&")
}

/// Flatten nested JSON into form params
fn flatten_json(prefix: &str, value: &serde_json::Value, output: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let new_prefix = if prefix.is_empty() {
                    key.to_string()
                } else {
                    format!("{}[{}]", prefix, key)
                };
                flatten_json(&new_prefix, val, output);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let new_prefix = format!("{}[{}]", prefix, i);
                flatten_json(&new_prefix, val, output);
            }
        }
        serde_json::Value::String(s) => {
            output.push(format!("{}={}", prefix, urlencoding::encode(s)));
        }
        serde_json::Value::Number(n) => {
            output.push(format!("{}={}", prefix, n));
        }
        serde_json::Value::Bool(b) => {
            output.push(format!("{}={}", prefix, b));
        }
        serde_json::Value::Null => {}
    }
}

// === Stripe API Types ===

#[derive(Debug, Deserialize)]
struct StripeErrorResponse {
    error: StripeError,
}

#[derive(Debug, Deserialize)]
struct StripeError {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
}

#[derive(Debug, Deserialize)]
struct StripeEvent {
    id: String,
    #[serde(rename = "type")]
    type_: String,
    data: StripeEventData,
}

#[derive(Debug, Deserialize)]
struct StripeEventData {
    object: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct StripeCustomer {
    id: String,
    email: Option<String>,
    name: Option<String>,
    metadata: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct StripeSubscription {
    id: String,
    customer: String,
    status: String,
    current_period_start: Option<i64>,
    current_period_end: Option<i64>,
    trial_start: Option<i64>,
    trial_end: Option<i64>,
    cancel_at: Option<i64>,
    canceled_at: Option<i64>,
    ended_at: Option<i64>,
    items: StripeList<StripeSubscriptionItem>,
    metadata: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct StripeSubscriptionItem {
    id: String,
    price: StripePrice,
}

#[derive(Debug, Deserialize)]
struct StripePrice {
    id: String,
    product: String,
}

#[derive(Debug, Deserialize)]
struct StripeList<T> {
    data: Vec<T>,
}

#[derive(Debug, Deserialize)]
struct StripeCheckoutSession {
    id: String,
    url: Option<String>,
    status: String,
    customer: Option<String>,
    subscription: Option<String>,
    metadata: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct StripePortalSession {
    id: String,
    url: String,
    customer: String,
}

#[derive(Debug, Deserialize)]
struct StripeInvoice {
    id: String,
    customer: String,
    status: String,
    total: i32,
    subtotal: i32,
    tax: Option<i32>,
    currency: String,
    invoice_pdf: Option<String>,
    hosted_invoice_url: Option<String>,
    period_start: Option<i64>,
    period_end: Option<i64>,
    status_transitions: StripeInvoiceStatusTransitions,
}

#[derive(Debug, Deserialize)]
struct StripeInvoiceStatusTransitions {
    paid_at: Option<i64>,
}

// === Database Row Types ===

use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(sqlx::FromRow)]
struct SubscriptionRow {
    id: String,
    tenant_id: String,
    stripe_customer_id: Option<String>,
    stripe_subscription_id: Option<String>,
    stripe_price_id: Option<String>,
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
