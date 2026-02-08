use crate::db::Database;
use crate::security::TenantKeyService;
use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

pub mod events;
mod types;

pub use events::*;
pub use types::*;

/// Queue statistics for webhook deliveries
#[derive(Debug, Clone)]
pub struct WebhookQueueStats {
    /// Number of pending deliveries
    pub pending: i64,
    /// Number of delivered webhooks
    pub delivered: i64,
    /// Number of failed deliveries
    pub failed: i64,
    /// Total number of deliveries
    pub total: i64,
}

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_PAYLOAD_SIZE: usize = 1 * 1024 * 1024; // 1MB

/// Webhook delivery service
#[derive(Clone)]
pub struct WebhookService {
    db: Database,
    http_client: Client,
    tenant_keys: Arc<TenantKeyService>,
}

impl WebhookService {
    pub fn new(db: Database, tenant_keys: Arc<TenantKeyService>) -> Self {
        let http_client = Client::builder()
            .timeout(WEBHOOK_TIMEOUT)
            .pool_max_idle_per_host(10)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            db,
            http_client,
            tenant_keys,
        }
    }

    /// Create a new webhook endpoint
    pub async fn create_endpoint(
        &self,
        tenant_id: &str,
        name: &str,
        url: &str,
        events: Vec<String>,
        secret: Option<String>,
        description: Option<String>,
        headers: Option<Value>,
    ) -> Result<WebhookEndpoint> {
        // Validate URL
        let _ = url::Url::parse(url).context("Invalid webhook URL")?;

        // Validate events
        for event in &events {
            if !is_valid_event_type(event) {
                anyhow::bail!("Invalid event type: {}", event);
            }
        }

        // Generate secret if not provided
        let secret = secret.unwrap_or_else(generate_webhook_secret);
        let encrypted_secret = self.encrypt_secret(tenant_id, &secret).await?;

        let endpoint = self
            .db
            .webhooks()
            .create_endpoint(
                tenant_id,
                name,
                url,
                events,
                encrypted_secret,
                description,
                headers,
            )
            .await?;

        info!(
            tenant_id = tenant_id,
            endpoint_id = %endpoint.id,
            "Created webhook endpoint"
        );

        Ok(endpoint)
    }

    /// Update a webhook endpoint
    pub async fn update_endpoint(
        &self,
        tenant_id: &str,
        endpoint_id: &str,
        updates: WebhookEndpointUpdate,
    ) -> Result<WebhookEndpoint> {
        if let Some(ref url) = updates.url {
            let _ = url::Url::parse(url).context("Invalid webhook URL")?;
        }

        if let Some(ref events) = updates.events {
            for event in events {
                if !is_valid_event_type(event) {
                    anyhow::bail!("Invalid event type: {}", event);
                }
            }
        }

        let mut updates = updates;
        if let Some(secret) = updates.secret.take() {
            let encrypted = self.encrypt_secret(tenant_id, &secret).await?;
            updates.secret = Some(encrypted);
        }

        let endpoint = self
            .db
            .webhooks()
            .update_endpoint(tenant_id, endpoint_id, updates)
            .await?;

        info!(
            tenant_id = tenant_id,
            endpoint_id = endpoint_id,
            "Updated webhook endpoint"
        );

        Ok(endpoint)
    }

    /// Delete a webhook endpoint (soft delete)
    pub async fn delete_endpoint(&self, tenant_id: &str, endpoint_id: &str) -> Result<()> {
        self.db
            .webhooks()
            .delete_endpoint(tenant_id, endpoint_id)
            .await?;

        info!(
            tenant_id = tenant_id,
            endpoint_id = endpoint_id,
            "Deleted webhook endpoint"
        );

        Ok(())
    }

    /// Get a webhook endpoint by ID
    pub async fn get_endpoint(
        &self,
        tenant_id: &str,
        endpoint_id: &str,
    ) -> Result<WebhookEndpoint> {
        self.db
            .webhooks()
            .get_endpoint(tenant_id, endpoint_id)
            .await
    }

    /// List webhook endpoints for a tenant
    pub async fn list_endpoints(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> Result<(Vec<WebhookEndpoint>, i64)> {
        self.db
            .webhooks()
            .list_endpoints(tenant_id, page, per_page)
            .await
    }

    /// Trigger an event - creates deliveries for all matching endpoints
    pub async fn trigger_event(
        &self,
        tenant_id: &str,
        event_type: &str,
        payload: Value,
    ) -> Result<Vec<WebhookDelivery>> {
        let payload_size = serde_json::to_string(&payload)
            .map(|s| s.len())
            .unwrap_or(0);

        if payload_size > MAX_PAYLOAD_SIZE {
            anyhow::bail!("Payload exceeds maximum size of {} bytes", MAX_PAYLOAD_SIZE);
        }

        let endpoints = self
            .db
            .webhooks()
            .get_active_endpoints_for_event(tenant_id, event_type)
            .await?;

        let mut deliveries = Vec::new();

        for endpoint in endpoints {
            let delivery = self
                .db
                .webhooks()
                .create_delivery(
                    &endpoint.id,
                    tenant_id,
                    event_type,
                    payload.clone(),
                    payload_size as i32,
                )
                .await?;

            deliveries.push(delivery);
        }

        info!(
            tenant_id = tenant_id,
            event_type = event_type,
            endpoint_count = deliveries.len(),
            "Created webhook deliveries"
        );

        Ok(deliveries)
    }

    /// Deliver a pending webhook
    pub async fn deliver_webhook(
        &self,
        tenant_id: &str,
        delivery_id: &str,
    ) -> Result<WebhookDelivery> {
        let delivery = self
            .db
            .webhooks()
            .get_delivery(tenant_id, delivery_id)
            .await
            .context("Failed to get webhook delivery")?;

        if delivery.status != "pending" {
            anyhow::bail!("Webhook delivery is not pending");
        }

        let endpoint = self
            .db
            .webhooks()
            .get_endpoint(&delivery.tenant_id, &delivery.endpoint_id)
            .await
            .context("Failed to get webhook endpoint")?;

        let result = self.execute_delivery(&endpoint, &delivery).await;

        match result {
            Ok((status_code, response_body)) => {
                let updated = self
                    .db
                    .webhooks()
                    .mark_delivered(tenant_id, delivery_id, status_code, response_body, None)
                    .await?;

                info!(
                    delivery_id = delivery_id,
                    status_code = status_code,
                    "Webhook delivered successfully"
                );

                Ok(updated)
            }
            Err(e) => {
                let max_retries = endpoint.max_retries;
                let should_retry = delivery.attempt_number < max_retries;

                let updated = self
                    .db
                    .webhooks()
                    .mark_failed(tenant_id, delivery_id, &e.to_string(), should_retry)
                    .await?;

                warn!(
                    delivery_id = delivery_id,
                    attempt = delivery.attempt_number,
                    max_retries = max_retries,
                    error = %e,
                    "Webhook delivery failed"
                );

                Ok(updated)
            }
        }
    }

    /// Execute the actual HTTP delivery
    async fn execute_delivery(
        &self,
        endpoint: &WebhookEndpoint,
        delivery: &WebhookDelivery,
    ) -> Result<(i32, Option<String>)> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        // Generate signature
        let payload_str = serde_json::to_string(&delivery.payload)?;
        let signature_payload = format!("{}.{}", delivery.id, payload_str);

        let secret = match self.decrypt_secret(&endpoint.tenant_id, &endpoint.secret).await {
            Ok(value) => value,
            Err(e) => {
                warn!(
                    tenant_id = %endpoint.tenant_id,
                    endpoint_id = %endpoint.id,
                    error = %e,
                    "Webhook secret decryption failed; falling back to stored value"
                );
                endpoint.secret.clone()
            }
        };

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|_| anyhow::anyhow!("Invalid secret"))?;
        mac.update(signature_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        // Build request
        let mut request = self
            .http_client
            .post(&endpoint.url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-ID", &delivery.id)
            .header(
                "X-Webhook-Timestamp",
                chrono::Utc::now().timestamp().to_string(),
            )
            .header("X-Webhook-Signature", format!("v1={}", signature))
            .header("X-Webhook-Event", &delivery.event_type)
            .header("User-Agent", "UserVault-Webhook/1.0");

        // Add custom headers
        if let Some(headers) = &endpoint.headers {
            if let Some(obj) = headers.as_object() {
                for (key, value) in obj {
                    if let Some(val) = value.as_str() {
                        request = request.header(key, val);
                    }
                }
            }
        }

        // Send request
        let response = request.json(&delivery.payload).send().await?;

        let status_code = response.status().as_u16() as i32;
        let response_body = response.text().await.ok();

        // Consider 2xx status codes as success
        if status_code >= 200 && status_code < 300 {
            Ok((status_code, response_body))
        } else {
            Err(anyhow::anyhow!(
                "HTTP error: {} - {}",
                status_code,
                response_body.as_deref().unwrap_or("No response body")
            ))
        }
    }

    async fn encrypt_secret(&self, tenant_id: &str, secret: &str) -> Result<String> {
        let key = self
            .tenant_keys
            .get_data_key(tenant_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to load tenant key: {}", e))?;
        crate::security::encryption::encrypt_to_base64(&key, secret.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to encrypt webhook secret: {}", e))
    }

    pub(crate) async fn decrypt_secret(&self, tenant_id: &str, encrypted: &str) -> Result<String> {
        let key = self
            .tenant_keys
            .get_data_key(tenant_id)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to load tenant key: {}", e))?;
        let bytes = crate::security::encryption::decrypt_from_base64(&key, encrypted)
            .map_err(|e| anyhow::anyhow!("Failed to decrypt webhook secret: {}", e))?;
        String::from_utf8(bytes).map_err(|e| anyhow::anyhow!("Invalid webhook secret: {}", e))
    }

    /// Get pending deliveries that need to be processed
    pub async fn get_pending_deliveries(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>> {
        self.db
            .webhooks()
            .get_pending_deliveries(tenant_id, limit)
            .await
    }

    /// List deliveries for an endpoint
    pub async fn list_deliveries(
        &self,
        tenant_id: &str,
        endpoint_id: &str,
        page: i64,
        per_page: i64,
    ) -> Result<(Vec<WebhookDelivery>, i64)> {
        self.db
            .webhooks()
            .list_deliveries(tenant_id, endpoint_id, page, per_page)
            .await
    }

    /// Retry a failed delivery
    pub async fn retry_delivery(
        &self,
        tenant_id: &str,
        delivery_id: &str,
    ) -> Result<WebhookDelivery> {
        let delivery = self
            .db
            .webhooks()
            .reset_delivery_for_retry(tenant_id, delivery_id)
            .await?;

        info!(
            delivery_id = delivery_id,
            "Reset webhook delivery for retry"
        );

        Ok(delivery)
    }
}

/// Generate a random webhook secret
fn generate_webhook_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Validate event type format
fn is_valid_event_type(event: &str) -> bool {
    // Event types follow pattern: resource.action (e.g., user.created)
    let parts: Vec<&str> = event.split('.').collect();
    if parts.len() != 2 {
        return false;
    }

    let valid_resources = ["user", "organization", "session", "audit", "webhook"];
    let valid_actions = [
        "created",
        "updated",
        "deleted",
        "activated",
        "deactivated",
        "login",
        "logout",
    ];

    valid_resources.contains(&parts[0]) && valid_actions.contains(&parts[1])
}
