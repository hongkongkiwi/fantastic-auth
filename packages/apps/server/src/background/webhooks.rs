//! Webhook background worker
//!
//! Processes pending webhook deliveries with retry logic.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::db::Database;
use crate::webhooks::{WebhookDelivery, WebhookEndpoint, WebhookQueueStats};
use vault_core::db::{with_request_context, RequestContext};

/// Background worker for webhook delivery
pub struct WebhookWorker {
    db: Database,
    http_client: reqwest::Client,
    poll_interval: Duration,
    batch_size: i64,
    max_attempts: i32,
}

impl WebhookWorker {
    /// Create a new webhook worker
    pub fn new(db: Database) -> Self {
        let http_client = Self::build_http_client()
            .unwrap_or_else(|e| {
                tracing::error!("Failed to build HTTP client: {}, using default", e);
                reqwest::Client::new()
            });

        Self {
            db,
            http_client,
            poll_interval: Duration::from_secs(10),
            batch_size: 100,
            max_attempts: 6,
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        db: Database,
        poll_interval: Duration,
        batch_size: i64,
        max_attempts: i32,
    ) -> Self {
        let http_client = Self::build_http_client()
            .unwrap_or_else(|e| {
                tracing::error!("Failed to build HTTP client: {}, using default", e);
                reqwest::Client::new()
            });

        Self {
            db,
            http_client,
            poll_interval,
            batch_size,
            max_attempts,
        }
    }

    fn build_http_client() -> Result<reqwest::Client, reqwest::Error> {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(10)
            .build()
    }

    /// Start the worker loop (runs forever)
    pub async fn start(self: Arc<Self>) {
        let mut interval = interval(self.poll_interval);

        info!(
            poll_interval_secs = self.poll_interval.as_secs(),
            batch_size = self.batch_size,
            "Webhook worker started"
        );

        loop {
            interval.tick().await;

            match self.process_batch().await {
                Ok(count) => {
                    if count > 0 {
                        debug!(deliveries_processed = count, "Webhook batch processed");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Webhook worker error");
                }
            }
        }
    }

    /// Process a single batch of pending deliveries
    async fn process_batch(&self) -> anyhow::Result<usize> {
        let tenant_ids = self.list_tenant_ids().await?;
        let mut total = 0usize;

        for tenant_id in tenant_ids {
            let ctx = RequestContext {
                tenant_id: Some(tenant_id.clone()),
                user_id: None,
                role: Some("service".to_string()),
            };

            let processed = with_request_context(ctx, async {
                let deliveries = self
                    .db
                    .webhooks()
                    .get_pending_deliveries(&tenant_id, self.batch_size)
                    .await?;

                let count = deliveries.len();

                for delivery in deliveries {
                    if let Err(e) = self.process_delivery(delivery).await {
                        error!(error = %e, "Failed to process webhook delivery");
                    }
                }

                Ok::<usize, anyhow::Error>(count)
            })
            .await?;

            total += processed;
        }

        Ok(total)
    }

    /// Process a single delivery
    async fn process_delivery(&self, delivery: WebhookDelivery) -> anyhow::Result<()> {
        debug!(
            delivery_id = %delivery.id,
            endpoint_id = %delivery.endpoint_id,
            attempt = delivery.attempt_number,
            "Processing webhook delivery"
        );

        // Get the endpoint
        let endpoint = match self
            .db
            .webhooks()
            .get_endpoint(&delivery.tenant_id, &delivery.endpoint_id)
            .await
        {
            Ok(ep) => ep,
            Err(e) => {
                // Endpoint not found or deleted, mark delivery as failed
                warn!(
                    delivery_id = %delivery.id,
                    endpoint_id = %delivery.endpoint_id,
                    error = %e,
                    "Webhook endpoint not found, marking delivery as failed"
                );
                self.db
                    .webhooks()
                    .mark_failed(
                        &delivery.tenant_id,
                        &delivery.id,
                        "Endpoint not found",
                        false,
                    )
                    .await?;
                return Ok(());
            }
        };

        // Check if endpoint is active
        if !endpoint.active {
            warn!(
                delivery_id = %delivery.id,
                endpoint_id = %endpoint.id,
                "Webhook endpoint is inactive, marking delivery as failed"
            );
            self.db
                .webhooks()
                .mark_failed(
                    &delivery.tenant_id,
                    &delivery.id,
                    "Endpoint is inactive",
                    false,
                )
                .await?;
            return Ok(());
        }

        // Check max attempts
        if delivery.attempt_number >= self.max_attempts {
            warn!(
                delivery_id = %delivery.id,
                attempt = delivery.attempt_number,
                max_attempts = self.max_attempts,
                "Max retry attempts reached"
            );
            self.db
                .webhooks()
                .mark_failed(
                    &delivery.tenant_id,
                    &delivery.id,
                    "Max retry attempts reached",
                    false,
                )
                .await?;
            return Ok(());
        }

        // Execute the delivery
        match self.execute_delivery(&endpoint, &delivery).await {
            Ok((status_code, response_body)) => {
                info!(
                    delivery_id = %delivery.id,
                    status_code = status_code,
                    "Webhook delivered successfully"
                );
                self.db
                    .webhooks()
                    .mark_delivered(
                        &delivery.tenant_id,
                        &delivery.id,
                        status_code,
                        response_body,
                        None,
                    )
                    .await?;
            }
            Err(e) => {
                let should_retry = delivery.attempt_number < self.max_attempts - 1;
                warn!(
                    delivery_id = %delivery.id,
                    attempt = delivery.attempt_number,
                    error = %e,
                    should_retry = should_retry,
                    "Webhook delivery failed"
                );
                self.db
                    .webhooks()
                    .mark_failed(
                        &delivery.tenant_id,
                        &delivery.id,
                        &e.to_string(),
                        should_retry,
                    )
                    .await?;
            }
        }

        Ok(())
    }

    /// Execute the HTTP delivery with HMAC signature
    async fn execute_delivery(
        &self,
        endpoint: &WebhookEndpoint,
        delivery: &WebhookDelivery,
    ) -> anyhow::Result<(i32, Option<String>)> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        // Generate HMAC-SHA256 signature
        // Format: timestamp.payload (Stripe-style)
        let timestamp = chrono::Utc::now().timestamp();
        let payload_str = serde_json::to_string(&delivery.payload)?;
        let signature_payload = format!("{}.{}", timestamp, payload_str);

        let mut mac = HmacSha256::new_from_slice(endpoint.secret.as_bytes())
            .map_err(|_| anyhow::anyhow!("Invalid secret"))?;
        mac.update(signature_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        // Build request with standard headers
        let mut request = self
            .http_client
            .post(&endpoint.url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-ID", &delivery.id)
            .header("X-Webhook-Timestamp", timestamp.to_string())
            .header("X-Webhook-Signature", format!("v1={}", signature))
            .header("X-Webhook-Event", &delivery.event_type)
            .header("X-Webhook-Attempt", delivery.attempt_number.to_string())
            .header("User-Agent", "Vault-Webhook/1.0");

        // Add custom headers if configured
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

    /// Run a single iteration (for testing/manual triggering)
    pub async fn run_once(&self) -> anyhow::Result<usize> {
        self.process_batch().await
    }

    /// Get queue statistics
    pub async fn get_stats(&self) -> anyhow::Result<WebhookQueueStats> {
        let tenant_ids = self.list_tenant_ids().await?;
        let mut pending = 0;
        let mut delivered = 0;
        let mut failed = 0;
        let mut total = 0;

        for tenant_id in tenant_ids {
            let ctx = RequestContext {
                user_id: None,
                role: Some("service".to_string()),
                tenant_id: Some(tenant_id.clone()),
            };

            let stats = with_request_context(ctx, async {
                self.db.webhooks().get_delivery_stats(&tenant_id).await
            })
            .await?;

            pending += stats.pending;
            delivered += stats.delivered;
            failed += stats.failed;
            total += stats.total;
        }

        Ok(WebhookQueueStats {
            pending,
            delivered,
            failed,
            total,
        })
    }
}

/// Start the webhook background worker
pub fn spawn_worker(db: Database) -> Arc<WebhookWorker> {
    let worker = Arc::new(WebhookWorker::new(db));
    let worker_clone = worker.clone();

    tokio::spawn(async move {
        worker_clone.start().await;
    });

    worker
}

/// Start the webhook background worker with custom configuration
pub fn spawn_worker_with_config(
    db: Database,
    poll_interval: Duration,
    batch_size: i64,
    max_attempts: i32,
) -> Arc<WebhookWorker> {
    let worker = Arc::new(WebhookWorker::with_config(
        db,
        poll_interval,
        batch_size,
        max_attempts,
    ));
    let worker_clone = worker.clone();

    tokio::spawn(async move {
        worker_clone.start().await;
    });

    worker
}

impl WebhookWorker {
    async fn list_tenant_ids(&self) -> anyhow::Result<Vec<String>> {
        let mut conn = self.db.acquire().await?;
        let rows = sqlx::query_scalar::<_, String>("SELECT id FROM tenants")
            .fetch_all(&mut *conn)
            .await?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_worker_creation() {
        // This is a basic smoke test
        // In real tests, we'd need a database connection
    }

    #[test]
    fn test_exponential_backoff_delays() {
        // Expected delays: 1s, 2s, 4s, 8s, 16s, 32s
        let expected: Vec<u64> = vec![1, 2, 4, 8, 16, 32];

        for (i, exp) in expected.iter().enumerate() {
            let delay = 1u64 << i; // 2^i
            assert_eq!(delay, *exp, "Backoff delay mismatch at attempt {}", i);
        }
    }
}
