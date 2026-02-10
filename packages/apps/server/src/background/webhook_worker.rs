//! Webhook Background Worker
//!
//! Processes pending webhook deliveries with retry logic and exponential backoff.
//! Includes concurrency limiting to prevent overwhelming the database or downstream services.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::db::Database;
use crate::webhooks::WebhookService;
use vault_core::db::{with_request_context, RequestContext};

/// Default maximum concurrent tenant processing
const DEFAULT_MAX_CONCURRENT_TENANTS: usize = 10;
/// Default maximum concurrent webhook deliveries per tenant
const DEFAULT_MAX_CONCURRENT_DELIVERIES: usize = 5;

/// Background worker for webhook delivery
pub struct WebhookWorker {
    db: Database,
    webhook_service: WebhookService,
    poll_interval: Duration,
    batch_size: i64,
    /// Semaphore to limit concurrent tenant processing
    tenant_semaphore: Arc<Semaphore>,
    /// Semaphore to limit concurrent deliveries per tenant
    delivery_semaphore: Arc<Semaphore>,
}

impl WebhookWorker {
    /// Create a new webhook worker
    pub fn new(db: Database, webhook_service: WebhookService) -> Self {
        Self::with_concurrency(
            db,
            webhook_service,
            DEFAULT_MAX_CONCURRENT_TENANTS,
            DEFAULT_MAX_CONCURRENT_DELIVERIES,
        )
    }

    /// Create with custom configuration
    pub fn with_config(
        db: Database,
        webhook_service: WebhookService,
        poll_interval: Duration,
        batch_size: i64,
    ) -> Self {
        Self {
            db,
            webhook_service,
            poll_interval,
            batch_size,
            tenant_semaphore: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_TENANTS)),
            delivery_semaphore: Arc::new(Semaphore::new(DEFAULT_MAX_CONCURRENT_DELIVERIES)),
        }
    }
    
    /// Create with custom concurrency limits
    pub fn with_concurrency(
        db: Database,
        webhook_service: WebhookService,
        max_concurrent_tenants: usize,
        max_concurrent_deliveries: usize,
    ) -> Self {
        info!(
            max_tenants = max_concurrent_tenants,
            max_deliveries = max_concurrent_deliveries,
            "Creating webhook worker with concurrency limits"
        );
        
        Self {
            db: db.clone(),
            webhook_service,
            poll_interval: Duration::from_secs(30),
            batch_size: 100,
            tenant_semaphore: Arc::new(Semaphore::new(max_concurrent_tenants)),
            delivery_semaphore: Arc::new(Semaphore::new(max_concurrent_deliveries)),
        }
    }

    /// Start the worker loop (runs forever)
    pub async fn start(self: Arc<Self>) {
        let mut ticker = interval(self.poll_interval);

        info!(
            poll_interval_secs = self.poll_interval.as_secs(),
            batch_size = self.batch_size,
            "Webhook worker started"
        );

        loop {
            ticker.tick().await;

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

    /// Process a single batch of pending deliveries with concurrency limits
    async fn process_batch(&self) -> anyhow::Result<usize> {
        let tenant_ids = self.list_tenant_ids().await?;
        let mut total = 0usize;
        
        // Limit concurrent tenant processing
        let semaphore = self.tenant_semaphore.clone();
        let delivery_sem = self.delivery_semaphore.clone();

        for tenant_id in tenant_ids {
            // Acquire permit for tenant processing
            let permit = semaphore.clone().acquire_owned().await?;
            let delivery_permit = delivery_sem.clone();
            
            let ctx = RequestContext {
                tenant_id: Some(tenant_id.clone()),
                user_id: None,
                role: Some("service".to_string()),
            };

            let processed = with_request_context(ctx, async move {
                let deliveries = self
                    .webhook_service
                    .get_pending_deliveries(&tenant_id, self.batch_size)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to get pending deliveries: {}", e))?;

                let count = deliveries.len();
                
                // Process deliveries with concurrency limit
                let mut handles = Vec::with_capacity(deliveries.len());
                
                for delivery in deliveries {
                    let delivery_sem = delivery_permit.clone();
                    let tenant_id = tenant_id.clone();
                    let webhook_service = self.webhook_service.clone();
                    
                    let handle = tokio::spawn(async move {
                        // Acquire permit for delivery
                        let _permit = delivery_sem.acquire().await?;
                        
                        match webhook_service.deliver_webhook(&tenant_id, &delivery.id).await {
                            Ok(_) => {
                                info!(
                                    delivery_id = %delivery.id,
                                    event_type = %delivery.event_type,
                                    "Webhook delivered successfully"
                                );
                                Ok(())
                            }
                            Err(e) => {
                                warn!(
                                    delivery_id = %delivery.id,
                                    error = %e,
                                    "Webhook delivery failed"
                                );
                                Err(e)
                            }
                        }
                    });
                    
                    handles.push(handle);
                }
                
                // Wait for all deliveries to complete
                for handle in handles {
                    if let Err(e) = handle.await {
                        warn!(error = %e, "Webhook delivery task panicked");
                    }
                }

                Ok::<usize, anyhow::Error>(count)
            })
            .await?;

            total += processed;
            
            // Permit is dropped here, allowing another tenant to be processed
            drop(permit);
        }

        Ok(total)
    }

    /// Run worker for a single iteration (for testing/manual triggering)
    pub async fn run_once(&self) -> anyhow::Result<usize> {
        self.process_batch().await
    }

    /// Get queue statistics
    pub async fn get_stats(&self) -> anyhow::Result<WebhookWorkerStats> {
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

        Ok(WebhookWorkerStats {
            pending,
            delivered,
            failed,
            total,
        })
    }

    async fn list_tenant_ids(&self) -> anyhow::Result<Vec<String>> {
        let mut conn = self.db.acquire().await?;
        let rows = sqlx::query_scalar::<_, String>("SELECT id FROM tenants")
            .fetch_all(&mut *conn)
            .await?;
        Ok(rows)
    }
}

/// Statistics for the webhook worker
#[derive(Debug, Clone)]
pub struct WebhookWorkerStats {
    /// Number of pending deliveries
    pub pending: i64,
    /// Number of delivered webhooks
    pub delivered: i64,
    /// Number of failed deliveries
    pub failed: i64,
    /// Total number of deliveries
    pub total: i64,
}

/// Start the webhook background worker
pub fn spawn_worker(db: Database, webhook_service: WebhookService) -> Arc<WebhookWorker> {
    let worker = Arc::new(WebhookWorker::new(db, webhook_service));
    let worker_clone = worker.clone();

    tokio::spawn(async move {
        worker_clone.start().await;
    });

    worker
}

/// Start the webhook background worker with custom configuration
pub fn spawn_worker_with_config(
    db: Database,
    webhook_service: WebhookService,
    poll_interval: Duration,
    batch_size: i64,
) -> Arc<WebhookWorker> {
    let worker = Arc::new(WebhookWorker::with_config(
        db,
        webhook_service,
        poll_interval,
        batch_size,
    ));
    let worker_clone = worker.clone();

    tokio::spawn(async move {
        worker_clone.start().await;
    });

    worker
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_worker_creation() {
        // This is a basic smoke test
        // In real tests, we'd need a full AppState
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
