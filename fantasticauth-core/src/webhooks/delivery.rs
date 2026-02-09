//! Webhook delivery management
//!
//! Handles delivery attempts, retries, and background workers.

use super::{WebhookAttempt, WebhookDeliveryStatus, WebhookError, WebhookService, WebhookStore};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::{interval, Duration};

/// Webhook delivery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    /// Delivery ID
    pub id: String,
    /// Endpoint ID
    pub endpoint_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Event type
    pub event_type: String,
    /// Payload (JSON string)
    pub payload: String,
    /// Payload size in bytes
    pub payload_size: i32,
    /// Delivery status
    pub status: WebhookDeliveryStatus,
    /// Delivery attempts
    pub attempts: Vec<WebhookAttempt>,
    /// Next attempt timestamp
    pub next_attempt_at: Option<DateTime<Utc>>,
    /// Delivered timestamp
    pub delivered_at: Option<DateTime<Utc>>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Delivery status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "webhook_delivery_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum WebhookDeliveryStatus {
    /// Waiting to be delivered
    Pending,
    /// Delivery in progress
    InProgress,
    /// Successfully delivered
    Delivered,
    /// Failed, will retry
    Retrying,
    /// Failed permanently
    Failed,
}

impl std::fmt::Display for WebhookDeliveryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookDeliveryStatus::Pending => write!(f, "pending"),
            WebhookDeliveryStatus::InProgress => write!(f, "in_progress"),
            WebhookDeliveryStatus::Delivered => write!(f, "delivered"),
            WebhookDeliveryStatus::Retrying => write!(f, "retrying"),
            WebhookDeliveryStatus::Failed => write!(f, "failed"),
        }
    }
}

/// Webhook worker for background delivery
pub struct WebhookWorker {
    service: Arc<WebhookService>,
    poll_interval: Duration,
    batch_size: i64,
}

impl WebhookWorker {
    /// Create new worker
    pub fn new(service: Arc<WebhookService>, poll_interval: Duration, batch_size: i64) -> Self {
        Self {
            service,
            poll_interval,
            batch_size,
        }
    }
    
    /// Create with defaults (30 second poll, batch of 100)
    pub fn with_defaults(service: Arc<WebhookService>) -> Self {
        Self::new(service, Duration::from_secs(30), 100)
    }
    
    /// Start the worker loop
    pub async fn start(self) {
        let mut interval = interval(self.poll_interval);
        
        loop {
            interval.tick().await;
            
            if let Err(e) = self.process_batch().await {
                tracing::error!("Webhook worker error: {}", e);
            }
        }
    }
    
    /// Process a batch of pending deliveries
    async fn process_batch(&self) -> Result<(), WebhookError> {
        let deliveries = self
            .service
            .claim_pending_deliveries(self.batch_size)
            .await?;

        for mut delivery in deliveries {
            if let Err(e) = self.service.deliver(&mut delivery).await {
                tracing::warn!("Webhook delivery failed: {}", e);
            }
        }

        Ok(())
    }
    
    /// Run worker for a single iteration (for testing)
    pub async fn run_once(&self) -> Result<usize, WebhookError> {
        let deliveries = self
            .service
            .claim_pending_deliveries(self.batch_size)
            .await?;

        let count = deliveries.len();
        for mut delivery in deliveries {
            if let Err(e) = self.service.deliver(&mut delivery).await {
                tracing::warn!("Webhook delivery failed: {}", e);
            }
        }

        Ok(count)
    }
}

/// Delivery metrics
#[derive(Debug, Clone, Default)]
pub struct DeliveryMetrics {
    /// Total deliveries attempted
    pub total_attempts: u64,
    /// Successful deliveries
    pub successful: u64,
    /// Failed deliveries
    pub failed: u64,
    /// Retries performed
    pub retries: u64,
    /// Average latency in ms
    pub average_latency_ms: f64,
}

/// SQLx delivery store
pub struct SqlxWebhookStore {
    pool: sqlx::PgPool,
}

impl SqlxWebhookStore {
    /// Create new store
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl WebhookStore for SqlxWebhookStore {
    async fn create_endpoint(
        &self,
        endpoint: super::WebhookEndpoint,
    ) -> Result<super::WebhookEndpoint, WebhookError> {
        sqlx::query_as::<_, super::WebhookEndpoint>(
            r#"
            INSERT INTO webhook_endpoints (
                id, tenant_id, url, description, events, secret,
                active, headers, max_retries, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING *
            "#
        )
        .bind(&endpoint.id)
        .bind(&endpoint.tenant_id)
        .bind(&endpoint.url)
        .bind(&endpoint.description)
        .bind(&endpoint.events)
        .bind(&endpoint.secret)
        .bind(endpoint.active)
        .bind(serde_json::to_value(&endpoint.headers).unwrap_or_default())
        .bind(endpoint.max_retries)
        .bind(endpoint.created_at)
        .bind(endpoint.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| WebhookError::Store(e.to_string()))
    }
    
    async fn get_endpoint(&self, id: &str) -> Result<super::WebhookEndpoint, WebhookError> {
        sqlx::query_as::<_, super::WebhookEndpoint>(
            "SELECT * FROM webhook_endpoints WHERE id = $1"
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => WebhookError::NotFound,
            _ => WebhookError::Store(e.to_string()),
        })
    }
    
    async fn list_endpoints(
        &self,
        tenant_id: &str,
        active_only: bool,
    ) -> Result<Vec<super::WebhookEndpoint>, WebhookError> {
        let query = if active_only {
            "SELECT * FROM webhook_endpoints WHERE tenant_id = $1 AND active = true"
        } else {
            "SELECT * FROM webhook_endpoints WHERE tenant_id = $1"
        };
        
        sqlx::query_as::<_, super::WebhookEndpoint>(query)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| WebhookError::Store(e.to_string()))
    }
    
    async fn update_endpoint(
        &self,
        endpoint: super::WebhookEndpoint,
    ) -> Result<super::WebhookEndpoint, WebhookError> {
        sqlx::query_as::<_, super::WebhookEndpoint>(
            r#"
            UPDATE webhook_endpoints SET
                url = $2,
                description = $3,
                events = $4,
                active = $5,
                headers = $6,
                max_retries = $7,
                updated_at = $8
            WHERE id = $1
            RETURNING *
            "#
        )
        .bind(&endpoint.id)
        .bind(&endpoint.url)
        .bind(&endpoint.description)
        .bind(&endpoint.events)
        .bind(endpoint.active)
        .bind(serde_json::to_value(&endpoint.headers).unwrap_or_default())
        .bind(endpoint.max_retries)
        .bind(Utc::now())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| WebhookError::Store(e.to_string()))
    }
    
    async fn delete_endpoint(&self, id: &str) -> Result<(), WebhookError> {
        sqlx::query("DELETE FROM webhook_endpoints WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| WebhookError::Store(e.to_string()))?;
        
        Ok(())
    }
    
    async fn store_delivery(&self, delivery: WebhookDelivery) -> Result<(), WebhookError> {
        sqlx::query(
            r#"
            INSERT INTO webhook_deliveries (
                id, endpoint_id, tenant_id, event_type, payload,
                payload_size, status, attempts, next_attempt_at,
                delivered_at, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#
        )
        .bind(&delivery.id)
        .bind(&delivery.endpoint_id)
        .bind(&delivery.tenant_id)
        .bind(&delivery.event_type)
        .bind(&delivery.payload)
        .bind(delivery.payload_size)
        .bind(delivery.status)
        .bind(serde_json::to_value(&delivery.attempts).unwrap_or_default())
        .bind(delivery.next_attempt_at)
        .bind(delivery.delivered_at)
        .bind(delivery.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| WebhookError::Store(e.to_string()))?;
        
        Ok(())
    }
    
    async fn get_delivery(&self, id: &str) -> Result<WebhookDelivery, WebhookError> {
        let row = sqlx::query(
            "SELECT * FROM webhook_deliveries WHERE id = $1"
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => WebhookError::NotFound,
            _ => WebhookError::Store(e.to_string()),
        })?;
        
        Ok(WebhookDelivery {
            id: row.try_get("id").map_err(|e| WebhookError::Store(e.to_string()))?,
            endpoint_id: row.try_get("endpoint_id").map_err(|e| WebhookError::Store(e.to_string()))?,
            tenant_id: row.try_get("tenant_id").map_err(|e| WebhookError::Store(e.to_string()))?,
            event_type: row.try_get("event_type").map_err(|e| WebhookError::Store(e.to_string()))?,
            payload: row.try_get("payload").map_err(|e| WebhookError::Store(e.to_string()))?,
            payload_size: row.try_get("payload_size").map_err(|e| WebhookError::Store(e.to_string()))?,
            status: row.try_get("status").map_err(|e| WebhookError::Store(e.to_string()))?,
            attempts: serde_json::from_value(
                row.try_get::<serde_json::Value, _>("attempts").map_err(|e| WebhookError::Store(e.to_string()))?
            ).map_err(|e| WebhookError::Store(e.to_string()))?,
            next_attempt_at: row.try_get("next_attempt_at").map_err(|e| WebhookError::Store(e.to_string()))?,
            delivered_at: row.try_get("delivered_at").map_err(|e| WebhookError::Store(e.to_string()))?,
            created_at: row.try_get("created_at").map_err(|e| WebhookError::Store(e.to_string()))?,
        })
    }
    
    async fn list_pending_deliveries(
        &self,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>, WebhookError> {
        let rows = sqlx::query(
            r#"
            SELECT * FROM webhook_deliveries
            WHERE status IN ('pending', 'retrying')
              AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
            ORDER BY created_at ASC
            LIMIT $1
            "#
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| WebhookError::Store(e.to_string()))?;
        
        let mut deliveries = Vec::new();
        for row in rows {
            deliveries.push(WebhookDelivery {
                id: row.try_get("id").map_err(|e| WebhookError::Store(e.to_string()))?,
                endpoint_id: row.try_get("endpoint_id").map_err(|e| WebhookError::Store(e.to_string()))?,
                tenant_id: row.try_get("tenant_id").map_err(|e| WebhookError::Store(e.to_string()))?,
                event_type: row.try_get("event_type").map_err(|e| WebhookError::Store(e.to_string()))?,
                payload: row.try_get("payload").map_err(|e| WebhookError::Store(e.to_string()))?,
                payload_size: row.try_get("payload_size").map_err(|e| WebhookError::Store(e.to_string()))?,
                status: row.try_get("status").map_err(|e| WebhookError::Store(e.to_string()))?,
                attempts: serde_json::from_value(
                    row.try_get::<serde_json::Value, _>("attempts").map_err(|e| WebhookError::Store(e.to_string()))?
                ).map_err(|e| WebhookError::Store(e.to_string()))?,
                next_attempt_at: row.try_get("next_attempt_at").map_err(|e| WebhookError::Store(e.to_string()))?,
                delivered_at: row.try_get("delivered_at").map_err(|e| WebhookError::Store(e.to_string()))?,
                created_at: row.try_get("created_at").map_err(|e| WebhookError::Store(e.to_string()))?,
            });
        }
        
        Ok(deliveries)
    }

    async fn claim_pending_deliveries(
        &self,
        limit: i64,
        in_progress_timeout_seconds: u64,
    ) -> Result<Vec<WebhookDelivery>, WebhookError> {
        let rows = sqlx::query(
            r#"
            WITH cte AS (
                SELECT id
                FROM webhook_deliveries
                WHERE status IN ('pending', 'retrying', 'in_progress')
                  AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
                ORDER BY next_attempt_at NULLS FIRST, created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT $1
            )
            UPDATE webhook_deliveries d
            SET status = 'in_progress',
                next_attempt_at = NOW() + ($2::bigint * INTERVAL '1 second')
            FROM cte
            WHERE d.id = cte.id
            RETURNING d.*
            "#
        )
        .bind(limit)
        .bind(in_progress_timeout_seconds as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| WebhookError::Store(e.to_string()))?;

        let mut deliveries = Vec::new();
        for row in rows {
            deliveries.push(WebhookDelivery {
                id: row.try_get("id").map_err(|e| WebhookError::Store(e.to_string()))?,
                endpoint_id: row
                    .try_get("endpoint_id")
                    .map_err(|e| WebhookError::Store(e.to_string()))?,
                tenant_id: row
                    .try_get("tenant_id")
                    .map_err(|e| WebhookError::Store(e.to_string()))?,
                event_type: row
                    .try_get("event_type")
                    .map_err(|e| WebhookError::Store(e.to_string()))?,
                payload: row.try_get("payload").map_err(|e| WebhookError::Store(e.to_string()))?,
                payload_size: row
                    .try_get("payload_size")
                    .map_err(|e| WebhookError::Store(e.to_string()))?,
                status: row.try_get("status").map_err(|e| WebhookError::Store(e.to_string()))?,
                attempts: serde_json::from_value(
                    row.try_get::<serde_json::Value, _>("attempts")
                        .map_err(|e| WebhookError::Store(e.to_string()))?,
                )
                .map_err(|e| WebhookError::Store(e.to_string()))?,
                next_attempt_at: row
                    .try_get("next_attempt_at")
                    .map_err(|e| WebhookError::Store(e.to_string()))?,
                delivered_at: row
                    .try_get("delivered_at")
                    .map_err(|e| WebhookError::Store(e.to_string()))?,
                created_at: row
                    .try_get("created_at")
                    .map_err(|e| WebhookError::Store(e.to_string()))?,
            });
        }

        Ok(deliveries)
    }
    
    async fn update_delivery(&self, delivery: WebhookDelivery) -> Result<(), WebhookError> {
        sqlx::query(
            r#"
            UPDATE webhook_deliveries SET
                status = $2,
                attempts = $3,
                next_attempt_at = $4,
                delivered_at = $5
            WHERE id = $1
            "#
        )
        .bind(&delivery.id)
        .bind(delivery.status)
        .bind(serde_json::to_value(&delivery.attempts).unwrap_or_default())
        .bind(delivery.next_attempt_at)
        .bind(delivery.delivered_at)
        .execute(&self.pool)
        .await
        .map_err(|e| WebhookError::Store(e.to_string()))?;
        
        Ok(())
    }
}

/// Database migration for webhooks tables
pub const WEBHOOKS_MIGRATION: &str = r#"
-- Webhook endpoints table
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    description TEXT,
    events TEXT[] NOT NULL,
    secret TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    headers JSONB NOT NULL DEFAULT '{}',
    max_retries INTEGER NOT NULL DEFAULT 4,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Webhook deliveries table
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    endpoint_id UUID NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    payload_size INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts JSONB NOT NULL DEFAULT '[]',
    next_attempt_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_tenant 
ON webhook_endpoints(tenant_id);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status 
ON webhook_deliveries(status, next_attempt_at);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint 
ON webhook_deliveries(endpoint_id);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_tenant 
ON webhook_deliveries(tenant_id);
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhooks::WebhookConfig;
    use mockall::mock;
    use tokio::runtime::Runtime;

    mock! {
        WebhookStore {}

        #[async_trait::async_trait]
        impl WebhookStore for WebhookStore {
            async fn create_endpoint(&self, endpoint: super::super::WebhookEndpoint) -> Result<super::super::WebhookEndpoint, WebhookError>;
            async fn get_endpoint(&self, id: &str) -> Result<super::super::WebhookEndpoint, WebhookError>;
            async fn list_endpoints(
                &self,
                tenant_id: &str,
                active_only: bool,
            ) -> Result<Vec<super::super::WebhookEndpoint>, WebhookError>;
            async fn update_endpoint(&self, endpoint: super::super::WebhookEndpoint) -> Result<super::super::WebhookEndpoint, WebhookError>;
            async fn delete_endpoint(&self, id: &str) -> Result<(), WebhookError>;
            async fn store_delivery(&self, delivery: WebhookDelivery) -> Result<(), WebhookError>;
            async fn get_delivery(&self, id: &str) -> Result<WebhookDelivery, WebhookError>;
            async fn list_pending_deliveries(&self, limit: i64) -> Result<Vec<WebhookDelivery>, WebhookError>;
            async fn claim_pending_deliveries(
                &self,
                limit: i64,
                in_progress_timeout_seconds: u64,
            ) -> Result<Vec<WebhookDelivery>, WebhookError>;
            async fn update_delivery(&self, delivery: WebhookDelivery) -> Result<(), WebhookError>;
        }
    }

    #[test]
    fn test_worker_claims_pending_deliveries() {
        let mut store = MockWebhookStore::new();
        store
            .expect_claim_pending_deliveries()
            .withf(|limit, timeout| *limit == 5 && *timeout == 300)
            .returning(|_, _| Ok(Vec::new()));

        let mut config = WebhookConfig::default();
        config.in_progress_timeout_seconds = 300;

        let service = WebhookService::new(config, Box::new(store));
        let worker = WebhookWorker::new(Arc::new(service), Duration::from_secs(1), 5);
        let rt = Runtime::new().expect("runtime");

        rt.block_on(async {
            let count = worker.run_once().await.expect("run_once");
            assert_eq!(count, 0);
        });
    }
}
