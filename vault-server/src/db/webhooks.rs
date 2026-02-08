use crate::webhooks::{WebhookDelivery, WebhookEndpoint, WebhookEndpointUpdate, WebhookQueueStats};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sqlx::PgPool;
use vault_core::db::set_connection_context;

/// Repository for webhook operations
#[derive(Clone)]
pub struct WebhookRepository {
    pool: PgPool,
}

impl WebhookRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn tenant_conn(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        let mut conn = self.pool.acquire().await?;
        set_connection_context(&mut conn, tenant_id).await?;
        Ok(conn)
    }

    /// Create a new webhook endpoint
    pub async fn create_endpoint(
        &self,
        tenant_id: &str,
        name: &str,
        url: &str,
        events: Vec<String>,
        secret: String,
        description: Option<String>,
        headers: Option<Value>,
    ) -> anyhow::Result<WebhookEndpoint> {
        let events_json = serde_json::to_value(&events)?;
        let mut conn = self.tenant_conn(tenant_id).await?;

        let row = sqlx::query_as::<_, WebhookEndpointRow>(
            r#"INSERT INTO webhook_endpoints 
               (tenant_id, name, url, secret, events, description, headers)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING id, tenant_id, name, url, secret, events, active, description, headers, max_retries, created_at, updated_at"#
        )
        .bind(tenant_id)
        .bind(name)
        .bind(url)
        .bind(secret)
        .bind(events_json)
        .bind(description)
        .bind(headers)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Update a webhook endpoint
    pub async fn update_endpoint(
        &self,
        tenant_id: &str,
        endpoint_id: &str,
        updates: WebhookEndpointUpdate,
    ) -> anyhow::Result<WebhookEndpoint> {
        let current = self.get_endpoint(tenant_id, endpoint_id).await?;
        let mut conn = self.tenant_conn(tenant_id).await?;

        let name = updates.name.unwrap_or(current.name);
        let url = updates.url.unwrap_or(current.url);
        let events = updates
            .events
            .map(|e| serde_json::to_value(&e).unwrap())
            .unwrap_or(serde_json::to_value(&current.events)?);
        let secret = updates.secret.unwrap_or(current.secret);
        let description = updates.description.or(current.description);
        let headers = updates.headers.or(current.headers);
        let active = updates.active.unwrap_or(current.active);
        let max_retries = updates.max_retries.unwrap_or(current.max_retries);

        let row = sqlx::query_as::<_, WebhookEndpointRow>(
            r#"UPDATE webhook_endpoints 
               SET name = $1, url = $2, events = $3, secret = $4, description = $5, 
                   headers = $6, active = $7, max_retries = $8, updated_at = NOW()
               WHERE id = $9 AND tenant_id = $10 AND deleted_at IS NULL
               RETURNING id, tenant_id, name, url, secret, events, active, description, headers, max_retries, created_at, updated_at"#
        )
        .bind(name)
        .bind(url)
        .bind(events)
        .bind(secret)
        .bind(description)
        .bind(headers)
        .bind(active)
        .bind(max_retries)
        .bind(endpoint_id)
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Delete (soft delete) a webhook endpoint
    pub async fn delete_endpoint(&self, tenant_id: &str, endpoint_id: &str) -> anyhow::Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"UPDATE webhook_endpoints 
               SET deleted_at = NOW() 
               WHERE id = $1 AND tenant_id = $2"#,
        )
        .bind(endpoint_id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Get a webhook endpoint by ID
    pub async fn get_endpoint(
        &self,
        tenant_id: &str,
        endpoint_id: &str,
    ) -> anyhow::Result<WebhookEndpoint> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, WebhookEndpointRow>(
            r#"SELECT id, tenant_id, name, url, secret, events, active, description, headers, max_retries, created_at, updated_at
               FROM admin_webhook_endpoints 
               WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL"#
        )
        .bind(endpoint_id)
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// List webhook endpoints for a tenant
    pub async fn list_endpoints(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> anyhow::Result<(Vec<WebhookEndpoint>, i64)> {
        let page = page.max(1);
        let per_page = per_page.clamp(1, 100);
        let offset = (page - 1) * per_page;
        let mut conn = self.tenant_conn(tenant_id).await?;

        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM admin_webhook_endpoints WHERE tenant_id = $1 AND deleted_at IS NULL"#
        )
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        let rows = sqlx::query_as::<_, WebhookEndpointRow>(
            r#"SELECT id, tenant_id, name, url, secret, events, active, description, headers, max_retries, created_at, updated_at
               FROM admin_webhook_endpoints 
               WHERE tenant_id = $1 AND deleted_at IS NULL
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3"#
        )
        .bind(tenant_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(&mut *conn)
        .await?;

        let items = rows.into_iter().map(|r| r.into()).collect();

        Ok((items, total))
    }

    /// Get active endpoints that subscribe to a specific event
    pub async fn get_active_endpoints_for_event(
        &self,
        tenant_id: &str,
        event_type: &str,
    ) -> anyhow::Result<Vec<WebhookEndpoint>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, WebhookEndpointRow>(
            r#"SELECT id, tenant_id, name, url, secret, events, active, description, headers, max_retries, created_at, updated_at
               FROM admin_webhook_endpoints 
               WHERE tenant_id = $1 AND active = TRUE AND deleted_at IS NULL
               AND events @> $2::jsonb"#
        )
        .bind(tenant_id)
        .bind(serde_json::json!([event_type]))
        .fetch_all(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Create a new delivery record
    pub async fn create_delivery(
        &self,
        endpoint_id: &str,
        tenant_id: &str,
        event_type: &str,
        payload: Value,
        payload_size: i32,
    ) -> anyhow::Result<WebhookDelivery> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, WebhookDeliveryRow>(
            r#"INSERT INTO webhook_deliveries 
               (endpoint_id, tenant_id, event_type, payload, payload_size, status)
               VALUES ($1, $2, $3, $4, $5, 'pending')
               RETURNING id, endpoint_id, tenant_id, event_type, payload, payload_size, attempt_number, status,
                         http_status_code, response_body, response_headers, error_message, duration_ms,
                         scheduled_at, delivered_at, created_at"#
        )
        .bind(endpoint_id)
        .bind(tenant_id)
        .bind(event_type)
        .bind(payload)
        .bind(payload_size)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Get a delivery by ID
    pub async fn get_delivery(
        &self,
        tenant_id: &str,
        delivery_id: &str,
    ) -> anyhow::Result<WebhookDelivery> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, WebhookDeliveryRow>(
            r#"SELECT id, endpoint_id, tenant_id, event_type, payload, payload_size, attempt_number, status,
                      http_status_code, response_body, response_headers, error_message, duration_ms,
                      scheduled_at, delivered_at, created_at
               FROM admin_webhook_deliveries 
               WHERE id = $1 AND tenant_id = $2"#
        )
        .bind(delivery_id)
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Get pending deliveries
    pub async fn get_pending_deliveries(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<WebhookDelivery>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, WebhookDeliveryRow>(
            r#"SELECT id, endpoint_id, tenant_id, event_type, payload, payload_size, attempt_number, status,
                      http_status_code, response_body, response_headers, error_message, duration_ms,
                      scheduled_at, delivered_at, created_at
               FROM admin_webhook_deliveries 
               WHERE tenant_id = $1 AND status = 'pending' AND scheduled_at <= NOW()
               ORDER BY created_at ASC
               LIMIT $2"#
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Mark a delivery as delivered
    pub async fn mark_delivered(
        &self,
        tenant_id: &str,
        delivery_id: &str,
        http_status_code: i32,
        response_body: Option<String>,
        response_headers: Option<Value>,
    ) -> anyhow::Result<WebhookDelivery> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, WebhookDeliveryRow>(
            r#"UPDATE webhook_deliveries 
               SET status = 'delivered', http_status_code = $2, response_body = $3, 
                   response_headers = $4, delivered_at = NOW()
               WHERE id = $1 AND tenant_id = $5
               RETURNING id, endpoint_id, tenant_id, event_type, payload, payload_size, attempt_number, status,
                         http_status_code, response_body, response_headers, error_message, duration_ms,
                         scheduled_at, delivered_at, created_at"#
        )
        .bind(delivery_id)
        .bind(http_status_code)
        .bind(response_body)
        .bind(response_headers)
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Mark a delivery as failed
    ///
    /// Uses exponential backoff for retries: 1s, 2s, 4s, 8s, 16s, 32s
    pub async fn mark_failed(
        &self,
        tenant_id: &str,
        delivery_id: &str,
        error_message: &str,
        should_retry: bool,
    ) -> anyhow::Result<WebhookDelivery> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        // Get current attempt number to calculate backoff
        let current_attempt: i32 = sqlx::query_scalar(
            "SELECT attempt_number FROM webhook_deliveries WHERE id = $1 AND tenant_id = $2",
        )
        .bind(delivery_id)
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        let scheduled_at = if should_retry {
            // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s
            // Using attempt_number as the exponent (0-indexed)
            let backoff_seconds = 1i64 << (current_attempt as i64); // 2^attempt
            Utc::now() + Duration::seconds(backoff_seconds)
        } else {
            Utc::now()
        };

        let status = if should_retry { "pending" } else { "failed" };

        let row = sqlx::query_as::<_, WebhookDeliveryRow>(
            r#"UPDATE webhook_deliveries 
               SET status = $2, error_message = $3, scheduled_at = $4,
                   attempt_number = attempt_number + 1
               WHERE id = $1 AND tenant_id = $5
               RETURNING id, endpoint_id, tenant_id, event_type, payload, payload_size, attempt_number, status,
                         http_status_code, response_body, response_headers, error_message, duration_ms,
                         scheduled_at, delivered_at, created_at"#
        )
        .bind(delivery_id)
        .bind(status)
        .bind(error_message)
        .bind(scheduled_at)
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Reset a delivery for retry
    pub async fn reset_delivery_for_retry(
        &self,
        tenant_id: &str,
        delivery_id: &str,
    ) -> anyhow::Result<WebhookDelivery> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, WebhookDeliveryRow>(
            r#"UPDATE webhook_deliveries 
               SET status = 'pending', attempt_number = 1, scheduled_at = NOW(),
                   error_message = NULL, http_status_code = NULL, response_body = NULL
               WHERE id = $1 AND tenant_id = $2
               RETURNING id, endpoint_id, tenant_id, event_type, payload, payload_size, attempt_number, status,
                         http_status_code, response_body, response_headers, error_message, duration_ms,
                         scheduled_at, delivered_at, created_at"#
        )
        .bind(delivery_id)
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// List deliveries for an endpoint
    pub async fn list_deliveries(
        &self,
        tenant_id: &str,
        endpoint_id: &str,
        page: i64,
        per_page: i64,
    ) -> anyhow::Result<(Vec<WebhookDelivery>, i64)> {
        let page = page.max(1);
        let per_page = per_page.clamp(1, 100);
        let offset = (page - 1) * per_page;
        let mut conn = self.tenant_conn(tenant_id).await?;

        let total: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM admin_webhook_deliveries WHERE tenant_id = $1 AND endpoint_id = $2"#
        )
        .bind(tenant_id)
        .bind(endpoint_id)
        .fetch_one(&mut *conn)
        .await?;

        let rows = sqlx::query_as::<_, WebhookDeliveryRow>(
            r#"SELECT id, endpoint_id, tenant_id, event_type, payload, payload_size, attempt_number, status,
                      http_status_code, response_body, response_headers, error_message, duration_ms,
                      scheduled_at, delivered_at, created_at
               FROM admin_webhook_deliveries 
               WHERE tenant_id = $1 AND endpoint_id = $2
               ORDER BY created_at DESC
               LIMIT $3 OFFSET $4"#
        )
        .bind(tenant_id)
        .bind(endpoint_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(&mut *conn)
        .await?;

        let items = rows.into_iter().map(|r| r.into()).collect();

        Ok((items, total))
    }

    /// Get delivery statistics
    pub async fn get_delivery_stats(&self, tenant_id: &str) -> anyhow::Result<WebhookQueueStats> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM admin_webhook_deliveries WHERE tenant_id = $1 AND status = 'pending'"
        )
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        let delivered: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM admin_webhook_deliveries WHERE tenant_id = $1 AND status = 'delivered'"
        )
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        let failed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM admin_webhook_deliveries WHERE tenant_id = $1 AND status = 'failed'"
        )
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM admin_webhook_deliveries WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(WebhookQueueStats {
            pending,
            delivered,
            failed,
            total,
        })
    }
}

#[derive(sqlx::FromRow)]
struct WebhookEndpointRow {
    id: String,
    tenant_id: String,
    name: String,
    url: String,
    secret: String,
    events: Value,
    active: bool,
    description: Option<String>,
    headers: Option<Value>,
    max_retries: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<WebhookEndpointRow> for WebhookEndpoint {
    fn from(row: WebhookEndpointRow) -> Self {
        let events = serde_json::from_value(row.events).unwrap_or_default();
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            url: row.url,
            secret: row.secret,
            events,
            active: row.active,
            description: row.description,
            headers: row.headers,
            max_retries: row.max_retries,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct WebhookDeliveryRow {
    id: String,
    endpoint_id: String,
    tenant_id: String,
    event_type: String,
    payload: Value,
    payload_size: i32,
    attempt_number: i32,
    status: String,
    http_status_code: Option<i32>,
    response_body: Option<String>,
    response_headers: Option<Value>,
    error_message: Option<String>,
    duration_ms: Option<i32>,
    scheduled_at: DateTime<Utc>,
    delivered_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<WebhookDeliveryRow> for WebhookDelivery {
    fn from(row: WebhookDeliveryRow) -> Self {
        Self {
            id: row.id,
            endpoint_id: row.endpoint_id,
            tenant_id: row.tenant_id,
            event_type: row.event_type,
            payload: row.payload,
            payload_size: row.payload_size,
            attempt_number: row.attempt_number,
            status: row.status,
            http_status_code: row.http_status_code,
            response_body: row.response_body,
            response_headers: row.response_headers,
            error_message: row.error_message,
            duration_ms: row.duration_ms,
            scheduled_at: row.scheduled_at,
            delivered_at: row.delivered_at,
            created_at: row.created_at,
        }
    }
}
