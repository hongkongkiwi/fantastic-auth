use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;

use crate::db::set_connection_context;
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LogStream {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub destination_type: String,
    pub config: serde_json::Value,
    pub filter: serde_json::Value,
    pub status: String,
    pub last_delivered_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LogDelivery {
    pub id: String,
    pub tenant_id: String,
    pub stream_id: String,
    pub audit_log_id: String,
    pub status: String,
    pub attempt_count: i32,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

pub struct LogStreamsRepository {
    pool: Arc<PgPool>,
}

impl LogStreamsRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    async fn tenant_conn(
        &self,
        tenant_id: &str,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        let mut conn = self.pool.acquire().await?;
        set_connection_context(&mut conn, tenant_id).await?;
        Ok(conn)
    }

    pub async fn list_streams(&self, tenant_id: &str) -> Result<Vec<LogStream>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let streams = sqlx::query_as::<_, LogStream>(
            r#"
            SELECT id::text, tenant_id::text, name, destination_type::text, config, filter,
                   status::text, last_delivered_at, last_error, created_at, updated_at
            FROM log_streams
            WHERE tenant_id = $1::uuid
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(streams)
    }

    pub async fn get_stream(&self, tenant_id: &str, stream_id: &str) -> Result<Option<LogStream>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let stream = sqlx::query_as::<_, LogStream>(
            r#"
            SELECT id::text, tenant_id::text, name, destination_type::text, config, filter,
                   status::text, last_delivered_at, last_error, created_at, updated_at
            FROM log_streams
            WHERE tenant_id = $1::uuid AND id = $2::uuid
            "#,
        )
        .bind(tenant_id)
        .bind(stream_id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(stream)
    }

    pub async fn create_stream(
        &self,
        tenant_id: &str,
        name: &str,
        destination_type: &str,
        config: serde_json::Value,
        filter: serde_json::Value,
        status: &str,
    ) -> Result<LogStream> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let stream = sqlx::query_as::<_, LogStream>(
            r#"
            INSERT INTO log_streams (tenant_id, name, destination_type, config, filter, status, created_at, updated_at)
            VALUES ($1::uuid, $2, $3::log_stream_type, $4, $5, $6::log_stream_status, NOW(), NOW())
            RETURNING id::text, tenant_id::text, name, destination_type::text, config, filter,
                      status::text, last_delivered_at, last_error, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(destination_type)
        .bind(config)
        .bind(filter)
        .bind(status)
        .fetch_one(&mut *conn)
        .await?;

        Ok(stream)
    }

    pub async fn update_stream(
        &self,
        tenant_id: &str,
        stream_id: &str,
        name: Option<&str>,
        config: Option<serde_json::Value>,
        filter: Option<serde_json::Value>,
        status: Option<&str>,
    ) -> Result<LogStream> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let stream = sqlx::query_as::<_, LogStream>(
            r#"
            UPDATE log_streams
            SET name = COALESCE($3, name),
                config = COALESCE($4, config),
                filter = COALESCE($5, filter),
                status = COALESCE($6, status),
                updated_at = NOW()
            WHERE tenant_id = $1::uuid AND id = $2::uuid
            RETURNING id::text, tenant_id::text, name, destination_type::text, config, filter,
                      status::text, last_delivered_at, last_error, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(stream_id)
        .bind(name)
        .bind(config)
        .bind(filter)
        .bind(status)
        .fetch_one(&mut *conn)
        .await?;

        Ok(stream)
    }

    pub async fn delete_stream(&self, tenant_id: &str, stream_id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"DELETE FROM log_streams WHERE tenant_id = $1::uuid AND id = $2::uuid"#,
        )
        .bind(tenant_id)
        .bind(stream_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    pub async fn record_delivery(
        &self,
        tenant_id: &str,
        stream_id: &str,
        audit_log_id: &str,
    ) -> Result<LogDelivery> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let delivery = sqlx::query_as::<_, LogDelivery>(
            r#"
            INSERT INTO log_stream_deliveries (
                tenant_id, stream_id, audit_log_id, status, created_at
            ) VALUES ($1::uuid, $2::uuid, $3::uuid, 'pending', NOW())
            RETURNING id::text, tenant_id::text, stream_id::text, audit_log_id::text, status::text,
                      attempt_count, last_attempt_at, next_attempt_at, error, created_at, delivered_at
            "#,
        )
        .bind(tenant_id)
        .bind(stream_id)
        .bind(audit_log_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(delivery)
    }

    pub async fn list_pending_deliveries(
        &self,
        tenant_id: &str,
        stream_id: &str,
        limit: i64,
    ) -> Result<Vec<LogDelivery>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let deliveries = sqlx::query_as::<_, LogDelivery>(
            r#"
            SELECT id::text, tenant_id::text, stream_id::text, audit_log_id::text, status::text,
                   attempt_count, last_attempt_at, next_attempt_at, error, created_at, delivered_at
            FROM log_stream_deliveries
            WHERE stream_id = $1::uuid AND status = 'pending'
              AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
            ORDER BY created_at ASC
            LIMIT $2
            "#,
        )
        .bind(stream_id)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;

        Ok(deliveries)
    }

    pub async fn mark_delivery_delivered(
        &self,
        tenant_id: &str,
        delivery_id: &str,
    ) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE log_stream_deliveries
            SET status = 'delivered',
                attempt_count = attempt_count + 1,
                last_attempt_at = NOW(),
                delivered_at = NOW()
            WHERE id = $1::uuid
            "#,
        )
        .bind(delivery_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    pub async fn mark_delivery_failed(
        &self,
        tenant_id: &str,
        delivery_id: &str,
        error: Option<&str>,
        next_attempt_at: DateTime<Utc>,
    ) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE log_stream_deliveries
            SET status = 'pending',
                error = $2,
                attempt_count = attempt_count + 1,
                last_attempt_at = NOW(),
                next_attempt_at = $3
            WHERE id = $1::uuid
            "#,
        )
        .bind(delivery_id)
        .bind(error)
        .bind(next_attempt_at)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    pub async fn update_stream_cursor(
        &self,
        tenant_id: &str,
        stream_id: &str,
        last_delivered_at: DateTime<Utc>,
        last_error: Option<&str>,
    ) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE log_streams
            SET last_delivered_at = $3,
                last_error = $4,
                updated_at = NOW()
            WHERE tenant_id = $1::uuid AND id = $2::uuid
            "#,
        )
        .bind(tenant_id)
        .bind(stream_id)
        .bind(last_delivered_at)
        .bind(last_error)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }
}
