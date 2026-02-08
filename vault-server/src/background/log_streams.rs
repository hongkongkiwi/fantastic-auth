//! Log streaming background worker

use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::StreamExt;
use serde::Serialize;
use sqlx::PgPool;
use vault_core::db::set_connection_context;
use tokio::time::interval;

use crate::state::AppState;

#[derive(Debug, Serialize, sqlx::FromRow)]
struct AuditLogRow {
    id: String,
    timestamp: DateTime<Utc>,
    tenant_id: String,
    user_id: Option<String>,
    session_id: Option<String>,
    action: String,
    resource_type: String,
    resource_id: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    success: bool,
    error: Option<String>,
    metadata: Option<serde_json::Value>,
}

pub fn start(state: AppState) {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(10));
        loop {
            ticker.tick().await;
            if let Err(e) = process_streams(&state).await {
                tracing::warn!("Log stream worker error: {}", e);
            }
        }
    });
}

async fn process_streams(state: &AppState) -> anyhow::Result<()> {
    let tenants: Vec<String> = sqlx::query_scalar(
        "SELECT id::text FROM tenants WHERE deleted_at IS NULL",
    )
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();

    for tenant_id in tenants {
        let streams = state
            .auth_service
            .db()
            .log_streams()
            .list_streams(&tenant_id)
            .await
            .unwrap_or_default();

        for stream in streams {
            if stream.status != "active" {
                continue;
            }

            if let Err(e) = process_stream(state, &stream, state.db.pool()).await {
                tracing::warn!("Failed to process log stream {}: {}", stream.id, e);
            }
        }
    }

    Ok(())
}

async fn process_stream(
    state: &AppState,
    stream: &vault_core::db::log_streams::LogStream,
    pool: &PgPool,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    set_connection_context(&mut conn, &stream.tenant_id).await?;
    let since = stream
        .last_delivered_at
        .unwrap_or_else(|| Utc::now() - chrono::Duration::minutes(60));

    let mut pending = state
        .auth_service
        .db()
        .log_streams()
        .list_pending_deliveries(&stream.tenant_id, &stream.id, 100)
        .await
        .unwrap_or_default();

    for delivery in pending.drain(..) {
        let row = sqlx::query_as::<_, AuditLogRow>(
            r#"
            SELECT id::text, timestamp, tenant_id::text, user_id::text, session_id::text, action, resource_type,
                   resource_id, ip_address::text, user_agent, success, error, metadata
            FROM audit_logs
            WHERE id = $1::uuid
            "#,
        )
        .bind(&delivery.audit_log_id)
        .fetch_one(&mut *conn)
        .await?;

        if !passes_filter(stream, &row) {
            state
                .auth_service
                .db()
                .log_streams()
                .mark_delivery_delivered(&stream.tenant_id, &delivery.id)
                .await
                .ok();
            continue;
        }

        let payload = audit_payload(&row);
        let result = match stream.destination_type.as_str() {
            "http" => deliver_http(stream, &payload).await,
            "kafka" => deliver_kafka(stream, &payload).await,
            _ => Err(anyhow::anyhow!("Unsupported destination type")),
        };

        match result {
            Ok(_) => {
                state
                    .auth_service
                    .db()
                    .log_streams()
                    .mark_delivery_delivered(&stream.tenant_id, &delivery.id)
                    .await
                    .ok();
                state
                    .auth_service
                    .db()
                    .log_streams()
                    .update_stream_cursor(&stream.tenant_id, &stream.id, row.timestamp, None)
                    .await
                    .ok();
            }
            Err(e) => {
                let backoff = next_backoff_seconds(delivery.attempt_count);
                let next_attempt_at = Utc::now() + chrono::Duration::seconds(backoff);
                state
                    .auth_service
                    .db()
                    .log_streams()
                    .mark_delivery_failed(
                        &stream.tenant_id,
                        &delivery.id,
                        Some(&e.to_string()),
                        next_attempt_at,
                    )
                    .await
                    .ok();
                state
                    .auth_service
                    .db()
                    .log_streams()
                    .update_stream_cursor(
                        &stream.tenant_id,
                        &stream.id,
                        row.timestamp,
                        Some(&e.to_string()),
                    )
                    .await
                    .ok();
            }
        }
    }

    let mut rows = sqlx::query_as::<_, AuditLogRow>(
        r#"
        SELECT id::text, timestamp, tenant_id::text, user_id::text, session_id::text, action, resource_type,
               resource_id, ip_address::text, user_agent, success, error, metadata
        FROM audit_logs
        WHERE tenant_id = $1::uuid AND timestamp > $2
        ORDER BY timestamp ASC
        LIMIT 100
        "#,
    )
    .bind(&stream.tenant_id)
    .bind(since)
    .fetch(&mut *conn);

    while let Some(row) = rows.next().await {
        let row = row?;
        if !passes_filter(stream, &row) {
            state
                .auth_service
                .db()
                .log_streams()
                .update_stream_cursor(&stream.tenant_id, &stream.id, row.timestamp, None)
                .await
                .ok();
            continue;
        }

        let payload = audit_payload(&row);

        let delivery = state
            .auth_service
            .db()
            .log_streams()
            .record_delivery(&stream.tenant_id, &stream.id, &row.id)
            .await?;

        let result = match stream.destination_type.as_str() {
            "http" => deliver_http(stream, &payload).await,
            "kafka" => deliver_kafka(stream, &payload).await,
            _ => Err(anyhow::anyhow!("Unsupported destination type")),
        };

        match result {
            Ok(_) => {
                state
                    .auth_service
                    .db()
                    .log_streams()
                    .mark_delivery_delivered(&stream.tenant_id, &delivery.id)
                    .await
                    .ok();
                state
                    .auth_service
                    .db()
                    .log_streams()
                    .update_stream_cursor(&stream.tenant_id, &stream.id, row.timestamp, None)
                    .await
                    .ok();
            }
            Err(e) => {
                let backoff = next_backoff_seconds(delivery.attempt_count);
                let next_attempt_at = Utc::now() + chrono::Duration::seconds(backoff);
                state
                    .auth_service
                    .db()
                    .log_streams()
                    .mark_delivery_failed(
                        &stream.tenant_id,
                        &delivery.id,
                        Some(&e.to_string()),
                        next_attempt_at,
                    )
                    .await
                    .ok();
                state
                    .auth_service
                    .db()
                    .log_streams()
                    .update_stream_cursor(&stream.tenant_id, &stream.id, row.timestamp, Some(&e.to_string()))
                    .await
                    .ok();
            }
        }
    }

    Ok(())
}

fn passes_filter(stream: &vault_core::db::log_streams::LogStream, row: &AuditLogRow) -> bool {
    let filter = &stream.filter;
    if let Some(actions) = filter.get("actions").and_then(|v| v.as_array()) {
        if !actions.iter().filter_map(|v| v.as_str()).any(|a| a == row.action) {
            return false;
        }
    }
    if let Some(resources) = filter.get("resource_types").and_then(|v| v.as_array()) {
        if !resources
            .iter()
            .filter_map(|v| v.as_str())
            .any(|r| r == row.resource_type)
        {
            return false;
        }
    }
    if let Some(success) = filter.get("success").and_then(|v| v.as_bool()) {
        if row.success != success {
            return false;
        }
    }
    true
}

fn audit_payload(row: &AuditLogRow) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "timestamp": row.timestamp,
        "tenant_id": row.tenant_id,
        "user_id": row.user_id,
        "session_id": row.session_id,
        "action": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "ip_address": row.ip_address,
        "user_agent": row.user_agent,
        "success": row.success,
        "error": row.error,
        "metadata": row.metadata,
    })
}

fn next_backoff_seconds(attempt_count: i32) -> i64 {
    let exp = attempt_count.clamp(0, 10) as u32;
    let base = 2_i64.pow(exp);
    base.min(3600)
}

async fn deliver_http(
    stream: &vault_core::db::log_streams::LogStream,
    payload: &serde_json::Value,
) -> anyhow::Result<()> {
    let url = stream
        .config
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing url in log stream config"))?;

    let client = reqwest::Client::new();
    let mut req = client.post(url).json(payload);

    if let Some(headers) = stream.config.get("headers") {
        if let Some(map) = headers.as_object() {
            for (k, v) in map {
                if let Some(value) = v.as_str() {
                    req = req.header(k, value);
                }
            }
        }
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("HTTP delivery failed: {}", resp.status()));
    }

    Ok(())
}

async fn deliver_kafka(
    stream: &vault_core::db::log_streams::LogStream,
    payload: &serde_json::Value,
) -> anyhow::Result<()> {
    let brokers = stream
        .config
        .get("brokers")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing brokers in log stream config"))?;
    let topic = stream
        .config
        .get("topic")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing topic in log stream config"))?;

    let producer: rdkafka::producer::FutureProducer = rdkafka::config::ClientConfig::new()
        .set("bootstrap.servers", brokers)
        .create()?;

    let payload = serde_json::to_vec(payload)?;
    let record = rdkafka::producer::FutureRecord::to(topic)
        .payload(&payload)
        .key(&stream.tenant_id);

    let _ = producer.send(record, Duration::from_secs(5)).await?;
    Ok(())
}
