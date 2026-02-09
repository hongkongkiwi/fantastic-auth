//! Push MFA Polling and Real-time Updates
//!
//! Provides long-polling endpoints and WebSocket support for real-time
//! push MFA status updates. Uses Redis pub/sub for distributed
//! communication between server instances.

use super::{PushMfaError, PushRequest, PushRequestStatus};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout};

/// Default long-polling timeout (30 seconds)
const DEFAULT_POLL_TIMEOUT_SECONDS: u64 = 30;

/// Default poll interval (1 second)
const DEFAULT_POLL_INTERVAL_MS: u64 = 1000;

/// Channel buffer size for WebSocket broadcasts
const WS_CHANNEL_BUFFER: usize = 100;

/// Polling service for push MFA status updates
#[derive(Clone)]
pub struct PushPollingService {
    db: crate::db::Database,
    redis: Option<redis::aio::ConnectionManager>,
    /// In-memory channel for WebSocket broadcasts (per-instance)
    ws_channels: std::sync::Arc<tokio::sync::RwLock<
        std::collections::HashMap<String, broadcast::Sender<PushStatusUpdate>>,
    >>,
}

/// Status update sent to polling clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushStatusUpdate {
    /// Request ID
    pub request_id: String,
    /// Current status
    pub status: String,
    /// Timestamp of update
    pub timestamp: String,
    /// Optional error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Long-polling response
#[derive(Debug, Serialize)]
pub struct PollingResponse {
    pub request_id: String,
    pub status: String,
    #[serde(rename = "remainingSeconds")]
    pub remaining_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
}



impl PushPollingService {
    /// Create a new polling service
    pub fn new(
        db: crate::db::Database,
        redis: Option<redis::aio::ConnectionManager>,
    ) -> Self {
        Self {
            db,
            redis,
            ws_channels: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::HashMap::new(),
            )),
        }
    }

    /// Poll for request status with long-polling
    pub async fn poll_request_status(
        &self,
        tenant_id: &str,
        user_id: &str,
        request_id: &str,
        timeout_seconds: Option<u64>,
    ) -> Result<PollingResponse, PushMfaError> {
        let timeout_duration = Duration::from_secs(timeout_seconds.unwrap_or(DEFAULT_POLL_TIMEOUT_SECONDS));
        let poll_interval = Duration::from_millis(DEFAULT_POLL_INTERVAL_MS);

        let start_time = tokio::time::Instant::now();

        loop {
            // Check if we've exceeded timeout
            if start_time.elapsed() >= timeout_duration {
                // Return current status without completing
                let request = self.get_request(tenant_id, user_id, request_id).await?;
                return Ok(PollingResponse {
                    request_id: request_id.to_string(),
                    status: request.status.to_string(),
                    remaining_seconds: request.remaining_seconds(),
                    completed_at: None,
                });
            }

            // Check request status
            match self.get_request(tenant_id, user_id, request_id).await {
                Ok(request) => {
                    // If request is completed or expired, return immediately
                    if !request.is_pending() {
                        return Ok(PollingResponse {
                            request_id: request_id.to_string(),
                            status: request.status.to_string(),
                            remaining_seconds: 0,
                            completed_at: request.responded_at.map(|d| d.to_rfc3339()),
                        });
                    }

                    // Check if expired
                    if request.is_expired() {
                        // Update status in database
                        self.expire_request(request_id).await?;
                        return Ok(PollingResponse {
                            request_id: request_id.to_string(),
                            status: "expired".to_string(),
                            remaining_seconds: 0,
                            completed_at: Some(chrono::Utc::now().to_rfc3339()),
                        });
                    }
                }
                Err(e) => {
                    // If request not found, return error
                    if matches!(e, PushMfaError::RequestNotFound(_)) {
                        return Err(e);
                    }
                    // Otherwise log and continue polling
                    tracing::warn!("Error polling request: {}", e);
                }
            }

            // Wait before next poll
            sleep(poll_interval).await;
        }
    }

    /// Poll with Redis pub/sub for distributed updates
    pub async fn poll_with_redis(
        &self,
        tenant_id: &str,
        user_id: &str,
        request_id: &str,
        timeout_seconds: Option<u64>,
    ) -> Result<PollingResponse, PushMfaError> {
        let timeout_duration = Duration::from_secs(timeout_seconds.unwrap_or(DEFAULT_POLL_TIMEOUT_SECONDS));

        // First check current status
        let request = self.get_request(tenant_id, user_id, request_id).await?;
        
        if !request.is_pending() {
            return Ok(PollingResponse {
                request_id: request_id.to_string(),
                status: request.status.to_string(),
                remaining_seconds: 0,
                completed_at: request.responded_at.map(|d| d.to_rfc3339()),
            });
        }

        // Set up Redis subscription if available
        if let Some(ref redis) = self.redis {
            let channel = format!("push_mfa:request:{}", request_id);
            
            match timeout(timeout_duration, self.redis_subscribe(redis, &channel)).await {
                Ok(Ok(update)) => {
                    return Ok(PollingResponse {
                        request_id: request_id.to_string(),
                        status: update.status,
                        remaining_seconds: 0,
                        completed_at: Some(update.timestamp),
                    });
                }
                Ok(Err(e)) => {
                    tracing::warn!("Redis subscription error: {}", e);
                }
                Err(_) => {
                    // Timeout - return current status
                }
            }
        }

        // Fallback to polling or return current status
        self.poll_request_status(tenant_id, user_id, request_id, Some(0)).await
    }

    /// Subscribe to Redis channel and wait for update (simplified - uses polling)
    async fn redis_subscribe(
        &self,
        _redis: &redis::aio::ConnectionManager,
        _channel: &str,
    ) -> Result<PushStatusUpdate, PushMfaError> {
        // Redis pub/sub implementation would go here
        // For now, just return an error to fall back to polling
        Err(PushMfaError::Internal("Redis pub/sub not implemented".to_string()))
    }

    /// Get or create WebSocket channel for a request
    pub async fn get_ws_channel(
        &self,
        request_id: &str,
    ) -> broadcast::Sender<PushStatusUpdate> {
        let channels = self.ws_channels.read().await;
        
        if let Some(sender) = channels.get(request_id) {
            return sender.clone();
        }
        
        drop(channels);
        
        // Create new channel
        let (sender, _) = broadcast::channel(WS_CHANNEL_BUFFER);
        let mut channels = self.ws_channels.write().await;
        channels.insert(request_id.to_string(), sender.clone());
        
        sender
    }

    /// Publish update to WebSocket subscribers
    pub async fn publish_ws_update(&self, update: &PushStatusUpdate) {
        let channels = self.ws_channels.read().await;
        
        if let Some(sender) = channels.get(&update.request_id) {
            let _ = sender.send(update.clone());
        }
    }

    /// Clean up WebSocket channel for completed request
    pub async fn cleanup_ws_channel(&self, request_id: &str) {
        let mut channels = self.ws_channels.write().await;
        channels.remove(request_id);
    }

    /// Handle WebSocket connection (placeholder for when ws feature is enabled)
    /// 
    /// To enable WebSocket support, add the "ws" feature to axum in Cargo.toml
    pub async fn handle_websocket(
        &self,
        _ws: impl std::any::Any, // Placeholder type
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        (
            axum::http::StatusCode::NOT_IMPLEMENTED,
            axum::Json(serde_json::json!({
                "error": "WebSocket support not enabled. Enable the 'ws' feature in axum."
            }))
        ).into_response()
    }

    /// Get request from database
    async fn get_request(
        &self,
        tenant_id: &str,
        user_id: &str,
        request_id: &str,
    ) -> Result<PushRequest, PushMfaError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, tenant_id, device_id, session_id, 
                   status as "status: super::PushRequestStatus", ip_address, user_agent, 
                   expires_at, responded_at, created_at, response_signature, response_timestamp
            FROM push_requests
            WHERE tenant_id = $1 AND user_id = $2 AND id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(request_id)
        .fetch_optional(self.db.pool())
        .await?;

        row.map(super::PushRequest::from_row)
            .ok_or_else(|| PushMfaError::RequestNotFound(request_id.to_string()))
    }

    /// Mark request as expired
    async fn expire_request(&self, request_id: &str) -> Result<(), PushMfaError> {
        sqlx::query(
            "UPDATE push_requests SET status = 'expired' WHERE id = $1"
        )
        .bind(request_id)
        .execute(self.db.pool())
        .await?;

        Ok(())
    }

    /// Start background task to clean up expired requests
    pub fn start_cleanup_task(&self) {
        let db = self.db.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                match sqlx::query(
                    "UPDATE push_requests SET status = 'expired' 
                     WHERE status = 'pending' AND expires_at < NOW()"
                )
                .execute(db.pool())
                .await {
                    Ok(result) => {
                        if result.rows_affected() > 0 {
                            tracing::info!(
                                "Cleaned up {} expired push requests",
                                result.rows_affected()
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to clean up expired requests: {}", e);
                    }
                }
            }
        });
    }
}



/// Publish a status update to Redis
pub async fn publish_status_update(
    redis: &mut redis::aio::ConnectionManager,
    request_id: &str,
    status: &str,
) -> Result<(), PushMfaError> {
    let channel = format!("push_mfa:request:{}", request_id);
    let message = serde_json::json!({
        "request_id": request_id,
        "status": status,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    redis
        .publish(&channel, message.to_string())
        .await
        .map_err(|e| PushMfaError::Internal(format!("Redis publish error: {}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_status_update_serialization() {
        let update = PushStatusUpdate {
            request_id: "req-123".to_string(),
            status: "approved".to_string(),
            timestamp: "2026-02-08T16:00:00Z".to_string(),
            error: None,
        };

        let json = serde_json::to_string(&update).unwrap();
        assert!(json.contains("req-123"));
        assert!(json.contains("approved"));
    }

    #[test]
    fn test_ws_message_deserialization() {
        let json = r#"{"type":"subscribe","request_id":"req-123"}"#;
        let msg: WsMessage = serde_json::from_str(json).unwrap();
        
        match msg {
            WsMessage::Subscribe { request_id } => {
                assert_eq!(request_id, "req-123");
            }
            _ => panic!("Expected Subscribe message"),
        }
    }

    #[test]
    fn test_polling_response_serialization() {
        let response = PollingResponse {
            request_id: "req-123".to_string(),
            status: "pending".to_string(),
            remaining_seconds: 120,
            completed_at: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("req-123"));
        assert!(json.contains("remainingSeconds"));
    }
}
