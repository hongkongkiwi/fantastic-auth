//! Webhook system for event delivery
//!
//! Provides reliable event delivery with retries, signatures, and endpoint management.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod delivery;
pub mod events;
pub mod signatures;

pub use delivery::{WebhookDelivery, WebhookDeliveryStatus, WebhookWorker};
pub use events::WebhookEvent;
pub use signatures::{sign_payload, verify_signature};

/// Webhook endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    /// Endpoint ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// URL to deliver events to
    pub url: String,
    /// Description
    pub description: Option<String>,
    /// Event types to subscribe to
    pub events: Vec<String>,
    /// Secret for signing payloads
    pub secret: String,
    /// Whether endpoint is active
    pub active: bool,
    /// Headers to include in requests
    pub headers: HashMap<String, String>,
    /// Maximum retries
    pub max_retries: i32,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Webhook delivery attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookAttempt {
    /// Attempt number (1-based)
    pub attempt_number: i32,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// HTTP status code (if received)
    pub status_code: Option<i32>,
    /// Response body (truncated)
    pub response_body: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: i64,
}

/// Webhook payload
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    /// Event ID
    pub id: String,
    /// Event type
    #[serde(rename = "type")]
    pub event_type: String,
    /// API version
    pub api_version: String,
    /// Timestamp
    pub created_at: String,
    /// Event data
    pub data: serde_json::Value,
}

/// Webhook store trait
#[async_trait]
pub trait WebhookStore: Send + Sync {
    /// Create endpoint
    async fn create_endpoint(&self, endpoint: WebhookEndpoint) -> Result<WebhookEndpoint, WebhookError>;
    
    /// Get endpoint by ID
    async fn get_endpoint(&self, id: &str) -> Result<WebhookEndpoint, WebhookError>;
    
    /// List endpoints for tenant
    async fn list_endpoints(
        &self,
        tenant_id: &str,
        active_only: bool,
    ) -> Result<Vec<WebhookEndpoint>, WebhookError>;
    
    /// Update endpoint
    async fn update_endpoint(&self, endpoint: WebhookEndpoint) -> Result<WebhookEndpoint, WebhookError>;
    
    /// Delete endpoint
    async fn delete_endpoint(&self, id: &str) -> Result<(), WebhookError>;
    
    /// Store delivery
    async fn store_delivery(&self, delivery: WebhookDelivery) -> Result<(), WebhookError>;
    
    /// Get delivery
    async fn get_delivery(&self, id: &str) -> Result<WebhookDelivery, WebhookError>;
    
    /// List pending deliveries
    async fn list_pending_deliveries(
        &self,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>, WebhookError>;

    /// Claim pending deliveries for processing (marks them in-progress)
    async fn claim_pending_deliveries(
        &self,
        limit: i64,
        in_progress_timeout_seconds: u64,
    ) -> Result<Vec<WebhookDelivery>, WebhookError>;
    
    /// Update delivery
    async fn update_delivery(&self, delivery: WebhookDelivery) -> Result<(), WebhookError>;
}

/// Webhook errors
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("Endpoint not found")]
    NotFound,
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),
    #[error("Store error: {0}")]
    Store(String),
    #[error("Delivery error: {0}")]
    Delivery(String),
    #[error("Signature error: {0}")]
    Signature(String),
}

/// Webhook configuration
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// User agent string
    pub user_agent: String,
    /// Request timeout in seconds
    pub timeout_seconds: u64,
    /// Retry delays in seconds (exponential backoff)
    pub retry_delays: Vec<u64>,
    /// Retry jitter factor (0.0 - 1.0)
    pub retry_jitter: f32,
    /// Overload penalty in seconds (applied to timeouts/429s)
    pub overload_penalty_seconds: u64,
    /// Maximum payload size in bytes
    pub max_payload_size: usize,
    /// Maximum response body size to store in attempts
    pub max_response_body_bytes: usize,
    /// Max time a delivery can be in-progress before it is re-claimed
    pub in_progress_timeout_seconds: u64,
    /// API version
    pub api_version: String,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            user_agent: "Vault-Webhook/1.0".to_string(),
            timeout_seconds: 30,
            retry_delays: vec![60, 300, 900, 3600], // 1min, 5min, 15min, 1hour
            retry_jitter: 0.2,
            overload_penalty_seconds: 60,
            max_payload_size: 1_000_000, // 1MB
            max_response_body_bytes: 20_000,
            in_progress_timeout_seconds: 300,
            api_version: "2024-01-01".to_string(),
        }
    }
}

/// Webhook service
pub struct WebhookService {
    config: WebhookConfig,
    store: Box<dyn WebhookStore>,
    client: reqwest::Client,
}

impl WebhookService {
    /// Create new webhook service
    pub fn new(config: WebhookConfig, store: Box<dyn WebhookStore>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_seconds))
            .user_agent(&config.user_agent)
            .build()
            .expect("Failed to build HTTP client");
        
        Self {
            config,
            store,
            client,
        }
    }

    /// Claim a batch of pending deliveries for processing.
    pub async fn claim_pending_deliveries(
        &self,
        limit: i64,
    ) -> Result<Vec<WebhookDelivery>, WebhookError> {
        self.store
            .claim_pending_deliveries(limit, self.config.in_progress_timeout_seconds)
            .await
    }
    
    /// Register new endpoint
    pub async fn register_endpoint(
        &self,
        tenant_id: &str,
        url: &str,
        events: Vec<String>,
        description: Option<&str>,
    ) -> Result<WebhookEndpoint, WebhookError> {
        // Validate URL
        if !url.starts_with("https://") {
            return Err(WebhookError::InvalidUrl(
                "URL must use HTTPS".to_string()
            ));
        }
        
        // Generate secret
        let secret = generate_secret();
        
        let endpoint = WebhookEndpoint {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            url: url.to_string(),
            description: description.map(|s| s.to_string()),
            events,
            secret,
            active: true,
            headers: HashMap::new(),
            max_retries: self.config.retry_delays.len().max(1) as i32,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        
        self.store.create_endpoint(endpoint).await
    }
    
    /// Send event to all subscribed endpoints
    pub async fn send_event(
        &self,
        tenant_id: &str,
        event: WebhookEvent,
    ) -> Result<Vec<WebhookDelivery>, WebhookError> {
        let endpoints = self.store.list_endpoints(tenant_id, true).await?;
        
        let event_type = event.event_type();
        let mut deliveries = Vec::new();
        
        for endpoint in endpoints {
            // Check if endpoint subscribes to this event
            if !endpoint.events.contains(&"*".to_string()) 
                && !endpoint.events.contains(&event_type) {
                continue;
            }
            
            let delivery = self.create_delivery(&endpoint, event.clone()).await?;
            deliveries.push(delivery);
        }
        
        Ok(deliveries)
    }
    
    /// Create a delivery
    async fn create_delivery(
        &self,
        endpoint: &WebhookEndpoint,
        event: WebhookEvent,
    ) -> Result<WebhookDelivery, WebhookError> {
        let payload = WebhookPayload {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: event.event_type(),
            api_version: self.config.api_version.clone(),
            created_at: Utc::now().to_rfc3339(),
            data: event.to_json(),
        };
        
        let payload_json = serde_json::to_string(&payload)
            .map_err(|e| WebhookError::Store(e.to_string()))?;

        if payload_json.len() > self.config.max_payload_size {
            return Err(WebhookError::Delivery(format!(
                "Payload too large: {} bytes",
                payload_json.len()
            )));
        }
        
        let delivery = WebhookDelivery {
            id: uuid::Uuid::new_v4().to_string(),
            endpoint_id: endpoint.id.clone(),
            tenant_id: endpoint.tenant_id.clone(),
            event_type: payload.event_type.clone(),
            payload: payload_json,
            payload_size: payload_json.len() as i32,
            status: WebhookDeliveryStatus::Pending,
            attempts: Vec::new(),
            next_attempt_at: Some(Utc::now()),
            delivered_at: None,
            created_at: Utc::now(),
        };
        
        self.store.store_delivery(delivery.clone()).await?;
        
        Ok(delivery)
    }
    
    /// Deliver a webhook
    pub async fn deliver(&self, delivery: &mut WebhookDelivery) -> Result<(), WebhookError> {
        let endpoint = self.store.get_endpoint(&delivery.endpoint_id).await?;
        
        if !endpoint.active {
            delivery.status = WebhookDeliveryStatus::Failed;
            delivery.next_attempt_at = None;
            self.store.update_delivery(delivery.clone()).await?;
            return Err(WebhookError::Delivery("Endpoint inactive".to_string()));
        }
        
        let attempt_number = (delivery.attempts.len() as i32) + 1;
        let start = std::time::Instant::now();
        
        // Sign payload
        let signature = sign_payload(&delivery.payload, &endpoint.secret)
            .map_err(|e| WebhookError::Signature(e.to_string()))?;
        
        // Build request
        let mut request = self.client
            .post(&endpoint.url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Signature", signature)
            .header("X-Webhook-ID", &delivery.id)
            .header("X-Webhook-Attempt", attempt_number.to_string())
            .header("X-Webhook-Event", &delivery.event_type)
            .header("User-Agent", &self.config.user_agent);
        
        // Add custom headers
        for (key, value) in &endpoint.headers {
            request = request.header(key, value);
        }
        
        // Send request
        let result = request.body(delivery.payload.clone()).send().await;

        let duration_ms = start.elapsed().as_millis() as i64;

        let mut retry_after_secs: Option<u64> = None;
        let mut penalize_overload = false;

        let attempt = match result {
            Ok(response) => {
                let status_code = response.status().as_u16() as i32;
                let success = response.status().is_success();

                if status_code == 429 || status_code == 503 || status_code == 504 || status_code == 408 {
                    penalize_overload = true;
                    retry_after_secs = response
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| s.parse::<u64>().ok());
                }

                // Truncate response body
                let response_body = response
                    .text()
                    .await
                    .ok()
                    .map(|b| {
                        if b.len() > self.config.max_response_body_bytes {
                            b[..self.config.max_response_body_bytes].to_string()
                        } else {
                            b
                        }
                    });

                WebhookAttempt {
                    attempt_number,
                    timestamp: Utc::now(),
                    status_code: Some(status_code),
                    response_body,
                    error: if success { None } else { Some(format!("HTTP {}", status_code)) },
                    duration_ms,
                }
            }
            Err(e) => {
                if e.is_timeout() {
                    penalize_overload = true;
                }
                WebhookAttempt {
                    attempt_number,
                    timestamp: Utc::now(),
                    status_code: None,
                    response_body: None,
                    error: Some(e.to_string()),
                    duration_ms,
                }
            }
        };
        
        delivery.attempts.push(attempt);
        
        // Determine status
        let last_attempt = delivery.attempts.last().unwrap();
        
        if last_attempt.status_code.map(|c| (200..300).contains(&c)).unwrap_or(false) {
            // Success
            delivery.status = WebhookDeliveryStatus::Delivered;
            delivery.delivered_at = Some(Utc::now());
            delivery.next_attempt_at = None;
        } else if attempt_number >= endpoint.max_retries {
            // Max retries reached
            delivery.status = WebhookDeliveryStatus::Failed;
            delivery.next_attempt_at = None;
        } else {
            // Schedule retry
            let base_delay = self
                .config
                .retry_delays
                .get((attempt_number - 1) as usize)
                .copied()
                .or_else(|| self.config.retry_delays.last().copied())
                .unwrap_or(3600);

            let delay = compute_retry_delay(
                base_delay,
                retry_after_secs,
                penalize_overload,
                self.config.overload_penalty_seconds,
                self.config.retry_jitter,
            );

            delivery.status = WebhookDeliveryStatus::Retrying;
            delivery.next_attempt_at = Some(Utc::now() + Duration::seconds(delay as i64));
        }
        
        self.store.update_delivery(delivery.clone()).await?;
        
        Ok(())
    }
}

/// Generate a random secret for webhook signing
fn generate_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::encode(bytes)
}

fn compute_retry_delay(
    base_delay: u64,
    retry_after_secs: Option<u64>,
    penalize_overload: bool,
    overload_penalty_seconds: u64,
    retry_jitter: f32,
) -> u64 {
    let mut delay = base_delay;
    if penalize_overload {
        delay = delay.max(overload_penalty_seconds);
    }
    if let Some(retry_after) = retry_after_secs {
        delay = delay.max(retry_after);
    }

    let jitter = retry_jitter.clamp(0.0, 1.0) as f64;
    if jitter > 0.0 {
        use rand::Rng;
        let min = (delay as f64) * (1.0 - jitter);
        let max = (delay as f64) * (1.0 + jitter);
        delay = rand::thread_rng().gen_range(min..=max).round() as u64;
    }

    delay
}

// Backwards compatibility with base64 crate
mod base64 {
    use base64::{engine::general_purpose::STANDARD, Engine};
    
    pub fn encode(input: impl AsRef<[u8]>) -> String {
        STANDARD.encode(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;
    use tokio::runtime::Runtime;
    
    #[test]
    fn test_webhook_config_default() {
        let config = WebhookConfig::default();
        assert_eq!(config.timeout_seconds, 30);
        assert_eq!(config.retry_delays.len(), 4);
        assert_eq!(config.retry_jitter, 0.2);
        assert_eq!(config.overload_penalty_seconds, 60);
    }
    
    #[test]
    fn test_generate_secret() {
        let secret1 = generate_secret();
        let secret2 = generate_secret();
        
        assert_ne!(secret1, secret2);
        assert!(!secret1.is_empty());
    }

    #[test]
    fn test_compute_retry_delay_no_jitter() {
        let delay = compute_retry_delay(60, None, false, 120, 0.0);
        assert_eq!(delay, 60);
    }

    #[test]
    fn test_compute_retry_delay_overload_penalty() {
        let delay = compute_retry_delay(30, None, true, 60, 0.0);
        assert_eq!(delay, 60);
    }

    #[test]
    fn test_compute_retry_delay_retry_after() {
        let delay = compute_retry_delay(60, Some(120), false, 60, 0.0);
        assert_eq!(delay, 120);
    }

    mock! {
        WebhookStore {}

        #[async_trait::async_trait]
        impl WebhookStore for WebhookStore {
            async fn create_endpoint(&self, endpoint: WebhookEndpoint) -> Result<WebhookEndpoint, WebhookError>;
            async fn get_endpoint(&self, id: &str) -> Result<WebhookEndpoint, WebhookError>;
            async fn list_endpoints(
                &self,
                tenant_id: &str,
                active_only: bool,
            ) -> Result<Vec<WebhookEndpoint>, WebhookError>;
            async fn update_endpoint(&self, endpoint: WebhookEndpoint) -> Result<WebhookEndpoint, WebhookError>;
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
    fn test_claim_pending_deliveries_forwards_timeout() {
        let mut store = MockWebhookStore::new();
        store
            .expect_claim_pending_deliveries()
            .withf(|limit, timeout| *limit == 10 && *timeout == 123)
            .returning(|_, _| Ok(Vec::new()));

        let mut config = WebhookConfig::default();
        config.in_progress_timeout_seconds = 123;

        let svc = WebhookService::new(config, Box::new(store));
        let rt = Runtime::new().expect("runtime");

        rt.block_on(async {
            let result = svc.claim_pending_deliveries(10).await;
            assert!(result.is_ok());
        });
    }
}
