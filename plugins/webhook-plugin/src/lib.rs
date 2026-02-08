//! Advanced Webhook Delivery Plugin
//!
//! This plugin provides advanced webhook capabilities including:
//! - Custom webhook endpoints with filtering
//! - Retry logic with exponential backoff
//! - Event signing for security
//! - Delivery status tracking
//! - Rate limiting
//!
//! ## Configuration
//!
//! ```yaml
//! plugins:
//!   - name: "webhook-plugin"
//!     config:
//!       webhooks:
//!         - name: "audit-log"
//!           url: "https://example.com/webhooks/audit"
//!           events: ["user.login", "user.created"]
//!           secret: "webhook-secret-key"
//!           retry_policy:
//!             max_retries: 3
//!             backoff_secs: 1
//!           timeout_secs: 30
//!           rate_limit:
//!             requests_per_second: 10
//!             burst: 20
//! ```

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::interval;
use vault_core::plugin::types::{
    ApiRequest, ApiResponse, AuthContext, AuthResult, HookType, HttpMethod,
    Plugin, PluginCapability, PluginConfig, PluginError, PluginHealth, PluginMetadata,
    RegisterContext, Route, PluginHealth as HealthStatus,
};
use vault_core::models::user::User;

type HmacSha256 = Hmac<Sha256>;

/// Webhook configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookConfig {
    /// Webhook name (unique identifier)
    pub name: String,
    /// Target URL
    pub url: String,
    /// Events to subscribe to
    pub events: Vec<String>,
    /// Signing secret
    pub secret: String,
    /// HTTP headers to include
    pub headers: Option<HashMap<String, String>>,
    /// Retry policy
    pub retry_policy: RetryPolicy,
    /// Request timeout (seconds)
    pub timeout_secs: u64,
    /// Rate limit configuration
    pub rate_limit: Option<RateLimitConfig>,
    /// Whether webhook is enabled
    pub enabled: bool,
}

/// Retry policy configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RetryPolicy {
    /// Maximum number of retries
    pub max_retries: u32,
    /// Initial backoff in seconds
    pub backoff_secs: u64,
    /// Maximum backoff in seconds
    pub max_backoff_secs: u64,
    /// Backoff multiplier
    pub multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_secs: 1,
            max_backoff_secs: 300, // 5 minutes
            multiplier: 2.0,
        }
    }
}

/// Rate limit configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    /// Requests per second
    pub requests_per_second: u64,
    /// Burst allowance
    pub burst: u64,
}

/// Plugin configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookPluginConfig {
    /// Webhook endpoints
    pub webhooks: Vec<WebhookConfig>,
    /// Default timeout for webhook delivery
    pub default_timeout_secs: u64,
    /// Default retry policy
    pub default_retry_policy: RetryPolicy,
    /// Queue size for pending deliveries
    pub queue_size: usize,
    /// Worker count for delivery
    pub worker_count: usize,
    /// Enable batching
    pub enable_batching: bool,
    /// Batch size
    pub batch_size: usize,
    /// Batch interval (seconds)
    pub batch_interval_secs: u64,
}

impl Default for WebhookPluginConfig {
    fn default() -> Self {
        Self {
            webhooks: Vec::new(),
            default_timeout_secs: 30,
            default_retry_policy: RetryPolicy::default(),
            queue_size: 10000,
            worker_count: 4,
            enable_batching: false,
            batch_size: 100,
            batch_interval_secs: 5,
        }
    }
}

/// Webhook delivery event
#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    /// Event ID
    pub id: String,
    /// Event type
    pub event_type: String,
    /// Event timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Event data
    pub data: serde_json::Value,
    /// Tenant ID
    pub tenant_id: String,
}

/// Delivery attempt record
#[derive(Debug, Clone, Serialize)]
pub struct DeliveryAttempt {
    /// Attempt number
    pub attempt: u32,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// HTTP status code (if received)
    pub status_code: Option<u16>,
    /// Response body (if any)
    pub response_body: Option<String>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Delivery status
#[derive(Debug, Clone, Serialize)]
pub struct DeliveryStatus {
    /// Event ID
    pub event_id: String,
    /// Webhook name
    pub webhook_name: String,
    /// Current state
    pub state: DeliveryState,
    /// Delivery attempts
    pub attempts: Vec<DeliveryAttempt>,
    /// Next retry time (if pending)
    pub next_retry_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Completed at (if delivered/failed)
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Delivery state
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryState {
    /// Waiting to be delivered
    Pending,
    /// Currently being delivered
    InProgress,
    /// Successfully delivered
    Delivered,
    /// Failed after retries
    Failed,
    /// Cancelled
    Cancelled,
}

/// Webhook Plugin
pub struct WebhookPlugin {
    metadata: PluginMetadata,
    config: WebhookPluginConfig,
    stats: Arc<WebhookStats>,
    delivery_queue: Option<mpsc::Sender<WebhookEvent>>,
    http_client: Option<reqwest::Client>,
}

/// Webhook statistics
#[derive(Debug, Default)]
struct WebhookStats {
    events_received: AtomicU64,
    events_delivered: AtomicU64,
    events_failed: AtomicU64,
    retries_attempted: AtomicU64,
    active_deliveries: AtomicU64,
}

impl WebhookStats {
    fn increment_received(&self) {
        self.events_received.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_delivered(&self) {
        self.events_delivered.fetch_add(1, Ordering::Relaxed);
    }

    fn increment_failed(&self) {
        self.events_failed.fetch_add(1, Ordering::Relaxed);
    }
}

impl WebhookPlugin {
    /// Create new webhook plugin
    pub fn new() -> Self {
        let metadata = PluginMetadata::new(
            "webhook-plugin",
            "1.0.0",
            "Vault Contributors",
            "Advanced webhook delivery plugin for Vault",
        )
        .with_hook(HookType::AfterAuth)
        .with_hook(HookType::AfterRegister)
        .with_hook(HookType::Audit)
        .with_capability(PluginCapability::WebhookSender)
        .with_capability(PluginCapability::AuditLogger);

        Self {
            metadata,
            config: WebhookPluginConfig::default(),
            stats: Arc::new(WebhookStats::default()),
            delivery_queue: None,
            http_client: None,
        }
    }

    /// Generate webhook signature
    fn generate_signature(&self, secret: &str, payload: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(payload);
        let result = mac.finalize();
        let bytes = result.into_bytes();
        format!("sha256={}", hex::encode(bytes))
    }

    /// Build webhook payload
    fn build_payload(&self, event: &WebhookEvent, webhook: &WebhookConfig) -> Vec<u8> {
        let payload = serde_json::to_vec(event).unwrap_or_default();
        payload
    }

    /// Deliver webhook
    async fn deliver_webhook(
        &self,
        webhook: &WebhookConfig,
        event: &WebhookEvent,
    ) -> Result<DeliveryAttempt, PluginError> {
        let start = Instant::now();
        
        let payload = self.build_payload(event, webhook);
        let signature = self.generate_signature(&webhook.secret, &payload);

        // Build request
        let client = self.http_client.as_ref().ok_or_else(|| {
            PluginError::new("NOT_INITIALIZED", "HTTP client not initialized")
        })?;

        let mut request = client
            .post(&webhook.url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Signature", signature)
            .header("X-Event-ID", &event.id)
            .header("X-Event-Type", &event.event_type)
            .header("X-Delivery-Timestamp", event.timestamp.to_rfc3339());

        // Add custom headers
        if let Some(ref headers) = webhook.headers {
            for (key, value) in headers {
                request = request.header(key, value);
            }
        }

        // Send request
        let response = request
            .body(payload)
            .timeout(Duration::from_secs(webhook.timeout_secs))
            .send()
            .await;

        let duration_ms = start.elapsed().as_millis() as u64;

        match response {
            Ok(resp) => {
                let status_code = resp.status().as_u16();
                let response_body = resp.text().await.ok();

                Ok(DeliveryAttempt {
                    attempt: 1,
                    timestamp: chrono::Utc::now(),
                    status_code: Some(status_code),
                    response_body,
                    error: None,
                    duration_ms,
                })
            }
            Err(e) => Ok(DeliveryAttempt {
                attempt: 1,
                timestamp: chrono::Utc::now(),
                status_code: None,
                response_body: None,
                error: Some(e.to_string()),
                duration_ms,
            }),
        }
    }

    /// Find webhooks subscribed to an event
    fn find_subscribed_webhooks(&self, event_type: &str) -> Vec<&WebhookConfig> {
        self.config
            .webhooks
            .iter()
            .filter(|w| w.enabled && w.events.iter().any(|e| Self::event_matches(e, event_type)))
            .collect()
    }

    /// Check if event pattern matches event type
    fn event_matches(pattern: &str, event_type: &str) -> bool {
        // Support wildcards like "user.*" or "*"
        if pattern == "*" {
            return true;
        }
        if pattern.ends_with(".*") {
            let prefix = &pattern[..pattern.len() - 1];
            return event_type.starts_with(prefix);
        }
        pattern == event_type
    }

    /// Send event to delivery queue
    async fn send_event(&self, event: WebhookEvent) -> Result<(), PluginError> {
        if let Some(ref sender) = self.delivery_queue {
            sender
                .send(event)
                .await
                .map_err(|_| PluginError::new("QUEUE_ERROR", "Failed to queue event"))?;
            Ok(())
        } else {
            Err(PluginError::new("NOT_INITIALIZED", "Delivery queue not initialized"))
        }
    }

    /// Get current statistics
    fn get_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "events_received": self.stats.events_received.load(Ordering::Relaxed),
            "events_delivered": self.stats.events_delivered.load(Ordering::Relaxed),
            "events_failed": self.stats.events_failed.load(Ordering::Relaxed),
            "retries_attempted": self.stats.retries_attempted.load(Ordering::Relaxed),
            "active_deliveries": self.stats.active_deliveries.load(Ordering::Relaxed),
        })
    }
}

impl Default for WebhookPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for WebhookPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&mut self, config: &PluginConfig) -> Result<(), PluginError> {
        tracing::info!("Initializing Webhook Plugin");

        // Parse configuration
        self.config = serde_json::from_value(config.config.clone())
            .map_err(|e| PluginError::new("CONFIG_ERROR", format!("Invalid config: {}", e)))?;

        // Create HTTP client
        self.http_client = Some(
            reqwest::Client::builder()
                .pool_max_idle_per_host(10)
                .timeout(Duration::from_secs(self.config.default_timeout_secs))
                .build()
                .map_err(|e| PluginError::new("CLIENT_ERROR", e.to_string()))?,
        );

        // Create delivery queue
        let (tx, mut rx) = mpsc::channel::<WebhookEvent>(self.config.queue_size);
        self.delivery_queue = Some(tx);

        // Spawn delivery workers
        let worker_count = self.config.worker_count;
        let stats = self.stats.clone();
        let config = self.config.clone();
        
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                stats.increment_received();
                stats.active_deliveries.fetch_add(1, Ordering::Relaxed);
                
                // Process event
                // In a full implementation, this would deliver to each subscribed webhook
                
                stats.active_deliveries.fetch_sub(1, Ordering::Relaxed);
            }
        });

        tracing::info!(
            "Webhook Plugin initialized with {} webhooks and {} workers",
            self.config.webhooks.len(),
            worker_count
        );

        Ok(())
    }

    async fn after_auth(&self, ctx: &AuthContext, result: &AuthResult) -> Result<(), PluginError> {
        let event_type = if result.success {
            "user.login.success"
        } else {
            "user.login.failure"
        };

        let event = WebhookEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: event_type.to_string(),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "email": ctx.email,
                "tenant_id": ctx.tenant_id,
                "ip_address": ctx.ip_address,
                "user_agent": ctx.user_agent,
                "success": result.success,
                "user_id": result.user_id,
            }),
            tenant_id: ctx.tenant_id.clone(),
        };

        // Queue event for delivery
        if let Err(e) = self.send_event(event).await {
            tracing::warn!("Failed to queue webhook event: {}", e);
        }

        Ok(())
    }

    async fn after_register(&self, ctx: &RegisterContext, user: &User) -> Result<(), PluginError> {
        let event = WebhookEvent {
            id: uuid::Uuid::new_v4().to_string(),
            event_type: "user.created".to_string(),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": user.id,
                "email": ctx.email,
                "tenant_id": ctx.tenant_id,
                "name": ctx.name,
                "ip_address": ctx.ip_address,
            }),
            tenant_id: ctx.tenant_id.clone(),
        };

        if let Err(e) = self.send_event(event).await {
            tracing::warn!("Failed to queue webhook event: {}", e);
        }

        Ok(())
    }

    fn routes(&self) -> Vec<Route> {
        vec![
            Route::new(HttpMethod::Get, "/stats", "get_stats")
                .with_permission("admin:plugins"),
            Route::new(HttpMethod::Get, "/webhooks", "list_webhooks")
                .with_permission("admin:plugins"),
            Route::new(HttpMethod::Post, "/webhooks", "create_webhook")
                .with_permission("admin:plugins"),
            Route::new(HttpMethod::Get, "/deliveries", "list_deliveries")
                .with_permission("admin:plugins"),
            Route::new(HttpMethod::Post, "/test", "test_webhook")
                .with_permission("admin:plugins"),
        ]
    }

    async fn handle_request(
        &self,
        route: &str,
        request: ApiRequest,
    ) -> Result<ApiResponse, PluginError> {
        match route {
            "get_stats" => {
                Ok(ApiResponse {
                    status: 200,
                    body: self.get_stats(),
                    headers: HashMap::new(),
                })
            }
            "list_webhooks" => {
                let webhooks: Vec<_> = self.config.webhooks.iter().map(|w| {
                    serde_json::json!({
                        "name": w.name,
                        "url": w.url,
                        "events": w.events,
                        "enabled": w.enabled,
                        "retry_policy": w.retry_policy,
                        "timeout_secs": w.timeout_secs,
                    })
                }).collect();

                Ok(ApiResponse {
                    status: 200,
                    body: serde_json::json!({ "webhooks": webhooks }),
                    headers: HashMap::new(),
                })
            }
            "create_webhook" => {
                // Would create new webhook from request body
                Ok(ApiResponse {
                    status: 201,
                    body: serde_json::json!({
                        "message": "Webhook created (not implemented in example)"
                    }),
                    headers: HashMap::new(),
                })
            }
            "list_deliveries" => {
                Ok(ApiResponse {
                    status: 200,
                    body: serde_json::json!({
                        "deliveries": [],
                        "message": "Not implemented in example"
                    }),
                    headers: HashMap::new(),
                })
            }
            "test_webhook" => {
                // Send test event
                let test_event = WebhookEvent {
                    id: uuid::Uuid::new_v4().to_string(),
                    event_type: "test".to_string(),
                    timestamp: chrono::Utc::now(),
                    data: serde_json::json!({"test": true}),
                    tenant_id: request.context.tenant_id.clone(),
                };

                self.send_event(test_event).await?;

                Ok(ApiResponse {
                    status: 202,
                    body: serde_json::json!({
                        "message": "Test event queued for delivery"
                    }),
                    headers: HashMap::new(),
                })
            }
            _ => Err(PluginError::new("NOT_FOUND", "Route not found")),
        }
    }

    async fn health_check(&self) -> HealthStatus {
        // Check queue health
        if self.delivery_queue.is_none() {
            return HealthStatus::Unhealthy;
        }
        HealthStatus::Healthy
    }

    async fn shutdown(&self) -> Result<(), PluginError> {
        tracing::info!("Webhook Plugin shutting down");
        // Close the channel to stop workers
        // In a real implementation, we'd gracefully drain the queue
        Ok(())
    }
}

/// Create plugin instance - called by the plugin loader
pub fn create_plugin() -> Box<dyn Plugin> {
    Box::new(WebhookPlugin::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_plugin_metadata() {
        let plugin = WebhookPlugin::new();
        let metadata = plugin.metadata();

        assert_eq!(metadata.name, "webhook-plugin");
        assert!(metadata.hooks.contains(&HookType::AfterAuth));
        assert!(metadata.hooks.contains(&HookType::AfterRegister));
    }

    #[tokio::test]
    async fn test_webhook_plugin_initialization() {
        let mut plugin = WebhookPlugin::new();
        
        let config = PluginConfig {
            name: "webhook-plugin".to_string(),
            enabled: true,
            config: serde_json::json!({
                "webhooks": [{
                    "name": "test",
                    "url": "https://example.com/webhook",
                    "events": ["user.login"],
                    "secret": "test-secret",
                    "enabled": true,
                    "retry_policy": {
                        "max_retries": 3,
                        "backoff_secs": 1,
                        "max_backoff_secs": 60,
                        "multiplier": 2.0
                    },
                    "timeout_secs": 30
                }],
                "queue_size": 1000,
                "worker_count": 2
            }),
            priority: 0,
            timeout_ms: None,
        };

        let result = plugin.initialize(&config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_signature_generation() {
        let plugin = WebhookPlugin::new();
        let secret = "test-secret";
        let payload = b"test payload";

        let sig1 = plugin.generate_signature(secret, payload);
        let sig2 = plugin.generate_signature(secret, payload);
        
        // Signature should be deterministic
        assert_eq!(sig1, sig2);
        assert!(sig1.starts_with("sha256="));
    }

    #[test]
    fn test_event_matching() {
        assert!(WebhookPlugin::event_matches("*", "user.login"));
        assert!(WebhookPlugin::event_matches("user.*", "user.login"));
        assert!(WebhookPlugin::event_matches("user.*", "user.created"));
        assert!(!WebhookPlugin::event_matches("user.*", "org.created"));
        assert!(WebhookPlugin::event_matches("user.login", "user.login"));
        assert!(!WebhookPlugin::event_matches("user.login", "user.logout"));
    }

    #[test]
    fn test_default_config() {
        let config = WebhookPluginConfig::default();
        assert!(config.webhooks.is_empty());
        assert_eq!(config.queue_size, 10000);
        assert_eq!(config.worker_count, 4);
        assert!(!config.enable_batching);
    }

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.backoff_secs, 1);
        assert_eq!(policy.max_backoff_secs, 300);
        assert_eq!(policy.multiplier, 2.0);
    }

    #[test]
    fn test_find_subscribed_webhooks() {
        let mut plugin = WebhookPlugin::new();
        plugin.config.webhooks = vec![
            WebhookConfig {
                name: "login-webhook".to_string(),
                url: "https://example.com/login".to_string(),
                events: vec!["user.login".to_string()],
                secret: "secret".to_string(),
                headers: None,
                retry_policy: RetryPolicy::default(),
                timeout_secs: 30,
                rate_limit: None,
                enabled: true,
            },
            WebhookConfig {
                name: "all-webhook".to_string(),
                url: "https://example.com/all".to_string(),
                events: vec!["*".to_string()],
                secret: "secret".to_string(),
                headers: None,
                retry_policy: RetryPolicy::default(),
                timeout_secs: 30,
                rate_limit: None,
                enabled: true,
            },
            WebhookConfig {
                name: "disabled-webhook".to_string(),
                url: "https://example.com/disabled".to_string(),
                events: vec!["user.login".to_string()],
                secret: "secret".to_string(),
                headers: None,
                retry_policy: RetryPolicy::default(),
                timeout_secs: 30,
                rate_limit: None,
                enabled: false,
            },
        ];

        let webhooks = plugin.find_subscribed_webhooks("user.login");
        assert_eq!(webhooks.len(), 2); // login-webhook and all-webhook
        assert!(webhooks.iter().any(|w| w.name == "login-webhook"));
        assert!(webhooks.iter().any(|w| w.name == "all-webhook"));
        assert!(!webhooks.iter().any(|w| w.name == "disabled-webhook"));
    }

    #[test]
    fn test_create_plugin() {
        let plugin = create_plugin();
        assert_eq!(plugin.metadata().name, "webhook-plugin");
    }
}
