use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Webhook endpoint (outgoing webhook configuration)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub url: String,
    pub secret: String,
    pub events: Vec<String>,
    pub active: bool,
    pub description: Option<String>,
    pub headers: Option<Value>,
    pub max_retries: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Webhook delivery attempt record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: String,
    pub endpoint_id: String,
    pub tenant_id: String,
    pub event_type: String,
    pub payload: Value,
    pub payload_size: i32,
    pub attempt_number: i32,
    pub status: String, // pending, delivered, failed
    pub http_status_code: Option<i32>,
    pub response_body: Option<String>,
    pub response_headers: Option<Value>,
    pub error_message: Option<String>,
    pub duration_ms: Option<i32>,
    pub scheduled_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Request to create a webhook endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct CreateWebhookEndpointRequest {
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub secret: Option<String>,
    pub description: Option<String>,
    pub headers: Option<Value>,
}

/// Request to update a webhook endpoint
#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpdateWebhookEndpointRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub secret: Option<String>,
    pub description: Option<String>,
    pub headers: Option<Value>,
    pub active: Option<bool>,
    pub max_retries: Option<i32>,
}

/// Internal update struct for service layer
#[derive(Debug, Clone, Default)]
pub struct WebhookEndpointUpdate {
    pub name: Option<String>,
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub secret: Option<String>,
    pub description: Option<String>,
    pub headers: Option<Value>,
    pub active: Option<bool>,
    pub max_retries: Option<i32>,
}

impl From<UpdateWebhookEndpointRequest> for WebhookEndpointUpdate {
    fn from(req: UpdateWebhookEndpointRequest) -> Self {
        Self {
            name: req.name,
            url: req.url,
            events: req.events,
            secret: req.secret,
            description: req.description,
            headers: req.headers,
            active: req.active,
            max_retries: req.max_retries,
        }
    }
}

/// Response payload for webhook endpoint (hides secret)
#[derive(Debug, Clone, Serialize)]
pub struct WebhookEndpointResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub active: bool,
    pub description: Option<String>,
    pub headers: Option<Value>,
    pub max_retries: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<WebhookEndpoint> for WebhookEndpointResponse {
    fn from(endpoint: WebhookEndpoint) -> Self {
        Self {
            id: endpoint.id,
            name: endpoint.name,
            url: endpoint.url,
            events: endpoint.events,
            active: endpoint.active,
            description: endpoint.description,
            headers: endpoint.headers,
            max_retries: endpoint.max_retries,
            created_at: endpoint.created_at,
            updated_at: endpoint.updated_at,
        }
    }
}

/// Response payload for webhook delivery (hides full payload in list view)
#[derive(Debug, Clone, Serialize)]
pub struct WebhookDeliveryResponse {
    pub id: String,
    pub event_type: String,
    pub payload_size: i32,
    pub attempt_number: i32,
    pub status: String,
    pub http_status_code: Option<i32>,
    pub error_message: Option<String>,
    pub duration_ms: Option<i32>,
    pub scheduled_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<WebhookDelivery> for WebhookDeliveryResponse {
    fn from(delivery: WebhookDelivery) -> Self {
        Self {
            id: delivery.id,
            event_type: delivery.event_type,
            payload_size: delivery.payload_size,
            attempt_number: delivery.attempt_number,
            status: delivery.status,
            http_status_code: delivery.http_status_code,
            error_message: delivery.error_message,
            duration_ms: delivery.duration_ms,
            scheduled_at: delivery.scheduled_at,
            delivered_at: delivery.delivered_at,
            created_at: delivery.created_at,
        }
    }
}

/// Detailed delivery response with full payload
#[derive(Debug, Clone, Serialize)]
pub struct WebhookDeliveryDetailResponse {
    pub id: String,
    pub event_type: String,
    pub payload: Value,
    pub payload_size: i32,
    pub attempt_number: i32,
    pub status: String,
    pub http_status_code: Option<i32>,
    pub response_body: Option<String>,
    pub response_headers: Option<Value>,
    pub error_message: Option<String>,
    pub duration_ms: Option<i32>,
    pub scheduled_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<WebhookDelivery> for WebhookDeliveryDetailResponse {
    fn from(delivery: WebhookDelivery) -> Self {
        Self {
            id: delivery.id,
            event_type: delivery.event_type,
            payload: delivery.payload,
            payload_size: delivery.payload_size,
            attempt_number: delivery.attempt_number,
            status: delivery.status,
            http_status_code: delivery.http_status_code,
            response_body: delivery.response_body,
            response_headers: delivery.response_headers,
            error_message: delivery.error_message,
            duration_ms: delivery.duration_ms,
            scheduled_at: delivery.scheduled_at,
            delivered_at: delivery.delivered_at,
            created_at: delivery.created_at,
        }
    }
}

/// Test webhook request
#[derive(Debug, Clone, Deserialize)]
pub struct TestWebhookRequest {
    pub event_type: String,
    pub payload: Option<Value>,
}

/// Test webhook response
#[derive(Debug, Clone, Serialize)]
pub struct TestWebhookResponse {
    pub success: bool,
    pub status_code: Option<i32>,
    pub response_body: Option<String>,
    pub error_message: Option<String>,
    pub duration_ms: i64,
}
