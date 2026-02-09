//! Webhook Management Routes
//!
//! Admin endpoints for managing webhook endpoints and viewing delivery logs.
//! All routes are prefixed with `/api/v1/admin`.
//!
//! Endpoints:
//! - POST /webhooks - Create webhook endpoint
//! - GET /webhooks - List webhooks
//! - GET /webhooks/:id - Get webhook details
//! - PATCH /webhooks/:id - Update webhook
//! - DELETE /webhooks/:id - Delete webhook
//! - POST /webhooks/:id/test - Send test event
//! - GET /webhooks/:id/deliveries - List delivery attempts
//! - POST /webhooks/:id/rotate-secret - Rotate signing secret

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::{delete, get, patch, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use validator::Validate;

use crate::audit::{AuditAction, AuditLogger, ResourceType};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use crate::webhooks::{
    TestWebhookResponse, WebhookDeliveryResponse, WebhookEndpointResponse, WebhookEndpointUpdate,
};

/// Create routes for webhook management
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/webhooks", get(list_webhooks).post(create_webhook))
        .route(
            "/webhooks/:id",
            get(get_webhook)
                .patch(update_webhook)
                .delete(delete_webhook),
        )
        .route("/webhooks/:id/test", post(test_webhook))
        .route("/webhooks/:id/deliveries", get(list_deliveries))
        .route("/webhooks/:id/rotate-secret", post(rotate_secret))
}

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
struct PaginationQuery {
    page: Option<i64>,
    per_page: Option<i64>,
}

#[derive(Debug, Deserialize, Validate)]
struct CreateWebhookRequest {
    #[validate(length(min = 1, max = 255))]
    name: String,
    #[validate(url)]
    url: String,
    events: Vec<String>,
    secret: Option<String>,
    description: Option<String>,
    headers: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Default)]
struct UpdateWebhookRequest {
    name: Option<String>,
    url: Option<String>,
    events: Option<Vec<String>>,
    description: Option<String>,
    headers: Option<serde_json::Value>,
    active: Option<bool>,
    max_retries: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct WebhookTestRequest {
    event_type: Option<String>,
    payload: Option<serde_json::Value>,
}

// ============ Handlers ============

/// List all webhook endpoints for the tenant
async fn list_webhooks(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);

    let (endpoints, total) = state
        .webhook_service
        .list_endpoints(&current_user.tenant_id, page, per_page)
        .await
        .map_err(|_| ApiError::internal())?;

    let response: Vec<WebhookEndpointResponse> = endpoints
        .into_iter()
        .map(WebhookEndpointResponse::from)
        .collect();

    Ok(Json(json!({
        "webhooks": response,
        "total": total,
        "page": page,
        "per_page": per_page
    })))
}

/// Create a new webhook endpoint
async fn create_webhook(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<WebhookEndpointResponse>), ApiError> {
    // Validate request
    req.validate()
        .map_err(|e| ApiError::Validation(e.to_string()))?;

    // Validate URL uses HTTPS
    if !req.url.starts_with("https://") {
        return Err(ApiError::Validation(
            "Webhook URL must use HTTPS".to_string(),
        ));
    }

    // Validate event types
    for event in &req.events {
        if !is_valid_event_type(event) {
            return Err(ApiError::Validation(format!(
                "Invalid event type: {}",
                event
            )));
        }
    }

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let endpoint = state
        .webhook_service
        .create_endpoint(
            &current_user.tenant_id,
            &req.name,
            &req.url,
            req.events,
            req.secret,
            req.description,
            req.headers,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create webhook: {}", e);
            ApiError::internal()
        })?;

    // Log webhook creation
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::WebhookCreated,
        ResourceType::Webhook,
        &endpoint.id,
        Some(current_user.user_id.clone()),
        current_user.session_id.clone(),
        None,
        true,
        None,
        Some(json!({
            "name": endpoint.name,
            "url": endpoint.url,
            "events": endpoint.events,
        })),
    );

    Ok((
        StatusCode::CREATED,
        Json(WebhookEndpointResponse::from(endpoint)),
    ))
}

/// Get a webhook endpoint by ID
async fn get_webhook(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<WebhookEndpointResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let endpoint = state
        .webhook_service
        .get_endpoint(&current_user.tenant_id, &id)
        .await
        .map_err(|e| {
            tracing::warn!("Webhook not found: {}", e);
            ApiError::NotFound
        })?;

    Ok(Json(WebhookEndpointResponse::from(endpoint)))
}

/// Update a webhook endpoint
async fn update_webhook(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateWebhookRequest>,
) -> Result<Json<WebhookEndpointResponse>, ApiError> {
    // Validate URL if provided
    if let Some(ref url) = req.url {
        if !url.starts_with("https://") {
            return Err(ApiError::Validation(
                "Webhook URL must use HTTPS".to_string(),
            ));
        }
    }

    // Validate event types if provided
    if let Some(ref events) = req.events {
        for event in events {
            if !is_valid_event_type(event) {
                return Err(ApiError::Validation(format!(
                    "Invalid event type: {}",
                    event
                )));
            }
        }
    }

    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Build update struct
    let updates = WebhookEndpointUpdate {
        name: req.name,
        url: req.url,
        events: req.events,
        secret: None, // Secret is only updated via rotate-secret endpoint
        description: req.description,
        headers: req.headers,
        active: req.active,
        max_retries: req.max_retries,
    };

    let endpoint = state
        .webhook_service
        .update_endpoint(&current_user.tenant_id, &id, updates)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update webhook: {}", e);
            ApiError::internal()
        })?;

    // Log webhook update
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::WebhookUpdated,
        ResourceType::Webhook,
        &id,
        Some(current_user.user_id.clone()),
        current_user.session_id.clone(),
        None,
        true,
        None,
        None,
    );

    Ok(Json(WebhookEndpointResponse::from(endpoint)))
}

/// Delete a webhook endpoint (soft delete)
async fn delete_webhook(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .webhook_service
        .delete_endpoint(&current_user.tenant_id, &id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete webhook: {}", e);
            ApiError::internal()
        })?;

    // Log webhook deletion
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::WebhookDeleted,
        ResourceType::Webhook,
        &id,
        Some(current_user.user_id.clone()),
        current_user.session_id.clone(),
        None,
        true,
        None,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Test a webhook endpoint by sending a test event
async fn test_webhook(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(req): Json<WebhookTestRequest>,
) -> Result<Json<TestWebhookResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Get the endpoint
    let endpoint = state
        .webhook_service
        .get_endpoint(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::NotFound)?;

    // Build test event
    let event_type = req.event_type.unwrap_or_else(|| "webhook.test".to_string());
    let payload = req.payload.unwrap_or_else(|| {
        json!({
            "test": true,
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "message": "This is a test event from FantasticAuth",
            "endpoint_id": endpoint.id,
        })
    });

    let start = std::time::Instant::now();

    // Trigger the event
    let deliveries = state
        .webhook_service
        .trigger_event(&current_user.tenant_id, &event_type, payload.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to trigger test event: {}", e);
            ApiError::internal()
        })?;

    // If no deliveries were created (endpoint doesn't subscribe to this event),
    // create a one-off delivery for testing
    if deliveries.is_empty() {
        // For test, we'll do a direct HTTP delivery
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| ApiError::internal())?;

        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let payload_str = serde_json::to_string(&payload).map_err(|_| ApiError::internal())?;
        let signature_payload = format!("test.{}.{}", chrono::Utc::now().timestamp(), payload_str);

        let secret = match state
            .webhook_service
            .decrypt_secret(&current_user.tenant_id, &endpoint.secret)
            .await
        {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(
                    endpoint_id = %endpoint.id,
                    error = %err,
                    "Failed to decrypt webhook secret for test delivery; using stored value"
                );
                endpoint.secret.clone()
            }
        };
        let mut mac =
            HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| ApiError::internal())?;
        mac.update(signature_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let response = client
            .post(&endpoint.url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-ID", "test")
            .header(
                "X-Webhook-Timestamp",
                chrono::Utc::now().timestamp().to_string(),
            )
            .header("X-Webhook-Signature", format!("v1={}", signature))
            .header("X-Webhook-Event", &event_type)
            .header("X-Webhook-Attempt", "1")
            .header("User-Agent", "FantasticAuth-Webhook/1.0")
            .json(&payload)
            .send()
            .await;

        let duration = start.elapsed();

        match response {
            Ok(resp) => {
                let status_code = resp.status().as_u16() as i32;
                let success = resp.status().is_success();
                let body = resp.text().await.ok();

                Ok(Json(TestWebhookResponse {
                    success,
                    status_code: Some(status_code),
                    response_body: body,
                    error_message: if success {
                        None
                    } else {
                        Some(format!("HTTP {}", status_code))
                    },
                    duration_ms: duration.as_millis() as i64,
                }))
            }
            Err(e) => Ok(Json(TestWebhookResponse {
                success: false,
                status_code: None,
                response_body: None,
                error_message: Some(e.to_string()),
                duration_ms: duration.as_millis() as i64,
            })),
        }
    } else {
        // Return info about the created delivery
        Ok(Json(TestWebhookResponse {
            success: true,
            status_code: None,
            response_body: None,
            error_message: None,
            duration_ms: start.elapsed().as_millis() as i64,
        }))
    }
}

/// List deliveries for a webhook endpoint
async fn list_deliveries(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);

    let (deliveries, total) = state
        .webhook_service
        .list_deliveries(&current_user.tenant_id, &id, page, per_page)
        .await
        .map_err(|_| ApiError::internal())?;

    let response: Vec<WebhookDeliveryResponse> = deliveries
        .into_iter()
        .map(WebhookDeliveryResponse::from)
        .collect();

    Ok(Json(json!({
        "deliveries": response,
        "total": total,
        "page": page,
        "per_page": per_page
    })))
}

/// Rotate the signing secret for a webhook endpoint
async fn rotate_secret(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    // Webhook secrets are used to sign and verify webhook payloads
    use rand::RngCore;
    use rand_core::OsRng;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let new_secret = hex::encode(bytes);

    // Update endpoint with new secret
    let updates = WebhookEndpointUpdate {
        secret: Some(new_secret.clone()),
        ..Default::default()
    };

    let endpoint = state
        .webhook_service
        .update_endpoint(&current_user.tenant_id, &id, updates)
        .await
        .map_err(|_| ApiError::internal())?;

    // Log secret rotation
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::WebhookSecretRotated,
        ResourceType::Webhook,
        &id,
        Some(current_user.user_id.clone()),
        current_user.session_id.clone(),
        None,
        true,
        None,
        Some(json!({
            "endpoint_name": endpoint.name,
        })),
    );

    Ok(Json(json!({
        "message": "Secret rotated successfully",
        "secret": new_secret,
        "warning": "Store this secret securely - it will not be shown again"
    })))
}

/// Validate event type format
fn is_valid_event_type(event: &str) -> bool {
    // Allow wildcard
    if event == "*" {
        return true;
    }

    // Event types follow pattern: resource.action (e.g., user.created)
    let parts: Vec<&str> = event.split('.').collect();
    if parts.len() != 2 {
        return false;
    }

    let valid_resources = ["user", "organization", "session", "audit", "webhook"];
    let valid_actions = [
        "created",
        "updated",
        "deleted",
        "activated",
        "deactivated",
        "login",
        "logout",
        "password_changed",
        "email_verified",
        "mfa_enabled",
        "mfa_disabled",
        "test",
    ];

    valid_resources.contains(&parts[0]) && valid_actions.contains(&parts[1])
}
