//! Internal Billing Webhook Routes
//!
//! Stripe webhook endpoint for receiving billing events.
//! These are public routes that Stripe calls directly.

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};

use crate::state::AppState;
use crate::state::CurrentUser;
use crate::routes::ApiError;

/// Create billing webhook routes
/// These are mounted under /api/v1/internal/billing
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/webhooks/stripe", post(stripe_webhook))
        .route("/invoices", get(list_platform_invoices))
}

/// Handle Stripe webhook events
async fn stripe_webhook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Check if billing is enabled
    if !state.billing_service.is_enabled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "Billing is not enabled");
    }

    // Get Stripe signature from headers
    let signature = match headers.get("stripe-signature") {
        Some(sig) => match sig.to_str() {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!("Invalid Stripe signature header encoding");
                return (StatusCode::BAD_REQUEST, "Invalid signature header");
            }
        },
        None => {
            tracing::warn!("Missing Stripe signature header");
            return (StatusCode::BAD_REQUEST, "Missing signature header");
        }
    };

    let payload = match std::str::from_utf8(&body) {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Invalid UTF-8 in body");
        }
    };

    // Process webhook
    match state
        .billing_service
        .handle_webhook(payload, signature)
        .await
    {
        Ok(Some(result)) => {
            tracing::info!(
                event_type = %result.event_type,
                tenant_id = ?result.tenant_id,
                processed = result.processed,
                "Stripe webhook processed"
            );
            (StatusCode::OK, "Webhook processed")
        }
        Ok(None) => {
            // Billing not enabled (shouldn't happen due to check above)
            (StatusCode::SERVICE_UNAVAILABLE, "Billing not enabled")
        }
        Err(e) => {
            tracing::error!("Failed to process Stripe webhook: {}", e);
            (StatusCode::BAD_REQUEST, "Webhook processing failed")
        }
    }
}

/// List invoices across all tenants (superadmin)
async fn list_platform_invoices(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.billing_service.is_enabled() {
        return Ok(Json(serde_json::json!({ \"invoices\": [] })));
    }

    let invoices = state
        .billing_service
        .list_all_invoices()
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({ \"invoices\": invoices })))
}
