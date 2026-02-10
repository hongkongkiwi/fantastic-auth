//! Admin Billing Routes
//!
//! Subscription and billing management endpoints.
//! These routes are only available when Stripe billing is enabled.

use axum::{
    extract::{Extension, State},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::billing::{
    CreateCheckoutRequest, PortalResponse, SubscriptionResponse, UpdateSubscriptionRequest,
};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Create billing routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/billing/status", get(get_billing_status))
        .route("/billing/plans", get(list_plans))
        .route(
            "/billing/subscription",
            get(get_subscription).post(create_subscription),
        )
        .route("/billing/subscription/cancel", post(cancel_subscription))
        .route("/billing/subscription/resume", post(resume_subscription))
        .route("/billing/subscription", put(update_subscription))
        .route("/billing/invoices", get(list_invoices))
        .route("/billing/portal", post(create_portal_session))
        .route("/billing/usage", post(record_usage))
}

/// Get billing status for tenant
async fn get_billing_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.billing_service.is_enabled() {
        return Err(ApiError::BadRequest("Billing is not enabled".to_string()));
    }

    let subscription = state
        .billing_service
        .get_subscription(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let invoices = state
        .billing_service
        .list_invoices(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(json!({
        "billing_enabled": true,
        "subscription": subscription,
        "invoices": invoices,
    })))
}

/// List available billing plans
async fn list_plans(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.billing_service.is_enabled() {
        return Ok(Json(json!({
            "billing_enabled": false,
            "plans": []
        })));
    }

    let plans = state
        .billing_service
        .list_plans()
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(json!({
        "billing_enabled": true,
        "plans": plans
    })))
}

/// Get current subscription
async fn get_subscription(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.billing_service.is_enabled() {
        return Err(ApiError::BadRequest("Billing is not enabled".to_string()));
    }

    let subscription = state
        .billing_service
        .get_subscription(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    match subscription {
        Some(sub) => Ok(Json(json!({ "subscription": sub }))),
        None => Ok(Json(json!({ "subscription": null }))),
    }
}

/// Create new subscription (checkout)
async fn create_subscription(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateCheckoutRequest>,
) -> Result<Json<SubscriptionResponse>, ApiError> {
    if !state.billing_service.is_enabled() {
        return Err(ApiError::BadRequest("Billing is not enabled".to_string()));
    }

    let session = state
        .billing_service
        .create_checkout_session(
            &current_user.tenant_id,
            &req.price_id,
            &req.success_url,
            &req.cancel_url,
        )
        .await
        .map_err(|_| ApiError::internal())?;

    match session {
        Some(s) => {
            // Get current subscription (may be incomplete)
            let subscription = state
                .billing_service
                .get_subscription(&current_user.tenant_id)
                .await
                .map_err(|_| ApiError::internal())?
                .ok_or(ApiError::internal())?;

            Ok(Json(SubscriptionResponse {
                subscription,
                checkout_url: Some(s.url),
            }))
        }
        None => Err(ApiError::internal()),
    }
}

/// Cancel subscription at period end
async fn cancel_subscription(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.billing_service.is_enabled() {
        return Err(ApiError::BadRequest("Billing is not enabled".to_string()));
    }

    let subscription = state
        .billing_service
        .cancel_subscription(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    match subscription {
        Some(sub) => Ok(Json(json!({
            "message": "Subscription will be canceled at the end of the billing period",
            "subscription": sub
        }))),
        None => Err(ApiError::NotFound),
    }
}

/// Resume canceled subscription
async fn resume_subscription(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.billing_service.is_enabled() {
        return Err(ApiError::BadRequest("Billing is not enabled".to_string()));
    }

    let subscription = state
        .billing_service
        .resume_subscription(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    match subscription {
        Some(sub) => Ok(Json(json!({
            "message": "Subscription resumed",
            "subscription": sub
        }))),
        None => Err(ApiError::NotFound),
    }
}

/// Update subscription plan
async fn update_subscription(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<UpdateSubscriptionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.billing_service.is_enabled() {
        return Err(ApiError::BadRequest("Billing is not enabled".to_string()));
    }

    let subscription = state
        .billing_service
        .update_subscription_plan(&current_user.tenant_id, &req.new_price_id)
        .await
        .map_err(|_| ApiError::internal())?;

    match subscription {
        Some(sub) => Ok(Json(json!({
            "message": "Subscription plan updated",
            "subscription": sub
        }))),
        None => Err(ApiError::NotFound),
    }
}

/// List invoices for tenant
async fn list_invoices(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.billing_service.is_enabled() {
        return Ok(Json(json!({ "invoices": [] })));
    }

    let invoices = state
        .billing_service
        .list_invoices(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(json!({ "invoices": invoices })))
}

/// Create customer portal session
async fn create_portal_session(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreatePortalRequest>,
) -> Result<Json<PortalResponse>, ApiError> {
    if !state.billing_service.is_enabled() {
        return Err(ApiError::BadRequest("Billing is not enabled".to_string()));
    }

    let session = state
        .billing_service
        .create_portal_session(&current_user.tenant_id, &req.return_url)
        .await
        .map_err(|_| ApiError::internal())?;

    match session {
        Some(s) => Ok(Json(PortalResponse { url: s.url })),
        None => Err(ApiError::NotFound),
    }
}

/// Record usage for metered billing
async fn record_usage(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<RecordUsageRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !state.billing_service.is_enabled() {
        return Err(ApiError::BadRequest("Billing is not enabled".to_string()));
    }

    state
        .billing_service
        .record_usage(&current_user.tenant_id, req.quantity)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(json!({
        "message": "Usage recorded",
        "quantity": req.quantity
    })))
}

#[derive(Debug, Deserialize)]
struct CreatePortalRequest {
    return_url: String,
}

#[derive(Debug, Deserialize)]
struct RecordUsageRequest {
    quantity: i64,
}
