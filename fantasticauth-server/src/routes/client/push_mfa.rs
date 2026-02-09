//! Client Push MFA Routes
//!
//! Endpoints for users to:
//! - Register and manage push devices
//! - Initiate push MFA challenges during login
//! - Poll for push response status
//! - Respond to push requests (from mobile app)

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::mfa::push::{
    device::{DeviceInfo, RegisterDeviceRequest, RenameDeviceRequest},
    polling::{PollingResponse, PushPollingService},
    PushMfaService, PushResponse, PushRequestStatus,
};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Push MFA client routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // Device management
        .route("/mfa/push/devices", get(list_devices).post(register_device))
        .route(
            "/mfa/push/devices/:device_id",
            delete(remove_device).patch(rename_device),
        )
        // MFA challenge
        .route("/mfa/push/challenge", post(initiate_challenge))
        .route("/mfa/push/status/:request_id", get(get_request_status))
        .route("/mfa/push/poll/:request_id", get(poll_request_status))
        // Mobile app response endpoint
        .route("/mfa/push/respond", post(respond_to_push))
        // WebSocket endpoint (requires axum ws feature)
        // .route("/mfa/push/ws", get(websocket_handler))
}

// ============ Request/Response Types ============

#[derive(Debug, Serialize)]
struct DeviceListResponse {
    devices: Vec<DeviceInfo>,
}

#[derive(Debug, Deserialize)]
struct InitiateChallengeRequest {
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ChallengeResponse {
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "remainingSeconds")]
    remaining_seconds: i64,
}

#[derive(Debug, Deserialize)]
struct RespondToPushRequest {
    #[serde(rename = "requestId")]
    request_id: String,
    action: String, // "approve" or "deny"
    #[serde(rename = "deviceId")]
    device_id: String,
    signature: Option<String>,
}

#[derive(Debug, Serialize)]
struct RespondResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Deserialize)]
struct PollQuery {
    #[serde(rename = "timeoutSeconds")]
    timeout_seconds: Option<u64>,
}

// ============ Device Management ============

/// List registered push devices for the current user
async fn list_devices(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<DeviceListResponse>, ApiError> {
    let service = get_push_service(&state)?;

    let devices = service
        .get_user_devices(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list push devices: {}", e);
            ApiError::Internal
        })?;

    let device_infos: Vec<DeviceInfo> = devices.into_iter().map(Into::into).collect();

    Ok(Json(DeviceListResponse {
        devices: device_infos,
    }))
}

/// Register a new push device
async fn register_device(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<RegisterDeviceRequest>,
) -> Result<Json<DeviceInfo>, ApiError> {
    let service = get_push_service(&state)?;

    // Parse device type
    let device_type = req
        .device_type
        .parse()
        .map_err(|e: String| ApiError::BadRequest(e))?;

    // Validate device token
    crate::mfa::push::device::validate_device_token(&req.device_token, device_type)
        .map_err(ApiError::BadRequest)?;

    let device = service
        .register_device(
            &current_user.tenant_id,
            &current_user.user_id,
            device_type,
            &req.device_token,
            req.device_name,
            req.public_key,
        )
        .await
        .map_err(|e| match e {
            crate::mfa::push::PushMfaError::MaxDevicesExceeded(max) => {
                ApiError::BadRequest(format!("Maximum devices exceeded (limit: {})", max))
            }
            crate::mfa::push::PushMfaError::InvalidDeviceToken => {
                ApiError::BadRequest("Invalid device token".to_string())
            }
            _ => {
                tracing::error!("Failed to register device: {}", e);
                ApiError::Internal
            }
        })?;

    // Audit log
    crate::audit::log_activity(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        "push_device_registered",
        Some(&device.id),
    )
    .await;

    Ok(Json(DeviceInfo::from(device)))
}

/// Remove/deactivate a push device
async fn remove_device(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(device_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let service = get_push_service(&state)?;

    service
        .deactivate_device(&current_user.tenant_id, &current_user.user_id, &device_id)
        .await
        .map_err(|e| match e {
            crate::mfa::push::PushMfaError::DeviceNotFound(_) => ApiError::NotFound,
            _ => {
                tracing::error!("Failed to remove device: {}", e);
                ApiError::Internal
            }
        })?;

    // Audit log
    crate::audit::log_activity(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        "push_device_removed",
        Some(&device_id),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Rename a push device
async fn rename_device(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(device_id): Path<String>,
    Json(req): Json<RenameDeviceRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let service = get_push_service(&state)?;

    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("Device name cannot be empty".to_string()));
    }

    if req.name.len() > 255 {
        return Err(ApiError::BadRequest("Device name too long".to_string()));
    }

    service
        .rename_device(
            &current_user.tenant_id,
            &current_user.user_id,
            &device_id,
            &req.name,
        )
        .await
        .map_err(|e| match e {
            crate::mfa::push::PushMfaError::DeviceNotFound(_) => ApiError::NotFound,
            _ => {
                tracing::error!("Failed to rename device: {}", e);
                ApiError::Internal
            }
        })?;

    Ok(Json(serde_json::json!({
        "message": "Device renamed successfully"
    })))
}

// ============ Challenge/Response ============

/// Initiate a push MFA challenge
async fn initiate_challenge(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<InitiateChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let service = get_push_service(&state)?;

    // Check if user has registered devices
    let devices = service
        .get_user_devices(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    if devices.is_empty() {
        return Err(ApiError::BadRequest(
            "No push devices registered. Please set up push MFA first.".to_string()
        ));
    }

    // Create push request
    let request = service
        .create_request(
            &current_user.tenant_id,
            &current_user.user_id,
            req.session_id,
            None, // IP address would be extracted from request
            None, // User agent would be extracted from request
        )
        .await
        .map_err(|e| match e {
            crate::mfa::push::PushMfaError::DeviceNotFound(msg) => {
                ApiError::BadRequest(msg)
            }
            _ => {
                tracing::error!("Failed to create push request: {}", e);
                ApiError::Internal
            }
        })?;

    let request_id = request.id.clone();
    let expires_at = request.expires_at.to_rfc3339();
    let remaining_seconds = request.remaining_seconds();
    Ok(Json(ChallengeResponse {
        request_id,
        expires_at,
        remaining_seconds,
    }))
}

/// Get current status of a push request
async fn get_request_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(request_id): Path<String>,
) -> Result<Json<PollingResponse>, ApiError> {
    let service = get_push_service(&state)?;

    let request = service
        .get_request(&current_user.tenant_id, &current_user.user_id, &request_id)
        .await
        .map_err(|e| match e {
            crate::mfa::push::PushMfaError::RequestNotFound(_) => ApiError::NotFound,
            _ => {
                tracing::error!("Failed to get request status: {}", e);
                ApiError::Internal
            }
        })?;

    let request_id = request.id.clone();
    let status = request.status.to_string();
    let remaining_seconds = request.remaining_seconds();
    let completed_at = request.responded_at.map(|d| d.to_rfc3339());
    Ok(Json(PollingResponse {
        request_id,
        status,
        remaining_seconds,
        completed_at,
    }))
}

/// Long-poll for request status (waits for status change or timeout)
async fn poll_request_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(request_id): Path<String>,
    Query(query): Query<PollQuery>,
) -> Result<Json<PollingResponse>, ApiError> {
    let polling_service = get_polling_service(&state)?;

    let response = polling_service
        .poll_request_status(
            &current_user.tenant_id,
            &current_user.user_id,
            &request_id,
            query.timeout_seconds,
        )
        .await
        .map_err(|e| match e {
            crate::mfa::push::PushMfaError::RequestNotFound(_) => ApiError::NotFound,
            _ => {
                tracing::error!("Failed to poll request: {}", e);
                ApiError::Internal
            }
        })?;

    Ok(Json(response))
}

/// Respond to a push MFA request (called from mobile app)
async fn respond_to_push(
    State(state): State<AppState>,
    Json(req): Json<RespondToPushRequest>,
) -> Result<Json<RespondResponse>, ApiError> {
    let service = get_push_service(&state)?;

    // Parse response action
    let response = match req.action.to_lowercase().as_str() {
        "approve" => PushResponse::Approve,
        "deny" => PushResponse::Deny,
        _ => return Err(ApiError::BadRequest("Invalid action. Use 'approve' or 'deny'".to_string())),
    };

    let request = service
        .respond_to_request(&req.request_id, &req.device_id, response, req.signature)
        .await
        .map_err(|e| match e {
            crate::mfa::push::PushMfaError::RequestNotFound(_) => ApiError::NotFound,
            crate::mfa::push::PushMfaError::RequestExpired(_) => {
                ApiError::BadRequest("Request has expired".to_string())
            }
            crate::mfa::push::PushMfaError::InvalidSignature => {
                ApiError::BadRequest("Invalid signature".to_string())
            }
            _ => {
                tracing::error!("Failed to respond to push: {}", e);
                ApiError::Internal
            }
        })?;

    // Trigger webhooks based on response
    let message = match request.status {
        PushRequestStatus::Approved => {
            crate::webhooks::events::trigger_mfa_verified(
                &state,
                &request.tenant_id,
                &request.user_id,
                "push",
            )
            .await;
            "Request approved".to_string()
        }
        PushRequestStatus::Denied => {
            crate::webhooks::events::trigger_mfa_denied(
                &state,
                &request.tenant_id,
                &request.user_id,
                "push",
            )
            .await;
            "Request denied".to_string()
        }
        _ => "Request processed".to_string(),
    };

    Ok(Json(RespondResponse {
        success: true,
        message,
    }))
}

// ============ WebSocket ============

/// WebSocket handler for real-time push MFA updates
/// Note: Requires axum ws feature to be enabled
#[allow(dead_code)]
async fn _websocket_handler(
    State(_state): State<AppState>,
) -> axum::response::Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "WebSocket support not enabled. Enable the 'ws' feature in axum.",
    )
        .into_response()
}

// ============ Helper Functions ============

/// Get push MFA service from app state
fn get_push_service(state: &AppState) -> Result<PushMfaService, ApiError> {
    // In production, the PushMfaService would be stored in AppState
    // For now, we create it on demand
    let config = crate::mfa::push::PushMfaConfig::default();
    Ok(PushMfaService::new(
        state.db.clone(),
        state.redis.clone(),
        config,
    ))
}

/// Get polling service from app state
fn get_polling_service(state: &AppState) -> Result<PushPollingService, ApiError> {
    Ok(PushPollingService::new(state.db.clone(), state.redis.clone()))
}

// ============ Integration with Auth Flow ============

/// Extension trait for integrating push MFA into authentication
pub trait PushMfaAuthExt {
    /// Check if push MFA is available for user
    async fn is_push_mfa_available(&self, user_id: &str, tenant_id: &str) -> bool;
    
    /// Initiate push MFA during login flow
    async fn initiate_push_mfa_login(
        &self,
        user_id: &str,
        tenant_id: &str,
        session_id: &str,
    ) -> Result<String, ApiError>;
}

impl PushMfaAuthExt for AppState {
    async fn is_push_mfa_available(&self, user_id: &str, tenant_id: &str) -> bool {
        let service = match get_push_service(self) {
            Ok(s) => s,
            Err(_) => return false,
        };

        match service.get_user_devices(tenant_id, user_id).await {
            Ok(devices) => !devices.is_empty(),
            Err(_) => false,
        }
    }

    async fn initiate_push_mfa_login(
        &self,
        user_id: &str,
        tenant_id: &str,
        session_id: &str,
    ) -> Result<String, ApiError> {
        let service = get_push_service(self)?;

        let request = service
            .create_request(
                tenant_id,
                user_id,
                Some(session_id.to_string()),
                None,
                None,
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to initiate push MFA: {}", e);
                ApiError::Internal
            })?;

        Ok(request.id)
    }
}
