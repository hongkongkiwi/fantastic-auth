//! Device Management Routes
//!
//! Zero Trust device management endpoints for users to view and manage
//! device trust levels, revoke suspicious devices, and configure device policies.

use axum::{
    extract::{Extension, Path, State},
    routing::{delete, get, put},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Device information response
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DeviceInfo {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    #[serde(rename = "deviceType")]
    pub device_type: String,
    #[serde(rename = "trustScore")]
    pub trust_score: i32,
    #[serde(rename = "isTrusted")]
    pub is_trusted: bool,
    #[serde(rename = "lastSeenAt")]
    pub last_seen_at: DateTime<Utc>,
    #[serde(rename = "firstSeenAt")]
    pub first_seen_at: DateTime<Utc>,
    pub location: Option<String>,
    #[serde(rename = "ipAddress")]
    pub ip_address: String,
    #[serde(rename = "browserFingerprint")]
    pub browser_fingerprint: Option<String>,
    #[serde(rename = "encryptionStatus")]
    pub encryption_status: String,
    #[serde(rename = "mfaStatus")]
    pub mfa_status: String,
}

/// Valid location mismatch actions
const VALID_LOCATION_ACTIONS: &[&str] = &["prompt", "block", "allow"];

/// Device trust policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTrustPolicy {
    #[serde(rename = "autoRevokeUntrusted")]
    pub auto_revoke_untrusted: bool,
    #[serde(rename = "requireApprovalForNewDevices")]
    pub require_approval_for_new_devices: bool,
    #[serde(rename = "maxTrustScore")]
    pub max_trust_score: i32,
    #[serde(rename = "locationMismatchAction")]
    pub location_mismatch_action: String,
}

impl DeviceTrustPolicy {
    /// Validate the policy values
    pub fn validate(&self) -> Result<(), ApiError> {
        // Validate trust score range
        if self.max_trust_score < 0 || self.max_trust_score > 100 {
            return Err(ApiError::validation("max_trust_score must be between 0 and 100"));
        }
        
        // Validate location mismatch action
        if !VALID_LOCATION_ACTIONS.contains(&self.location_mismatch_action.as_str()) {
            return Err(ApiError::validation(format!(
                "location_mismatch_action must be one of: {}",
                VALID_LOCATION_ACTIONS.join(", ")
            )));
        }
        
        Ok(())
    }
}

/// Trust score update request
#[derive(Debug, Deserialize)]
pub struct UpdateTrustRequest {
    #[serde(rename = "trustScore")]
    pub trust_score: i32,
    #[serde(rename = "isTrusted")]
    pub is_trusted: bool,
}

/// Trust score update response
#[derive(Debug, Serialize)]
pub struct UpdateTrustResponse {
    pub success: bool,
    pub message: String,
}

/// Device list response
#[derive(Debug, Serialize)]
pub struct DeviceListResponse {
    pub devices: Vec<DeviceInfo>,
    pub total: usize,
}

/// Device statistics
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct DeviceStats {
    #[serde(rename = "totalDevices")]
    pub total_devices: i64,
    #[serde(rename = "trustedDevices")]
    pub trusted_devices: i64,
    #[serde(rename = "untrustedDevices")]
    pub untrusted_devices: i64,
    #[serde(rename = "avgTrustScore")]
    pub avg_trust_score: f64,
}

/// Create device routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/me/devices", get(list_my_devices))
        .route("/me/devices/stats", get(get_my_device_stats))
        .route("/me/devices/policy", get(get_my_device_policy).put(update_my_device_policy))
        .route("/me/devices/:device_id/trust", put(update_my_device_trust))
        .route("/me/devices/:device_id", delete(revoke_my_device))
}

/// List all devices for current user
async fn list_my_devices(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<DeviceListResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    let devices: Vec<DeviceInfo> = sqlx::query_as::<_, DeviceInfo>(
        r#"
        SELECT 
            d.id::text as id,
            d.user_id::text as user_id,
            d.device_name,
            d.device_type,
            d.trust_score,
            d.is_trusted,
            d.last_seen_at,
            d.first_seen_at,
            d.location,
            d.ip_address,
            d.browser_fingerprint,
            d.encryption_status,
            d.mfa_status
        FROM user_devices d
        WHERE d.user_id = $1 AND d.is_active = true
        ORDER BY d.last_seen_at DESC
        "#
    )
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    let total = devices.len();
    
    Ok(Json(DeviceListResponse { devices, total }))
}

/// Update device trust score
async fn update_my_device_trust(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(device_id): Path<Uuid>,
    Json(req): Json<UpdateTrustRequest>,
) -> Result<Json<UpdateTrustResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    // Validate trust score range
    if req.trust_score < 0 || req.trust_score > 100 {
        return Err(ApiError::bad_request("Trust score must be between 0 and 100"));
    }

    let result = sqlx::query(
        r#"
        UPDATE user_devices 
        SET trust_score = $1, is_trusted = $2, updated_at = NOW()
        WHERE id = $3 AND user_id = $4 AND is_active = true
        "#
    )
    .bind(req.trust_score)
    .bind(req.is_trusted)
    .bind(device_id)
    .bind(user_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Device not found"));
    }

    Ok(Json(UpdateTrustResponse {
        success: true,
        message: format!("Device trust score updated to {}", req.trust_score),
    }))
}

/// Revoke/remove a device
async fn revoke_my_device(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(device_id): Path<Uuid>,
) -> Result<Json<UpdateTrustResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    // Soft delete - mark as inactive
    let result = sqlx::query(
        r#"
        UPDATE user_devices 
        SET is_active = false, updated_at = NOW()
        WHERE id = $1 AND user_id = $2 AND is_active = true
        "#
    )
    .bind(device_id)
    .bind(user_id)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Device not found"));
    }

    Ok(Json(UpdateTrustResponse {
        success: true,
        message: "Device successfully revoked".to_string(),
    }))
}

/// Get device statistics for current user
async fn get_my_device_stats(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<DeviceStats>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    let stats = sqlx::query_as::<_, DeviceStats>(
        r#"
        SELECT 
            COUNT(*) as total_devices,
            COUNT(*) FILTER (WHERE is_trusted = true) as trusted_devices,
            COUNT(*) FILTER (WHERE is_trusted = false) as untrusted_devices,
            COALESCE(AVG(trust_score)::float8, 0.0) as avg_trust_score
        FROM user_devices 
        WHERE user_id = $1 AND is_active = true
        "#
    )
    .bind(user_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    Ok(Json(stats))
}

/// Get device policy for current user
async fn get_my_device_policy(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<DeviceTrustPolicy>, ApiError> {
    // Return default policy (can be stored in database later)
    Ok(Json(DeviceTrustPolicy {
        auto_revoke_untrusted: false,
        require_approval_for_new_devices: true,
        max_trust_score: 100,
        location_mismatch_action: "prompt".to_string(),
    }))
}

/// Update device policy for current user
async fn update_my_device_policy(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Json(policy): Json<DeviceTrustPolicy>,
) -> Result<Json<DeviceTrustPolicy>, ApiError> {
    // Validate policy values using the struct's validation method
    policy.validate()?;

    // Return the policy (can be stored in database later)
    Ok(Json(policy))
}
