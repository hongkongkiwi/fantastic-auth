//! Admin Push MFA Routes
//!
//! Administrative endpoints for:
//! - Managing push MFA configuration (FCM/APNS credentials)
//! - Viewing and managing push devices for all users
//! - Push MFA statistics and analytics
//! - Tenant-wide push MFA settings

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, post, put},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::collections::HashMap;

use crate::mfa::push::{
    device::DeviceInfo,
    PushMfaService, PushRequestStatus,
};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Admin push MFA routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // Settings/configuration
        .route("/push-mfa/settings", get(get_settings).put(update_settings))
        .route("/push-mfa/settings/test", post(test_configuration))
        // Credentials management
        .route("/push-mfa/credentials/fcm", put(update_fcm_credentials))
        .route("/push-mfa/credentials/apns", put(update_apns_credentials))
        .route("/push-mfa/credentials", delete(clear_credentials))
        // Device management (admin view of all devices)
        .route("/push-mfa/devices", get(list_all_devices))
        .route("/push-mfa/devices/:device_id", get(get_device).delete(admin_remove_device))
        // User device management
        .route("/push-mfa/users/:user_id/devices", get(get_user_devices))
        // Statistics
        .route("/push-mfa/stats", get(get_statistics))
        .route("/push-mfa/stats/overview", get(get_overview_stats))
        // Request management
        .route("/push-mfa/requests", get(list_recent_requests))
        .route("/push-mfa/requests/:request_id", get(get_request_details))
        .route("/push-mfa/requests/:request_id/cancel", post(cancel_request))
}

// ============ Request/Response Types ============

#[derive(Debug, Serialize)]
struct SettingsResponse {
    #[serde(rename = "fcmEnabled")]
    fcm_enabled: bool,
    #[serde(rename = "apnsEnabled")]
    apns_enabled: bool,
    #[serde(rename = "requestTimeoutSeconds")]
    request_timeout_seconds: i32,
    #[serde(rename = "maxDevicesPerUser")]
    max_devices_per_user: i32,
    #[serde(rename = "fcmProjectId")]
    fcm_project_id: Option<String>,
    #[serde(rename = "apnsBundleId")]
    apns_bundle_id: Option<String>,
    #[serde(rename = "apnsUseSandbox")]
    apns_use_sandbox: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UpdateSettingsRequest {
    #[serde(rename = "requestTimeoutSeconds")]
    request_timeout_seconds: Option<i32>,
    #[serde(rename = "maxDevicesPerUser")]
    max_devices_per_user: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct FcmCredentialsRequest {
    #[serde(rename = "projectId")]
    project_id: String,
    #[serde(rename = "serviceAccountJson")]
    service_account_json: String,
}

#[derive(Debug, Deserialize)]
struct ApnsCredentialsRequest {
    #[serde(rename = "keyId")]
    key_id: String,
    #[serde(rename = "teamId")]
    team_id: String,
    #[serde(rename = "bundleId")]
    bundle_id: String,
    #[serde(rename = "privateKey")]
    private_key: String,
    #[serde(rename = "useSandbox")]
    use_sandbox: bool,
}

#[derive(Debug, Serialize)]
struct DeviceListResponse {
    devices: Vec<AdminDeviceInfo>,
    #[serde(rename = "totalCount")]
    total_count: i64,
}

#[derive(Debug, Serialize)]
struct AdminDeviceInfo {
    #[serde(flatten)]
    device: DeviceInfo,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "userEmail")]
    user_email: Option<String>,
    #[serde(rename = "tenantId")]
    tenant_id: String,
}

#[derive(Debug, Deserialize)]
struct ListDevicesQuery {
    #[serde(rename = "userId")]
    user_id: Option<String>,
    #[serde(rename = "deviceType")]
    device_type: Option<String>,
    #[serde(default)]
    page: i64,
    #[serde(rename = "perPage", default = "default_per_page")]
    per_page: i64,
}

fn default_per_page() -> i64 {
    20
}

#[derive(Debug, Serialize)]
struct StatisticsResponse {
    #[serde(rename = "totalDevices")]
    total_devices: i64,
    #[serde(rename = "activeDevices")]
    active_devices: i64,
    #[serde(rename = "iosDevices")]
    ios_devices: i64,
    #[serde(rename = "androidDevices")]
    android_devices: i64,
    #[serde(rename = "totalRequests24h")]
    total_requests_24h: i64,
    #[serde(rename = "approvedRequests24h")]
    approved_requests_24h: i64,
    #[serde(rename = "deniedRequests24h")]
    denied_requests_24h: i64,
    #[serde(rename = "expiredRequests24h")]
    expired_requests_24h: i64,
    #[serde(rename = "pendingRequests")]
    pending_requests: i64,
}

#[derive(Debug, Serialize)]
struct OverviewStatsResponse {
    #[serde(rename = "usersWithPushMfa")]
    users_with_push_mfa: i64,
    #[serde(rename = "avgDevicesPerUser")]
    avg_devices_per_user: f64,
    #[serde(rename = "pushMfaAdoptionRate")]
    push_mfa_adoption_rate: f64,
}

#[derive(Debug, Serialize)]
struct RequestDetailsResponse {
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "userEmail")]
    user_email: Option<String>,
    status: String,
    #[serde(rename = "ipAddress")]
    ip_address: Option<String>,
    #[serde(rename = "userAgent")]
    user_agent: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "respondedAt")]
    responded_at: Option<String>,
    #[serde(rename = "deviceId")]
    device_id: Option<String>,
    #[serde(rename = "deviceName")]
    device_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListRequestsQuery {
    #[serde(rename = "userId")]
    user_id: Option<String>,
    status: Option<String>,
    #[serde(default)]
    page: i64,
    #[serde(rename = "perPage", default = "default_per_page")]
    per_page: i64,
}

// ============ Settings Management ============

/// Get current push MFA settings
async fn get_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SettingsResponse>, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT fcm_enabled, apns_enabled, request_timeout_seconds, max_devices_per_user,
               fcm_service_account_json_encrypted IS NOT NULL as has_fcm_creds,
               apns_bundle_id, apns_use_sandbox
        FROM push_mfa_settings
        WHERE tenant_id = $1
        "#
    )
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to get push MFA settings: {}", e);
        ApiError::Internal
    })?;

    let response = match row {
        Some(row) => SettingsResponse {
            fcm_enabled: row.get("fcm_enabled"),
            apns_enabled: row.get("apns_enabled"),
            request_timeout_seconds: row.get("request_timeout_seconds"),
            max_devices_per_user: row.get("max_devices_per_user"),
            fcm_project_id: None, // Extracted from encrypted credentials
            apns_bundle_id: row.get("apns_bundle_id"),
            apns_use_sandbox: row.get("apns_use_sandbox"),
        },
        None => SettingsResponse {
            fcm_enabled: false,
            apns_enabled: false,
            request_timeout_seconds: 300,
            max_devices_per_user: 5,
            fcm_project_id: None,
            apns_bundle_id: None,
            apns_use_sandbox: None,
        },
    };

    Ok(Json(response))
}

/// Update push MFA settings
async fn update_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<Json<SettingsResponse>, ApiError> {
    // Validate settings
    if let Some(timeout) = req.request_timeout_seconds {
        if timeout < 30 || timeout > 1800 {
            return Err(ApiError::BadRequest(
                "Request timeout must be between 30 and 1800 seconds".to_string()
            ));
        }
    }

    if let Some(max_devices) = req.max_devices_per_user {
        if max_devices < 1 || max_devices > 10 {
            return Err(ApiError::BadRequest(
                "Max devices per user must be between 1 and 10".to_string()
            ));
        }
    }

    sqlx::query(
        r#"
        INSERT INTO push_mfa_settings 
        (tenant_id, request_timeout_seconds, max_devices_per_user, updated_at)
        VALUES ($1, COALESCE($2, 300), COALESCE($3, 5), NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET
            request_timeout_seconds = COALESCE($2, push_mfa_settings.request_timeout_seconds),
            max_devices_per_user = COALESCE($3, push_mfa_settings.max_devices_per_user),
            updated_at = NOW()
        "#
    )
    .bind(&current_user.tenant_id)
    .bind(req.request_timeout_seconds)
    .bind(req.max_devices_per_user)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to update push MFA settings: {}", e);
        ApiError::Internal
    })?;

    // Audit log
    crate::audit::log_activity(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        "push_mfa_settings_updated",
        None,
    )
    .await;

    // Return updated settings
    get_settings(State(state), Extension(current_user)).await
}

/// Test push MFA configuration
async fn test_configuration(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let device_token = req.get("deviceToken")
        .ok_or_else(|| ApiError::BadRequest("deviceToken required".to_string()))?;
    let device_type = req.get("deviceType")
        .ok_or_else(|| ApiError::BadRequest("deviceType required".to_string()))?;

    // Validate configuration exists
    let settings = sqlx::query(
        "SELECT fcm_enabled, apns_enabled FROM push_mfa_settings WHERE tenant_id = $1"
    )
    .bind(&current_user.tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let (fcm_enabled, apns_enabled) = match settings {
        Some(row) => (
            row.get::<bool, _>("fcm_enabled"),
            row.get::<bool, _>("apns_enabled"),
        ),
        None => (false, false),
    };

    // Check if provider is enabled for device type
    match device_type.as_str() {
        "android" => {
            if !fcm_enabled {
                return Err(ApiError::BadRequest(
                    "FCM is not enabled for this tenant".to_string()
                ));
            }
        }
        "ios" => {
            if !apns_enabled {
                return Err(ApiError::BadRequest(
                    "APNS is not enabled for this tenant".to_string()
                ));
            }
        }
        _ => return Err(ApiError::BadRequest("Invalid device type".to_string())),
    }

    // In production, this would actually send a test notification
    // For now, we just validate the configuration
    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Configuration appears valid. Test notification would be sent in production.",
        "deviceToken": device_token.chars().take(8).collect::<String>() + "...",
    })))
}

// ============ Credentials Management ============

/// Update FCM credentials
async fn update_fcm_credentials(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<FcmCredentialsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Validate service account JSON
    let service_account: serde_json::Value = serde_json::from_str(&req.service_account_json)
        .map_err(|e| ApiError::BadRequest(format!("Invalid service account JSON: {}", e)))?;

    let project_id = service_account
        .get("project_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError::BadRequest("Missing project_id in service account".to_string()))?;

    // Encrypt service account JSON using tenant key service
    let dek = state
        .tenant_key_service
        .get_data_key(&current_user.tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load tenant DEK: {}", e);
            ApiError::Internal
        })?;
    let encrypted =
        crate::security::encryption::encrypt_to_base64(&dek, req.service_account_json.as_bytes())
            .map_err(|e| {
                tracing::error!("Failed to encrypt FCM credentials: {}", e);
                ApiError::Internal
            })?;

    sqlx::query(
        r#"
        INSERT INTO push_mfa_settings 
        (tenant_id, fcm_enabled, fcm_service_account_json_encrypted, updated_at)
        VALUES ($1, TRUE, $2, NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET
            fcm_enabled = TRUE,
            fcm_service_account_json_encrypted = $2,
            updated_at = NOW()
        "#
    )
    .bind(&current_user.tenant_id)
    .bind(&encrypted)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to save FCM credentials: {}", e);
        ApiError::Internal
    })?;

    // Audit log (without sensitive data)
    crate::audit::log_activity(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        "push_mfa_fcm_credentials_updated",
        Some(&format!("project_id: {}", project_id)),
    )
    .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "FCM credentials updated",
        "projectId": project_id,
    })))
}

/// Update APNS credentials
async fn update_apns_credentials(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<ApnsCredentialsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Validate private key format (P8)
    if !req.private_key.contains("BEGIN PRIVATE KEY") {
        return Err(ApiError::BadRequest(
            "Invalid private key format. Expected P8 format.".to_string()
        ));
    }

    // Encrypt private key
    let dek = state
        .tenant_key_service
        .get_data_key(&current_user.tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to load tenant DEK: {}", e);
            ApiError::Internal
        })?;
    let encrypted = crate::security::encryption::encrypt_to_base64(&dek, req.private_key.as_bytes())
        .map_err(|e| {
            tracing::error!("Failed to encrypt APNS credentials: {}", e);
            ApiError::Internal
        })?;

    sqlx::query(
        r#"
        INSERT INTO push_mfa_settings 
        (tenant_id, apns_enabled, apns_key_id, apns_team_id, apns_bundle_id, 
         apns_private_key_encrypted, apns_use_sandbox, updated_at)
        VALUES ($1, TRUE, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET
            apns_enabled = TRUE,
            apns_key_id = $2,
            apns_team_id = $3,
            apns_bundle_id = $4,
            apns_private_key_encrypted = $5,
            apns_use_sandbox = $6,
            updated_at = NOW()
        "#
    )
    .bind(&current_user.tenant_id)
    .bind(&req.key_id)
    .bind(&req.team_id)
    .bind(&req.bundle_id)
    .bind(&encrypted)
    .bind(req.use_sandbox)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to save APNS credentials: {}", e);
        ApiError::Internal
    })?;

    // Audit log
    crate::audit::log_activity(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        "push_mfa_apns_credentials_updated",
        Some(&format!("bundle_id: {}", req.bundle_id)),
    )
    .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "APNS credentials updated",
        "bundleId": req.bundle_id,
        "useSandbox": req.use_sandbox,
    })))
}

/// Clear push MFA credentials
async fn clear_credentials(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<HashMap<String, String>>,
) -> Result<StatusCode, ApiError> {
    let provider = req.get("provider")
        .ok_or_else(|| ApiError::BadRequest("provider required (fcm or apns)".to_string()))?;

    match provider.as_str() {
        "fcm" => {
            sqlx::query(
                "UPDATE push_mfa_settings SET fcm_enabled = FALSE, fcm_service_account_json_encrypted = NULL WHERE tenant_id = $1"
            )
            .bind(&current_user.tenant_id)
            .execute(state.db.pool())
            .await
            .map_err(|_| ApiError::Internal)?;
        }
        "apns" => {
            sqlx::query(
                "UPDATE push_mfa_settings SET apns_enabled = FALSE, apns_private_key_encrypted = NULL WHERE tenant_id = $1"
            )
            .bind(&current_user.tenant_id)
            .execute(state.db.pool())
            .await
            .map_err(|_| ApiError::Internal)?;
        }
        _ => return Err(ApiError::BadRequest("Invalid provider".to_string())),
    }

    // Audit log
    crate::audit::log_activity(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        &format!("push_mfa_{}_credentials_cleared", provider),
        None,
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

use axum::http::StatusCode;

// ============ Device Management ============

/// List all push devices (admin view)
async fn list_all_devices(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListDevicesQuery>,
) -> Result<Json<DeviceListResponse>, ApiError> {
    const MAX_PER_PAGE: i64 = 100;
    let per_page = query.per_page.min(MAX_PER_PAGE);
    let offset = (query.page - 1) * per_page;

    // Get total count
    let mut count_builder =
        sqlx::QueryBuilder::new("SELECT COUNT(*) FROM push_devices d WHERE d.tenant_id = ");
    count_builder.push_bind(&current_user.tenant_id);
    if let Some(user_id) = &query.user_id {
        count_builder.push(" AND d.user_id = ").push_bind(user_id);
    }
    if let Some(device_type) = &query.device_type {
        count_builder.push(" AND d.device_type = ").push_bind(device_type);
    }
    let (total_count,) = count_builder
        .build_query_as::<(i64,)>()
        .fetch_one(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;

    // Get devices with user info
    let mut devices_builder = sqlx::QueryBuilder::new(
        r#"
        SELECT d.id, d.user_id, d.device_type as "device_type: crate::mfa::push::device::DeviceType",
               d.device_name, d.is_active, d.created_at, d.last_used_at,
               u.email as user_email
        FROM push_devices d
        JOIN users u ON d.user_id = u.id AND d.tenant_id = u.tenant_id
        WHERE d.tenant_id = "#
    );
    devices_builder.push_bind(&current_user.tenant_id);
    if let Some(user_id) = &query.user_id {
        devices_builder.push(" AND d.user_id = ").push_bind(user_id);
    }
    if let Some(device_type) = &query.device_type {
        devices_builder.push(" AND d.device_type = ").push_bind(device_type);
    }
    devices_builder
        .push(" ORDER BY d.last_used_at DESC NULLS LAST, d.created_at DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);

    let devices = devices_builder
        .build()
        .fetch_all(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to list devices: {}", e);
            ApiError::Internal
        })?;

    let device_infos: Vec<AdminDeviceInfo> = devices
        .into_iter()
        .map(|row| {
            use sqlx::Row;
            let device = crate::mfa::push::PushDevice {
                id: row.get("id"),
                user_id: row.get("user_id"),
                tenant_id: current_user.tenant_id.clone(),
                device_type: row.get("device_type"),
                device_name: row.get("device_name"),
                device_token: String::new(), // Don't expose token
                is_active: row.get("is_active"),
                created_at: row.get("created_at"),
                last_used_at: row.get("last_used_at"),
                public_key: None,
            };

            AdminDeviceInfo {
                device: DeviceInfo::from(device),
                user_id: row.get("user_id"),
                user_email: row.get("user_email"),
                tenant_id: current_user.tenant_id.clone(),
            }
        })
        .collect();

    Ok(Json(DeviceListResponse {
        devices: device_infos,
        total_count,
    }))
}

/// Get specific device details
async fn get_device(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(device_id): Path<String>,
) -> Result<Json<AdminDeviceInfo>, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT d.id, d.user_id, d.device_type as "device_type: crate::mfa::push::device::DeviceType",
               d.device_name, d.is_active, d.created_at, d.last_used_at,
               u.email as user_email
        FROM push_devices d
        JOIN users u ON d.user_id = u.id AND d.tenant_id = u.tenant_id
        WHERE d.tenant_id = $1 AND d.id = $2
        "#
    )
    .bind(&current_user.tenant_id)
    .bind(&device_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let row = row.ok_or(ApiError::NotFound)?;

    use sqlx::Row;
    let device = crate::mfa::push::PushDevice {
        id: row.get("id"),
        user_id: row.get("user_id"),
        tenant_id: current_user.tenant_id.clone(),
        device_type: row.get("device_type"),
        device_name: row.get("device_name"),
        device_token: String::new(),
        is_active: row.get("is_active"),
        created_at: row.get("created_at"),
        last_used_at: row.get("last_used_at"),
        public_key: None,
    };

    Ok(Json(AdminDeviceInfo {
        device: DeviceInfo::from(device),
        user_id: row.get("user_id"),
        user_email: row.get("user_email"),
        tenant_id: current_user.tenant_id.clone(),
    }))
}

/// Admin remove a device
async fn admin_remove_device(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(device_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let service = PushMfaService::new(
        state.db.clone(),
        state.redis.clone(),
        crate::mfa::push::PushMfaConfig::default(),
    );

    // Get device first to log user_id
    let device = sqlx::query("SELECT user_id FROM push_devices WHERE tenant_id = $1 AND id = $2")
        .bind(&current_user.tenant_id)
        .bind(&device_id)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;

    let user_id: Option<String> = device.as_ref().map(|row| row.get("user_id"));

    // Deactivate device (soft delete)
    sqlx::query("UPDATE push_devices SET is_active = FALSE WHERE tenant_id = $1 AND id = $2")
        .bind(&current_user.tenant_id)
        .bind(&device_id)
        .execute(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;

    // Audit log
    crate::audit::log_activity(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        "push_device_admin_removed",
        user_id.as_deref(),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Get devices for a specific user
async fn get_user_devices(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<DeviceInfo>>, ApiError> {
    let service = PushMfaService::new(
        state.db.clone(),
        state.redis.clone(),
        crate::mfa::push::PushMfaConfig::default(),
    );

    let devices = service
        .get_user_devices(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let device_infos: Vec<DeviceInfo> = devices.into_iter().map(Into::into).collect();

    Ok(Json(device_infos))
}

// ============ Statistics ============

/// Get push MFA statistics
async fn get_statistics(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<StatisticsResponse>, ApiError> {
    let pool = state.db.pool();

    // Device statistics
    let total_devices: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM push_devices WHERE tenant_id = $1"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let active_devices: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM push_devices WHERE tenant_id = $1 AND is_active = TRUE"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let ios_devices: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM push_devices WHERE tenant_id = $1 AND device_type = 'ios'"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let android_devices: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM push_devices WHERE tenant_id = $1 AND device_type = 'android'"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    // Request statistics (last 24 hours)
    let total_requests_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM push_requests WHERE tenant_id = $1 AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let approved_requests_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM push_requests WHERE tenant_id = $1 AND status = 'approved' AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let denied_requests_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM push_requests WHERE tenant_id = $1 AND status = 'denied' AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let expired_requests_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM push_requests WHERE tenant_id = $1 AND status = 'expired' AND created_at > NOW() - INTERVAL '24 hours'"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let pending_requests: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM push_requests WHERE tenant_id = $1 AND status = 'pending'"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    Ok(Json(StatisticsResponse {
        total_devices,
        active_devices,
        ios_devices,
        android_devices,
        total_requests_24h,
        approved_requests_24h,
        denied_requests_24h,
        expired_requests_24h,
        pending_requests,
    }))
}

/// Get overview/adoption statistics
async fn get_overview_stats(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<OverviewStatsResponse>, ApiError> {
    let pool = state.db.pool();

    let users_with_push_mfa: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT user_id) FROM push_devices WHERE tenant_id = $1 AND is_active = TRUE"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let total_users: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND deleted_at IS NULL"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or(1); // Avoid division by zero

    let adoption_rate = if total_users > 0 {
        (users_with_push_mfa as f64 / total_users as f64) * 100.0
    } else {
        0.0
    };

    let avg_devices_per_user: Option<f64> = sqlx::query_scalar(
        "SELECT AVG(device_count) FROM (SELECT COUNT(*) as device_count FROM push_devices WHERE tenant_id = $1 AND is_active = TRUE GROUP BY user_id) as counts"
    )
    .bind(&current_user.tenant_id)
    .fetch_one(pool)
    .await
    .ok()
    .flatten();

    Ok(Json(OverviewStatsResponse {
        users_with_push_mfa,
        avg_devices_per_user: avg_devices_per_user.unwrap_or(0.0),
        push_mfa_adoption_rate: adoption_rate,
    }))
}

// ============ Request Management ============

/// List recent push MFA requests
async fn list_recent_requests(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListRequestsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    const MAX_PER_PAGE: i64 = 100;
    let per_page = query.per_page.min(MAX_PER_PAGE);
    let offset = (query.page - 1) * per_page;

    let mut sql = String::from(
        r#"
        SELECT r.id, r.user_id, r.status, r.ip_address, r.user_agent, 
               r.created_at, r.expires_at, r.responded_at,
               u.email as user_email
        FROM push_requests r
        JOIN users u ON r.user_id = u.id AND r.tenant_id = u.tenant_id
        WHERE r.tenant_id = $1
        "#
    );

    if query.user_id.is_some() {
        sql.push_str(" AND r.user_id = $4");
    }
    if query.status.is_some() {
        sql.push_str(" AND r.status = $5");
    }

    sql.push_str(" ORDER BY r.created_at DESC LIMIT $2 OFFSET $3");

    let requests = sqlx::query(&sql)
        .bind(&current_user.tenant_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;

    let request_list: Vec<RequestDetailsResponse> = requests
        .into_iter()
        .map(|row| {
            use sqlx::Row;
            RequestDetailsResponse {
                request_id: row.get("id"),
                user_id: row.get("user_id"),
                user_email: row.get("user_email"),
                status: row.get::<PushRequestStatus, _>("status").to_string(),
                ip_address: row.get("ip_address"),
                user_agent: row.get("user_agent"),
                created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
                expires_at: row.get::<chrono::DateTime<chrono::Utc>, _>("expires_at").to_rfc3339(),
                responded_at: row
                    .get::<Option<chrono::DateTime<chrono::Utc>>, _>("responded_at")
                    .map(|d| d.to_rfc3339()),
                device_id: None,
                device_name: None,
            }
        })
        .collect();

    Ok(Json(serde_json::json!({
        "requests": request_list,
        "page": query.page,
        "perPage": per_page,
    })))
}

/// Get detailed information about a specific request
async fn get_request_details(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(request_id): Path<String>,
) -> Result<Json<RequestDetailsResponse>, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT r.id, r.user_id, r.status, r.ip_address, r.user_agent, 
               r.created_at, r.expires_at, r.responded_at, r.device_id,
               d.device_name,
               u.email as user_email
        FROM push_requests r
        JOIN users u ON r.user_id = u.id AND r.tenant_id = u.tenant_id
        LEFT JOIN push_devices d ON r.device_id = d.id
        WHERE r.tenant_id = $1 AND r.id = $2
        "#
    )
    .bind(&current_user.tenant_id)
    .bind(&request_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    let row = row.ok_or(ApiError::NotFound)?;

    use sqlx::Row;
    Ok(Json(RequestDetailsResponse {
        request_id: row.get("id"),
        user_id: row.get("user_id"),
        user_email: row.get("user_email"),
        status: row.get::<PushRequestStatus, _>("status").to_string(),
        ip_address: row.get("ip_address"),
        user_agent: row.get("user_agent"),
        created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        expires_at: row.get::<chrono::DateTime<chrono::Utc>, _>("expires_at").to_rfc3339(),
        responded_at: row
            .get::<Option<chrono::DateTime<chrono::Utc>>, _>("responded_at")
            .map(|d| d.to_rfc3339()),
        device_id: row.get("device_id"),
        device_name: row.get("device_name"),
    }))
}

/// Cancel a pending push MFA request
async fn cancel_request(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(request_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = sqlx::query(
        "UPDATE push_requests SET status = 'denied', responded_at = NOW() WHERE tenant_id = $1 AND id = $2 AND status = 'pending'"
    )
    .bind(&current_user.tenant_id)
    .bind(&request_id)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    // Audit log
    crate::audit::log_activity(
        &state,
        &current_user.tenant_id,
        &current_user.user_id,
        "push_request_cancelled",
        Some(&request_id),
    )
    .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Request cancelled"
    })))
}
