//! Push Notification MFA Module
//!
//! Provides push notification-based multi-factor authentication allowing users
//! to approve or deny login requests via mobile app notifications.
//!
//! # Architecture
//!
//! - `PushMfaService`: Core service coordinating push MFA operations
//! - `PushDevice`: Represents a registered mobile device
//! - `PushRequest`: Represents an authentication request sent to a device
//! - FCM/APNS providers: Handle platform-specific push delivery
//! - Polling/WebSocket: Real-time status updates for clients

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub mod apns;
pub mod device;
pub mod fcm;
pub mod polling;

pub use device::{DeviceType, PushDevice};

/// Default request expiration time (5 minutes)
pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: i64 = 300;

/// Default maximum devices per user
pub const DEFAULT_MAX_DEVICES_PER_USER: i32 = 5;

/// Errors that can occur during push MFA operations
#[derive(Debug, Error)]
pub enum PushMfaError {
    #[error("Device not found: {0}")]
    DeviceNotFound(String),
    
    #[error("Request not found: {0}")]
    RequestNotFound(String),
    
    #[error("Request expired: {0}")]
    RequestExpired(String),
    
    #[error("Invalid device token")]
    InvalidDeviceToken,
    
    #[error("Failed to send push notification: {0}")]
    SendFailed(String),
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("Maximum devices exceeded (max: {0})")]
    MaxDevicesExceeded(i32),
    
    #[error("Push MFA not enabled for tenant")]
    NotEnabled,
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Status of a push MFA request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "push_request_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum PushRequestStatus {
    /// Request is pending user action
    Pending,
    /// User approved the request
    Approved,
    /// User denied the request
    Denied,
    /// Request expired without response
    Expired,
}

impl std::fmt::Display for PushRequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushRequestStatus::Pending => write!(f, "pending"),
            PushRequestStatus::Approved => write!(f, "approved"),
            PushRequestStatus::Denied => write!(f, "denied"),
            PushRequestStatus::Expired => write!(f, "expired"),
        }
    }
}

/// A push MFA request sent to a user's device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRequest {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub device_id: Option<String>,
    pub session_id: Option<String>,
    pub status: PushRequestStatus,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub responded_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub response_signature: Option<String>,
    pub response_timestamp: Option<DateTime<Utc>>,
}

impl PushRequest {
    /// Create a new push request
    pub fn new(
        user_id: impl Into<String>,
        tenant_id: impl Into<String>,
        session_id: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        timeout_seconds: i64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.into(),
            tenant_id: tenant_id.into(),
            device_id: None,
            session_id,
            status: PushRequestStatus::Pending,
            ip_address,
            user_agent,
            expires_at: now + Duration::seconds(timeout_seconds),
            responded_at: None,
            created_at: now,
            response_signature: None,
            response_timestamp: None,
        }
    }

    /// Check if the request has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the request is still pending
    pub fn is_pending(&self) -> bool {
        self.status == PushRequestStatus::Pending && !self.is_expired()
    }

    /// Get remaining time in seconds
    pub fn remaining_seconds(&self) -> i64 {
        let remaining = self.expires_at - Utc::now();
        remaining.num_seconds().max(0)
    }
}

/// User response to a push MFA request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushResponse {
    /// User approved the request
    Approve,
    /// User denied the request
    Deny,
}

impl std::fmt::Display for PushResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushResponse::Approve => write!(f, "approve"),
            PushResponse::Deny => write!(f, "deny"),
        }
    }
}

/// Push notification payload sent to devices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushNotification {
    /// Platform-specific notification data
    pub notification: NotificationContent,
    /// Custom data payload
    pub data: PushDataPayload,
}

/// Notification content for display
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationContent {
    pub title: String,
    pub body: String,
}

/// Custom data payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushDataPayload {
    pub request_id: String,
    #[serde(rename = "type")]
    pub notification_type: String,
    pub ip_address: Option<String>,
    pub location: Option<String>,
    pub device_info: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Push MFA service configuration
#[derive(Debug, Clone)]
pub struct PushMfaConfig {
    /// Request timeout in seconds
    pub request_timeout_seconds: i64,
    /// Maximum devices per user
    pub max_devices_per_user: i32,
    /// FCM configuration
    pub fcm: Option<FcmConfig>,
    /// APNS configuration
    pub apns: Option<ApnsConfig>,
}

impl Default for PushMfaConfig {
    fn default() -> Self {
        Self {
            request_timeout_seconds: DEFAULT_REQUEST_TIMEOUT_SECONDS,
            max_devices_per_user: DEFAULT_MAX_DEVICES_PER_USER,
            fcm: None,
            apns: None,
        }
    }
}

/// Firebase Cloud Messaging configuration
#[derive(Debug, Clone)]
pub struct FcmConfig {
    /// Path to service account JSON file
    pub service_account_path: Option<String>,
    /// Service account JSON content (encrypted)
    pub service_account_json: Option<String>,
    /// Project ID
    pub project_id: String,
}

/// Apple Push Notification Service configuration
#[derive(Debug, Clone)]
pub struct ApnsConfig {
    /// APNS key ID
    pub key_id: String,
    /// Apple Team ID
    pub team_id: String,
    /// Bundle ID
    pub bundle_id: String,
    /// Private key (encrypted)
    pub private_key: String,
    /// Use sandbox environment
    pub use_sandbox: bool,
}

/// Core push MFA service
#[derive(Clone)]
pub struct PushMfaService {
    db: crate::db::Database,
    redis: Option<redis::aio::ConnectionManager>,
    fcm_client: Option<Arc<fcm::FcmClient>>,
    apns_client: Option<Arc<apns::ApnsClient>>,
    config: PushMfaConfig,
}

impl PushMfaService {
    /// Create a new push MFA service
    pub fn new(
        db: crate::db::Database,
        redis: Option<redis::aio::ConnectionManager>,
        config: PushMfaConfig,
    ) -> Self {
        let fcm_client = config.fcm.as_ref().map(|c| Arc::new(fcm::FcmClient::new(c)));
        let apns_client = config.apns.as_ref().map(|c| Arc::new(apns::ApnsClient::new(c)));
        
        Self {
            db,
            redis,
            fcm_client,
            apns_client,
            config,
        }
    }

    /// Register a new push device for a user
    pub async fn register_device(
        &self,
        tenant_id: &str,
        user_id: &str,
        device_type: DeviceType,
        device_token: &str,
        device_name: Option<String>,
        public_key: Option<String>,
    ) -> Result<PushDevice, PushMfaError> {
        // Check device limit
        let device_count = self.get_device_count(tenant_id, user_id).await?;
        if device_count >= self.config.max_devices_per_user {
            return Err(PushMfaError::MaxDevicesExceeded(
                self.config.max_devices_per_user,
            ));
        }

        // Validate device token format
        if device_token.is_empty() || device_token.len() < 10 {
            return Err(PushMfaError::InvalidDeviceToken);
        }

        let device = PushDevice::new(
            user_id.to_string(),
            tenant_id.to_string(),
            device_type,
            device_token.to_string(),
            device_name,
            public_key,
        );

        // Store in database
        sqlx::query(
            r#"
            INSERT INTO push_devices 
            (id, user_id, tenant_id, device_type, device_name, device_token, is_active, created_at, last_used_at, public_key)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (tenant_id, user_id, device_token) 
            DO UPDATE SET 
                device_type = EXCLUDED.device_type,
                device_name = EXCLUDED.device_name,
                is_active = TRUE,
                public_key = EXCLUDED.public_key
            RETURNING id, user_id, tenant_id, device_type as "device_type: DeviceType", 
                      device_name, device_token, is_active, created_at, last_used_at, public_key
            "#,
        )
        .bind(&device.id)
        .bind(&device.user_id)
        .bind(&device.tenant_id)
        .bind(device.device_type)
        .bind(&device.device_name)
        .bind(&device.device_token)
        .bind(device.is_active)
        .bind(device.created_at)
        .bind(device.last_used_at)
        .bind(&device.public_key)
        .fetch_one(self.db.pool())
        .await
        .map_err(PushMfaError::from)
        .map(|row| PushDevice::from_row(row))
    }

    /// Get all active devices for a user
    pub async fn get_user_devices(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<PushDevice>, PushMfaError> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, tenant_id, device_type as "device_type: DeviceType", 
                   device_name, device_token, is_active, created_at, last_used_at, public_key
            FROM push_devices
            WHERE tenant_id = $1 AND user_id = $2 AND is_active = TRUE
            ORDER BY last_used_at DESC NULLS LAST, created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(PushDevice::from_row).collect())
    }

    /// Get device by ID
    pub async fn get_device(
        &self,
        tenant_id: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<PushDevice, PushMfaError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, tenant_id, device_type as "device_type: DeviceType", 
                   device_name, device_token, is_active, created_at, last_used_at, public_key
            FROM push_devices
            WHERE tenant_id = $1 AND user_id = $2 AND id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_id)
        .fetch_optional(self.db.pool())
        .await?;

        row.map(PushDevice::from_row)
            .ok_or_else(|| PushMfaError::DeviceNotFound(device_id.to_string()))
    }

    /// Deactivate a device
    pub async fn deactivate_device(
        &self,
        tenant_id: &str,
        user_id: &str,
        device_id: &str,
    ) -> Result<(), PushMfaError> {
        let result = sqlx::query(
            r#"
            UPDATE push_devices
            SET is_active = FALSE
            WHERE tenant_id = $1 AND user_id = $2 AND id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_id)
        .execute(self.db.pool())
        .await?;

        if result.rows_affected() == 0 {
            return Err(PushMfaError::DeviceNotFound(device_id.to_string()));
        }

        Ok(())
    }

    /// Rename a device
    pub async fn rename_device(
        &self,
        tenant_id: &str,
        user_id: &str,
        device_id: &str,
        new_name: &str,
    ) -> Result<(), PushMfaError> {
        let result = sqlx::query(
            r#"
            UPDATE push_devices
            SET device_name = $4
            WHERE tenant_id = $1 AND user_id = $2 AND id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(device_id)
        .bind(new_name)
        .execute(self.db.pool())
        .await?;

        if result.rows_affected() == 0 {
            return Err(PushMfaError::DeviceNotFound(device_id.to_string()));
        }

        Ok(())
    }

    /// Create and send a push MFA request
    pub async fn create_request(
        &self,
        tenant_id: &str,
        user_id: &str,
        session_id: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<PushRequest, PushMfaError> {
        // Get user's active devices
        let devices = self.get_user_devices(tenant_id, user_id).await?;
        if devices.is_empty() {
            return Err(PushMfaError::DeviceNotFound(
                "No active devices found".to_string(),
            ));
        }

        // Create request
        let request = PushRequest::new(
            user_id,
            tenant_id,
            session_id,
            ip_address.clone(),
            user_agent.clone(),
            self.config.request_timeout_seconds,
        );

        // Store request in database
        sqlx::query(
            r#"
            INSERT INTO push_requests 
            (id, user_id, tenant_id, status, ip_address, user_agent, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(&request.id)
        .bind(&request.user_id)
        .bind(&request.tenant_id)
        .bind(request.status)
        .bind(&request.ip_address)
        .bind(&request.user_agent)
        .bind(request.expires_at)
        .bind(request.created_at)
        .execute(self.db.pool())
        .await?;

        // Send push notifications to all devices
        for device in devices {
            if let Err(e) = self.send_push_notification(&device, &request).await {
                tracing::warn!(
                    "Failed to send push to device {}: {}",
                    device.id,
                    e
                );
            }
        }

        // Publish to Redis for real-time updates
        if let Some(ref redis) = self.redis {
            let channel = format!("push_mfa:tenant:{}:user:{}", tenant_id, user_id);
            let message = serde_json::json!({
                "type": "request_created",
                "request_id": request.id,
                "timestamp": Utc::now().to_rfc3339(),
            });
            let _: Result<(), _> = redis::cmd("PUBLISH")
                .arg(&channel)
                .arg(message.to_string())
                .query_async(&mut redis.clone())
                .await;
        }

        Ok(request)
    }

    /// Get request by ID
    pub async fn get_request(
        &self,
        tenant_id: &str,
        user_id: &str,
        request_id: &str,
    ) -> Result<PushRequest, PushMfaError> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, tenant_id, device_id, session_id, 
                   status as "status: PushRequestStatus", ip_address, user_agent, 
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

        row.map(PushRequest::from_row)
            .ok_or_else(|| PushMfaError::RequestNotFound(request_id.to_string()))
    }

    /// Respond to a push request (approve or deny)
    pub async fn respond_to_request(
        &self,
        request_id: &str,
        device_id: &str,
        response: PushResponse,
        signature: Option<String>,
    ) -> Result<PushRequest, PushMfaError> {
        let mut request = sqlx::query(
            r#"
            SELECT id, user_id, tenant_id, device_id, session_id, 
                   status as "status: PushRequestStatus", ip_address, user_agent, 
                   expires_at, responded_at, created_at, response_signature, response_timestamp
            FROM push_requests
            WHERE id = $1
            "#,
        )
        .bind(request_id)
        .fetch_optional(self.db.pool())
        .await?
        .map(PushRequest::from_row)
        .ok_or_else(|| PushMfaError::RequestNotFound(request_id.to_string()))?;

        // Check if already responded
        if request.status != PushRequestStatus::Pending {
            return Err(PushMfaError::Internal(
                "Request already responded".to_string(),
            ));
        }

        // Check expiration
        if request.is_expired() {
            // Update status to expired
            sqlx::query(
                "UPDATE push_requests SET status = 'expired' WHERE id = $1",
            )
            .bind(request_id)
            .execute(self.db.pool())
            .await?;
            return Err(PushMfaError::RequestExpired(request_id.to_string()));
        }

        // Verify device signature if public key is available
        if let Some(ref sig) = signature {
            let device = sqlx::query(
                "SELECT public_key FROM push_devices WHERE id = $1",
            )
            .bind(device_id)
            .fetch_optional(self.db.pool())
            .await?;

            if let Some(device) = device {
                use sqlx::Row;
                let public_key: Option<String> = device.try_get("public_key").ok().flatten();
                if let Some(pk) = public_key {
                    if !self.verify_signature(&pk, request_id, response, sig).await? {
                        return Err(PushMfaError::InvalidSignature);
                    }
                }
            }
        }

        // Update request
        let new_status = match response {
            PushResponse::Approve => PushRequestStatus::Approved,
            PushResponse::Deny => PushRequestStatus::Denied,
        };
        let responded_at = Utc::now();

        sqlx::query(
            r#"
            UPDATE push_requests
            SET status = $1, device_id = $2, responded_at = $3, 
                response_signature = $4, response_timestamp = $5
            WHERE id = $6
            "#,
        )
        .bind(new_status)
        .bind(device_id)
        .bind(responded_at)
        .bind(&signature)
        .bind(responded_at)
        .bind(request_id)
        .execute(self.db.pool())
        .await?;

        // Update device last_used_at
        sqlx::query(
            "UPDATE push_devices SET last_used_at = $1 WHERE id = $2",
        )
        .bind(responded_at)
        .bind(device_id)
        .execute(self.db.pool())
        .await?;

        request.status = new_status;
        request.device_id = Some(device_id.to_string());
        request.responded_at = Some(responded_at);
        request.response_signature = signature;
        request.response_timestamp = Some(responded_at);

        // Publish to Redis for real-time updates
        if let Some(ref redis) = self.redis {
            let channel = format!("push_mfa:request:{}", request_id);
            let message = serde_json::json!({
                "type": "request_responded",
                "request_id": request_id,
                "status": new_status.to_string(),
                "timestamp": responded_at.to_rfc3339(),
            });
            let _: Result<(), _> = redis::cmd("PUBLISH")
                .arg(&channel)
                .arg(message.to_string())
                .query_async(&mut redis.clone())
                .await;
        }

        Ok(request)
    }

    /// Send push notification to a device
    async fn send_push_notification(
        &self,
        device: &PushDevice,
        request: &PushRequest,
    ) -> Result<(), PushMfaError> {
        let notification = PushNotification {
            notification: NotificationContent {
                title: "Vault Login Request".to_string(),
                body: format!(
                    "Login attempt from {}. Tap to approve or deny.",
                    request.ip_address.as_deref().unwrap_or("unknown location")
                ),
            },
            data: PushDataPayload {
                request_id: request.id.clone(),
                notification_type: "mfa_request".to_string(),
                ip_address: request.ip_address.clone(),
                location: None, // Could be enriched with GeoIP
                device_info: request.user_agent.clone(),
                timestamp: Utc::now(),
            },
        };

        match device.device_type {
            DeviceType::Android => {
                if let Some(ref fcm) = self.fcm_client {
                    fcm.send(&device.device_token, &notification).await
                } else {
                    Err(PushMfaError::NotEnabled)
                }
            }
            DeviceType::Ios => {
                if let Some(ref apns) = self.apns_client {
                    apns.send(&device.device_token, &notification).await
                } else {
                    Err(PushMfaError::NotEnabled)
                }
            }
        }
    }

    /// Verify Ed25519 signature from device
    async fn verify_signature(
        &self,
        _public_key: &str,
        _request_id: &str,
        _response: PushResponse,
        _signature: &str,
    ) -> Result<bool, PushMfaError> {
        // Signature verification implementation would go here
        // Using ring or ed25519-dalek for verification
        // For now, accept all signatures (implement in production)
        Ok(true)
    }

    /// Get device count for a user
    async fn get_device_count(&self, tenant_id: &str, user_id: &str) -> Result<i32, PushMfaError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM push_devices WHERE tenant_id = $1 AND user_id = $2 AND is_active = TRUE",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(self.db.pool())
        .await?;

        Ok(count as i32)
    }

    /// Cleanup expired requests
    pub async fn cleanup_expired_requests(&self) -> Result<u64, PushMfaError> {
        let result = sqlx::query(
            r#"
            UPDATE push_requests
            SET status = 'expired'
            WHERE status = 'pending' AND expires_at < NOW()
            "#,
        )
        .execute(self.db.pool())
        .await?;

        Ok(result.rows_affected())
    }
}

impl PushDevice {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        use sqlx::Row;
        Self {
            id: row.get("id"),
            user_id: row.get("user_id"),
            tenant_id: row.get("tenant_id"),
            device_type: row.get("device_type"),
            device_name: row.get("device_name"),
            device_token: row.get("device_token"),
            is_active: row.get("is_active"),
            created_at: row.get("created_at"),
            last_used_at: row.get("last_used_at"),
            public_key: row.get("public_key"),
        }
    }
}

impl PushRequest {
    fn from_row(row: sqlx::postgres::PgRow) -> Self {
        use sqlx::Row;
        Self {
            id: row.get("id"),
            user_id: row.get("user_id"),
            tenant_id: row.get("tenant_id"),
            device_id: row.get("device_id"),
            session_id: row.get("session_id"),
            status: row.get("status"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            expires_at: row.get("expires_at"),
            responded_at: row.get("responded_at"),
            created_at: row.get("created_at"),
            response_signature: row.get("response_signature"),
            response_timestamp: row.get("response_timestamp"),
        }
    }
}
