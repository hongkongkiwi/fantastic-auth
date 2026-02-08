//! Push Device Management
//!
//! Represents mobile devices registered for push notification MFA.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Type of mobile device
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "push_device_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    /// iOS device (APNS)
    Ios,
    /// Android device (FCM)
    Android,
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceType::Ios => write!(f, "ios"),
            DeviceType::Android => write!(f, "android"),
        }
    }
}

impl std::str::FromStr for DeviceType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ios" | "apple" | "iphone" | "ipad" => Ok(DeviceType::Ios),
            "android" => Ok(DeviceType::Android),
            _ => Err(format!("Unknown device type: {}", s)),
        }
    }
}

/// A registered push notification device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushDevice {
    /// Device unique identifier (UUID)
    pub id: String,
    /// User ID who owns this device
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Device type (iOS or Android)
    pub device_type: DeviceType,
    /// Human-readable device name (e.g., "iPhone 15", "Pixel 7")
    pub device_name: Option<String>,
    /// Push notification token (FCM or APNS token)
    /// Note: This is stored encrypted at rest
    pub device_token: String,
    /// Whether the device is active and can receive push notifications
    pub is_active: bool,
    /// When the device was registered
    pub created_at: DateTime<Utc>,
    /// When the device was last used for MFA
    pub last_used_at: Option<DateTime<Utc>>,
    /// Ed25519 public key for verifying device responses (optional)
    pub public_key: Option<String>,
}

impl PushDevice {
    /// Create a new push device
    pub fn new(
        user_id: String,
        tenant_id: String,
        device_type: DeviceType,
        device_token: String,
        device_name: Option<String>,
        public_key: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            tenant_id,
            device_type,
            device_name,
            device_token,
            is_active: true,
            created_at: now,
            last_used_at: None,
            public_key,
        }
    }

    /// Get a display name for the device
    pub fn display_name(&self) -> String {
        self.device_name.clone().unwrap_or_else(|| {
            format!("{} Device", self.device_type.to_string().to_uppercase())
        })
    }

    /// Check if this is an iOS device
    pub fn is_ios(&self) -> bool {
        self.device_type == DeviceType::Ios
    }

    /// Check if this is an Android device
    pub fn is_android(&self) -> bool {
        self.device_type == DeviceType::Android
    }

    /// Get a masked version of the device token for logging
    pub fn masked_token(&self) -> String {
        if self.device_token.len() <= 8 {
            "****".to_string()
        } else {
            format!(
                "{}...{}",
                &self.device_token[..4],
                &self.device_token[self.device_token.len() - 4..]
            )
        }
    }

    /// Update the last used timestamp
    pub fn mark_used(&mut self) {
        self.last_used_at = Some(Utc::now());
    }

    /// Deactivate the device
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }
}

/// Request to register a new device
#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    /// Device token from FCM or APNS
    pub device_token: String,
    /// Device type ("ios" or "android")
    pub device_type: String,
    /// Optional human-readable device name
    pub device_name: Option<String>,
    /// Optional Ed25519 public key for response verification
    pub public_key: Option<String>,
}

/// Response after device registration
#[derive(Debug, Serialize)]
pub struct RegisterDeviceResponse {
    /// Device ID
    pub id: String,
    /// Device name
    pub device_name: String,
    /// Device type
    pub device_type: String,
    /// Registration timestamp
    pub created_at: String,
}

/// Device information for listing
#[derive(Debug, Serialize)]
pub struct DeviceInfo {
    pub id: String,
    pub device_type: String,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    #[serde(rename = "isActive")]
    pub is_active: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "lastUsedAt")]
    pub last_used_at: Option<String>,
}

impl From<PushDevice> for DeviceInfo {
    fn from(device: PushDevice) -> Self {
        let device_type_str = device.device_type.to_string();
        let device_name = device.device_name.clone().unwrap_or_else(|| {
            format!("{} Device", device.device_type.to_string().to_uppercase())
        });
        Self {
            id: device.id,
            device_type: device_type_str,
            device_name,
            is_active: device.is_active,
            created_at: device.created_at.to_rfc3339(),
            last_used_at: device.last_used_at.map(|d| d.to_rfc3339()),
        }
    }
}

/// Request to rename a device
#[derive(Debug, Deserialize)]
pub struct RenameDeviceRequest {
    pub name: String,
}

/// Device registration validation
pub fn validate_device_token(token: &str, device_type: DeviceType) -> Result<(), String> {
    if token.is_empty() {
        return Err("Device token cannot be empty".to_string());
    }

    // FCM tokens are typically ~152 characters
    // APNS tokens are typically 64 hexadecimal characters
    match device_type {
        DeviceType::Android => {
            if token.len() < 20 {
                return Err("FCM token appears too short".to_string());
            }
            if token.len() > 500 {
                return Err("FCM token appears too long".to_string());
            }
        }
        DeviceType::Ios => {
            // APNS device tokens are 64 hex characters
            if token.len() != 64 {
                return Err("APNS token should be 64 characters".to_string());
            }
            if !token.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("APNS token should be hexadecimal".to_string());
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_type_from_str() {
        assert_eq!(
            DeviceType::from_str("ios").unwrap(),
            DeviceType::Ios
        );
        assert_eq!(
            DeviceType::from_str("android").unwrap(),
            DeviceType::Android
        );
        assert_eq!(
            DeviceType::from_str("IOS").unwrap(),
            DeviceType::Ios
        );
        assert!(DeviceType::from_str("windows").is_err());
    }

    #[test]
    fn test_device_display_name() {
        let device = PushDevice::new(
            "user-123".to_string(),
            "tenant-456".to_string(),
            DeviceType::Ios,
            "a".repeat(64),
            Some("My iPhone".to_string()),
            None,
        );
        assert_eq!(device.display_name(), "My iPhone");

        let device_no_name = PushDevice::new(
            "user-123".to_string(),
            "tenant-456".to_string(),
            DeviceType::Android,
            "fcm_token_123".to_string(),
            None,
            None,
        );
        assert_eq!(device_no_name.display_name(), "ANDROID Device");
    }

    #[test]
    fn test_masked_token() {
        let device = PushDevice::new(
            "user-123".to_string(),
            "tenant-456".to_string(),
            DeviceType::Ios,
            "a".repeat(64),
            None,
            None,
        );
        let masked = device.masked_token();
        assert!(masked.starts_with("aaaa"));
        assert!(masked.ends_with("aaaa"));
        assert!(masked.contains("..."));
    }

    #[test]
    fn test_validate_apns_token() {
        // Valid 64-char hex token
        let valid_token = "a".repeat(64);
        assert!(validate_device_token(&valid_token, DeviceType::Ios).is_ok());

        // Too short
        let short_token = "a".repeat(32);
        assert!(validate_device_token(&short_token, DeviceType::Ios).is_err());

        // Not hex
        let invalid_token = "g".repeat(64);
        assert!(validate_device_token(&invalid_token, DeviceType::Ios).is_err());
    }

    #[test]
    fn test_validate_fcm_token() {
        // Valid FCM token
        let valid_token = "a".repeat(100);
        assert!(validate_device_token(&valid_token, DeviceType::Android).is_ok());

        // Too short
        let short_token = "abc";
        assert!(validate_device_token(&short_token, DeviceType::Android).is_err());

        // Too long
        let long_token = "a".repeat(600);
        assert!(validate_device_token(&long_token, DeviceType::Android).is_err());
    }
}
