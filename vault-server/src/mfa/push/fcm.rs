//! Firebase Cloud Messaging (FCM) Integration
//!
//! Handles sending push notifications to Android devices via FCM HTTP v1 API.
//! Supports retry logic, batch sending, and error handling.

use super::{FcmConfig, PushMfaError, PushNotification};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

/// FCM API base URL
const FCM_API_BASE: &str = "https://fcm.googleapis.com/v1/projects";

/// Maximum retry attempts for failed sends
const MAX_RETRIES: u32 = 3;

/// Initial retry delay in milliseconds
const INITIAL_RETRY_DELAY_MS: u64 = 1000;

/// FCM HTTP client
#[derive(Clone)]
pub struct FcmClient {
    project_id: String,
    access_token: String,
    http_client: reqwest::Client,
}

impl FcmClient {
    /// Create a new FCM client
    pub fn new(config: &FcmConfig) -> Self {
        // In production, this would load service account credentials and obtain
        // an OAuth2 access token from Google's token endpoint
        // For now, we use a placeholder that should be replaced with actual token
        let access_token = std::env::var("FCM_ACCESS_TOKEN")
            .unwrap_or_else(|_| "placeholder_token".to_string());

        Self {
            project_id: config.project_id.clone(),
            access_token,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .pool_max_idle_per_host(10)
                .build()
                .expect("Failed to build HTTP client"),
        }
    }

    /// Send a push notification to a device
    pub async fn send(
        &self,
        device_token: &str,
        notification: &PushNotification,
    ) -> Result<(), PushMfaError> {
        self.send_with_retry(device_token, notification, 0).await
    }

    /// Send with exponential backoff retry
    async fn send_with_retry(
        &self,
        device_token: &str,
        notification: &PushNotification,
        attempt: u32,
    ) -> Result<(), PushMfaError> {
        match self.send_internal(device_token, notification).await {
            Ok(_) => Ok(()),
            Err(e) => {
                if attempt < MAX_RETRIES && Self::should_retry(&e) {
                    let delay = INITIAL_RETRY_DELAY_MS * 2_u64.pow(attempt);
                    tracing::warn!(
                        "FCM send failed, retrying in {}ms (attempt {})",
                        delay,
                        attempt + 1
                    );
                    sleep(Duration::from_millis(delay)).await;
                    self.send_with_retry(device_token, notification, attempt + 1)
                        .await
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Internal send implementation
    async fn send_internal(
        &self,
        device_token: &str,
        notification: &PushNotification,
    ) -> Result<(), PushMfaError> {
        let url = format!(
            "{}/{}/messages:send",
            FCM_API_BASE, self.project_id
        );

        let request_body = FcmRequest {
            message: FcmMessage {
                token: device_token.to_string(),
                notification: FcmNotification {
                    title: notification.notification.title.clone(),
                    body: notification.notification.body.clone(),
                },
                data: notification.data.clone(),
                android: Some(FcmAndroidConfig {
                    priority: "high".to_string(),
                    ttl: "300s".to_string(),
                    notification: FcmAndroidNotification {
                        channel_id: "mfa_requests".to_string(),
                        priority: "high".to_string(),
                        sound: "default".to_string(),
                    },
                }),
                apns: None, // Not used for Android
            },
        };

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .header("Content-Type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| PushMfaError::SendFailed(format!("HTTP error: {}", e)))?;

        let status = response.status();
        let response_body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| PushMfaError::SendFailed(format!("Invalid response: {}", e)))?;

        if status.is_success() {
            tracing::debug!("FCM notification sent successfully");
            Ok(())
        } else {
            let error = FcmError::from_response(&response_body);
            tracing::error!("FCM send failed: {:?}", error);
            
            match error.error_code.as_str() {
                "UNREGISTERED" | "INVALID_ARGUMENT" => {
                    Err(PushMfaError::InvalidDeviceToken)
                }
                "SENDER_ID_MISMATCH" => {
                    Err(PushMfaError::SendFailed("Invalid FCM configuration".to_string()))
                }
                "QUOTA_EXCEEDED" => {
                    Err(PushMfaError::SendFailed("FCM quota exceeded".to_string()))
                }
                _ => Err(PushMfaError::SendFailed(format!(
                    "FCM error: {}",
                    error.message
                ))),
            }
        }
    }

    /// Send to multiple devices (multicast)
    pub async fn send_multicast(
        &self,
        device_tokens: &[String],
        notification: &PushNotification,
    ) -> Vec<(String, Result<(), PushMfaError>)> {
        let mut results = Vec::with_capacity(device_tokens.len());

        // FCM v1 doesn't support true multicast in a single request
        // We send individual requests concurrently
        let futures: Vec<_> = device_tokens
            .iter()
            .map(|token| {
                let token = token.clone();
                async move {
                    let result = self.send(&token, notification).await;
                    (token, result)
                }
            })
            .collect();

        for result in futures::future::join_all(futures).await {
            results.push(result);
        }

        results
    }

    /// Determine if an error is retryable
    fn should_retry(error: &PushMfaError) -> bool {
        match error {
            PushMfaError::SendFailed(msg) => {
                // Retry on transient errors
                msg.contains("timeout")
                    || msg.contains("connection")
                    || msg.contains("500")
                    || msg.contains("503")
                    || msg.contains("UNAVAILABLE")
            }
            _ => false,
        }
    }

    /// Refresh access token (should be called periodically)
    pub async fn refresh_token(&mut self) -> Result<(), PushMfaError> {
        // In production, implement OAuth2 token refresh using service account
        // This would use the google-auth-library or similar
        self.access_token = std::env::var("FCM_ACCESS_TOKEN")
            .map_err(|_| PushMfaError::SendFailed("FCM token not configured".to_string()))?;
        Ok(())
    }
}

/// FCM request body structure
#[derive(Debug, Serialize)]
struct FcmRequest {
    message: FcmMessage,
}

/// FCM message structure
#[derive(Debug, Serialize)]
struct FcmMessage {
    token: String,
    notification: FcmNotification,
    data: super::PushDataPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    android: Option<FcmAndroidConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apns: Option<serde_json::Value>,
}

/// FCM notification content
#[derive(Debug, Serialize)]
struct FcmNotification {
    title: String,
    body: String,
}

/// Android-specific configuration
#[derive(Debug, Serialize)]
struct FcmAndroidConfig {
    priority: String,
    ttl: String,
    notification: FcmAndroidNotification,
}

/// Android notification settings
#[derive(Debug, Serialize)]
struct FcmAndroidNotification {
    #[serde(rename = "channelId")]
    channel_id: String,
    priority: String,
    sound: String,
}

/// FCM error response
#[derive(Debug, Deserialize)]
struct FcmError {
    error_code: String,
    message: String,
    status: String,
}

impl FcmError {
    fn from_response(value: &serde_json::Value) -> Self {
        let error = value
            .get("error")
            .and_then(|e| e.get("details"))
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.first())
            .and_then(|d| d.get("errorCode"))
            .and_then(|e| e.as_str())
            .unwrap_or("UNKNOWN");

        let message = value
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error")
            .to_string();

        let status = value
            .get("error")
            .and_then(|e| e.get("status"))
            .and_then(|s| s.as_str())
            .unwrap_or("UNKNOWN")
            .to_string();

        Self {
            error_code: error.to_string(),
            message,
            status,
        }
    }
}

/// Service account credentials for FCM
#[derive(Debug, Deserialize, Clone)]
pub struct ServiceAccount {
    #[serde(rename = "type")]
    pub account_type: String,
    #[serde(rename = "project_id")]
    pub project_id: String,
    #[serde(rename = "private_key_id")]
    pub private_key_id: String,
    #[serde(rename = "private_key")]
    pub private_key: String,
    #[serde(rename = "client_email")]
    pub client_email: String,
    #[serde(rename = "client_id")]
    pub client_id: String,
    #[serde(rename = "auth_uri")]
    pub auth_uri: String,
    #[serde(rename = "token_uri")]
    pub token_uri: String,
}

impl ServiceAccount {
    /// Load service account from JSON file
    pub fn from_file(path: &str) -> Result<Self, std::io::Error> {
        let contents = std::fs::read_to_string(path)?;
        serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Load service account from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// OAuth2 token response from Google
#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(rename = "access_token")]
    access_token: String,
    #[serde(rename = "expires_in")]
    expires_in: i64,
    #[serde(rename = "token_type")]
    token_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_account_from_json() {
        let json = r#"{
            "type": "service_account",
            "project_id": "test-project",
            "private_key_id": "key123",
            "private_key": "-----BEGIN PRIVATE KEY-----\n...",
            "client_email": "test@test-project.iam.gserviceaccount.com",
            "client_id": "123456789",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }"#;

        let account = ServiceAccount::from_json(json).unwrap();
        assert_eq!(account.project_id, "test-project");
        assert_eq!(account.account_type, "service_account");
    }

    #[test]
    fn test_should_retry() {
        let timeout_error = PushMfaError::SendFailed("connection timeout".to_string());
        assert!(FcmClient::should_retry(&timeout_error));

        let unavailable_error = PushMfaError::SendFailed("UNAVAILABLE".to_string());
        assert!(FcmClient::should_retry(&unavailable_error));

        let invalid_token = PushMfaError::InvalidDeviceToken;
        assert!(!FcmClient::should_retry(&invalid_token));
    }
}
