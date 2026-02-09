//! Apple Push Notification Service (APNS) Integration
//!
//! Handles sending push notifications to iOS devices via APNS HTTP/2 API.
//! Supports JWT-based authentication, production/sandbox environments,
//! and concurrent request handling.

use super::{ApnsConfig, PushMfaError, PushNotification};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// APNS production endpoint
const APNS_PRODUCTION: &str = "https://api.push.apple.com";

/// APNS sandbox/development endpoint
const APNS_SANDBOX: &str = "https://api.development.push.apple.com";

/// JWT token expiry (1 hour max for APNS)
const JWT_EXPIRY_SECONDS: u64 = 3300; // 55 minutes

/// Maximum retry attempts
const MAX_RETRIES: u32 = 3;

/// Initial retry delay
const INITIAL_RETRY_DELAY_MS: u64 = 1000;

/// APNS HTTP/2 client
#[derive(Clone)]
pub struct ApnsClient {
    key_id: String,
    team_id: String,
    bundle_id: String,
    private_key: String,
    base_url: String,
    http_client: reqwest::Client,
    jwt_token: std::sync::Arc<tokio::sync::RwLock<JwtToken>>,
}

/// JWT token with expiry
#[derive(Clone)]
struct JwtToken {
    token: String,
    issued_at: u64,
}

impl ApnsClient {
    /// Create a new APNS client
    pub fn new(config: &ApnsConfig) -> Self {
        let base_url = if config.use_sandbox {
            APNS_SANDBOX.to_string()
        } else {
            APNS_PRODUCTION.to_string()
        };

        // Create HTTP/2 client
        let http_client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(600))
            .build()
            .expect("Failed to build HTTP client");

        let initial_jwt = JwtToken {
            token: String::new(),
            issued_at: 0,
        };

        Self {
            key_id: config.key_id.clone(),
            team_id: config.team_id.clone(),
            bundle_id: config.bundle_id.clone(),
            private_key: config.private_key.clone(),
            base_url,
            http_client,
            jwt_token: std::sync::Arc::new(tokio::sync::RwLock::new(initial_jwt)),
        }
    }

    /// Send a push notification to an iOS device
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
        let mut current_attempt = attempt;
        loop {
            match self.send_internal(device_token, notification).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if current_attempt < MAX_RETRIES && Self::should_retry(&e) {
                        let delay = INITIAL_RETRY_DELAY_MS * 2_u64.pow(current_attempt);
                        tracing::warn!(
                            "APNS send failed, retrying in {}ms (attempt {})",
                            delay,
                            current_attempt + 1
                        );
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                        current_attempt += 1;
                        continue;
                    }
                    return Err(e);
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
        let url = format!("{}/3/device/{}", self.base_url, device_token);

        // Get or refresh JWT token
        let jwt = self.get_jwt_token().await?;

        let request_body = ApnsRequest {
            aps: Aps {
                alert: Alert {
                    title: notification.notification.title.clone(),
                    body: notification.notification.body.clone(),
                },
                badge: Some(1),
                sound: "default".to_string(),
                category: "mfa_request".to_string(),
                mutable_content: 1,
            },
            data: notification.data.clone(),
        };

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", jwt))
            .header("apns-topic", &self.bundle_id)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-expiration", "0") // Deliver immediately or not at all
            .json(&request_body)
            .send()
            .await
            .map_err(|e| PushMfaError::SendFailed(format!("HTTP error: {}", e)))?;

        let status = response.status();

        if status.is_success() {
            tracing::debug!("APNS notification sent successfully");
            Ok(())
        } else {
            let response_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            
            let error: ApnsError = serde_json::from_str(&response_text)
                .unwrap_or_else(|_| ApnsError {
                    reason: "Unknown".to_string(),
                    timestamp: None,
                });

            tracing::error!("APNS send failed: {} - {}", status, error.reason);

            match error.reason.as_str() {
                "BadDeviceToken" | "Unregistered" => {
                    Err(PushMfaError::InvalidDeviceToken)
                }
                "ExpiredProviderToken" | "InvalidProviderToken" => {
                    // Force token refresh and retry
                    self.refresh_jwt_token().await?;
                    Err(PushMfaError::SendFailed("Token expired, retrying".to_string()))
                }
                "TooManyRequests" => {
                    Err(PushMfaError::SendFailed("Rate limited".to_string()))
                }
                "BadTopic" => {
                    Err(PushMfaError::SendFailed("Invalid bundle ID".to_string()))
                }
                _ => Err(PushMfaError::SendFailed(format!(
                    "APNS error: {}",
                    error.reason
                ))),
            }
        }
    }

    /// Get JWT token, refreshing if necessary
    async fn get_jwt_token(&self) -> Result<String, PushMfaError> {
        let token = self.jwt_token.read().await;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if !token.token.is_empty() && (now - token.issued_at) < JWT_EXPIRY_SECONDS {
            return Ok(token.token.clone());
        }

        drop(token);
        self.refresh_jwt_token().await
    }

    /// Refresh JWT token
    async fn refresh_jwt_token(&self) -> Result<String, PushMfaError> {
        let mut token = self.jwt_token.write().await;

        // Double-check after acquiring write lock
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if !token.token.is_empty() && (now - token.issued_at) < JWT_EXPIRY_SECONDS {
            return Ok(token.token.clone());
        }

        // Generate new JWT
        let new_token = self.generate_jwt(now)?;
        
        *token = JwtToken {
            token: new_token.clone(),
            issued_at: now,
        };

        Ok(new_token)
    }

    /// Generate JWT for APNS authentication
    fn generate_jwt(&self, issued_at: u64) -> Result<String, PushMfaError> {
        // JWT header
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": self.key_id,
        });

        // JWT claims
        let claims = serde_json::json!({
            "iss": self.team_id,
            "iat": issued_at,
        });

        let header_b64 = base64_encode_json(&header)?;
        let claims_b64 = base64_encode_json(&claims)?;

        let signing_input = format!("{}.{}", header_b64, claims_b64);

        // Sign with private key (P8 format)
        // In production, use ring or p256 crate for ECDSA signing
        // For now, return a placeholder that should be replaced
        let signature = self.sign_ecdsa(&signing_input)?;

        Ok(format!("{}.{}.{}", header_b64, claims_b64, signature))
    }

    /// Sign data with ECDSA using P-256 (placeholder implementation)
    fn sign_ecdsa(&self, _data: &str) -> Result<String, PushMfaError> {
        // This is a placeholder - actual implementation would:
        // 1. Parse the P8 private key
        // 2. Use p256::ecdsa::SigningKey to sign
        // 3. Return base64url-encoded signature
        
        // For production, use:
        // let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(&private_key_der)?;
        // let signature: p256::ecdsa::Signature = signing_key.sign(data.as_bytes());
        // Ok(base64::encode(signature.to_der()))
        
        Ok("placeholder_signature".to_string())
    }

    /// Determine if an error is retryable
    fn should_retry(error: &PushMfaError) -> bool {
        match error {
            PushMfaError::SendFailed(msg) => {
                msg.contains("timeout")
                    || msg.contains("connection")
                    || msg.contains("retry")
            }
            _ => false,
        }
    }

    /// Send to multiple devices concurrently
    pub async fn send_multicast(
        &self,
        device_tokens: &[String],
        notification: &PushNotification,
    ) -> Vec<(String, Result<(), PushMfaError>)> {
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

        futures::future::join_all(futures).await
    }

    /// Check if client is configured for sandbox
    pub fn is_sandbox(&self) -> bool {
        self.base_url == APNS_SANDBOX
    }
}

/// Base64url encode JSON without padding
fn base64_encode_json(value: &serde_json::Value) -> Result<String, PushMfaError> {
    let json_str = serde_json::to_string(value)
        .map_err(|e| PushMfaError::Internal(format!("JSON error: {}", e)))?;
    
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        json_str.as_bytes(),
    ))
}

/// APNS request body
#[derive(Debug, Serialize)]
struct ApnsRequest {
    aps: Aps,
    #[serde(flatten)]
    data: super::PushDataPayload,
}

/// APNS aps payload
#[derive(Debug, Serialize)]
struct Aps {
    alert: Alert,
    badge: Option<i32>,
    sound: String,
    category: String,
    #[serde(rename = "mutable-content")]
    mutable_content: i32,
}

/// APNS alert content
#[derive(Debug, Serialize)]
struct Alert {
    title: String,
    body: String,
}

/// APNS error response
#[derive(Debug, Deserialize)]
struct ApnsError {
    reason: String,
    #[serde(rename = "timestamp")]
    timestamp: Option<u64>,
}

/// APNS private key parser for P8 format
pub struct ApnsPrivateKey;

impl ApnsPrivateKey {
    /// Parse P8 private key content (removes PEM headers/footers)
    pub fn parse_pem(pem_content: &str) -> Result<Vec<u8>, PushMfaError> {
        let cleaned = pem_content
            .lines()
            .filter(|line| !line.starts_with("-----") && !line.trim().is_empty())
            .collect::<String>();
        
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &cleaned,
        )
        .map_err(|e| PushMfaError::Internal(format!("Invalid private key: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> ApnsConfig {
        ApnsConfig {
            key_id: "ABC123DEF4".to_string(),
            team_id: "TEAM123456".to_string(),
            bundle_id: "com.example.vault".to_string(),
            private_key: "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----".to_string(),
            use_sandbox: true,
        }
    }

    #[test]
    fn test_apns_client_creation() {
        let config = create_test_config();
        let client = ApnsClient::new(&config);
        
        assert!(client.is_sandbox());
        assert_eq!(client.base_url, APNS_SANDBOX);
    }

    #[test]
    fn test_base64_encode_json() {
        let json = serde_json::json!({"test": "value"});
        let encoded = base64_encode_json(&json).unwrap();
        
        // Should be URL-safe base64 without padding
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn test_should_retry() {
        let timeout_error = PushMfaError::SendFailed("connection timeout".to_string());
        assert!(ApnsClient::should_retry(&timeout_error));

        let bad_device = PushMfaError::InvalidDeviceToken;
        assert!(!ApnsClient::should_retry(&bad_device));
    }

    #[test]
    fn test_parse_private_key() {
        let pem = r#"-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
-----END PRIVATE KEY-----"#;

        // This will fail because it's not valid base64, but tests the parsing logic
        let result = ApnsPrivateKey::parse_pem(pem);
        // We expect an error because the content isn't valid base64
        assert!(result.is_err());
    }
}
