//! Bot protection using Cloudflare Turnstile
//!
//! Provides CAPTCHA verification to protect against automated attacks.

use async_trait::async_trait;
use serde::Deserialize;

/// Bot protection trait
#[async_trait]
pub trait BotProtection: Send + Sync {
    /// Verify a CAPTCHA token
    async fn verify_token(
        &self,
        token: &str,
        remote_ip: Option<&str>,
    ) -> Result<VerificationResult, BotError>;

    /// Get the site key for the frontend
    fn site_key(&self) -> &str;

    /// Check if bot protection is enabled
    fn is_enabled(&self) -> bool;
}

/// Verification result
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the token is valid
    pub success: bool,
    /// Challenge timestamp
    pub challenge_ts: Option<String>,
    /// Hostname where challenge was solved
    pub hostname: Option<String>,
    /// Error codes (if failed)
    pub error_codes: Vec<String>,
    /// Action (if specified)
    pub action: Option<String>,
    /// cdata (if specified)
    pub cdata: Option<String>,
}

impl VerificationResult {
    /// Check if verification succeeded
    pub fn is_success(&self) -> bool {
        self.success
    }
}

/// Bot protection errors
#[derive(Debug, thiserror::Error)]
pub enum BotError {
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
}

/// Cloudflare Turnstile implementation
pub struct CloudflareTurnstile {
    secret_key: String,
    site_key: String,
    client: reqwest::Client,
    verify_url: String,
}

impl CloudflareTurnstile {
    /// Turnstile verify endpoint
    const VERIFY_URL: &'static str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    /// Create new Turnstile verifier
    pub fn new(secret_key: impl Into<String>, site_key: impl Into<String>) -> Self {
        Self {
            secret_key: secret_key.into(),
            site_key: site_key.into(),
            client: reqwest::Client::new(),
            verify_url: Self::VERIFY_URL.to_string(),
        }
    }

    /// Create for testing with custom URL
    #[cfg(test)]
    pub fn with_url(
        secret_key: impl Into<String>,
        site_key: impl Into<String>,
        verify_url: impl Into<String>,
    ) -> Self {
        Self {
            secret_key: secret_key.into(),
            site_key: site_key.into(),
            client: reqwest::Client::new(),
            verify_url: verify_url.into(),
        }
    }

    /// Create disabled (for development)
    pub fn disabled() -> DisabledBotProtection {
        DisabledBotProtection
    }
}

#[async_trait]
impl BotProtection for CloudflareTurnstile {
    async fn verify_token(
        &self,
        token: &str,
        remote_ip: Option<&str>,
    ) -> Result<VerificationResult, BotError> {
        let mut params = vec![("secret", self.secret_key.as_str()), ("response", token)];

        if let Some(ip) = remote_ip {
            params.push(("remoteip", ip));
        }

        let response = self
            .client
            .post(&self.verify_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| BotError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(BotError::InvalidResponse(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let turnstile_response: TurnstileResponse = response
            .json()
            .await
            .map_err(|e| BotError::InvalidResponse(e.to_string()))?;

        Ok(VerificationResult {
            success: turnstile_response.success,
            challenge_ts: turnstile_response.challenge_ts,
            hostname: turnstile_response.hostname,
            error_codes: turnstile_response.error_codes.unwrap_or_default(),
            action: turnstile_response.action,
            cdata: turnstile_response.cdata,
        })
    }

    fn site_key(&self) -> &str {
        &self.site_key
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

/// Turnstile API response
#[derive(Debug, Clone, Deserialize)]
pub struct TurnstileResponse {
    pub success: bool,
    #[serde(rename = "challenge_ts")]
    pub challenge_ts: Option<String>,
    pub hostname: Option<String>,
    #[serde(rename = "error-codes")]
    pub error_codes: Option<Vec<String>>,
    pub action: Option<String>,
    pub cdata: Option<String>,
}

/// Disabled bot protection (for development/testing)
pub struct DisabledBotProtection;

#[async_trait]
impl BotProtection for DisabledBotProtection {
    async fn verify_token(
        &self,
        _token: &str,
        _remote_ip: Option<&str>,
    ) -> Result<VerificationResult, BotError> {
        Ok(VerificationResult {
            success: true,
            challenge_ts: None,
            hostname: None,
            error_codes: vec![],
            action: None,
            cdata: None,
        })
    }

    fn site_key(&self) -> &str {
        ""
    }

    fn is_enabled(&self) -> bool {
        false
    }
}

/// hCaptcha implementation (alternative to Turnstile)
pub struct HCaptcha {
    secret_key: String,
    site_key: String,
    client: reqwest::Client,
}

impl HCaptcha {
    /// hCaptcha verify endpoint
    const VERIFY_URL: &'static str = "https://hcaptcha.com/siteverify";

    /// Create new hCaptcha verifier
    pub fn new(secret_key: impl Into<String>, site_key: impl Into<String>) -> Self {
        Self {
            secret_key: secret_key.into(),
            site_key: site_key.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl BotProtection for HCaptcha {
    async fn verify_token(
        &self,
        token: &str,
        remote_ip: Option<&str>,
    ) -> Result<VerificationResult, BotError> {
        let mut params = vec![("secret", self.secret_key.as_str()), ("response", token)];

        if let Some(ip) = remote_ip {
            params.push(("remoteip", ip));
        }

        let response = self
            .client
            .post(Self::VERIFY_URL)
            .form(&params)
            .send()
            .await
            .map_err(|e| BotError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(BotError::InvalidResponse(format!(
                "HTTP {}",
                response.status()
            )));
        }

        let hcaptcha_response: HCaptchaResponse = response
            .json()
            .await
            .map_err(|e| BotError::InvalidResponse(e.to_string()))?;

        Ok(VerificationResult {
            success: hcaptcha_response.success,
            challenge_ts: hcaptcha_response.challenge_ts,
            hostname: hcaptcha_response.hostname,
            error_codes: hcaptcha_response.error_codes.unwrap_or_default(),
            action: None,
            cdata: None,
        })
    }

    fn site_key(&self) -> &str {
        &self.site_key
    }

    fn is_enabled(&self) -> bool {
        true
    }
}

/// hCaptcha API response
#[derive(Debug, Clone, Deserialize)]
pub struct HCaptchaResponse {
    pub success: bool,
    #[serde(rename = "challenge_ts")]
    pub challenge_ts: Option<String>,
    pub hostname: Option<String>,
    #[serde(rename = "error-codes")]
    pub error_codes: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_bot_protection() {
        let bot = DisabledBotProtection;
        assert!(!bot.is_enabled());
        assert_eq!(bot.site_key(), "");
    }

    #[tokio::test]
    async fn test_disabled_verification() {
        let bot = DisabledBotProtection;
        let result = bot.verify_token("any-token", None).await.unwrap();
        assert!(result.success);
    }
}
