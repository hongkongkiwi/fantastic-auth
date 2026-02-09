//! Bot protection for Fantastic Auth Server
//!
//! Re-exports bot protection types from fantasticauth-core for server-side usage.
//! Provides additional server-specific bot protection utilities.

pub use vault_core::security::bot_protection::{
    BotError, BotProtection, CloudflareTurnstile, DisabledBotProtection, HCaptcha,
    VerificationResult,
};

/// Bot protection error types for API responses
#[derive(Debug, thiserror::Error)]
pub enum BotProtectionError {
    /// Verification failed
    #[error("CAPTCHA verification failed: {0}")]
    VerificationFailed(String),
    /// Network error
    #[error("Network error: {0}")]
    Network(String),
    /// Invalid response from provider
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
    /// Missing token
    #[error("CAPTCHA token is required")]
    MissingToken,
}

impl From<BotError> for BotProtectionError {
    fn from(error: BotError) -> Self {
        match error {
            BotError::VerificationFailed(msg) => Self::VerificationFailed(msg),
            BotError::Network(msg) => Self::Network(msg),
            BotError::InvalidResponse(msg) => Self::InvalidResponse(msg),
            BotError::Configuration(msg) => Self::Configuration(msg),
        }
    }
}

/// Result type for bot protection operations
pub type BotProtectionResult<T> = std::result::Result<T, BotProtectionError>;

/// Verify a CAPTCHA token using the configured bot protection provider
///
/// # Arguments
/// * `bot_protection` - The bot protection implementation
/// * `token` - The CAPTCHA token to verify
/// * `remote_ip` - Optional client IP address for additional verification
///
/// # Returns
/// `true` if verification succeeds, `false` otherwise
pub async fn verify_captcha_token(
    bot_protection: &dyn BotProtection,
    token: &str,
    remote_ip: Option<&str>,
) -> BotProtectionResult<bool> {
    if !bot_protection.is_enabled() {
        return Ok(true);
    }

    let result = bot_protection
        .verify_token(token, remote_ip)
        .await
        .map_err(BotProtectionError::from)?;

    Ok(result.success)
}

/// Check if bot protection is required for a specific endpoint
///
/// # Arguments
/// * `bot_protection` - The bot protection implementation
/// * `endpoint` - The endpoint name (e.g., "login", "register")
/// * `failed_attempts` - Number of failed attempts (for conditional protection)
///
/// # Returns
/// `true` if CAPTCHA is required, `false` otherwise
pub fn is_captcha_required(
    bot_protection: &dyn BotProtection,
    _endpoint: &str,
    failed_attempts: u32,
    threshold: u32,
) -> bool {
    if !bot_protection.is_enabled() {
        return false;
    }

    // If threshold is 0, CAPTCHA is always required
    if threshold == 0 {
        return true;
    }

    // Require CAPTCHA after threshold is reached
    failed_attempts >= threshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bot_protection_error_conversion() {
        let bot_error = BotError::VerificationFailed("test".to_string());
        let app_error: BotProtectionError = bot_error.into();

        match app_error {
            BotProtectionError::VerificationFailed(msg) => assert_eq!(msg, "test"),
            _ => panic!("Wrong error variant"),
        }
    }

    #[test]
    fn test_disabled_bot_protection() {
        let disabled = DisabledBotProtection;
        assert!(!disabled.is_enabled());
        assert_eq!(disabled.site_key(), "");
    }

    #[tokio::test]
    async fn test_verify_captcha_disabled() {
        let disabled = DisabledBotProtection;
        let result = verify_captcha_token(&disabled, "any-token", None).await;
        assert!(result.unwrap());
    }
}
