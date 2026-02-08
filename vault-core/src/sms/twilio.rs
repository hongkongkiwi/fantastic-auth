//! Twilio SMS provider implementation

use super::{SmsError, SmsProvider};
use async_trait::async_trait;
use serde::Deserialize;

/// Twilio SMS provider
pub struct TwilioProvider {
    account_sid: String,
    auth_token: String,
    from_number: String,
    base_url: String,
    http_client: reqwest::Client,
}

impl TwilioProvider {
    /// Create new Twilio provider
    pub fn new(
        account_sid: impl Into<String>,
        auth_token: impl Into<String>,
        from_number: impl Into<String>,
    ) -> Self {
        let account_sid = account_sid.into();
        Self {
            account_sid: account_sid.clone(),
            auth_token: auth_token.into(),
            from_number: from_number.into(),
            base_url: format!(
                "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
                account_sid
            ),
            http_client: reqwest::Client::new(),
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Result<Self, SmsError> {
        let account_sid = std::env::var("TWILIO_ACCOUNT_SID").map_err(|_| {
            SmsError::Configuration("TWILIO_ACCOUNT_SID environment variable not set".to_string())
        })?;

        let auth_token = std::env::var("TWILIO_AUTH_TOKEN").map_err(|_| {
            SmsError::Configuration("TWILIO_AUTH_TOKEN environment variable not set".to_string())
        })?;

        let from_number = std::env::var("TWILIO_FROM_NUMBER").map_err(|_| {
            SmsError::Configuration("TWILIO_FROM_NUMBER environment variable not set".to_string())
        })?;

        Ok(Self::new(account_sid, auth_token, from_number))
    }
}

/// Twilio API response
#[derive(Debug, Deserialize)]
struct TwilioMessageResponse {
    sid: Option<String>,
    status: Option<String>,
    error_code: Option<String>,
    error_message: Option<String>,
}

/// Twilio error response
#[derive(Debug, Deserialize)]
struct TwilioErrorResponse {
    code: Option<u32>,
    message: String,
    #[serde(rename = "more_info")]
    more_info: Option<String>,
    status: Option<u16>,
}

#[async_trait]
impl SmsProvider for TwilioProvider {
    async fn send_sms(&self, to: &str, message: &str) -> Result<(), SmsError> {
        let params = [("To", to), ("From", &self.from_number), ("Body", message)];

        let response = self
            .http_client
            .post(&self.base_url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&params)
            .send()
            .await
            .map_err(|e| SmsError::ProviderError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();

        if status.is_success() {
            let message_response: TwilioMessageResponse = response
                .json()
                .await
                .map_err(|e| SmsError::ProviderError(format!("Failed to parse response: {}", e)))?;

            tracing::debug!(
                "Twilio message sent: sid={:?}, status={:?}",
                message_response.sid,
                message_response.status
            );

            Ok(())
        } else {
            // Try to parse error response
            let error_text = response.text().await.unwrap_or_default();

            // Attempt to parse structured error
            if let Ok(error_response) = serde_json::from_str::<TwilioErrorResponse>(&error_text) {
                let msg = format!(
                    "Twilio error ({}): {}",
                    error_response
                        .code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "unknown".to_string()),
                    error_response.message
                );

                // Map specific error codes
                if let Some(code) = error_response.code {
                    match code {
                        21211 | 21614 => {
                            return Err(SmsError::InvalidPhoneNumber(format!(
                                "Invalid 'To' phone number: {}",
                                to
                            )))
                        }
                        21606 => {
                            return Err(SmsError::Configuration(
                                "Twilio from number is not valid".to_string(),
                            ))
                        }
                        20003 => {
                            return Err(SmsError::Configuration(
                                "Twilio authentication failed - check credentials".to_string(),
                            ))
                        }
                        21610 => {
                            return Err(SmsError::ProviderError(
                                "Message cannot be sent to 'To' number due to compliance"
                                    .to_string(),
                            ))
                        }
                        _ => return Err(SmsError::ProviderError(msg)),
                    }
                }

                return Err(SmsError::ProviderError(msg));
            }

            Err(SmsError::ProviderError(format!(
                "Twilio API error ({}): {}",
                status, error_text
            )))
        }
    }

    fn name(&self) -> &'static str {
        "twilio"
    }

    async fn health_check(&self) -> Result<(), SmsError> {
        // Twilio doesn't have a specific health check endpoint
        // We can verify credentials by making a simple API call
        // For now, just verify credentials are set
        if self.account_sid.is_empty() || self.auth_token.is_empty() {
            return Err(SmsError::Configuration(
                "Twilio credentials not configured".to_string(),
            ));
        }

        // Verify account SID format (starts with "AC")
        if !self.account_sid.starts_with("AC") {
            return Err(SmsError::Configuration(
                "Invalid Twilio Account SID - should start with 'AC'".to_string(),
            ));
        }

        Ok(())
    }
}

/// Twilio configuration for server setup
#[derive(Debug, Clone)]
pub struct TwilioConfig {
    pub account_sid: String,
    pub auth_token: String,
    pub from_number: String,
}

impl TwilioConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<(), SmsError> {
        if self.account_sid.is_empty() {
            return Err(SmsError::Configuration(
                "Twilio account_sid is required".to_string(),
            ));
        }

        if self.auth_token.is_empty() {
            return Err(SmsError::Configuration(
                "Twilio auth_token is required".to_string(),
            ));
        }

        if self.from_number.is_empty() {
            return Err(SmsError::Configuration(
                "Twilio from_number is required".to_string(),
            ));
        }

        if !self.account_sid.starts_with("AC") {
            return Err(SmsError::Configuration(
                "Invalid Twilio Account SID - should start with 'AC'".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_twilio_config_validation() {
        let valid_config = TwilioConfig {
            account_sid: "AC_FAKE_SID_REMOVED".to_string(),
            auth_token: "some_auth_token".to_string(),
            from_number: "+12345678901".to_string(),
        };
        assert!(valid_config.validate().is_ok());

        // Invalid - no AC prefix
        let invalid_config = TwilioConfig {
            account_sid: "12345678901234567890123456789012".to_string(),
            auth_token: "some_auth_token".to_string(),
            from_number: "+12345678901".to_string(),
        };
        assert!(invalid_config.validate().is_err());

        // Invalid - empty fields
        let empty_config = TwilioConfig {
            account_sid: "".to_string(),
            auth_token: "".to_string(),
            from_number: "".to_string(),
        };
        assert!(empty_config.validate().is_err());
    }

    #[test]
    fn test_twilio_provider_name() {
        let provider = TwilioProvider::new(
            "AC_FAKE_SID_REMOVED",
            "auth_token",
            "+12345678901",
        );
        assert_eq!(provider.name(), "twilio");
    }

    // Note: Integration tests would require actual Twilio credentials
    // These should be run only in a secure CI environment
}
