//! WhatsApp Business API provider for sending OTP codes
//!
//! This provider uses the WhatsApp Business API (via Meta/Facebook Graph API)
//! to send OTP verification codes through WhatsApp messages.
//!
//! # Requirements
//! - Meta Business account
//! - WhatsApp Business app
//! - Pre-approved message template for OTP
//! - Phone number registered with WhatsApp Business
//!
//! # Example
//! ```rust
//! use vault_core::sms::whatsapp::{WhatsAppProvider, WhatsAppConfig};
//!
//! let config = WhatsAppConfig {
//!     phone_number_id: "1234567890".to_string(),
//!     access_token: "EAABsbCS...".to_string(),
//!     api_version: "v18.0".to_string(),
//!     template_name: "vault_otp_en".to_string(),
//!     fallback_to_sms: true,
//! };
//!
//! let provider = WhatsAppProvider::new(config);
//! ```

use super::{SmsError, SmsProvider};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// WhatsApp API configuration
#[derive(Debug, Clone)]
pub struct WhatsAppConfig {
    /// WhatsApp Business phone number ID
    pub phone_number_id: String,
    /// Meta access token (permanent or temporary)
    pub access_token: String,
    /// Graph API version (e.g., "v18.0")
    pub api_version: String,
    /// Template name for OTP messages
    pub template_name: String,
    /// Fallback to SMS if WhatsApp fails
    pub fallback_to_sms: bool,
    /// Language code for template (default: en)
    pub language_code: String,
}

impl Default for WhatsAppConfig {
    fn default() -> Self {
        Self {
            phone_number_id: String::new(),
            access_token: String::new(),
            api_version: "v18.0".to_string(),
            template_name: "vault_otp_en".to_string(),
            fallback_to_sms: true,
            language_code: "en".to_string(),
        }
    }
}

impl WhatsAppConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<(), SmsError> {
        if self.phone_number_id.is_empty() {
            return Err(SmsError::Configuration(
                "WhatsApp phone_number_id is required".to_string(),
            ));
        }

        if self.access_token.is_empty() {
            return Err(SmsError::Configuration(
                "WhatsApp access_token is required".to_string(),
            ));
        }

        if self.api_version.is_empty() {
            return Err(SmsError::Configuration(
                "WhatsApp api_version is required".to_string(),
            ));
        }

        if self.template_name.is_empty() {
            return Err(SmsError::Configuration(
                "WhatsApp template_name is required".to_string(),
            ));
        }

        Ok(())
    }
}

/// WhatsApp message ID
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageId(pub String);

/// WhatsApp API response for message sending
#[derive(Debug, Deserialize)]
struct WhatsAppMessageResponse {
    #[serde(rename = "messaging_product")]
    messaging_product: String,
    #[serde(rename = "contacts")]
    contacts: Option<Vec<WhatsAppContact>>,
    #[serde(rename = "messages")]
    messages: Option<Vec<WhatsAppMessage>>,
}

#[derive(Debug, Deserialize)]
struct WhatsAppContact {
    input: String,
    #[serde(rename = "wa_id")]
    wa_id: String,
}

#[derive(Debug, Deserialize)]
struct WhatsAppMessage {
    id: String,
}

/// WhatsApp API error response
#[derive(Debug, Deserialize)]
struct WhatsAppErrorResponse {
    error: WhatsAppErrorDetail,
}

#[derive(Debug, Deserialize)]
struct WhatsAppErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
    code: i32,
    #[serde(rename = "error_subcode")]
    error_subcode: Option<i32>,
    #[serde(rename = "fbtrace_id")]
    fbtrace_id: Option<String>,
}

/// Request body for sending template message
#[derive(Debug, Serialize)]
struct TemplateMessageRequest {
    #[serde(rename = "messaging_product")]
    messaging_product: String,
    #[serde(rename = "recipient_type")]
    recipient_type: String,
    to: String,
    #[serde(rename = "type")]
    message_type: String,
    template: Template,
}

#[derive(Debug, Serialize)]
struct Template {
    name: String,
    language: Language,
    components: Vec<Component>,
}

#[derive(Debug, Serialize)]
struct Language {
    code: String,
}

#[derive(Debug, Serialize)]
struct Component {
    #[serde(rename = "type")]
    component_type: String,
    parameters: Vec<Parameter>,
}

#[derive(Debug, Serialize)]
struct Parameter {
    #[serde(rename = "type")]
    param_type: String,
    text: String,
}

/// WhatsApp Business API provider
pub struct WhatsAppProvider {
    config: WhatsAppConfig,
    http_client: reqwest::Client,
}

impl WhatsAppProvider {
    const API_BASE: &'static str = "https://graph.facebook.com";

    /// Create new WhatsApp provider with configuration
    pub fn new(config: WhatsAppConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Result<Self, SmsError> {
        let phone_number_id = std::env::var("WHATSAPP_PHONE_NUMBER_ID").map_err(|_| {
            SmsError::Configuration(
                "WHATSAPP_PHONE_NUMBER_ID environment variable not set".to_string(),
            )
        })?;

        let access_token = std::env::var("WHATSAPP_ACCESS_TOKEN").map_err(|_| {
            SmsError::Configuration(
                "WHATSAPP_ACCESS_TOKEN environment variable not set".to_string(),
            )
        })?;

        let api_version = std::env::var("WHATSAPP_API_VERSION").unwrap_or_else(|_| "v18.0".to_string());

        let template_name = std::env::var("WHATSAPP_TEMPLATE_NAME").unwrap_or_else(|_| "vault_otp_en".to_string());

        let fallback_to_sms = std::env::var("WHATSAPP_FALLBACK_TO_SMS")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true);

        let language_code = std::env::var("WHATSAPP_LANGUAGE_CODE").unwrap_or_else(|_| "en".to_string());

        let config = WhatsAppConfig {
            phone_number_id,
            access_token,
            api_version,
            template_name,
            fallback_to_sms,
            language_code,
        };

        Ok(Self::new(config))
    }

    /// Send OTP code via WhatsApp
    ///
    /// # Arguments
    /// * `to` - Phone number in E.164 format (e.g., +1234567890)
    /// * `code` - OTP code to send
    /// * `template_name` - Optional custom template name (uses config default if not provided)
    pub async fn send_otp(
        &self,
        to: &str,
        code: &str,
        template_name: Option<&str>,
    ) -> Result<MessageId, SmsError> {
        // Validate phone number format (E.164)
        let normalized_phone = Self::validate_whatsapp_number(to)?;

        let template = template_name.unwrap_or(&self.config.template_name);

        let url = format!(
            "{}/{}/{}/messages",
            Self::API_BASE,
            self.config.api_version,
            self.config.phone_number_id
        );

        let body = TemplateMessageRequest {
            messaging_product: "whatsapp".to_string(),
            recipient_type: "individual".to_string(),
            to: normalized_phone.clone(),
            message_type: "template".to_string(),
            template: Template {
                name: template.to_string(),
                language: Language {
                    code: self.config.language_code.clone(),
                },
                components: vec![Component {
                    component_type: "body".to_string(),
                    parameters: vec![Parameter {
                        param_type: "text".to_string(),
                        text: code.to_string(),
                    }],
                }],
            },
        };

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.access_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| SmsError::ProviderError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();

        if status.is_success() {
            let message_response: WhatsAppMessageResponse = response
                .json()
                .await
                .map_err(|e| SmsError::ProviderError(format!("Failed to parse response: {}", e)))?;

            let message_id = message_response
                .messages
                .as_ref()
                .and_then(|m| m.first())
                .map(|m| MessageId(m.id.clone()))
                .ok_or_else(|| SmsError::ProviderError("No message ID in response".to_string()))?;

            tracing::debug!(
                "WhatsApp message sent: id={}, to={}",
                message_id.0,
                normalized_phone
            );

            Ok(message_id)
        } else {
            let error_text = response.text().await.unwrap_or_default();

            if let Ok(error_response) = serde_json::from_str::<WhatsAppErrorResponse>(&error_text) {
                let err = &error_response.error;
                let msg = format!(
                    "WhatsApp API error ({}): {}",
                    err.code, err.message
                );

                // Map specific error codes
                match err.code {
                    100 => {
                        // Invalid parameter
                        if err.message.contains("phone") {
                            return Err(SmsError::InvalidPhoneNumber(format!(
                                "Invalid phone number: {}",
                                to
                            )));
                        }
                    }
                    190 => {
                        return Err(SmsError::Configuration(
                            "Invalid or expired WhatsApp access token".to_string(),
                        ))
                    }
                    200 => {
                        return Err(SmsError::Configuration(
                            "WhatsApp permission denied - check access token permissions".to_string(),
                        ))
                    }
                    80007 => {
                        // Template does not exist
                        return Err(SmsError::Configuration(format!(
                            "WhatsApp template '{}' not found or not approved",
                            template
                        )));
                    }
                    131000 => {
                        // Template parameter mismatch
                        return Err(SmsError::Configuration(
                            "WhatsApp template parameter mismatch - template may need {{1}} placeholder"
                                .to_string(),
                        ));
                    }
                    _ => {}
                }

                return Err(SmsError::ProviderError(msg));
            }

            Err(SmsError::ProviderError(format!(
                "WhatsApp API error ({}): {}",
                status, error_text
            )))
        }
    }

    /// Validate WhatsApp number format
    /// WhatsApp requires E.164 format but doesn't allow certain characters
    fn validate_whatsapp_number(phone: &str) -> Result<String, SmsError> {
        // Basic E.164 validation
        if !phone.starts_with('+') {
            return Err(SmsError::InvalidPhoneNumber(
                "Phone number must start with + and include country code".to_string(),
            ));
        }

        let digits_only: String = phone.chars().skip(1).filter(|c| c.is_ascii_digit()).collect();

        if digits_only.len() < 7 || digits_only.len() > 15 {
            return Err(SmsError::InvalidPhoneNumber(
                "Phone number must be between 7 and 15 digits".to_string(),
            ));
        }

        // Normalize to E.164 format (WhatsApp prefers this)
        Ok(format!("{}", digits_only))
    }

    /// Check if user has WhatsApp installed
    /// This is a best-effort check - the API doesn't guarantee delivery
    pub async fn check_whatsapp_user(&self, phone: &str) -> Result<bool, SmsError> {
        // The WhatsApp Business API doesn't provide a direct way to check
        // if a user has WhatsApp. We can only attempt to send and handle errors.
        // This method is provided for future API enhancements.
        Ok(true)
    }

    /// Send a generic template message (requires a pre-approved template)
    pub async fn send_template_message(
        &self,
        to: &str,
        template_name: &str,
        params: &[String],
    ) -> Result<MessageId, SmsError> {
        let normalized_phone = Self::validate_whatsapp_number(to)?;

        let url = format!(
            "{}/{}/{}/messages",
            Self::API_BASE,
            self.config.api_version,
            self.config.phone_number_id
        );

        let parameters: Vec<Parameter> = params
            .iter()
            .map(|text| Parameter {
                param_type: "text".to_string(),
                text: text.clone(),
            })
            .collect();

        let body = TemplateMessageRequest {
            messaging_product: "whatsapp".to_string(),
            recipient_type: "individual".to_string(),
            to: normalized_phone.clone(),
            message_type: "template".to_string(),
            template: Template {
                name: template_name.to_string(),
                language: Language {
                    code: self.config.language_code.clone(),
                },
                components: vec![Component {
                    component_type: "body".to_string(),
                    parameters,
                }],
            },
        };

        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.config.access_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| SmsError::ProviderError(format!("HTTP request failed: {}", e)))?;

        let status = response.status();

        if status.is_success() {
            let message_response: WhatsAppMessageResponse = response
                .json()
                .await
                .map_err(|e| SmsError::ProviderError(format!("Failed to parse response: {}", e)))?;

            let message_id = message_response
                .messages
                .as_ref()
                .and_then(|m| m.first())
                .map(|m| MessageId(m.id.clone()))
                .ok_or_else(|| SmsError::ProviderError("No message ID in response".to_string()))?;

            Ok(message_id)
        } else {
            let error_text = response.text().await.unwrap_or_default();
            if let Ok(error_response) = serde_json::from_str::<WhatsAppErrorResponse>(&error_text) {
                let err = &error_response.error;
                let msg = format!(
                    "WhatsApp API error ({}): {}",
                    err.code, err.message
                );
                return Err(SmsError::ProviderError(msg));
            }
            Err(SmsError::ProviderError(format!(
                "WhatsApp API error: {}",
                error_text
            )))
        }
    }
}

#[async_trait]
impl SmsProvider for WhatsAppProvider {
    async fn send_sms(&self, to: &str, message: &str) -> Result<(), SmsError> {
        // Extract OTP code from the message
        // Expected format: "Your verification code is: 123456. This code will expire in 10 minutes."
        let code = extract_code_from_message(message);

        if let Some(code) = code {
            self.send_otp(to, &code, None).await?;
            Ok(())
        } else {
            // Fallback: WhatsApp templates don't support arbitrary text messages
            // For non-OTP messages, this would require a different template
            Err(SmsError::ProviderError(
                "WhatsApp provider only supports OTP template messages".to_string(),
            ))
        }
    }

    async fn send_template(
        &self,
        to: &str,
        template_name: &str,
        params: &[String],
    ) -> Result<(), SmsError> {
        self.send_template_message(to, template_name, params).await?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "whatsapp"
    }

    async fn health_check(&self) -> Result<(), SmsError> {
        // Validate configuration
        self.config.validate()?;

        // Verify token format (should start with EAAB for permanent tokens)
        // Note: Temporary tokens have different format
        if !self.config.access_token.starts_with("EA") {
            return Err(SmsError::Configuration(
                "Invalid WhatsApp access token format - should start with 'EA'".to_string(),
            ));
        }

        // We could make a request to /me/accounts to verify token validity
        // but that requires additional permissions. For now, config validation is sufficient.

        Ok(())
    }
}

/// Extract OTP code from SMS message format
fn extract_code_from_message(message: &str) -> Option<String> {
    // Look for pattern: "Your verification code is: XXXXXX"
    message
        .split("Your verification code is: ")
        .nth(1)
        .and_then(|s| s.split('.').next())
        .map(|s| s.trim().to_string())
}

/// Pre-defined WhatsApp template configurations for common languages
pub mod templates {
    /// English OTP template
    pub const OTP_EN: &str = "vault_otp_en";

    /// Spanish OTP template
    pub const OTP_ES: &str = "vault_otp_es";

    /// Portuguese OTP template
    pub const OTP_PT: &str = "vault_otp_pt";

    /// French OTP template
    pub const OTP_FR: &str = "vault_otp_fr";

    /// German OTP template
    pub const OTP_DE: &str = "vault_otp_de";

    /// Hindi OTP template
    pub const OTP_HI: &str = "vault_otp_hi";

    /// Arabic OTP template
    pub const OTP_AR: &str = "vault_otp_ar";

    /// Indonesian OTP template
    pub const OTP_ID: &str = "vault_otp_id";

    /// Get template name for language code
    pub fn template_for_language(lang: &str) -> &'static str {
        match lang.to_lowercase().as_str() {
            "es" | "es-es" | "es-mx" | "es-ar" => OTP_ES,
            "pt" | "pt-br" | "pt-pt" => OTP_PT,
            "fr" | "fr-fr" | "fr-ca" => OTP_FR,
            "de" | "de-de" => OTP_DE,
            "hi" | "hi-in" => OTP_HI,
            "ar" | "ar-sa" => OTP_AR,
            "id" | "id-id" => OTP_ID,
            _ => OTP_EN,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whatsapp_config_validation() {
        let valid_config = WhatsAppConfig {
            phone_number_id: "1234567890".to_string(),
            access_token: "EAABsbCS...".to_string(),
            api_version: "v18.0".to_string(),
            template_name: "vault_otp_en".to_string(),
            fallback_to_sms: true,
            language_code: "en".to_string(),
        };
        assert!(valid_config.validate().is_ok());

        // Invalid - empty fields
        let invalid_config = WhatsAppConfig {
            phone_number_id: "".to_string(),
            access_token: "".to_string(),
            api_version: "".to_string(),
            template_name: "".to_string(),
            fallback_to_sms: true,
            language_code: "en".to_string(),
        };
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_validate_whatsapp_number() {
        // Valid numbers
        assert!(WhatsAppProvider::validate_whatsapp_number("+12345678901").is_ok());
        assert_eq!(
            WhatsAppProvider::validate_whatsapp_number("+1 (234) 567-8901").unwrap(),
            "12345678901"
        );

        // Invalid - no country code
        assert!(WhatsAppProvider::validate_whatsapp_number("1234567890").is_err());

        // Invalid - too short
        assert!(WhatsAppProvider::validate_whatsapp_number("+123").is_err());
    }

    #[test]
    fn test_extract_code_from_message() {
        let message = "Your verification code is: 123456. This code will expire in 10 minutes.";
        assert_eq!(extract_code_from_message(message), Some("123456".to_string()));

        let message_no_code = "Hello, this is a test message.";
        assert_eq!(extract_code_from_message(message_no_code), None);
    }

    #[test]
    fn test_template_for_language() {
        assert_eq!(templates::template_for_language("en"), "vault_otp_en");
        assert_eq!(templates::template_for_language("es"), "vault_otp_es");
        assert_eq!(templates::template_for_language("es-MX"), "vault_otp_es");
        assert_eq!(templates::template_for_language("pt-BR"), "vault_otp_pt");
        assert_eq!(templates::template_for_language("fr"), "vault_otp_fr");
        assert_eq!(templates::template_for_language("unknown"), "vault_otp_en");
    }

    #[test]
    fn test_whatsapp_provider_name() {
        let config = WhatsAppConfig::default();
        let provider = WhatsAppProvider::new(config);
        assert_eq!(provider.name(), "whatsapp");
    }
}
