//! Common MFA Verification Handlers
//!
//! Provides shared logic for OTP-based MFA methods (SMS, WhatsApp, Email).
//! This eliminates code duplication across method-specific handlers.

use super::errors::{MfaError, MfaResult};
use crate::state::AppState;

/// Trait for MFA verification handlers
#[async_trait::async_trait]
pub trait MfaVerificationHandler {
    /// Send verification code to the user
    async fn send_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        identifier: &str,
    ) -> MfaResult<CodeSendResult>;

    /// Verify the provided code
    async fn verify_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> MfaResult<bool>;

    /// Check if this MFA method is enabled for the user
    async fn is_enabled(&self, state: &AppState, tenant_id: &str, user_id: &str) -> MfaResult<bool>;

    /// Get the method type
    fn method_type(&self) -> super::MfaMethod;
}

/// Result of sending a verification code
#[derive(Debug, Clone)]
pub struct CodeSendResult {
    /// Success message
    pub message: String,
    /// Destination identifier (phone number, email, etc.) - masked for security
    pub destination_masked: String,
    /// Channel used (e.g., "sms", "whatsapp", "email")
    pub channel: String,
    /// Number of remaining attempts (if applicable)
    pub remaining_attempts: Option<u32>,
    /// Expiration time in minutes
    pub expires_in_minutes: i64,
}

/// OTP-based verification handler for SMS/WhatsApp/Email
pub struct OtpVerificationHandler {
    method: super::MfaMethod,
    code_expiry_minutes: i64,
}

impl OtpVerificationHandler {
    /// Create a new OTP handler for the specified method
    pub fn new(method: super::MfaMethod) -> Self {
        Self {
            method,
            code_expiry_minutes: 10, // Default 10 minutes
        }
    }

    /// Create with custom expiry
    pub fn with_expiry(mut self, minutes: i64) -> Self {
        self.code_expiry_minutes = minutes;
        self
    }

    /// Get the database method type
    fn db_method_type(&self) -> vault_core::db::mfa::MfaMethodType {
        match self.method {
            super::MfaMethod::Sms => vault_core::db::mfa::MfaMethodType::Sms,
            super::MfaMethod::Whatsapp => vault_core::db::mfa::MfaMethodType::Whatsapp,
            super::MfaMethod::Email => vault_core::db::mfa::MfaMethodType::Email,
            _ => panic!("OtpVerificationHandler only supports SMS, WhatsApp, and Email"),
        }
    }
}

#[async_trait::async_trait]
impl MfaVerificationHandler for OtpVerificationHandler {
    async fn send_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        identifier: &str,
    ) -> MfaResult<CodeSendResult> {
        // Store code in database
        let code = generate_otp_code(6);
        let expires_at = chrono::Utc::now()
            + chrono::Duration::try_minutes(self.code_expiry_minutes)
                .unwrap_or(chrono::Duration::try_hours(1).unwrap());

        state
            .db
            .mfa()
            .store_otp_code(tenant_id, user_id, &code, expires_at, &self.method.to_string())
            .await
            .map_err(|e| {
                tracing::error!("Failed to store OTP code: {}", e);
                MfaError::Internal("Failed to store verification code".to_string())
            })?;

        // Mask the identifier for the response
        let masked = mask_identifier(identifier);

        Ok(CodeSendResult {
            message: format!("Verification code sent to {}", masked),
            destination_masked: masked,
            channel: self.method.as_str().to_string(),
            remaining_attempts: None,
            expires_in_minutes: self.code_expiry_minutes,
        })
    }

    async fn verify_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> MfaResult<bool> {
        // Verify code against database
        let valid = state
            .db
            .mfa()
            .verify_otp_code(tenant_id, user_id, code, &self.method.to_string())
            .await
            .map_err(|e| {
                tracing::error!("Failed to verify OTP code: {}", e);
                MfaError::Internal("Failed to verify code".to_string())
            })?;

        if valid {
            // Mark method as used
            state
                .db
                .mfa()
                .mark_method_used(tenant_id, user_id, self.db_method_type())
                .await
                .ok();
        }

        Ok(valid)
    }

    async fn is_enabled(&self, state: &AppState, tenant_id: &str, user_id: &str) -> MfaResult<bool> {
        let methods = state
            .db
            .mfa()
            .get_enabled_methods(tenant_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get MFA methods: {}", e);
                MfaError::Database(e)
            })?;

        let method_type = self.db_method_type();
        Ok(methods
            .iter()
            .any(|m| m.method_type == method_type && m.enabled))
    }

    fn method_type(&self) -> super::MfaMethod {
        self.method
    }
}

/// Generate a random OTP code
fn generate_otp_code(length: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| rng.gen_range(0..10).to_string())
        .collect()
}

/// Mask an identifier (phone number or email) for display
fn mask_identifier(identifier: &str) -> String {
    if identifier.contains('@') {
        // Email masking
        mask_email(identifier)
    } else {
        // Phone number masking
        mask_phone(identifier)
    }
}

/// Mask email address (show first 2 chars and domain)
fn mask_email(email: &str) -> String {
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return "***".to_string();
    }
    let local = parts[0];
    let domain = parts[1];

    if local.len() <= 2 {
        format!("{}@{}", local, domain)
    } else {
        format!("{}***@{}", &local[..2], domain)
    }
}

/// Mask phone number (show last 4 digits)
fn mask_phone(phone: &str) -> String {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() <= 4 {
        phone.to_string()
    } else {
        format!("***-{}-{}", &digits[digits.len() - 4..digits.len() - 2], &digits[digits.len() - 2..])
    }
}

/// Unified verification response
#[derive(Debug, serde::Serialize)]
pub struct VerificationResponse {
    pub valid: bool,
    pub message: String,
}

impl VerificationResponse {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            valid: true,
            message: message.into(),
        }
    }

    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            valid: false,
            message: message.into(),
        }
    }
}

/// Unified setup response
#[derive(Debug, serde::Serialize)]
pub struct SetupResponse {
    pub message: String,
    pub expires_in_minutes: i64,
}

impl SetupResponse {
    pub fn new(message: impl Into<String>, expires_in_minutes: i64) -> Self {
        Self {
            message: message.into(),
            expires_in_minutes,
        }
    }
}

/// Unified send code response
#[derive(Debug, serde::Serialize)]
pub struct SendCodeResponse {
    pub message: String,
    #[serde(rename = "destinationMasked")]
    pub destination_masked: String,
    pub channel: String,
    #[serde(rename = "remainingAttempts")]
    pub remaining_attempts: Option<u32>,
    #[serde(rename = "expiresInMinutes")]
    pub expires_in_minutes: i64,
}

impl From<CodeSendResult> for SendCodeResponse {
    fn from(result: CodeSendResult) -> Self {
        Self {
            message: result.message,
            destination_masked: result.destination_masked,
            channel: result.channel,
            remaining_attempts: result.remaining_attempts,
            expires_in_minutes: result.expires_in_minutes,
        }
    }
}
