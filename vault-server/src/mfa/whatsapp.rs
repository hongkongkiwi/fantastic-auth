//! WhatsApp MFA Handler
//!
//! Handles WhatsApp-based MFA setup, verification, and delivery.
//! Shares SMS infrastructure for OTP delivery.

use super::common::{CodeSendResult, MfaVerificationHandler};
use super::errors::{MfaError, MfaResult};
use crate::state::AppState;

/// WhatsApp MFA handler
pub struct WhatsappMfaHandler;

impl WhatsappMfaHandler {
    /// Create a new WhatsApp MFA handler
    pub fn new() -> Self {
        Self
    }

    /// Setup WhatsApp MFA - send verification code
    pub async fn setup(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        phone_number: &str,
    ) -> MfaResult<CodeSendResult> {
        // Validate phone number
        let normalized = Self::normalize_phone(phone_number)?;

        // Get WhatsApp service (uses SMS service with WhatsApp provider)
        let sms_service = self.get_service(state).await?;

        // Send verification code via WhatsApp
        sms_service
            .send_code(&normalized)
            .await
            .map_err(|e| match e {
                vault_core::sms::SmsError::RateLimitExceeded(_) => MfaError::RateLimitExceeded,
                vault_core::sms::SmsError::InvalidPhoneNumber(msg) => {
                    MfaError::InvalidPhoneNumber(msg)
                }
                _ => {
                    tracing::error!("Failed to send WhatsApp message: {}", e);
                    MfaError::WhatsappServiceUnavailable
                }
            })?;

        let masked = Self::mask_phone(&normalized);

        Ok(CodeSendResult {
            message: format!("Verification code sent to {} via WhatsApp", masked),
            destination_masked: masked,
            channel: "whatsapp".to_string(),
            remaining_attempts: Some(3),
            expires_in_minutes: 10,
        })
    }

    /// Verify WhatsApp setup code and enable WhatsApp MFA
    pub async fn verify_setup(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        phone_number: &str,
        code: &str,
    ) -> MfaResult<()> {
        let normalized = Self::normalize_phone(phone_number)?;

        let sms_service = self.get_service(state).await?;

        let valid = sms_service
            .verify_code(&normalized, code)
            .await
            .map_err(|e| match e {
                vault_core::sms::SmsError::InvalidCode => MfaError::InvalidCode,
                vault_core::sms::SmsError::CodeNotFound => MfaError::CodeExpired,
                _ => {
                    tracing::error!("Failed to verify WhatsApp code: {}", e);
                    MfaError::Internal("Verification failed".to_string())
                }
            })?;

        if !valid {
            return Err(MfaError::InvalidCode);
        }

        // Enable WhatsApp MFA
        state
            .db
            .mfa()
            .create_whatsapp_method(tenant_id, user_id, &normalized)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create WhatsApp method: {}", e);
                MfaError::Database(e)
            })?;

        // Sync user MFA status
        crate::routes::client::mfa::sync_user_mfa_methods(state, tenant_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to sync MFA methods: {}", e);
                MfaError::Internal("Failed to sync MFA status".to_string())
            })?;

        Ok(())
    }

    /// Send WhatsApp code for login verification
    pub async fn send_login_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
    ) -> MfaResult<CodeSendResult> {
        let phone = state
            .db
            .mfa()
            .get_whatsapp_phone_number(tenant_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get WhatsApp phone: {}", e);
                MfaError::Database(e)
            })?
            .ok_or(MfaError::PhoneNotConfigured)?;

        self.setup(state, tenant_id, user_id, &phone).await
    }

    /// Verify WhatsApp code for login
    pub async fn verify_login_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> MfaResult<bool> {
        let phone = state
            .db
            .mfa()
            .get_whatsapp_phone_number(tenant_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get WhatsApp phone: {}", e);
                MfaError::Database(e)
            })?
            .ok_or(MfaError::PhoneNotConfigured)?;

        let sms_service = self.get_service(state).await?;

        let valid = sms_service
            .verify_code(&phone, code)
            .await
            .map_err(|e| match e {
                vault_core::sms::SmsError::InvalidCode => MfaError::InvalidCode,
                vault_core::sms::SmsError::CodeNotFound => MfaError::CodeExpired,
                _ => {
                    tracing::error!("Failed to verify WhatsApp code: {}", e);
                    MfaError::Internal("Verification failed".to_string())
                }
            })?;

        if valid {
            state
                .db
                .mfa()
                .mark_method_used(
                    tenant_id,
                    user_id,
                    vault_core::db::mfa::MfaMethodType::Whatsapp,
                )
                .await
                .ok();
        }

        Ok(valid)
    }

    fn normalize_phone(phone: &str) -> MfaResult<String> {
        vault_core::sms::SmsService::validate_phone_number(phone)
            .map_err(|e| MfaError::InvalidPhoneNumber(e.to_string()))
    }

    fn mask_phone(phone: &str) -> String {
        let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.len() <= 4 {
            phone.to_string()
        } else {
            format!(
                "***-{}-{}",
                &digits[digits.len() - 4..digits.len() - 2],
                &digits[digits.len() - 2..]
            )
        }
    }

    async fn get_service(&self, state: &AppState) -> MfaResult<Arc<vault_core::sms::SmsService>> {
        state
            .sms_service
            .clone()
            .ok_or(MfaError::WhatsappServiceUnavailable)
    }
}

impl Default for WhatsappMfaHandler {
    fn default() -> Self {
        Self::new()
    }
}

use std::sync::Arc;

#[async_trait::async_trait]
impl MfaVerificationHandler for WhatsappMfaHandler {
    async fn send_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        _identifier: &str,
    ) -> MfaResult<CodeSendResult> {
        self.send_login_code(state, tenant_id, user_id).await
    }

    async fn verify_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> MfaResult<bool> {
        self.verify_login_code(state, tenant_id, user_id, code).await
    }

    async fn is_enabled(&self, state: &AppState, tenant_id: &str, user_id: &str) -> MfaResult<bool> {
        let methods = state
            .db
            .mfa()
            .get_enabled_methods(tenant_id, user_id)
            .await
            .map_err(MfaError::Database)?;

        Ok(methods
            .iter()
            .any(|m| matches!(m.method_type, vault_core::db::mfa::MfaMethodType::Whatsapp) && m.enabled))
    }

    fn method_type(&self) -> super::MfaMethod {
        super::MfaMethod::Whatsapp
    }
}
