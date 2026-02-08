//! Email MFA Handler
//!
//! Handles Email-based MFA setup, verification, and delivery.

use super::common::{CodeSendResult, MfaVerificationHandler};
use super::errors::{MfaError, MfaResult};
use crate::state::AppState;

/// Email MFA handler
pub struct EmailMfaHandler;

impl EmailMfaHandler {
    /// Create a new Email MFA handler
    pub fn new() -> Self {
        Self
    }

    /// Setup Email MFA - send verification code
    pub async fn setup(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        email: &str,
    ) -> MfaResult<CodeSendResult> {
        // Generate and store OTP code
        let code = Self::generate_code(6);
        let expires_at = chrono::Utc::now() + chrono::Duration::try_minutes(10).unwrap();

        state
            .db
            .mfa()
            .store_email_otp(tenant_id, user_id, &code, expires_at)
            .await
            .map_err(|e| {
                tracing::error!("Failed to store email OTP: {}", e);
                MfaError::Internal("Failed to store verification code".to_string())
            })?;

        // Send email
        if let Some(ref email_service) = state.email_service {
            let request = vault_core::email::EmailRequest {
                to: email.to_string(),
                subject: "Your verification code".to_string(),
                body: format!("Your verification code is: {}", code),
                html_body: Some(format!(
                    "<h2>Your Verification Code</h2><p>Your code is: <strong>{}</strong></p>",
                    code
                )),
                from: None,
                reply_to: None,
            };

            email_service
                .send(request)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to send email: {}", e);
                    MfaError::EmailServiceUnavailable
                })?;
        } else {
            return Err(MfaError::EmailServiceUnavailable);
        }

        let masked = Self::mask_email(email);

        Ok(CodeSendResult {
            message: format!("Verification code sent to {}", masked),
            destination_masked: masked,
            channel: "email".to_string(),
            remaining_attempts: None,
            expires_in_minutes: 10,
        })
    }

    /// Verify Email setup code and enable Email MFA
    pub async fn verify_setup(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> MfaResult<()> {
        let valid = self.verify_code(state, tenant_id, user_id, code).await?;

        if !valid {
            return Err(MfaError::InvalidCode);
        }

        // Enable Email MFA
        state
            .db
            .mfa()
            .create_email_method(tenant_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to create email method: {}", e);
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

    /// Send Email code for login verification
    pub async fn send_login_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        email: &str,
    ) -> MfaResult<CodeSendResult> {
        self.setup(state, tenant_id, user_id, email).await
    }

    /// Verify Email code for login
    pub async fn verify_login_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> MfaResult<bool> {
        let valid = state
            .db
            .mfa()
            .verify_email_otp(tenant_id, user_id, code)
            .await
            .map_err(|e| {
                tracing::error!("Failed to verify email OTP: {}", e);
                MfaError::Internal("Verification failed".to_string())
            })?;

        if valid {
            state
                .db
                .mfa()
                .mark_method_used(
                    tenant_id,
                    user_id,
                    vault_core::db::mfa::MfaMethodType::Email,
                )
                .await
                .ok();
        }

        Ok(valid)
    }

    /// Generate random OTP code
    fn generate_code(length: usize) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| rng.gen_range(0..10).to_string())
            .collect()
    }

    /// Mask email for display
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
}

impl Default for EmailMfaHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl MfaVerificationHandler for EmailMfaHandler {
    async fn send_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        identifier: &str,
    ) -> MfaResult<CodeSendResult> {
        self.setup(state, tenant_id, user_id, identifier).await
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
            .any(|m| matches!(m.method_type, vault_core::db::mfa::MfaMethodType::Email) && m.enabled))
    }

    fn method_type(&self) -> super::MfaMethod {
        super::MfaMethod::Email
    }
}
