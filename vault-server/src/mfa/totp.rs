//! TOTP (Time-based One-Time Password) MFA Handler
//!
//! Handles TOTP-based MFA setup and verification using standard authenticator apps.

use super::errors::{MfaError, MfaResult};
use crate::state::AppState;
use subtle::ConstantTimeEq;

/// TOTP MFA handler
pub struct TotpMfaHandler;

impl TotpMfaHandler {
    /// Create a new TOTP MFA handler
    pub fn new() -> Self {
        Self
    }

    /// Setup TOTP MFA - generate secret and QR code
    pub async fn setup(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        user_email: &str,
    ) -> MfaResult<TotpSetupResult> {
        // Generate TOTP secret
        let secret = Self::generate_secret();
        
        // Generate backup codes
        let backup_codes: Vec<String> = (0..10)
            .map(|_| Self::generate_backup_code())
            .collect();

        // Store pending TOTP setup
        state
            .db
            .mfa()
            .store_pending_totp(tenant_id, user_id, &secret, &backup_codes)
            .await
            .map_err(|e| {
                tracing::error!("Failed to store pending TOTP: {}", e);
                MfaError::Database(e)
            })?;

        // Generate QR code URI
        let qr_uri = format!(
            "otpauth://totp/Vault:{}?secret={}&issuer=Vault",
            user_email, secret
        );

        Ok(TotpSetupResult {
            secret,
            qr_code_uri: qr_uri,
            backup_codes,
        })
    }

    /// Verify TOTP setup code and enable TOTP MFA
    pub async fn verify_setup(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        code: &str,
        provided_secret: &str,
    ) -> MfaResult<()> {
        // Verify the code against the provided secret
        let valid = Self::verify_totp_code(provided_secret, code)?;

        if !valid {
            return Err(MfaError::InvalidCode);
        }

        // Confirm TOTP setup
        state
            .db
            .mfa()
            .confirm_totp_setup(tenant_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to confirm TOTP setup: {}", e);
                MfaError::Database(e)
            })?;

        // Sync user MFA status
        crate::mfa::sync_user_mfa_methods(state, tenant_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to sync MFA methods: {}", e);
                MfaError::Internal("Failed to sync MFA status".to_string())
            })?;

        Ok(())
    }

    /// Verify TOTP code for login
    pub async fn verify_login_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> MfaResult<bool> {
        // Get user's TOTP secret
        let secret = state
            .db
            .mfa()
            .get_totp_secret(tenant_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!("Failed to get TOTP secret: {}", e);
                MfaError::Database(e)
            })?
            .ok_or_else(|| MfaError::MethodNotEnabled("TOTP".to_string()))?;

        // Verify code
        let valid = Self::verify_totp_code(&secret, code)?;

        if valid {
            state
                .db
                .mfa()
                .mark_method_used(
                    tenant_id,
                    user_id,
                    vault_core::db::mfa::MfaMethodType::Totp,
                )
                .await
                .ok();
        }

        Ok(valid)
    }

    /// Verify backup code
    pub async fn verify_backup_code(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> MfaResult<bool> {
        state
            .db
            .mfa()
            .verify_and_consume_backup_code(tenant_id, user_id, code)
            .await
            .map_err(|e| {
                tracing::error!("Failed to verify backup code: {}", e);
                MfaError::Database(e)
            })
    }

    /// Check if TOTP is enabled for user
    pub async fn is_enabled(
        &self,
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
    ) -> MfaResult<bool> {
        let methods = state
            .db
            .mfa()
            .get_enabled_methods(tenant_id, user_id)
            .await
            .map_err(MfaError::Database)?;

        Ok(methods
            .iter()
            .any(|m| matches!(m.method_type, vault_core::db::mfa::MfaMethodType::Totp) && m.enabled))
    }

    /// Generate a random TOTP secret (Base32)
    fn generate_secret() -> String {
        use rand::Rng;
        const BASE32_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut rng = rand::thread_rng();
        
        (0..32)
            .map(|_| {
                let idx = rng.gen_range(0..BASE32_CHARS.len());
                BASE32_CHARS[idx] as char
            })
            .collect()
    }

    /// Generate a backup code
    fn generate_backup_code() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        // Format: XXXX-XXXX-XXXX (12 alphanumeric characters)
        (0..12)
            .map(|i| {
                if i == 4 || i == 8 {
                    '-'
                } else {
                    let chars = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No confusing characters
                    let idx = rng.gen_range(0..chars.len());
                    chars[idx] as char
                }
            })
            .collect()
    }

    /// Verify a TOTP code against a secret
    fn verify_totp_code(secret: &str, code: &str) -> MfaResult<bool> {
        // Basic validation
        if code.len() != 6 {
            return Ok(false);
        }

        // Check if code is numeric
        if !code.chars().all(|c| c.is_ascii_digit()) {
            return Ok(false);
        }

        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| MfaError::Internal("Time error".to_string()))?
            .as_secs();

        // TOTP time step (30 seconds)
        const TIME_STEP: u64 = 30;
        let current_step = timestamp / TIME_STEP;

        // Check current, previous, and next time windows
        for window in -1_i32..=1_i32 {
            let step = if window < 0 {
                current_step.saturating_sub((-window) as u64)
            } else {
                current_step.saturating_add(window as u64)
            };
            let expected_code = Self::generate_totp_code(secret, step)?;

            if code.as_bytes().ct_eq(expected_code.as_bytes()).into() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Generate TOTP code for a specific time step
    fn generate_totp_code(secret: &str, step: u64) -> MfaResult<String> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        // Decode base32 secret
        let decoded = base32_decode(secret)
            .ok_or_else(|| MfaError::Internal("Invalid secret".to_string()))?;

        // Create HMAC
        let mut mac = HmacSha256::new_from_slice(&decoded)
            .map_err(|_| MfaError::Internal("HMAC error".to_string()))?;

        // Add time step
        mac.update(&step.to_be_bytes());
        let result = mac.finalize();
        let hash = result.into_bytes();

        // Dynamic truncation
        let offset = (hash[hash.len() - 1] & 0x0f) as usize;
        let code = ((hash[offset] as u32 & 0x7f) << 24
            | (hash[offset + 1] as u32 & 0xff) << 16
            | (hash[offset + 2] as u32 & 0xff) << 8
            | (hash[offset + 3] as u32 & 0xff)) % 1_000_000;

        Ok(format!("{:06}", code))
    }
}

impl Default for TotpMfaHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// TOTP setup result
#[derive(Debug, Clone)]
pub struct TotpSetupResult {
    pub secret: String,
    pub qr_code_uri: String,
    pub backup_codes: Vec<String>,
}

/// Simple base32 decoder
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    const BASE32_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    
    let input = input.to_uppercase();
    let mut result = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits_left: u8 = 0;

    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        
        let value = BASE32_CHARS.find(ch)? as u32;
        buffer = (buffer << 5) | value;
        bits_left += 5;

        if bits_left >= 8 {
            bits_left -= 8;
            result.push((buffer >> bits_left) as u8);
        }
    }

    Some(result)
}
