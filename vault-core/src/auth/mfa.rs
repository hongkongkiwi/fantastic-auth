//! Multi-factor authentication (MFA)
//!
//! Supports:
//! - TOTP (Time-based One-Time Password)
//! - Email OTP
//! - SMS OTP
//! - WebAuthn (FIDO2)
//! - Backup codes

use crate::error::{Result, VaultError};
use crate::sms::SmsService;
use std::sync::Arc;

/// MFA service that coordinates multiple MFA methods
pub struct MfaService {
    sms_service: Option<Arc<SmsService>>,
}

impl MfaService {
    /// Create new MFA service
    pub fn new() -> Self {
        Self { sms_service: None }
    }

    /// Create with SMS service
    pub fn with_sms_service(mut self, sms_service: Arc<SmsService>) -> Self {
        self.sms_service = Some(sms_service);
        self
    }

    /// Check if SMS MFA is available
    pub fn is_sms_available(&self) -> bool {
        self.sms_service
            .as_ref()
            .map(|s| s.is_configured())
            .unwrap_or(false)
    }

    /// Get SMS service reference
    pub fn sms_service(&self) -> Option<&Arc<SmsService>> {
        self.sms_service.as_ref()
    }

    /// Send SMS MFA code to a phone number
    pub async fn send_sms_code(&self, phone: &str) -> Result<()> {
        match &self.sms_service {
            Some(service) => service.send_code(phone).await.map_err(|e| e.into()),
            None => Err(VaultError::Config("SMS service not configured".to_string())),
        }
    }

    /// Verify SMS MFA code
    pub async fn verify_sms_code(&self, phone: &str, code: &str) -> Result<bool> {
        match &self.sms_service {
            Some(service) => service.verify_code(phone, code).await.map_err(|e| e.into()),
            None => Err(VaultError::Config("SMS service not configured".to_string())),
        }
    }
}

impl Default for MfaService {
    fn default() -> Self {
        Self::new()
    }
}

/// MFA method types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaType {
    /// Time-based OTP (TOTP)
    Totp,
    /// Email OTP
    Email,
    /// SMS OTP
    Sms,
    /// WebAuthn/FIDO2
    Webauthn,
    /// Backup codes
    BackupCodes,
}

impl MfaType {
    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            MfaType::Totp => "Authenticator App",
            MfaType::Email => "Email",
            MfaType::Sms => "SMS",
            MfaType::Webauthn => "Security Key",
            MfaType::BackupCodes => "Backup Codes",
        }
    }
}

/// TOTP configuration
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// Secret key (base32 encoded)
    pub secret: String,
    /// Issuer name
    pub issuer: String,
    /// Account name (email)
    pub account_name: String,
    /// Algorithm (SHA1, SHA256, SHA512)
    pub algorithm: String,
    /// Digits (usually 6)
    pub digits: u8,
    /// Period in seconds (usually 30)
    pub period: u32,
}

impl TotpConfig {
    /// Generate new TOTP configuration
    pub fn generate(issuer: impl Into<String>, account_name: impl Into<String>) -> Self {
        use crate::crypto::generate_random_bytes;
        use base32::Alphabet;

        // Generate random secret (20 bytes = 160 bits)
        let secret_bytes = generate_random_bytes(20);
        let secret = base32::encode(Alphabet::Rfc4648 { padding: false }, &secret_bytes);

        Self {
            secret,
            issuer: issuer.into(),
            account_name: account_name.into(),
            algorithm: "SHA1".to_string(),
            digits: 6,
            period: 30,
        }
    }

    /// Generate QR code URI
    pub fn qr_uri(&self) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            urlencoding::encode(&self.issuer),
            urlencoding::encode(&self.account_name),
            self.secret,
            urlencoding::encode(&self.issuer),
            self.algorithm,
            self.digits,
            self.period
        )
    }

    /// Verify TOTP code
    pub fn verify(&self, code: &str, window: i64) -> bool {
        use hmac::Hmac;
        use sha1::Sha1;

        type HmacSha1 = Hmac<Sha1>;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for offset in -window..=window {
            let test_time = timestamp.saturating_add((offset * self.period as i64) as u64);
            let counter = test_time / self.period as u64;

            if let Ok(expected) = self.generate_code(counter) {
                if crate::crypto::secure_compare(code.as_bytes(), expected.as_bytes()) {
                    return true;
                }
            }
        }

        false
    }

    /// Generate TOTP code for a specific counter
    fn generate_code(&self, counter: u64) -> Result<String> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        type HmacSha1 = Hmac<Sha1>;

        let secret_bytes =
            base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &self.secret)
                .ok_or_else(|| VaultError::crypto("Invalid TOTP secret"))?;

        let mut mac = HmacSha1::new_from_slice(&secret_bytes)
            .map_err(|_| VaultError::crypto("Invalid TOTP secret"))?;
        mac.update(&counter.to_be_bytes());
        let result = mac.finalize();
        let hash = result.into_bytes();

        // Dynamic truncation
        let offset = (hash[hash.len() - 1] & 0xf) as usize;
        let binary = ((hash[offset] as u32 & 0x7f) << 24)
            | ((hash[offset + 1] as u32) << 16)
            | ((hash[offset + 2] as u32) << 8)
            | (hash[offset + 3] as u32);

        let otp = binary % 10u32.pow(self.digits as u32);

        Ok(format!("{:0digits$}", otp, digits = self.digits as usize))
    }
}

/// Generate backup codes
pub fn generate_backup_codes(count: usize) -> Vec<String> {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let mut codes = Vec::with_capacity(count);

    for _ in 0..count {
        // Format: XXXX-XXXX-XXXX (4 groups of 4 alphanumeric)
        let code: String = (0..12)
            .map(|i| {
                if i > 0 && i % 4 == 0 {
                    '-'
                } else {
                    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No confusing chars
                    CHARSET[rng.gen_range(0..CHARSET.len())] as char
                }
            })
            .collect();
        codes.push(code);
    }

    codes
}

/// Hash backup codes for storage
pub fn hash_backup_codes(codes: &[String]) -> Vec<String> {
    use crate::crypto::VaultPasswordHasher;

    codes
        .iter()
        .map(|code| {
            // Normalize: uppercase and remove dashes
            let normalized = code.to_uppercase().replace('-', "");
            VaultPasswordHasher::hash(&normalized).unwrap()
        })
        .collect()
}

/// Verify backup code
pub fn verify_backup_code(code: &str, hashed_codes: &[String]) -> bool {
    use crate::crypto::VaultPasswordHasher;

    let normalized = code.to_uppercase().replace('-', "");

    for hashed in hashed_codes {
        if VaultPasswordHasher::verify(&normalized, hashed).unwrap_or(false) {
            return true;
        }
    }

    false
}

/// WebAuthn challenge (placeholder)
#[derive(Debug, Clone)]
pub struct WebAuthnChallenge {
    pub challenge: Vec<u8>,
    pub rp_id: String,
    pub user_id: String,
}

impl WebAuthnChallenge {
    /// Generate new challenge
    pub fn generate(rp_id: impl Into<String>, user_id: impl Into<String>) -> Self {
        use crate::crypto::generate_random_bytes;

        Self {
            challenge: generate_random_bytes(32),
            rp_id: rp_id.into(),
            user_id: user_id.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_generation() {
        let config = TotpConfig::generate("Vault", "user@example.com");
        assert!(!config.secret.is_empty());
        assert_eq!(config.digits, 6);
        assert_eq!(config.period, 30);
    }

    #[test]
    fn test_totp_verification() {
        let config = TotpConfig::generate("Vault", "user@example.com");

        // Generate current code
        let code = config
            .generate_code(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    / 30,
            )
            .unwrap();

        // Verify within window
        assert!(config.verify(&code, 1));

        // Verify wrong code fails
        assert!(!config.verify("000000", 1));
    }

    #[test]
    fn test_backup_codes() {
        let codes = generate_backup_codes(10);
        assert_eq!(codes.len(), 10);

        // Check format
        for code in &codes {
            assert_eq!(code.len(), 14); // 12 chars + 2 dashes
            assert_eq!(code.matches('-').count(), 2);
        }

        // Hash and verify
        let hashed = hash_backup_codes(&codes);
        assert!(verify_backup_code(&codes[0], &hashed));
        assert!(!verify_backup_code("INVALID", &hashed));
    }
}
