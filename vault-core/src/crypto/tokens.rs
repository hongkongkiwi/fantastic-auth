//! Secure token generation and validation
//!
//! This module provides various token types for different purposes:
//! - CSRF tokens for form protection
//! - Magic link tokens for passwordless auth
//! - OTP codes for multi-factor authentication
//! - Refresh tokens for session management

use crate::error::{Result, VaultError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};

use super::{generate_random_bytes, generate_secure_random, secure_compare};

/// Token format version for future compatibility
const TOKEN_VERSION: u8 = 1;

/// Base trait for secure tokens
pub trait SecureToken: Sized {
    /// Generate a new token
    fn generate() -> Self;

    /// Generate with custom expiry
    fn with_expiry(expires_at: DateTime<Utc>) -> Self;

    /// Verify a token string
    fn verify(token: &str, secret: &str) -> Result<Self>;

    /// Get the token string
    fn as_str(&self) -> &str;

    /// Check if token is expired
    fn is_expired(&self) -> bool;

    /// Get expiry time
    fn expires_at(&self) -> DateTime<Utc>;
}

/// CSRF Token for form protection
#[derive(Debug, Clone)]
pub struct CsrfToken {
    token: String,
    hash: String,
    expires_at: DateTime<Utc>,
}

impl CsrfToken {
    /// Create new CSRF token
    pub fn new() -> Self {
        let token = generate_secure_random(32);
        let hash = Self::hash_token(&token);

        Self {
            token,
            hash,
            expires_at: Utc::now() + Duration::hours(24),
        }
    }

    /// Hash a token for storage in session
    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify a submitted token against stored hash
    pub fn verify_against_hash(&self, submitted: &str, stored_hash: &str) -> bool {
        let computed_hash = Self::hash_token(submitted);
        secure_compare(computed_hash.as_bytes(), stored_hash.as_bytes()) && !self.is_expired()
    }

    /// Get the hash for session storage
    pub fn hash(&self) -> &str {
        &self.hash
    }
}

impl Default for CsrfToken {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureToken for CsrfToken {
    fn generate() -> Self {
        Self::new()
    }

    fn with_expiry(expires_at: DateTime<Utc>) -> Self {
        let mut token = Self::new();
        token.expires_at = expires_at;
        token
    }

    fn verify(_token: &str, _secret: &str) -> Result<Self> {
        // CSRF tokens are verified against hash, not reconstructed
        Err(VaultError::crypto(
            "Use verify_against_hash for CSRF tokens",
        ))
    }

    fn as_str(&self) -> &str {
        &self.token
    }

    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

/// Magic link token for passwordless authentication
#[derive(Debug, Clone)]
pub struct MagicLinkToken {
    token: String,
    user_id: String,
    email: String,
    expires_at: DateTime<Utc>,
    used: bool,
}

impl MagicLinkToken {
    /// Generate new magic link token
    pub fn new(user_id: impl Into<String>, email: impl Into<String>) -> Self {
        // Format: version(1) || random(16) || user_id_hash(8) || timestamp(8)
        let random_part = generate_random_bytes(16);
        let user_id_str = user_id.into();
        let email_str = email.into();

        // Include hash of user_id to prevent token swapping
        let user_hash = {
            let mut hasher = Sha256::new();
            hasher.update(user_id_str.as_bytes());
            &hasher.finalize()[..8]
        };

        let timestamp = Utc::now().timestamp().to_be_bytes();

        let mut token_bytes = Vec::with_capacity(33);
        token_bytes.push(TOKEN_VERSION);
        token_bytes.extend_from_slice(&random_part);
        token_bytes.extend_from_slice(user_hash);
        token_bytes.extend_from_slice(&timestamp);

        let token = URL_SAFE_NO_PAD.encode(&token_bytes);

        Self {
            token,
            user_id: user_id_str,
            email: email_str,
            expires_at: Utc::now() + Duration::minutes(15),
            used: false,
        }
    }

    /// Get user ID
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Get email
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Mark token as used
    pub fn mark_used(&mut self) {
        self.used = true;
    }

    /// Check if token has been used
    pub fn is_used(&self) -> bool {
        self.used
    }

    /// Validate token format and extract components
    fn parse(token: &str) -> Result<(u8, Vec<u8>, Vec<u8>, i64)> {
        let bytes = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| VaultError::crypto("Invalid magic link token encoding"))?;

        if bytes.len() < 33 {
            return Err(VaultError::crypto("Magic link token too short"));
        }

        let version = bytes[0];
        let random = bytes[1..17].to_vec();
        let user_hash = bytes[17..25].to_vec();
        let timestamp = i64::from_be_bytes([
            bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31], bytes[32],
        ]);

        Ok((version, random, user_hash, timestamp))
    }
}

impl SecureToken for MagicLinkToken {
    fn generate() -> Self {
        Self::new("", "")
    }

    fn with_expiry(expires_at: DateTime<Utc>) -> Self {
        let mut token = Self::new("", "");
        token.expires_at = expires_at;
        token
    }

    fn verify(token: &str, user_id: &str) -> Result<Self> {
        let (version, _random, stored_hash, _timestamp) = Self::parse(token)?;

        if version != TOKEN_VERSION {
            return Err(VaultError::crypto("Invalid token version"));
        }

        // Verify user_id hash matches
        let computed_hash = {
            let mut hasher = Sha256::new();
            hasher.update(user_id.as_bytes());
            &hasher.finalize()[..8]
        };

        if !secure_compare(&computed_hash, &stored_hash) {
            return Err(VaultError::crypto("Token user mismatch"));
        }

        // Note: In production, you'd look up the token in database
        // to get the associated user_id and email. This is a simplified version.
        Err(VaultError::crypto(
            "Token verification requires database lookup",
        ))
    }

    fn as_str(&self) -> &str {
        &self.token
    }

    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at || self.used
    }

    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

/// TOTP/OTP code for multi-factor authentication
#[derive(Debug, Clone)]
pub struct OtpCode {
    code: String,
    expires_at: DateTime<Utc>,
    attempts: u32,
    max_attempts: u32,
}

impl OtpCode {
    /// Create new OTP code
    pub fn new(length: usize, ttl_seconds: i64) -> Self {
        let code = Self::generate_code(length);

        Self {
            code,
            expires_at: Utc::now() + Duration::seconds(ttl_seconds),
            attempts: 0,
            max_attempts: 3,
        }
    }

    /// Generate numeric OTP code
    /// 
    /// SECURITY: Uses OsRng (operating system's CSPRNG) for cryptographically secure
    /// random digit generation. This prevents predictability of OTP codes which could
    /// allow attackers to bypass MFA authentication.
    fn generate_code(length: usize) -> String {
        use rand::Rng;
        use rand_core::OsRng;
        
        let mut rng = OsRng;
        let mut code = String::with_capacity(length);

        for _ in 0..length {
            let digit = rng.gen_range(0..10);
            code.push(char::from_digit(digit, 10).unwrap());
        }

        code
    }

    /// Verify OTP code (with rate limiting per attempt)
    pub fn verify(&mut self, submitted: &str) -> Result<bool> {
        // Check expiry
        if self.is_expired() {
            return Err(VaultError::Authentication("OTP code has expired".into()));
        }

        // Check attempts
        if self.attempts >= self.max_attempts {
            return Err(VaultError::Authentication(
                "Maximum verification attempts exceeded".into(),
            ));
        }

        self.attempts += 1;

        // Constant-time comparison
        Ok(secure_compare(submitted.as_bytes(), self.code.as_bytes()))
    }

    /// Get remaining attempts
    pub fn remaining_attempts(&self) -> u32 {
        self.max_attempts.saturating_sub(self.attempts)
    }

    /// Create TOTP (Time-based OTP) using RFC 6238
    pub fn generate_totp(secret: &[u8], period: u64, digits: usize) -> Result<String> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        type HmacSha1 = Hmac<Sha1>;

        let timestamp = Utc::now().timestamp() as u64;
        let counter = timestamp / period;

        let mut mac = HmacSha1::new_from_slice(secret)
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

        let otp = binary % 10u32.pow(digits as u32);

        Ok(format!("{:0digits$}", otp, digits = digits))
    }

    /// Verify TOTP with time window tolerance
    pub fn verify_totp(secret: &[u8], submitted: &str, period: u64, window: i64) -> Result<bool> {
        let timestamp = Utc::now().timestamp() as u64;

        for offset in -window..=window {
            let test_time = timestamp.saturating_add((offset * period as i64) as u64);
            let counter = test_time / period;

            let expected = Self::generate_totp_at(secret, counter)?;
            if secure_compare(submitted.as_bytes(), expected.as_bytes()) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn generate_totp_at(secret: &[u8], counter: u64) -> Result<String> {
        use hmac::{Hmac, Mac};
        use sha1::Sha1;

        type HmacSha1 = Hmac<Sha1>;

        let mut mac = HmacSha1::new_from_slice(secret)
            .map_err(|_| VaultError::crypto("Invalid TOTP secret"))?;
        mac.update(&counter.to_be_bytes());
        let result = mac.finalize();
        let hash = result.into_bytes();

        let offset = (hash[hash.len() - 1] & 0xf) as usize;
        let binary = ((hash[offset] as u32 & 0x7f) << 24)
            | ((hash[offset + 1] as u32) << 16)
            | ((hash[offset + 2] as u32) << 8)
            | (hash[offset + 3] as u32);

        let otp = binary % 1_000_000;
        Ok(format!("{:06}", otp))
    }
}

impl SecureToken for OtpCode {
    fn generate() -> Self {
        Self::new(6, 300) // 6 digits, 5 minutes
    }

    fn with_expiry(expires_at: DateTime<Utc>) -> Self {
        let mut code = Self::new(6, 300);
        code.expires_at = expires_at;
        code
    }

    fn verify(_token: &str, _secret: &str) -> Result<Self> {
        // OTP codes are verified with verify() method, not reconstructed
        Err(VaultError::crypto("Use verify() method for OTP codes"))
    }

    fn as_str(&self) -> &str {
        &self.code
    }

    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

/// Refresh token for session management
#[derive(Debug, Clone)]
pub struct RefreshToken {
    token: String,
    token_hash: String,
    user_id: String,
    session_id: String,
    expires_at: DateTime<Utc>,
    used: bool,
    family: String, // Token family for rotation detection
}

impl RefreshToken {
    /// Create new refresh token
    pub fn new(user_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        // Generate cryptographically secure random token
        let random_bytes = generate_random_bytes(32);
        let token = URL_SAFE_NO_PAD.encode(&random_bytes);

        // Hash for database storage
        let mut hasher = Sha256::new();
        hasher.update(&random_bytes);
        let token_hash = hex::encode(hasher.finalize());

        // Generate token family for rotation detection
        let family = generate_secure_random(16);

        Self {
            token,
            token_hash,
            user_id: user_id.into(),
            session_id: session_id.into(),
            expires_at: Utc::now() + Duration::days(7),
            used: false,
            family,
        }
    }

    /// Get user ID
    pub fn user_id(&self) -> &str {
        &self.user_id
    }

    /// Get session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Get token hash for storage
    pub fn hash(&self) -> &str {
        &self.token_hash
    }

    /// Get token family
    pub fn family(&self) -> &str {
        &self.family
    }

    /// Mark as used
    pub fn mark_used(&mut self) {
        self.used = true;
    }

    /// Check if used
    pub fn is_used(&self) -> bool {
        self.used
    }

    /// Verify a submitted token against stored hash
    pub fn verify_against_hash(submitted: &str, stored_hash: &str) -> bool {
        let bytes = match URL_SAFE_NO_PAD.decode(submitted) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let computed_hash = hex::encode(hasher.finalize());

        secure_compare(computed_hash.as_bytes(), stored_hash.as_bytes())
    }

    /// Get the token string
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Rotate to new token (for refresh token rotation)
    pub fn rotate(&self) -> Self {
        let mut new_token = Self::new(&self.user_id, &self.session_id);
        new_token.family = self.family.clone(); // Keep same family
        new_token
    }
}

impl SecureToken for RefreshToken {
    fn generate() -> Self {
        Self::new("", "")
    }

    fn with_expiry(expires_at: DateTime<Utc>) -> Self {
        let mut token = Self::new("", "");
        token.expires_at = expires_at;
        token
    }

    fn verify(_token: &str, _secret: &str) -> Result<Self> {
        // Refresh tokens are verified against hash, not reconstructed
        Err(VaultError::crypto(
            "Use verify_against_hash for refresh tokens",
        ))
    }

    fn as_str(&self) -> &str {
        &self.token
    }

    fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at || self.used
    }

    fn expires_at(&self) -> DateTime<Utc> {
        self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_token() {
        let token = CsrfToken::new();
        assert_eq!(token.as_str().len(), 32);

        let hash = token.hash();
        assert!(token.verify_against_hash(token.as_str(), hash));
        assert!(!token.verify_against_hash("wrong_token", hash));
    }

    #[test]
    fn test_magic_link_token() {
        let token = MagicLinkToken::new("user_123", "test@example.com");
        assert!(!token.as_str().is_empty());
        assert!(!token.is_expired());
    }

    #[test]
    fn test_otp_code() {
        let mut code = OtpCode::new(6, 300);
        assert_eq!(code.as_str().len(), 6);
        assert!(code.as_str().chars().all(|c| c.is_ascii_digit()));

        // Correct code should verify
        let code_str = code.as_str().to_string();
        assert!(code.verify(&code_str).unwrap());

        // Wrong code should fail
        assert!(!code.verify("000000").unwrap());

        // Max attempts should be enforced
        let mut code2 = OtpCode::new(6, 300);
        code2.max_attempts = 2;
        assert!(!code2.verify("111111").unwrap());
        assert!(!code2.verify("222222").unwrap());
        assert!(code2.verify("333333").is_err()); // Max attempts exceeded
    }

    #[test]
    fn test_totp_generation() {
        let secret = b"12345678901234567890"; // RFC 6238 test secret

        // Test vector from RFC 6238
        let otp = OtpCode::generate_totp(secret, 30, 6).unwrap();
        assert_eq!(otp.len(), 6);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_refresh_token() {
        let token = RefreshToken::new("user_123", "session_456");
        assert!(!token.as_str().is_empty());
        assert!(!token.is_expired());
        assert_eq!(token.user_id(), "user_123");
        assert_eq!(token.session_id(), "session_456");

        // Verify hash
        assert!(RefreshToken::verify_against_hash(
            token.as_str(),
            token.hash()
        ));
        assert!(!RefreshToken::verify_against_hash("invalid", token.hash()));

        // Rotation
        let rotated = token.rotate();
        assert_eq!(rotated.family(), token.family());
        assert_ne!(rotated.as_str(), token.as_str());
    }

    #[test]
    fn test_token_expiry() {
        let expired_token = CsrfToken::with_expiry(Utc::now() - Duration::hours(1));
        assert!(expired_token.is_expired());
    }
}
