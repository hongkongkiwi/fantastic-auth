//! Biometric authentication support
//!
//! Provides authentication using device biometrics (Face ID, Touch ID, Fingerprint)
//! using ECDSA P-256 challenge-response authentication.

use crate::crypto::generate_secure_random;
use crate::error::{Result, VaultError};
use chrono::{DateTime, Duration, Utc};
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Biometric key stored for user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricKey {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub public_key: Vec<u8>,
    pub key_id: String,
    pub device_name: String,
    pub biometric_type: BiometricType,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Biometric authentication types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "biometric_type", rename_all = "snake_case")]
pub enum BiometricType {
    /// iOS Face ID
    FaceId,
    /// iOS Touch ID
    TouchId,
    /// Android fingerprint
    Fingerprint,
    /// Android face unlock
    FaceUnlock,
    /// Samsung iris
    Iris,
}

impl fmt::Display for BiometricType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BiometricType::FaceId => write!(f, "Face ID"),
            BiometricType::TouchId => write!(f, "Touch ID"),
            BiometricType::Fingerprint => write!(f, "Fingerprint"),
            BiometricType::FaceUnlock => write!(f, "Face Unlock"),
            BiometricType::Iris => write!(f, "Iris"),
        }
    }
}

impl BiometricType {
    pub fn as_str(&self) -> &'static str {
        match self {
            BiometricType::FaceId => "face_id",
            BiometricType::TouchId => "touch_id",
            BiometricType::Fingerprint => "fingerprint",
            BiometricType::FaceUnlock => "face_unlock",
            BiometricType::Iris => "iris",
        }
    }
}

/// Challenge for biometric authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricChallenge {
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
}

impl BiometricChallenge {
    /// Create a new challenge with default 5-minute expiry
    pub fn new() -> Self {
        Self {
            challenge: generate_secure_random(32),
            expires_at: Utc::now() + Duration::minutes(5),
        }
    }

    /// Create a new challenge with custom expiry
    pub fn with_expiry(minutes: i64) -> Self {
        Self {
            challenge: generate_secure_random(32),
            expires_at: Utc::now() + Duration::minutes(minutes),
        }
    }

    /// Check if challenge has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Verify that a provided challenge matches
    pub fn verify(&self, challenge: &str) -> bool {
        crate::crypto::secure_compare(self.challenge.as_bytes(), challenge.as_bytes())
    }
}

impl Default for BiometricChallenge {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during biometric authentication
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BiometricError {
    /// Key not found
    KeyNotFound,
    /// Invalid public key format
    InvalidPublicKey,
    /// Invalid signature
    InvalidSignature,
    /// Challenge expired
    ChallengeExpired,
    /// Challenge not found
    ChallengeNotFound,
    /// Invalid challenge response
    InvalidChallenge,
    /// Key already exists
    KeyAlreadyExists,
    /// Rate limit exceeded
    RateLimited,
    /// Database error
    DatabaseError(String),
    /// Internal error
    Internal(String),
}

impl fmt::Display for BiometricError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BiometricError::KeyNotFound => write!(f, "Biometric key not found"),
            BiometricError::InvalidPublicKey => write!(f, "Invalid public key format"),
            BiometricError::InvalidSignature => write!(f, "Invalid signature"),
            BiometricError::ChallengeExpired => write!(f, "Challenge has expired"),
            BiometricError::ChallengeNotFound => write!(f, "Challenge not found"),
            BiometricError::InvalidChallenge => write!(f, "Invalid challenge response"),
            BiometricError::KeyAlreadyExists => write!(f, "Biometric key already exists"),
            BiometricError::RateLimited => write!(f, "Rate limit exceeded"),
            BiometricError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            BiometricError::Internal(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl std::error::Error for BiometricError {}

impl From<sqlx::Error> for BiometricError {
    fn from(err: sqlx::Error) -> Self {
        BiometricError::DatabaseError(err.to_string())
    }
}

impl From<VaultError> for BiometricError {
    fn from(err: VaultError) -> Self {
        BiometricError::Internal(err.to_string())
    }
}

impl From<BiometricError> for VaultError {
    fn from(err: BiometricError) -> Self {
        match err {
            BiometricError::KeyNotFound => VaultError::not_found("BiometricKey", "unknown"),
            BiometricError::InvalidPublicKey | BiometricError::InvalidSignature => {
                VaultError::authentication("Biometric verification failed")
            }
            BiometricError::ChallengeExpired => VaultError::authentication("Challenge expired"),
            BiometricError::ChallengeNotFound => {
                VaultError::authentication("Challenge not found")
            }
            BiometricError::InvalidChallenge => {
                VaultError::authentication("Invalid challenge response")
            }
            BiometricError::KeyAlreadyExists => {
                VaultError::conflict("Biometric key already exists")
            }
            BiometricError::RateLimited => VaultError::rate_limit(60),
            BiometricError::DatabaseError(msg) => VaultError::database(msg),
            BiometricError::Internal(msg) => VaultError::internal(msg),
        }
    }
}

/// Trait for biometric key storage
#[async_trait::async_trait]
pub trait BiometricKeyStore: Send + Sync {
    /// Store a new biometric key
    async fn store_key(&self, key: &BiometricKey) -> std::result::Result<(), BiometricError>;

    /// Get a biometric key by its key_id
    async fn get_key_by_key_id(&self, key_id: &str) -> std::result::Result<Option<BiometricKey>, BiometricError>;

    /// Get all biometric keys for a user
    async fn get_keys_for_user(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> std::result::Result<Vec<BiometricKey>, BiometricError>;

    /// Delete a biometric key
    async fn delete_key(&self, key_id: &str) -> std::result::Result<(), BiometricError>;

    /// Update last used timestamp
    async fn update_last_used(&self, key_id: &str) -> std::result::Result<(), BiometricError>;
}

/// Trait for challenge storage
#[async_trait::async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Store a challenge
    async fn store_challenge(
        &self,
        key_id: &str,
        challenge: &BiometricChallenge,
    ) -> std::result::Result<(), BiometricError>;

    /// Get and remove a challenge
    async fn get_challenge(&self, key_id: &str) -> std::result::Result<Option<BiometricChallenge>, BiometricError>;

    /// Clean up expired challenges
    async fn cleanup_expired(&self) -> std::result::Result<u64, BiometricError>;
}

/// Request to register a biometric key
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterBiometricKeyRequest {
    pub user_id: String,
    pub tenant_id: String,
    pub public_key: Vec<u8>,
    pub key_id: String,
    pub device_name: String,
    pub biometric_type: BiometricType,
}

/// Response after successful biometric authentication
#[derive(Debug, Clone, Serialize)]
pub struct BiometricAuthSuccess {
    pub user_id: String,
    pub tenant_id: String,
    pub key_id: String,
    pub biometric_type: BiometricType,
}

/// Verify an ECDSA P-256 signature
pub fn verify_ecdsa_signature(
    public_key_bytes: &[u8],
    message: &[u8],
    signature_bytes: &[u8],
) -> Result<bool, BiometricError> {
    // Parse the verifying key
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .map_err(|_| BiometricError::InvalidPublicKey)?;

    // Parse the signature
    let signature = Signature::from_der(signature_bytes)
        .map_err(|_| BiometricError::InvalidSignature)?;

    // Verify the signature
    match verifying_key.verify(message, &signature) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate a new ECDSA P-256 key pair for testing
#[cfg(test)]
pub fn generate_test_keypair() -> (SigningKey, VerifyingKey) {
    use rand::rngs::OsRng;
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    (signing_key, verifying_key)
}

/// Sign a message with ECDSA P-256 for testing
#[cfg(test)]
pub fn sign_with_key(signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer;
    let signature: Signature = signing_key.sign(message);
    signature.to_der().to_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometric_challenge_creation() {
        let challenge = BiometricChallenge::new();
        assert!(!challenge.challenge.is_empty());
        assert!(!challenge.is_expired());
    }

    #[test]
    fn test_biometric_challenge_expiry() {
        let challenge = BiometricChallenge {
            challenge: "test".to_string(),
            expires_at: Utc::now() - Duration::minutes(1),
        };
        assert!(challenge.is_expired());
    }

    #[test]
    fn test_biometric_challenge_verification() {
        let challenge = BiometricChallenge::new();
        assert!(challenge.verify(&challenge.challenge));
        assert!(!challenge.verify("wrong_challenge"));
    }

    #[test]
    fn test_ecdsa_signature_verification() {
        let (signing_key, verifying_key) = generate_test_keypair();
        let message = b"test message";
        let signature = sign_with_key(&signing_key, message);

        let public_key_bytes = verifying_key.to_sec1_bytes();

        // Valid signature should verify
        assert!(verify_ecdsa_signature(&public_key_bytes, message, &signature).unwrap());

        // Wrong message should fail
        assert!(
            !verify_ecdsa_signature(&public_key_bytes, b"wrong message", &signature).unwrap()
        );
    }

    #[test]
    fn test_biometric_type_display() {
        assert_eq!(BiometricType::FaceId.to_string(), "Face ID");
        assert_eq!(BiometricType::TouchId.to_string(), "Touch ID");
        assert_eq!(BiometricType::Fingerprint.to_string(), "Fingerprint");
        assert_eq!(BiometricType::FaceUnlock.to_string(), "Face Unlock");
        assert_eq!(BiometricType::Iris.to_string(), "Iris");
    }

    #[test]
    fn test_biometric_type_as_str() {
        assert_eq!(BiometricType::FaceId.as_str(), "face_id");
        assert_eq!(BiometricType::TouchId.as_str(), "touch_id");
        assert_eq!(BiometricType::Fingerprint.as_str(), "fingerprint");
        assert_eq!(BiometricType::FaceUnlock.as_str(), "face_unlock");
        assert_eq!(BiometricType::Iris.as_str(), "iris");
    }
}
