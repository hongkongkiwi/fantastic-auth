//! Zero-Knowledge Architecture Module
//!
//! This module implements a true zero-knowledge architecture where the server
//! cannot read user data even if compromised. All encryption happens client-side,
//! and the server only stores encrypted blobs.
//!
//! ## Security Properties
//!
//! - **Server compromise**: Attacker gets encrypted data, cannot decrypt without user passwords
//! - **Database leak**: Encrypted blobs are useless without keys
//! - **Insider threat**: Employees cannot read user data
//! - **Legal requests**: Cannot provide plaintext data (don't have keys)
//!
//! ## Architecture
//!
//! ```text
//! Client-side:
//! 1. User enters password
//! 2. Derive master key from password + salt (Argon2id)
//! 3. Generate RSA key pair from master key material
//! 4. Encrypt data with AES-256-GCM using data encryption key (DEK)
//! 5. Wrap DEK with RSA public key
//! 6. Send encrypted data + wrapped DEK to server
//!
//! Server-side:
//! - Stores: salt, RSA public key, encrypted private key, encrypted data, wrapped DEK
//! - Never sees: password, master key, plaintext data, DEK
//! ```

pub mod encryption;
pub mod key_derivation;
pub mod proofs;
pub mod recovery;
pub mod secure_computation;

pub use encryption::{
    decrypt_user_data, encrypt_user_data, AesGcmEncryption, DataEncryptionKey, EncryptedUserData,
    WrappedDek,
};
pub use key_derivation::MasterKey;
pub use key_derivation::{
    derive_master_key_from_password, generate_salt, Argon2Params, MasterKeyDerivation,
};
pub use proofs::{verify_password_proof, ZkPasswordProof, ZkProofError};
pub use recovery::{RecoveryShare, ShareMetadata, SocialRecovery};
pub use secure_computation::{
    verify_age_eligibility, EncryptedComparable, HomomorphicCiphertext, SecureComputation,
};

use crate::error::{Result, VaultError};
use serde::{Deserialize, Serialize};

/// Zero-knowledge error type
#[derive(Debug, thiserror::Error)]
pub enum ZkError {
    /// Encryption/decryption error
    #[error("ZK encryption error: {0}")]
    Encryption(String),

    /// Key derivation error
    #[error("ZK key derivation error: {0}")]
    KeyDerivation(String),

    /// Proof generation/verification error
    #[error("ZK proof error: {0}")]
    Proof(String),

    /// Recovery error
    #[error("ZK recovery error: {0}")]
    Recovery(String),

    /// Invalid parameters
    #[error("ZK invalid parameters: {0}")]
    InvalidParams(String),

    /// Serialization error
    #[error("ZK serialization error: {0}")]
    Serialization(String),
}

impl From<ZkError> for VaultError {
    fn from(err: ZkError) -> Self {
        VaultError::crypto(err.to_string())
    }
}

/// Version of the ZK protocol (for future upgrades)
pub const ZK_PROTOCOL_VERSION: u32 = 1;

/// Zero-knowledge user registration data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkRegistrationData {
    /// Protocol version
    pub version: u32,
    /// Random salt for key derivation
    pub salt: Vec<u8>,
    /// RSA public key (for wrapping DEKs)
    pub public_key: Vec<u8>,
    /// RSA private key encrypted with master key
    pub encrypted_private_key: Vec<u8>,
    /// ZK proof commitment (password verification)
    pub zk_commitment: [u8; 32],
    /// Recovery shares hash (for verification)
    pub recovery_shares_hash: Option<[u8; 32]>,
}

/// Zero-knowledge authentication data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkAuthenticationData {
    /// Protocol version
    pub version: u32,
    /// ZK proof of password knowledge
    pub proof: ZkPasswordProof,
    /// Challenge nonce (prevent replay)
    pub challenge: [u8; 32],
}

/// Zero-knowledge key bundle (stored on server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkKeyBundle {
    /// User ID
    pub user_id: String,
    /// Salt for key derivation
    pub salt: Vec<u8>,
    /// RSA public key
    pub public_key: Vec<u8>,
    /// Encrypted RSA private key (server cannot decrypt)
    pub encrypted_private_key: Vec<u8>,
    /// ZK proof commitment for password verification
    pub zk_commitment: [u8; 32],
    /// Key creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last rotation timestamp
    pub rotated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ZkKeyBundle {
    /// Create a new key bundle
    pub fn new(
        user_id: impl Into<String>,
        salt: Vec<u8>,
        public_key: Vec<u8>,
        encrypted_private_key: Vec<u8>,
        zk_commitment: [u8; 32],
    ) -> Self {
        Self {
            user_id: user_id.into(),
            salt,
            public_key,
            encrypted_private_key,
            zk_commitment,
            created_at: chrono::Utc::now(),
            rotated_at: None,
        }
    }
}

/// Initialize the zero-knowledge module
pub fn init() {
    tracing::info!("Zero-knowledge module initialized (protocol v{})", ZK_PROTOCOL_VERSION);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_error_conversion() {
        let zk_err = ZkError::Encryption("test".to_string());
        let vault_err: VaultError = zk_err.into();
        assert!(matches!(vault_err, VaultError::Crypto(_)));
    }

    #[test]
    fn test_key_bundle_creation() {
        let bundle = ZkKeyBundle::new(
            "user_123",
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
            [0u8; 32],
        );
        assert_eq!(bundle.user_id, "user_123");
        assert!(bundle.rotated_at.is_none());
    }
}
