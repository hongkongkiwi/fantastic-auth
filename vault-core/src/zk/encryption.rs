//! Client-Side Encryption for Zero-Knowledge Architecture
//!
//! This module implements the client-side encryption that ensures the server
//! never sees plaintext user data. Data is encrypted in the browser/app before
//! being sent to the server.
//!
//! ## Encryption Scheme
//!
//! ```text
//! User Data
//!     |
//!     v
//! Generate Data Encryption Key (DEK) - random 32 bytes
//!     |
//!     v
//! Encrypt data with AES-256-GCM using DEK
//!     |
//!     +--> Ciphertext
//!     +--> Nonce (12 bytes)
//!     |
//!     v
//! Wrap DEK with RSA public key (OAEP-SHA256)
//!     |
//!     +--> Encrypted DEK
//! ```
//!
//! ## Storage Format
//!
//! Server stores:
//! - `encrypted_data`: AES-256-GCM ciphertext
//! - `data_nonce`: 12-byte nonce
//! - `encrypted_dek`: RSA-OAEP wrapped DEK
//!
//! Client needs:
//! - Master key (derived from password) to unwrap RSA private key
//! - RSA private key to unwrap DEK
//! - DEK to decrypt data

use crate::crypto::generate_random_bytes;
use crate::models::user::UserProfile;
use crate::zk::key_derivation::MasterKey;
use crate::zk::ZkError;
use rand::RngCore;
use rsa::{pkcs8::DecodePrivateKey, sha2::Sha256, Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

/// AES-256-GCM nonce size (12 bytes = 96 bits)
pub const NONCE_SIZE: usize = 12;

/// AES-256-GCM tag size (16 bytes = 128 bits)
pub const TAG_SIZE: usize = 16;

/// Data Encryption Key (DEK) - 256 bits
pub type DataEncryptionKey = [u8; 32];

/// Wrapped (encrypted) DEK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedDek {
    /// RSA-OAEP encrypted DEK
    pub ciphertext: Vec<u8>,
}

/// Encrypted user data with all necessary metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedUserData {
    /// Protocol version
    pub version: u32,
    /// AES-256-GCM ciphertext
    pub ciphertext: Vec<u8>,
    /// Nonce (12 bytes)
    pub nonce: [u8; NONCE_SIZE],
    /// RSA-OAEP wrapped data encryption key
    pub encrypted_dek: WrappedDek,
    /// Timestamp of encryption
    pub encrypted_at: chrono::DateTime<chrono::Utc>,
}

impl EncryptedUserData {
    /// Create new encrypted user data
    pub fn new(ciphertext: Vec<u8>, nonce: [u8; NONCE_SIZE], encrypted_dek: WrappedDek) -> Self {
        Self {
            version: super::ZK_PROTOCOL_VERSION,
            ciphertext,
            nonce,
            encrypted_dek,
            encrypted_at: chrono::Utc::now(),
        }
    }

    /// Serialize to JSON bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, ZkError> {
        serde_json::to_vec(self)
            .map_err(|e| ZkError::Serialization(format!("Failed to serialize: {}", e)))
    }

    /// Deserialize from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        serde_json::from_slice(bytes)
            .map_err(|e| ZkError::Serialization(format!("Failed to deserialize: {}", e)))
    }
}

/// AES-256-GCM encryption helper
pub struct AesGcmEncryption;

impl AesGcmEncryption {
    /// Encrypt plaintext using AES-256-GCM
    pub fn encrypt(
        key: &DataEncryptionKey,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), ZkError> {
        use ring::aead::{
            Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM,
        };

        // Generate random nonce
        let nonce_bytes: [u8; NONCE_SIZE] = generate_random_bytes(NONCE_SIZE)
            .try_into()
            .map_err(|_| ZkError::Encryption("Failed to generate nonce".to_string()))?;

        struct OneNonce([u8; NONCE_SIZE]);
        impl NonceSequence for OneNonce {
            fn advance(&mut self) -> std::result::Result<Nonce, ring::error::Unspecified> {
                Nonce::try_assume_unique_for_key(&self.0)
            }
        }

        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| ZkError::Encryption("Invalid key".to_string()))?;
        let mut sealing_key = SealingKey::new(unbound_key, OneNonce(nonce_bytes));

        let mut ciphertext = plaintext.to_vec();
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut ciphertext)
            .map_err(|_| ZkError::Encryption("Encryption failed".to_string()))?;

        // Append tag to ciphertext
        ciphertext.extend_from_slice(tag.as_ref());

        Ok((ciphertext, nonce_bytes))
    }

    /// Decrypt ciphertext using AES-256-GCM
    pub fn decrypt(
        key: &DataEncryptionKey,
        ciphertext: &[u8],
        nonce: &[u8; NONCE_SIZE],
    ) -> Result<Vec<u8>, ZkError> {
        use ring::aead::{
            Aad, BoundKey, Nonce, NonceSequence, OpeningKey, UnboundKey, AES_256_GCM,
        };

        if ciphertext.len() < TAG_SIZE {
            return Err(ZkError::Encryption("Ciphertext too short".to_string()));
        }

        struct OneNonce([u8; NONCE_SIZE]);
        impl NonceSequence for OneNonce {
            fn advance(&mut self) -> std::result::Result<Nonce, ring::error::Unspecified> {
                Nonce::try_assume_unique_for_key(&self.0)
            }
        }

        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| ZkError::Encryption("Invalid key".to_string()))?;
        let mut opening_key = OpeningKey::new(unbound_key, OneNonce(*nonce));

        let mut in_out = ciphertext.to_vec();

        let plaintext = opening_key
            .open_in_place(Aad::empty(), &mut in_out)
            .map_err(|_| {
                ZkError::Encryption("Decryption failed - invalid key or corrupted data".to_string())
            })?;

        Ok(plaintext.to_vec())
    }
}

/// Generate a random Data Encryption Key
///
/// SECURITY: Uses OsRng (operating system's CSPRNG) for generating DEKs.
/// Data Encryption Keys are used to encrypt sensitive data and must be
/// cryptographically secure to maintain data confidentiality.
pub fn generate_dek() -> DataEncryptionKey {
    use rand::RngCore;
    use rand_core::OsRng;

    let mut dek = [0u8; 32];
    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    OsRng.fill_bytes(&mut dek);
    dek
}

/// Wrap DEK with RSA public key using OAEP-SHA256
///
/// SECURITY: Uses OsRng (operating system's CSPRNG) for RSA-OAEP encryption.
/// OAEP requires random padding for semantic security - using a predictable
/// RNG would compromise the encryption's security.
pub fn wrap_dek(dek: &DataEncryptionKey, public_key: &RsaPublicKey) -> Result<WrappedDek, ZkError> {
    use rand::RngCore;

    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    let mut rng = rand_core::OsRng;
    let padding = Oaep::new::<Sha256>();

    let ciphertext = public_key
        .encrypt(&mut rng, padding, dek)
        .map_err(|e| ZkError::Encryption(format!("DEK wrapping failed: {}", e)))?;

    Ok(WrappedDek { ciphertext })
}

/// Unwrap DEK with RSA private key using OAEP-SHA256
pub fn unwrap_dek(
    wrapped_dek: &WrappedDek,
    private_key: &RsaPrivateKey,
) -> Result<DataEncryptionKey, ZkError> {
    let padding = Oaep::new::<Sha256>();

    let plaintext = private_key
        .decrypt(padding, &wrapped_dek.ciphertext)
        .map_err(|e| ZkError::Encryption(format!("DEK unwrapping failed: {}", e)))?;

    if plaintext.len() != 32 {
        return Err(ZkError::Encryption("Invalid DEK length".to_string()));
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&plaintext);
    Ok(dek)
}

/// Encrypt user data client-side
pub fn encrypt_user_data(
    profile: &UserProfile,
    master_key: &MasterKey,
) -> Result<EncryptedUserData, ZkError> {
    // Serialize user profile
    let plaintext = serde_json::to_vec(profile)
        .map_err(|e| ZkError::Serialization(format!("Failed to serialize profile: {}", e)))?;

    // Generate random DEK
    let dek = generate_dek();

    // Encrypt data with DEK
    let (ciphertext, nonce) = AesGcmEncryption::encrypt(&dek, &plaintext)?;

    // Wrap DEK with RSA public key
    let encrypted_dek = wrap_dek(&dek, &master_key.rsa_public_key)?;

    Ok(EncryptedUserData::new(ciphertext, nonce, encrypted_dek))
}

/// Decrypt user data client-side
pub fn decrypt_user_data(
    encrypted_data: &EncryptedUserData,
    master_key: &MasterKey,
) -> Result<UserProfile, ZkError> {
    // Unwrap DEK
    let dek = unwrap_dek(&encrypted_data.encrypted_dek, &master_key.rsa_private_key)?;

    // Decrypt data
    let plaintext =
        AesGcmEncryption::decrypt(&dek, &encrypted_data.ciphertext, &encrypted_data.nonce)?;

    // Deserialize
    serde_json::from_slice(&plaintext)
        .map_err(|e| ZkError::Serialization(format!("Failed to deserialize profile: {}", e)))
}

/// Encrypt data with master key (convenience method)
pub fn encrypt_with_master_key(
    data: &[u8],
    master_key: &MasterKey,
) -> Result<EncryptedUserData, ZkError> {
    // Generate random DEK
    let dek = generate_dek();

    // Encrypt data with DEK
    let (ciphertext, nonce) = AesGcmEncryption::encrypt(&dek, data)?;

    // Wrap DEK with RSA public key
    let encrypted_dek = wrap_dek(&dek, &master_key.rsa_public_key)?;

    Ok(EncryptedUserData::new(ciphertext, nonce, encrypted_dek))
}

/// Decrypt data with master key (convenience method)
pub fn decrypt_with_master_key(
    encrypted_data: &EncryptedUserData,
    master_key: &MasterKey,
) -> Result<Vec<u8>, ZkError> {
    // Unwrap DEK
    let dek = unwrap_dek(&encrypted_data.encrypted_dek, &master_key.rsa_private_key)?;

    // Decrypt data
    AesGcmEncryption::decrypt(&dek, &encrypted_data.ciphertext, &encrypted_data.nonce)
}

/// Encrypt RSA private key for server storage
pub fn encrypt_private_key_for_storage(
    private_key: &RsaPrivateKey,
    encryption_key: &[u8; 32],
) -> Result<Vec<u8>, ZkError> {
    use crate::crypto::encrypt_to_base64;
    use rsa::pkcs8::EncodePrivateKey;

    let pk_der = private_key
        .to_pkcs8_der()
        .map_err(|e| ZkError::Encryption(format!("Failed to serialize private key: {}", e)))?;

    let encrypted = encrypt_to_base64(encryption_key, pk_der.as_bytes())
        .map_err(|e| ZkError::Encryption(format!("Failed to encrypt private key: {}", e)))?;

    Ok(encrypted.into_bytes())
}

/// Decrypt RSA private key from server storage
pub fn decrypt_private_key_from_storage(
    encrypted_key: &[u8],
    encryption_key: &[u8; 32],
) -> Result<RsaPrivateKey, ZkError> {
    use crate::crypto::decrypt_from_base64;

    let encrypted_str = String::from_utf8(encrypted_key.to_vec())
        .map_err(|e| ZkError::Encryption(format!("Invalid encrypted key format: {}", e)))?;

    let pk_der = decrypt_from_base64(encryption_key, &encrypted_str)
        .map_err(|e| ZkError::Encryption(format!("Failed to decrypt private key: {}", e)))?;

    RsaPrivateKey::from_pkcs8_der(&pk_der)
        .map_err(|e| ZkError::Encryption(format!("Failed to parse private key: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::user::Address;
    use crate::zk::key_derivation::{derive_master_key_from_password, generate_salt};

    fn create_test_master_key() -> MasterKey {
        let password = "test_password";
        let salt = generate_salt();
        derive_master_key_from_password(password, &salt, None).unwrap()
    }

    #[test]
    fn test_generate_dek() {
        let dek1 = generate_dek();
        let dek2 = generate_dek();
        assert_ne!(dek1, dek2); // Should be random
    }

    #[test]
    fn test_aes_gcm_encryption() {
        let key = generate_dek();
        let plaintext = b"Hello, zero-knowledge world!";

        let (ciphertext, nonce) = AesGcmEncryption::encrypt(&key, plaintext).unwrap();
        assert!(!ciphertext.is_empty());

        let decrypted = AesGcmEncryption::decrypt(&key, &ciphertext, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_gcm_wrong_key() {
        let key1 = generate_dek();
        let key2 = generate_dek();
        let plaintext = b"Secret data";

        let (ciphertext, nonce) = AesGcmEncryption::encrypt(&key1, plaintext).unwrap();

        // Decrypt with wrong key should fail
        let result = AesGcmEncryption::decrypt(&key2, &ciphertext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_unwrap_dek() {
        let master_key = create_test_master_key();
        let dek = generate_dek();

        // Wrap DEK with public key
        let wrapped = wrap_dek(&dek, &master_key.rsa_public_key).unwrap();

        // Unwrap with private key
        let unwrapped = unwrap_dek(&wrapped, &master_key.rsa_private_key).unwrap();

        assert_eq!(dek, unwrapped);
    }

    #[test]
    fn test_encrypt_decrypt_user_profile() {
        let master_key = create_test_master_key();

        let profile = UserProfile {
            name: Some("John Doe".to_string()),
            given_name: Some("John".to_string()),
            family_name: Some("Doe".to_string()),
            email: Some("john@example.com".to_string()),
            phone_number: Some("+1234567890".to_string()),
            address: Some(Address {
                formatted: Some("123 Main St".to_string()),
                street_address: Some("123 Main St".to_string()),
                locality: Some("Boston".to_string()),
                region: Some("MA".to_string()),
                postal_code: Some("02101".to_string()),
                country: Some("US".to_string()),
            }),
            ..Default::default()
        };

        // Encrypt
        let encrypted = encrypt_user_data(&profile, &master_key).unwrap();

        // Decrypt
        let decrypted = decrypt_user_data(&encrypted, &master_key).unwrap();

        assert_eq!(decrypted.name, profile.name);
        assert_eq!(decrypted.email, profile.email);
        assert_eq!(decrypted.phone_number, profile.phone_number);
    }

    #[test]
    fn test_encrypt_decrypt_with_different_master_key() {
        let master_key1 = create_test_master_key();
        let master_key2 = create_test_master_key();

        let profile = UserProfile {
            name: Some("John Doe".to_string()),
            ..Default::default()
        };

        let encrypted = encrypt_user_data(&profile, &master_key1).unwrap();

        // Decrypt with different key should fail
        let result = decrypt_user_data(&encrypted, &master_key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypted_data_serialization() {
        let master_key = create_test_master_key();

        let profile = UserProfile {
            name: Some("Test User".to_string()),
            ..Default::default()
        };

        let encrypted = encrypt_user_data(&profile, &master_key).unwrap();

        // Serialize
        let bytes = encrypted.to_bytes().unwrap();

        // Deserialize
        let restored = EncryptedUserData::from_bytes(&bytes).unwrap();

        // Verify decryption still works
        let decrypted = decrypt_user_data(&restored, &master_key).unwrap();
        assert_eq!(decrypted.name, profile.name);
    }

    #[test]
    fn test_private_key_storage_encryption() {
        let master_key = create_test_master_key();

        // Encrypt private key
        let encrypted = encrypt_private_key_for_storage(
            &master_key.rsa_private_key,
            &master_key.encryption_key,
        )
        .unwrap();

        // Decrypt private key
        let decrypted =
            decrypt_private_key_from_storage(&encrypted, &master_key.encryption_key).unwrap();

        // Verify it's the same key
        let original_der = master_key.rsa_private_key_to_der().unwrap();
        let decrypted_der = decrypted
            .to_pkcs8_der()
            .map_err(|e| ZkError::Encryption(e.to_string()))
            .unwrap()
            .as_bytes()
            .to_vec();

        assert_eq!(original_der, decrypted_der);
    }

    #[test]
    fn test_encrypt_decrypt_bytes() {
        let master_key = create_test_master_key();
        let data = b"Some arbitrary binary data".to_vec();

        // Encrypt
        let encrypted = encrypt_with_master_key(&data, &master_key).unwrap();

        // Decrypt
        let decrypted = decrypt_with_master_key(&encrypted, &master_key).unwrap();

        assert_eq!(data, decrypted);
    }
}
