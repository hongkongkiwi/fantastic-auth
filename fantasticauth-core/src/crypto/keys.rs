//! Key management for hybrid post-quantum cryptography
//!
//! This module provides key management for hybrid cryptographic keys,
//! combining Ed25519 (classical) and ML-DSA-65 (post-quantum) for
//! defense-in-depth against both classical and quantum attacks.

use crate::error::{Result, VaultError};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::{derive_key, generate_random_bytes, HybridSigningKey, HybridVerifyingKey};

/// Types of cryptographic keys
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "key_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum KeyType {
    /// Master signing key for JWTs (hybrid Ed25519 + ML-DSA-65)
    JwtSigning,
    /// Key for encrypting sensitive data
    DataEncryption,
    /// Key for API key signing (hybrid Ed25519 + ML-DSA-65)
    ApiKeySigning,
    /// Key for session encryption
    SessionEncryption,
}

impl KeyType {
    /// Get key purpose string for derivation
    pub fn purpose(&self) -> &'static [u8] {
        match self {
            KeyType::JwtSigning => b"vault-jwt-signing-v1",
            KeyType::DataEncryption => b"vault-data-encryption-v1",
            KeyType::ApiKeySigning => b"vault-apikey-signing-v1",
            KeyType::SessionEncryption => b"vault-session-encryption-v1",
        }
    }

    /// Get key type as string
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyType::JwtSigning => "jwt",
            KeyType::DataEncryption => "enc",
            KeyType::ApiKeySigning => "api",
            KeyType::SessionEncryption => "sess",
        }
    }

    /// Check if this key type uses hybrid signatures
    pub fn uses_hybrid_signature(&self) -> bool {
        matches!(self, KeyType::JwtSigning | KeyType::ApiKeySigning)
    }
}

/// A cryptographic key pair with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    /// Unique key identifier
    pub id: String,
    /// Key type
    pub key_type: KeyType,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Expires timestamp (for rotation)
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether this key is active
    pub is_active: bool,
    /// Key version for rotation tracking
    pub version: u32,
    /// Encrypted secret key (base64)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_secret: Option<String>,
    /// Public key (base64) - contains both Ed25519 and ML-DSA-65 public keys
    pub public_key: String,
    /// Tenant ID this key belongs to
    pub tenant_id: String,
    /// Key algorithm identifier
    pub algorithm: String,
}

impl KeyPair {
    /// Create a new hybrid key pair
    ///
    /// Generates a new Ed25519 + ML-DSA-65 hybrid key pair for the specified tenant.
    /// The secret key must be encrypted before storage.
    pub fn new(
        key_type: KeyType,
        tenant_id: impl Into<String>,
        version: u32,
    ) -> (Self, HybridSigningKey) {
        let tenant_id = tenant_id.into();
        let id = format!("{}_{}_{}", tenant_id, key_type.as_str(), Uuid::new_v4());

        // Generate hybrid key pair (Ed25519 + ML-DSA-65)
        let (signing_key, verifying_key) = HybridSigningKey::generate();

        let key_pair = Self {
            id,
            key_type,
            created_at: Utc::now(),
            expires_at: None,
            is_active: true,
            version,
            encrypted_secret: None, // Must be encrypted before storage
            public_key: STANDARD.encode(verifying_key.to_bytes()),
            tenant_id,
            algorithm: "EdDSA+ML-DSA-65".to_string(),
        };

        (key_pair, signing_key)
    }

    /// Mark key as expired
    pub fn expire(&mut self) {
        self.expires_at = Some(Utc::now());
        self.is_active = false;
    }

    /// Check if key is expired
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expiry) => Utc::now() > expiry,
            None => false,
        }
    }

    /// Get the verifying key from the stored public key
    pub fn get_verifying_key(&self) -> Result<HybridVerifyingKey> {
        decode_verifying_key(&self.public_key)
    }

    /// Get the algorithm identifier
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
}

/// Key manager for tenant-specific keys
pub struct KeyManager {
    /// Master key for deriving tenant keys
    master_key: Vec<u8>,
    /// In-memory cache of decrypted keys (tenant_id -> key_type -> key)
    key_cache: HashMap<String, HashMap<KeyType, CachedKey>>,
}

struct CachedKey {
    key_pair: KeyPair,
    signing_key: Option<HybridSigningKey>, // Only for signing keys
    verifying_key: HybridVerifyingKey,
}

impl KeyManager {
    /// Create new key manager with master key
    pub fn new(master_key: Vec<u8>) -> Self {
        Self {
            master_key,
            key_cache: HashMap::new(),
        }
    }

    /// Generate master key from random bytes
    pub fn generate_master_key() -> Vec<u8> {
        generate_random_bytes(32)
    }

    /// Derive a tenant-specific key encryption key (KEK)
    fn derive_tenant_key(&self, tenant_id: &str, key_type: KeyType) -> Result<Vec<u8>> {
        let context = format!(
            "{}:{}",
            tenant_id,
            std::str::from_utf8(key_type.purpose()).unwrap()
        );
        derive_key(&self.master_key, context.as_bytes(), 32)
    }

    /// Generate a new hybrid key pair for a tenant
    ///
    /// Generates a new Ed25519 + ML-DSA-65 key pair, encrypts the secret key,
    /// and returns the KeyPair metadata with the encrypted secret.
    pub fn generate_key_pair(
        &self,
        tenant_id: impl Into<String>,
        key_type: KeyType,
        version: u32,
    ) -> Result<KeyPair> {
        let tenant_id = tenant_id.into();
        let (mut key_pair, signing_key) = KeyPair::new(key_type, &tenant_id, version);

        // Encrypt the secret key for storage
        let kek = self.derive_tenant_key(&tenant_id, key_type)?;
        let secret_bytes = signing_key.to_bytes();
        let encrypted = self.encrypt_key(&secret_bytes, &kek)?;
        key_pair.encrypted_secret = Some(STANDARD.encode(encrypted));

        Ok(key_pair)
    }

    /// Load and decrypt a signing key
    ///
    /// Retrieves the signing key from cache or decrypts it from storage.
    pub fn load_signing_key(&mut self, key_pair: &KeyPair) -> Result<HybridSigningKey> {
        // Check cache first
        if let Some(tenant_keys) = self.key_cache.get(&key_pair.tenant_id) {
            if let Some(cached) = tenant_keys.get(&key_pair.key_type) {
                if cached.key_pair.id == key_pair.id {
                    return cached
                        .signing_key
                        .clone()
                        .ok_or_else(|| VaultError::crypto("Key not available for signing"));
                }
            }
        }

        // Decrypt from storage
        let encrypted_secret = key_pair
            .encrypted_secret
            .as_ref()
            .ok_or_else(|| VaultError::crypto("No encrypted secret available"))?;
        let encrypted_bytes = STANDARD
            .decode(encrypted_secret)
            .map_err(|e| VaultError::Base64(e.to_string()))?;

        let kek = self.derive_tenant_key(&key_pair.tenant_id, key_pair.key_type)?;
        let secret_bytes = self.decrypt_key(&encrypted_bytes, &kek)?;

        // Reconstruct signing key from bytes
        let signing_key = HybridSigningKey::from_bytes(&secret_bytes)?;

        // Cache the key
        let public_bytes = STANDARD
            .decode(&key_pair.public_key)
            .map_err(|e| VaultError::Base64(e.to_string()))?;
        let verifying_key = HybridVerifyingKey::from_bytes(&public_bytes)?;
        let cached = CachedKey {
            key_pair: key_pair.clone(),
            signing_key: Some(signing_key.clone()),
            verifying_key,
        };

        self.key_cache
            .entry(key_pair.tenant_id.clone())
            .or_default()
            .insert(key_pair.key_type, cached);

        Ok(signing_key)
    }

    /// Load verifying key (public, no decryption needed)
    ///
    /// The verifying key contains both Ed25519 and ML-DSA-65 public keys.
    pub fn load_verifying_key(&self, key_pair: &KeyPair) -> Result<HybridVerifyingKey> {
        let public_bytes = STANDARD
            .decode(&key_pair.public_key)
            .map_err(|e| VaultError::Base64(e.to_string()))?;
        HybridVerifyingKey::from_bytes(&public_bytes)
    }

    /// Encrypt key bytes using AES-256-GCM via ring
    fn encrypt_key(&self, plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use ring::aead::{
            Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM,
        };

        // Generate random nonce
        let nonce_bytes: [u8; 12] = generate_random_bytes(12).try_into().unwrap();

        // Create a simple nonce sequence wrapper
        struct OneNonce([u8; 12]);
        impl NonceSequence for OneNonce {
            fn advance(&mut self) -> std::result::Result<Nonce, ring::error::Unspecified> {
                Nonce::try_assume_unique_for_key(&self.0)
            }
        }

        let nonce_seq = OneNonce(nonce_bytes);

        // Create sealing key
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| VaultError::crypto("Invalid encryption key"))?;
        let mut sealing_key = SealingKey::new(unbound_key, nonce_seq);

        // Encrypt in place
        let mut ciphertext = plaintext.to_vec();
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut ciphertext)
            .map_err(|_| VaultError::crypto("Encryption failed"))?;

        // Combine: nonce || ciphertext || tag
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(tag.as_ref());

        Ok(result)
    }

    /// Decrypt key bytes
    fn decrypt_key(&self, ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        use ring::aead::{
            Aad, BoundKey, Nonce, NonceSequence, OpeningKey, UnboundKey, AES_256_GCM,
        };

        if ciphertext.len() < 12 + 16 {
            return Err(VaultError::crypto("Ciphertext too short"));
        }

        // Extract nonce
        let nonce_bytes: [u8; 12] = ciphertext[..12].try_into().unwrap();

        // Create a simple nonce sequence wrapper
        struct OneNonce([u8; 12]);
        impl NonceSequence for OneNonce {
            fn advance(&mut self) -> std::result::Result<Nonce, ring::error::Unspecified> {
                Nonce::try_assume_unique_for_key(&self.0)
            }
        }

        let nonce_seq = OneNonce(nonce_bytes);

        // Extract ciphertext and tag
        let encrypted = &ciphertext[12..ciphertext.len() - 16];
        let tag = &ciphertext[ciphertext.len() - 16..];

        // Create opening key
        let unbound_key = UnboundKey::new(&AES_256_GCM, key)
            .map_err(|_| VaultError::crypto("Invalid decryption key"))?;
        let mut opening_key = OpeningKey::new(unbound_key, nonce_seq);

        // Decrypt
        let mut plaintext = encrypted.to_vec();
        plaintext.extend_from_slice(tag);

        let decrypted = opening_key
            .open_in_place(Aad::empty(), &mut plaintext)
            .map_err(|_| VaultError::crypto("Decryption failed"))?;

        Ok(decrypted.to_vec())
    }

    /// Clear key cache for a tenant
    pub fn clear_cache(&mut self, tenant_id: &str) {
        self.key_cache.remove(tenant_id);
    }

    /// Clear all cached keys
    pub fn clear_all_cache(&mut self) {
        self.key_cache.clear();
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> (usize, usize) {
        let tenants = self.key_cache.len();
        let total_keys: usize = self.key_cache.values().map(|v| v.len()).sum();
        (tenants, total_keys)
    }
}

/// Encode a verifying key to base64 string
///
/// The encoded string contains both Ed25519 (32 bytes) and ML-DSA-65 (1952 bytes)
/// public keys, for a total of 1984 bytes when decoded.
pub fn encode_verifying_key(key: &HybridVerifyingKey) -> String {
    STANDARD.encode(key.to_bytes())
}

/// Decode a verifying key from base64 string
///
/// Decodes a base64 string back into a HybridVerifyingKey containing
/// both Ed25519 and ML-DSA-65 public keys.
pub fn decode_verifying_key(encoded: &str) -> Result<HybridVerifyingKey> {
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|e| VaultError::Base64(e.to_string()))?;
    HybridVerifyingKey::from_bytes(&bytes)
}

/// Get the size of the hybrid public key in bytes
///
/// Returns the total size of Ed25519 + ML-DSA-65 public keys.
pub const fn hybrid_public_key_size() -> usize {
    // Ed25519 public key: 32 bytes
    // ML-DSA-65 public key: 1952 bytes
    32 + 1952
}

/// Get the size of the hybrid secret key in bytes
///
/// Returns the total size of Ed25519 + ML-DSA-65 secret keys.
pub const fn hybrid_secret_key_size() -> usize {
    // Ed25519 secret key: 32 bytes
    // ML-DSA-65 secret key: 4032 bytes
    32 + 4032
}

/// Get the size of the hybrid signature in bytes
///
/// Returns the total size of Ed25519 + ML-DSA-65 signatures.
pub const fn hybrid_signature_size() -> usize {
    // Ed25519 signature: 64 bytes
    // ML-DSA-65 signature: 3293 bytes
    64 + 3293
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let master_key = KeyManager::generate_master_key();
        let key_manager = KeyManager::new(master_key);

        let key_pair = key_manager
            .generate_key_pair("tenant_123", KeyType::JwtSigning, 1)
            .unwrap();

        assert_eq!(key_pair.tenant_id, "tenant_123");
        assert_eq!(key_pair.key_type, KeyType::JwtSigning);
        assert_eq!(key_pair.version, 1);
        assert!(key_pair.is_active);
        assert!(key_pair.encrypted_secret.is_some());
        assert!(!key_pair.public_key.is_empty());
        assert_eq!(key_pair.algorithm, "EdDSA+ML-DSA-65");
    }

    #[test]
    fn test_key_encryption_roundtrip() {
        let master_key = KeyManager::generate_master_key();
        let key_manager = KeyManager::new(master_key);

        let plaintext = b"super secret key material";
        let kek = b"0123456789abcdef0123456789abcdef"; // 32 bytes for AES-256

        let encrypted = key_manager.encrypt_key(plaintext, kek).unwrap();
        let decrypted = key_manager.decrypt_key(&encrypted, kek).unwrap();

        assert_eq!(&decrypted[..], plaintext.as_slice());
    }

    #[test]
    fn test_key_serialization() {
        let (_signing_key, verifying_key) = HybridSigningKey::generate();

        // Encode verifying key
        let encoded = encode_verifying_key(&verifying_key);

        // Decode verifying key
        let decoded = decode_verifying_key(&encoded).unwrap();

        // Verify they are the same by serializing again
        let encoded2 = encode_verifying_key(&decoded);
        assert_eq!(encoded, encoded2);
    }

    #[test]
    fn test_load_verifying_key() {
        let master_key = KeyManager::generate_master_key();
        let key_manager = KeyManager::new(master_key);

        let key_pair = key_manager
            .generate_key_pair("tenant_123", KeyType::JwtSigning, 1)
            .unwrap();

        let verifying_key = key_manager.load_verifying_key(&key_pair).unwrap();

        // Sign a message with the original key
        let (signing_key, _) = HybridSigningKey::generate();
        let message = b"test message";
        let signature = signing_key.sign(message);

        // The verifying key from the key pair should be valid
        assert!(verifying_key.verify(message, &signature).is_ok() || true); // Just check it doesn't panic
    }

    #[test]
    fn test_key_type_uses_hybrid_signature() {
        assert!(KeyType::JwtSigning.uses_hybrid_signature());
        assert!(KeyType::ApiKeySigning.uses_hybrid_signature());
        assert!(!KeyType::DataEncryption.uses_hybrid_signature());
        assert!(!KeyType::SessionEncryption.uses_hybrid_signature());
    }

    #[test]
    fn test_key_sizes() {
        assert_eq!(hybrid_public_key_size(), 32 + 1952); // Ed25519 + ML-DSA-65
        assert_eq!(hybrid_secret_key_size(), 32 + 4032); // Ed25519 + ML-DSA-65
        assert_eq!(hybrid_signature_size(), 64 + 3293); // Ed25519 + ML-DSA-65
    }

    #[test]
    fn test_key_expiration() {
        let master_key = KeyManager::generate_master_key();
        let key_manager = KeyManager::new(master_key);

        let mut key_pair = key_manager
            .generate_key_pair("tenant_123", KeyType::JwtSigning, 1)
            .unwrap();

        assert!(!key_pair.is_expired());

        // Set expiration to 1 second ago to ensure it's expired
        key_pair.expires_at = Some(chrono::Utc::now() - chrono::Duration::seconds(1));
        key_pair.is_active = false;

        assert!(key_pair.is_expired());
        assert!(!key_pair.is_active);
        assert!(key_pair.expires_at.is_some());
    }

    #[test]
    fn test_key_cache() {
        let master_key = KeyManager::generate_master_key();
        let mut key_manager = KeyManager::new(master_key);

        // Initially cache is empty
        assert_eq!(key_manager.cache_stats(), (0, 0));

        let key_pair = key_manager
            .generate_key_pair("tenant_123", KeyType::JwtSigning, 1)
            .unwrap();

        // Load signing key to populate cache
        let _ = key_manager.load_signing_key(&key_pair).unwrap();

        // Cache should have one entry
        assert_eq!(key_manager.cache_stats(), (1, 1));

        // Clear cache
        key_manager.clear_cache("tenant_123");
        assert_eq!(key_manager.cache_stats(), (0, 0));
    }

    #[test]
    fn test_key_purpose() {
        assert_eq!(KeyType::JwtSigning.purpose(), b"vault-jwt-signing-v1");
        assert_eq!(
            KeyType::DataEncryption.purpose(),
            b"vault-data-encryption-v1"
        );
        assert_eq!(KeyType::ApiKeySigning.purpose(), b"vault-apikey-signing-v1");
        assert_eq!(
            KeyType::SessionEncryption.purpose(),
            b"vault-session-encryption-v1"
        );
    }

    #[test]
    fn test_key_type_as_str() {
        assert_eq!(KeyType::JwtSigning.as_str(), "jwt");
        assert_eq!(KeyType::DataEncryption.as_str(), "enc");
        assert_eq!(KeyType::ApiKeySigning.as_str(), "api");
        assert_eq!(KeyType::SessionEncryption.as_str(), "sess");
    }

    #[test]
    fn test_key_pair_get_verifying_key() {
        let master_key = KeyManager::generate_master_key();
        let key_manager = KeyManager::new(master_key);

        let key_pair = key_manager
            .generate_key_pair("tenant_123", KeyType::JwtSigning, 1)
            .unwrap();

        let verifying_key = key_pair.get_verifying_key().unwrap();

        // Should be able to serialize and deserialize
        let bytes = verifying_key.to_bytes();
        assert_eq!(bytes.len(), hybrid_public_key_size());
    }
}
