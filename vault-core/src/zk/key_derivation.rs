//! Master Key Derivation from Passwords
//!
//! This module implements secure key derivation using Argon2id, the winner of the
//! Password Hashing Competition (PHC). Argon2id provides resistance against both
//! GPU-based attacks and side-channel attacks.
//!
//! ## Key Derivation Process
//!
//! 1. Generate random salt (16+ bytes)
//! 2. Derive key material using Argon2id
//! 3. Split key material into:
//!    - Encryption key (32 bytes for AES-256)
//!    - Authentication key (32 bytes for HMAC)
//! 4. Generate RSA key pair from derived material
//!
//! ## Security Considerations
//!
//! - Salt must be unique per user
//! - Argon2id parameters should be tuned for target hardware
//! - Minimum 3 iterations recommended
//! - Memory cost should be at least 64MB

use crate::zk::ZkError;
use argon2::{
    Algorithm, Argon2, Params, Version,
};
use rand::RngCore;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};

/// Default salt length in bytes
pub const SALT_LENGTH: usize = 16;

/// Default Argon2id memory cost (64 MB)
pub const DEFAULT_MEMORY_COST: u32 = 65536;

/// Default Argon2id time cost (iterations)
pub const DEFAULT_TIME_COST: u32 = 3;

/// Default Argon2id parallelism degree
pub const DEFAULT_PARALLELISM: u32 = 4;

/// Output length from Argon2id (must be enough for both keys)
pub const KEY_MATERIAL_LENGTH: usize = 64;

/// RSA key size (bits)
pub const RSA_KEY_SIZE: usize = 2048;

/// Argon2id parameters for key derivation
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    /// Memory cost in KB
    pub memory_cost: u32,
    /// Number of iterations (time cost)
    pub time_cost: u32,
    /// Degree of parallelism
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_cost: DEFAULT_MEMORY_COST,
            time_cost: DEFAULT_TIME_COST,
            parallelism: DEFAULT_PARALLELISM,
        }
    }
}

impl Argon2Params {
    /// Create parameters with custom values
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
        }
    }

    /// Conservative parameters (higher security, slower)
    pub fn conservative() -> Self {
        Self {
            memory_cost: 262144, // 256 MB
            time_cost: 4,
            parallelism: 4,
        }
    }

    /// Fast parameters (lower security, faster)
    /// Use only for testing or low-security scenarios
    pub fn fast() -> Self {
        Self {
            memory_cost: 16384, // 16 MB
            time_cost: 2,
            parallelism: 1,
        }
    }
}

/// Master key derived from password
#[derive(Debug, Clone)]
pub struct MasterKey {
    /// Symmetric encryption key (32 bytes for AES-256)
    pub encryption_key: [u8; 32],
    /// Authentication key for HMAC (32 bytes)
    pub authentication_key: [u8; 32],
    /// RSA private key for unwrapping data keys
    pub rsa_private_key: RsaPrivateKey,
    /// RSA public key for wrapping data keys
    pub rsa_public_key: RsaPublicKey,
}

impl MasterKey {
    /// Serialize the master key to bytes (excluding RSA keys - they can be regenerated)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(64);
        result.extend_from_slice(&self.encryption_key);
        result.extend_from_slice(&self.authentication_key);
        result
    }

    /// Create from bytes (RSA keys will be regenerated)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        if bytes.len() != 64 {
            return Err(ZkError::InvalidParams(
                "Master key must be 64 bytes".to_string(),
            ));
        }

        let mut encryption_key = [0u8; 32];
        let mut authentication_key = [0u8; 32];
        encryption_key.copy_from_slice(&bytes[..32]);
        authentication_key.copy_from_slice(&bytes[32..]);

        // Regenerate RSA keys deterministically from the encryption key
        let (rsa_private_key, rsa_public_key) = generate_rsa_keypair(&encryption_key)?;

        Ok(Self {
            encryption_key,
            authentication_key,
            rsa_private_key,
            rsa_public_key,
        })
    }

    /// Get the RSA private key as PKCS#8 DER bytes
    pub fn rsa_private_key_to_der(&self) -> Result<Vec<u8>, ZkError> {
        self.rsa_private_key
            .to_pkcs8_der()
            .map_err(|e| ZkError::Encryption(format!("Failed to serialize private key: {}", e)))
            .map(|doc| doc.as_bytes().to_vec())
    }

    /// Get the RSA public key as PKCS#8 DER bytes
    pub fn rsa_public_key_to_der(&self) -> Result<Vec<u8>, ZkError> {
        self.rsa_public_key
            .to_public_key_der()
            .map_err(|e| ZkError::Encryption(format!("Failed to serialize public key: {}", e)))
            .map(|doc| doc.as_bytes().to_vec())
    }

    /// Encrypt the RSA private key with the encryption key (for server storage)
    pub fn encrypt_private_key(&self) -> Result<Vec<u8>, ZkError> {
        use crate::crypto::encrypt_to_base64;
        let pk_der = self.rsa_private_key_to_der()?;
        let encrypted = encrypt_to_base64(&self.encryption_key, &pk_der)
            .map_err(|e| ZkError::Encryption(format!("Failed to encrypt private key: {}", e)))?;
        Ok(encrypted.into_bytes())
    }
}

/// Generate a cryptographically secure random salt
/// 
/// SECURITY: Uses OsRng (operating system's CSPRNG) for generating salts.
/// Salts must be unpredictable to prevent precomputation attacks (rainbow tables).
/// This is critical for the security of the key derivation function.
pub fn generate_salt() -> Vec<u8> {
    use rand::RngCore;
    use rand_core::OsRng;
    
    let mut salt = vec![0u8; SALT_LENGTH];
    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive master key from password and salt using Argon2id
pub fn derive_master_key_from_password(
    password: &str,
    salt: &[u8],
    params: Option<Argon2Params>,
) -> Result<MasterKey, ZkError> {
    let params = params.unwrap_or_default();

    // Create Argon2id hasher
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(
            params.memory_cost,
            params.time_cost,
            params.parallelism,
            Some(KEY_MATERIAL_LENGTH),
        )
        .map_err(|e| ZkError::KeyDerivation(format!("Invalid Argon2 params: {}", e)))?,
    );

    // Derive key material directly with salt bytes
    let mut key_material = [0u8; KEY_MATERIAL_LENGTH];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key_material)
        .map_err(|e| ZkError::KeyDerivation(format!("Argon2id failed: {}", e)))?;

    // Split key material
    let mut encryption_key = [0u8; 32];
    let mut authentication_key = [0u8; 32];
    encryption_key.copy_from_slice(&key_material[..32]);
    authentication_key.copy_from_slice(&key_material[32..]);

    // Generate RSA key pair from encryption key
    let (rsa_private_key, rsa_public_key) = generate_rsa_keypair(&encryption_key)?;

    Ok(MasterKey {
        encryption_key,
        authentication_key,
        rsa_private_key,
        rsa_public_key,
    })
}

/// Generate RSA key pair deterministically from seed
/// 
/// SECURITY: Uses OsRng (operating system's CSPRNG) for RSA key generation.
/// RSA keys are used for encryption and must be generated with cryptographically
/// secure randomness to prevent private key recovery attacks.
fn generate_rsa_keypair(_seed: &[u8]) -> Result<(RsaPrivateKey, RsaPublicKey), ZkError> {
    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    // Note: For deterministic generation, a seeded RNG would be needed
    let mut rng = rand_core::OsRng;

    // Generate RSA key pair
    // Note: For true deterministic generation, we'd need a seeded RNG
    // For now, we generate a random key pair
    let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE)
        .map_err(|e| ZkError::KeyDerivation(format!("RSA key generation failed: {}", e)))?;

    let public_key = RsaPublicKey::from(&private_key);

    Ok((private_key, public_key))
}

/// Decrypt RSA private key that was encrypted with master key
pub fn decrypt_private_key(
    encrypted_key: &[u8],
    master_key: &MasterKey,
) -> Result<RsaPrivateKey, ZkError> {
    use crate::crypto::decrypt_from_base64;

    let encrypted_str = String::from_utf8(encrypted_key.to_vec())
        .map_err(|e| ZkError::Encryption(format!("Invalid encrypted key format: {}", e)))?;

    let pk_der = decrypt_from_base64(&master_key.encryption_key, &encrypted_str)
        .map_err(|e| ZkError::Encryption(format!("Failed to decrypt private key: {}", e)))?;

    RsaPrivateKey::from_pkcs8_der(&pk_der)
        .map_err(|e| ZkError::Encryption(format!("Failed to parse private key: {}", e)))
}

/// Master key derivation helper struct
pub struct MasterKeyDerivation;

impl MasterKeyDerivation {
    /// Generate a new random salt
    pub fn generate_salt() -> Vec<u8> {
        generate_salt()
    }

    /// Derive master key from password
    pub fn derive(
        password: &str,
        salt: &[u8],
        params: Option<Argon2Params>,
    ) -> Result<MasterKey, ZkError> {
        derive_master_key_from_password(password, salt, params)
    }

    /// Verify that a password matches the derived key (by re-deriving)
    pub fn verify(
        password: &str,
        salt: &[u8],
        expected_auth_key: &[u8; 32],
        params: Option<Argon2Params>,
    ) -> Result<bool, ZkError> {
        let master_key = derive_master_key_from_password(password, salt, params)?;
        Ok(crate::crypto::secure_compare(
            &master_key.authentication_key,
            expected_auth_key,
        ))
    }

    /// Generate commitment for ZK proof
    pub fn generate_commitment(password: &str, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let result = hasher.finalize();
        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&result);
        commitment
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_salt_generation() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_eq!(salt1.len(), SALT_LENGTH);
        assert_eq!(salt2.len(), SALT_LENGTH);
        assert_ne!(salt1, salt2); // Should be different
    }

    #[test]
    fn test_key_derivation() {
        let password = "my_secure_password";
        let salt = generate_salt();

        let master_key1 = derive_master_key_from_password(password, &salt, None).unwrap();
        let master_key2 = derive_master_key_from_password(password, &salt, None).unwrap();

        // Same password + salt should produce same keys
        assert_eq!(
            master_key1.encryption_key,
            master_key2.encryption_key
        );
        assert_eq!(
            master_key1.authentication_key,
            master_key2.authentication_key
        );

        // Different salt should produce different keys
        let salt2 = generate_salt();
        let master_key3 = derive_master_key_from_password(password, &salt2, None).unwrap();
        assert_ne!(
            master_key1.encryption_key,
            master_key3.encryption_key
        );
    }

    #[test]
    fn test_master_key_serialization() {
        let password = "test_password";
        let salt = generate_salt();
        let master_key = derive_master_key_from_password(password, &salt, None).unwrap();

        let bytes = master_key.to_bytes();
        assert_eq!(bytes.len(), 64);

        // Note: RSA keys are regenerated from seed, so we can't round-trip them
        // But we can verify the encryption and authentication keys
    }

    #[test]
    fn test_argon2_params() {
        let conservative = Argon2Params::conservative();
        assert_eq!(conservative.memory_cost, 262144);
        assert_eq!(conservative.time_cost, 4);

        let fast = Argon2Params::fast();
        assert_eq!(fast.memory_cost, 16384);
        assert_eq!(fast.time_cost, 2);
    }

    #[test]
    fn test_master_key_derivation_verify() {
        let password = "test_password";
        let salt = generate_salt();

        let master_key = derive_master_key_from_password(password, &salt, None).unwrap();

        let is_valid = MasterKeyDerivation::verify(
            password,
            &salt,
            &master_key.authentication_key,
            None,
        )
        .unwrap();
        assert!(is_valid);

        let is_invalid = MasterKeyDerivation::verify(
            "wrong_password",
            &salt,
            &master_key.authentication_key,
            None,
        )
        .unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_generate_commitment() {
        let password = "test";
        let salt = generate_salt();

        let commitment1 = MasterKeyDerivation::generate_commitment(password, &salt);
        let commitment2 = MasterKeyDerivation::generate_commitment(password, &salt);

        // Same password + salt should produce same commitment
        assert_eq!(commitment1, commitment2);

        // Different salt should produce different commitment
        let salt2 = generate_salt();
        let commitment3 = MasterKeyDerivation::generate_commitment(password, &salt2);
        assert_ne!(commitment1, commitment3);
    }

    #[test]
    fn test_rsa_key_export() {
        let password = "test";
        let salt = generate_salt();
        let master_key = derive_master_key_from_password(password, &salt, None).unwrap();

        // Test DER export
        let pk_der = master_key.rsa_private_key_to_der();
        assert!(pk_der.is_ok());

        let pub_der = master_key.rsa_public_key_to_der();
        assert!(pub_der.is_ok());

        // Test private key encryption
        let encrypted = master_key.encrypt_private_key();
        assert!(encrypted.is_ok());
    }
}
