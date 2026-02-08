//! Cryptography module with quantum-resistant algorithms
//!
//! This module implements a hybrid approach combining traditional and post-quantum
//! cryptography for defense in depth against both classical and quantum attacks.

use crate::error::{Result, VaultError};
use argon2::{
    password_hash::{
        rand_core::OsRng, PasswordHash, PasswordHasher as ArgonPasswordHasher, PasswordVerifier,
        SaltString,
    },
    Argon2,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{
    DetachedSignature as PQDetachedSignature, PublicKey as PQPublicKey, SecretKey as PQSecretKey,
    SignedMessage as PQSignedMessage,
};
use rand::RngCore;

mod jwt;
mod keys;
mod symmetric;
mod tokens;

pub use jwt::{
    AuthMethod, Claims, HybridJwt, StepUpChallenge, StepUpLevel, StepUpSession, TokenType,
};
pub use keys::{KeyManager, KeyPair, KeyType};
pub use symmetric::{decrypt_from_base64, encrypt_to_base64};
pub use tokens::{CsrfToken, MagicLinkToken, OtpCode, RefreshToken};

/// Size of Ed25519 signature
const ED25519_SIG_SIZE: usize = 64;
/// Size of ML-DSA-65 signature
const MLDSA65_SIG_SIZE: usize = mldsa65::signature_bytes();
/// Size of Ed25519 secret key
const ED25519_SECRET_SIZE: usize = 32;
/// Size of Ed25519 public key
const ED25519_PUBLIC_SIZE: usize = 32;

/// Hybrid signature combining Ed25519 and ML-DSA-65
#[derive(Clone, Debug)]
pub struct HybridSignature {
    /// Ed25519 signature component (64 bytes)
    pub ed25519: [u8; ED25519_SIG_SIZE],
    /// ML-DSA-65 signature component (3293 bytes)
    pub mldsa: [u8; MLDSA65_SIG_SIZE],
}

impl HybridSignature {
    /// Create new hybrid signature from components
    pub fn new(ed25519: [u8; ED25519_SIG_SIZE], mldsa: [u8; MLDSA65_SIG_SIZE]) -> Self {
        Self { ed25519, mldsa }
    }

    /// Serialize to bytes (Ed25519 || ML-DSA)
    /// Format: [Ed25519_sig (64 bytes)] + [ML-DSA-65_sig (3293 bytes)] = 3357 bytes total
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ED25519_SIG_SIZE + MLDSA65_SIG_SIZE);
        bytes.extend_from_slice(&self.ed25519);
        bytes.extend_from_slice(&self.mldsa);
        bytes
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ED25519_SIG_SIZE + MLDSA65_SIG_SIZE {
            return Err(VaultError::crypto(format!(
                "Invalid hybrid signature length: expected {}, got {}",
                ED25519_SIG_SIZE + MLDSA65_SIG_SIZE,
                bytes.len()
            )));
        }

        let mut ed25519 = [0u8; ED25519_SIG_SIZE];
        ed25519.copy_from_slice(&bytes[..ED25519_SIG_SIZE]);

        let mut mldsa = [0u8; MLDSA65_SIG_SIZE];
        mldsa.copy_from_slice(&bytes[ED25519_SIG_SIZE..]);

        Ok(Self { ed25519, mldsa })
    }
}

/// Hybrid key pair for signing (Ed25519 + ML-DSA-65)
pub struct HybridSigningKey {
    ed25519: SigningKey,
    mldsa: mldsa65::SecretKey,
}

/// Hybrid verifying key for signature verification
#[derive(Clone)]
pub struct HybridVerifyingKey {
    ed25519: VerifyingKey,
    mldsa: mldsa65::PublicKey,
}

impl HybridSigningKey {
    /// Generate a new hybrid key pair
    pub fn generate() -> (Self, HybridVerifyingKey) {
        // Generate Ed25519 key pair
        let ed25519_signing = SigningKey::generate(&mut rand::thread_rng());
        let ed25519_verifying = ed25519_signing.verifying_key();

        // Generate ML-DSA-65 key pair using pqcrypto
        let (mldsa_public, mldsa_secret) = mldsa65::keypair();

        let signing = Self {
            ed25519: ed25519_signing,
            mldsa: mldsa_secret,
        };

        let verifying = HybridVerifyingKey {
            ed25519: ed25519_verifying,
            mldsa: mldsa_public,
        };

        (signing, verifying)
    }

    /// Sign a message with both algorithms (hybrid signing)
    /// Returns a hybrid signature containing both Ed25519 and ML-DSA-65 signatures
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        // Ed25519 signature (64 bytes)
        let ed25519_sig = self.ed25519.sign(message);

        // ML-DSA-65 signature using pqcrypto
        // mldsa65::sign returns a SignedMessage which contains signature + message
        let signed_msg = mldsa65::sign(message, &self.mldsa);
        let signed_msg_bytes = signed_msg.as_bytes();

        // The signed message format from pqcrypto includes the signature followed by the message
        // For ML-DSA-65, signature is 3293 bytes
        let mldsa_sig = &signed_msg_bytes[..MLDSA65_SIG_SIZE];

        let mut mldsa_sig_array = [0u8; MLDSA65_SIG_SIZE];
        mldsa_sig_array.copy_from_slice(mldsa_sig);

        HybridSignature {
            ed25519: ed25519_sig.to_bytes(),
            mldsa: mldsa_sig_array,
        }
    }

    /// Serialize secret key to bytes (for storage)
    /// Format: [Ed25519_secret (32 bytes)] + [ML-DSA_secret (4032 bytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ed25519_bytes = self.ed25519.to_bytes();
        let mldsa_bytes = self.mldsa.as_bytes();

        let mut result = Vec::with_capacity(ed25519_bytes.len() + mldsa_bytes.len());
        result.extend_from_slice(&ed25519_bytes);
        result.extend_from_slice(mldsa_bytes);
        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Ed25519 secret key is 32 bytes
        // ML-DSA-65 secret key is 4032 bytes
        const MLDSA65_SECRET_SIZE: usize = 4032;
        const EXPECTED_SIZE: usize = ED25519_SECRET_SIZE + MLDSA65_SECRET_SIZE;

        if bytes.len() != EXPECTED_SIZE {
            return Err(VaultError::crypto(format!(
                "Invalid signing key length: expected {}, got {}",
                EXPECTED_SIZE,
                bytes.len()
            )));
        }

        let ed25519_bytes: [u8; ED25519_SECRET_SIZE] = bytes[..ED25519_SECRET_SIZE]
            .try_into()
            .map_err(|_| VaultError::crypto("Invalid Ed25519 secret key length"))?;

        let mldsa_bytes = &bytes[ED25519_SECRET_SIZE..];
        let mldsa_secret = mldsa65::SecretKey::from_bytes(mldsa_bytes)
            .map_err(|_| VaultError::crypto("Invalid ML-DSA-65 secret key"))?;

        let ed25519_signing = SigningKey::from_bytes(&ed25519_bytes);

        Ok(Self {
            ed25519: ed25519_signing,
            mldsa: mldsa_secret,
        })
    }
}

impl Clone for HybridSigningKey {
    fn clone(&self) -> Self {
        // Clone by serializing and deserializing
        let bytes = self.to_bytes();
        Self::from_bytes(&bytes).expect("Failed to clone signing key")
    }
}

impl HybridVerifyingKey {
    /// Verify a hybrid signature
    /// Both Ed25519 and ML-DSA-65 signatures must be valid
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> Result<()> {
        // Verify Ed25519 signature
        let ed25519_sig = Signature::from_bytes(&signature.ed25519);
        self.ed25519
            .verify(message, &ed25519_sig)
            .map_err(|_| VaultError::crypto("Ed25519 signature verification failed"))?;

        // Verify ML-DSA-65 signature using detached signature verification
        // The signature is the detached ML-DSA-65 signature (3293 bytes)
        let mldsa_sig = pqcrypto_traits::sign::DetachedSignature::from_bytes(&signature.mldsa)
            .map_err(|_| VaultError::crypto("Invalid ML-DSA-65 signature format"))?;

        mldsa65::verify_detached_signature(&mldsa_sig, message, &self.mldsa)
            .map_err(|_| VaultError::crypto("ML-DSA-65 signature verification failed"))?;

        Ok(())
    }

    /// Serialize to bytes
    /// Format: [Ed25519_public (32 bytes)] + [ML-DSA_public (1952 bytes)]
    pub fn to_bytes(&self) -> Vec<u8> {
        let ed25519_bytes = self.ed25519.to_bytes();
        let mldsa_bytes = self.mldsa.as_bytes();

        let mut result = Vec::with_capacity(ed25519_bytes.len() + mldsa_bytes.len());
        result.extend_from_slice(&ed25519_bytes);
        result.extend_from_slice(mldsa_bytes);
        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Ed25519 public key is 32 bytes
        // ML-DSA-65 public key is 1952 bytes
        const MLDSA65_PUBLIC_SIZE: usize = 1952;
        const EXPECTED_SIZE: usize = ED25519_PUBLIC_SIZE + MLDSA65_PUBLIC_SIZE;

        if bytes.len() != EXPECTED_SIZE {
            return Err(VaultError::crypto(format!(
                "Invalid verifying key length: expected {}, got {}",
                EXPECTED_SIZE,
                bytes.len()
            )));
        }

        let ed25519_bytes: [u8; ED25519_PUBLIC_SIZE] = bytes[..ED25519_PUBLIC_SIZE]
            .try_into()
            .map_err(|_| VaultError::crypto("Invalid Ed25519 public key length"))?;
        let ed25519 = VerifyingKey::from_bytes(&ed25519_bytes)
            .map_err(|_| VaultError::crypto("Invalid Ed25519 public key"))?;

        let mldsa_bytes = &bytes[ED25519_PUBLIC_SIZE..];
        let mldsa = mldsa65::PublicKey::from_bytes(mldsa_bytes)
            .map_err(|_| VaultError::crypto("Invalid ML-DSA-65 public key"))?;

        Ok(Self { ed25519, mldsa })
    }

    /// Get the Ed25519 public key
    pub fn ed25519_key(&self) -> &VerifyingKey {
        &self.ed25519
    }

    /// Get the ML-DSA-65 public key
    pub fn mldsa_key(&self) -> &mldsa65::PublicKey {
        &self.mldsa
    }
}

/// Password hashing with Argon2id
pub struct VaultPasswordHasher;

impl VaultPasswordHasher {
    /// Hash a password using Argon2id
    pub fn hash(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(65536, 3, 4, None)
                .map_err(|e| VaultError::crypto(format!("Argon2 params error: {}", e)))?,
        );

        let password_hash = ArgonPasswordHasher::hash_password(&argon2, password.as_bytes(), &salt)
            .map_err(|e| VaultError::crypto(format!("Password hashing failed: {}", e)))?;

        Ok(password_hash.to_string())
    }

    /// Verify a password against a hash
    pub fn verify(password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| VaultError::crypto(format!("Invalid password hash: {}", e)))?;

        let argon2 = Argon2::default();

        match argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(VaultError::crypto(format!(
                "Password verification error: {}",
                e
            ))),
        }
    }
}

/// Generate a cryptographically secure random string
pub fn generate_secure_random(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);

    bytes
        .iter()
        .map(|b| CHARSET[(b % CHARSET.len() as u8) as usize] as char)
        .collect()
}

/// Generate a cryptographically secure random byte array
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

/// Constant-time comparison to prevent timing attacks
pub fn secure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Derive a key from a master key using HKDF
pub fn derive_key(master_key: &[u8], context: &[u8], output_len: usize) -> Result<Vec<u8>> {
    use ring::hkdf;

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(master_key);

    // For arbitrary length output, we need to use multiple expands or a simpler approach
    // Here we use a simple approach with SHA-256 output
    if output_len > 32 {
        return Err(VaultError::crypto(
            "Output length too large for HKDF-SHA256",
        ));
    }

    // Create OKM buffer with fixed size for SHA-256
    let mut okm = [0u8; 32];
    let context_slices: &[&[u8]] = &[context];
    let expand_result = prk
        .expand(context_slices, hkdf::HKDF_SHA256)
        .map_err(|_| VaultError::crypto("Key derivation expand failed"))?;
    expand_result
        .fill(&mut okm)
        .map_err(|_| VaultError::crypto("Key derivation fill failed"))?;

    // Return requested length
    Ok(okm[..output_len].to_vec())
}

/// Sign a message using hybrid approach (Ed25519 + ML-DSA-65)
/// This is a convenience function for external use
pub fn hybrid_sign(message: &[u8], signing_key: &HybridSigningKey) -> HybridSignature {
    signing_key.sign(message)
}

/// Verify a hybrid signature (Ed25519 + ML-DSA-65)
/// This is a convenience function for external use
pub fn hybrid_verify(
    message: &[u8],
    signature: &HybridSignature,
    verifying_key: &HybridVerifyingKey,
) -> Result<()> {
    verifying_key.verify(message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_signing() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        let message = b"Hello, quantum world!";

        let signature = signing_key.sign(message);

        // Should verify successfully
        assert!(verifying_key.verify(message, &signature).is_ok());

        // Should fail with wrong message
        let wrong_message = b"Wrong message";
        assert!(verifying_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_hybrid_signature_serialization() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        let message = b"Test message for serialization";

        let signature = signing_key.sign(message);
        let serialized = signature.to_bytes();

        // Check exact size: 64 (Ed25519) + 3293 (ML-DSA-65) = 3357 bytes
        assert_eq!(serialized.len(), ED25519_SIG_SIZE + MLDSA65_SIG_SIZE);

        let deserialized = HybridSignature::from_bytes(&serialized).unwrap();

        // Should verify after serialization round-trip
        assert!(verifying_key.verify(message, &deserialized).is_ok());
    }

    #[test]
    fn test_hybrid_key_serialization() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();

        // Test signing key serialization
        let signing_bytes = signing_key.to_bytes();
        let restored_signing = HybridSigningKey::from_bytes(&signing_bytes).unwrap();

        let message = b"Test message";
        let signature = restored_signing.sign(message);
        assert!(verifying_key.verify(message, &signature).is_ok());

        // Test verifying key serialization
        let verifying_bytes = verifying_key.to_bytes();
        let restored_verifying = HybridVerifyingKey::from_bytes(&verifying_bytes).unwrap();

        let signature2 = signing_key.sign(message);
        assert!(restored_verifying.verify(message, &signature2).is_ok());
    }

    #[test]
    fn test_hybrid_sign_verify_functions() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        let message = b"Testing convenience functions";

        // Use the convenience functions
        let signature = hybrid_sign(message, &signing_key);
        assert!(hybrid_verify(message, &signature, &verifying_key).is_ok());

        // Should fail with tampered message
        assert!(hybrid_verify(b"Tampered", &signature, &verifying_key).is_err());
    }

    #[test]
    fn test_signature_tampering() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        let message = b"Original message";
        let mut signature = signing_key.sign(message);

        // Tamper with Ed25519 signature
        signature.ed25519[0] ^= 0xFF;
        assert!(verifying_key.verify(message, &signature).is_err());

        // Restore and tamper with ML-DSA signature
        let signature2 = signing_key.sign(message);
        signature = signature2;
        signature.mldsa[0] ^= 0xFF;
        assert!(verifying_key.verify(message, &signature).is_err());
    }

    #[test]
    fn test_password_hashing() {
        let password = "my_secure_password123!";
        let hash = VaultPasswordHasher::hash(password).unwrap();

        // Correct password should verify
        assert!(VaultPasswordHasher::verify(password, &hash).unwrap());

        // Wrong password should fail
        assert!(!VaultPasswordHasher::verify("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_secure_random() {
        let random1 = generate_secure_random(32);
        let random2 = generate_secure_random(32);

        assert_eq!(random1.len(), 32);
        assert_eq!(random2.len(), 32);
        assert_ne!(random1, random2); // Should be different
    }

    #[test]
    fn test_secure_compare() {
        let a = b"secret";
        let b = b"secret";
        let c = b"different";

        assert!(secure_compare(a, b));
        assert!(!secure_compare(a, c));
        assert!(!secure_compare(a, &a[..3]));
    }

    #[test]
    fn test_key_sizes() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();

        // Check signing key size
        let signing_bytes = signing_key.to_bytes();
        assert_eq!(signing_bytes.len(), 32 + 4032); // Ed25519 + ML-DSA-65

        // Check verifying key size
        let verifying_bytes = verifying_key.to_bytes();
        assert_eq!(verifying_bytes.len(), 32 + 1952); // Ed25519 + ML-DSA-65

        // Check signature size
        let message = b"test";
        let signature = signing_key.sign(message);
        assert_eq!(
            signature.to_bytes().len(),
            ED25519_SIG_SIZE + MLDSA65_SIG_SIZE
        ); // Ed25519 + ML-DSA-65
    }
}
