//! WebAuthn verification
//!
//! Handles signature verification and attestation validation.

use super::{sha256, AuthenticatorData, AuthenticatorFlags, CollectedClientData};
use crate::error::{Result, VaultError};

/// WebAuthn verifier
pub struct WebAuthnVerifier;

impl WebAuthnVerifier {
    /// Verify registration
    pub fn verify_registration(
        client_data: &CollectedClientData,
        attestation_object: &[u8],
        expected_challenge: &str,
        expected_origin: &str,
    ) -> Result<()> {
        // Verify challenge matches
        if client_data.challenge != expected_challenge {
            return Err(VaultError::validation("Challenge mismatch"));
        }

        // Verify origin
        if client_data.origin != expected_origin {
            return Err(VaultError::validation("Origin mismatch"));
        }

        // Verify type
        if client_data.type_ != "webauthn.create" {
            return Err(VaultError::validation("Invalid type"));
        }

        // Note: Full attestation verification requires CBOR parsing
        // and certificate chain validation which is complex.
        // For production, use a proper WebAuthn library.

        Ok(())
    }

    /// Verify authentication
    pub fn verify_authentication(
        client_data: &CollectedClientData,
        authenticator_data: &[u8],
        signature: &[u8],
        public_key: &[u8],
        stored_sign_count: u32,
        expected_challenge: &str,
        expected_origin: &str,
        require_user_verification: bool,
    ) -> Result<u32> {
        // Verify challenge matches
        if client_data.challenge != expected_challenge {
            return Err(VaultError::validation("Challenge mismatch"));
        }

        // Verify origin
        if client_data.origin != expected_origin {
            return Err(VaultError::validation("Origin mismatch"));
        }

        // Verify type
        if client_data.type_ != "webauthn.get" {
            return Err(VaultError::validation("Invalid type"));
        }

        // Parse authenticator data
        if authenticator_data.len() < 37 {
            return Err(VaultError::validation("Invalid authenticator data length"));
        }

        // Extract sign count
        let sign_count = u32::from_be_bytes([
            authenticator_data[33],
            authenticator_data[34],
            authenticator_data[35],
            authenticator_data[36],
        ]);

        // Check for clone detection
        if sign_count > 0 && sign_count <= stored_sign_count {
            return Err(VaultError::authentication(
                "Possible authenticator clone detected",
            ));
        }

        // Verify flags
        let flags = AuthenticatorFlags::from(authenticator_data[32]);

        if !flags.up {
            return Err(VaultError::authentication("User presence not confirmed"));
        }

        if require_user_verification && !flags.uv {
            return Err(VaultError::authentication("User verification required"));
        }

        // Compute client data hash
        let client_data_json = serde_json::to_string(client_data)
            .map_err(|_| VaultError::internal("Failed to serialize client data"))?;
        let client_data_hash = sha256(client_data_json.as_bytes());

        // Construct signed data
        let mut signed_data = authenticator_data.to_vec();
        signed_data.extend_from_slice(&client_data_hash);

        // Verify signature
        // Note: This is a simplified version. In production, you need to:
        // 1. Parse the COSE key format
        // 2. Determine the algorithm (ES256, RS256, Ed25519)
        // 3. Verify using the appropriate algorithm
        Self::verify_signature(&signed_data, signature, public_key)?;

        Ok(sign_count)
    }

    /// Verify signature
    ///
    /// Supports ES256 (P-256 + SHA-256), ES384, ES512, EdDSA, and RS256
    fn verify_signature(
        signed_data: &[u8],
        signature: &[u8],
        public_key_cose: &[u8],
    ) -> Result<()> {
        if signed_data.is_empty() || signature.is_empty() || public_key_cose.is_empty() {
            return Err(VaultError::validation("Invalid signature data"));
        }

        // Parse COSE key to extract algorithm and public key
        let (algorithm, public_key) = Self::parse_cose_key(public_key_cose)?;

        match algorithm {
            CoseAlgorithm::ES256 => Self::verify_es256(signed_data, signature, &public_key),
            CoseAlgorithm::ES384 => Self::verify_es384(signed_data, signature, &public_key),
            CoseAlgorithm::ES512 => Self::verify_es512(signed_data, signature, &public_key),
            CoseAlgorithm::EdDSA => Self::verify_ed25519(signed_data, signature, &public_key),
            CoseAlgorithm::RS256 => Self::verify_rs256(signed_data, signature, &public_key),
            _ => Err(VaultError::validation("Unsupported signature algorithm")),
        }
    }

    /// Parse COSE key format
    ///
    /// COSE_Key format:
    /// {
    ///   1: kty (1=OKP, 2=EC2, 3=RSA)
    ///   3: alg (-7=ES256, -8=EdDSA, -257=RS256, etc.)
    ///   -2: x (public key x coordinate for EC2/OKP)
    ///   -3: y (public key y coordinate for EC2, optional for OKP)
    ///   -4: d (private key, not present in public keys)
    ///   -1: crv (1=P-256, 6=Ed25519, etc.)
    /// }
    fn parse_cose_key(cose_key: &[u8]) -> Result<(CoseAlgorithm, Vec<u8>)> {
        use ciborium::de::from_reader;
        use std::collections::BTreeMap;

        let cose_map: BTreeMap<i64, ciborium::value::Value> = from_reader(cose_key)
            .map_err(|e| VaultError::validation(format!("Invalid COSE key: {}", e)))?;

        // Get algorithm (key 3)
        let alg = cose_map
            .get(&3)
            .and_then(|v| v.as_integer())
            .and_then(|i| i.try_into().ok())
            .and_then(CoseAlgorithm::from_i64)
            .ok_or_else(|| VaultError::validation("Missing or invalid algorithm in COSE key"))?;

        // Get key type (key 1)
        let kty = cose_map
            .get(&1)
            .and_then(|v| v.as_integer())
            .and_then(|i| i.try_into().ok())
            .ok_or_else(|| VaultError::validation("Missing key type in COSE key"))?;

        // Extract public key based on key type
        let public_key = match kty {
            2 => {
                // EC2 - Elliptic Curve
                let x = cose_map
                    .get(&-2)
                    .and_then(|v| v.as_bytes())
                    .ok_or_else(|| VaultError::validation("Missing x coordinate in EC2 key"))?;
                let y = cose_map
                    .get(&-3)
                    .and_then(|v| v.as_bytes())
                    .ok_or_else(|| VaultError::validation("Missing y coordinate in EC2 key"))?;

                // SEC1 uncompressed format: 0x04 || x || y
                let mut key = vec![0x04];
                key.extend_from_slice(x);
                key.extend_from_slice(y);
                key
            }
            1 => {
                // OKP - Octet Key Pair (Ed25519, X25519)
                cose_map
                    .get(&-2)
                    .and_then(|v| v.as_bytes())
                    .map(|b| b.to_vec())
                    .ok_or_else(|| VaultError::validation("Missing public key in OKP key"))?
            }
            3 => {
                // RSA
                // For RSA, the public key is the modulus (n)
                cose_map
                    .get(&-1)
                    .and_then(|v| v.as_bytes())
                    .map(|b| b.to_vec())
                    .ok_or_else(|| VaultError::validation("Missing modulus in RSA key"))?
            }
            _ => return Err(VaultError::validation("Unsupported key type")),
        };

        Ok((alg, public_key))
    }

    /// Verify ES256 signature (P-256 + SHA-256)
    fn verify_es256(signed_data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| VaultError::crypto(format!("Invalid ES256 public key: {}", e)))?;

        let sig = Signature::from_der(signature)
            .map_err(|e| VaultError::crypto(format!("Invalid ES256 signature: {}", e)))?;

        verifying_key
            .verify(signed_data, &sig)
            .map_err(|_| VaultError::authentication("Signature verification failed"))
    }

    /// Verify ES384 signature (P-384 + SHA-384)
    fn verify_es384(signed_data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| VaultError::crypto(format!("Invalid ES384 public key: {}", e)))?;

        let sig = Signature::from_der(signature)
            .map_err(|e| VaultError::crypto(format!("Invalid ES384 signature: {}", e)))?;

        verifying_key
            .verify(signed_data, &sig)
            .map_err(|_| VaultError::authentication("Signature verification failed"))
    }

    /// Verify ES512 signature (P-521 + SHA-512)
    fn verify_es512(signed_data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        use p521::ecdsa::{signature::Verifier, Signature, VerifyingKey};

        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| VaultError::crypto(format!("Invalid ES512 public key: {}", e)))?;

        let sig = Signature::from_der(signature)
            .map_err(|e| VaultError::crypto(format!("Invalid ES512 signature: {}", e)))?;

        verifying_key
            .verify(signed_data, &sig)
            .map_err(|_| VaultError::authentication("Signature verification failed"))
    }

    /// Verify Ed25519 signature
    fn verify_ed25519(signed_data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let verifying_key: VerifyingKey = public_key
            .try_into()
            .map_err(|_| VaultError::crypto("Invalid Ed25519 public key length"))?;

        let sig: Signature = signature
            .try_into()
            .map_err(|_| VaultError::crypto("Invalid Ed25519 signature length"))?;

        verifying_key
            .verify(signed_data, &sig)
            .map_err(|_| VaultError::authentication("Signature verification failed"))
    }

    /// Verify RS256 signature (RSA-PKCS1-v1_5 + SHA-256)
    fn verify_rs256(signed_data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        use rsa::BigUint;
        use rsa::{pkcs1v15::Pkcs1v15Sign, RsaPublicKey};
        use sha2::{Digest, Sha256};

        // Parse RSA public key
        let n = BigUint::from_bytes_be(public_key);
        let e = BigUint::from(65537u32);

        let public_key = RsaPublicKey::new(n, e)
            .map_err(|e| VaultError::crypto(format!("Invalid RSA public key: {}", e)))?;

        // Hash the data
        let hashed = Sha256::digest(signed_data);

        // Verify signature
        public_key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &hashed, signature)
            .map_err(|_| VaultError::authentication("Signature verification failed"))
    }

    /// Parse authenticator data
    pub fn parse_authenticator_data(data: &[u8]) -> Result<AuthenticatorData> {
        if data.len() < 37 {
            return Err(VaultError::validation("Authenticator data too short"));
        }

        // RP ID hash (32 bytes)
        let rp_id_hash = data[0..32].to_vec();

        // Flags (1 byte)
        let flags = data[32];

        // Sign count (4 bytes)
        let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);

        // Attested credential data (if AT flag is set)
        let attested_credential_data = if (flags & 0x40) != 0 {
            // Parse AAGUID (16 bytes)
            // Parse credential ID length (2 bytes)
            // Parse credential ID
            // Parse COSE public key
            // For simplicity, returning None here
            None
        } else {
            None
        };

        // Extensions (if ED flag is set)
        let extensions = if (flags & 0x80) != 0 {
            // Parse extensions
            None
        } else {
            None
        };

        Ok(AuthenticatorData {
            rp_id_hash,
            flags,
            sign_count,
            attested_credential_data,
            extensions,
        })
    }
}

/// COSE key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum CoseKeyType {
    OKP = 1,       // Octet Key Pair (EdDSA, X25519)
    EC2 = 2,       // Elliptic Curve Keys w/ x-y coordinate pair
    RSA = 3,       // RSA
    Symmetric = 4, // Symmetric keys
    HssLms = 5,    // HSS/LMS Hash-based signatures
    WalnutDSA = 6, // WalnutDSA
}

/// COSE algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum CoseAlgorithm {
    // ECDSA w/ SHA
    ES256 = -7,  // ECDSA w/ SHA-256
    ES384 = -35, // ECDSA w/ SHA-384
    ES512 = -36, // ECDSA w/ SHA-512

    // EdDSA
    EdDSA = -8, // EdDSA

    // RSASSA-PKCS1-v1_5
    RS256 = -257, // RSASSA-PKCS1-v1_5 w/ SHA-256
    RS384 = -258, // RSASSA-PKCS1-v1_5 w/ SHA-384
    RS512 = -259, // RSASSA-PKCS1-v1_5 w/ SHA-512

    // RSASSA-PSS
    PS256 = -37, // RSASSA-PSS w/ SHA-256
    PS384 = -38, // RSASSA-PSS w/ SHA-384
    PS512 = -39, // RSASSA-PSS w/ SHA-512
}

impl CoseAlgorithm {
    /// Get algorithm from i64 value
    pub fn from_i64(v: i64) -> Option<Self> {
        match v {
            -7 => Some(CoseAlgorithm::ES256),
            -35 => Some(CoseAlgorithm::ES384),
            -36 => Some(CoseAlgorithm::ES512),
            -8 => Some(CoseAlgorithm::EdDSA),
            -257 => Some(CoseAlgorithm::RS256),
            -258 => Some(CoseAlgorithm::RS384),
            -259 => Some(CoseAlgorithm::RS512),
            -37 => Some(CoseAlgorithm::PS256),
            -38 => Some(CoseAlgorithm::PS384),
            -39 => Some(CoseAlgorithm::PS512),
            _ => None,
        }
    }

    /// Get hash algorithm
    pub fn hash_algorithm(&self) -> &'static str {
        match self {
            CoseAlgorithm::ES256 | CoseAlgorithm::RS256 | CoseAlgorithm::PS256 => "SHA-256",
            CoseAlgorithm::ES384 | CoseAlgorithm::RS384 | CoseAlgorithm::PS384 => "SHA-384",
            CoseAlgorithm::ES512 | CoseAlgorithm::RS512 | CoseAlgorithm::PS512 => "SHA-512",
            CoseAlgorithm::EdDSA => "SHA-512", // Ed25519 uses SHA-512 internally
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_authenticator_data() {
        // Minimal authenticator data
        let mut data = vec![0u8; 37];
        // RP ID hash (first 32 bytes)
        for i in 0..32 {
            data[i] = i as u8;
        }
        // Flags (user present)
        data[32] = 0x01;
        // Sign count
        data[33..37].copy_from_slice(&[0, 0, 0, 42]);

        let auth_data = WebAuthnVerifier::parse_authenticator_data(&data).unwrap();
        assert_eq!(auth_data.rp_id_hash.len(), 32);
        assert_eq!(auth_data.flags, 0x01);
        assert_eq!(auth_data.sign_count, 42);
    }

    #[test]
    fn test_cose_algorithm_from_i64() {
        assert_eq!(CoseAlgorithm::from_i64(-7), Some(CoseAlgorithm::ES256));
        assert_eq!(CoseAlgorithm::from_i64(-8), Some(CoseAlgorithm::EdDSA));
        assert_eq!(CoseAlgorithm::from_i64(-257), Some(CoseAlgorithm::RS256));
        assert_eq!(CoseAlgorithm::from_i64(0), None);
    }
}
