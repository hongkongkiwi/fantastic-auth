//! Web3 signature verification
//!
//! Supports:
//! - EVM (Ethereum) signatures (EIP-191 personal sign)
//! - Solana signatures (Ed25519)
//!
//! Uses pure Rust libraries:
//! - `k256` for Ethereum ECDSA signature verification
//! - `ed25519-dalek` for Solana signatures

use crate::auth::web3::siwe::{normalize_address, ChainType, SiweError};
use k256::ecdsa::{self, VerifyingKey};
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// Errors that can occur during signature verification
#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("Invalid signature format: {0}")]
    InvalidFormat(String),
    #[error("Signature verification failed: {0}")]
    VerificationFailed(String),
    #[error("Invalid chain type: {0}")]
    InvalidChainType(String),
    #[error("SIWE error: {0}")]
    SiweError(#[from] SiweError),
    #[error("ECDSA error: {0}")]
    EcdsaError(String),
    #[error("Ed25519 error: {0}")]
    Ed25519Error(String),
}

/// Signature format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFormat {
    /// Ethereum personal sign (EIP-191)
    EthereumPersonalSign,
    /// Raw ECDSA signature
    RawEcdsa,
    /// Solana Ed25519 signature
    Solana,
}

/// Verify an Ethereum (EVM) signature
///
/// The signature should be in the format:
/// - 65 bytes: r (32) + s (32) + v (1)
/// - Or as a hex string: "0x{r}{s}{v}"
///
/// # Arguments
/// * `message` - The message that was signed (UTF-8 string)
/// * `signature` - The signature in hex format (with or without 0x prefix)
/// * `expected_address` - The expected Ethereum address
///
/// # Returns
/// * `Ok(true)` if signature is valid
/// * `Ok(false)` if signature is invalid
/// * `Err(SignatureError)` if there's a format error
pub fn verify_ethereum_signature(
    message: &str,
    signature: &str,
    expected_address: &str,
) -> Result<bool, SignatureError> {
    // Normalize expected address
    let expected_address = normalize_address(expected_address)?;

    // Parse signature
    let sig_bytes = parse_hex_signature(signature)?;

    if sig_bytes.len() != 65 {
        return Err(SignatureError::InvalidFormat(format!(
            "Invalid signature length: expected 65, got {}",
            sig_bytes.len()
        )));
    }

    // Extract r, s, v
    let r = &sig_bytes[0..32];
    let s = &sig_bytes[32..64];
    let v = sig_bytes[64];

    // Normalize v (can be 27/28 or 0/1)
    let recovery_id = match v {
        27 | 28 => v - 27,
        0 | 1 => v,
        _ => {
            return Err(SignatureError::InvalidFormat(format!(
                "Invalid recovery id (v): {}",
                v
            )))
        }
    };

    // Create Ethereum personal sign message prefix
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut full_message = prefix.into_bytes();
    full_message.extend_from_slice(message.as_bytes());

    // Hash the message with Keccak-256
    let message_hash = keccak256(&full_message);

    // Recover public key from signature
    let r_arr: [u8; 32] = r.try_into().map_err(|_| SignatureError::InvalidFormat("Invalid r component".to_string()))?;
    let s_arr: [u8; 32] = s.try_into().map_err(|_| SignatureError::InvalidFormat("Invalid s component".to_string()))?;
    let sig = ecdsa::Signature::from_scalars(r_arr, s_arr)
        .map_err(|e| SignatureError::EcdsaError(format!("{:?}", e)))?;

    let rec_id = ecdsa::RecoveryId::try_from(recovery_id as u8)
        .map_err(|e| SignatureError::EcdsaError(format!("{:?}", e)))?;

    // Recover the verifying key
    let verifying_key = VerifyingKey::recover_from_prehash(&message_hash, &sig, rec_id)
        .map_err(|e| SignatureError::VerificationFailed(format!("{:?}", e)))?;

    // Derive Ethereum address from public key
    let public_key_bytes = verifying_key.to_encoded_point(false);
    let public_key_uncompressed = public_key_bytes.as_bytes();

    // Skip the 0x04 prefix and hash the remaining 64 bytes
    let address_hash = keccak256(&public_key_uncompressed[1..]);
    let recovered_address = format!("0x{}", hex::encode(&address_hash[12..]));

    // Compare addresses (case-insensitive)
    Ok(recovered_address.to_lowercase() == expected_address.to_lowercase())
}

/// Verify a raw ECDSA signature (without Ethereum prefix)
///
/// # Arguments
/// * `message_hash` - The 32-byte message hash
/// * `signature` - The signature in hex format
/// * `expected_address` - The expected Ethereum address
pub fn verify_raw_ecdsa_signature(
    message_hash: &[u8],
    signature: &str,
    expected_address: &str,
) -> Result<bool, SignatureError> {
    // Normalize expected address
    let expected_address = normalize_address(expected_address)?;

    // Parse signature
    let sig_bytes = parse_hex_signature(signature)?;

    if sig_bytes.len() != 65 {
        return Err(SignatureError::InvalidFormat(format!(
            "Invalid signature length: expected 65, got {}",
            sig_bytes.len()
        )));
    }

    // Extract r, s, v
    let r = &sig_bytes[0..32];
    let s = &sig_bytes[32..64];
    let v = sig_bytes[64];

    // Normalize v
    let recovery_id = match v {
        27 | 28 => v - 27,
        0 | 1 => v,
        _ => {
            return Err(SignatureError::InvalidFormat(format!(
                "Invalid recovery id (v): {}",
                v
            )))
        }
    };

    // Recover public key
    let r_arr: [u8; 32] = r.try_into().map_err(|_| SignatureError::InvalidFormat("Invalid r component".to_string()))?;
    let s_arr: [u8; 32] = s.try_into().map_err(|_| SignatureError::InvalidFormat("Invalid s component".to_string()))?;
    let sig = ecdsa::Signature::from_scalars(r_arr, s_arr)
        .map_err(|e| SignatureError::EcdsaError(format!("{:?}", e)))?;

    let rec_id = ecdsa::RecoveryId::try_from(recovery_id as u8)
        .map_err(|e| SignatureError::EcdsaError(format!("{:?}", e)))?;

    let verifying_key = VerifyingKey::recover_from_prehash(message_hash, &sig, rec_id)
        .map_err(|e| SignatureError::VerificationFailed(format!("{:?}", e)))?;

    // Derive Ethereum address
    let public_key_bytes = verifying_key.to_encoded_point(false);
    let public_key_uncompressed = public_key_bytes.as_bytes();
    let address_hash = keccak256(&public_key_uncompressed[1..]);
    let recovered_address = format!("0x{}", hex::encode(&address_hash[12..]));

    Ok(recovered_address.to_lowercase() == expected_address.to_lowercase())
}

/// Verify a Solana (Ed25519) signature
///
/// # Arguments
/// * `message` - The message that was signed
/// * `signature` - The 64-byte Ed25519 signature in hex format
/// * `public_key` - The 32-byte Ed25519 public key in hex format
pub fn verify_solana_signature(
    message: &[u8],
    signature: &str,
    public_key: &str,
) -> Result<bool, SignatureError> {
    use ed25519_dalek::{Signature as EdSignature, VerifyingKey as EdVerifyingKey};

    // Parse signature (64 bytes for Ed25519)
    let sig_bytes = parse_hex_signature(signature)?;

    if sig_bytes.len() != 64 {
        return Err(SignatureError::InvalidFormat(format!(
            "Invalid Ed25519 signature length: expected 64, got {}",
            sig_bytes.len()
        )));
    }

    // Parse public key (32 bytes for Ed25519)
    let pk_bytes = parse_hex_signature(public_key)?;

    if pk_bytes.len() != 32 {
        return Err(SignatureError::InvalidFormat(format!(
            "Invalid Ed25519 public key length: expected 32, got {}",
            pk_bytes.len()
        )));
    }

    // Create signature and verifying key
    let signature = EdSignature::from_slice(&sig_bytes)
        .map_err(|e| SignatureError::Ed25519Error(format!("{:?}", e)))?;

    let verifying_key = EdVerifyingKey::from_bytes(&pk_bytes.try_into().map_err(|_| {
        SignatureError::Ed25519Error("Failed to convert public key bytes".to_string())
    })?)
    .map_err(|e| SignatureError::Ed25519Error(format!("{:?}", e)))?;

    // Verify signature
    Ok(verifying_key.verify_strict(message, &signature).is_ok())
}

/// Verify a signature based on chain type
pub fn verify_signature(
    chain_type: ChainType,
    message: &str,
    signature: &str,
    address: &str,
) -> Result<bool, SignatureError> {
    match chain_type {
        ChainType::Ethereum
        | ChainType::Polygon
        | ChainType::Arbitrum
        | ChainType::Optimism
        | ChainType::Base
        | ChainType::Avalanche
        | ChainType::Bsc => verify_ethereum_signature(message, signature, address),
        ChainType::Solana => verify_solana_signature(message.as_bytes(), signature, address),
    }
}

/// Parse a hex signature (with or without 0x prefix)
fn parse_hex_signature(signature: &str) -> Result<Vec<u8>, SignatureError> {
    let sig = signature.trim().trim_start_matches("0x");

    hex::decode(sig)
        .map_err(|e| SignatureError::InvalidFormat(format!("Invalid hex: {}", e)))
}

/// Compute Keccak-256 hash
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Convert an Ethereum address to checksum format (EIP-55)
pub fn to_checksum_address(address: &str) -> Result<String, SignatureError> {
    let normalized = normalize_address(address)?;
    let addr = normalized.trim_start_matches("0x").to_lowercase();

    // Hash the lowercase address
    let hash = keccak256(addr.as_bytes());
    let hash_hex = hex::encode(hash);

    // Apply checksum
    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (i, c) in addr.chars().enumerate() {
        let hash_char = hash_hex.chars().nth(i).unwrap_or('0');
        let hash_nibble = hash_char.to_digit(16).unwrap_or(0);

        if hash_nibble >= 8 {
            result.push(c.to_ascii_uppercase());
        } else {
            result.push(c);
        }
    }

    Ok(result)
}

/// Check if a string is a valid Ethereum address
pub fn is_valid_ethereum_address(address: &str) -> bool {
    super::siwe::validate_evm_address(address).is_ok()
}

/// Check if a string is a valid Solana address
pub fn is_valid_solana_address(address: &str) -> bool {
    // Solana addresses are base58-encoded and 32 bytes
    match bs58::decode(address).into_vec() {
        Ok(bytes) => bytes.len() == 32,
        Err(_) => false,
    }
}

/// Detect address type from format
pub fn detect_address_type(address: &str) -> Option<ChainType> {
    if is_valid_ethereum_address(address) {
        Some(ChainType::Ethereum)
    } else if is_valid_solana_address(address) {
        Some(ChainType::Solana)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_signature() {
        let hex = "0x1234abcd";
        let result = parse_hex_signature(hex).unwrap();
        assert_eq!(result, vec![0x12, 0x34, 0xab, 0xcd]);

        let no_prefix = "1234abcd";
        let result2 = parse_hex_signature(no_prefix).unwrap();
        assert_eq!(result2, vec![0x12, 0x34, 0xab, 0xcd]);
    }

    #[test]
    fn test_to_checksum_address() {
        let lowercase = "0xeefca179f39baceb1e833c0fd6f3de13b74f3e73";
        let checksum = to_checksum_address(lowercase).unwrap();
        // The checksum should have mixed case
        assert_ne!(checksum, lowercase);
        assert!(checksum.contains("0x"));
    }

    #[test]
    fn test_is_valid_ethereum_address() {
        assert!(is_valid_ethereum_address(
            "0x1234567890123456789012345678901234567890"
        ));
        assert!(!is_valid_ethereum_address("0xINVALID"));
        assert!(!is_valid_ethereum_address(""));
    }

    #[test]
    fn test_keccak256() {
        let data = b"hello world";
        let hash = keccak256(data);
        assert_eq!(hash.len(), 32);

        // Known test vector
        let empty_hash = keccak256(b"");
        assert_eq!(
            hex::encode(empty_hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }
}
