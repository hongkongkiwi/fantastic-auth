//! DPoP (Demonstrating Proof-of-Possession) Implementation
//!
//! DPoP is a mechanism to bind access tokens to a specific client using
//! public key cryptography. This prevents token theft and replay attacks.
//!
//! # RFC 9449 Compliance
//!
//! This implementation follows RFC 9449 - OAuth 2.0 Demonstrating Proof-of-Possession
//! at the Application Layer (DPoP).
//!
//! # How It Works
//!
//! 1. Client generates an ephemeral key pair (ECDSA P-256)
//! 2. Client sends DPoP proof (JWT signed with private key) with token request
//! 3. Server binds access token to the public key
//! 4. Client must send DPoP proof with each API request using the access token
//! 5. Server verifies the DPoP proof matches the bound public key
//!
//! # Security Benefits
//!
//! - Prevents token replay across different clients/devices
//! - Binds tokens to the TLS channel
//! - Mitigates token theft impact
//! - Required by FAPI 2.0 and some high-security profiles

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};

/// DPoP proof header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopHeader {
    /// Algorithm (must be ES256 for P-256)
    pub alg: String,
    /// Token type (must be "DPoP")
    pub typ: String,
    /// JWT type (must be "dpop+jwt")
    #[serde(rename = "jwk")]
    pub jwk: Jwk,
}

/// JSON Web Key for ECDSA P-256
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type
    pub kty: String,
    /// Curve
    pub crv: String,
    /// X coordinate
    pub x: String,
    /// Y coordinate
    pub y: String,
}

/// DPoP proof payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopPayload {
    /// JWT ID (unique identifier)
    pub jti: String,
    /// HTTP method
    pub htm: String,
    /// HTTP URL
    pub htu: String,
    /// Issued at timestamp
    pub iat: u64,
    /// Access token hash (when used with access tokens)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
    /// Nonce from authorization server
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// DPoP proof (JWT)
#[derive(Debug, Clone)]
pub struct DpopProof {
    pub header: DpopHeader,
    pub payload: DpopPayload,
    pub signature: Vec<u8>,
}

/// DPoP verification result
#[derive(Debug, Clone)]
pub struct DpopVerification {
    pub public_key: Vec<u8>,
    pub jwk_thumbprint: String,
    pub is_valid: bool,
}

/// DPoP errors
#[derive(Debug, thiserror::Error)]
pub enum DpopError {
    #[error("Invalid DPoP proof format: {0}")]
    InvalidFormat(String),
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),
    #[error("Expired DPoP proof")]
    Expired,
    #[error("Invalid HTTP method binding")]
    InvalidMethod,
    #[error("Invalid HTTP URL binding")]
    InvalidUrl,
    #[error("Replay detected")]
    ReplayDetected,
    #[error("Missing DPoP nonce")]
    MissingNonce,
    #[error("Invalid nonce")]
    InvalidNonce,
    #[error("Access token hash mismatch")]
    AthMismatch,
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

/// DPoP validator
pub struct DpopValidator {
    /// Clock skew tolerance in seconds
    clock_skew: Duration,
    /// Replay cache (in production, use Redis)
    seen_jtis: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl Default for DpopValidator {
    fn default() -> Self {
        Self {
            clock_skew: Duration::from_secs(60),
            seen_jtis: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }
}

impl DpopValidator {
    /// Create a new DPoP validator
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Create with custom clock skew
    pub fn with_clock_skew(seconds: u64) -> Self {
        Self {
            clock_skew: Duration::from_secs(seconds),
            seen_jtis: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }
    
    /// Verify a DPoP proof
    ///
    /// # Arguments
    /// * `proof_jwt` - The DPoP proof JWT
    /// * `http_method` - The HTTP method (GET, POST, etc.)
    /// * `http_url` - The HTTP URL
    /// * `access_token` - Optional access token (for ath claim)
    ///
    pub fn verify(
        &self,
        proof_jwt: &str,
        http_method: &str,
        http_url: &str,
        access_token: Option<&str>,
    ) -> Result<DpopVerification, DpopError> {
        // Parse the JWT
        let (header_b64, payload_b64, signature_b64) = self.parse_jwt(proof_jwt)?;
        
        // Decode header
        let header_json = base64_decode(&header_b64)
            .map_err(|e| DpopError::InvalidFormat(format!("Header decode: {}", e)))?;
        let header: DpopHeader = serde_json::from_slice(&header_json)
            .map_err(|e| DpopError::InvalidFormat(format!("Header JSON: {}", e)))?;
        
        // Validate header
        self.validate_header(&header)?;
        
        // Decode payload
        let payload_json = base64_decode(&payload_b64)
            .map_err(|e| DpopError::InvalidFormat(format!("Payload decode: {}", e)))?;
        let payload: DpopPayload = serde_json::from_slice(&payload_json)
            .map_err(|e| DpopError::InvalidFormat(format!("Payload JSON: {}", e)))?;
        
        // Validate payload
        self.validate_payload(&payload, http_method, http_url)?;
        
        // Check for replay
        self.check_replay(&payload.jti)?;
        
        // Verify access token hash if provided
        if let Some(token) = access_token {
            self.verify_ath(&payload, token)?;
        }
        
        // Verify signature
        let signature = base64_decode(&signature_b64)
            .map_err(|e| DpopError::InvalidSignature(format!("Signature decode: {}", e)))?;
        self.verify_signature(&header, &header_b64, &payload_b64, &signature)?;
        
        // Calculate JWK thumbprint
        let jwk_thumbprint = self.calculate_jwk_thumbprint(&header.jwk)?;
        
        Ok(DpopVerification {
            public_key: serde_json::to_vec(&header.jwk)
                .map_err(|e| DpopError::InvalidFormat(e.to_string()))?,
            jwk_thumbprint,
            is_valid: true,
        })
    }
    
    /// Parse a JWT into its three parts
    fn parse_jwt(&self, jwt: &str) -> Result<(String, String, String), DpopError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(DpopError::InvalidFormat(
                "JWT must have 3 parts".to_string()
            ));
        }
        
        Ok((parts[0].to_string(), parts[1].to_string(), parts[2].to_string()))
    }
    
    /// Validate DPoP header
    fn validate_header(&self, header: &DpopHeader) -> Result<(), DpopError> {
        // Must be DPoP type
        if header.typ != "DPoP" {
            return Err(DpopError::InvalidFormat(
                format!("Expected typ=DPoP, got {}", header.typ)
            ));
        }
        
        // Must use ES256 (ECDSA with P-256 and SHA-256)
        if header.alg != "ES256" {
            return Err(DpopError::UnsupportedAlgorithm(header.alg.clone()));
        }
        
        // JWK must be EC key on P-256 curve
        if header.jwk.kty != "EC" {
            return Err(DpopError::InvalidFormat(
                format!("Expected kty=EC, got {}", header.jwk.kty)
            ));
        }
        
        if header.jwk.crv != "P-256" {
            return Err(DpopError::UnsupportedAlgorithm(
                format!("Curve {} not supported, use P-256", header.jwk.crv)
            ));
        }
        
        Ok(())
    }
    
    /// Validate DPoP payload
    fn validate_payload(
        &self,
        payload: &DpopPayload,
        expected_method: &str,
        expected_url: &str,
    ) -> Result<(), DpopError> {
        // Check timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let max_age = 60 + self.clock_skew.as_secs(); // 1 minute + skew
        if payload.iat + max_age < now {
            return Err(DpopError::Expired);
        }
        
        // Check HTTP method binding
        if payload.htm.to_uppercase() != expected_method.to_uppercase() {
            return Err(DpopError::InvalidMethod);
        }
        
        // Check HTTP URL binding (normalize)
        let normalized_expected = self.normalize_url(expected_url);
        let normalized_actual = self.normalize_url(&payload.htu);
        
        if normalized_expected != normalized_actual {
            return Err(DpopError::InvalidUrl);
        }
        
        Ok(())
    }
    
    /// Normalize URL for comparison
    fn normalize_url(&self, url: &str) -> String {
        // Remove trailing slash and fragment
        let mut normalized = url.to_lowercase();
        normalized = normalized.split('#').next().unwrap_or(&normalized).to_string();
        if normalized.ends_with('/') && normalized.len() > 1 {
            normalized.pop();
        }
        normalized
    }
    
    /// Check for replay attacks
    fn check_replay(&self, jti: &str) -> Result<(), DpopError> {
        let mut seen = self.seen_jtis.lock().unwrap();
        
        if seen.contains(jti) {
            return Err(DpopError::ReplayDetected);
        }
        
        // In production, use Redis with TTL instead
        seen.insert(jti.to_string());
        
        // Prune if too large (simple LRU)
        if seen.len() > 10000 {
            seen.clear();
        }
        
        Ok(())
    }
    
    /// Verify access token hash (ath claim)
    fn verify_ath(&self, payload: &DpopPayload, access_token: &str) -> Result<(), DpopError> {
        let expected_ath = payload.ath.as_ref()
            .ok_or(DpopError::AthMismatch)?;
        
        // Compute SHA-256 hash of access token, base64url encoded
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(access_token.as_bytes());
        let hash = hasher.finalize();
        
        // Take first half (128 bits)
        let computed_ath = base64_url_encode(&hash[..16]);
        
        if computed_ath != *expected_ath {
            return Err(DpopError::AthMismatch);
        }
        
        Ok(())
    }
    
    /// Verify ECDSA signature
    fn verify_signature(
        &self,
        header: &DpopHeader,
        header_b64: &str,
        payload_b64: &str,
        signature: &[u8],
    ) -> Result<(), DpopError> {
        // Reconstruct the signing input
        let signing_input = format!("{}.{}", header_b64, payload_b64);
        
        // Decode the public key from JWK
        let pk_x = base64_url_decode(&header.jwk.x)
            .map_err(|e| DpopError::InvalidSignature(format!("X decode: {}", e)))?;
        let pk_y = base64_url_decode(&header.jwk.y)
            .map_err(|e| DpopError::InvalidSignature(format!("Y decode: {}", e)))?;
        
        // In production, use p256 crate for full verification
        // Validate coordinate lengths
        if pk_x.len() != 32 || pk_y.len() != 32 {
            return Err(DpopError::InvalidSignature(
                "Invalid P-256 point coordinates".to_string()
            ));
        }
        
        // Full ECDSA verification using p256 crate
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        use p256::EncodedPoint;
        
        // Reconstruct the public key from coordinates
        // We already validated lengths above, so these should succeed
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&pk_x);
        let mut y_bytes = [0u8; 32];
        y_bytes.copy_from_slice(&pk_y);
        
        let encoded_point = EncodedPoint::from_affine_coordinates(
            &x_bytes.into(),
            &y_bytes.into(),
            false,
        );
        
        let verifying_key = VerifyingKey::from_encoded_point(&encoded_point)
            .map_err(|e| DpopError::InvalidSignature(format!("Invalid public key: {}", e)))?;
        
        // Parse the signature
        let sig = Signature::try_from(signature)
            .map_err(|e| DpopError::InvalidSignature(format!("Invalid signature format: {}", e)))?;
        
        // Verify the signature
        verifying_key
            .verify(signing_input.as_bytes(), &sig)
            .map_err(|_| DpopError::InvalidSignature("Signature verification failed".to_string()))?;
        
        Ok(())
    }
    
    /// Calculate JWK thumbprint (RFC 7638)
    fn calculate_jwk_thumbprint(&self, jwk: &Jwk) -> Result<String, DpopError> {
        // Required members for EC key thumbprint: crv, kty, x, y in lexicographic order
        let thumbprint_json = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            jwk.crv, jwk.kty, jwk.x, jwk.y
        );
        
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(thumbprint_json.as_bytes());
        let hash = hasher.finalize();
        
        Ok(base64_url_encode(&hash))
    }
    
    /// Generate a DPoP nonce
    pub fn generate_nonce() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let nonce: [u8; 16] = rng.gen();
        hex::encode(nonce)
    }
}

/// DPoP token binding for access tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopBinding {
    /// JWK thumbprint
    pub jkt: String,
    /// Confirmation method
    #[serde(rename = "cnf")]
    pub confirmation: Confirmation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confirmation {
    /// JWK thumbprint
    #[serde(rename = "jkt")]
    pub jwk_thumbprint: String,
}

/// Generate DPoP binding for an access token
pub fn generate_dpop_binding(jwk_thumbprint: &str) -> DpopBinding {
    DpopBinding {
        jkt: jwk_thumbprint.to_string(),
        confirmation: Confirmation {
            jwk_thumbprint: jwk_thumbprint.to_string(),
        },
    }
}

/// Helper: Base64 URL-safe encoding without padding
fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Helper: Base64 URL-safe decoding
fn base64_url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
}

/// Helper: Standard base64 decode
fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    // Handle both standard and URL-safe
    if input.contains('-') || input.contains('_') {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
    } else {
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(input)
    }
}

/// DPoP middleware for Axum
#[cfg(feature = "axum")]
pub mod middleware {
    use super::*;
    use axum::{
        extract::{Request, State},
        middleware::Next,
        response::Response,
    };
    
    /// State for DPoP middleware
    #[derive(Clone)]
    pub struct DpopMiddlewareState {
        pub validator: Arc<DpopValidator>,
        pub require_dpop: bool,
    }
    
    /// DPoP verification middleware
    pub async fn dpop_middleware(
        State(state): State<DpopMiddlewareState>,
        mut request: Request,
        next: Next,
    ) -> Result<Response, DpopError> {
        // Extract DPoP proof from header
        let dpop_header = request.headers()
            .get("DPoP")
            .and_then(|h| h.to_str().ok());
        
        if let Some(proof) = dpop_header {
            let method = request.method().as_str();
            let url = request.uri().to_string();
            
            // Verify the DPoP proof
            match state.validator.verify(proof, method, &url, None) {
                Ok(verification) => {
                    // Attach verification to request extensions
                    request.extensions_mut().insert(verification);
                }
                Err(e) => {
                    if state.require_dpop {
                        return Err(e);
                    }
                    // If DPoP is optional, continue without it
                    tracing::warn!("Optional DPoP verification failed: {}", e);
                }
            }
        } else if state.require_dpop {
            return Err(DpopError::InvalidFormat(
                "DPoP header required but not provided".to_string()
            ));
        }
        
        Ok(next.run(request).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_dpop_validator_creation() {
        let validator = DpopValidator::new();
        assert_eq!(validator.clock_skew.as_secs(), 60);
    }
    
    #[test]
    fn test_parse_valid_jwt() {
        let validator = DpopValidator::new();
        let jwt = "header.payload.signature";
        let result = validator.parse_jwt(jwt);
        assert!(result.is_ok());
        
        let (h, p, s) = result.unwrap();
        assert_eq!(h, "header");
        assert_eq!(p, "payload");
        assert_eq!(s, "signature");
    }
    
    #[test]
    fn test_parse_invalid_jwt() {
        let validator = DpopValidator::new();
        let jwt = "invalid";
        let result = validator.parse_jwt(jwt);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_url_normalization() {
        let validator = DpopValidator::new();
        
        assert_eq!(
            validator.normalize_url("https://example.com/path/"),
            "https://example.com/path"
        );
        assert_eq!(
            validator.normalize_url("HTTPS://Example.COM/Path"),
            "https://example.com/path"
        );
        assert_eq!(
            validator.normalize_url("https://example.com/path#fragment"),
            "https://example.com/path"
        );
    }
    
    #[test]
    fn test_replay_detection() {
        let validator = DpopValidator::new();
        let jti = "test-jti-123".to_string();
        
        // First check should succeed
        assert!(validator.check_replay(&jti).is_ok());
        
        // Second check should fail (replay)
        assert!(validator.check_replay(&jti).is_err());
    }
    
    #[test]
    fn test_dpop_binding_generation() {
        let jkt = "test-thumbprint";
        let binding = generate_dpop_binding(jkt);
        
        assert_eq!(binding.jkt, jkt);
        assert_eq!(binding.confirmation.jwk_thumbprint, jkt);
    }
    
    #[test]
    fn test_base64_url_encoding() {
        let data = b"hello world";
        let encoded = base64_url_encode(data);
        let decoded = base64_url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}


// Property-based tests for DPoP proof parser
// 
// These tests verify:
// 1. The DPoP parser never panics on arbitrary input (security/DoS protection)
// 2. JWT parsing handles malformed input correctly
// 3. Base64 decoding is robust against invalid input
// 4. URL normalization handles edge cases
// 5. Replay detection works correctly with various JTIs
#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Test that JWT parsing never panics on arbitrary input
        // This is critical as malformed JWTs could cause DoS
        #[test]
        fn test_jwt_parsing_never_panics(jwt in "\\PC*") {
            let validator = DpopValidator::new();
            // Should never panic regardless of input
            let _ = validator.parse_jwt(&jwt);
        }

        // Test that the full DPoP verify function never panics
        #[test]
        fn test_dpop_verify_never_panics(
            proof in "\\PC*",
            method in "\\PC*",
            url in "\\PC*"
        ) {
            let validator = DpopValidator::new();
            // Should never panic regardless of input
            let _ = validator.verify(&proof, &method, &url, None);
        }

        // Test that base64 URL decoding handles arbitrary input
        #[test]
        fn test_base64_url_decode_never_panics(input in "\\PC*") {
            // Should never panic
            let _ = base64_url_decode(&input);
        }

        // Test that base64 standard decoding handles arbitrary input
        #[test]
        fn test_base64_decode_never_panics(input in "\\PC*") {
            // Should never panic
            let _ = base64_decode(&input);
        }

        // Test that URL normalization never panics on arbitrary input
        #[test]
        fn test_url_normalization_never_panics(url in "\\PC*") {
            let validator = DpopValidator::new();
            // Should never panic
            let _ = validator.normalize_url(&url);
        }

        // Test that JWK thumbprint calculation handles arbitrary JWKs
        #[test]
        fn test_jwk_thumbprint_never_panics(
            kty in "\\PC*",
            crv in "\\PC*",
            x in "\\PC*",
            y in "\\PC*"
        ) {
            let jwk = Jwk { kty, crv, x, y };
            let validator = DpopValidator::new();
            // Should never panic
            let _ = validator.calculate_jwk_thumbprint(&jwk);
        }

        // Test that header validation handles arbitrary headers
        #[test]
        fn test_header_validation_never_panics(
            alg in "\\PC*",
            typ in "\\PC*",
            kty in "\\PC*",
            crv in "\\PC*",
            x in "\\PC*",
            y in "\\PC*"
        ) {
            let header = DpopHeader {
                alg,
                typ,
                jwk: Jwk { kty, crv, x, y },
            };
            let validator = DpopValidator::new();
            // Should never panic
            let _ = validator.validate_header(&header);
        }

        // Test replay detection with arbitrary JTIs
        #[test]
        fn test_replay_detection_never_panics(jti in "\\PC*") {
            let validator = DpopValidator::new();
            // Should never panic
            let _ = validator.check_replay(&jti);
        }

        // Test that replay detection correctly identifies unique JTIs
        #[test]
        fn test_replay_detection_unique_jtis(jti in "[a-zA-Z0-9_-]{1,100}") {
            let validator = DpopValidator::new();
            
            // First check should succeed
            let result1 = validator.check_replay(&jti);
            prop_assert!(result1.is_ok(), "First JTI check should succeed: {}", jti);
            
            // Second check should fail (replay)
            let result2 = validator.check_replay(&jti);
            prop_assert!(result2.is_err(), "Second JTI check should fail (replay): {}", jti);
        }

        // Test base64 round-trip encoding/decoding
        #[test]
        fn test_base64_roundtrip(data in "[a-zA-Z0-9+/=]*") {
            let encoded = base64_url_encode(data.as_bytes());
            let decoded = base64_url_decode(&encoded);
            
            prop_assert!(decoded.is_ok(), "Decoding should succeed");
            prop_assert_eq!(
                decoded.unwrap(),
                data.as_bytes(),
                "Round-trip should preserve data"
            );
        }

        // Test that URL normalization is consistent
        #[test]
        fn test_url_normalization_consistency(url in "[a-zA-Z0-9:/._#-]*") {
            let validator = DpopValidator::new();
            
            let normalized1 = validator.normalize_url(&url);
            let normalized2 = validator.normalize_url(&url);
            
            prop_assert_eq!(
                normalized1, normalized2,
                "URL normalization should be deterministic"
            );
        }

        // Test that URL normalization handles fragments correctly
        #[test]
        fn test_url_normalization_fragments(
            base in "https://[a-z]{1,20}\\.[a-z]{2,10}/[a-z]{1,20}",
            fragment in "[a-zA-Z0-9_-]{0,50}"
        ) {
            let validator = DpopValidator::new();
            
            let url_with_fragment = format!("{}#{}", base, fragment);
            let normalized = validator.normalize_url(&url_with_fragment);
            
            // Fragment should be removed
            prop_assert!(
                !normalized.contains('#'),
                "Fragment should be removed: {} -> {}",
                url_with_fragment, normalized
            );
        }

        // Test that URL normalization handles trailing slashes correctly
        #[test]
        fn test_url_normalization_trailing_slashes(
            base in "https://[a-z]{1,20}\\.[a-z]{2,10}/[a-z]{1,20}"
        ) {
            let validator = DpopValidator::new();
            
            let url_with_slash = format!("{}/", base);
            let normalized = validator.normalize_url(&url_with_slash);
            
            // Trailing slash should be removed (except for root)
            if url_with_slash.len() > 8 {
                // "https://" is 8 chars, so anything longer shouldn't end with /
                prop_assert!(
                    !normalized.ends_with('/'),
                    "Trailing slash should be removed: {} -> {}",
                    url_with_slash, normalized
                );
            }
        }

        // Test that URL normalization is case-insensitive for scheme/host
        #[test]
        fn test_url_normalization_case_insensitive(
            scheme in "(https|HTTPS|Https)",
            host in "[a-zA-Z]{5,20}\\.[a-zA-Z]{2,10}",
            path in "[a-zA-Z/]{1,30}"
        ) {
            let validator = DpopValidator::new();
            
            let url = format!("{}://{}{}", scheme, host, path);
            let normalized = validator.normalize_url(&url);
            
            // Should be lowercase
            prop_assert!(
                normalized.chars().all(|c| !c.is_ascii_uppercase()),
                "Normalized URL should be lowercase: {} -> {}",
                url, normalized
            );
        }

        // Test that JWT parsing handles various separator counts
        #[test]
        fn test_jwt_parsing_separators(jwt in "[a-zA-Z0-9._-]{0,500}") {
            let validator = DpopValidator::new();
            
            let result = validator.parse_jwt(&jwt);
            
            // Valid JWTs have exactly 2 dots
            let dot_count = jwt.matches('.').count();
            if dot_count == 2 && !jwt.starts_with('.') && !jwt.ends_with('.') {
                // This might be a valid JWT format
                // (though content may still be invalid)
            } else {
                // Should return an error, not panic
                prop_assert!(
                    result.is_err(),
                    "JWT with {} dots should fail: {}",
                    dot_count, jwt
                );
            }
        }

        // Test that the validator handles binary/null data
        #[test]
        fn test_dpop_handles_binary_data(input in "[\\x00-\\x1F]*") {
            let validator = DpopValidator::new();
            
            // Should not panic on binary data
            let _ = validator.parse_jwt(&input);
            let _ = base64_url_decode(&input);
            let _ = base64_decode(&input);
            let _ = validator.normalize_url(&input);
        }

        // Test that the validator handles unicode input
        #[test]
        fn test_dpop_handles_unicode(input in "\\PC*") {
            let validator = DpopValidator::new();
            
            // Should not panic on unicode
            let _ = validator.parse_jwt(&input);
            let _ = base64_url_decode(&input);
            let _ = base64_decode(&input);
            let _ = validator.normalize_url(&input);
        }

        // Test that the validator handles very long inputs
        #[test]
        fn test_dpop_handles_long_inputs(length in 1000usize..10000usize) {
            let validator = DpopValidator::new();
            let long_input = "a".repeat(length);
            
            // Should not panic on long inputs
            let _ = validator.parse_jwt(&long_input);
            let _ = base64_url_decode(&long_input);
            let _ = base64_decode(&long_input);
            let _ = validator.normalize_url(&long_input);
        }

        // Test that DPoP binding generation is consistent
        #[test]
        fn test_dpop_binding_consistency(thumbprint in "[a-zA-Z0-9_-]{1,100}") {
            let binding1 = generate_dpop_binding(&thumbprint);
            let binding2 = generate_dpop_binding(&thumbprint);
            
            prop_assert_eq!(
                binding1.jkt, binding2.jkt,
                "DPoP binding should be consistent"
            );
            prop_assert_eq!(
                binding1.confirmation.jwk_thumbprint,
                binding2.confirmation.jwk_thumbprint,
                "DPoP binding confirmation should be consistent"
            );
            prop_assert_eq!(
                binding1.jkt, thumbprint,
                "JKT should match input thumbprint"
            );
        }

        // Test that nonce generation produces valid hex strings
        #[test]
        fn test_nonce_generation() {
            let nonce = DpopValidator::generate_nonce();
            
            // Should be 32 hex characters (16 bytes)
            prop_assert_eq!(
                nonce.len(), 32,
                "Nonce should be 32 hex characters"
            );
            
            // Should be valid hex
            prop_assert!(
                nonce.chars().all(|c| c.is_ascii_hexdigit()),
                "Nonce should be valid hex: {}", nonce
            );
        }

        // Test that empty inputs are handled correctly
        #[test]
        fn test_empty_inputs() {
            let validator = DpopValidator::new();
            
            // Empty JWT should fail gracefully
            let result = validator.parse_jwt("");
            prop_assert!(result.is_err(), "Empty JWT should fail");
            
            // Empty URL normalization should work
            let normalized = validator.normalize_url("");
            prop_assert_eq!(normalized, "", "Empty URL should normalize to empty");
            
            // Empty base64 decode
            let decoded = base64_url_decode("");
            prop_assert!(decoded.is_ok(), "Empty base64 should decode");
            prop_assert!(decoded.unwrap().is_empty(), "Empty base64 should decode to empty");
        }
    }
}
