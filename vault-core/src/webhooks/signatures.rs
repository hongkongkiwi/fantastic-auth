//! Webhook signature verification
//!
//! Implements HMAC-SHA256 signing for webhook payloads.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Signature prefix
const SIGNATURE_PREFIX: &str = "v1=";

/// Sign a payload with the given secret
pub fn sign_payload(payload: &str, secret: &str) -> Result<String, String> {
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| format!("Failed to create HMAC: {}", e))?;
    
    mac.update(payload.as_bytes());
    
    let result = mac.finalize();
    let signature = hex::encode(result.into_bytes());
    
    Ok(format!("{}{}", SIGNATURE_PREFIX, signature))
}

/// Verify a payload signature
pub fn verify_signature(payload: &str, secret: &str, signature: &str) -> Result<bool, String> {
    // Compute expected signature
    let expected = sign_payload(payload, secret)?;
    
    // Constant-time comparison to prevent timing attacks
    Ok(constant_time_eq::constant_time_eq(signature.as_bytes(), expected.as_bytes()))
}

/// Extract timestamp and signatures from signature header
pub fn parse_signature_header(header: &str) -> Option<(i64, Vec<String>)> {
    let parts: Vec<&str> = header.split(',').collect();
    
    let mut timestamp = None;
    let mut signatures = Vec::new();
    
    for part in parts {
        let kv: Vec<&str> = part.splitn(2, '=').collect();
        if kv.len() != 2 {
            continue;
        }
        
        match kv[0].trim() {
            "t" => {
                timestamp = kv[1].parse().ok();
            }
            "v1" => {
                signatures.push(kv[1].to_string());
            }
            _ => {}
        }
    }
    
    timestamp.map(|t| (t, signatures))
}

/// Build signed payload string for verification
pub fn build_signed_payload(timestamp: i64, payload: &str) -> String {
    format!("{}.{}", timestamp, payload)
}

/// Verify webhook payload with timestamp tolerance
pub fn verify_payload_with_tolerance(
    payload: &str,
    secret: &str,
    signature_header: &str,
    tolerance_seconds: i64,
) -> Result<bool, String> {
    let (timestamp, signatures) = parse_signature_header(signature_header)
        .ok_or("Invalid signature header format")?;
    
    // Check timestamp tolerance
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > tolerance_seconds {
        return Err("Timestamp outside tolerance window".to_string());
    }
    
    // Build signed payload
    let signed_payload = build_signed_payload(timestamp, payload);
    
    // Verify against all provided signatures
    for sig in signatures {
        if verify_signature(&signed_payload, secret, &format!("v1={}", sig))? {
            return Ok(true);
        }
    }
    
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sign_payload() {
        let secret = "whsec_fake_removed
        let payload = r#"{"id":"evt_123","type":"user.created"}"#;
        
        let signature = sign_payload(payload, secret).unwrap();
        
        // Should start with v1=
        assert!(signature.starts_with("v1="));
        
        // Should be hex
        let hex_part = &signature[3..];
        assert_eq!(hex_part.len(), 64); // SHA256 hex = 64 chars
        
        // Verify same payload produces same signature
        let signature2 = sign_payload(payload, secret).unwrap();
        assert_eq!(signature, signature2);
        
        // Different payload produces different signature
        let different_payload = r#"{"id":"evt_456","type":"user.deleted"}"#;
        let signature3 = sign_payload(different_payload, secret).unwrap();
        assert_ne!(signature, signature3);
    }
    
    #[test]
    fn test_verify_signature() {
        let secret = "whsec_fake_removed
        let payload = r#"{"id":"evt_123","type":"user.created"}"#;
        
        let signature = sign_payload(payload, secret).unwrap();
        
        // Valid signature
        assert!(verify_signature(payload, secret, &signature).unwrap());
        
        // Invalid secret
        assert!(!verify_signature(payload, "wrong_secret", &signature).unwrap());
        
        // Invalid signature format
        assert!(!verify_signature(payload, secret, "invalid").unwrap());
    }
    
    #[test]
    fn test_parse_signature_header() {
        let header = "t=1234567890,v1=abc123,v1=def456";
        
        let (timestamp, signatures) = parse_signature_header(header).unwrap();
        
        assert_eq!(timestamp, 1234567890);
        assert_eq!(signatures.len(), 2);
        assert_eq!(signatures[0], "abc123");
        assert_eq!(signatures[1], "def456");
    }
    
    #[test]
    fn test_parse_signature_header_invalid() {
        // No timestamp
        assert!(parse_signature_header("v1=abc123").is_none());
        
        // Empty header
        assert!(parse_signature_header("").is_none());
    }
    
    #[test]
    fn test_build_signed_payload() {
        let payload = r#"{"id":"evt_123"}"#;
        let signed = build_signed_payload(1234567890, payload);
        
        assert_eq!(signed, "1234567890.{\"id\":\"evt_123\"}");
    }
}
