//! Authorization Code Management
//!
//! This module handles the generation, storage, and validation of
//! OAuth 2.0 authorization codes with PKCE (Proof Key for Code Exchange)
//! support as defined in RFC 7636.
//!
//! Features:
//! - Secure random code generation (256-bit entropy)
//! - Code storage with expiration (default 10 minutes)
//! - PKCE S256 and plain method support
//! - Single-use codes (consumed on first use)
//! - Automatic cleanup of expired codes

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Authorization code entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCodeEntry {
    /// The authorization code (plaintext, only used for lookup)
    pub code: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Client ID
    pub client_id: String,
    /// User ID who authorized the request
    pub user_id: String,
    /// Redirect URI used in the authorization request
    pub redirect_uri: String,
    /// Granted scopes (space-separated)
    pub scope: Option<String>,
    /// PKCE code challenge
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (S256 or plain)
    pub code_challenge_method: Option<String>,
    /// Nonce for ID token validation
    pub nonce: Option<String>,
    /// When the code expires
    pub expires_at: DateTime<Utc>,
    /// When the code was created
    pub created_at: DateTime<Utc>,
    /// When the code was consumed (None if not yet used)
    pub consumed_at: Option<DateTime<Utc>>,
}

impl AuthorizationCodeEntry {
    /// Check if the code has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the code has been consumed
    pub fn is_consumed(&self) -> bool {
        self.consumed_at.is_some()
    }

    /// Check if the code is valid (not expired and not consumed)
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.is_consumed()
    }

    /// Mark the code as consumed
    pub fn consume(&mut self) {
        self.consumed_at = Some(Utc::now());
    }
}

/// Authorization code manager
#[derive(Debug, Clone)]
pub struct AuthorizationCodeManager {
    /// Code expiration duration (default: 10 minutes)
    expiration: Duration,
}

impl AuthorizationCodeManager {
    /// Create a new authorization code manager
    pub fn new() -> Self {
        Self {
            expiration: Duration::minutes(10),
        }
    }

    /// Create a manager with custom expiration
    pub fn with_expiration(minutes: i64) -> Self {
        Self {
            expiration: Duration::minutes(minutes),
        }
    }

    /// Generate a new authorization code
    /// 
    /// Returns a secure random code with 256-bit entropy (43 characters base64url)
    pub fn generate_code(&self) -> String {
        vault_core::crypto::generate_secure_random(32)
    }

    /// Calculate the expiration time for a new code
    pub fn expiration_time(&self) -> DateTime<Utc> {
        Utc::now() + self.expiration
    }

    /// Create a new authorization code entry
    pub fn create_code(
        &self,
        tenant_id: impl Into<String>,
        client_id: impl Into<String>,
        user_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: Option<String>,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
        nonce: Option<String>,
    ) -> AuthorizationCodeEntry {
        let code = self.generate_code();
        let now = Utc::now();

        AuthorizationCodeEntry {
            code,
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            user_id: user_id.into(),
            redirect_uri: redirect_uri.into(),
            scope,
            code_challenge,
            code_challenge_method,
            nonce,
            expires_at: self.expiration_time(),
            created_at: now,
            consumed_at: None,
        }
    }

    /// Validate a PKCE code verifier against a code challenge
    /// 
    /// Supports S256 (SHA-256 hash) and plain methods.
    /// 
    /// # Arguments
    /// * `verifier` - The code verifier from the token request
    /// * `challenge` - The code challenge from the authorization request
    /// * `method` - The code challenge method (S256 or plain)
    /// 
    /// # Returns
    /// `true` if the verifier matches the challenge
    pub fn verify_pkce(
        &self,
        verifier: &str,
        challenge: &str,
        method: &str,
    ) -> bool {
        match method.to_uppercase().as_str() {
            "S256" => {
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
                use sha2::Digest;
                use subtle::ConstantTimeEq;
                
                let digest = sha2::Sha256::digest(verifier.as_bytes());
                let computed = URL_SAFE_NO_PAD.encode(digest);
                // SECURITY: Use constant-time comparison to prevent timing attacks
                computed.as_bytes().ct_eq(challenge.as_bytes()).into()
            }
            "PLAIN" => {
                // SECURITY: Use constant-time comparison for plain method too
                use subtle::ConstantTimeEq;
                verifier.as_bytes().ct_eq(challenge.as_bytes()).into()
            }
            _ => false,
        }
    }

    /// Get the default code challenge method
    pub fn default_challenge_method() -> &'static str {
        "S256"
    }

    /// Generate a PKCE code challenge from a verifier
    /// 
    /// Returns both the challenge and the method used.
    pub fn generate_pkce_challenge(&self, verifier: &str) -> (String, String) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use sha2::Digest;
        
        let digest = sha2::Sha256::digest(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(digest);
        (challenge, "S256".to_string())
    }

    /// Generate a PKCE code verifier
    /// 
    /// Returns a secure random string suitable for use as a code verifier.
    /// The verifier should be between 43 and 128 characters.
    pub fn generate_pkce_verifier(&self) -> String {
        // Generate 32 bytes = 43 characters base64url
        vault_core::crypto::generate_secure_random(32)
    }
}

impl Default for AuthorizationCodeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// In-memory authorization code store (for testing and development)
/// 
/// In production, codes should be stored in a persistent database
/// with proper TTL support (e.g., Redis with EXPIRE).
#[derive(Debug, Clone)]
pub struct InMemoryCodeStore {
    codes: HashMap<String, AuthorizationCodeEntry>,
}

impl InMemoryCodeStore {
    /// Create a new in-memory code store
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
        }
    }

    /// Store an authorization code
    pub fn store(&mut self, entry: AuthorizationCodeEntry) {
        self.codes.insert(entry.code.clone(), entry);
    }

    /// Get an authorization code by its value
    /// 
    /// Returns None if the code doesn't exist, is expired, or has been consumed.
    pub fn get(&self, code: &str) -> Option<&AuthorizationCodeEntry> {
        self.codes.get(code).filter(|e| e.is_valid())
    }

    /// Consume an authorization code
    /// 
    /// Marks the code as used and returns the entry.
    /// Returns None if the code doesn't exist or is invalid.
    pub fn consume(&mut self, code: &str) -> Option<AuthorizationCodeEntry> {
        if let Some(entry) = self.codes.get_mut(code) {
            if entry.is_valid() {
                entry.consume();
                return Some(entry.clone());
            }
        }
        None
    }

    /// Remove expired and consumed codes
    pub fn cleanup(&mut self) {
        let now = Utc::now();
        self.codes.retain(|_, entry| {
            // Keep codes that haven't expired and haven't been consumed
            // or were consumed very recently (within last hour)
            if let Some(consumed_at) = entry.consumed_at {
                now - consumed_at < Duration::hours(1)
            } else {
                now < entry.expires_at
            }
        });
    }

    /// Get the number of stored codes
    pub fn len(&self) -> usize {
        self.codes.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.codes.is_empty()
    }
}

impl Default for InMemoryCodeStore {
    fn default() -> Self {
        Self::new()
    }
}

/// PKCE parameters for authorization requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkceParams {
    /// The code challenge
    pub code_challenge: String,
    /// The code challenge method (S256 or plain)
    pub code_challenge_method: String,
}

impl PkceParams {
    /// Create new PKCE parameters with S256 method
    pub fn new_s256(challenge: impl Into<String>) -> Self {
        Self {
            code_challenge: challenge.into(),
            code_challenge_method: "S256".to_string(),
        }
    }

    /// Create new PKCE parameters with plain method
    pub fn new_plain(challenge: impl Into<String>) -> Self {
        Self {
            code_challenge: challenge.into(),
            code_challenge_method: "plain".to_string(),
        }
    }

    /// Validate a code verifier against these parameters
    pub fn verify(&self, verifier: &str) -> bool {
        match self.code_challenge_method.as_str() {
            "S256" => {
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
                use sha2::Digest;
                
                let digest = sha2::Sha256::digest(verifier.as_bytes());
                let computed = URL_SAFE_NO_PAD.encode(digest);
                computed == self.code_challenge
            }
            "plain" => verifier == self.code_challenge,
            _ => false,
        }
    }
}

/// Authorization code request validation result
#[derive(Debug, Clone)]
pub enum CodeValidationResult {
    /// Code is valid
    Valid(AuthorizationCodeEntry),
    /// Code not found
    NotFound,
    /// Code has expired
    Expired,
    /// Code has already been used
    AlreadyUsed,
    /// Redirect URI doesn't match
    RedirectUriMismatch,
    /// PKCE verification failed
    InvalidPkce,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_generation() {
        let manager = AuthorizationCodeManager::new();
        let code = manager.generate_code();
        
        // Code should be 43 characters (256 bits base64url encoded)
        assert_eq!(code.len(), 43);
        
        // Code should be URL-safe
        assert!(!code.contains('+'));
        assert!(!code.contains('/'));
        assert!(!code.contains('='));
    }

    #[test]
    fn test_code_creation() {
        let manager = AuthorizationCodeManager::new();
        let entry = manager.create_code(
            "tenant-1",
            "client-1",
            "user-1",
            "https://example.com/callback",
            Some("openid profile".to_string()),
            Some("challenge123".to_string()),
            Some("S256".to_string()),
            Some("nonce456".to_string()),
        );

        assert_eq!(entry.tenant_id, "tenant-1");
        assert_eq!(entry.client_id, "client-1");
        assert_eq!(entry.user_id, "user-1");
        assert_eq!(entry.redirect_uri, "https://example.com/callback");
        assert_eq!(entry.scope, Some("openid profile".to_string()));
        assert!(entry.is_valid());
        assert!(!entry.is_expired());
        assert!(!entry.is_consumed());
    }

    #[test]
    fn test_code_expiration() {
        let manager = AuthorizationCodeManager::with_expiration(-1); // Already expired
        let entry = manager.create_code(
            "tenant-1",
            "client-1",
            "user-1",
            "https://example.com/callback",
            None,
            None,
            None,
            None,
        );

        assert!(entry.is_expired());
        assert!(!entry.is_valid());
    }

    #[test]
    fn test_code_consumption() {
        let mut entry = AuthorizationCodeEntry {
            code: "test-code".to_string(),
            tenant_id: "tenant-1".to_string(),
            client_id: "client-1".to_string(),
            user_id: "user-1".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            expires_at: Utc::now() + Duration::minutes(10),
            created_at: Utc::now(),
            consumed_at: None,
        };

        assert!(!entry.is_consumed());
        entry.consume();
        assert!(entry.is_consumed());
        assert!(!entry.is_valid());
    }

    #[test]
    fn test_pkce_verification_s256() {
        let manager = AuthorizationCodeManager::new();
        
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let (challenge, _) = manager.generate_pkce_challenge(verifier);
        
        assert!(manager.verify_pkce(verifier, &challenge, "S256"));
        assert!(!manager.verify_pkce("wrong-verifier", &challenge, "S256"));
    }

    #[test]
    fn test_pkce_verification_plain() {
        let manager = AuthorizationCodeManager::new();
        
        let verifier = "plain-verifier";
        let challenge = "plain-verifier";
        
        assert!(manager.verify_pkce(verifier, challenge, "plain"));
        assert!(!manager.verify_pkce("wrong", challenge, "plain"));
    }

    #[test]
    fn test_pkce_generation() {
        let manager = AuthorizationCodeManager::new();
        
        let verifier = manager.generate_pkce_verifier();
        let (challenge, method) = manager.generate_pkce_challenge(&verifier);
        
        assert_eq!(method, "S256");
        assert_eq!(challenge.len(), 43);
        assert!(manager.verify_pkce(&verifier, &challenge, &method));
    }

    #[test]
    fn test_in_memory_store() {
        let mut store = InMemoryCodeStore::new();
        let manager = AuthorizationCodeManager::new();
        
        let entry = manager.create_code(
            "tenant-1",
            "client-1",
            "user-1",
            "https://example.com/callback",
            None,
            None,
            None,
            None,
        );
        
        let code = entry.code.clone();
        store.store(entry);
        
        assert_eq!(store.len(), 1);
        assert!(store.get(&code).is_some());
        
        let consumed = store.consume(&code);
        assert!(consumed.is_some());
        assert!(store.get(&code).is_none());
    }

    #[test]
    fn test_pkce_params() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use sha2::Digest;
        
        let verifier = "test-verifier";
        let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
        
        let params = PkceParams::new_s256(&challenge);
        assert!(params.verify(verifier));
        assert!(!params.verify("wrong-verifier"));
        
        let plain_params = PkceParams::new_plain("plain-challenge");
        assert!(plain_params.verify("plain-challenge"));
        assert!(!plain_params.verify("wrong"));
    }
}
