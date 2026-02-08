//! JWT implementation with hybrid post-quantum signatures
//!
//! This module implements JWT signing using a hybrid approach:
//! - Ed25519 for classical security
//! - ML-DSA-65 for post-quantum security
//!
//! The token format is compatible with standard JWT but uses custom
//! algorithm identifiers for the hybrid scheme.

use crate::error::{Result, VaultError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{HybridSignature, HybridSigningKey, HybridVerifyingKey};

/// Step-up authentication levels
///
/// These levels represent different assurance levels for authentication
/// based on the NIST Digital Identity Guidelines and OpenID Connect ACR values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpLevel {
    /// No authentication (anonymous)
    None,
    /// Standard authentication (username/password)
    Standard,
    /// Elevated authentication (password + additional verification)
    Elevated,
    /// High assurance authentication (multi-factor with hardware token)
    HighAssurance,
}

impl StepUpLevel {
    /// Get the ACR (Authentication Context Class Reference) value
    ///
    /// Standard ACR values per OpenID Connect:
    /// - 0: No authentication
    /// - 1: Username/password
    /// - 2: Two-factor authentication
    /// - 3: Multi-factor with hardware token
    pub fn acr_value(&self) -> u8 {
        match self {
            StepUpLevel::None => 0,
            StepUpLevel::Standard => 1,
            StepUpLevel::Elevated => 2,
            StepUpLevel::HighAssurance => 3,
        }
    }

    /// Get the ACR value as a string
    pub fn acr_string(&self) -> String {
        self.acr_value().to_string()
    }

    /// Check if this level meets or exceeds the required level
    pub fn satisfies(&self, required: &StepUpLevel) -> bool {
        self.acr_value() >= required.acr_value()
    }
}

impl Default for StepUpLevel {
    fn default() -> Self {
        StepUpLevel::Standard
    }
}

/// Authentication Methods Reference (AMR)
///
/// Lists the authentication methods used in the authentication.
/// Based on OpenID Connect AMR values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Password-based authentication
    Pwd,
    /// One-time password
    Otp,
    /// Time-based one-time password
    Totp,
    /// Hardware token
    Hwk,
    /// SMS-based verification
    Sms,
    /// Email-based verification
    Email,
    /// WebAuthn / FIDO2
    Webauthn,
    /// Magic link
    Mlk,
    /// OAuth/Social login
    Mfa,
    /// Biometric
    Bio,
    /// Knowledge-based authentication
    Kba,
    /// Risk-based authentication
    Rba,
}

impl AuthMethod {
    /// Get the standard AMR value string
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::Pwd => "pwd",
            AuthMethod::Otp => "otp",
            AuthMethod::Totp => "totp",
            AuthMethod::Hwk => "hwk",
            AuthMethod::Sms => "sms",
            AuthMethod::Email => "email",
            AuthMethod::Webauthn => "webauthn",
            AuthMethod::Mlk => "mlk",
            AuthMethod::Mfa => "mfa",
            AuthMethod::Bio => "bio",
            AuthMethod::Kba => "kba",
            AuthMethod::Rba => "rba",
        }
    }
}

/// Step-up challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpChallenge {
    /// Password verification required
    Password,
    /// MFA verification required
    Mfa,
    /// Both password and MFA required
    Both,
}

/// Step-up session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpSession {
    /// The achieved authentication level
    pub level: StepUpLevel,
    /// When the step-up authentication expires (Unix timestamp)
    pub expires_at: i64,
    /// The authentication methods used
    pub amr: Vec<AuthMethod>,
}

impl StepUpSession {
    /// Create a new step-up session
    pub fn new(level: StepUpLevel, expires_at: i64, amr: Vec<AuthMethod>) -> Self {
        Self {
            level,
            expires_at,
            amr,
        }
    }

    /// Check if the step-up session is still valid
    pub fn is_valid(&self) -> bool {
        Utc::now().timestamp() < self.expires_at
    }

    /// Check if the session meets the required level
    pub fn satisfies_level(&self, required: &StepUpLevel) -> bool {
        self.is_valid() && self.level.satisfies(required)
    }
}

/// JWT Algorithm identifier for hybrid Ed25519 + ML-DSA-65
pub const ALGORITHM: &str = "EdDSA+ML-DSA-65";

/// Token type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Access token (short-lived)
    Access,
    /// Refresh token (longer-lived, single-use)
    Refresh,
    /// ID token (contains user claims)
    Id,
    /// Email verification token
    EmailVerification,
    /// Password reset token
    PasswordReset,
    /// Magic link token
    MagicLink,
    /// API key token
    ApiKey,
    /// Step-up authentication token (short-lived elevated token)
    StepUp,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TokenType {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenType::Access => "access",
            TokenType::Refresh => "refresh",
            TokenType::Id => "id",
            TokenType::EmailVerification => "email_verification",
            TokenType::PasswordReset => "password_reset",
            TokenType::MagicLink => "magic_link",
            TokenType::ApiKey => "api_key",
            TokenType::StepUp => "step_up",
        }
    }

    /// Get default expiry duration for token type
    pub fn default_duration(&self) -> Duration {
        match self {
            TokenType::Access => Duration::minutes(15),
            TokenType::Refresh => Duration::days(7),
            TokenType::Id => Duration::minutes(60),
            TokenType::EmailVerification => Duration::hours(24),
            TokenType::PasswordReset => Duration::hours(1),
            TokenType::MagicLink => Duration::minutes(15),
            TokenType::ApiKey => Duration::days(365),
            TokenType::StepUp => Duration::minutes(10), // Short-lived step-up tokens
        }
    }
}

use std::fmt;

/// JWT Claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer
    pub iss: String,
    /// Subject (user ID)
    pub sub: String,
    /// Audience
    pub aud: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Not before (Unix timestamp)
    pub nbf: i64,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// JWT ID (unique token identifier)
    pub jti: String,
    /// Token type
    #[serde(rename = "type")]
    pub token_type: TokenType,
    /// Tenant ID
    pub tenant_id: String,
    /// Session ID
    pub session_id: Option<String>,
    /// User email
    pub email: Option<String>,
    /// Whether email is verified
    pub email_verified: Option<bool>,
    /// User's full name
    pub name: Option<String>,
    /// User roles
    pub roles: Option<Vec<String>>,
    /// MFA authenticated
    pub mfa_authenticated: Option<bool>,
    /// Scope (for OAuth compatibility)
    pub scope: Option<String>,
    /// ACR (Authentication Context Class Reference) - step-up auth level
    /// Standard values: "0" (none), "1" (pwd), "2" (2FA), "3" (MFA+hw)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// AMR (Authentication Methods Reference) - methods used
    /// Example: ["pwd", "totp"], ["pwd", "webauthn"]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Step-up authentication expiration time
    /// When the elevated authentication expires (Unix timestamp)
    #[serde(rename = "step_up_expires_at", skip_serializing_if = "Option::is_none")]
    pub step_up_expires_at: Option<i64>,
    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl Claims {
    /// Create new claims for a user
    pub fn new(
        user_id: impl Into<String>,
        tenant_id: impl Into<String>,
        token_type: TokenType,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        let expiry = now + token_type.default_duration();

        Self {
            iss: issuer.into(),
            sub: user_id.into(),
            aud: audience.into(),
            exp: expiry.timestamp(),
            nbf: now.timestamp(),
            iat: now.timestamp(),
            jti: uuid::Uuid::new_v4().to_string(),
            token_type,
            tenant_id: tenant_id.into(),
            session_id: None,
            email: None,
            email_verified: None,
            name: None,
            roles: None,
            mfa_authenticated: None,
            scope: None,
            acr: None,
            amr: None,
            step_up_expires_at: None,
            custom: HashMap::new(),
        }
    }

    /// Set expiration time
    pub fn with_expiry(mut self, expiry: chrono::DateTime<Utc>) -> Self {
        self.exp = expiry.timestamp();
        self
    }

    /// Set session ID
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Set email
    pub fn with_email(mut self, email: impl Into<String>, verified: bool) -> Self {
        self.email = Some(email.into());
        self.email_verified = Some(verified);
        self
    }

    /// Set name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set roles
    pub fn with_roles(mut self, roles: Vec<String>) -> Self {
        self.roles = Some(roles);
        self
    }

    /// Set MFA status
    pub fn with_mfa(mut self, authenticated: bool) -> Self {
        self.mfa_authenticated = Some(authenticated);
        self
    }

    /// Set scope
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Add custom claim
    pub fn with_custom(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }

    /// Set ACR (Authentication Context Class Reference)
    pub fn with_acr(mut self, acr: impl Into<String>) -> Self {
        self.acr = Some(acr.into());
        self
    }

    /// Set AMR (Authentication Methods Reference)
    pub fn with_amr(mut self, amr: Vec<String>) -> Self {
        self.amr = Some(amr);
        self
    }

    /// Set authentication methods from AuthMethod enum
    pub fn with_auth_methods(mut self, methods: Vec<AuthMethod>) -> Self {
        self.amr = Some(methods.iter().map(|m| m.as_str().to_string()).collect());
        self
    }

    /// Set step-up authentication level
    pub fn with_step_up_level(mut self, level: StepUpLevel) -> Self {
        self.acr = Some(level.acr_string());
        self
    }

    /// Set step-up authentication expiration
    pub fn with_step_up_expiry(mut self, expires_at: chrono::DateTime<Utc>) -> Self {
        self.step_up_expires_at = Some(expires_at.timestamp());
        self
    }

    /// Set step-up session information
    pub fn with_step_up_session(mut self, session: &StepUpSession) -> Self {
        self.acr = Some(session.level.acr_string());
        self.amr = Some(session.amr.iter().map(|m| m.as_str().to_string()).collect());
        self.step_up_expires_at = Some(session.expires_at);
        self
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    /// Check if token is valid (not expired and not before issue time)
    pub fn is_valid(&self) -> bool {
        let now = Utc::now().timestamp();
        now >= self.nbf && now <= self.exp
    }

    /// Check if step-up authentication is still valid
    ///
    /// Returns true if:
    /// - No step-up was required (step_up_expires_at is None)
    /// - Step-up is still valid (not expired)
    pub fn is_step_up_valid(&self) -> bool {
        match self.step_up_expires_at {
            None => true, // No step-up required
            Some(expires_at) => Utc::now().timestamp() < expires_at,
        }
    }

    /// Check if the token meets the required step-up level
    ///
    /// # Arguments
    /// * `required_level` - The minimum step-up level required
    ///
    /// # Returns
    /// `true` if the token has a valid step-up at or above the required level
    pub fn has_step_up_level(&self, required_level: &StepUpLevel) -> bool {
        if !self.is_step_up_valid() {
            return false;
        }

        let current_level = self
            .acr
            .as_ref()
            .and_then(|acr| acr.parse::<u8>().ok())
            .unwrap_or(1); // Default to Standard (1) if not set

        current_level >= required_level.acr_value()
    }

    /// Get the step-up level from ACR claim
    pub fn step_up_level(&self) -> StepUpLevel {
        match self.acr.as_ref().and_then(|acr| acr.parse::<u8>().ok()) {
            Some(0) => StepUpLevel::None,
            Some(1) => StepUpLevel::Standard,
            Some(2) => StepUpLevel::Elevated,
            Some(3) => StepUpLevel::HighAssurance,
            _ => StepUpLevel::Standard, // Default
        }
    }
}

/// JWT Header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    /// Algorithm identifier
    pub alg: String,
    /// Token type
    pub typ: String,
    /// Key ID for key rotation
    pub kid: Option<String>,
    /// Algorithm details (optional extension)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg_details: Option<AlgorithmDetails>,
}

/// Algorithm details for the hybrid signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmDetails {
    /// Classical algorithm
    pub classical: String,
    /// Post-quantum algorithm
    pub post_quantum: String,
    /// Post-quantum algorithm version
    pub pq_version: String,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            alg: ALGORITHM.to_string(),
            typ: "JWT".to_string(),
            kid: None,
            alg_details: Some(AlgorithmDetails {
                classical: "Ed25519".to_string(),
                post_quantum: "ML-DSA".to_string(),
                pq_version: "65".to_string(),
            }),
        }
    }
}

/// Hybrid JWT implementation
pub struct HybridJwt;

impl HybridJwt {
    /// Encode claims into a JWT string with hybrid signature
    ///
    /// The JWT format follows the standard: header.payload.signature
    /// - Header: Base64url-encoded JSON containing algorithm info
    /// - Payload: Base64url-encoded JSON containing claims
    /// - Signature: Base64url-encoded hybrid signature (Ed25519 + ML-DSA-65)
    pub fn encode(claims: &Claims, signing_key: &HybridSigningKey) -> Result<String> {
        let header = Header::default();
        Self::encode_with_header(claims, signing_key, header)
    }

    /// Encode with custom header (for key rotation)
    pub fn encode_with_header(
        claims: &Claims,
        signing_key: &HybridSigningKey,
        header: Header,
    ) -> Result<String> {
        // Serialize header and claims
        let header_json = serde_json::to_vec(&header)
            .map_err(|e| VaultError::crypto(format!("Failed to serialize header: {}", e)))?;
        let claims_json = serde_json::to_vec(claims)
            .map_err(|e| VaultError::crypto(format!("Failed to serialize claims: {}", e)))?;

        // Base64url encode
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
        let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_json);

        // Create signing input
        let signing_input = format!("{}.{}", header_b64, claims_b64);

        // Sign with hybrid key (Ed25519 + ML-DSA-65)
        let signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

        // Return complete JWT
        Ok(format!("{}.{}.{}", header_b64, claims_b64, signature_b64))
    }

    /// Decode and verify a JWT
    ///
    /// Verifies both the Ed25519 and ML-DSA-65 signatures as part of the hybrid verification.
    /// Returns the claims if both signatures are valid and the token is not expired.
    pub fn decode(token: &str, verifying_key: &HybridVerifyingKey) -> Result<Claims> {
        // Split token
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(VaultError::crypto("Invalid JWT format: expected 3 parts"));
        }

        let header_b64 = parts[0];
        let claims_b64 = parts[1];
        let signature_b64 = parts[2];

        // Decode and verify header
        let header_json = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|_| VaultError::crypto("Invalid JWT header encoding"))?;
        let header: Header = serde_json::from_slice(&header_json)
            .map_err(|e| VaultError::crypto(format!("Invalid JWT header: {}", e)))?;

        // Verify algorithm - must be our hybrid algorithm
        if header.alg != ALGORITHM {
            return Err(VaultError::crypto(format!(
                "Unsupported algorithm: expected '{}', got '{}'",
                ALGORITHM, header.alg
            )));
        }

        // Decode signature
        let signature_bytes = URL_SAFE_NO_PAD
            .decode(signature_b64)
            .map_err(|_| VaultError::crypto("Invalid JWT signature encoding"))?;
        let signature = HybridSignature::from_bytes(&signature_bytes)?;

        // Verify hybrid signature (both Ed25519 and ML-DSA-65)
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        verifying_key.verify(signing_input.as_bytes(), &signature)?;

        // Decode and return claims
        let claims_json = URL_SAFE_NO_PAD
            .decode(claims_b64)
            .map_err(|_| VaultError::crypto("Invalid JWT claims encoding"))?;
        let claims: Claims = serde_json::from_slice(&claims_json)
            .map_err(|e| VaultError::crypto(format!("Invalid JWT claims: {}", e)))?;

        // Check expiration
        if claims.is_expired() {
            return Err(VaultError::Authentication("Token has expired".into()));
        }

        // Check not-before
        let now = Utc::now().timestamp();
        if now < claims.nbf {
            return Err(VaultError::Authentication("Token not yet valid".into()));
        }

        Ok(claims)
    }

    /// Decode without verification (for debugging only!)
    ///
    /// WARNING: This does NOT verify the signature and should only be used for debugging.
    /// Never use this in production code for authentication/authorization decisions.
    #[cfg(debug_assertions)]
    pub fn decode_unverified(token: &str) -> Result<Claims> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(VaultError::crypto("Invalid JWT format"));
        }

        let claims_b64 = parts[1];
        let claims_json = URL_SAFE_NO_PAD
            .decode(claims_b64)
            .map_err(|_| VaultError::crypto("Invalid claims encoding"))?;
        let claims: Claims = serde_json::from_slice(&claims_json)
            .map_err(|e| VaultError::crypto(format!("Invalid claims: {}", e)))?;

        Ok(claims)
    }

    /// Get the JWT algorithm identifier
    pub fn algorithm() -> &'static str {
        ALGORITHM
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HybridSigningKey;

    #[test]
    fn test_jwt_encode_decode() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();

        let claims = Claims::new(
            "user_123",
            "tenant_456",
            TokenType::Access,
            "vault",
            "myapp",
        )
        .with_email("test@example.com", true)
        .with_name("Test User")
        .with_roles(vec!["user".to_string(), "admin".to_string()]);

        // Encode
        let token = HybridJwt::encode(&claims, &signing_key).unwrap();
        assert!(token.split('.').count() == 3);

        // Decode and verify
        let decoded = HybridJwt::decode(&token, &verifying_key).unwrap();
        assert_eq!(decoded.sub, "user_123");
        assert_eq!(decoded.tenant_id, "tenant_456");
        assert_eq!(decoded.email, Some("test@example.com".to_string()));
        assert_eq!(decoded.name, Some("Test User".to_string()));
        assert_eq!(
            decoded.roles,
            Some(vec!["user".to_string(), "admin".to_string()])
        );
    }

    #[test]
    fn test_step_up_level_acr_values() {
        assert_eq!(StepUpLevel::None.acr_value(), 0);
        assert_eq!(StepUpLevel::Standard.acr_value(), 1);
        assert_eq!(StepUpLevel::Elevated.acr_value(), 2);
        assert_eq!(StepUpLevel::HighAssurance.acr_value(), 3);
    }

    #[test]
    fn test_step_up_level_satisfies() {
        assert!(StepUpLevel::Standard.satisfies(&StepUpLevel::None));
        assert!(StepUpLevel::Standard.satisfies(&StepUpLevel::Standard));
        assert!(!StepUpLevel::Standard.satisfies(&StepUpLevel::Elevated));

        assert!(StepUpLevel::HighAssurance.satisfies(&StepUpLevel::None));
        assert!(StepUpLevel::HighAssurance.satisfies(&StepUpLevel::Standard));
        assert!(StepUpLevel::HighAssurance.satisfies(&StepUpLevel::Elevated));
        assert!(StepUpLevel::HighAssurance.satisfies(&StepUpLevel::HighAssurance));
    }

    #[test]
    fn test_step_up_session_validity() {
        let future = Utc::now() + Duration::minutes(10);
        let session = StepUpSession::new(
            StepUpLevel::Elevated,
            future.timestamp(),
            vec![AuthMethod::Pwd, AuthMethod::Totp],
        );

        assert!(session.is_valid());
        assert!(session.satisfies_level(&StepUpLevel::Standard));
        assert!(session.satisfies_level(&StepUpLevel::Elevated));
        assert!(!session.satisfies_level(&StepUpLevel::HighAssurance));
    }

    #[test]
    fn test_claims_with_step_up() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();

        let step_up_session = StepUpSession::new(
            StepUpLevel::Elevated,
            (Utc::now() + Duration::minutes(10)).timestamp(),
            vec![AuthMethod::Pwd, AuthMethod::Totp],
        );

        let claims = Claims::new(
            "user_123",
            "tenant_456",
            TokenType::StepUp,
            "vault",
            "myapp",
        )
        .with_step_up_session(&step_up_session);

        // Encode
        let token = HybridJwt::encode(&claims, &signing_key).unwrap();

        // Decode and verify
        let decoded = HybridJwt::decode(&token, &verifying_key).unwrap();
        assert_eq!(decoded.acr, Some("2".to_string()));
        assert_eq!(
            decoded.amr,
            Some(vec!["pwd".to_string(), "totp".to_string()])
        );
        assert!(decoded.step_up_expires_at.is_some());
        assert!(decoded.is_step_up_valid());
        assert!(decoded.has_step_up_level(&StepUpLevel::Standard));
        assert!(decoded.has_step_up_level(&StepUpLevel::Elevated));
        assert!(!decoded.has_step_up_level(&StepUpLevel::HighAssurance));
        assert_eq!(decoded.step_up_level(), StepUpLevel::Elevated);
    }

    #[test]
    fn test_step_up_expired() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();

        let past = Utc::now() - Duration::minutes(10);
        let claims = Claims::new(
            "user_123",
            "tenant_456",
            TokenType::Access,
            "vault",
            "myapp",
        )
        .with_step_up_level(StepUpLevel::Elevated)
        .with_step_up_expiry(past);

        let token = HybridJwt::encode(&claims, &signing_key).unwrap();
        let decoded = HybridJwt::decode(&token, &verifying_key).unwrap();

        assert!(!decoded.is_step_up_valid());
        assert!(!decoded.has_step_up_level(&StepUpLevel::Standard));
    }

    #[test]
    fn test_auth_method_as_str() {
        assert_eq!(AuthMethod::Pwd.as_str(), "pwd");
        assert_eq!(AuthMethod::Totp.as_str(), "totp");
        assert_eq!(AuthMethod::Webauthn.as_str(), "webauthn");
        assert_eq!(AuthMethod::Hwk.as_str(), "hwk");
    }

    #[test]
    fn test_jwt_header_algorithm() {
        let (signing_key, _verifying_key) = HybridSigningKey::generate();
        let claims = Claims::new(
            "user_123",
            "tenant_456",
            TokenType::Access,
            "vault",
            "myapp",
        );

        let token = HybridJwt::encode(&claims, &signing_key).unwrap();

        // Decode header manually to check algorithm
        let parts: Vec<&str> = token.split('.').collect();
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header: Header = serde_json::from_slice(&header_json).unwrap();

        assert_eq!(header.alg, "EdDSA+ML-DSA-65");
        assert_eq!(header.typ, "JWT");
        assert!(header.alg_details.is_some());

        let details = header.alg_details.unwrap();
        assert_eq!(details.classical, "Ed25519");
        assert_eq!(details.post_quantum, "ML-DSA");
        assert_eq!(details.pq_version, "65");
    }

    #[test]
    fn test_jwt_signature_size() {
        let (signing_key, _verifying_key) = HybridSigningKey::generate();
        let claims = Claims::new(
            "user_123",
            "tenant_456",
            TokenType::Access,
            "vault",
            "myapp",
        );

        let token = HybridJwt::encode(&claims, &signing_key).unwrap();
        let parts: Vec<&str> = token.split('.').collect();

        // Decode and check signature size
        let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();

        // Ed25519 (64) + ML-DSA-65 (3373 bytes from pqcrypto) = 3437 bytes
        use crate::crypto::{ED25519_SIG_SIZE, MLDSA65_SIG_SIZE};
        assert_eq!(signature_bytes.len(), ED25519_SIG_SIZE + MLDSA65_SIG_SIZE);
    }

    #[test]
    fn test_jwt_expiration() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();

        // Create expired token
        let mut claims = Claims::new(
            "user_123",
            "tenant_456",
            TokenType::Access,
            "vault",
            "myapp",
        );
        claims.exp = Utc::now().timestamp() - 3600; // 1 hour ago

        let token = HybridJwt::encode(&claims, &signing_key).unwrap();

        // Should fail verification due to expiration
        let result = HybridJwt::decode(&token, &verifying_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn test_jwt_tampering() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();

        let claims = Claims::new(
            "user_123",
            "tenant_456",
            TokenType::Access,
            "vault",
            "myapp",
        );

        let token = HybridJwt::encode(&claims, &signing_key).unwrap();

        // Tamper with the token payload
        let mut parts: Vec<&str> = token.split('.').collect();
        let tampered_payload = URL_SAFE_NO_PAD.encode(b"{\"sub\":\"hacked\"}");
        parts[1] = &tampered_payload;
        let tampered_token = parts.join(".");

        // Should fail verification
        let result = HybridJwt::decode(&tampered_token, &verifying_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_wrong_algorithm() {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        let claims = Claims::new(
            "user_123",
            "tenant_456",
            TokenType::Access,
            "vault",
            "myapp",
        );

        // Create header with wrong algorithm
        let wrong_header = Header {
            alg: "EdDSA".to_string(),
            typ: "JWT".to_string(),
            kid: None,
            alg_details: None,
        };

        let token = HybridJwt::encode_with_header(&claims, &signing_key, wrong_header).unwrap();

        // Should fail verification due to wrong algorithm
        let result = HybridJwt::decode(&token, &verifying_key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported algorithm"));
    }

    #[test]
    fn test_token_type_default_durations() {
        assert_eq!(TokenType::Access.default_duration(), Duration::minutes(15));
        assert_eq!(TokenType::Refresh.default_duration(), Duration::days(7));
        assert_eq!(TokenType::Id.default_duration(), Duration::minutes(60));
        assert_eq!(
            TokenType::EmailVerification.default_duration(),
            Duration::hours(24)
        );
        assert_eq!(
            TokenType::PasswordReset.default_duration(),
            Duration::hours(1)
        );
        assert_eq!(
            TokenType::MagicLink.default_duration(),
            Duration::minutes(15)
        );
        assert_eq!(TokenType::ApiKey.default_duration(), Duration::days(365));
        assert_eq!(TokenType::StepUp.default_duration(), Duration::minutes(10));
    }

    #[test]
    fn test_token_type_as_str() {
        assert_eq!(TokenType::Access.as_str(), "access");
        assert_eq!(TokenType::Refresh.as_str(), "refresh");
        assert_eq!(TokenType::Id.as_str(), "id");
        assert_eq!(TokenType::EmailVerification.as_str(), "email_verification");
        assert_eq!(TokenType::PasswordReset.as_str(), "password_reset");
        assert_eq!(TokenType::MagicLink.as_str(), "magic_link");
        assert_eq!(TokenType::ApiKey.as_str(), "api_key");
        assert_eq!(TokenType::StepUp.as_str(), "step_up");
    }
}
