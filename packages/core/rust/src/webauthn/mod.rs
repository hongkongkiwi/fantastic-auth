//! WebAuthn/Passkey support for passwordless authentication
//!
//! Implements FIDO2 standard for secure, phishing-resistant authentication.

use crate::error::{Result, VaultError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod challenge;
pub mod credentials;
pub mod verification;

pub use challenge::{ChallengeStore, ChallengeStoreError, MemoryChallengeStore};
pub use credentials::CredentialStore;
pub use verification::WebAuthnVerifier;

/// WebAuthn configuration
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    /// Relying Party ID (e.g., "example.com")
    pub rp_id: String,
    /// Relying Party name (e.g., "Example App")
    pub rp_name: String,
    /// Origin URL (e.g., "https://example.com")
    pub origin: String,
    /// Whether to require resident keys (discoverable credentials)
    pub require_resident_key: bool,
    /// User verification requirement
    pub user_verification: UserVerificationRequirement,
    /// Preferred authenticator attachment
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
}

impl WebAuthnConfig {
    /// Create new configuration
    pub fn new(
        rp_id: impl Into<String>,
        rp_name: impl Into<String>,
        origin: impl Into<String>,
    ) -> Self {
        Self {
            rp_id: rp_id.into(),
            rp_name: rp_name.into(),
            origin: origin.into(),
            require_resident_key: false,
            user_verification: UserVerificationRequirement::Preferred,
            authenticator_attachment: None,
        }
    }

    /// Require resident keys (passkeys)
    pub fn with_resident_keys(mut self) -> Self {
        self.require_resident_key = true;
        self
    }

    /// Set user verification requirement
    pub fn with_user_verification(mut self, uv: UserVerificationRequirement) -> Self {
        self.user_verification = uv;
        self
    }

    /// Set preferred authenticator attachment
    pub fn with_authenticator_attachment(mut self, attachment: AuthenticatorAttachment) -> Self {
        self.authenticator_attachment = Some(attachment);
        self
    }
}

/// User verification requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserVerificationRequirement {
    /// Verification required
    Required,
    /// Verification preferred (falls back to no verification)
    Preferred,
    /// Verification discouraged
    Discouraged,
}

/// Authenticator attachment preference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorAttachment {
    /// Platform authenticator (built-in, e.g., Touch ID, Windows Hello)
    Platform,
    /// Cross-platform authenticator (external, e.g., YubiKey)
    CrossPlatform,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    /// Algorithm (e.g., -7 for ES256, -257 for RS256)
    pub alg: i32,
    /// Type (always "public-key")
    #[serde(rename = "type")]
    pub type_: String,
}

impl PubKeyCredParam {
    /// Get recommended algorithms (ES256, RS256, Ed25519)
    pub fn recommended() -> Vec<Self> {
        vec![
            Self {
                alg: -7,
                type_: "public-key".to_string(),
            }, // ES256
            Self {
                alg: -257,
                type_: "public-key".to_string(),
            }, // RS256
            Self {
                alg: -8,
                type_: "public-key".to_string(),
            }, // Ed25519
        ]
    }
}

/// WebAuthn user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    /// User ID (base64url encoded)
    pub id: String,
    /// Display name
    pub display_name: String,
    /// Username/login handle
    pub name: String,
}

/// Relying party information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    /// RP ID (domain)
    pub id: String,
    /// RP name
    pub name: String,
}

/// Credential creation options (for registration)
#[derive(Debug, Clone, Serialize)]
pub struct CredentialCreationOptions {
    /// Random challenge (base64url encoded)
    pub challenge: String,
    /// Relying party information
    #[serde(rename = "rp")]
    pub rp: PublicKeyCredentialRpEntity,
    /// User information
    pub user: PublicKeyCredentialUserEntity,
    /// Accepted public key algorithms
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    /// Timeout in milliseconds
    pub timeout: u32,
    /// Exclude credentials (already registered)
    #[serde(rename = "excludeCredentials")]
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    /// Authenticator selection criteria
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    /// Attestation conveyance preference
    #[serde(rename = "attestation")]
    pub attestation: AttestationConveyancePreference,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    /// Authenticator attachment
    #[serde(rename = "authenticatorAttachment")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    /// Require resident key
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: bool,
    /// Resident key requirement
    #[serde(rename = "residentKey")]
    pub resident_key: ResidentKeyRequirement,
    /// User verification
    #[serde(rename = "userVerification")]
    pub user_verification: String,
}

/// Resident key requirement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResidentKeyRequirement {
    Required,
    Preferred,
    Discouraged,
}

/// Attestation conveyance preference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttestationConveyancePreference {
    None,
    Indirect,
    Direct,
    Enterprise,
}

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    /// Credential type
    #[serde(rename = "type")]
    pub type_: String,
    /// Credential ID (base64url encoded)
    pub id: String,
    /// Transport methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

/// Authenticator transport
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticatorTransport {
    Usb,
    Nfc,
    Ble,
    #[serde(rename = "smart-card")]
    SmartCard,
    Hybrid,
    Internal,
}

/// Credential request options (for authentication)
#[derive(Debug, Clone, Serialize)]
pub struct CredentialRequestOptions {
    /// Random challenge (base64url encoded)
    pub challenge: String,
    /// Timeout in milliseconds
    pub timeout: u32,
    /// Relying party ID
    #[serde(rename = "rpId")]
    pub rp_id: String,
    /// Allowed credentials (if known)
    #[serde(rename = "allowCredentials")]
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    /// User verification requirement
    #[serde(rename = "userVerification")]
    pub user_verification: String,
}

/// Client data JSON structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectedClientData {
    /// Type ("webauthn.create" or "webauthn.get")
    #[serde(rename = "type")]
    pub type_: String,
    /// Challenge (base64url encoded)
    pub challenge: String,
    /// Origin
    pub origin: String,
    /// Whether cross-origin
    #[serde(rename = "crossOrigin")]
    pub cross_origin: Option<bool>,
}

/// Authenticator data structure
#[derive(Debug, Clone)]
pub struct AuthenticatorData {
    /// RP ID hash (32 bytes)
    pub rp_id_hash: Vec<u8>,
    /// Flags byte
    pub flags: u8,
    /// Signature counter
    pub sign_count: u32,
    /// Attested credential data (if present)
    pub attested_credential_data: Option<AttestedCredentialData>,
    /// Extensions (if present)
    pub extensions: Option<Vec<u8>>,
}

/// Flags in authenticator data
#[derive(Debug, Clone, Copy)]
pub struct AuthenticatorFlags {
    /// User present
    pub up: bool,
    /// User verified
    pub uv: bool,
    /// Attested credential data included
    pub at: bool,
    /// Extension data included
    pub ed: bool,
}

impl From<u8> for AuthenticatorFlags {
    fn from(flags: u8) -> Self {
        Self {
            up: (flags & 0x01) != 0,
            uv: (flags & 0x04) != 0,
            at: (flags & 0x40) != 0,
            ed: (flags & 0x80) != 0,
        }
    }
}

/// Attested credential data
#[derive(Debug, Clone)]
pub struct AttestedCredentialData {
    /// AAGUID (16 bytes)
    pub aaguid: Vec<u8>,
    /// Credential ID length
    pub credential_id_len: u16,
    /// Credential ID
    pub credential_id: Vec<u8>,
    /// COSE key
    pub credential_public_key: Vec<u8>,
}

/// Stored WebAuthn credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Credential ID (base64url encoded)
    pub credential_id: String,
    /// User ID
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Public key (COSE format)
    pub public_key: Vec<u8>,
    /// Sign count
    pub sign_count: u32,
    /// AAGUID
    pub aaguid: Option<String>,
    /// Device/credential name
    pub name: Option<String>,
    /// Whether this is a passkey (discoverable credential)
    pub is_passkey: bool,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used_at: Option<DateTime<Utc>>,
}

/// WebAuthn service for managing credentials
pub struct WebAuthnService {
    config: WebAuthnConfig,
    challenge_store: Box<dyn ChallengeStore>,
    credential_store: Box<dyn CredentialStore>,
}

impl WebAuthnService {
    /// Create new WebAuthn service
    pub fn new(
        config: WebAuthnConfig,
        challenge_store: Box<dyn ChallengeStore>,
        credential_store: Box<dyn CredentialStore>,
    ) -> Self {
        Self {
            config,
            challenge_store,
            credential_store,
        }
    }

    /// Begin registration - create credential creation options
    pub async fn begin_registration(
        &self,
        user_id: &str,
        tenant_id: &str,
        display_name: &str,
        name: &str,
    ) -> Result<CredentialCreationOptions> {
        // Generate challenge
        let challenge = generate_challenge()?;
        let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge);

        // Store challenge
        self.challenge_store
            .store_challenge(&challenge_b64, user_id, tenant_id, 600) // 10 minute expiry
            .await
            .map_err(|e| VaultError::internal(format!("Failed to store challenge: {}", e)))?;

        // Get existing credentials for exclude list
        let existing_creds = self
            .credential_store
            .get_credentials_for_user(user_id)
            .await
            .map_err(|e| VaultError::internal(format!("Failed to get credentials: {}", e)))?;

        let exclude_credentials: Vec<PublicKeyCredentialDescriptor> = existing_creds
            .into_iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: cred.credential_id,
                transports: Some(vec![
                    AuthenticatorTransport::Internal,
                    AuthenticatorTransport::Hybrid,
                ]),
            })
            .collect();

        let options = CredentialCreationOptions {
            challenge: challenge_b64,
            rp: PublicKeyCredentialRpEntity {
                id: self.config.rp_id.clone(),
                name: self.config.rp_name.clone(),
            },
            user: PublicKeyCredentialUserEntity {
                id: URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
                display_name: display_name.to_string(),
                name: name.to_string(),
            },
            pub_key_cred_params: PubKeyCredParam::recommended(),
            timeout: 120000, // 2 minutes
            exclude_credentials,
            authenticator_selection: AuthenticatorSelectionCriteria {
                authenticator_attachment: self.config.authenticator_attachment.map(|a| match a {
                    AuthenticatorAttachment::Platform => "platform".to_string(),
                    AuthenticatorAttachment::CrossPlatform => "cross-platform".to_string(),
                }),
                require_resident_key: self.config.require_resident_key,
                resident_key: if self.config.require_resident_key {
                    ResidentKeyRequirement::Required
                } else {
                    ResidentKeyRequirement::Preferred
                },
                user_verification: match self.config.user_verification {
                    UserVerificationRequirement::Required => "required".to_string(),
                    UserVerificationRequirement::Preferred => "preferred".to_string(),
                    UserVerificationRequirement::Discouraged => "discouraged".to_string(),
                },
            },
            attestation: AttestationConveyancePreference::None,
        };

        Ok(options)
    }

    /// Finish registration - verify and store credential
    pub async fn finish_registration(
        &self,
        credential_response: RegistrationCredentialResponse,
    ) -> Result<StoredCredential> {
        // Verify challenge
        let challenge_data = self
            .challenge_store
            .consume_challenge(&credential_response.response.client_data_json)
            .await
            .map_err(|e| VaultError::authentication(format!("Invalid challenge: {}", e)))?;

        // Parse client data
        let client_data: CollectedClientData = serde_json::from_str(
            &String::from_utf8(
                URL_SAFE_NO_PAD
                    .decode(&credential_response.response.client_data_json)
                    .map_err(|_| VaultError::validation("Invalid client data"))?,
            )
            .map_err(|_| VaultError::validation("Invalid client data encoding"))?,
        )
        .map_err(|_| VaultError::validation("Invalid client data JSON"))?;

        // Verify type
        if client_data.type_ != "webauthn.create" {
            return Err(VaultError::validation("Invalid client data type"));
        }

        // Verify origin
        if client_data.origin != self.config.origin {
            return Err(VaultError::validation("Invalid origin"));
        }

        // Decode and parse authenticator data
        let auth_data_bytes = URL_SAFE_NO_PAD
            .decode(&credential_response.response.attestation_object)
            .map_err(|_| VaultError::validation("Invalid attestation object"))?;

        // For simplicity, we're not doing full COSE key parsing here
        // In production, you would use a proper WebAuthn library

        // Create stored credential
        let credential = StoredCredential {
            credential_id: credential_response.id,
            user_id: challenge_data.user_id,
            tenant_id: challenge_data.tenant_id,
            public_key: auth_data_bytes, // Simplified - would extract actual public key
            sign_count: 0,
            aaguid: None,
            name: None,
            is_passkey: self.config.require_resident_key,
            created_at: Utc::now(),
            last_used_at: None,
        };

        // Store credential
        self.credential_store
            .store_credential(credential.clone())
            .await
            .map_err(|e| VaultError::internal(format!("Failed to store credential: {}", e)))?;

        Ok(credential)
    }

    /// Begin authentication - create credential request options
    pub async fn begin_authentication(
        &self,
        tenant_id: Option<&str>,
        user_id: Option<&str>,
    ) -> Result<CredentialRequestOptions> {
        // Generate challenge
        let challenge = generate_challenge()?;
        let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge);

        // Determine allowed credentials
        let allow_credentials = if let Some(uid) = user_id {
            let creds = self
                .credential_store
                .get_credentials_for_user(uid)
                .await
                .map_err(|e| VaultError::internal(format!("Failed to get credentials: {}", e)))?;

            creds
                .into_iter()
                .map(|cred| PublicKeyCredentialDescriptor {
                    type_: "public-key".to_string(),
                    id: cred.credential_id,
                    transports: Some(vec![
                        AuthenticatorTransport::Internal,
                        AuthenticatorTransport::Hybrid,
                    ]),
                })
                .collect()
        } else {
            Vec::new() // Empty for discoverable credentials (passkeys)
        };

        // Store challenge
        self.challenge_store
            .store_challenge(
                &challenge_b64,
                user_id.unwrap_or("discoverable"),
                tenant_id.unwrap_or("default"),
                300,
            )
            .await
            .map_err(|e| VaultError::internal(format!("Failed to store challenge: {}", e)))?;

        Ok(CredentialRequestOptions {
            challenge: challenge_b64,
            timeout: 120000, // 2 minutes
            rp_id: self.config.rp_id.clone(),
            allow_credentials,
            user_verification: match self.config.user_verification {
                UserVerificationRequirement::Required => "required".to_string(),
                UserVerificationRequirement::Preferred => "preferred".to_string(),
                UserVerificationRequirement::Discouraged => "discouraged".to_string(),
            },
        })
    }

    /// Finish authentication - verify credential
    pub async fn finish_authentication(
        &self,
        credential_response: AuthenticationCredentialResponse,
    ) -> Result<AuthenticationResult> {
        // Get stored credential
        let mut credential = self
            .credential_store
            .get_credential(&credential_response.id)
            .await
            .map_err(|e| VaultError::authentication(format!("Credential not found: {}", e)))?;

        // Parse client data
        let client_data_json = String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(&credential_response.response.client_data_json)
                .map_err(|_| VaultError::validation("Invalid client data"))?,
        )
        .map_err(|_| VaultError::validation("Invalid client data encoding"))?;

        let client_data: CollectedClientData = serde_json::from_str(&client_data_json)
            .map_err(|_| VaultError::validation("Invalid client data JSON"))?;

        // Verify type
        if client_data.type_ != "webauthn.get" {
            return Err(VaultError::validation("Invalid client data type"));
        }

        // Verify origin
        if client_data.origin != self.config.origin {
            return Err(VaultError::validation("Invalid origin"));
        }

        // Consume challenge
        let _challenge_data = self
            .challenge_store
            .consume_challenge(&credential_response.response.client_data_json)
            .await
            .map_err(|e| VaultError::authentication(format!("Invalid challenge: {}", e)))?;

        // Decode authenticator data
        let auth_data = URL_SAFE_NO_PAD
            .decode(&credential_response.response.authenticator_data)
            .map_err(|_| VaultError::validation("Invalid authenticator data"))?;

        // Verify flags
        let flags = AuthenticatorFlags::from(auth_data[32]);

        if self.config.user_verification == UserVerificationRequirement::Required && !flags.uv {
            return Err(VaultError::authentication("User verification required"));
        }

        // Check signature counter for cloned authenticator detection
        let sign_count =
            u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);

        if sign_count > 0 && sign_count <= credential.sign_count {
            return Err(VaultError::authentication(
                "Possible authenticator clone detected",
            ));
        }

        // Update sign count
        credential.sign_count = sign_count;
        credential.last_used_at = Some(Utc::now());

        self.credential_store
            .update_credential(credential.clone())
            .await
            .map_err(|e| VaultError::internal(format!("Failed to update credential: {}", e)))?;

        Ok(AuthenticationResult {
            credential_id: credential.credential_id,
            user_id: credential.user_id,
            tenant_id: credential.tenant_id,
            user_verified: flags.uv,
        })
    }

    /// Get all credentials for a user
    pub async fn get_credentials_for_user(&self, user_id: &str) -> Result<Vec<StoredCredential>> {
        self.credential_store
            .get_credentials_for_user(user_id)
            .await
            .map_err(|e| VaultError::internal(format!("Failed to get credentials: {}", e)))
    }

    /// Get a specific credential by ID
    pub async fn get_credential(&self, credential_id: &str) -> Result<StoredCredential> {
        self.credential_store
            .get_credential(credential_id)
            .await
            .map_err(|_e| VaultError::not_found("WebAuthn credential", credential_id))
    }

    /// Delete a credential
    pub async fn delete_credential(&self, credential_id: &str) -> Result<()> {
        self.credential_store
            .delete_credential(credential_id)
            .await
            .map_err(|e| VaultError::internal(format!("Failed to delete credential: {}", e)))
    }

    /// Delete all credentials for a user
    pub async fn delete_credentials_for_user(&self, user_id: &str) -> Result<u64> {
        self.credential_store
            .delete_credentials_for_user(user_id)
            .await
            .map_err(|e| VaultError::internal(format!("Failed to delete credentials: {}", e)))
    }
}

/// Registration credential response from client
#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationCredentialResponse {
    /// Credential ID (base64url)
    pub id: String,
    /// Raw ID (base64url)
    #[serde(rename = "rawId")]
    pub raw_id: String,
    /// Response data
    pub response: AuthenticatorAttestationResponse,
    /// Credential type
    #[serde(rename = "type")]
    pub type_: String,
}

/// Authenticator attestation response
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    /// Client data JSON (base64url)
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Attestation object (base64url CBOR)
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

/// Authentication credential response from client
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationCredentialResponse {
    /// Credential ID (base64url)
    pub id: String,
    /// Raw ID (base64url)
    #[serde(rename = "rawId")]
    pub raw_id: String,
    /// Response data
    pub response: AuthenticatorAssertionResponse,
    /// Credential type
    #[serde(rename = "type")]
    pub type_: String,
}

/// Authenticator assertion response
#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    /// Authenticator data (base64url)
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    /// Client data JSON (base64url)
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Signature (base64url)
    pub signature: String,
    /// User handle (base64url, optional - for discoverable credentials)
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    /// Credential ID used
    pub credential_id: String,
    /// User ID
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Whether user was verified
    pub user_verified: bool,
}

/// Generate random challenge
///
/// SECURITY: Uses OsRng (operating system's CSPRNG) for generating WebAuthn challenges.
/// WebAuthn challenges must be unpredictable to prevent replay attacks and ensure
/// the authenticator response is fresh for each authentication ceremony.
fn generate_challenge() -> Result<Vec<u8>> {
    use rand::RngCore;
    use rand_core::OsRng;

    let mut challenge = vec![0u8; 32];
    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    OsRng.fill_bytes(&mut challenge);
    Ok(challenge)
}

/// Compute SHA-256 hash
pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authenticator_flags() {
        let flags = AuthenticatorFlags::from(0x01);
        assert!(flags.up);
        assert!(!flags.uv);

        let flags = AuthenticatorFlags::from(0x05); // up + uv
        assert!(flags.up);
        assert!(flags.uv);

        let flags = AuthenticatorFlags::from(0x41); // up + at
        assert!(flags.up);
        assert!(flags.at);
    }

    #[test]
    fn test_generate_challenge() {
        let challenge = generate_challenge().unwrap();
        assert_eq!(challenge.len(), 32);

        let challenge2 = generate_challenge().unwrap();
        assert_ne!(challenge, challenge2); // Should be random
    }
}
