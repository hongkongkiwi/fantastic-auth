//! OAuth 2.0 Client Management
//!
//! This module provides functionality for managing OAuth 2.0 / OIDC clients,
//! including registration, validation, and secret management.
//!
//! Features:
//! - Client registration with metadata
//! - Client type classification (confidential/public)
//! - Redirect URI validation
//! - Scope management and validation
//! - Grant type restrictions
//! - Client secret generation and rotation
//! - Token endpoint authentication method configuration

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// OAuth 2.0 client types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    /// Confidential clients can maintain the confidentiality of their credentials
    /// (e.g., server-side web applications)
    Confidential,
    /// Public clients cannot maintain credential confidentiality
    /// (e.g., browser-based apps, mobile apps)
    Public,
}

impl ClientType {
    /// Check if this is a confidential client
    pub fn is_confidential(&self) -> bool {
        matches!(self, ClientType::Confidential)
    }

    /// Check if this is a public client
    pub fn is_public(&self) -> bool {
        matches!(self, ClientType::Public)
    }

    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            ClientType::Confidential => "confidential",
            ClientType::Public => "public",
        }
    }
}

impl Default for ClientType {
    fn default() -> Self {
        ClientType::Confidential
    }
}

/// OAuth 2.0 grant types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantType {
    /// Authorization Code grant
    AuthorizationCode,
    /// Client Credentials grant (for M2M)
    ClientCredentials,
    /// Refresh Token grant
    RefreshToken,
    /// Implicit grant (deprecated, not recommended)
    Implicit,
    /// Resource Owner Password Credentials grant (deprecated)
    Password,
    /// Device Authorization grant (Device Code flow)
    DeviceCode,
}

impl GrantType {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::RefreshToken => "refresh_token",
            GrantType::Implicit => "implicit",
            GrantType::Password => "password",
            GrantType::DeviceCode => "urn:ietf:params:oauth:grant-type:device_code",
        }
    }

    /// Check if this grant type is supported for the given client type
    pub fn is_supported_for(&self, client_type: &ClientType) -> bool {
        match (self, client_type) {
            // Public clients shouldn't use client_credentials
            (GrantType::ClientCredentials, ClientType::Public) => false,
            // Implicit grant is deprecated for security reasons
            (GrantType::Implicit, _) => false,
            // Password grant is deprecated for security reasons
            (GrantType::Password, _) => false,
            _ => true,
        }
    }
}

/// Token endpoint authentication methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    /// Client authentication via HTTP Basic authentication
    ClientSecretBasic,
    /// Client authentication via POST body parameters
    ClientSecretPost,
    /// No client authentication (for public clients)
    None,
}

impl TokenEndpointAuthMethod {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenEndpointAuthMethod::ClientSecretBasic => "client_secret_basic",
            TokenEndpointAuthMethod::ClientSecretPost => "client_secret_post",
            TokenEndpointAuthMethod::None => "none",
        }
    }

    /// Check if this method is valid for the given client type
    pub fn is_valid_for(&self, client_type: &ClientType) -> bool {
        match (self, client_type) {
            // Public clients can only use 'none' - they must use PKCE for security
            (TokenEndpointAuthMethod::None, ClientType::Public) => true,
            (TokenEndpointAuthMethod::ClientSecretBasic, ClientType::Public) => false,
            (TokenEndpointAuthMethod::ClientSecretPost, ClientType::Public) => false,
            // Confidential clients can use any method
            (_, ClientType::Confidential) => true,
        }
    }
}

impl Default for TokenEndpointAuthMethod {
    fn default() -> Self {
        TokenEndpointAuthMethod::ClientSecretBasic
    }
}

/// OAuth 2.0 client metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata {
    /// Client name (human-readable)
    pub client_name: Option<String>,
    /// Client description
    pub description: Option<String>,
    /// Client URI (homepage)
    pub client_uri: Option<String>,
    /// Logo URI
    pub logo_uri: Option<String>,
    /// Terms of Service URI
    pub tos_uri: Option<String>,
    /// Policy URI
    pub policy_uri: Option<String>,
    /// Contacts (email addresses)
    pub contacts: Option<Vec<String>>,
    /// Software ID (unique identifier for the client software)
    pub software_id: Option<String>,
    /// Software version
    pub software_version: Option<String>,
    /// Application type (web or native)
    pub application_type: Option<ApplicationType>,
    /// JWKS URI for client public keys
    pub jwks_uri: Option<String>,
    /// JWKS containing client public keys (inline)
    pub jwks: Option<serde_json::Value>,
}

/// Application type for OAuth clients
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationType {
    /// Web application (runs on a server)
    Web,
    /// Native application (mobile or desktop)
    Native,
}

/// OAuth 2.0 client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    /// Internal ID (UUID)
    pub id: String,
    /// Client ID (public identifier)
    pub client_id: String,
    /// Client secret hash (None for public clients)
    #[serde(skip_serializing)]
    pub client_secret_hash: Option<String>,
    /// Client type
    pub client_type: ClientType,
    /// Tenant ID (for multi-tenant setups)
    pub tenant_id: String,
    /// Allowed redirect URIs
    pub redirect_uris: Vec<String>,
    /// Allowed OAuth scopes
    pub allowed_scopes: Vec<String>,
    /// Allowed grant types
    pub allowed_grants: Vec<GrantType>,
    /// Token endpoint authentication method
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Whether PKCE is required
    pub pkce_required: bool,
    /// Whether PKCE S256 is enforced (disallows plain)
    pub pkce_s256_required: bool,
    /// Client metadata
    pub metadata: ClientMetadata,
    /// Whether the client is active
    pub is_active: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

impl OAuthClient {
    /// Check if a redirect URI is valid for this client
    pub fn is_valid_redirect_uri(&self, redirect_uri: &str) -> bool {
        self.redirect_uris.contains(&redirect_uri.to_string())
    }

    /// Check if a scope is allowed for this client
    pub fn is_scope_allowed(&self, scope: &str) -> bool {
        self.allowed_scopes.contains(&scope.to_string())
    }

    /// Validate a set of scopes
    /// 
    /// Returns true if all requested scopes are allowed.
    pub fn validate_scopes(&self, scopes: &[String]) -> bool {
        scopes.iter().all(|s| self.is_scope_allowed(s))
    }

    /// Check if a grant type is allowed
    pub fn is_grant_allowed(&self, grant: &GrantType) -> bool {
        self.allowed_grants.contains(grant)
    }

    /// Check if PKCE is required for this client
    pub fn requires_pkce(&self) -> bool {
        self.pkce_required || self.client_type.is_public()
    }

    /// Check if the client has a secret
    pub fn has_secret(&self) -> bool {
        self.client_secret_hash.is_some()
    }

    /// Verify a client secret
    pub fn verify_secret(&self, secret: &str) -> Result<bool, vault_core::error::VaultError> {
        match &self.client_secret_hash {
            Some(hash) => vault_core::crypto::VaultPasswordHasher::verify(secret, hash),
            None => Ok(false),
        }
    }

    /// Validate a token request
    pub fn validate_token_request(
        &self,
        grant_type: &GrantType,
        scopes: Option<&[String]>,
    ) -> Result<(), ClientValidationError> {
        // Check if client is active
        if !self.is_active {
            return Err(ClientValidationError::ClientInactive);
        }

        // Check grant type
        if !self.is_grant_allowed(grant_type) {
            return Err(ClientValidationError::GrantNotAllowed(
                grant_type.as_str().to_string(),
            ));
        }

        // Check grant type is valid for client type
        if !grant_type.is_supported_for(&self.client_type) {
            return Err(ClientValidationError::GrantNotSupportedForClientType(
                grant_type.as_str().to_string(),
            ));
        }

        // Check scopes if provided
        if let Some(scopes) = scopes {
            if !self.validate_scopes(scopes) {
                return Err(ClientValidationError::InvalidScope);
            }
        }

        Ok(())
    }

    /// Get allowed scopes as a space-separated string
    pub fn allowed_scopes_string(&self) -> String {
        self.allowed_scopes.join(" ")
    }

    /// Get allowed grant types as strings
    pub fn allowed_grants_strings(&self) -> Vec<String> {
        self.allowed_grants.iter().map(|g| g.as_str().to_string()).collect()
    }
}

/// Client validation errors
#[derive(Debug, Clone)]
pub enum ClientValidationError {
    /// Client is inactive
    ClientInactive,
    /// Grant type not allowed
    GrantNotAllowed(String),
    /// Grant type not supported for client type
    GrantNotSupportedForClientType(String),
    /// Invalid scope requested
    InvalidScope,
    /// Redirect URI not allowed
    InvalidRedirectUri,
    /// Missing required PKCE parameter
    MissingPkce,
    /// Invalid PKCE verifier
    InvalidPkce,
    /// Client authentication failed
    AuthenticationFailed,
}

impl std::fmt::Display for ClientValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientValidationError::ClientInactive => write!(f, "Client is inactive"),
            ClientValidationError::GrantNotAllowed(g) => {
                write!(f, "Grant type not allowed: {}", g)
            }
            ClientValidationError::GrantNotSupportedForClientType(g) => {
                write!(f, "Grant type {} not supported for this client type", g)
            }
            ClientValidationError::InvalidScope => write!(f, "Invalid or unauthorized scope"),
            ClientValidationError::InvalidRedirectUri => write!(f, "Invalid redirect URI"),
            ClientValidationError::MissingPkce => write!(f, "PKCE code_challenge is required"),
            ClientValidationError::InvalidPkce => write!(f, "Invalid PKCE code_verifier"),
            ClientValidationError::AuthenticationFailed => {
                write!(f, "Client authentication failed")
            }
        }
    }
}

impl std::error::Error for ClientValidationError {}

/// Client registration request
#[derive(Debug, Clone, Deserialize)]
pub struct ClientRegistrationRequest {
    /// Client name
    pub client_name: String,
    /// Redirect URIs
    pub redirect_uris: Vec<String>,
    /// Client type (defaults to confidential)
    #[serde(default)]
    pub client_type: Option<ClientType>,
    /// Allowed scopes (defaults to openid)
    pub allowed_scopes: Option<Vec<String>>,
    /// Allowed grant types (defaults to authorization_code)
    pub allowed_grants: Option<Vec<GrantType>>,
    /// Token endpoint authentication method
    pub token_endpoint_auth_method: Option<TokenEndpointAuthMethod>,
    /// Whether to require PKCE
    #[serde(default = "default_pkce_required")]
    pub pkce_required: bool,
    /// Client metadata
    pub metadata: Option<ClientMetadata>,
}

fn default_pkce_required() -> bool {
    true
}

/// Client registration response
#[derive(Debug, Clone, Serialize)]
pub struct ClientRegistrationResponse {
    /// Client ID
    pub client_id: String,
    /// Client secret (only shown once during registration)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Client ID issued at
    pub client_id_issued_at: i64,
    /// Client secret expires at (0 for never)
    pub client_secret_expires_at: i64,
    /// Registration access token (for managing the client)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
    /// Registration client URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,
    /// Token endpoint authentication method
    pub token_endpoint_auth_method: String,
}

/// Client update request
#[derive(Debug, Clone, Deserialize)]
pub struct ClientUpdateRequest {
    /// Client name
    pub client_name: Option<String>,
    /// Redirect URIs
    pub redirect_uris: Option<Vec<String>>,
    /// Allowed scopes
    pub allowed_scopes: Option<Vec<String>>,
    /// Allowed grant types
    pub allowed_grants: Option<Vec<GrantType>>,
    /// Whether PKCE is required
    pub pkce_required: Option<bool>,
    /// Whether the client is active
    pub is_active: Option<bool>,
    /// Client metadata
    pub metadata: Option<ClientMetadata>,
}

/// Client manager for CRUD operations
#[derive(Debug, Clone)]
pub struct ClientManager {
    /// In-memory client storage (for testing/development)
    /// In production, use database storage
    _clients: HashMap<String, OAuthClient>,
}

impl ClientManager {
    /// Create a new client manager
    pub fn new() -> Self {
        Self {
            _clients: HashMap::new(),
        }
    }

    /// Generate a new client ID
    /// 
    /// Format: vault_<random>
    pub fn generate_client_id(&self) -> String {
        let random = vault_core::crypto::generate_secure_random(16);
        format!("vault_{}", random)
    }

    /// Generate a new client secret
    /// 
    /// Returns a secure random secret with 256-bit entropy.
    /// The secret is only shown once during client registration.
    pub fn generate_client_secret(&self) -> String {
        vault_core::crypto::generate_secure_random(32)
    }

    /// Validate a redirect URI
    /// 
    /// Checks that the URI:
    /// - Is a valid URL
    /// - Uses HTTPS (except for localhost)
    /// - Has no fragment component
    pub fn validate_redirect_uri(&self, uri: &str) -> Result<(), String> {
        // Parse the URL
        let url = url::Url::parse(uri).map_err(|e| format!("Invalid URL: {}", e))?;

        // Check scheme
        match url.scheme() {
            "https" => {}
            "http" => {
                // Allow http only for localhost
                let host = url.host_str().unwrap_or("");
                if host != "localhost" && host != "127.0.0.1" && host != "::1" {
                    return Err("HTTP redirect URIs are only allowed for localhost".to_string());
                }
            }
            scheme => {
                // Allow custom schemes for native apps
                if !scheme.contains("+") && !scheme.ends_with(":") {
                    // It's a custom scheme, allow it for native apps
                }
            }
        }

        // Check for fragment
        if url.fragment().is_some() {
            return Err("Redirect URI must not contain a fragment".to_string());
        }

        Ok(())
    }

    /// Validate redirect URIs for a client registration
    pub fn validate_redirect_uris(&self, uris: &[String]) -> Result<(), String> {
        if uris.is_empty() {
            return Err("At least one redirect URI is required".to_string());
        }

        for uri in uris {
            self.validate_redirect_uri(uri)?;
        }

        Ok(())
    }

    /// Get default scopes for a new client
    pub fn default_scopes(&self) -> Vec<String> {
        vec!["openid".to_string()]
    }

    /// Get default grant types for a client type
    pub fn default_grants(&self, client_type: &ClientType) -> Vec<GrantType> {
        match client_type {
            ClientType::Confidential => vec![
                GrantType::AuthorizationCode,
                GrantType::ClientCredentials,
                GrantType::RefreshToken,
            ],
            ClientType::Public => vec![
                GrantType::AuthorizationCode,
                GrantType::RefreshToken,
            ],
        }
    }

    /// Determine if PKCE should be required based on client type
    pub fn default_pkce_required(&self, client_type: &ClientType) -> bool {
        // PKCE is always required for public clients
        // Recommended for confidential clients
        matches!(client_type, ClientType::Public)
    }
}

impl Default for ClientManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Client secret rotation response
#[derive(Debug, Clone, Serialize)]
pub struct SecretRotationResponse {
    /// New client secret (only shown once)
    pub new_client_secret: String,
    /// Old secret expiration time
    pub old_secret_expires_at: DateTime<Utc>,
}

/// Client usage statistics
#[derive(Debug, Clone, Serialize)]
pub struct ClientUsage {
    /// Number of authorization requests
    pub authorization_requests: i64,
    /// Number of token requests
    pub token_requests: i64,
    /// Number of active tokens
    pub active_tokens: i64,
    /// Last used timestamp
    pub last_used_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_type() {
        assert!(ClientType::Confidential.is_confidential());
        assert!(!ClientType::Confidential.is_public());
        assert!(ClientType::Public.is_public());
        assert!(!ClientType::Public.is_confidential());
    }

    #[test]
    fn test_grant_type_support() {
        assert!(GrantType::AuthorizationCode.is_supported_for(&ClientType::Public));
        assert!(GrantType::AuthorizationCode.is_supported_for(&ClientType::Confidential));
        
        // Client credentials not supported for public clients
        assert!(!GrantType::ClientCredentials.is_supported_for(&ClientType::Public));
        assert!(GrantType::ClientCredentials.is_supported_for(&ClientType::Confidential));
    }

    #[test]
    fn test_token_endpoint_auth_method() {
        assert!(TokenEndpointAuthMethod::None.is_valid_for(&ClientType::Public));
        assert!(!TokenEndpointAuthMethod::ClientSecretBasic.is_valid_for(&ClientType::Public));
        assert!(!TokenEndpointAuthMethod::ClientSecretPost.is_valid_for(&ClientType::Public));
        
        assert!(TokenEndpointAuthMethod::ClientSecretBasic.is_valid_for(&ClientType::Confidential));
        assert!(TokenEndpointAuthMethod::ClientSecretPost.is_valid_for(&ClientType::Confidential));
        assert!(TokenEndpointAuthMethod::None.is_valid_for(&ClientType::Confidential));
    }

    #[test]
    fn test_client_validation() {
        let client = OAuthClient {
            id: "uuid-123".to_string(),
            client_id: "client-123".to_string(),
            client_secret_hash: Some("hash".to_string()),
            client_type: ClientType::Confidential,
            tenant_id: "tenant-1".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            allowed_scopes: vec!["openid".to_string(), "profile".to_string()],
            allowed_grants: vec![GrantType::AuthorizationCode, GrantType::ClientCredentials],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            pkce_required: false,
            pkce_s256_required: false,
            metadata: ClientMetadata {
                client_name: Some("Test Client".to_string()),
                description: None,
                client_uri: None,
                logo_uri: None,
                tos_uri: None,
                policy_uri: None,
                contacts: None,
                software_id: None,
                software_version: None,
                application_type: Some(ApplicationType::Web),
                jwks_uri: None,
                jwks: None,
            },
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(client.is_valid_redirect_uri("https://example.com/callback"));
        assert!(!client.is_valid_redirect_uri("https://evil.com/callback"));
        
        assert!(client.is_scope_allowed("openid"));
        assert!(client.is_scope_allowed("profile"));
        assert!(!client.is_scope_allowed("admin"));
        
        assert!(client.is_grant_allowed(&GrantType::AuthorizationCode));
        assert!(client.is_grant_allowed(&GrantType::ClientCredentials));
        assert!(!client.is_grant_allowed(&GrantType::DeviceCode));
        
        assert!(!client.requires_pkce());
    }

    #[test]
    fn test_public_client_requires_pkce() {
        let public_client = OAuthClient {
            id: "uuid-123".to_string(),
            client_id: "client-123".to_string(),
            client_secret_hash: None,
            client_type: ClientType::Public,
            tenant_id: "tenant-1".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            allowed_scopes: vec!["openid".to_string()],
            allowed_grants: vec![GrantType::AuthorizationCode],
            token_endpoint_auth_method: TokenEndpointAuthMethod::None,
            pkce_required: false, // Even if false, public clients require PKCE
            pkce_s256_required: true,
            metadata: ClientMetadata {
                client_name: None,
                description: None,
                client_uri: None,
                logo_uri: None,
                tos_uri: None,
                policy_uri: None,
                contacts: None,
                software_id: None,
                software_version: None,
                application_type: Some(ApplicationType::Native),
                jwks_uri: None,
                jwks: None,
            },
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(public_client.requires_pkce());
        assert!(!public_client.has_secret());
    }

    #[test]
    fn test_validate_redirect_uri() {
        let manager = ClientManager::new();
        
        // Valid HTTPS URI
        assert!(manager.validate_redirect_uri("https://example.com/callback").is_ok());
        
        // Valid localhost HTTP
        assert!(manager.validate_redirect_uri("http://localhost:3000/callback").is_ok());
        assert!(manager.validate_redirect_uri("http://127.0.0.1:8080/callback").is_ok());
        
        // Invalid non-localhost HTTP
        assert!(manager.validate_redirect_uri("http://example.com/callback").is_err());
        
        // Invalid with fragment
        assert!(manager.validate_redirect_uri("https://example.com/callback#section").is_err());
        
        // Invalid URL
        assert!(manager.validate_redirect_uri("not-a-url").is_err());
    }

    #[test]
    fn test_client_id_generation() {
        let manager = ClientManager::new();
        let client_id = manager.generate_client_id();
        
        assert!(client_id.starts_with("vault_"));
        assert_eq!(client_id.len(), 6 + 22); // "vault_" + 16 bytes base64url
    }

    #[test]
    fn test_client_secret_generation() {
        let manager = ClientManager::new();
        let secret = manager.generate_client_secret();
        
        // 32 bytes = 43 characters base64url
        assert_eq!(secret.len(), 43);
    }

    #[test]
    fn test_inactive_client_validation() {
        let client = OAuthClient {
            id: "uuid-123".to_string(),
            client_id: "client-123".to_string(),
            client_secret_hash: Some("hash".to_string()),
            client_type: ClientType::Confidential,
            tenant_id: "tenant-1".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            allowed_scopes: vec!["openid".to_string()],
            allowed_grants: vec![GrantType::AuthorizationCode],
            token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
            pkce_required: false,
            pkce_s256_required: false,
            metadata: ClientMetadata {
                client_name: None,
                description: None,
                client_uri: None,
                logo_uri: None,
                tos_uri: None,
                policy_uri: None,
                contacts: None,
                software_id: None,
                software_version: None,
                application_type: None,
                jwks_uri: None,
                jwks: None,
            },
            is_active: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let result = client.validate_token_request(&GrantType::AuthorizationCode, None);
        assert!(matches!(result, Err(ClientValidationError::ClientInactive)));
    }
}
