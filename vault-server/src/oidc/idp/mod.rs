//! OIDC Identity Provider (IdP) Core Module
//!
//! This module implements a complete OIDC Identity Provider that allows Vault
//! to act as an authentication authority for external applications.
//!
//! Features:
//! - OIDC Discovery (.well-known/openid-configuration)
//! - Authorization Code flow with PKCE
//! - Client Credentials flow for M2M authentication
//! - Refresh Token flow
//! - ID Token generation with standard claims
//! - JWKS endpoint for key rotation
//! - Token introspection (RFC 7662)
//! - Token revocation (RFC 7009)
//! - Full scope support (openid, profile, email, phone, address)

use axum::Router;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::state::AppState;
use vault_core::crypto::{Claims, HybridJwt, TokenType};
use vault_core::db::oidc::OauthClient;

pub mod auth_code;
pub mod client_management;
pub mod endpoints;
pub mod grants;
pub mod scopes;

pub use auth_code::{AuthorizationCodeEntry, AuthorizationCodeManager, PkceParams};
pub use client_management::{
    ClientManager, ClientRegistrationRequest, ClientRegistrationResponse, ClientType,
    ClientUpdateRequest, GrantType, OAuthClient, TokenEndpointAuthMethod,
};
pub use endpoints::routes;
pub use grants::GrantHandler;
pub use scopes::{Scope, ScopeManager, StandardScope};

/// OIDC Identity Provider main struct
#[derive(Clone)]
pub struct OidcIdentityProvider {
    /// Client manager for OAuth client operations
    pub client_manager: ClientManager,
    /// Authorization code manager
    pub code_manager: AuthorizationCodeManager,
    /// Scope manager
    pub scope_manager: ScopeManager,
    /// Grant handler
    pub grant_handler: GrantHandler,
    /// Issuer URL (base URL of the IdP)
    pub issuer: String,
}

impl OidcIdentityProvider {
    /// Create a new OIDC Identity Provider
    pub fn new(issuer: impl Into<String>) -> Self {
        let issuer = issuer.into();
        Self {
            client_manager: ClientManager::new(),
            code_manager: AuthorizationCodeManager::new(),
            scope_manager: ScopeManager::new(),
            grant_handler: GrantHandler::new(),
            issuer,
        }
    }

    /// Get the issuer URL
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Get the discovery document URL
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.issuer)
    }

    /// Get the authorization endpoint URL
    pub fn authorization_endpoint(&self) -> String {
        format!("{}/oauth/authorize", self.issuer)
    }

    /// Get the token endpoint URL
    pub fn token_endpoint(&self) -> String {
        format!("{}/oauth/token", self.issuer)
    }

    /// Get the userinfo endpoint URL
    pub fn userinfo_endpoint(&self) -> String {
        format!("{}/oauth/userinfo", self.issuer)
    }

    /// Get the JWKS endpoint URL
    pub fn jwks_uri(&self) -> String {
        format!("{}/oauth/jwks", self.issuer)
    }

    /// Get the introspection endpoint URL
    pub fn introspection_endpoint(&self) -> String {
        format!("{}/oauth/introspect", self.issuer)
    }

    /// Get the revocation endpoint URL
    pub fn revocation_endpoint(&self) -> String {
        format!("{}/oauth/revoke", self.issuer)
    }

    /// Build the discovery document response
    pub fn discovery_document(&self) -> DiscoveryDocument {
        DiscoveryDocument {
            issuer: self.issuer.clone(),
            authorization_endpoint: self.authorization_endpoint(),
            token_endpoint: self.token_endpoint(),
            userinfo_endpoint: Some(self.userinfo_endpoint()),
            jwks_uri: self.jwks_uri(),
            registration_endpoint: None,
            scopes_supported: Some(vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
                "phone".to_string(),
                "address".to_string(),
                "offline_access".to_string(),
            ]),
            response_types_supported: vec![
                "code".to_string(),
                "token".to_string(),
                "id_token".to_string(),
                "code token".to_string(),
                "code id_token".to_string(),
                "token id_token".to_string(),
                "code token id_token".to_string(),
            ],
            response_modes_supported: Some(vec![
                "query".to_string(),
                "fragment".to_string(),
                "form_post".to_string(),
            ]),
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
                "refresh_token".to_string(),
            ],
            acr_values_supported: Some(vec![
                "0".to_string(),
                "1".to_string(),
                "2".to_string(),
                "3".to_string(),
            ]),
            subject_types_supported: vec!["public".to_string()],
            id_token_signing_alg_values_supported: vec!["EdDSA+ML-DSA-65".to_string()],
            id_token_encryption_alg_values_supported: None,
            id_token_encryption_enc_values_supported: None,
            userinfo_signing_alg_values_supported: Some(vec!["EdDSA+ML-DSA-65".to_string()]),
            userinfo_encryption_alg_values_supported: None,
            userinfo_encryption_enc_values_supported: None,
            request_object_signing_alg_values_supported: Some(vec!["EdDSA+ML-DSA-65".to_string()]),
            request_object_encryption_alg_values_supported: None,
            request_object_encryption_enc_values_supported: None,
            token_endpoint_auth_methods_supported: Some(vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
                "none".to_string(),
            ]),
            token_endpoint_auth_signing_alg_values_supported: None,
            display_values_supported: Some(vec![
                "page".to_string(),
                "popup".to_string(),
                "touch".to_string(),
                "wap".to_string(),
            ]),
            claim_types_supported: Some(vec!["normal".to_string()]),
            claims_supported: Some(vec![
                "sub".to_string(),
                "iss".to_string(),
                "aud".to_string(),
                "exp".to_string(),
                "iat".to_string(),
                "auth_time".to_string(),
                "nonce".to_string(),
                "acr".to_string(),
                "amr".to_string(),
                "name".to_string(),
                "given_name".to_string(),
                "family_name".to_string(),
                "middle_name".to_string(),
                "nickname".to_string(),
                "preferred_username".to_string(),
                "profile".to_string(),
                "picture".to_string(),
                "website".to_string(),
                "email".to_string(),
                "email_verified".to_string(),
                "gender".to_string(),
                "birthdate".to_string(),
                "zoneinfo".to_string(),
                "locale".to_string(),
                "phone_number".to_string(),
                "phone_number_verified".to_string(),
                "address".to_string(),
                "updated_at".to_string(),
            ]),
            service_documentation: None,
            claims_locales_supported: None,
            ui_locales_supported: Some(vec![
                "en".to_string(),
                "en-US".to_string(),
                "zh".to_string(),
                "zh-CN".to_string(),
                "es".to_string(),
                "fr".to_string(),
                "de".to_string(),
                "ja".to_string(),
            ]),
            claims_parameter_supported: Some(true),
            request_parameter_supported: Some(false),
            request_uri_parameter_supported: Some(false),
            require_request_uri_registration: Some(false),
            op_policy_uri: None,
            op_tos_uri: None,
            revocation_endpoint: Some(self.revocation_endpoint()),
            revocation_endpoint_auth_methods_supported: Some(vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
            ]),
            introspection_endpoint: Some(self.introspection_endpoint()),
            introspection_endpoint_auth_methods_supported: Some(vec![
                "client_secret_basic".to_string(),
                "client_secret_post".to_string(),
            ]),
            code_challenge_methods_supported: Some(vec!["S256".to_string(), "plain".to_string()]),
        }
    }
}

/// OIDC Discovery Document
/// 
/// This is the main configuration document that describes the IdP capabilities
/// and endpoints. Clients use this to configure themselves automatically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    /// The authorization server's issuer identifier
    pub issuer: String,
    /// URL of the authorization endpoint
    pub authorization_endpoint: String,
    /// URL of the token endpoint
    pub token_endpoint: String,
    /// URL of the userinfo endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_endpoint: Option<String>,
    /// URL of the JWKS endpoint
    pub jwks_uri: String,
    /// URL of the registration endpoint (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// List of OAuth 2.0 scope values supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes_supported: Option<Vec<String>>,
    /// List of OAuth 2.0 response_type values supported
    pub response_types_supported: Vec<String>,
    /// List of OAuth 2.0 response_mode values supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_modes_supported: Option<Vec<String>>,
    /// List of OAuth 2.0 grant type values supported
    pub grant_types_supported: Vec<String>,
    /// List of ACR values supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values_supported: Option<Vec<String>>,
    /// List of subject identifier types supported
    pub subject_types_supported: Vec<String>,
    /// List of JWS signing algorithms supported for ID tokens
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// List of JWE encryption algorithms supported for ID tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_alg_values_supported: Option<Vec<String>>,
    /// List of JWE encryption methods supported for ID tokens
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encryption_enc_values_supported: Option<Vec<String>>,
    /// List of JWS signing algorithms supported for userinfo responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signing_alg_values_supported: Option<Vec<String>>,
    /// List of JWE encryption algorithms supported for userinfo responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_alg_values_supported: Option<Vec<String>>,
    /// List of JWE encryption methods supported for userinfo responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encryption_enc_values_supported: Option<Vec<String>>,
    /// List of JWS signing algorithms supported for request objects
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg_values_supported: Option<Vec<String>>,
    /// List of JWE encryption algorithms supported for request objects
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg_values_supported: Option<Vec<String>>,
    /// List of JWE encryption methods supported for request objects
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc_values_supported: Option<Vec<String>>,
    /// List of client authentication methods supported at the token endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// List of JWS signing algorithms supported for token endpoint authentication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    /// List of display parameter values supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_values_supported: Option<Vec<String>>,
    /// List of claim types supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_types_supported: Option<Vec<String>>,
    /// List of claim names supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_supported: Option<Vec<String>>,
    /// URL of a page containing human-readable information about the service
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_documentation: Option<String>,
    /// List of languages and scripts supported for values in claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_locales_supported: Option<Vec<String>>,
    /// List of languages and scripts supported for the user interface
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales_supported: Option<Vec<String>>,
    /// Whether the OP supports use of the claims parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims_parameter_supported: Option<bool>,
    /// Whether the OP supports use of the request parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_parameter_supported: Option<bool>,
    /// Whether the OP supports use of the request_uri parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri_parameter_supported: Option<bool>,
    /// Whether the OP requires request_uri registration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_request_uri_registration: Option<bool>,
    /// URL that the authorization server provides to the person registering the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_policy_uri: Option<String>,
    /// URL that the authorization server provides to the person registering the client for terms of service
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_tos_uri: Option<String>,
    /// URL of the revocation endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint: Option<String>,
    /// List of client authentication methods supported at the revocation endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// URL of the introspection endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint: Option<String>,
    /// List of client authentication methods supported at the introspection endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// List of PKCE code challenge methods supported
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// Authorization Request
/// 
/// The request parameters for the OAuth 2.0 authorization endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationRequest {
    /// Response type (e.g., "code", "token", "id_token")
    pub response_type: String,
    /// Client identifier
    pub client_id: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Scope (space-separated)
    pub scope: Option<String>,
    /// State parameter (for CSRF protection)
    pub state: Option<String>,
    /// Nonce for ID token
    pub nonce: Option<String>,
    /// PKCE code challenge
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (S256 or plain)
    pub code_challenge_method: Option<String>,
    /// Requested authentication context class reference
    pub acr_values: Option<String>,
    /// Requested claims (JSON object)
    pub claims: Option<String>,
    /// Display mode (page, popup, touch, wap)
    pub display: Option<String>,
    /// Login hint (username/email)
    pub login_hint: Option<String>,
    /// Maximum authentication age in seconds
    pub max_age: Option<i64>,
    /// UI locales (space-separated)
    pub ui_locales: Option<String>,
    /// Prompt (none, login, consent, select_account)
    pub prompt: Option<String>,
}

impl AuthorizationRequest {
    /// Get scopes as a vector
    pub fn scopes(&self) -> Vec<String> {
        self.scope
            .as_ref()
            .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
            .unwrap_or_else(|| vec!["openid".to_string()])
    }

    /// Check if openid scope is requested
    pub fn is_oidc_request(&self) -> bool {
        self.scopes().contains(&"openid".to_string())
    }

    /// Validate the request
    pub fn validate(&self) -> Result<(), AuthorizationError> {
        if self.response_type.is_empty() {
            return Err(AuthorizationError::InvalidRequest(
                "response_type is required".to_string(),
            ));
        }
        if self.client_id.is_empty() {
            return Err(AuthorizationError::InvalidRequest(
                "client_id is required".to_string(),
            ));
        }
        if self.redirect_uri.is_empty() {
            return Err(AuthorizationError::InvalidRequest(
                "redirect_uri is required".to_string(),
            ));
        }
        Ok(())
    }
}

/// Token Request
/// 
/// The request parameters for the OAuth 2.0 token endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    /// Grant type (authorization_code, client_credentials, refresh_token)
    pub grant_type: String,
    /// Authorization code (for authorization_code grant)
    pub code: Option<String>,
    /// Redirect URI (for authorization_code grant)
    pub redirect_uri: Option<String>,
    /// Client ID
    pub client_id: Option<String>,
    /// Client secret
    pub client_secret: Option<String>,
    /// PKCE code verifier
    pub code_verifier: Option<String>,
    /// Refresh token (for refresh_token grant)
    pub refresh_token: Option<String>,
    /// Scope (space-separated)
    pub scope: Option<String>,
}

/// Token Response
/// 
/// The successful response from the token endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    /// Access token
    pub access_token: String,
    /// Token type (Bearer)
    pub token_type: String,
    /// Expiration time in seconds
    pub expires_in: i64,
    /// Refresh token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// ID token (for OIDC requests)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Scope (space-separated)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// UserInfo Response
/// 
/// The response from the userinfo endpoint containing user claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    /// Subject identifier (user ID)
    pub sub: String,
    /// Full name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Given name (first name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Family name (last name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Middle name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    /// Nickname
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// Preferred username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// Profile URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Picture URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Website URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// Email address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether email is verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// Gender
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    /// Birthdate (YYYY-MM-DD format)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    /// Timezone
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    /// Locale
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Phone number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// Whether phone number is verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    /// Address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressClaim>,
    /// Last update time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<i64>,
    /// Additional claims
    #[serde(flatten)]
    pub additional_claims: HashMap<String, serde_json::Value>,
}

impl UserInfo {
    /// Create a new UserInfo with subject
    pub fn new(sub: impl Into<String>) -> Self {
        Self {
            sub: sub.into(),
            name: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            preferred_username: None,
            profile: None,
            picture: None,
            website: None,
            email: None,
            email_verified: None,
            gender: None,
            birthdate: None,
            zoneinfo: None,
            locale: None,
            phone_number: None,
            phone_number_verified: None,
            address: None,
            updated_at: None,
            additional_claims: HashMap::new(),
        }
    }

    /// Build UserInfo from JWT claims
    pub fn from_claims(claims: &Claims) -> Self {
        let mut userinfo = Self::new(&claims.sub);
        userinfo.email = claims.email.clone();
        userinfo.email_verified = claims.email_verified;
        userinfo.name = claims.name.clone();
        userinfo
    }
}

/// Address claim for UserInfo
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressClaim {
    /// Full mailing address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// Street address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    /// Locality (city)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// Region (state/province)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Postal code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    /// Country
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// Introspection Request
#[derive(Debug, Clone, Deserialize)]
pub struct IntrospectRequest {
    /// Token to introspect
    pub token: String,
    /// Token type hint (access_token or refresh_token)
    pub token_type_hint: Option<String>,
}

/// Introspection Response
/// 
/// Response from the token introspection endpoint (RFC 7662)
#[derive(Debug, Clone, Serialize)]
pub struct IntrospectResponse {
    /// Whether the token is active
    pub active: bool,
    /// Scope
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Client ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Token type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Expiration time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Issued at (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Not before (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Subject (user ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// Revocation Request
#[derive(Debug, Clone, Deserialize)]
pub struct RevokeRequest {
    /// Token to revoke
    pub token: String,
    /// Token type hint (access_token or refresh_token)
    pub token_type_hint: Option<String>,
}

/// JWKS Response
#[derive(Debug, Clone, Serialize)]
pub struct JwksResponse {
    /// Array of JSON Web Keys
    pub keys: Vec<Jwk>,
}

/// JSON Web Key
#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    /// Key type (e.g., "OKP", "RSA")
    pub kty: String,
    /// Key ID
    pub kid: String,
    /// Key use (sig or enc)
    #[serde(rename = "use")]
    pub use_: String,
    /// Algorithm
    pub alg: String,
    /// Curve (for OKP keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// X coordinate (for OKP keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// RSA modulus (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA exponent (for RSA keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

/// Authorization errors
#[derive(Debug, Clone)]
pub enum AuthorizationError {
    InvalidRequest(String),
    InvalidClient(String),
    InvalidGrant(String),
    UnauthorizedClient(String),
    AccessDenied(String),
    UnsupportedResponseType(String),
    InvalidScope(String),
    ServerError(String),
    TemporarilyUnavailable(String),
    LoginRequired,
    InteractionRequired,
}

impl AuthorizationError {
    /// Get the error code
    pub fn error_code(&self) -> &'static str {
        match self {
            AuthorizationError::InvalidRequest(_) => "invalid_request",
            AuthorizationError::InvalidClient(_) => "invalid_client",
            AuthorizationError::InvalidGrant(_) => "invalid_grant",
            AuthorizationError::UnauthorizedClient(_) => "unauthorized_client",
            AuthorizationError::AccessDenied(_) => "access_denied",
            AuthorizationError::UnsupportedResponseType(_) => "unsupported_response_type",
            AuthorizationError::InvalidScope(_) => "invalid_scope",
            AuthorizationError::ServerError(_) => "server_error",
            AuthorizationError::TemporarilyUnavailable(_) => "temporarily_unavailable",
            AuthorizationError::LoginRequired => "login_required",
            AuthorizationError::InteractionRequired => "interaction_required",
        }
    }

    /// Get the error description
    pub fn description(&self) -> String {
        match self {
            AuthorizationError::InvalidRequest(s) => s.clone(),
            AuthorizationError::InvalidClient(s) => s.clone(),
            AuthorizationError::InvalidGrant(s) => s.clone(),
            AuthorizationError::UnauthorizedClient(s) => s.clone(),
            AuthorizationError::AccessDenied(s) => s.clone(),
            AuthorizationError::UnsupportedResponseType(s) => s.clone(),
            AuthorizationError::InvalidScope(s) => s.clone(),
            AuthorizationError::ServerError(s) => s.clone(),
            AuthorizationError::TemporarilyUnavailable(s) => s.clone(),
            AuthorizationError::LoginRequired => "Login required".to_string(),
            AuthorizationError::InteractionRequired => {
                "User interaction required".to_string()
            }
        }
    }
}

/// OAuth 2.0 error response
#[derive(Debug, Clone, Serialize)]
pub struct OAuthErrorResponse {
    /// Error code
    pub error: String,
    /// Error description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// Error URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
    /// State parameter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl From<AuthorizationError> for OAuthErrorResponse {
    fn from(err: AuthorizationError) -> Self {
        Self {
            error: err.error_code().to_string(),
            error_description: Some(err.description()),
            error_uri: None,
            state: None,
        }
    }
}

/// Generate JWT access token with custom claims
pub fn generate_access_token(
    user_id: impl Into<String>,
    tenant_id: impl Into<String>,
    client_id: impl Into<String>,
    issuer: impl Into<String>,
    scope: Option<String>,
    signing_key: &vault_core::crypto::HybridSigningKey,
) -> Result<String, vault_core::error::VaultError> {
    let mut claims = Claims::new(
        user_id,
        tenant_id,
        TokenType::Access,
        issuer,
        client_id,
    );

    if let Some(scope) = scope {
        claims = claims.with_scope(scope);
    }

    HybridJwt::encode(&claims, signing_key)
}

/// Generate ID token for OIDC
pub fn generate_id_token(
    user_id: impl Into<String>,
    tenant_id: impl Into<String>,
    client_id: impl Into<String>,
    issuer: impl Into<String>,
    user_info: &UserInfo,
    nonce: Option<String>,
    auth_time: Option<i64>,
    signing_key: &vault_core::crypto::HybridSigningKey,
) -> Result<String, vault_core::error::VaultError> {
    let mut claims = Claims::new(
        user_id,
        tenant_id,
        TokenType::Id,
        issuer,
        client_id,
    );

    // Add user info claims
    if let Some(ref email) = user_info.email {
        claims = claims.with_email(email, user_info.email_verified.unwrap_or(false));
    }
    if let Some(ref name) = user_info.name {
        claims = claims.with_name(name);
    }

    // Add nonce if present
    if let Some(nonce) = nonce {
        claims = claims.with_custom("nonce", serde_json::json!(nonce));
    }

    // Add auth_time if present
    if let Some(auth_time) = auth_time {
        claims = claims.with_custom("auth_time", serde_json::json!(auth_time));
    }

    HybridJwt::encode(&claims, signing_key)
}

/// Generate refresh token
pub fn generate_refresh_token(
    user_id: impl Into<String>,
    tenant_id: impl Into<String>,
    client_id: impl Into<String>,
    issuer: impl Into<String>,
    signing_key: &vault_core::crypto::HybridSigningKey,
) -> Result<String, vault_core::error::VaultError> {
    let claims = Claims::new(
        user_id,
        tenant_id,
        TokenType::Refresh,
        issuer,
        client_id,
    )
    .with_expiry(Utc::now() + Duration::days(30));

    HybridJwt::encode(&claims, signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_document() {
        let idp = OidcIdentityProvider::new("https://vault.example.com");
        let doc = idp.discovery_document();

        assert_eq!(doc.issuer, "https://vault.example.com");
        assert!(doc.authorization_endpoint.contains("/oauth/authorize"));
        assert!(doc.token_endpoint.contains("/oauth/token"));
        assert!(doc.userinfo_endpoint.as_ref().unwrap().contains("/oauth/userinfo"));
        assert!(doc.jwks_uri.contains("/oauth/jwks"));
    }

    #[test]
    fn test_authorization_request_parsing() {
        let req = AuthorizationRequest {
            response_type: "code".to_string(),
            client_id: "test-client".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some("openid profile email".to_string()),
            state: Some("abc123".to_string()),
            nonce: Some("nonce123".to_string()),
            code_challenge: None,
            code_challenge_method: None,
            acr_values: None,
            claims: None,
            display: None,
            login_hint: None,
            max_age: None,
            ui_locales: None,
            prompt: None,
        };

        assert!(req.is_oidc_request());
        assert_eq!(req.scopes().len(), 3);
    }

    #[test]
    fn test_userinfo_builder() {
        let userinfo = UserInfo::new("user-123")
            .with_name("John Doe")
            .with_email("john@example.com", true);

        assert_eq!(userinfo.sub, "user-123");
        assert_eq!(userinfo.name, Some("John Doe".to_string()));
        assert_eq!(userinfo.email, Some("john@example.com".to_string()));
        assert_eq!(userinfo.email_verified, Some(true));
    }
}

// Extension trait for building UserInfo
pub trait UserInfoBuilder {
    /// Set the name
    fn with_name(self, name: impl Into<String>) -> Self;
    /// Set the email and verification status
    fn with_email(self, email: impl Into<String>, verified: bool) -> Self;
}

impl UserInfoBuilder for UserInfo {
    fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    fn with_email(mut self, email: impl Into<String>, verified: bool) -> Self {
        self.email = Some(email.into());
        self.email_verified = Some(verified);
        self
    }
}
