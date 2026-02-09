//! OAuth 2.0 Grant Handlers
//!
//! This module implements the different OAuth 2.0 grant types:
//! - Authorization Code Grant (RFC 6749, Section 4.1)
//! - Client Credentials Grant (RFC 6749, Section 4.4)
//! - Refresh Token Grant (RFC 6749, Section 6)
//! - Device Code Grant (RFC 8628) - Optional
//!
//! Each grant type has specific requirements and security considerations.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::oidc::idp::{
    ClientType, GrantType, OAuthClient, TokenResponse, UserInfo,
};

/// Grant handler for processing OAuth 2.0 token requests
#[derive(Debug, Clone)]
pub struct GrantHandler {
    /// Access token lifetime in minutes
    pub access_token_lifetime: i64,
    /// Refresh token lifetime in days
    pub refresh_token_lifetime: i64,
    /// ID token lifetime in minutes
    pub id_token_lifetime: i64,
    /// Whether to issue refresh tokens
    pub issue_refresh_tokens: bool,
    /// Whether to rotate refresh tokens
    pub rotate_refresh_tokens: bool,
}

impl GrantHandler {
    /// Create a new grant handler with default settings
    pub fn new() -> Self {
        Self {
            access_token_lifetime: 15,  // 15 minutes
            refresh_token_lifetime: 30, // 30 days
            id_token_lifetime: 60,      // 60 minutes
            issue_refresh_tokens: true,
            rotate_refresh_tokens: true,
        }
    }

    /// Set access token lifetime
    pub fn with_access_token_lifetime(mut self, minutes: i64) -> Self {
        self.access_token_lifetime = minutes;
        self
    }

    /// Set refresh token lifetime
    pub fn with_refresh_token_lifetime(mut self, days: i64) -> Self {
        self.refresh_token_lifetime = days;
        self
    }

    /// Set whether to issue refresh tokens
    pub fn with_refresh_tokens(mut self, issue: bool) -> Self {
        self.issue_refresh_tokens = issue;
        self
    }

    /// Set whether to rotate refresh tokens
    pub fn with_refresh_token_rotation(mut self, rotate: bool) -> Self {
        self.rotate_refresh_tokens = rotate;
        self
    }

    /// Calculate access token expiration
    pub fn access_token_expires_at(&self) -> DateTime<Utc> {
        Utc::now() + Duration::minutes(self.access_token_lifetime)
    }

    /// Calculate refresh token expiration
    pub fn refresh_token_expires_at(&self) -> DateTime<Utc> {
        Utc::now() + Duration::days(self.refresh_token_lifetime)
    }

    /// Calculate ID token expiration
    pub fn id_token_expires_at(&self) -> DateTime<Utc> {
        Utc::now() + Duration::minutes(self.id_token_lifetime)
    }

    /// Check if a grant type is supported
    pub fn is_grant_supported(&self, grant_type: &GrantType) -> bool {
        match grant_type {
            GrantType::AuthorizationCode => true,
            GrantType::ClientCredentials => true,
            GrantType::RefreshToken => self.issue_refresh_tokens,
            GrantType::DeviceCode => true, // Optional support
            // Deprecated grant types
            GrantType::Implicit | GrantType::Password => false,
        }
    }
}

impl Default for GrantHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Authorization Code Grant context
/// 
/// Contains all the information needed to process an authorization code exchange.
#[derive(Debug, Clone)]
pub struct AuthorizationCodeContext {
    /// The authorization code
    pub code: String,
    /// Redirect URI (must match the one used in authorization request)
    pub redirect_uri: Option<String>,
    /// PKCE code verifier
    pub code_verifier: Option<String>,
    /// Client ID
    pub client_id: String,
    /// Requested scopes (defaults to authorized scopes if not specified)
    pub scope: Option<String>,
}

/// Authorization Code Grant result
#[derive(Debug, Clone)]
pub struct AuthorizationCodeResult {
    /// The user ID
    pub user_id: String,
    /// The authorized scopes
    pub scope: Option<String>,
    /// The nonce from the authorization request
    pub nonce: Option<String>,
    /// Authentication time (Unix timestamp)
    pub auth_time: i64,
}

/// Client Credentials Grant context
/// 
/// Used for machine-to-machine authentication.
#[derive(Debug, Clone)]
pub struct ClientCredentialsContext {
    /// Client ID
    pub client_id: String,
    /// Requested scopes
    pub scope: Option<String>,
}

/// Client Credentials Grant result
#[derive(Debug, Clone)]
pub struct ClientCredentialsResult {
    /// The granted scopes
    pub scope: Option<String>,
}

/// Refresh Token Grant context
/// 
/// Used to exchange a refresh token for a new access token.
#[derive(Debug, Clone)]
pub struct RefreshTokenContext {
    /// The refresh token
    pub refresh_token: String,
    /// Requested scopes (must be subset of original scopes)
    pub scope: Option<String>,
}

/// Refresh Token Grant result
#[derive(Debug, Clone)]
pub struct RefreshTokenResult {
    /// The user ID (if applicable)
    pub user_id: Option<String>,
    /// The original authorized scopes
    pub scope: Option<String>,
    /// The original client ID
    pub original_client_id: String,
}

/// Device Code Grant context
/// 
/// Used for device authorization flow (RFC 8628).
#[derive(Debug, Clone)]
pub struct DeviceCodeContext {
    /// Device code
    pub device_code: String,
    /// Client ID
    pub client_id: String,
}

/// Token generation parameters
#[derive(Debug, Clone)]
pub struct TokenGenerationParams {
    /// User ID (None for client credentials)
    pub user_id: Option<String>,
    /// Tenant ID
    pub tenant_id: String,
    /// Client ID
    pub client_id: String,
    /// Scopes
    pub scope: Option<String>,
    /// Nonce (for ID tokens)
    pub nonce: Option<String>,
    /// Authentication time (for ID tokens)
    pub auth_time: Option<i64>,
    /// Whether to include an ID token
    pub include_id_token: bool,
    /// Whether to include a refresh token
    pub include_refresh_token: bool,
    /// User info (for ID tokens)
    pub user_info: Option<UserInfo>,
}

/// Grant processing result
#[derive(Debug, Clone)]
pub enum GrantResult {
    /// Authorization code grant successful
    AuthorizationCode(AuthorizationCodeResult),
    /// Client credentials grant successful
    ClientCredentials(ClientCredentialsResult),
    /// Refresh token grant successful
    RefreshToken(RefreshTokenResult),
    /// Device code grant pending
    DeviceCodePending {
        /// User code to display
        user_code: String,
        /// Verification URI
        verification_uri: String,
        /// Expires in seconds
        expires_in: i64,
        /// Polling interval in seconds
        interval: i64,
    },
    /// Device code grant successful
    DeviceCodeSuccess(AuthorizationCodeResult),
}

/// Grant error types
#[derive(Debug, Clone)]
pub enum GrantError {
    /// Invalid request parameters
    InvalidRequest(String),
    /// Invalid client authentication
    InvalidClient(String),
    /// Invalid grant (expired code, revoked token, etc.)
    InvalidGrant(String),
    /// Unauthorized client for this grant type
    UnauthorizedClient(String),
    /// Unsupported grant type
    UnsupportedGrantType(String),
    /// Invalid scope
    InvalidScope(String),
    /// Access denied
    AccessDenied(String),
    /// Server error
    ServerError(String),
    /// Authorization pending (for device flow)
    AuthorizationPending,
    /// Slow down polling (for device flow)
    SlowDown,
    /// Expired token (for device flow)
    ExpiredToken,
}

impl GrantError {
    /// Get the OAuth 2.0 error code
    pub fn error_code(&self) -> &'static str {
        match self {
            GrantError::InvalidRequest(_) => "invalid_request",
            GrantError::InvalidClient(_) => "invalid_client",
            GrantError::InvalidGrant(_) => "invalid_grant",
            GrantError::UnauthorizedClient(_) => "unauthorized_client",
            GrantError::UnsupportedGrantType(_) => "unsupported_grant_type",
            GrantError::InvalidScope(_) => "invalid_scope",
            GrantError::AccessDenied(_) => "access_denied",
            GrantError::ServerError(_) => "server_error",
            GrantError::AuthorizationPending => "authorization_pending",
            GrantError::SlowDown => "slow_down",
            GrantError::ExpiredToken => "expired_token",
        }
    }

    /// Get the error description
    pub fn description(&self) -> String {
        match self {
            GrantError::InvalidRequest(s) => s.clone(),
            GrantError::InvalidClient(s) => s.clone(),
            GrantError::InvalidGrant(s) => s.clone(),
            GrantError::UnauthorizedClient(s) => s.clone(),
            GrantError::UnsupportedGrantType(s) => s.clone(),
            GrantError::InvalidScope(s) => s.clone(),
            GrantError::AccessDenied(s) => s.clone(),
            GrantError::ServerError(s) => s.clone(),
            GrantError::AuthorizationPending => {
                "Authorization request is still pending".to_string()
            }
            GrantError::SlowDown => "Please slow down your polling".to_string(),
            GrantError::ExpiredToken => "The token has expired".to_string(),
        }
    }
}

/// Device authorization request (RFC 8628)
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAuthorizationRequest {
    /// Client ID
    pub client_id: String,
    /// Optional scope
    pub scope: Option<String>,
}

/// Device authorization response
#[derive(Debug, Clone, Serialize)]
pub struct DeviceAuthorizationResponse {
    /// Device verification code
    pub device_code: String,
    /// User verification code
    pub user_code: String,
    /// Verification URI
    pub verification_uri: String,
    /// Complete verification URI with user code
    pub verification_uri_complete: Option<String>,
    /// Expires in seconds
    pub expires_in: i64,
    /// Minimum polling interval in seconds
    pub interval: i64,
}

/// Device authorization session
#[derive(Debug, Clone)]
pub struct DeviceAuthorizationSession {
    /// Device code
    pub device_code: String,
    /// User code
    pub user_code: String,
    /// Client ID
    pub client_id: String,
    /// Scopes
    pub scope: Option<String>,
    /// Expiration time
    pub expires_at: DateTime<Utc>,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last poll time
    pub last_poll_at: Option<DateTime<Utc>>,
    /// Polling interval in seconds
    pub interval: i64,
    /// User ID (set when user authorizes)
    pub user_id: Option<String>,
    /// Authorization status
    pub status: DeviceAuthorizationStatus,
}

/// Device authorization status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAuthorizationStatus {
    /// Pending user authorization
    Pending,
    /// Authorized by user
    Authorized,
    /// Denied by user
    Denied,
    /// Expired
    Expired,
}

impl DeviceAuthorizationSession {
    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at || self.status == DeviceAuthorizationStatus::Expired
    }

    /// Check if polling is allowed (rate limiting)
    pub fn can_poll(&self) -> bool {
        match self.last_poll_at {
            Some(last) => {
                let elapsed = Utc::now() - last;
                elapsed.num_seconds() >= self.interval
            }
            None => true,
        }
    }

    /// Record a poll attempt
    pub fn record_poll(&mut self) {
        self.last_poll_at = Some(Utc::now());
    }
}

/// Default scopes for different grant types
pub fn default_scopes_for_grant(grant_type: &GrantType) -> Vec<String> {
    match grant_type {
        GrantType::AuthorizationCode => vec!["openid".to_string()],
        GrantType::ClientCredentials => vec![],
        GrantType::RefreshToken => vec![],
        GrantType::DeviceCode => vec!["openid".to_string()],
        _ => vec![],
    }
}

/// Filter scopes based on what was originally authorized
/// 
/// When refreshing a token, the requested scopes must be a subset
/// of the originally authorized scopes.
pub fn filter_scopes(requested: Option<&str>, authorized: Option<&str>) -> Option<String> {
    let requested_set: std::collections::HashSet<String> = requested
        .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
        .unwrap_or_default();

    let authorized_set: std::collections::HashSet<String> = authorized
        .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
        .unwrap_or_default();

    if requested_set.is_empty() {
        // If no scopes requested, return all authorized scopes
        return authorized.map(|s| s.to_string());
    }

    // Check that all requested scopes are authorized
    if !requested_set.is_subset(&authorized_set) {
        return None;
    }

    Some(requested_set.into_iter().collect::<Vec<_>>().join(" "))
}

/// Generate a unique user code for device flow
/// 
/// Format: XXXX-XXXX (easy to type)
pub fn generate_user_code() -> String {
    // Use secure random generation instead of thread_rng for consistency
    let bytes = vault_core::crypto::generate_random_bytes(4);
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Removed confusing chars
    
    let part1: String = bytes[..2]
        .iter()
        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
        .collect();
    let part2: String = bytes[2..]
        .iter()
        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
        .collect();
    
    format!("{}-{}", part1, part2)
}

/// Generate a device code
/// 
/// Returns a secure random code with high entropy.
pub fn generate_device_code() -> String {
    vault_core::crypto::generate_secure_random(32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grant_handler_default() {
        let handler = GrantHandler::new();
        assert_eq!(handler.access_token_lifetime, 15);
        assert_eq!(handler.refresh_token_lifetime, 30);
        assert!(handler.issue_refresh_tokens);
        assert!(handler.rotate_refresh_tokens);
    }

    #[test]
    fn test_grant_handler_builder() {
        let handler = GrantHandler::new()
            .with_access_token_lifetime(30)
            .with_refresh_token_lifetime(60)
            .with_refresh_tokens(false)
            .with_refresh_token_rotation(false);
        
        assert_eq!(handler.access_token_lifetime, 30);
        assert_eq!(handler.refresh_token_lifetime, 60);
        assert!(!handler.issue_refresh_tokens);
        assert!(!handler.rotate_refresh_tokens);
    }

    #[test]
    fn test_grant_supported() {
        let handler = GrantHandler::new();
        
        assert!(handler.is_grant_supported(&GrantType::AuthorizationCode));
        assert!(handler.is_grant_supported(&GrantType::ClientCredentials));
        assert!(handler.is_grant_supported(&GrantType::RefreshToken));
        assert!(handler.is_grant_supported(&GrantType::DeviceCode));
        
        // Deprecated grants not supported
        assert!(!handler.is_grant_supported(&GrantType::Implicit));
        assert!(!handler.is_grant_supported(&GrantType::Password));
    }

    #[test]
    fn test_scope_filtering() {
        // Requested is subset of authorized
        let result = filter_scopes(Some("openid email"), Some("openid profile email"));
        assert_eq!(result, Some("openid email".to_string()));
        
        // Requested equals authorized
        let result = filter_scopes(Some("openid email"), Some("openid email"));
        assert_eq!(result, Some("openid email".to_string()));
        
        // Requested has scope not in authorized
        let result = filter_scopes(Some("openid admin"), Some("openid email"));
        assert_eq!(result, None);
        
        // No requested scopes - return all authorized
        let result = filter_scopes(None, Some("openid email"));
        assert_eq!(result, Some("openid email".to_string()));
        
        // Empty requested scopes
        let result = filter_scopes(Some(""), Some("openid email"));
        assert_eq!(result, Some("openid email".to_string()));
    }

    #[test]
    fn test_grant_error_codes() {
        let error = GrantError::InvalidRequest("test".to_string());
        assert_eq!(error.error_code(), "invalid_request");
        
        let error = GrantError::InvalidGrant("expired".to_string());
        assert_eq!(error.error_code(), "invalid_grant");
        
        let error = GrantError::AuthorizationPending;
        assert_eq!(error.error_code(), "authorization_pending");
    }

    #[test]
    fn test_device_session() {
        let mut session = DeviceAuthorizationSession {
            device_code: "device-123".to_string(),
            user_code: "USER-CODE".to_string(),
            client_id: "client-123".to_string(),
            scope: Some("openid".to_string()),
            expires_at: Utc::now() + Duration::minutes(10),
            created_at: Utc::now(),
            last_poll_at: None,
            interval: 5,
            user_id: None,
            status: DeviceAuthorizationStatus::Pending,
        };
        
        assert!(!session.is_expired());
        assert!(session.can_poll());
        
        session.record_poll();
        assert!(!session.can_poll()); // Just polled
        
        // Mark as expired
        session.expires_at = Utc::now() - Duration::minutes(1);
        assert!(session.is_expired());
    }

    #[test]
    fn test_generate_user_code() {
        let code = generate_user_code();
        assert_eq!(code.len(), 9); // XXXX-XXXX
        assert!(code.contains('-'));
        
        // Should be uppercase alphanumeric (excluding confusing chars)
        assert!(code.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'));
    }

    #[test]
    fn test_generate_device_code() {
        let code = generate_device_code();
        assert_eq!(code.len(), 43); // 32 bytes base64url
    }

    #[test]
    fn test_default_scopes() {
        let auth_code_scopes = default_scopes_for_grant(&GrantType::AuthorizationCode);
        assert!(auth_code_scopes.contains(&"openid".to_string()));
        
        let client_creds_scopes = default_scopes_for_grant(&GrantType::ClientCredentials);
        assert!(client_creds_scopes.is_empty());
    }
}
