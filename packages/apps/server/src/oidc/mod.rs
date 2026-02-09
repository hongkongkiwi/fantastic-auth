//! OIDC Identity Provider Module
//!
//! This module provides a complete OpenID Connect (OIDC) Identity Provider
//! implementation for Vault, allowing it to act as an authentication authority
//! for external applications.
//!
//! ## Features
//!
//! - **OIDC Discovery**: Automatic configuration via `.well-known/openid-configuration`
//! - **Authorization Code Flow**: Standard OAuth 2.0 authorization code grant
//! - **PKCE**: Proof Key for Code Exchange (RFC 7636) for public clients
//! - **Client Credentials**: Machine-to-machine authentication
//! - **Refresh Tokens**: Long-lived tokens for obtaining new access tokens
//! - **ID Tokens**: JWT tokens containing user identity claims
//! - **UserInfo Endpoint**: Retrieve user claims via API
//! - **Token Introspection**: RFC 7662 token validation
//! - **Token Revocation**: RFC 7009 token revocation
//! - **JWKS Endpoint**: Public key distribution for token verification
//! - **Standard Scopes**: Full support for OIDC standard scopes
//!
//! ## Endpoints
//!
//! | Endpoint | Description |
//! |----------|-------------|
//! | `GET /.well-known/openid-configuration` | Discovery document |
//! | `GET /.well-known/jwks.json` | JWKS (alternative path) |
//! | `GET /oauth/authorize` | Authorization endpoint |
//! | `POST /oauth/token` | Token endpoint |
//! | `GET /oauth/userinfo` | UserInfo endpoint |
//! | `POST /oauth/introspect` | Token introspection |
//! | `POST /oauth/revoke` | Token revocation |
//! | `GET /oauth/jwks` | JWKS endpoint |
//!
//! ## Usage Example
//!
//! ```rust
//! use vault_server::oidc::OidcIdentityProvider;
//!
//! let idp = OidcIdentityProvider::new("https://vault.example.com");
//! let discovery = idp.discovery_document();
//! ```

pub mod idp;

// Re-export main types
pub use idp::{
    AuthorizationCodeManager, AuthorizationCodeEntry, AuthorizationRequest,
    ClientManager, ClientRegistrationRequest, ClientRegistrationResponse,
    ClientUpdateRequest, ClientType, GrantHandler, GrantType,
    IntrospectRequest, IntrospectResponse, Jwk, JwksResponse,
    OidcIdentityProvider, DiscoveryDocument, OAuthClient, OAuthErrorResponse,
    PkceParams, RevokeRequest, Scope, ScopeManager, StandardScope,
    TokenEndpointAuthMethod, TokenRequest, TokenResponse, UserInfo, AddressClaim,
    UserInfoBuilder,
};

// Re-export endpoints
pub use idp::routes as idp_routes;
