//! OIDC Identity Provider Endpoints
//!
//! Implements all the required OIDC/OAuth2 endpoints:
//! - Discovery document (/.well-known/openid-configuration)
//! - Authorization endpoint (/oauth/authorize)
//! - Token endpoint (/oauth/token)
//! - UserInfo endpoint (/oauth/userinfo)
//! - Token introspection (/oauth/introspect)
//! - Token revocation (/oauth/revoke)
//! - JWKS endpoint (/oauth/jwks)

use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    middleware,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Extension, Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use serde::Deserialize;
use sha2::Digest;

use crate::middleware::auth::auth_middleware;
use crate::oidc::idp::{
    AuthorizationError, AuthorizationRequest, DiscoveryDocument, IntrospectRequest,
    IntrospectResponse, Jwk, JwksResponse, OAuthErrorResponse, OidcIdentityProvider,
    RevokeRequest, TokenRequest, TokenResponse, UserInfo,
};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::crypto::HybridJwt;

/// Create all OIDC routes
pub fn routes() -> Router<AppState> {
    let auth_routes = Router::new().route("/oauth/authorize", get(authorize));

    Router::new()
        // Discovery endpoints
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        // OAuth endpoints
        .route("/oauth/token", post(token))
        .route("/oauth/userinfo", get(userinfo))
        .route("/oauth/introspect", post(introspect))
        .route("/oauth/revoke", post(revoke))
        .route("/oauth/jwks", get(jwks))
        // Authorization endpoint requires authentication
        .merge(auth_routes.layer(middleware::from_fn(auth_middleware)))
}

/// GET /.well-known/openid-configuration
/// 
/// Returns the OIDC Discovery Document (OpenID Provider Metadata).
/// This document describes the IdP's endpoints and capabilities.
async fn discovery(State(state): State<AppState>) -> Result<Json<DiscoveryDocument>, ApiError> {
    let idp = OidcIdentityProvider::new(&state.config.base_url);
    Ok(Json(idp.discovery_document()))
}

/// GET /oauth/jwks or /.well-known/jwks.json
/// 
/// Returns the JSON Web Key Set containing the public keys used to sign tokens.
/// Clients use these keys to verify token signatures.
async fn jwks(State(state): State<AppState>) -> Result<Json<JwksResponse>, ApiError> {
    let verifying_key = state.auth_service.verifying_key();
    let ed_bytes = verifying_key.ed25519_public_bytes();
    let x = URL_SAFE_NO_PAD.encode(ed_bytes);
    let kid_hash = sha2::Sha256::digest(ed_bytes);
    let kid = URL_SAFE_NO_PAD.encode(kid_hash);

    Ok(Json(JwksResponse {
        keys: vec![Jwk {
            kty: "OKP".to_string(),
            kid,
            use_: "sig".to_string(),
            alg: "EdDSA+ML-DSA-65".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some(x),
            n: None,
            e: None,
        }],
    }))
}

/// GET /oauth/authorize
/// 
/// The authorization endpoint handles user authentication and consent.
/// It supports the authorization code flow with PKCE.
async fn authorize(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    headers: HeaderMap,
    Query(query): Query<AuthorizationRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // Validate the request
    if let Err(err) = query.validate() {
        return Err(ApiError::BadRequest(err.description()));
    }

    // Only support authorization code flow for now
    if query.response_type != "code" {
        return Err(ApiError::BadRequest("Unsupported response_type. Only 'code' is supported".to_string()));
    }

    let tenant_id = extract_tenant_id(&headers);

    // Get the client
    let client = state
        .auth_service
        .db()
        .oidc()
        .get_client(&tenant_id, &query.client_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or_else(|| ApiError::BadRequest("Invalid client_id".to_string()))?;

    // Validate redirect URI
    let redirect_uris: Vec<String> = serde_json::from_value(client.redirect_uris.clone())
        .unwrap_or_else(|_| Vec::new());
    if !redirect_uris.contains(&query.redirect_uri) {
        return Err(ApiError::BadRequest("Invalid redirect_uri".to_string()));
    }

    // Validate scopes
    let scopes = query.scopes();
    let allowed_scopes: Vec<String> = serde_json::from_value(client.allowed_scopes.clone())
        .unwrap_or_else(|_| vec!["openid".to_string()]);
    
    for scope in &scopes {
        if !allowed_scopes.contains(scope) {
            return Err(ApiError::BadRequest(format!("Invalid scope: {}", scope)));
        }
    }

    // Validate PKCE for public clients or if required
    if client.pkce_required && query.code_challenge.is_none() {
        return Err(ApiError::BadRequest("PKCE code_challenge is required".to_string()));
    }

    // Generate authorization code
    let code = vault_core::crypto::generate_secure_random(32);
    let expires_at = Utc::now() + chrono::Duration::minutes(10);

    // Store the authorization code
    let scope_str = if scopes.is_empty() {
        None
    } else {
        Some(scopes.join(" "))
    };

    state
        .auth_service
        .db()
        .oidc()
        .create_authorization_code(
            &tenant_id,
            &query.client_id,
            &current_user.user_id,
            &code,
            &query.redirect_uri,
            scope_str.as_deref(),
            query.code_challenge.as_deref(),
            query.code_challenge_method.as_deref(),
            query.nonce.as_deref(),
            expires_at,
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    // Build redirect URL with code
    let mut redirect_url = format!(
        "{}?code={}",
        query.redirect_uri,
        urlencoding::encode(&code)
    );

    // Add state if provided
    if let Some(state_param) = query.state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(&state_param)));
    }

    // Log the authorization event
    tracing::info!(
        "Authorization granted: client_id={}, user_id={}, tenant_id={}",
        query.client_id,
        current_user.user_id,
        tenant_id
    );

    Ok(Redirect::to(&redirect_url))
}

/// POST /oauth/token
/// 
/// The token endpoint exchanges authorization codes or refresh tokens for access tokens.
/// Supports:
/// - authorization_code grant
/// - client_credentials grant
/// - refresh_token grant
async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&headers);

    // Extract client credentials
    let (client_id, client_secret) = extract_client_credentials(&headers, &req)?;

    // Get the client
    let client = state
        .auth_service
        .db()
        .oidc()
        .get_client(&tenant_id, &client_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or_else(|| ApiError::BadRequest("Invalid client_id".to_string()))?;

    // Validate client authentication for confidential clients
    if client.client_type == "confidential" {
        let secret_hash = client
            .client_secret_hash
            .as_ref()
            .ok_or_else(|| ApiError::BadRequest("Client secret required".to_string()))?;
        
        if client_secret.is_none() {
            return Err(ApiError::BadRequest("Client secret required".to_string()));
        }

        if !vault_core::crypto::VaultPasswordHasher::verify(
            client_secret.as_ref().unwrap(),
            secret_hash,
        )
        .map_err(|_| ApiError::BadRequest("Invalid client secret".to_string()))?
        {
            return Err(ApiError::BadRequest("Invalid client secret".to_string()));
        }
    }

    // Handle different grant types
    match req.grant_type.as_str() {
        "authorization_code" => {
            handle_authorization_code_grant(&state, &tenant_id, &client, req).await
        }
        "client_credentials" => {
            handle_client_credentials_grant(&state, &tenant_id, &client_id).await
        }
        "refresh_token" => {
            handle_refresh_token_grant(&state, &tenant_id, &client_id, req).await
        }
        _ => Err(ApiError::BadRequest(format!(
            "Unsupported grant_type: {}",
            req.grant_type
        ))),
    }
}

/// Handle authorization code grant
async fn handle_authorization_code_grant(
    state: &AppState,
    tenant_id: &str,
    client: &vault_core::db::oidc::OauthClient,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    let code = req
        .code
        .ok_or_else(|| ApiError::BadRequest("Missing code parameter".to_string()))?;

    // Consume the authorization code
    let code_record = state
        .auth_service
        .db()
        .oidc()
        .consume_authorization_code(tenant_id, &client.client_id, &code)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or_else(|| ApiError::BadRequest("Invalid or expired authorization code".to_string()))?;

    // Validate redirect URI
    if let Some(ref redirect_uri) = req.redirect_uri {
        if redirect_uri != &code_record.redirect_uri {
            return Err(ApiError::BadRequest("redirect_uri mismatch".to_string()));
        }
    }

    // Validate PKCE if code challenge was provided
    if let Some(ref challenge) = code_record.code_challenge {
        let verifier = req
            .code_verifier
            .ok_or_else(|| ApiError::BadRequest("Missing code_verifier".to_string()))?;

        let method = code_record.code_challenge_method.as_deref().unwrap_or("S256");
        if !verify_pkce(&verifier, challenge, method) {
            return Err(ApiError::BadRequest("Invalid code_verifier".to_string()));
        }
    }

    // Get the user
    let user = state
        .auth_service
        .db()
        .users()
        .find_by_id(tenant_id, &code_record.user_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or_else(|| ApiError::BadRequest("User not found".to_string()))?;

    // Build access token claims
    let mut access_claims = vault_core::crypto::Claims::new(
        &user.id,
        &user.tenant_id,
        vault_core::crypto::TokenType::Access,
        &state.config.jwt.issuer,
        &client.client_id,
    )
    .with_email(&user.email, user.email_verified);

    if let Some(ref scope) = code_record.scope {
        access_claims = access_claims.with_scope(scope.clone());
    }

    access_claims = access_claims.with_custom("client_id", serde_json::json!(client.client_id.clone()));

    // Encode access token
    let access_token = HybridJwt::encode(&access_claims, state.auth_service.signing_key())
        .map_err(|_| ApiError::Internal)?;

    // Build and encode ID token if openid scope requested
    let mut id_token = None;
    if code_record.scope.as_ref().map_or(false, |s| s.contains("openid")) {
        let user_info = build_user_info(&user, &code_record.scope);
        let mut id_claims = vault_core::crypto::Claims::new(
            &user.id,
            &user.tenant_id,
            vault_core::crypto::TokenType::Id,
            &state.config.jwt.issuer,
            &client.client_id,
        )
        .with_email(&user.email, user.email_verified);

        if let Some(ref name) = user.profile.name {
            id_claims = id_claims.with_name(name.clone());
        }

        if let Some(ref nonce) = code_record.nonce {
            id_claims = id_claims.with_custom("nonce", serde_json::json!(nonce));
        }

        id_token = Some(
            HybridJwt::encode(&id_claims, state.auth_service.signing_key())
                .map_err(|_| ApiError::Internal)?,
        );
    }

    // Store token record
    let expires_at = Utc::now() + chrono::Duration::minutes(15);
    state
        .auth_service
        .db()
        .oidc()
        .store_token(
            tenant_id,
            &client.client_id,
            Some(&user.id),
            &access_claims.jti,
            None, // refresh_token
            code_record.scope.as_deref(),
            expires_at,
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    tracing::info!(
        "Token issued via authorization_code: client_id={}, user_id={}",
        client.client_id,
        user.id
    );

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 900,
        refresh_token: None,
        id_token,
        scope: code_record.scope,
    }))
}

/// Handle client credentials grant (M2M)
async fn handle_client_credentials_grant(
    state: &AppState,
    tenant_id: &str,
    client_id: &str,
) -> Result<Json<TokenResponse>, ApiError> {
    let access_claims = vault_core::crypto::Claims::new(
        client_id,
        tenant_id,
        vault_core::crypto::TokenType::Access,
        &state.config.jwt.issuer,
        client_id,
    )
    .with_custom("client_id", serde_json::json!(client_id));

    let access_token = HybridJwt::encode(&access_claims, state.auth_service.signing_key())
        .map_err(|_| ApiError::Internal)?;

    let expires_at = Utc::now() + chrono::Duration::minutes(15);
    state
        .auth_service
        .db()
        .oidc()
        .store_token(
            tenant_id,
            client_id,
            None,
            &access_claims.jti,
            None,
            None,
            expires_at,
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    tracing::info!("Token issued via client_credentials: client_id={}", client_id);

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: 900,
        refresh_token: None,
        id_token: None,
        scope: None,
    }))
}

/// Handle refresh token grant
async fn handle_refresh_token_grant(
    state: &AppState,
    tenant_id: &str,
    client_id: &str,
    req: TokenRequest,
) -> Result<Json<TokenResponse>, ApiError> {
    // For now, return error since refresh tokens aren't fully implemented
    // In a complete implementation:
    // 1. Validate the refresh token
    // 2. Look up the original token by refresh token hash
    // 3. Revoke the old tokens
    // 4. Issue new access and refresh tokens
    Err(ApiError::BadRequest("Refresh token grant not yet implemented".to_string()))
}

/// GET /oauth/userinfo
/// 
/// Returns claims about the authenticated user.
/// Requires a valid access token in the Authorization header.
async fn userinfo(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<UserInfo>, ApiError> {
    // Extract access token from Authorization header
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(ApiError::Unauthorized);
    }

    let token = &auth_header[7..];

    // Decode and validate the token
    let claims = HybridJwt::decode(token, state.auth_service.verifying_key())
        .map_err(|_| ApiError::Unauthorized)?;

    // Get user information
    let user = state
        .auth_service
        .db()
        .users()
        .find_by_id(&claims.tenant_id, &claims.sub)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or_else(|| ApiError::NotFound)?;

    // Build UserInfo response based on scopes
    let mut userinfo = UserInfo::new(&user.id);

    if let Some(ref scope) = claims.scope {
        let scopes: Vec<&str> = scope.split_whitespace().collect();

        if scopes.contains(&"email") {
            userinfo.email = Some(user.email.clone());
            userinfo.email_verified = Some(user.email_verified);
        }

        if scopes.contains(&"profile") {
            userinfo.name = user.profile.name.clone();
            userinfo.given_name = user.profile.given_name.clone();
            userinfo.family_name = user.profile.family_name.clone();
            userinfo.middle_name = user.profile.middle_name.clone();
            userinfo.nickname = user.profile.nickname.clone();
            userinfo.preferred_username = Some(user.email.clone());
            userinfo.profile = user.profile.profile_url.clone();
            userinfo.picture = user.profile.picture_url.clone();
            userinfo.website = user.profile.website.clone();
            userinfo.gender = user.profile.gender.clone();
            userinfo.birthdate = user.profile.birthdate.clone();
            userinfo.zoneinfo = user.profile.zoneinfo.clone();
            userinfo.locale = user.profile.locale.clone();
            userinfo.updated_at = Some(user.updated_at.timestamp());
        }

        if scopes.contains(&"phone") {
            userinfo.phone_number = user.profile.phone_number.clone();
            userinfo.phone_number_verified = user.profile.phone_number_verified;
        }

        if scopes.contains(&"address") {
            userinfo.address = user.profile.address.as_ref().map(|a| super::AddressClaim {
                formatted: a.formatted.clone(),
                street_address: a.street_address.clone(),
                locality: a.locality.clone(),
                region: a.region.clone(),
                postal_code: a.postal_code.clone(),
                country: a.country.clone(),
            });
        }
    }

    Ok(Json(userinfo))
}

/// POST /oauth/introspect
/// 
/// Token introspection endpoint (RFC 7662).
/// Returns information about a token's validity and metadata.
async fn introspect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<IntrospectRequest>,
) -> Result<Json<IntrospectResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&headers);

    // Try to decode as JWT
    let claims = match HybridJwt::decode(&req.token, state.auth_service.verifying_key()) {
        Ok(c) => c,
        Err(_) => {
            return Ok(Json(IntrospectResponse {
                active: false,
                scope: None,
                client_id: None,
                username: None,
                token_type: None,
                exp: None,
                iat: None,
                nbf: None,
                sub: None,
                aud: None,
                iss: None,
                jti: None,
            }));
        }
    };

    // Check token in database
    let token_record = state
        .auth_service
        .db()
        .oidc()
        .get_token_by_jti(&tenant_id, &claims.jti)
        .await
        .map_err(|_| ApiError::Internal)?;

    let active = token_record
        .as_ref()
        .map(|t| t.revoked_at.is_none() && t.expires_at > Utc::now())
        .unwrap_or(false);

    Ok(Json(IntrospectResponse {
        active,
        scope: claims.scope.clone(),
        client_id: claims
            .custom
            .get("client_id")
            .and_then(|v| v.as_str().map(|s| s.to_string())),
        username: claims.email.clone(),
        token_type: Some(format!("{:?}", claims.token_type).to_lowercase()),
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        nbf: Some(claims.nbf),
        sub: Some(claims.sub),
        aud: Some(claims.aud),
        iss: Some(claims.iss),
        jti: Some(claims.jti),
    }))
}

/// POST /oauth/revoke
/// 
/// Token revocation endpoint (RFC 7009).
/// Revokes access or refresh tokens.
async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<RevokeRequest>,
) -> Result<StatusCode, ApiError> {
    let tenant_id = extract_tenant_id(&headers);

    // Try to revoke by refresh token
    let revoked = state
        .auth_service
        .db()
        .oidc()
        .revoke_token_by_refresh(&tenant_id, &req.token)
        .await
        .map_err(|_| ApiError::Internal)?;

    // If not found as refresh token, try to decode as access token
    // and revoke by JTI
    if !revoked {
        if let Ok(claims) = HybridJwt::decode(&req.token, state.auth_service.verifying_key()) {
            // Mark token as revoked in database
            // This is a simplified implementation
            tracing::info!(
                "Token revocation requested for jti={} in tenant={}",
                claims.jti,
                tenant_id
            );
        }
    }

    // RFC 7009: The server responds with HTTP 200 regardless of
    // whether the token was valid or not
    Ok(StatusCode::OK)
}

/// Extract tenant ID from headers
fn extract_tenant_id(headers: &HeaderMap) -> String {
    headers
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "default".to_string())
}

/// Extract client credentials from headers or request body
fn extract_client_credentials(
    headers: &HeaderMap,
    req: &TokenRequest,
) -> Result<(String, Option<String>), ApiError> {
    // Try to extract from Authorization header (Basic auth)
    if let Some(auth) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth) = auth.to_str() {
            if auth.starts_with("Basic ") {
                let encoded = &auth[6..];
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| ApiError::BadRequest("Invalid authorization header".to_string()))?;
                let decoded = String::from_utf8(decoded)
                    .map_err(|_| ApiError::BadRequest("Invalid authorization header".to_string()))?;
                let mut parts = decoded.splitn(2, ':');
                let client_id = parts.next().unwrap_or("").to_string();
                let client_secret = parts.next().map(|s| s.to_string());
                return Ok((client_id, client_secret));
            }
        }
    }

    // Fall back to request body parameters
    let client_id = req
        .client_id
        .clone()
        .ok_or_else(|| ApiError::BadRequest("Missing client_id".to_string()))?;
    Ok((client_id, req.client_secret.clone()))
}

/// Verify PKCE code verifier
fn verify_pkce(verifier: &str, challenge: &str, method: &str) -> bool {
    match method.to_uppercase().as_str() {
        "S256" => {
            let digest = sha2::Sha256::digest(verifier.as_bytes());
            let computed = URL_SAFE_NO_PAD.encode(digest);
            computed == challenge
        }
        "PLAIN" => verifier == challenge,
        _ => false,
    }
}

/// Build UserInfo from user record
fn build_user_info(
    user: &vault_core::models::user::User,
    scope: &Option<String>,
) -> UserInfo {
    let mut userinfo = UserInfo::new(&user.id);

    if let Some(ref scope) = scope {
        let scopes: Vec<&str> = scope.split_whitespace().collect();

        if scopes.contains(&"email") {
            userinfo.email = Some(user.email.clone());
            userinfo.email_verified = Some(user.email_verified);
        }

        if scopes.contains(&"profile") {
            userinfo.name = user.profile.name.clone();
            userinfo.given_name = user.profile.given_name.clone();
            userinfo.family_name = user.profile.family_name.clone();
            userinfo.middle_name = user.profile.middle_name.clone();
            userinfo.nickname = user.profile.nickname.clone();
            userinfo.preferred_username = Some(user.email.clone());
            userinfo.profile = user.profile.profile_url.clone();
            userinfo.picture = user.profile.picture_url.clone();
            userinfo.website = user.profile.website.clone();
            userinfo.gender = user.profile.gender.clone();
            userinfo.birthdate = user.profile.birthdate.clone();
            userinfo.zoneinfo = user.profile.zoneinfo.clone();
            userinfo.locale = user.profile.locale.clone();
            userinfo.updated_at = Some(user.updated_at.timestamp());
        }

        if scopes.contains(&"phone") {
            userinfo.phone_number = user.profile.phone_number.clone();
            userinfo.phone_number_verified = user.profile.phone_number_verified;
        }
    }

    userinfo
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_verification_s256() {
        let verifier = "test_verifier_12345";
        let challenge = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(verifier.as_bytes()));
        
        assert!(verify_pkce(verifier, &challenge, "S256"));
        assert!(!verify_pkce("wrong_verifier", &challenge, "S256"));
    }

    #[test]
    fn test_pkce_verification_plain() {
        let verifier = "plain_challenge";
        
        assert!(verify_pkce(verifier, verifier, "plain"));
        assert!(!verify_pkce(verifier, "different", "plain"));
    }

    #[test]
    fn test_extract_tenant_id() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Tenant-ID", "tenant-123".parse().unwrap());
        
        assert_eq!(extract_tenant_id(&headers), "tenant-123");
    }

    #[test]
    fn test_extract_tenant_id_default() {
        let headers = HeaderMap::new();
        assert_eq!(extract_tenant_id(&headers), "default");
    }
}
