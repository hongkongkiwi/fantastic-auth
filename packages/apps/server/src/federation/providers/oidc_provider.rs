//! OIDC Federation Provider
//!
//! Implements OpenID Connect federation support for Vault.

use std::collections::HashMap;

use base64::Engine;
use serde::Deserialize;

use super::{OidcProviderConfig, TokenResponse};

/// OIDC Federation Provider implementation
#[derive(Debug, Clone)]
pub struct OidcFederationProvider {
    config: OidcProviderConfig,
    http_client: reqwest::Client,
}

/// OIDC discovery document
#[derive(Debug, Deserialize)]
struct OidcDiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    scopes_supported: Option<Vec<String>>,
}

/// Token endpoint response
#[derive(Debug, Deserialize)]
struct TokenEndpointResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// UserInfo response
#[derive(Debug, Deserialize)]
struct UserInfoResponse {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    given_name: Option<String>,
    #[serde(default)]
    family_name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

impl OidcFederationProvider {
    /// Create a new OIDC federation provider
    pub fn new(config: OidcProviderConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self { config, http_client }
    }

    /// Discover OIDC configuration from well-known endpoint
    pub async fn discover(issuer_url: &str) -> anyhow::Result<OidcProviderConfig> {
        let well_known_url = format!("{}/.well-known/openid-configuration", issuer_url.trim_end_matches('/'));
        
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let discovery: OidcDiscoveryDocument = client
            .get(&well_known_url)
            .send()
            .await?
            .json()
            .await?;

        Ok(OidcProviderConfig {
            issuer: discovery.issuer,
            authorization_endpoint: discovery.authorization_endpoint,
            token_endpoint: discovery.token_endpoint,
            userinfo_endpoint: discovery.userinfo_endpoint,
            jwks_uri: discovery.jwks_uri,
            client_id: String::new(), // Must be set by caller
            client_secret: None,
            scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
            claims_mapping: default_claims_mapping(),
            pkce_enabled: true,
        })
    }

    /// Build authorization URL with PKCE support
    pub fn get_authorization_url(
        &self,
        state: &str,
        nonce: &str,
        pkce_challenge: Option<&str>,
        redirect_uri: &str,
    ) -> String {
        let scopes = self.config.scopes.join(" ");
        
        let mut url = format!(
            "{}?client_id={}&response_type=code&scope={}&redirect_uri={}&state={}&nonce={}",
            self.config.authorization_endpoint,
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&scopes),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(nonce)
        );

        // Add PKCE if enabled
        if self.config.pkce_enabled {
            if let Some(challenge) = pkce_challenge {
                url.push_str(&format!(
                    "&code_challenge={}&code_challenge_method=S256",
                    urlencoding::encode(challenge)
                ));
            }
        }

        url
    }

    /// Generate PKCE code challenge from verifier
    pub fn generate_pkce_challenge(verifier: &str) -> String {
        let hash = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash.as_ref())
    }

    /// Generate a PKCE code verifier
    pub fn generate_pkce_verifier() -> String {
        let random_bytes = vault_core::crypto::generate_random_bytes(32);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes)
    }

    /// Exchange authorization code for tokens
    pub async fn exchange_code(
        &self,
        code: &str,
        pkce_verifier: Option<&str>,
        redirect_uri: &str,
    ) -> anyhow::Result<TokenResponse> {
        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &self.config.client_id),
            ("redirect_uri", redirect_uri),
        ];

        // Add client secret if configured
        if let Some(ref secret) = self.config.client_secret {
            params.push(("client_secret", secret));
        }

        // Add PKCE verifier if provided
        if let Some(verifier) = pkce_verifier {
            params.push(("code_verifier", verifier));
        }

        let response = self
            .http_client
            .post(&self.config.token_endpoint)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("Token exchange failed: {}", error_text);
        }

        let token_response: TokenEndpointResponse = response.json().await?;

        Ok(TokenResponse {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_in: token_response.expires_in,
            refresh_token: token_response.refresh_token,
            id_token: token_response.id_token,
            scope: token_response.scope,
        })
    }

    /// Fetch user info from the UserInfo endpoint
    pub async fn get_userinfo(&self, access_token: &str) -> anyhow::Result<HashMap<String, String>> {
        let response = self
            .http_client
            .get(&self.config.userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("UserInfo request failed: {}", error_text);
        }

        let userinfo: UserInfoResponse = response.json().await?;
        
        // Convert to HashMap
        let mut claims = HashMap::new();
        
        if let Some(sub) = userinfo.sub {
            claims.insert("sub".to_string(), sub);
        }
        if let Some(email) = userinfo.email {
            claims.insert("email".to_string(), email);
        }
        if let Some(name) = userinfo.name {
            claims.insert("name".to_string(), name);
        }
        if let Some(given_name) = userinfo.given_name {
            claims.insert("given_name".to_string(), given_name);
        }
        if let Some(family_name) = userinfo.family_name {
            claims.insert("family_name".to_string(), family_name);
        }
        if let Some(picture) = userinfo.picture {
            claims.insert("picture".to_string(), picture);
        }
        if let Some(groups) = userinfo.groups {
            claims.insert("groups".to_string(), groups.join(","));
        }

        // Add any extra claims
        for (key, value) in userinfo.extra {
            if !claims.contains_key(&key) {
                if let Some(s) = value.as_str() {
                    claims.insert(key, s.to_string());
                }
            }
        }

        Ok(claims)
    }

    /// Validate ID token and extract claims
    pub async fn validate_id_token(&self, id_token: &str, expected_nonce: &str) -> anyhow::Result<HashMap<String, String>> {
        // Parse JWT without verification first to get header
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid ID token format");
        }

        // Decode payload
        let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_json)?;

        // Validate issuer
        let issuer = payload["iss"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing issuer claim"))?;
        
        if issuer != self.config.issuer {
            anyhow::bail!("Invalid issuer: expected {}, got {}", self.config.issuer, issuer);
        }

        // Validate audience
        let audience = payload["aud"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing audience claim"))?;
        
        if audience != self.config.client_id {
            anyhow::bail!("Invalid audience");
        }

        // Validate nonce if present in token
        if let Some(token_nonce) = payload["nonce"].as_str() {
            if token_nonce != expected_nonce {
                anyhow::bail!("Nonce mismatch");
            }
        }

        // Validate expiration
        let exp = payload["exp"]
            .as_i64()
            .ok_or_else(|| anyhow::anyhow!("Missing expiration claim"))?;
        
        let now = chrono::Utc::now().timestamp();
        if now > exp {
            anyhow::bail!("ID token expired");
        }

        // Extract claims
        let mut claims = HashMap::new();
        
        if let Some(obj) = payload.as_object() {
            for (key, value) in obj {
                if let Some(s) = value.as_str() {
                    claims.insert(key.clone(), s.to_string());
                } else if let Some(arr) = value.as_array() {
                    // Handle array values (like groups)
                    let values: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect();
                    if !values.is_empty() {
                        claims.insert(key.clone(), values.join(","));
                    }
                }
            }
        }

        Ok(claims)
    }

    /// Refresh an access token using a refresh token
    pub async fn refresh_token(&self, refresh_token: &str) -> anyhow::Result<TokenResponse> {
        let mut params = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.config.client_id),
        ];

        if let Some(ref secret) = self.config.client_secret {
            params.push(("client_secret", secret));
        }

        let response = self
            .http_client
            .post(&self.config.token_endpoint)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("Token refresh failed: {}", error_text);
        }

        let token_response: TokenEndpointResponse = response.json().await?;

        Ok(TokenResponse {
            access_token: token_response.access_token,
            token_type: token_response.token_type,
            expires_in: token_response.expires_in,
            refresh_token: token_response.refresh_token,
            id_token: token_response.id_token,
            scope: token_response.scope,
        })
    }
}

fn default_claims_mapping() -> HashMap<String, String> {
    let mut mapping = HashMap::new();
    mapping.insert("sub".to_string(), "sub".to_string());
    mapping.insert("email".to_string(), "email".to_string());
    mapping.insert("name".to_string(), "name".to_string());
    mapping.insert("given_name".to_string(), "given_name".to_string());
    mapping.insert("family_name".to_string(), "family_name".to_string());
    mapping.insert("picture".to_string(), "picture".to_string());
    mapping.insert("groups".to_string(), "groups".to_string());
    mapping
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_generation() {
        let verifier = OidcFederationProvider::generate_pkce_verifier();
        let challenge = OidcFederationProvider::generate_pkce_challenge(&verifier);
        
        assert!(!verifier.is_empty());
        assert!(!challenge.is_empty());
        assert_ne!(verifier, challenge);
    }

    #[test]
    fn test_authorization_url_building() {
        let config = OidcProviderConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/auth".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: "https://idp.example.com/userinfo".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
            client_id: "my-client".to_string(),
            client_secret: Some("secret".to_string()),
            scopes: vec!["openid".to_string(), "email".to_string()],
            claims_mapping: default_claims_mapping(),
            pkce_enabled: true,
        };

        let provider = OidcFederationProvider::new(config);
        let url = provider.get_authorization_url(
            "my-state",
            "my-nonce",
            Some("my-challenge"),
            "https://app.example.com/callback",
        );

        assert!(url.starts_with("https://idp.example.com/auth"));
        assert!(url.contains("client_id=my-client"));
        assert!(url.contains("state=my-state"));
        assert!(url.contains("nonce=my-nonce"));
        assert!(url.contains("code_challenge=my-challenge"));
    }
}
