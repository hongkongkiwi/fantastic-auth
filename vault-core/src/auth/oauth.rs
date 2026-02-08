//! OAuth 2.0 and OpenID Connect authentication
//!
//! Supports:
//! - Google
//! - GitHub
//! - Microsoft
//! - Apple
//! - Generic OAuth2/OIDC

use crate::error::{Result, VaultError};
use serde::{Deserialize, Serialize};

/// Apple Sign-In specific configuration
#[derive(Debug, Clone)]
pub struct AppleOAuthCredentials {
    /// Services ID (client_id)
    pub client_id: String,
    /// Apple Team ID
    pub team_id: String,
    /// Private Key ID
    pub key_id: String,
    /// Private Key (PEM format)
    pub private_key: String,
    /// Redirect URI
    pub redirect_uri: String,
}

impl AppleOAuthCredentials {
    /// Generate client secret JWT for Apple
    /// Apple requires the client_secret to be a JWT signed with ES256
    pub fn generate_client_secret(&self) -> Result<String> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| VaultError::Internal(format!("Failed to get current time: {}", e)))?
            .as_secs() as i64;

        // Token expires in 6 months (15777000 seconds is Apple's max)
        let exp = now + 15777000;

        let claims = AppleClientSecretClaims {
            iss: self.team_id.clone(),
            iat: now,
            exp,
            aud: "https://appleid.apple.com".to_string(),
            sub: self.client_id.clone(),
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        // Parse the private key
        let encoding_key = EncodingKey::from_ec_pem(self.private_key.as_bytes()).map_err(|e| {
            VaultError::Internal(format!("Failed to parse Apple private key: {}", e))
        })?;

        let token = encode(&header, &claims, &encoding_key).map_err(|e| {
            VaultError::Internal(format!("Failed to generate Apple client secret: {}", e))
        })?;

        Ok(token)
    }
}

/// Claims for Apple client secret JWT
#[derive(Debug, Serialize)]
struct AppleClientSecretClaims {
    /// Issuer (Team ID)
    iss: String,
    /// Issued at
    iat: i64,
    /// Expiration time
    exp: i64,
    /// Audience
    aud: String,
    /// Subject (Services ID)
    sub: String,
}

/// OAuth provider types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthProvider {
    Google,
    GitHub,
    Microsoft,
    Apple,
    Discord,
    Slack,
    Custom,
}

impl OAuthProvider {
    /// Get provider name
    pub fn name(&self) -> &'static str {
        match self {
            OAuthProvider::Google => "google",
            OAuthProvider::GitHub => "github",
            OAuthProvider::Microsoft => "microsoft",
            OAuthProvider::Apple => "apple",
            OAuthProvider::Discord => "discord",
            OAuthProvider::Slack => "slack",
            OAuthProvider::Custom => "custom",
        }
    }

    /// Get authorization endpoint
    pub fn auth_endpoint(&self) -> &str {
        match self {
            OAuthProvider::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            OAuthProvider::GitHub => "https://github.com/login/oauth/authorize",
            OAuthProvider::Microsoft => {
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
            }
            OAuthProvider::Apple => "https://appleid.apple.com/auth/authorize",
            OAuthProvider::Discord => "https://discord.com/oauth2/authorize",
            OAuthProvider::Slack => "https://slack.com/oauth/v2/authorize",
            OAuthProvider::Custom => "",
        }
    }

    /// Get token endpoint
    pub fn token_endpoint(&self) -> &str {
        match self {
            OAuthProvider::Google => "https://oauth2.googleapis.com/token",
            OAuthProvider::GitHub => "https://github.com/login/oauth/access_token",
            OAuthProvider::Microsoft => {
                "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            }
            OAuthProvider::Apple => "https://appleid.apple.com/auth/token",
            OAuthProvider::Discord => "https://discord.com/api/oauth2/token",
            OAuthProvider::Slack => "https://slack.com/api/oauth.v2.access",
            OAuthProvider::Custom => "",
        }
    }

    /// Get userinfo endpoint
    pub fn userinfo_endpoint(&self) -> &str {
        match self {
            OAuthProvider::Google => "https://openidconnect.googleapis.com/v1/userinfo",
            OAuthProvider::GitHub => "https://api.github.com/user",
            OAuthProvider::Microsoft => "https://graph.microsoft.com/oidc/userinfo",
            OAuthProvider::Apple => "https://appleid.apple.com/auth/userinfo",
            OAuthProvider::Discord => "https://discord.com/api/users/@me",
            OAuthProvider::Slack => "https://slack.com/api/users.identity",
            OAuthProvider::Custom => "",
        }
    }

    /// Get default scopes
    pub fn default_scopes(&self) -> Vec<&str> {
        match self {
            OAuthProvider::Google => vec!["openid", "email", "profile"],
            OAuthProvider::GitHub => vec!["user:email", "read:user"],
            OAuthProvider::Microsoft => vec!["openid", "email", "profile"],
            OAuthProvider::Apple => vec!["name", "email"],
            OAuthProvider::Discord => vec!["identify", "email"],
            OAuthProvider::Slack => vec!["identity.basic", "identity.email"],
            OAuthProvider::Custom => vec!["openid", "email", "profile"],
        }
    }
}

/// OAuth configuration
#[derive(Debug, Clone)]
pub struct OAuthConfig {
    /// Provider type
    pub provider: OAuthProvider,
    /// Client ID
    pub client_id: String,
    /// Client secret
    pub client_secret: String,
    /// Redirect URI
    pub redirect_uri: String,
    /// Additional scopes
    pub scopes: Vec<String>,
    /// PKCE enabled
    pub pkce_enabled: bool,
    /// Apple-specific credentials (required for Apple Sign-In)
    pub apple_credentials: Option<AppleOAuthCredentials>,
}

/// OAuth authorization URL request
#[derive(Debug, Clone)]
pub struct AuthUrlRequest {
    /// State parameter (CSRF protection)
    pub state: String,
    /// PKCE code verifier
    pub code_verifier: Option<String>,
    /// Additional scopes
    pub scopes: Vec<String>,
}

/// OAuth callback data
#[derive(Debug, Clone)]
pub struct OAuthCallback {
    /// Authorization code
    pub code: String,
    /// State parameter
    pub state: String,
    /// Error (if any)
    pub error: Option<String>,
}

/// OAuth user info
#[derive(Debug, Clone, Default)]
pub struct OAuthUserInfo {
    /// Provider user ID
    pub id: String,
    /// Email address
    pub email: Option<String>,
    /// Email verified
    pub email_verified: bool,
    /// Full name
    pub name: Option<String>,
    /// Given name
    pub given_name: Option<String>,
    /// Family name
    pub family_name: Option<String>,
    /// Profile picture URL
    pub picture: Option<String>,
    /// Username/handle
    pub username: Option<String>,
    /// Locale
    pub locale: Option<String>,
    /// Raw provider data
    pub raw: serde_json::Value,
}

/// OAuth service
pub struct OAuthService {
    config: OAuthConfig,
    http_client: reqwest::Client,
}

impl OAuthService {
    /// Create new OAuth service
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            config,
            http_client: reqwest::Client::new(),
        }
    }

    /// Generate authorization URL
    pub fn get_authorization_url(&self, request: AuthUrlRequest) -> String {
        let mut url = url::Url::parse(self.config.provider.auth_endpoint()).unwrap();

        let scopes = if request.scopes.is_empty() {
            self.config.provider.default_scopes().join(" ")
        } else {
            request.scopes.join(" ")
        };

        url.query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &scopes)
            .append_pair("state", &request.state);

        // Apple-specific: use form_post response mode
        if self.config.provider == OAuthProvider::Apple {
            url.query_pairs_mut()
                .append_pair("response_mode", "form_post");
        }

        // Add PKCE if enabled
        if self.config.pkce_enabled {
            if let Some(verifier) = request.code_verifier {
                let challenge = Self::generate_code_challenge(&verifier);
                url.query_pairs_mut()
                    .append_pair("code_challenge", &challenge)
                    .append_pair("code_challenge_method", "S256");
            }
        }

        url.to_string()
    }

    /// Exchange code for tokens
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<TokenResponse> {
        // Apple uses a JWT as client_secret instead of a static secret
        let client_secret = if self.config.provider == OAuthProvider::Apple {
            if let Some(ref apple_creds) = self.config.apple_credentials {
                apple_creds.generate_client_secret()?
            } else {
                return Err(VaultError::Internal(
                    "Apple OAuth credentials not configured".into(),
                ));
            }
        } else {
            self.config.client_secret.clone()
        };

        let mut params = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &self.config.client_id),
            ("client_secret", &client_secret),
            ("redirect_uri", &self.config.redirect_uri),
        ];

        if let Some(verifier) = code_verifier {
            params.push(("code_verifier", verifier));
        }

        let response = self
            .http_client
            .post(self.config.provider.token_endpoint())
            .form(&params)
            .send()
            .await
            .map_err(|e| VaultError::ExternalService {
                service: "OAuth".into(),
                message: e.to_string(),
            })?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(VaultError::ExternalService {
                service: "OAuth".into(),
                message: format!("Token exchange failed: {}", error_text),
            });
        }

        let token_response: TokenResponse =
            response
                .json()
                .await
                .map_err(|e| VaultError::ExternalService {
                    service: "OAuth".into(),
                    message: e.to_string(),
                })?;

        Ok(token_response)
    }

    /// Fetch user info
    pub async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo> {
        let response = self
            .http_client
            .get(self.config.provider.userinfo_endpoint())
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| VaultError::ExternalService {
                service: "OAuth".into(),
                message: e.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(VaultError::ExternalService {
                service: "OAuth".into(),
                message: "Failed to fetch user info".into(),
            });
        }

        let raw: serde_json::Value =
            response
                .json()
                .await
                .map_err(|e| VaultError::ExternalService {
                    service: "OAuth".into(),
                    message: e.to_string(),
                })?;

        // Parse based on provider
        let user_info = match self.config.provider {
            OAuthProvider::Google => Self::parse_google_user_info(&raw),
            OAuthProvider::GitHub => Self::parse_github_user_info(&raw),
            OAuthProvider::Microsoft => Self::parse_microsoft_user_info(&raw),
            OAuthProvider::Apple => Self::parse_apple_user_info(&raw),
            _ => Self::parse_generic_user_info(&raw),
        };

        Ok(user_info)
    }

    /// Generate PKCE code challenge
    fn generate_code_challenge(verifier: &str) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        URL_SAFE_NO_PAD
            .encode(hash)
            .replace('+', "-")
            .replace('/', "_")
            .replace('=', "")
    }

    /// Parse Google user info
    fn parse_google_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["sub"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: raw["email_verified"].as_bool().unwrap_or(false),
            name: raw["name"].as_str().map(String::from),
            given_name: raw["given_name"].as_str().map(String::from),
            family_name: raw["family_name"].as_str().map(String::from),
            picture: raw["picture"].as_str().map(String::from),
            username: None,
            locale: raw["locale"].as_str().map(String::from),
            raw: raw.clone(),
        }
    }

    /// Parse GitHub user info
    fn parse_github_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["id"].to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: raw["email"].as_str().is_some(),
            name: raw["name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: raw["avatar_url"].as_str().map(String::from),
            username: raw["login"].as_str().map(String::from),
            locale: None,
            raw: raw.clone(),
        }
    }

    /// Parse Microsoft user info
    fn parse_microsoft_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["oid"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: raw["email"].as_str().is_some(),
            name: raw["name"].as_str().map(String::from),
            given_name: raw["given_name"].as_str().map(String::from),
            family_name: raw["family_name"].as_str().map(String::from),
            picture: None,
            username: None,
            locale: None,
            raw: raw.clone(),
        }
    }

    /// Parse generic user info
    fn parse_generic_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["sub"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: raw["email_verified"].as_bool().unwrap_or(false),
            name: raw["name"].as_str().map(String::from),
            given_name: raw["given_name"].as_str().map(String::from),
            family_name: raw["family_name"].as_str().map(String::from),
            picture: raw["picture"].as_str().map(String::from),
            username: raw["preferred_username"].as_str().map(String::from),
            locale: raw["locale"].as_str().map(String::from),
            raw: raw.clone(),
        }
    }

    /// Parse Apple user info from ID token claims
    /// Note: Apple only returns user info on the first authorization
    fn parse_apple_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        // Apple's ID token contains the user info
        // The "sub" claim is the user's unique ID
        let id = raw["sub"].as_str().unwrap_or("").to_string();

        // Email is only provided on first sign-in, and only if requested
        let email = raw["email"].as_str().map(String::from);

        // Apple always verifies emails for their domain
        let email_verified = email.is_some();

        // Name is only provided on first sign-in as a nested object
        // Format: { "name": { "firstName": "...", "lastName": "..." } }
        let name = if let Some(name_obj) = raw.get("name") {
            let first = name_obj["firstName"].as_str().unwrap_or("");
            let last = name_obj["lastName"].as_str().unwrap_or("");
            let full = format!("{} {}", first, last).trim().to_string();
            if full.is_empty() {
                None
            } else {
                Some(full)
            }
        } else {
            None
        };

        let given_name = raw["name"]["firstName"].as_str().map(String::from);
        let family_name = raw["name"]["lastName"].as_str().map(String::from);

        OAuthUserInfo {
            id,
            email,
            email_verified,
            name,
            given_name,
            family_name,
            picture: None, // Apple doesn't provide profile pictures
            username: None,
            locale: None,
            raw: raw.clone(),
        }
    }
}

/// OAuth token response
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

/// Generate PKCE code verifier
pub fn generate_code_verifier() -> String {
    use rand::Rng;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let mut rng = rand::thread_rng();

    (0..128)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Generate OAuth state parameter
pub fn generate_state() -> String {
    crate::crypto::generate_secure_random(32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_endpoints() {
        assert_eq!(
            OAuthProvider::Google.auth_endpoint(),
            "https://accounts.google.com/o/oauth2/v2/auth"
        );
        assert_eq!(
            OAuthProvider::GitHub.auth_endpoint(),
            "https://github.com/login/oauth/authorize"
        );
    }

    #[test]
    fn test_authorization_url() {
        let config = OAuthConfig {
            provider: OAuthProvider::Google,
            client_id: "test_client".to_string(),
            client_secret: "test_secret".to_string(),
            redirect_uri: "http://localhost/callback".to_string(),
            scopes: vec![],
            pkce_enabled: false,
            apple_credentials: None,
        };

        let service = OAuthService::new(config);
        let request = AuthUrlRequest {
            state: "test_state".to_string(),
            code_verifier: None,
            scopes: vec![],
        };

        let url = service.get_authorization_url(request);
        assert!(url.contains("client_id=test_client"));
        assert!(url.contains("state=test_state"));
        assert!(url.contains("response_type=code"));
    }

    #[test]
    fn test_pkce() {
        let verifier = generate_code_verifier();
        assert_eq!(verifier.len(), 128);

        let challenge = OAuthService::generate_code_challenge(&verifier);
        assert!(!challenge.is_empty());
    }

    #[test]
    fn test_parse_google_user_info() {
        let raw = serde_json::json!({
            "sub": "12345",
            "email": "test@example.com",
            "email_verified": true,
            "name": "Test User",
            "picture": "https://example.com/photo.jpg"
        });

        let info = OAuthService::parse_google_user_info(&raw);
        assert_eq!(info.id, "12345");
        assert_eq!(info.email, Some("test@example.com".to_string()));
        assert_eq!(info.name, Some("Test User".to_string()));
    }
}
