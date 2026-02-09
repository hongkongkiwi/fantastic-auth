//! OAuth 2.0 and OpenID Connect authentication
//!
//! Supports 30+ OAuth providers:
//! Social/Consumer: Google, GitHub, Facebook, Twitter/X, Instagram, TikTok, Snapchat, Pinterest, Reddit, Twitch, Spotify, Discord, Slack
//! Professional: LinkedIn, Microsoft, Apple
//! Developer/Tech: GitLab, Bitbucket, DigitalOcean, Heroku, Vercel, Netlify, Cloudflare
//! Enterprise: Salesforce, HubSpot, Zendesk, Notion, Figma, Linear, Atlassian (Jira/Confluence), Okta
//! Regional: WeChat, LINE, KakaoTalk, VKontakte (VK), Yandex

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

/// OAuth provider types - 30+ providers supported
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthProvider {
    // Existing providers
    Google,
    GitHub,
    Microsoft,
    Apple,
    Discord,
    Slack,

    // Social/Consumer
    Facebook,
    Twitter,
    Instagram,
    TikTok,
    Snapchat,
    Pinterest,
    Reddit,
    Twitch,
    Spotify,

    // Professional
    LinkedIn,

    // Developer/Tech
    GitLab,
    Bitbucket,
    DigitalOcean,
    Heroku,
    Vercel,
    Netlify,
    Cloudflare,

    // Enterprise
    Salesforce,
    HubSpot,
    Zendesk,
    Notion,
    Figma,
    Linear,
    Atlassian,
    Okta,

    // Regional
    WeChat,
    Line,
    KakaoTalk,
    Vkontakte,
    Yandex,

    // Custom/generic
    Custom,
}

impl OAuthProvider {
    /// Get provider name
    pub fn name(&self) -> &'static str {
        match self {
            // Existing providers
            OAuthProvider::Google => "google",
            OAuthProvider::GitHub => "github",
            OAuthProvider::Microsoft => "microsoft",
            OAuthProvider::Apple => "apple",
            OAuthProvider::Discord => "discord",
            OAuthProvider::Slack => "slack",

            // Social/Consumer
            OAuthProvider::Facebook => "facebook",
            OAuthProvider::Twitter => "twitter",
            OAuthProvider::Instagram => "instagram",
            OAuthProvider::TikTok => "tiktok",
            OAuthProvider::Snapchat => "snapchat",
            OAuthProvider::Pinterest => "pinterest",
            OAuthProvider::Reddit => "reddit",
            OAuthProvider::Twitch => "twitch",
            OAuthProvider::Spotify => "spotify",

            // Professional
            OAuthProvider::LinkedIn => "linkedin",

            // Developer/Tech
            OAuthProvider::GitLab => "gitlab",
            OAuthProvider::Bitbucket => "bitbucket",
            OAuthProvider::DigitalOcean => "digitalocean",
            OAuthProvider::Heroku => "heroku",
            OAuthProvider::Vercel => "vercel",
            OAuthProvider::Netlify => "netlify",
            OAuthProvider::Cloudflare => "cloudflare",

            // Enterprise
            OAuthProvider::Salesforce => "salesforce",
            OAuthProvider::HubSpot => "hubspot",
            OAuthProvider::Zendesk => "zendesk",
            OAuthProvider::Notion => "notion",
            OAuthProvider::Figma => "figma",
            OAuthProvider::Linear => "linear",
            OAuthProvider::Atlassian => "atlassian",
            OAuthProvider::Okta => "okta",

            // Regional
            OAuthProvider::WeChat => "wechat",
            OAuthProvider::Line => "line",
            OAuthProvider::KakaoTalk => "kakaotalk",
            OAuthProvider::Vkontakte => "vkontakte",
            OAuthProvider::Yandex => "yandex",

            // Custom
            OAuthProvider::Custom => "custom",
        }
    }

    /// Get display name for UI
    pub fn display_name(&self) -> &'static str {
        match self {
            OAuthProvider::Google => "Google",
            OAuthProvider::GitHub => "GitHub",
            OAuthProvider::Microsoft => "Microsoft",
            OAuthProvider::Apple => "Apple",
            OAuthProvider::Discord => "Discord",
            OAuthProvider::Slack => "Slack",
            OAuthProvider::Facebook => "Facebook",
            OAuthProvider::Twitter => "X (Twitter)",
            OAuthProvider::Instagram => "Instagram",
            OAuthProvider::TikTok => "TikTok",
            OAuthProvider::Snapchat => "Snapchat",
            OAuthProvider::Pinterest => "Pinterest",
            OAuthProvider::Reddit => "Reddit",
            OAuthProvider::Twitch => "Twitch",
            OAuthProvider::Spotify => "Spotify",
            OAuthProvider::LinkedIn => "LinkedIn",
            OAuthProvider::GitLab => "GitLab",
            OAuthProvider::Bitbucket => "Bitbucket",
            OAuthProvider::DigitalOcean => "DigitalOcean",
            OAuthProvider::Heroku => "Heroku",
            OAuthProvider::Vercel => "Vercel",
            OAuthProvider::Netlify => "Netlify",
            OAuthProvider::Cloudflare => "Cloudflare",
            OAuthProvider::Salesforce => "Salesforce",
            OAuthProvider::HubSpot => "HubSpot",
            OAuthProvider::Zendesk => "Zendesk",
            OAuthProvider::Notion => "Notion",
            OAuthProvider::Figma => "Figma",
            OAuthProvider::Linear => "Linear",
            OAuthProvider::Atlassian => "Atlassian",
            OAuthProvider::Okta => "Okta",
            OAuthProvider::WeChat => "WeChat",
            OAuthProvider::Line => "LINE",
            OAuthProvider::KakaoTalk => "KakaoTalk",
            OAuthProvider::Vkontakte => "VKontakte",
            OAuthProvider::Yandex => "Yandex",
            OAuthProvider::Custom => "Custom",
        }
    }

    /// Get authorization endpoint
    pub fn auth_endpoint(&self) -> &str {
        match self {
            // Existing providers
            OAuthProvider::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            OAuthProvider::GitHub => "https://github.com/login/oauth/authorize",
            OAuthProvider::Microsoft => {
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
            }
            OAuthProvider::Apple => "https://appleid.apple.com/auth/authorize",
            OAuthProvider::Discord => "https://discord.com/oauth2/authorize",
            OAuthProvider::Slack => "https://slack.com/oauth/v2/authorize",

            // Social/Consumer
            OAuthProvider::Facebook => "https://www.facebook.com/v18.0/dialog/oauth",
            OAuthProvider::Twitter => "https://twitter.com/i/oauth2/authorize",
            OAuthProvider::Instagram => "https://api.instagram.com/oauth/authorize",
            OAuthProvider::TikTok => "https://www.tiktok.com/auth/authorize",
            OAuthProvider::Snapchat => "https://accounts.snapchat.com/accounts/oauth2/auth",
            OAuthProvider::Pinterest => "https://www.pinterest.com/oauth",
            OAuthProvider::Reddit => "https://www.reddit.com/api/v1/authorize",
            OAuthProvider::Twitch => "https://id.twitch.tv/oauth2/authorize",
            OAuthProvider::Spotify => "https://accounts.spotify.com/authorize",

            // Professional
            OAuthProvider::LinkedIn => "https://www.linkedin.com/oauth/v2/authorization",

            // Developer/Tech
            OAuthProvider::GitLab => "https://gitlab.com/oauth/authorize",
            OAuthProvider::Bitbucket => "https://bitbucket.org/site/oauth2/authorize",
            OAuthProvider::DigitalOcean => "https://cloud.digitalocean.com/v1/oauth/authorize",
            OAuthProvider::Heroku => "https://id.heroku.com/oauth/authorize",
            OAuthProvider::Vercel => "https://vercel.com/oauth/authorize",
            OAuthProvider::Netlify => "https://app.netlify.com/authorize",
            OAuthProvider::Cloudflare => "https://dash.cloudflare.com/oauth2/auth",

            // Enterprise
            OAuthProvider::Salesforce => "https://login.salesforce.com/services/oauth2/authorize",
            OAuthProvider::HubSpot => "https://app.hubspot.com/oauth/authorize",
            OAuthProvider::Zendesk => "https://{subdomain}.zendesk.com/oauth/authorizations/new",
            OAuthProvider::Notion => "https://api.notion.com/v1/oauth/authorize",
            OAuthProvider::Figma => "https://www.figma.com/oauth",
            OAuthProvider::Linear => "https://linear.app/oauth/authorize",
            OAuthProvider::Atlassian => "https://auth.atlassian.com/authorize",
            OAuthProvider::Okta => "https://{domain}/oauth2/default/v1/authorize",

            // Regional
            OAuthProvider::WeChat => "https://open.weixin.qq.com/connect/qrconnect",
            OAuthProvider::Line => "https://access.line.me/oauth2/v2.1/authorize",
            OAuthProvider::KakaoTalk => "https://kauth.kakao.com/oauth/authorize",
            OAuthProvider::Vkontakte => "https://oauth.vk.com/authorize",
            OAuthProvider::Yandex => "https://oauth.yandex.com/authorize",

            OAuthProvider::Custom => "",
        }
    }

    /// Get token endpoint
    pub fn token_endpoint(&self) -> &str {
        match self {
            // Existing providers
            OAuthProvider::Google => "https://oauth2.googleapis.com/token",
            OAuthProvider::GitHub => "https://github.com/login/oauth/access_token",
            OAuthProvider::Microsoft => {
                "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            }
            OAuthProvider::Apple => "https://appleid.apple.com/auth/token",
            OAuthProvider::Discord => "https://discord.com/api/oauth2/token",
            OAuthProvider::Slack => "https://slack.com/api/oauth.v2.access",

            // Social/Consumer
            OAuthProvider::Facebook => "https://graph.facebook.com/v18.0/oauth/access_token",
            OAuthProvider::Twitter => "https://api.twitter.com/2/oauth2/token",
            OAuthProvider::Instagram => "https://api.instagram.com/oauth/access_token",
            OAuthProvider::TikTok => "https://open.tiktokapis.com/v2/oauth/token",
            OAuthProvider::Snapchat => "https://accounts.snapchat.com/accounts/oauth2/token",
            OAuthProvider::Pinterest => "https://api.pinterest.com/v5/oauth/token",
            OAuthProvider::Reddit => "https://www.reddit.com/api/v1/access_token",
            OAuthProvider::Twitch => "https://id.twitch.tv/oauth2/token",
            OAuthProvider::Spotify => "https://accounts.spotify.com/api/token",

            // Professional
            OAuthProvider::LinkedIn => "https://www.linkedin.com/oauth/v2/accessToken",

            // Developer/Tech
            OAuthProvider::GitLab => "https://gitlab.com/oauth/token",
            OAuthProvider::Bitbucket => "https://bitbucket.org/site/oauth2/access_token",
            OAuthProvider::DigitalOcean => "https://cloud.digitalocean.com/v1/oauth/token",
            OAuthProvider::Heroku => "https://id.heroku.com/oauth/token",
            OAuthProvider::Vercel => "https://api.vercel.com/v2/oauth/access_token",
            OAuthProvider::Netlify => "https://api.netlify.com/oauth/token",
            OAuthProvider::Cloudflare => "https://dash.cloudflare.com/oauth2/token",

            // Enterprise
            OAuthProvider::Salesforce => "https://login.salesforce.com/services/oauth2/token",
            OAuthProvider::HubSpot => "https://api.hubapi.com/oauth/v1/token",
            OAuthProvider::Zendesk => "https://{subdomain}.zendesk.com/oauth/tokens",
            OAuthProvider::Notion => "https://api.notion.com/v1/oauth/token",
            OAuthProvider::Figma => "https://www.figma.com/api/oauth/token",
            OAuthProvider::Linear => "https://api.linear.app/oauth/token",
            OAuthProvider::Atlassian => "https://auth.atlassian.com/oauth/token",
            OAuthProvider::Okta => "https://{domain}/oauth2/default/v1/token",

            // Regional
            OAuthProvider::WeChat => "https://api.weixin.qq.com/sns/oauth2/access_token",
            OAuthProvider::Line => "https://api.line.me/oauth2/v2.1/token",
            OAuthProvider::KakaoTalk => "https://kauth.kakao.com/oauth/token",
            OAuthProvider::Vkontakte => "https://oauth.vk.com/access_token",
            OAuthProvider::Yandex => "https://oauth.yandex.com/token",

            OAuthProvider::Custom => "",
        }
    }

    /// Get userinfo endpoint
    pub fn userinfo_endpoint(&self) -> &str {
        match self {
            // Existing providers
            OAuthProvider::Google => "https://openidconnect.googleapis.com/v1/userinfo",
            OAuthProvider::GitHub => "https://api.github.com/user",
            OAuthProvider::Microsoft => "https://graph.microsoft.com/oidc/userinfo",
            OAuthProvider::Apple => "https://appleid.apple.com/auth/userinfo",
            OAuthProvider::Discord => "https://discord.com/api/users/@me",
            OAuthProvider::Slack => "https://slack.com/api/users.identity",

            // Social/Consumer
            OAuthProvider::Facebook => "https://graph.facebook.com/v18.0/me",
            OAuthProvider::Twitter => "https://api.twitter.com/2/users/me",
            OAuthProvider::Instagram => "https://graph.instagram.com/me",
            OAuthProvider::TikTok => "https://open.tiktokapis.com/v2/user/info",
            OAuthProvider::Snapchat => "https://kit.snapchat.com/v1/me",
            OAuthProvider::Pinterest => "https://api.pinterest.com/v5/user_account",
            OAuthProvider::Reddit => "https://oauth.reddit.com/api/v1/me",
            OAuthProvider::Twitch => "https://api.twitch.tv/helix/users",
            OAuthProvider::Spotify => "https://api.spotify.com/v1/me",

            // Professional
            OAuthProvider::LinkedIn => "https://api.linkedin.com/v2/userinfo",

            // Developer/Tech
            OAuthProvider::GitLab => "https://gitlab.com/api/v4/user",
            OAuthProvider::Bitbucket => "https://api.bitbucket.org/2.0/user",
            OAuthProvider::DigitalOcean => "https://api.digitalocean.com/v2/account",
            OAuthProvider::Heroku => "https://api.heroku.com/account",
            OAuthProvider::Vercel => "https://api.vercel.com/v2/user",
            OAuthProvider::Netlify => "https://api.netlify.com/api/v1/user",
            OAuthProvider::Cloudflare => "https://api.cloudflare.com/client/v4/user",

            // Enterprise
            OAuthProvider::Salesforce => "https://login.salesforce.com/services/oauth2/userinfo",
            OAuthProvider::HubSpot => "https://api.hubapi.com/oauth/v1/access-tokens",
            OAuthProvider::Zendesk => "https://{subdomain}.zendesk.com/api/v2/users/me",
            OAuthProvider::Notion => "https://api.notion.com/v1/users/me",
            OAuthProvider::Figma => "https://api.figma.com/v1/me",
            OAuthProvider::Linear => "https://api.linear.app/graphql",
            OAuthProvider::Atlassian => "https://api.atlassian.com/me",
            OAuthProvider::Okta => "https://{domain}/oauth2/default/v1/userinfo",

            // Regional
            OAuthProvider::WeChat => "https://api.weixin.qq.com/sns/userinfo",
            OAuthProvider::Line => "https://api.line.me/v2/profile",
            OAuthProvider::KakaoTalk => "https://kapi.kakao.com/v2/user/me",
            OAuthProvider::Vkontakte => "https://api.vk.com/method/users.get",
            OAuthProvider::Yandex => "https://login.yandex.ru/info",

            OAuthProvider::Custom => "",
        }
    }

    /// Get default scopes
    pub fn default_scopes(&self) -> Vec<&str> {
        match self {
            // Existing providers
            OAuthProvider::Google => vec!["openid", "email", "profile"],
            OAuthProvider::GitHub => vec!["user:email", "read:user"],
            OAuthProvider::Microsoft => vec!["openid", "email", "profile"],
            OAuthProvider::Apple => vec!["name", "email"],
            OAuthProvider::Discord => vec!["identify", "email"],
            OAuthProvider::Slack => vec!["identity.basic", "identity.email"],

            // Social/Consumer
            OAuthProvider::Facebook => vec!["email", "public_profile"],
            OAuthProvider::Twitter => vec!["tweet.read", "users.read"],
            OAuthProvider::Instagram => vec!["instagram_graph_user_profile"],
            OAuthProvider::TikTok => vec!["user.info.basic"],
            OAuthProvider::Snapchat => vec![
                "https://auth.snapchat.com/oauth2/api/user.display_name",
                "https://auth.snapchat.com/oauth2/api/user.bitmoji.avatar",
            ],
            OAuthProvider::Pinterest => vec!["user_accounts:read"],
            OAuthProvider::Reddit => vec!["identity"],
            OAuthProvider::Twitch => vec!["user:read:email"],
            OAuthProvider::Spotify => vec!["user-read-email", "user-read-private"],

            // Professional
            OAuthProvider::LinkedIn => vec!["openid", "email", "profile"],

            // Developer/Tech
            OAuthProvider::GitLab => vec!["read_user", "openid"],
            OAuthProvider::Bitbucket => vec!["account"],
            OAuthProvider::DigitalOcean => vec!["read"],
            OAuthProvider::Heroku => vec!["identity"],
            OAuthProvider::Vercel => vec!["user"],
            OAuthProvider::Netlify => vec!["user"],
            OAuthProvider::Cloudflare => vec!["user:read"],

            // Enterprise
            OAuthProvider::Salesforce => vec!["openid", "email", "profile"],
            OAuthProvider::HubSpot => vec!["oauth"],
            OAuthProvider::Zendesk => vec!["read"],
            OAuthProvider::Notion => vec!["user:read"],
            OAuthProvider::Figma => vec!["file_read"],
            OAuthProvider::Linear => vec!["read", "issues:read"],
            OAuthProvider::Atlassian => vec!["read:me"],
            OAuthProvider::Okta => vec!["openid", "email", "profile"],

            // Regional
            OAuthProvider::WeChat => vec!["snsapi_login", "snsapi_userinfo"],
            OAuthProvider::Line => vec!["profile", "openid"],
            OAuthProvider::KakaoTalk => vec!["account_email", "profile_nickname", "profile_image"],
            OAuthProvider::Vkontakte => vec!["email", "profile"],
            OAuthProvider::Yandex => vec!["login:email", "login:info", "login:avatar"],

            OAuthProvider::Custom => vec!["openid", "email", "profile"],
        }
    }

    /// Check if provider uses PKCE by default
    pub fn pkce_default(&self) -> bool {
        matches!(
            self,
            OAuthProvider::Apple
                | OAuthProvider::Twitter
                | OAuthProvider::LinkedIn
                | OAuthProvider::Spotify
                | OAuthProvider::Okta
                | OAuthProvider::Notion
                | OAuthProvider::Linear
                | OAuthProvider::Atlassian
        )
    }

    /// Get provider category
    pub fn category(&self) -> OAuthProviderCategory {
        match self {
            OAuthProvider::Google
            | OAuthProvider::GitHub
            | OAuthProvider::Discord
            | OAuthProvider::Slack
            | OAuthProvider::Facebook
            | OAuthProvider::Twitter
            | OAuthProvider::Instagram
            | OAuthProvider::TikTok
            | OAuthProvider::Snapchat
            | OAuthProvider::Pinterest
            | OAuthProvider::Reddit
            | OAuthProvider::Twitch
            | OAuthProvider::Spotify => OAuthProviderCategory::Social,

            OAuthProvider::Microsoft | OAuthProvider::Apple | OAuthProvider::LinkedIn => {
                OAuthProviderCategory::Professional
            }

            OAuthProvider::GitLab
            | OAuthProvider::Bitbucket
            | OAuthProvider::DigitalOcean
            | OAuthProvider::Heroku
            | OAuthProvider::Vercel
            | OAuthProvider::Netlify
            | OAuthProvider::Cloudflare => OAuthProviderCategory::Developer,

            OAuthProvider::Salesforce
            | OAuthProvider::HubSpot
            | OAuthProvider::Zendesk
            | OAuthProvider::Notion
            | OAuthProvider::Figma
            | OAuthProvider::Linear
            | OAuthProvider::Atlassian
            | OAuthProvider::Okta => OAuthProviderCategory::Enterprise,

            OAuthProvider::WeChat
            | OAuthProvider::Line
            | OAuthProvider::KakaoTalk
            | OAuthProvider::Vkontakte
            | OAuthProvider::Yandex => OAuthProviderCategory::Regional,

            OAuthProvider::Custom => OAuthProviderCategory::Custom,
        }
    }

    /// Check if provider requires special handling
    pub fn requires_special_handling(&self) -> bool {
        matches!(
            self,
            OAuthProvider::Apple
                | OAuthProvider::Twitter
                | OAuthProvider::WeChat
                | OAuthProvider::Zendesk
                | OAuthProvider::Okta
        )
    }
}

/// OAuth provider categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthProviderCategory {
    Social,
    Professional,
    Developer,
    Enterprise,
    Regional,
    Custom,
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
    /// Additional provider-specific settings
    pub extra_config: Option<serde_json::Value>,
}

impl OAuthConfig {
    /// Create a new OAuth configuration
    pub fn new(
        provider: OAuthProvider,
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> Self {
        let pkce_enabled = provider.pkce_default();
        Self {
            provider,
            client_id,
            client_secret,
            redirect_uri,
            scopes: Vec::new(),
            pkce_enabled,
            apple_credentials: None,
            extra_config: None,
        }
    }

    /// Enable PKCE
    pub fn with_pkce(mut self, enabled: bool) -> Self {
        self.pkce_enabled = enabled;
        self
    }

    /// Add additional scopes
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Add Apple credentials (required for Apple Sign-In)
    pub fn with_apple_credentials(mut self, credentials: AppleOAuthCredentials) -> Self {
        self.apple_credentials = Some(credentials);
        self
    }

    /// Add extra configuration
    pub fn with_extra_config(mut self, config: serde_json::Value) -> Self {
        self.extra_config = Some(config);
        self
    }
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

impl AuthUrlRequest {
    /// Create a new authorization URL request
    pub fn new(state: String) -> Self {
        Self {
            state,
            code_verifier: None,
            scopes: Vec::new(),
        }
    }

    /// Add PKCE code verifier
    pub fn with_pkce(mut self, verifier: String) -> Self {
        self.code_verifier = Some(verifier);
        self
    }

    /// Add additional scopes
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }
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
    /// Provider type
    pub provider: Option<OAuthProvider>,
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

        // Provider-specific parameters
        match self.config.provider {
            OAuthProvider::Apple => {
                url.query_pairs_mut()
                    .append_pair("response_mode", "form_post");
            }
            OAuthProvider::Twitter => {
                url.query_pairs_mut()
                    .append_pair("code_challenge_method", "S256");
            }
            OAuthProvider::Reddit => {
                url.query_pairs_mut().append_pair("duration", "permanent");
            }
            OAuthProvider::WeChat => {
                // WeChat uses 'appid' instead of 'client_id'
                // Note: This is handled separately in a specialized flow
            }
            OAuthProvider::Line => {
                url.query_pairs_mut()
                    .append_pair("nonce", &generate_state());
            }
            _ => {}
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
        let mut request = self
            .http_client
            .get(self.config.provider.userinfo_endpoint())
            .header("Authorization", format!("Bearer {}", access_token));

        // Provider-specific headers
        match self.config.provider {
            OAuthProvider::GitHub => {
                request = request.header("Accept", "application/vnd.github+json");
            }
            OAuthProvider::Heroku => {
                request = request.header("Accept", "application/vnd.heroku+json; version=3");
            }
            OAuthProvider::Twitch => {
                request = request.header("Client-Id", &self.config.client_id);
            }
            OAuthProvider::Atlassian => {
                request = request.header("Accept", "application/json");
            }
            OAuthProvider::Vkontakte => {
                // VK requires API version parameter
                return self.get_vk_user_info(access_token).await;
            }
            _ => {}
        }

        let response = request
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
        let mut user_info = match self.config.provider {
            OAuthProvider::Google => Self::parse_google_user_info(&raw),
            OAuthProvider::GitHub => Self::parse_github_user_info(&raw),
            OAuthProvider::Microsoft => Self::parse_microsoft_user_info(&raw),
            OAuthProvider::Apple => Self::parse_apple_user_info(&raw),
            OAuthProvider::Discord => Self::parse_discord_user_info(&raw),
            OAuthProvider::Slack => Self::parse_slack_user_info(&raw),

            // Social/Consumer
            OAuthProvider::Facebook => Self::parse_facebook_user_info(&raw),
            OAuthProvider::Twitter => Self::parse_twitter_user_info(&raw),
            OAuthProvider::Instagram => Self::parse_instagram_user_info(&raw),
            OAuthProvider::TikTok => Self::parse_tiktok_user_info(&raw),
            OAuthProvider::Pinterest => Self::parse_pinterest_user_info(&raw),
            OAuthProvider::Reddit => Self::parse_reddit_user_info(&raw),
            OAuthProvider::Twitch => Self::parse_twitch_user_info(&raw),
            OAuthProvider::Spotify => Self::parse_spotify_user_info(&raw),

            // Professional
            OAuthProvider::LinkedIn => Self::parse_linkedin_user_info(&raw),

            // Developer/Tech
            OAuthProvider::GitLab => Self::parse_gitlab_user_info(&raw),
            OAuthProvider::Bitbucket => Self::parse_bitbucket_user_info(&raw),
            OAuthProvider::DigitalOcean => Self::parse_digitalocean_user_info(&raw),
            OAuthProvider::Heroku => Self::parse_heroku_user_info(&raw),
            OAuthProvider::Vercel => Self::parse_vercel_user_info(&raw),
            OAuthProvider::Netlify => Self::parse_netlify_user_info(&raw),

            // Enterprise
            OAuthProvider::Salesforce => Self::parse_salesforce_user_info(&raw),
            OAuthProvider::Notion => Self::parse_notion_user_info(&raw),
            OAuthProvider::Figma => Self::parse_figma_user_info(&raw),
            OAuthProvider::Atlassian => Self::parse_atlassian_user_info(&raw),

            // Regional
            OAuthProvider::Line => Self::parse_line_user_info(&raw),
            OAuthProvider::KakaoTalk => Self::parse_kakao_user_info(&raw),
            OAuthProvider::Yandex => Self::parse_yandex_user_info(&raw),

            _ => Self::parse_generic_user_info(&raw),
        };

        user_info.provider = Some(self.config.provider);
        Ok(user_info)
    }

    /// Get VKontakte user info (requires special handling for API version)
    async fn get_vk_user_info(&self, access_token: &str) -> Result<OAuthUserInfo> {
        let url = format!(
            "{}?access_token={}&v=5.131&fields=email,photo_max",
            self.config.provider.userinfo_endpoint(),
            access_token
        );

        let response =
            self.http_client
                .get(&url)
                .send()
                .await
                .map_err(|e| VaultError::ExternalService {
                    service: "OAuth".into(),
                    message: e.to_string(),
                })?;

        let raw: serde_json::Value =
            response
                .json()
                .await
                .map_err(|e| VaultError::ExternalService {
                    service: "OAuth".into(),
                    message: e.to_string(),
                })?;

        Ok(Self::parse_vkontakte_user_info(&raw))
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

    // ============= Provider-specific user info parsers =============

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
            provider: Some(OAuthProvider::Google),
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
            provider: Some(OAuthProvider::GitHub),
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
            provider: Some(OAuthProvider::Microsoft),
            raw: raw.clone(),
        }
    }

    /// Parse Apple user info from ID token claims
    fn parse_apple_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let id = raw["sub"].as_str().unwrap_or("").to_string();
        let email = raw["email"].as_str().map(String::from);
        let email_verified = email.is_some();

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
            picture: None,
            username: None,
            locale: None,
            provider: Some(OAuthProvider::Apple),
            raw: raw.clone(),
        }
    }

    /// Parse Discord user info
    fn parse_discord_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["id"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: raw["verified"].as_bool().unwrap_or(false),
            name: raw["global_name"]
                .as_str()
                .map(String::from)
                .or_else(|| raw["username"].as_str().map(String::from)),
            given_name: None,
            family_name: None,
            picture: raw["avatar"].as_str().map(|a| {
                format!(
                    "https://cdn.discordapp.com/avatars/{}/{}",
                    raw["id"].as_str().unwrap_or(""),
                    a
                )
            }),
            username: raw["username"].as_str().map(String::from),
            locale: raw["locale"].as_str().map(String::from),
            provider: Some(OAuthProvider::Discord),
            raw: raw.clone(),
        }
    }

    /// Parse Slack user info
    fn parse_slack_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let user = &raw["user"];
        OAuthUserInfo {
            id: user["id"].as_str().unwrap_or("").to_string(),
            email: user["email"].as_str().map(String::from),
            email_verified: user["email"].as_str().is_some(),
            name: user["name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: user["image_512"].as_str().map(String::from),
            username: user["name"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::Slack),
            raw: raw.clone(),
        }
    }

    // ============= Social/Consumer Parsers =============

    /// Parse Facebook user info
    fn parse_facebook_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let picture = raw["picture"]["data"]["url"].as_str().map(String::from);
        OAuthUserInfo {
            id: raw["id"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: raw["email"].as_str().is_some(),
            name: raw["name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture,
            username: None,
            locale: raw["locale"].as_str().map(String::from),
            provider: Some(OAuthProvider::Facebook),
            raw: raw.clone(),
        }
    }

    /// Parse Twitter/X user info
    fn parse_twitter_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let data = &raw["data"];
        let picture = data["profile_image_url"].as_str().map(String::from);
        OAuthUserInfo {
            id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(String::from),
            email_verified: data["verified"].as_bool().unwrap_or(false),
            name: data["name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture,
            username: data["username"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::Twitter),
            raw: raw.clone(),
        }
    }

    /// Parse Instagram user info
    fn parse_instagram_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["id"].as_str().unwrap_or("").to_string(),
            email: None, // Instagram Basic Display doesn't provide email
            email_verified: false,
            name: None,
            given_name: None,
            family_name: None,
            picture: None, // Requires additional API call
            username: raw["username"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::Instagram),
            raw: raw.clone(),
        }
    }

    /// Parse TikTok user info
    fn parse_tiktok_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let data = &raw["data"];
        let user = &data["user"];
        OAuthUserInfo {
            id: user["open_id"].as_str().unwrap_or("").to_string(),
            email: None, // TikTok doesn't provide email
            email_verified: false,
            name: None,
            given_name: None,
            family_name: None,
            picture: user["avatar_url"].as_str().map(String::from),
            username: user["display_name"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::TikTok),
            raw: raw.clone(),
        }
    }

    /// Parse Pinterest user info
    fn parse_pinterest_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["username"].as_str().unwrap_or("").to_string(),
            email: None, // Requires additional scope
            email_verified: false,
            name: raw["profile_image"].as_str().map(String::from), // Using profile_image as placeholder
            given_name: None,
            family_name: None,
            picture: raw["profile_image"].as_str().map(String::from),
            username: raw["username"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::Pinterest),
            raw: raw.clone(),
        }
    }

    /// Parse Reddit user info
    fn parse_reddit_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["id"].as_str().unwrap_or("").to_string(),
            email: None, // Reddit doesn't provide email by default
            email_verified: false,
            name: raw["name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: raw["icon_img"]
                .as_str()
                .map(|s| s.split('?').next().unwrap_or(s).to_string()),
            username: raw["name"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::Reddit),
            raw: raw.clone(),
        }
    }

    /// Parse Twitch user info
    fn parse_twitch_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let data = raw["data"].get(0).unwrap_or(&serde_json::Value::Null);
        OAuthUserInfo {
            id: data["id"].as_str().unwrap_or("").to_string(),
            email: data["email"].as_str().map(String::from),
            email_verified: data["email"].as_str().is_some(),
            name: None,
            given_name: None,
            family_name: None,
            picture: data["profile_image_url"].as_str().map(String::from),
            username: data["display_name"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::Twitch),
            raw: raw.clone(),
        }
    }

    /// Parse Spotify user info
    fn parse_spotify_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let picture = raw["images"]
            .get(0)
            .and_then(|img| img["url"].as_str().map(String::from));
        OAuthUserInfo {
            id: raw["id"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: raw["email"].as_str().is_some(),
            name: raw["display_name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture,
            username: None,
            locale: None,
            provider: Some(OAuthProvider::Spotify),
            raw: raw.clone(),
        }
    }

    // ============= Professional Parsers =============

    /// Parse LinkedIn user info
    fn parse_linkedin_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["sub"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: raw["email_verified"].as_bool().unwrap_or(false),
            name: raw["name"].as_str().map(String::from),
            given_name: raw["given_name"].as_str().map(String::from),
            family_name: raw["family_name"].as_str().map(String::from),
            picture: raw["picture"].as_str().map(String::from),
            username: None,
            locale: None,
            provider: Some(OAuthProvider::LinkedIn),
            raw: raw.clone(),
        }
    }

    // ============= Developer/Tech Parsers =============

    /// Parse GitLab user info
    fn parse_gitlab_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["id"].to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: true, // GitLab requires verified email
            name: raw["name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: raw["avatar_url"].as_str().map(String::from),
            username: raw["username"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::GitLab),
            raw: raw.clone(),
        }
    }

    /// Parse Bitbucket user info
    fn parse_bitbucket_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let avatar = raw["links"]["avatar"]["href"].as_str().map(String::from);
        OAuthUserInfo {
            id: raw["account_id"].as_str().unwrap_or("").to_string(),
            email: None, // Requires separate API call
            email_verified: false,
            name: raw["display_name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: avatar,
            username: raw["username"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::Bitbucket),
            raw: raw.clone(),
        }
    }

    /// Parse DigitalOcean user info
    fn parse_digitalocean_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let account = &raw["account"];
        OAuthUserInfo {
            id: account["uuid"].as_str().unwrap_or("").to_string(),
            email: account["email"].as_str().map(String::from),
            email_verified: true,
            name: None,
            given_name: None,
            family_name: None,
            picture: None,
            username: None,
            locale: None,
            provider: Some(OAuthProvider::DigitalOcean),
            raw: raw.clone(),
        }
    }

    /// Parse Heroku user info
    fn parse_heroku_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["id"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: true,
            name: raw["name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: None,
            username: None,
            locale: None,
            provider: Some(OAuthProvider::Heroku),
            raw: raw.clone(),
        }
    }

    /// Parse Vercel user info
    fn parse_vercel_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let user = &raw["user"];
        OAuthUserInfo {
            id: user["id"].as_str().unwrap_or("").to_string(),
            email: user["email"].as_str().map(String::from),
            email_verified: user["emailVerified"].as_bool().unwrap_or(false),
            name: user["name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: user["avatar"].as_str().map(String::from),
            username: user["username"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::Vercel),
            raw: raw.clone(),
        }
    }

    /// Parse Netlify user info
    fn parse_netlify_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["id"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: raw["email"].as_str().is_some(),
            name: raw["full_name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: raw["avatar_url"].as_str().map(String::from),
            username: raw["slug"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::Netlify),
            raw: raw.clone(),
        }
    }

    // ============= Enterprise Parsers =============

    /// Parse Salesforce user info
    fn parse_salesforce_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["user_id"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: true,
            name: raw["name"].as_str().map(String::from),
            given_name: raw["given_name"].as_str().map(String::from),
            family_name: raw["family_name"].as_str().map(String::from),
            picture: raw["photos"]["picture"].as_str().map(String::from),
            username: raw["preferred_username"].as_str().map(String::from),
            locale: raw["locale"].as_str().map(String::from),
            provider: Some(OAuthProvider::Salesforce),
            raw: raw.clone(),
        }
    }

    /// Parse Notion user info
    fn parse_notion_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let owner = &raw["owner"];
        let user = &owner["user"];
        let person = &user["person"];
        OAuthUserInfo {
            id: user["id"].as_str().unwrap_or("").to_string(),
            email: person["email"].as_str().map(String::from),
            email_verified: true,
            name: user["name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: user["avatar_url"].as_str().map(String::from),
            username: None,
            locale: None,
            provider: Some(OAuthProvider::Notion),
            raw: raw.clone(),
        }
    }

    /// Parse Figma user info
    fn parse_figma_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let img = raw["img_url"].as_str().map(String::from);
        OAuthUserInfo {
            id: raw["id"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: true,
            name: raw["handle"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: img,
            username: raw["handle"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::Figma),
            raw: raw.clone(),
        }
    }

    /// Parse Atlassian user info
    fn parse_atlassian_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let picture = raw["picture"].as_str().map(String::from);
        OAuthUserInfo {
            id: raw["account_id"].as_str().unwrap_or("").to_string(),
            email: raw["email"].as_str().map(String::from),
            email_verified: raw["email_verified"].as_bool().unwrap_or(false),
            name: raw["name"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture,
            username: None,
            locale: None,
            provider: Some(OAuthProvider::Atlassian),
            raw: raw.clone(),
        }
    }

    // ============= Regional Parsers =============

    /// Parse LINE user info
    fn parse_line_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        OAuthUserInfo {
            id: raw["userId"].as_str().unwrap_or("").to_string(),
            email: None, // Requires additional scope
            email_verified: false,
            name: raw["displayName"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: raw["pictureUrl"].as_str().map(String::from),
            username: None,
            locale: None,
            provider: Some(OAuthProvider::Line),
            raw: raw.clone(),
        }
    }

    /// Parse KakaoTalk user info
    fn parse_kakao_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let account = &raw["kakao_account"];
        let profile = &account["profile"];
        OAuthUserInfo {
            id: raw["id"].to_string(),
            email: account["email"].as_str().map(String::from),
            email_verified: account["is_email_verified"].as_bool().unwrap_or(false),
            name: profile["nickname"].as_str().map(String::from),
            given_name: None,
            family_name: None,
            picture: profile["profile_image_url"].as_str().map(String::from),
            username: profile["nickname"].as_str().map(String::from),
            locale: None,
            provider: Some(OAuthProvider::KakaoTalk),
            raw: raw.clone(),
        }
    }

    /// Parse VKontakte user info
    fn parse_vkontakte_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let users = raw["response"].as_array();
        let user = users
            .and_then(|u| u.get(0))
            .unwrap_or(&serde_json::Value::Null);
        let name = format!(
            "{} {}",
            user["first_name"].as_str().unwrap_or(""),
            user["last_name"].as_str().unwrap_or("")
        )
        .trim()
        .to_string();
        OAuthUserInfo {
            id: user["id"].to_string(),
            email: None, // Provided in token response, not user info
            email_verified: false,
            name: if name.is_empty() { None } else { Some(name) },
            given_name: user["first_name"].as_str().map(String::from),
            family_name: user["last_name"].as_str().map(String::from),
            picture: user["photo_max"].as_str().map(String::from),
            username: None,
            locale: None,
            provider: Some(OAuthProvider::Vkontakte),
            raw: raw.clone(),
        }
    }

    /// Parse Yandex user info
    fn parse_yandex_user_info(raw: &serde_json::Value) -> OAuthUserInfo {
        let name = format!(
            "{} {}",
            raw["first_name"].as_str().unwrap_or(""),
            raw["last_name"].as_str().unwrap_or("")
        )
        .trim()
        .to_string();
        OAuthUserInfo {
            id: raw["id"].as_str().unwrap_or("").to_string(),
            email: raw["default_email"].as_str().map(String::from),
            email_verified: raw["is_avatar_empty"]
                .as_bool()
                .map(|_| true)
                .unwrap_or(false),
            name: if name.is_empty() { None } else { Some(name) },
            given_name: raw["first_name"].as_str().map(String::from),
            family_name: raw["last_name"].as_str().map(String::from),
            picture: raw["default_avatar_id"]
                .as_str()
                .map(|id| format!("https://avatars.yandex.net/get-yapic/{}/islands-200", id)),
            username: raw["login"].as_str().map(String::from),
            locale: raw["locale"].as_str().map(String::from),
            provider: Some(OAuthProvider::Yandex),
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
            provider: None,
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
/// Generate PKCE code verifier
///
/// SECURITY: Uses OsRng (operating system's CSPRNG) for cryptographically secure
/// code verifier generation. The code verifier is critical for OAuth 2.0 PKCE flow
/// to prevent authorization code interception attacks.
pub fn generate_code_verifier() -> String {
    use rand::Rng;
    use rand_core::OsRng;

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    let mut rng = OsRng;

    (0..128)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Generate OAuth state parameter
pub fn generate_state() -> String {
    crate::crypto::generate_secure_random(32)
}

/// Get all available OAuth providers
pub fn get_all_providers() -> Vec<OAuthProvider> {
    vec![
        OAuthProvider::Google,
        OAuthProvider::GitHub,
        OAuthProvider::Microsoft,
        OAuthProvider::Apple,
        OAuthProvider::Facebook,
        OAuthProvider::Twitter,
        OAuthProvider::LinkedIn,
        OAuthProvider::Discord,
        OAuthProvider::Slack,
        OAuthProvider::Instagram,
        OAuthProvider::TikTok,
        OAuthProvider::Snapchat,
        OAuthProvider::Pinterest,
        OAuthProvider::Reddit,
        OAuthProvider::Twitch,
        OAuthProvider::Spotify,
        OAuthProvider::GitLab,
        OAuthProvider::Bitbucket,
        OAuthProvider::DigitalOcean,
        OAuthProvider::Heroku,
        OAuthProvider::Vercel,
        OAuthProvider::Netlify,
        OAuthProvider::Cloudflare,
        OAuthProvider::Salesforce,
        OAuthProvider::HubSpot,
        OAuthProvider::Zendesk,
        OAuthProvider::Notion,
        OAuthProvider::Figma,
        OAuthProvider::Linear,
        OAuthProvider::Atlassian,
        OAuthProvider::Okta,
        OAuthProvider::WeChat,
        OAuthProvider::Line,
        OAuthProvider::KakaoTalk,
        OAuthProvider::Vkontakte,
        OAuthProvider::Yandex,
    ]
}

/// Get OAuth providers by category
pub fn get_providers_by_category(category: OAuthProviderCategory) -> Vec<OAuthProvider> {
    get_all_providers()
        .into_iter()
        .filter(|p| p.category() == category)
        .collect()
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
        assert_eq!(
            OAuthProvider::Facebook.auth_endpoint(),
            "https://www.facebook.com/v18.0/dialog/oauth"
        );
        assert_eq!(
            OAuthProvider::LinkedIn.auth_endpoint(),
            "https://www.linkedin.com/oauth/v2/authorization"
        );
    }

    #[test]
    fn test_authorization_url() {
        let config = OAuthConfig::new(
            OAuthProvider::Google,
            "test_client".to_string(),
            "test_secret".to_string(),
            "http://localhost/callback".to_string(),
        );

        let service = OAuthService::new(config);
        let request = AuthUrlRequest::new("test_state".to_string());

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

    #[test]
    fn test_provider_categories() {
        assert_eq!(
            OAuthProvider::Google.category(),
            OAuthProviderCategory::Social
        );
        assert_eq!(
            OAuthProvider::LinkedIn.category(),
            OAuthProviderCategory::Professional
        );
        assert_eq!(
            OAuthProvider::GitLab.category(),
            OAuthProviderCategory::Developer
        );
        assert_eq!(
            OAuthProvider::Salesforce.category(),
            OAuthProviderCategory::Enterprise
        );
        assert_eq!(
            OAuthProvider::WeChat.category(),
            OAuthProviderCategory::Regional
        );
    }

    #[test]
    fn test_all_providers_count() {
        let providers = get_all_providers();
        assert!(
            providers.len() >= 30,
            "Expected at least 30 OAuth providers"
        );
    }

    #[test]
    fn test_provider_names() {
        assert_eq!(OAuthProvider::Twitter.name(), "twitter");
        assert_eq!(OAuthProvider::Twitter.display_name(), "X (Twitter)");
        assert_eq!(OAuthProvider::Line.display_name(), "LINE");
        assert_eq!(OAuthProvider::KakaoTalk.display_name(), "KakaoTalk");
    }
}
