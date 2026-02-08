//! Auth0 migration implementation

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::migration::models::{
    CreateUserFromMigration, ExternalMfaMethod, ExternalOAuthConnection, ExternalUser,
    MigrationError, MigrationOptions, ValidationResult,
};
use vault_core::models::user::{CreateUserRequest, UserProfile};

/// Auth0 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth0Config {
    pub domain: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default)]
    pub connection: Option<String>,
    #[serde(default)]
    pub import_passwords: bool,
    #[serde(default)]
    pub audience: Option<String>,
}

impl Auth0Config {
    /// Get the management API base URL
    pub fn management_api_url(&self) -> String {
        format!("https://{}/api/v2", self.domain)
    }

    /// Get the token endpoint
    pub fn token_url(&self) -> String {
        format!("https://{}/oauth/token", self.domain)
    }
}

/// Auth0 user representation
#[derive(Debug, Clone, Deserialize)]
pub struct Auth0User {
    #[serde(rename = "user_id")]
    pub user_id: String,
    pub email: String,
    #[serde(rename = "email_verified")]
    pub email_verified: bool,
    pub username: Option<String>,
    #[serde(rename = "given_name")]
    pub given_name: Option<String>,
    #[serde(rename = "family_name")]
    pub family_name: Option<String>,
    #[serde(rename = "phone_number")]
    pub phone_number: Option<String>,
    #[serde(rename = "phone_verified")]
    pub phone_verified: Option<bool>,
    pub picture: Option<String>,
    #[serde(rename = "app_metadata")]
    pub app_metadata: Option<serde_json::Value>,
    #[serde(rename = "user_metadata")]
    pub user_metadata: Option<serde_json::Value>,
    #[serde(rename = "created_at")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "updated_at")]
    pub updated_at: DateTime<Utc>,
    pub identities: Vec<Auth0Identity>,
    #[serde(rename = "logins_count")]
    pub logins_count: Option<i32>,
    #[serde(rename = "last_login")]
    pub last_login: Option<DateTime<Utc>>,
    #[serde(rename = "last_ip")]
    pub last_ip: Option<String>,
    pub blocked: Option<bool>,
    #[serde(rename = "multifactor")]
    pub multifactor: Option<Vec<String>>,
}

/// Auth0 identity (linked social accounts)
#[derive(Debug, Clone, Deserialize)]
pub struct Auth0Identity {
    #[serde(rename = "user_id")]
    pub user_id: String,
    pub provider: String,
    pub connection: String,
    #[serde(rename = "isSocial")]
    pub is_social: bool,
    #[serde(rename = "access_token")]
    pub access_token: Option<String>,
    #[serde(rename = "refresh_token")]
    pub refresh_token: Option<String>,
}

/// Auth0 token response
#[derive(Debug, Clone, Deserialize)]
struct Auth0TokenResponse {
    #[serde(rename = "access_token")]
    access_token: String,
    #[serde(rename = "token_type")]
    token_type: String,
    #[serde(rename = "expires_in")]
    expires_in: u64,
}

/// Auth0 API error response
#[derive(Debug, Clone, Deserialize)]
struct Auth0Error {
    error: String,
    #[serde(rename = "error_description")]
    error_description: Option<String>,
    message: Option<String>,
}

/// Auth0 migrator implementation
pub struct Auth0Migrator {
    client: reqwest::Client,
    config: Auth0Config,
    access_token: String,
}

impl Auth0Migrator {
    /// Create a new Auth0 migrator
    pub async fn new(config: Auth0Config) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let access_token = Self::fetch_access_token(&client, &config).await?;

        Ok(Self {
            client,
            config,
            access_token,
        })
    }

    /// Fetch access token from Auth0
    async fn fetch_access_token(
        client: &reqwest::Client,
        config: &Auth0Config,
    ) -> anyhow::Result<String> {
        let request_body = serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "audience": config.audience.clone().unwrap_or_else(|| {
                format!("https://{}/api/v2/", config.domain)
            }),
        });

        let response = client
            .post(&config.token_url())
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!("Auth0 token request failed: {}", error_text));
        }

        let token_response: Auth0TokenResponse = response.json().await?;
        Ok(token_response.access_token)
    }

    /// Get total user count
    pub async fn get_user_count(&self) -> anyhow::Result<i32> {
        let url = format!("{}/users", self.config.management_api_url());

        let mut request = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .query(&[("per_page", "1"), ("page", "0"), ("include_totals", "true")]);

        // Filter by connection if specified
        if let Some(ref connection) = self.config.connection {
            request = request.query(&[("connection", connection)]);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let error: Auth0Error = response.json().await?;
            return Err(anyhow::anyhow!(
                "Auth0 API error: {} - {:?}",
                error.error,
                error.error_description
            ));
        }

        // Auth0 returns total in X-Total-Count header or in response body
        let total_header = response.headers().get("X-Total-Count");
        if let Some(total) = total_header {
            let total_str = total.to_str()?;
            return Ok(total_str.parse()?);
        }

        // Fallback: parse from response body
        #[derive(Deserialize)]
        struct UsersResponse {
            total: i32,
        }
        let body: UsersResponse = response.json().await?;
        Ok(body.total)
    }

    /// Get users with pagination
    pub async fn get_users(&self, page: i32, per_page: i32) -> anyhow::Result<Vec<Auth0User>> {
        let url = format!("{}/users", self.config.management_api_url());

        let mut request = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .query(&[
                ("per_page", per_page.to_string().as_str()),
                ("page", page.to_string().as_str()),
                ("include_totals", "false"),
            ]);

        // Filter by connection if specified
        if let Some(ref connection) = self.config.connection {
            request = request.query(&[("connection", connection)]);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let error: Auth0Error = response.json().await?;
            return Err(anyhow::anyhow!(
                "Auth0 API error: {} - {:?}",
                error.error,
                error.error_description
            ));
        }

        let users: Vec<Auth0User> = response.json().await?;
        Ok(users)
    }

    /// Get a single user by ID
    pub async fn get_user(&self, user_id: &str) -> anyhow::Result<Option<Auth0User>> {
        let url = format!("{}/users/{}", self.config.management_api_url(), user_id);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .send()
            .await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            let error: Auth0Error = response.json().await?;
            return Err(anyhow::anyhow!(
                "Auth0 API error: {} - {:?}",
                error.error,
                error.error_description
            ));
        }

        let user: Auth0User = response.json().await?;
        Ok(Some(user))
    }

    /// Get password hash for a user (requires special permission)
    /// Note: Auth0 does not expose password hashes through the API by default
    pub async fn get_password_hash(&self, _user_id: &str) -> anyhow::Result<Option<String>> {
        // Auth0 doesn't provide password hashes via Management API
        // Users need to export their database or use the export job API
        // This is a placeholder that returns None
        Ok(None)
    }

    /// Convert Auth0 user to external user format
    pub fn convert_to_external_user(&self, auth0_user: Auth0User) -> ExternalUser {
        let mut metadata = HashMap::new();

        // Merge app_metadata and user_metadata
        if let Some(app_meta) = auth0_user.app_metadata {
            if let Some(obj) = app_meta.as_object() {
                for (key, value) in obj {
                    metadata.insert(format!("app_{}", key), value.clone());
                }
            }
        }

        if let Some(user_meta) = auth0_user.user_metadata {
            if let Some(obj) = user_meta.as_object() {
                for (key, value) in obj.iter() {
                    metadata.insert(key.clone(), value.clone());
                }
            }
        }

        // Convert OAuth identities
        let oauth_connections: Vec<ExternalOAuthConnection> = auth0_user
            .identities
            .into_iter()
            .filter(|i| i.is_social)
            .map(|identity| ExternalOAuthConnection {
                provider: identity.provider,
                provider_user_id: identity.user_id,
                provider_username: None,
                email: Some(auth0_user.email.clone()),
                access_token: identity.access_token,
                refresh_token: identity.refresh_token,
                token_expires_at: None,
                raw_data: None,
            })
            .collect();

        // Convert MFA methods
        let mfa_methods: Vec<ExternalMfaMethod> = auth0_user
            .multifactor
            .as_ref()
            .map(|methods| {
                methods
                    .iter()
                    .map(|m| ExternalMfaMethod {
                        method_type: m.clone(),
                        enabled: true,
                        data: serde_json::json!({}),
                    })
                    .collect()
            })
            .unwrap_or_default();

        ExternalUser {
            external_id: auth0_user.user_id,
            email: Some(auth0_user.email),
            email_verified: auth0_user.email_verified,
            username: auth0_user.username,
            given_name: auth0_user.given_name,
            family_name: auth0_user.family_name,
            display_name: None,
            phone_number: auth0_user.phone_number,
            phone_verified: auth0_user.phone_verified.unwrap_or(false),
            picture: auth0_user.picture,
            password_hash: None, // Auth0 doesn't expose passwords via API
            password_salt: None,
            status: if auth0_user.blocked.unwrap_or(false) {
                Some("blocked".to_string())
            } else {
                None
            },
            created_at: Some(auth0_user.created_at),
            last_login_at: auth0_user.last_login,
            last_ip: auth0_user.last_ip,
            logins_count: auth0_user.logins_count,
            metadata,
            oauth_connections,
            mfa_methods,
            enabled: !auth0_user.blocked.unwrap_or(false),
            locked: auth0_user.blocked.unwrap_or(false),
        }
    }

    /// Validate an Auth0 user before migration
    pub fn validate_user(&self, user: &Auth0User, _options: &MigrationOptions) -> ValidationResult {
        let mut result = ValidationResult::valid();

        // Check for required email
        if user.email.is_empty() {
            result = result.with_error("User has no email address");
        }

        // Check for valid email format
        if !user.email.contains('@') {
            result = result.with_error(format!("Invalid email format: {}", user.email));
        }

        // Warn about unverified emails
        if !user.email_verified {
            result = result.with_warning("User email is not verified");
        }

        result
    }

    /// Stream all users from Auth0
    pub async fn stream_users(
        &self,
        batch_size: usize,
    ) -> anyhow::Result<impl futures::Stream<Item = Result<Auth0User, MigrationError>>> {
        use futures::stream::{self, BoxStream, StreamExt};

        let total = self.get_user_count().await? as usize;
        let total_pages = (total + batch_size - 1) / batch_size;
        let config = self.config.clone();

        let stream = stream::iter(0..total_pages)
            .then(move |page| {
                let config = config.clone();
                async move -> BoxStream<'static, Result<Auth0User, MigrationError>> {
                    match Auth0Migrator::new(config).await {
                        Ok(migrator) => match migrator.get_users(page as i32, batch_size as i32).await {
                            Ok(users) => stream::iter(users.into_iter().map(Ok)).boxed(),
                            Err(e) => stream::iter(vec![Err(MigrationError {
                                user_id: "".to_string(),
                                email: None,
                                error: format!("Failed to get users: {}", e),
                                details: None,
                            })])
                            .boxed(),
                        },
                        Err(e) => stream::iter(vec![Err(MigrationError {
                            user_id: "".to_string(),
                            email: None,
                            error: format!("Failed to create migrator: {}", e),
                            details: None,
                        })])
                        .boxed(),
                    }
                }
            })
            .flatten();

        Ok(stream)
    }
}

/// Convert external user to Vault CreateUserRequest
pub fn convert_to_vault_request(
    external: ExternalUser,
    tenant_id: String,
    options: &MigrationOptions,
) -> CreateUserFromMigration {
    let profile = UserProfile {
        name: external.display_name.clone(),
        given_name: external.given_name.clone(),
        family_name: external.family_name.clone(),
        preferred_username: external.username.clone(),
        picture: external.picture.clone(),
        phone_number: external.phone_number.clone(),
        phone_number_verified: Some(external.phone_verified),
        ..Default::default()
    };

    let metadata = external.metadata_json();

    CreateUserFromMigration {
        tenant_id,
        email: external.email.unwrap_or_default(),
        email_verified: external.email_verified,
        password_hash: if options.import_passwords {
            external.password_hash
        } else {
            None
        },
        profile: Some(serde_json::to_value(profile).unwrap_or_default()),
        metadata: Some(metadata),
        external_id: Some(external.external_id),
        source: "auth0".to_string(),
        status: external.status,
        created_at: external.created_at,
        oauth_connections: external.oauth_connections,
        mfa_methods: external.mfa_methods,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_auth0_user() -> Auth0User {
        Auth0User {
            user_id: "auth0|123456".to_string(),
            email: "test@example.com".to_string(),
            email_verified: true,
            username: Some("testuser".to_string()),
            given_name: Some("Test".to_string()),
            family_name: Some("User".to_string()),
            phone_number: Some("+1234567890".to_string()),
            phone_verified: Some(true),
            picture: Some("https://example.com/pic.jpg".to_string()),
            app_metadata: Some(serde_json::json!({"role": "admin"})),
            user_metadata: Some(serde_json::json!({"theme": "dark"})),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            identities: vec![],
            logins_count: Some(5),
            last_login: Some(Utc::now()),
            last_ip: Some("192.168.1.1".to_string()),
            blocked: Some(false),
            multifactor: Some(vec!["google-authenticator".to_string()]),
        }
    }

    #[test]
    fn test_auth0_config_urls() {
        let config = Auth0Config {
            domain: "mydomain.auth0.com".to_string(),
            client_id: "client123".to_string(),
            client_secret: "secret".to_string(),
            connection: None,
            import_passwords: false,
            audience: None,
        };

        assert_eq!(
            config.management_api_url(),
            "https://mydomain.auth0.com/api/v2"
        );
        assert_eq!(config.token_url(), "https://mydomain.auth0.com/oauth/token");
    }

    #[test]
    fn test_convert_to_external_user() {
        let config = Auth0Config {
            domain: "test.auth0.com".to_string(),
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            connection: None,
            import_passwords: false,
            audience: None,
        };

        let auth0_user = create_test_auth0_user();
        let migrator = Auth0Migrator {
            client: reqwest::Client::new(),
            config,
            access_token: "test".to_string(),
        };

        let external = migrator.convert_to_external_user(auth0_user);

        assert_eq!(external.external_id, "auth0|123456");
        assert_eq!(external.email, Some("test@example.com".to_string()));
        assert!(external.email_verified);
        assert_eq!(external.given_name, Some("Test".to_string()));
        assert!(external.enabled);
    }

    #[test]
    fn test_validate_user() {
        let config = Auth0Config {
            domain: "test.auth0.com".to_string(),
            client_id: "test".to_string(),
            client_secret: "test".to_string(),
            connection: None,
            import_passwords: false,
            audience: None,
        };

        let migrator = Auth0Migrator {
            client: reqwest::Client::new(),
            config,
            access_token: "test".to_string(),
        };

        let options = MigrationOptions::default();

        // Valid user
        let valid_user = create_test_auth0_user();
        let result = migrator.validate_user(&valid_user, &options);
        assert!(result.valid);

        // Invalid email
        let mut invalid_user = create_test_auth0_user();
        invalid_user.email = "not-an-email".to_string();
        let result = migrator.validate_user(&invalid_user, &options);
        assert!(!result.valid);

        // Empty email
        let mut no_email = create_test_auth0_user();
        no_email.email = "".to_string();
        let result = migrator.validate_user(&no_email, &options);
        assert!(!result.valid);
    }
}
