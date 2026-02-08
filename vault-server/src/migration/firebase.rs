//! Firebase Authentication migration implementation

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::migration::models::{
    CreateUserFromMigration, ExternalMfaMethod, ExternalOAuthConnection, ExternalUser,
    MigrationError, MigrationOptions, ValidationResult,
};
use vault_core::models::user::UserProfile;

/// Firebase configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirebaseConfig {
    pub project_id: String,
    pub credentials_json: String,
    #[serde(default)]
    pub import_password_hashes: bool,
}

impl FirebaseConfig {
    /// Get the Identity Toolkit API base URL
    pub fn identity_toolkit_url(&self) -> String {
        format!(
            "https://identitytoolkit.googleapis.com/v1/projects/{}",
            self.project_id
        )
    }

    /// Get the Google Auth token URL
    pub fn token_url() -> &'static str {
        "https://oauth2.googleapis.com/token"
    }

    /// Parse service account credentials
    pub fn parse_credentials(&self) -> anyhow::Result<ServiceAccountCredentials> {
        let creds: ServiceAccountCredentials = serde_json::from_str(&self.credentials_json)?;
        Ok(creds)
    }
}

/// Service account credentials
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceAccountCredentials {
    #[serde(rename = "type")]
    pub cred_type: String,
    #[serde(rename = "project_id")]
    pub project_id: String,
    #[serde(rename = "private_key_id")]
    pub private_key_id: String,
    #[serde(rename = "private_key")]
    pub private_key: String,
    #[serde(rename = "client_email")]
    pub client_email: String,
    #[serde(rename = "client_id")]
    pub client_id: String,
    #[serde(rename = "auth_uri")]
    pub auth_uri: String,
    #[serde(rename = "token_uri")]
    pub token_uri: String,
}

/// Google OAuth token response
#[derive(Debug, Clone, Deserialize)]
struct GoogleTokenResponse {
    #[serde(rename = "access_token")]
    access_token: String,
    #[serde(rename = "token_type")]
    token_type: String,
    #[serde(rename = "expires_in")]
    expires_in: u64,
}

/// Firebase user representation
#[derive(Debug, Clone, Deserialize)]
pub struct FirebaseUser {
    #[serde(rename = "localId")]
    pub uid: String,
    pub email: Option<String>,
    #[serde(rename = "emailVerified")]
    pub email_verified: Option<bool>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "photoUrl")]
    pub photo_url: Option<String>,
    #[serde(rename = "phoneNumber")]
    pub phone_number: Option<String>,
    pub disabled: Option<bool>,
    pub metadata: Option<FirebaseUserMetadata>,
    #[serde(rename = "providerUserInfo")]
    pub provider_data: Option<Vec<FirebaseProviderData>>,
    #[serde(rename = "passwordHash")]
    pub password_hash: Option<String>,
    #[serde(rename = "salt")]
    pub password_salt: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(rename = "lastLoginAt")]
    pub last_login_at: Option<String>,
    #[serde(rename = "lastRefreshAt")]
    pub last_refresh_at: Option<String>,
    #[serde(rename = "customAttributes")]
    pub custom_attributes: Option<String>,
    pub tenant_id: Option<String>,
    #[serde(rename = "mfaInfo")]
    pub mfa_info: Option<Vec<FirebaseMfaInfo>>,
}

/// Firebase user metadata
#[derive(Debug, Clone, Deserialize)]
pub struct FirebaseUserMetadata {
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(rename = "lastLoginAt")]
    pub last_login_at: Option<String>,
    #[serde(rename = "lastRefreshAt")]
    pub last_refresh_at: Option<String>,
}

/// Firebase provider data (linked accounts)
#[derive(Debug, Clone, Deserialize)]
pub struct FirebaseProviderData {
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "federatedId")]
    pub federated_id: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "photoUrl")]
    pub photo_url: Option<String>,
    #[serde(rename = "phoneNumber")]
    pub phone_number: Option<String>,
    #[serde(rename = "rawId")]
    pub raw_id: Option<String>,
}

/// Firebase MFA info
#[derive(Debug, Clone, Deserialize)]
pub struct FirebaseMfaInfo {
    #[serde(rename = "mfaEnrollmentId")]
    pub enrollment_id: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "phoneInfo")]
    pub phone_info: Option<String>,
    #[serde(rename = "enrolledAt")]
    pub enrolled_at: Option<String>,
}

/// Firebase list users response
#[derive(Debug, Clone, Deserialize)]
struct ListUsersResponse {
    #[serde(rename = "users")]
    users: Option<Vec<FirebaseUser>>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

/// Firebase error response
#[derive(Debug, Clone, Deserialize)]
struct FirebaseError {
    error: FirebaseErrorDetails,
}

#[derive(Debug, Clone, Deserialize)]
struct FirebaseErrorDetails {
    code: i32,
    message: String,
    status: String,
}

/// Firebase migrator implementation
pub struct FirebaseMigrator {
    client: reqwest::Client,
    config: FirebaseConfig,
    access_token: String,
}

impl FirebaseMigrator {
    /// Create a new Firebase migrator
    pub async fn new(config: FirebaseConfig) -> anyhow::Result<Self> {
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

    /// Fetch access token using service account
    async fn fetch_access_token(
        client: &reqwest::Client,
        config: &FirebaseConfig,
    ) -> anyhow::Result<String> {
        let creds = config.parse_credentials()?;

        // Create JWT for service account authentication
        let jwt = Self::create_service_account_jwt(&creds)?;

        let request_body = serde_json::json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt,
        });

        let response = client
            .post(FirebaseConfig::token_url())
            .header("content-type", "application/x-www-form-urlencoded")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!(
                "Google token request failed: {}",
                error_text
            ));
        }

        let token_response: GoogleTokenResponse = response.json().await?;
        Ok(token_response.access_token)
    }

    /// Create JWT for service account authentication
    fn create_service_account_jwt(creds: &ServiceAccountCredentials) -> anyhow::Result<String> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use serde_json::json;

        let now = chrono::Utc::now().timestamp() as usize;
        let claims = json!({
            "iss": creds.client_email,
            "sub": creds.client_email,
            "scope": "https://www.googleapis.com/auth/identitytoolkit.readonly",
            "aud": creds.token_uri,
            "iat": now,
            "exp": now + 3600,
        });

        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(creds.private_key.as_bytes())?;
        let token = encode(&header, &claims, &key)?;

        Ok(token)
    }

    /// List users with pagination
    pub async fn list_users(
        &self,
        page_token: Option<String>,
        max_results: i32,
    ) -> anyhow::Result<(Vec<FirebaseUser>, Option<String>)> {
        let url = format!(
            "{}/accounts:batchGet",
            self.config.identity_toolkit_url()
        );

        let mut request = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .query(&[("maxResults", max_results.to_string())]);

        if let Some(token) = page_token {
            request = request.query(&[("nextPageToken", token)]);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!("Firebase API error: {}", error_text));
        }

        let list_response: ListUsersResponse = response.json().await?;
        let users = list_response.users.unwrap_or_default();
        let next_token = list_response.next_page_token;

        Ok((users, next_token))
    }

    /// Get a single user by UID
    pub async fn get_user(&self, uid: &str) -> anyhow::Result<Option<FirebaseUser>> {
        let url = format!("{}/accounts:lookup", self.config.identity_toolkit_url());

        let request_body = serde_json::json!({
            "localId": [uid],
        });

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!("Firebase API error: {}", error_text));
        }

        let result: ListUsersResponse = response.json().await?;
        Ok(result.users.and_then(|u| u.into_iter().next()))
    }

    /// Convert Firebase user to external user format
    pub fn convert_to_external_user(&self, fb_user: FirebaseUser) -> ExternalUser {
        // Parse timestamps
        let created_at = fb_user
            .created_at
            .as_ref()
            .and_then(|t| t.parse::<i64>().ok())
            .map(|ms| DateTime::from_timestamp_millis(ms).map(|dt| dt.with_timezone(&Utc)))
            .flatten()
            .or_else(|| {
                fb_user.metadata.as_ref().and_then(|m| {
                    m.created_at
                        .as_ref()
                        .and_then(|t| t.parse::<i64>().ok())
                        .map(|ms| DateTime::from_timestamp_millis(ms).map(|dt| dt.with_timezone(&Utc)))
                        .flatten()
                })
            });

        let last_login_at = fb_user
            .last_login_at
            .as_ref()
            .and_then(|t| t.parse::<i64>().ok())
            .map(|ms| DateTime::from_timestamp_millis(ms).map(|dt| dt.with_timezone(&Utc)))
            .flatten()
            .or_else(|| {
                fb_user.metadata.as_ref().and_then(|m| {
                    m.last_login_at
                        .as_ref()
                        .and_then(|t| t.parse::<i64>().ok())
                        .map(|ms| DateTime::from_timestamp_millis(ms).map(|dt| dt.with_timezone(&Utc)))
                        .flatten()
                })
            });

        // Parse custom attributes as metadata
        let mut metadata = HashMap::new();
        if let Some(attrs) = fb_user.custom_attributes {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&attrs) {
                if let Some(obj) = json.as_object() {
                    for (key, value) in obj {
                        metadata.insert(key.clone(), value.clone());
                    }
                }
            }
        }

        // Convert provider data to OAuth connections
        let oauth_connections: Vec<ExternalOAuthConnection> = fb_user
            .provider_data
            .unwrap_or_default()
            .into_iter()
            .filter(|p| p.provider_id != "password" && p.provider_id != "phone")
            .map(|provider| ExternalOAuthConnection {
                provider: provider.provider_id,
                provider_user_id: provider.federated_id.or(provider.raw_id).unwrap_or_default(),
                provider_username: provider.display_name.clone(),
                email: provider.email.clone(),
                access_token: None,
                refresh_token: None,
                token_expires_at: None,
                raw_data: None,
            })
            .collect();

        // Convert MFA info
        let mfa_methods: Vec<ExternalMfaMethod> = fb_user
            .mfa_info
            .unwrap_or_default()
            .into_iter()
            .map(|mfa| ExternalMfaMethod {
                method_type: if mfa.phone_info.is_some() {
                    "sms".to_string()
                } else {
                    "totp".to_string()
                },
                enabled: true,
                data: serde_json::json!({
                    "enrollment_id": mfa.enrollment_id,
                    "display_name": mfa.display_name,
                    "phone_info": mfa.phone_info,
                    "enrolled_at": mfa.enrolled_at,
                }),
            })
            .collect();

        ExternalUser {
            external_id: fb_user.uid,
            email: fb_user.email,
            email_verified: fb_user.email_verified.unwrap_or(false),
            username: None,
            given_name: None,
            family_name: None,
            display_name: fb_user.display_name,
            phone_number: fb_user.phone_number,
            phone_verified: false, // Firebase tracks this separately
            picture: fb_user.photo_url,
            password_hash: fb_user.password_hash,
            password_salt: fb_user.password_salt,
            status: if fb_user.disabled.unwrap_or(false) {
                Some("disabled".to_string())
            } else {
                None
            },
            created_at,
            last_login_at,
            last_ip: None, // Not available in Firebase API
            logins_count: None,
            metadata,
            oauth_connections,
            mfa_methods,
            enabled: !fb_user.disabled.unwrap_or(false),
            locked: false,
        }
    }

    /// Validate a Firebase user before migration
    pub fn validate_user(
        &self,
        user: &FirebaseUser,
        _options: &MigrationOptions,
    ) -> ValidationResult {
        let mut result = ValidationResult::valid();

        // Check for required email or phone
        if user.email.is_none() && user.phone_number.is_none() {
            result = result.with_error("User has neither email nor phone number");
        }

        // Validate email format if present
        if let Some(ref email) = user.email {
            if !email.contains('@') {
                result = result.with_error(format!("Invalid email format: {}", email));
            }
        }

        // Warn about unverified emails
        if let Some(false) = user.email_verified {
            result = result.with_warning("User email is not verified");
        }

        // Warn about disabled accounts
        if user.disabled.unwrap_or(false) {
            result = result.with_warning("User account is disabled");
        }

        result
    }

    /// Stream all users from Firebase
    pub async fn stream_users(
        &self,
        batch_size: usize,
    ) -> anyhow::Result<impl futures::Stream<Item = Result<FirebaseUser, MigrationError>>> {
        use futures::stream::{self, StreamExt};

        let config = self.config.clone();
        let stream = Box::pin(stream::unfold(
            (None::<String>, config, batch_size),
            |(page_token, config, batch_size)| async move {
                let migrator = match FirebaseMigrator::new(config.clone()).await {
                    Ok(m) => m,
                    Err(e) => {
                        return Some((
                            vec![Err(MigrationError {
                                user_id: "".to_string(),
                                email: None,
                                error: format!("Failed to create migrator: {}", e),
                                details: None,
                            })],
                            (None, config, batch_size),
                        ))
                    }
                };

                match migrator.list_users(page_token, batch_size as i32).await {
                    Ok((users, next_token)) => {
                        let items: Vec<_> = users.into_iter().map(Ok).collect();
                        Some((items, (next_token, config, batch_size)))
                    }
                    Err(e) => Some((
                        vec![Err(MigrationError {
                            user_id: "".to_string(),
                            email: None,
                            error: format!("Failed to list users: {}", e),
                            details: None,
                        })],
                        (None, config, batch_size),
                    )),
                }
            },
        )
        .flat_map(stream::iter));

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
        picture: external.picture.clone(),
        phone_number: external.phone_number.clone(),
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
        source: "firebase".to_string(),
        status: external.status,
        created_at: external.created_at,
        oauth_connections: external.oauth_connections,
        mfa_methods: external.mfa_methods,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firebase_config_urls() {
        let config = FirebaseConfig {
            project_id: "my-project".to_string(),
            credentials_json: r#"{"type": "service_account"}"#.to_string(),
            import_password_hashes: false,
        };

        assert_eq!(
            config.identity_toolkit_url(),
            "https://identitytoolkit.googleapis.com/v1/projects/my-project"
        );
    }

    #[test]
    fn test_parse_service_account_credentials() {
        let json = r#"{
            "type": "service_account",
            "project_id": "test-project",
            "private_key_id": "key123",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMII...\n-----END RSA PRIVATE KEY-----\n",
            "client_email": "test@test-project.iam.gserviceaccount.com",
            "client_id": "123456",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }"#;

        let config = FirebaseConfig {
            project_id: "test-project".to_string(),
            credentials_json: json.to_string(),
            import_password_hashes: false,
        };

        let creds = config.parse_credentials().unwrap();
        assert_eq!(creds.project_id, "test-project");
        assert_eq!(creds.client_email, "test@test-project.iam.gserviceaccount.com");
    }

    #[test]
    fn test_convert_to_external_user() {
        let fb_user = FirebaseUser {
            uid: "abc123".to_string(),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            display_name: Some("Test User".to_string()),
            photo_url: Some("https://example.com/photo.jpg".to_string()),
            phone_number: Some("+1234567890".to_string()),
            disabled: Some(false),
            metadata: Some(FirebaseUserMetadata {
                created_at: Some("1609459200000".to_string()),
                last_login_at: Some("1609459200000".to_string()),
                last_refresh_at: None,
            }),
            provider_data: Some(vec![FirebaseProviderData {
                provider_id: "google.com".to_string(),
                federated_id: Some("12345".to_string()),
                display_name: Some("Test User".to_string()),
                email: Some("test@example.com".to_string()),
                photo_url: Some("https://example.com/photo.jpg".to_string()),
                phone_number: None,
                raw_id: Some("12345".to_string()),
            }]),
            password_hash: Some("hash123".to_string()),
            password_salt: Some("salt123".to_string()),
            created_at: Some("1609459200000".to_string()),
            last_login_at: Some("1609459200000".to_string()),
            last_refresh_at: None,
            custom_attributes: Some(r#"{"role": "admin"}"#.to_string()),
            tenant_id: None,
            mfa_info: Some(vec![FirebaseMfaInfo {
                enrollment_id: "mfa123".to_string(),
                display_name: Some("Phone".to_string()),
                phone_info: Some("+1234567890".to_string()),
                enrolled_at: Some("2021-01-01T00:00:00Z".to_string()),
            }]),
        };

        let config = FirebaseConfig {
            project_id: "test".to_string(),
            credentials_json: "{}".to_string(),
            import_password_hashes: false,
        };

        let migrator = FirebaseMigrator {
            client: reqwest::Client::new(),
            config,
            access_token: "test".to_string(),
        };

        let external = migrator.convert_to_external_user(fb_user);

        assert_eq!(external.external_id, "abc123");
        assert_eq!(external.email, Some("test@example.com".to_string()));
        assert_eq!(external.display_name, Some("Test User".to_string()));
        assert!(external.created_at.is_some());
        assert_eq!(external.oauth_connections.len(), 1);
        assert_eq!(external.mfa_methods.len(), 1);
    }
}
