//! AWS Cognito migration implementation

use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::migration::models::{
    CreateUserFromMigration, ExternalMfaMethod, ExternalUser,
    MigrationError, MigrationOptions, ValidationResult,
};
use vault_core::models::user::UserProfile;

/// AWS Cognito configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitoConfig {
    pub region: String,
    #[serde(rename = "user_pool_id")]
    pub user_pool_id: String,
    #[serde(rename = "access_key_id")]
    pub access_key_id: String,
    #[serde(rename = "secret_access_key")]
    pub secret_access_key: String,
    #[serde(default)]
    pub session_token: Option<String>,
}

impl CognitoConfig {
    /// Get the Cognito IDP endpoint
    pub fn endpoint(&self) -> String {
        format!(
            "https://cognito-idp.{}.amazonaws.com",
            self.region
        )
    }
}

/// Cognito user representation
#[derive(Debug, Clone, Deserialize)]
pub struct CognitoUser {
    #[serde(rename = "Username")]
    pub username: String,
    #[serde(rename = "Attributes")]
    pub attributes: Vec<CognitoAttribute>,
    #[serde(rename = "UserCreateDate")]
    pub created_at: f64,
    #[serde(rename = "UserLastModifiedDate")]
    pub modified_at: f64,
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "UserStatus")]
    pub user_status: String,
    #[serde(rename = "MFAOptions")]
    pub mfa_options: Option<Vec<CognitoMfaOption>>,
    #[serde(rename = "UserMFASettingList")]
    pub user_mfa_settings: Option<Vec<String>>,
}

/// Cognito user attribute
#[derive(Debug, Clone, Deserialize)]
pub struct CognitoAttribute {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Value")]
    pub value: String,
}

/// Cognito MFA option
#[derive(Debug, Clone, Deserialize)]
pub struct CognitoMfaOption {
    #[serde(rename = "DeliveryMedium")]
    pub delivery_medium: String,
    #[serde(rename = "AttributeName")]
    pub attribute_name: String,
}

/// Cognito list users response
#[derive(Debug, Clone, Deserialize)]
struct ListUsersResponse {
    #[serde(rename = "Users")]
    users: Option<Vec<CognitoUser>>,
    #[serde(rename = "PaginationToken")]
    pagination_token: Option<String>,
}

/// Cognito API request wrapper
#[derive(Debug, Clone, Serialize)]
struct CognitoRequest {
    #[serde(rename = "Target")]
    target: String,
    #[serde(rename = "UserPoolId")]
    user_pool_id: String,
    #[serde(rename = "PaginationToken", skip_serializing_if = "Option::is_none")]
    pagination_token: Option<String>,
    #[serde(rename = "Limit", skip_serializing_if = "Option::is_none")]
    limit: Option<i32>,
    #[serde(rename = "Filter", skip_serializing_if = "Option::is_none")]
    filter: Option<String>,
}

/// AWS Signature V4 signer
pub struct AwsSigner {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
    region: String,
    service: String,
}

impl AwsSigner {
    pub fn new(
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        session_token: Option<String>,
        region: impl Into<String>,
    ) -> Self {
        Self {
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            session_token,
            region: region.into(),
            service: "cognito-idp".to_string(),
        }
    }

    /// Sign a request using AWS Signature Version 4
    pub fn sign_request(
        &self,
        method: &str,
        uri: &str,
        headers: &mut HashMap<String, String>,
        payload: &str,
    ) -> anyhow::Result<()> {
        use sha2::{Digest, Sha256};

        let now = chrono::Utc::now();
        let date_stamp = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        // Add required headers
        headers.insert("host".to_string(), uri.replace("https://", ""));
        headers.insert("x-amz-date".to_string(), amz_date.clone());

        if let Some(ref token) = self.session_token {
            headers.insert("x-amz-security-token".to_string(), token.clone());
        }

        // Create canonical request
        let payload_hash = hex::encode(Sha256::digest(payload.as_bytes()));
        headers.insert("x-amz-content-sha256".to_string(), payload_hash.clone());

        let canonical_headers = self.build_canonical_headers(headers);
        let signed_headers = headers.keys().map(|k| k.as_str()).collect::<Vec<_>>().join(";");

        let canonical_request = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            method,
            "/",
            "",
            canonical_headers,
            signed_headers,
            payload_hash
        );

        // Create string to sign
        let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, self.region, self.service);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_date,
            credential_scope,
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        // Calculate signature
        let signature = self.calculate_signature(&date_stamp, &string_to_sign)?;

        // Add authorization header
        let auth_header = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
            self.access_key, credential_scope, signed_headers, signature
        );
        headers.insert("authorization".to_string(), auth_header);

        Ok(())
    }

    fn build_canonical_headers(&self, headers: &HashMap<String, String>) -> String {
        let mut sorted: Vec<_> = headers.iter().collect();
        sorted.sort_by_key(|(k, _)| k.to_lowercase());

        sorted
            .into_iter()
            .map(|(k, v)| format!("{}:{}\n", k.to_lowercase(), v.trim()))
            .collect()
    }

    fn calculate_signature(&self, date_stamp: &str, string_to_sign: &str) -> anyhow::Result<String> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let date_key = {
            let mut mac = HmacSha256::new_from_slice(
                format!("AWS4{}", self.secret_key).as_bytes()
            ).map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(date_stamp.as_bytes());
            mac.finalize().into_bytes()
        };

        let date_region_key = {
            let mut mac = HmacSha256::new_from_slice(&date_key)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(self.region.as_bytes());
            mac.finalize().into_bytes()
        };

        let date_region_service_key = {
            let mut mac = HmacSha256::new_from_slice(&date_region_key)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(self.service.as_bytes());
            mac.finalize().into_bytes()
        };

        let signing_key = {
            let mut mac = HmacSha256::new_from_slice(&date_region_service_key)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(b"aws4_request");
            mac.finalize().into_bytes()
        };

        let signature = {
            let mut mac = HmacSha256::new_from_slice(&signing_key)
                .map_err(|e| anyhow::anyhow!("HMAC error: {}", e))?;
            mac.update(string_to_sign.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        };

        Ok(signature)
    }
}

/// AWS Cognito migrator implementation
pub struct CognitoMigrator {
    client: reqwest::Client,
    config: CognitoConfig,
    signer: AwsSigner,
}

impl CognitoMigrator {
    /// Create a new Cognito migrator
    pub fn new(config: CognitoConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let signer = AwsSigner::new(
            config.access_key_id.clone(),
            config.secret_access_key.clone(),
            config.session_token.clone(),
            config.region.clone(),
        );

        Ok(Self {
            client,
            config,
            signer,
        })
    }

    /// List users with pagination
    pub async fn list_users(
        &self,
        pagination_token: Option<String>,
        limit: Option<i32>,
    ) -> anyhow::Result<(Vec<CognitoUser>, Option<String>)> {
        let url = self.config.endpoint();

        let request_body = CognitoRequest {
            target: "AWSCognitoIdpService.ListUsers".to_string(),
            user_pool_id: self.config.user_pool_id.clone(),
            pagination_token,
            limit,
            filter: None,
        };

        let payload = serde_json::to_string(&request_body)?;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/x-amz-json-1.1".to_string());
        headers.insert("x-amz-target".to_string(), "AWSCognitoIdpService.ListUsers".to_string());

        self.signer.sign_request("POST", &url, &mut headers, &payload)?;

        let mut request = self.client.post(&url).body(payload);

        for (key, value) in headers {
            request = request.header(key, value);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!("Cognito API error: {}", error_text));
        }

        let list_response: ListUsersResponse = response.json().await?;
        let users = list_response.users.unwrap_or_default();
        let next_token = list_response.pagination_token;

        Ok((users, next_token))
    }

    /// Get a single user by username
    pub async fn get_user(&self, username: &str) -> anyhow::Result<Option<CognitoUser>> {
        let url = self.config.endpoint();

        #[derive(Serialize)]
        struct AdminGetUserRequest {
            #[serde(rename = "UserPoolId")]
            user_pool_id: String,
            #[serde(rename = "Username")]
            username: String,
        }

        let request_body = AdminGetUserRequest {
            user_pool_id: self.config.user_pool_id.clone(),
            username: username.to_string(),
        };

        let payload = serde_json::to_string(&request_body)?;

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/x-amz-json-1.1".to_string());
        headers.insert("x-amz-target".to_string(), "AWSCognitoIdpService.AdminGetUser".to_string());

        self.signer.sign_request("POST", &url, &mut headers, &payload)?;

        let mut request = self.client.post(&url).body(payload);

        for (key, value) in headers {
            request = request.header(key, value);
        }

        let response = request.send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow::anyhow!("Cognito API error: {}", error_text));
        }

        let user: CognitoUser = response.json().await?;
        Ok(Some(user))
    }

    /// Get user attribute by name
    fn get_attribute(&self, user: &CognitoUser, name: &str) -> Option<String> {
        user.attributes
            .iter()
            .find(|attr| attr.name == name)
            .map(|attr| attr.value.clone())
    }

    /// Convert Cognito user to external user format
    pub fn convert_to_external_user(&self, cognito_user: CognitoUser) -> ExternalUser {
        let email = self.get_attribute(&cognito_user, "email");
        let email_verified = self
            .get_attribute(&cognito_user, "email_verified")
            .map(|v| v == "true")
            .unwrap_or(false);
        let given_name = self.get_attribute(&cognito_user, "given_name");
        let family_name = self.get_attribute(&cognito_user, "family_name");
        let phone_number = self.get_attribute(&cognito_user, "phone_number");
        let phone_verified = self
            .get_attribute(&cognito_user, "phone_number_verified")
            .map(|v| v == "true")
            .unwrap_or(false);
        let picture = self.get_attribute(&cognito_user, "picture");

        // Parse timestamps (Cognito returns epoch seconds as float)
        let created_at = DateTime::from_timestamp(cognito_user.created_at as i64, 0);
        let modified_at = DateTime::from_timestamp(cognito_user.modified_at as i64, 0);

        // Collect all other attributes as metadata
        let mut metadata = HashMap::new();
        for attr in &cognito_user.attributes {
            let standard_attrs = [
                "email",
                "email_verified",
                "given_name",
                "family_name",
                "phone_number",
                "phone_number_verified",
                "picture",
                "sub",
            ];
            if !standard_attrs.contains(&attr.name.as_str()) {
                metadata.insert(
                    attr.name.clone(),
                    serde_json::Value::String(attr.value.clone()),
                );
            }
        }

        // Convert MFA settings
        let mfa_methods: Vec<ExternalMfaMethod> = cognito_user
            .user_mfa_settings
            .as_ref()
            .map(|settings| {
                settings
                    .iter()
                    .map(|s| ExternalMfaMethod {
                        method_type: s.clone(),
                        enabled: true,
                        data: serde_json::json!({}),
                    })
                    .collect()
            })
            .unwrap_or_default();

        // Map status
        let status = match cognito_user.user_status.as_str() {
            "UNCONFIRMED" => Some("unconfirmed".to_string()),
            "CONFIRMED" => None,
            "ARCHIVED" => Some("archived".to_string()),
            "COMPROMISED" => Some("compromised".to_string()),
            "UNKNOWN" => Some("unknown".to_string()),
            "RESET_REQUIRED" => Some("reset_required".to_string()),
            "FORCE_CHANGE_PASSWORD" => Some("force_change_password".to_string()),
            _ => None,
        };

        ExternalUser {
            external_id: cognito_user.username.clone(),
            email,
            email_verified,
            username: Some(cognito_user.username),
            given_name,
            family_name,
            display_name: None,
            phone_number,
            phone_verified,
            picture,
            password_hash: None, // Cognito doesn't expose password hashes
            password_salt: None,
            status: status.clone(),
            created_at,
            last_login_at: None, // Not directly available
            last_ip: None,
            logins_count: None,
            metadata,
            oauth_connections: Vec::new(), // Would need separate API calls
            mfa_methods,
            enabled: cognito_user.enabled,
            locked: !cognito_user.enabled || status.as_deref() == Some("compromised"),
        }
    }

    /// Validate a Cognito user before migration
    pub fn validate_user(
        &self,
        user: &CognitoUser,
        _options: &MigrationOptions,
    ) -> ValidationResult {
        let mut result = ValidationResult::valid();

        let email = self.get_attribute(user, "email");

        // Check for required email
        if email.is_none() {
            result = result.with_error("User has no email address");
        }

        // Validate email format if present
        if let Some(ref email) = email {
            if !email.contains('@') {
                result = result.with_error(format!("Invalid email format: {}", email));
            }
        }

        // Check user status
        match user.user_status.as_str() {
            "UNCONFIRMED" => result = result.with_warning("User is unconfirmed"),
            "ARCHIVED" => result = result.with_warning("User is archived"),
            "COMPROMISED" => result = result.with_warning("User is marked as compromised"),
            "RESET_REQUIRED" => result = result.with_warning("Password reset required"),
            "FORCE_CHANGE_PASSWORD" => result = result.with_warning("Force password change required"),
            _ => {}
        }

        // Warn about disabled accounts
        if !user.enabled {
            result = result.with_warning("User account is disabled");
        }

        result
    }

    /// Stream all users from Cognito
    pub async fn stream_users(
        &self,
        batch_size: usize,
    ) -> anyhow::Result<impl futures::Stream<Item = Result<CognitoUser, MigrationError>>> {
        use futures::stream::{self, StreamExt};

        let config = self.config.clone();
        let stream = Box::pin(stream::unfold(
            (None::<String>, config, batch_size),
            |(page_token, config, batch_size)| async move {
                let migrator = match CognitoMigrator::new(config.clone()) {
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

                match migrator.list_users(page_token, Some(batch_size as i32)).await {
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
        source: "cognito".to_string(),
        status: external.status,
        created_at: external.created_at,
        oauth_connections: external.oauth_connections,
        mfa_methods: external.mfa_methods,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_cognito_user() -> CognitoUser {
        CognitoUser {
            username: "testuser".to_string(),
            attributes: vec![
                CognitoAttribute {
                    name: "email".to_string(),
                    value: "test@example.com".to_string(),
                },
                CognitoAttribute {
                    name: "email_verified".to_string(),
                    value: "true".to_string(),
                },
                CognitoAttribute {
                    name: "given_name".to_string(),
                    value: "Test".to_string(),
                },
                CognitoAttribute {
                    name: "family_name".to_string(),
                    value: "User".to_string(),
                },
            ],
            created_at: 1609459200.0,
            modified_at: 1609459200.0,
            enabled: true,
            user_status: "CONFIRMED".to_string(),
            mfa_options: None,
            user_mfa_settings: Some(vec!["SMS_MFA".to_string()]),
        }
    }

    #[test]
    fn test_cognito_config() {
        let config = CognitoConfig {
            region: "us-east-1".to_string(),
            user_pool_id: "us-east-1_123456789".to_string(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        };

        assert_eq!(
            config.endpoint(),
            "https://cognito-idp.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn test_convert_to_external_user() {
        let cognito_user = create_test_cognito_user();

        let config = CognitoConfig {
            region: "us-east-1".to_string(),
            user_pool_id: "test".to_string(),
            access_key_id: "test".to_string(),
            secret_access_key: "test".to_string(),
            session_token: None,
        };

        let migrator = CognitoMigrator::new(config).unwrap();
        let external = migrator.convert_to_external_user(cognito_user);

        assert_eq!(external.external_id, "testuser");
        assert_eq!(external.email, Some("test@example.com".to_string()));
        assert!(external.email_verified);
        assert_eq!(external.given_name, Some("Test".to_string()));
        assert_eq!(external.family_name, Some("User".to_string()));
        assert!(external.enabled);
        assert_eq!(external.mfa_methods.len(), 1);
    }

    #[test]
    fn test_validate_user() {
        let cognito_user = create_test_cognito_user();

        let config = CognitoConfig {
            region: "us-east-1".to_string(),
            user_pool_id: "test".to_string(),
            access_key_id: "test".to_string(),
            secret_access_key: "test".to_string(),
            session_token: None,
        };

        let migrator = CognitoMigrator::new(config).unwrap();
        let options = MigrationOptions::default();

        let result = migrator.validate_user(&cognito_user, &options);
        assert!(result.valid);

        // Test with no email
        let mut no_email = cognito_user.clone();
        no_email.attributes.retain(|a| a.name != "email");
        let result = migrator.validate_user(&no_email, &options);
        assert!(!result.valid);

        // Test with disabled user
        let mut disabled = cognito_user.clone();
        disabled.enabled = false;
        let result = migrator.validate_user(&disabled, &options);
        assert!(result.valid); // Still valid, but with warning
        assert!(!result.warnings.is_empty());
    }
}
