//! Client Credentials Flow Implementation
//!
//! Implements OAuth 2.0 Client Credentials Grant for M2M authentication:
//! https://tools.ietf.org/html/rfc6749#section-4.4
//!
//! Key differences from user auth:
//! - No refresh tokens (just request new token)
//! - Shorter token lifetimes (1 hour default)
//! - Different JWT claims (client_id instead of sub)
//! - Scope-based permissions

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use vault_core::crypto::{HybridSigningKey, HybridVerifyingKey, TokenType};

/// Client credentials token request
#[derive(Debug, Deserialize)]
pub struct ClientCredentialsRequest {
    pub grant_type: String,
    pub client_id: String,
    pub client_secret: String,
    /// Optional requested scopes (space-separated)
    pub scope: Option<String>,
}

/// Successful token response
#[derive(Debug, Serialize)]
pub struct ClientCredentialsResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    /// Granted scopes (space-separated)
    pub scope: String,
}

/// Error response for token endpoint
#[derive(Debug, Serialize)]
pub struct TokenErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Token validation result
#[derive(Debug, Clone)]
pub struct ClientCredentialsValidation {
    pub service_account_id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub permissions: Vec<String>,
}

/// Default token lifetime in seconds (1 hour)
pub const DEFAULT_TOKEN_LIFETIME_SECS: i64 = 3600;

/// Maximum token lifetime in seconds (24 hours)
pub const MAX_TOKEN_LIFETIME_SECS: i64 = 86400;

/// Client credentials service
#[derive(Clone)]
pub struct ClientCredentialsService {
    db: crate::db::Database,
    jwt_issuer: String,
    jwt_audience: String,
    token_lifetime_secs: i64,
    signing_key: HybridSigningKey,
    verifying_key: HybridVerifyingKey,
}

impl ClientCredentialsService {
    /// Create a new client credentials service
    pub fn new(
        db: crate::db::Database,
        jwt_issuer: String,
        jwt_audience: String,
    ) -> Self {
        let (signing_key, verifying_key) = HybridSigningKey::generate();
        Self {
            db,
            jwt_issuer,
            jwt_audience,
            token_lifetime_secs: DEFAULT_TOKEN_LIFETIME_SECS,
            signing_key,
            verifying_key,
        }
    }

    /// Set custom token lifetime
    pub fn with_token_lifetime(mut self, seconds: i64) -> Self {
        self.token_lifetime_secs = seconds.min(MAX_TOKEN_LIFETIME_SECS);
        self
    }

    /// Exchange client credentials for an access token
    pub async fn exchange_token(
        &self,
        request: ClientCredentialsRequest,
        tenant_id: &str,
    ) -> Result<ClientCredentialsResponse, ClientCredentialsError> {
        // Validate grant type
        if request.grant_type != "client_credentials" {
            return Err(ClientCredentialsError::UnsupportedGrantType);
        }

        // Validate client credentials
        let service_account = self
            .validate_client_credentials(tenant_id, &request.client_id, &request.client_secret)
            .await?;

        // Check if account is active
        if !service_account.is_active {
            return Err(ClientCredentialsError::InvalidClient);
        }

        // Check expiration
        if let Some(expires_at) = service_account.expires_at {
            if Utc::now() > expires_at {
                return Err(ClientCredentialsError::AccountExpired);
            }
        }

        // Determine scopes to grant
        let requested_scopes = request
            .scope
            .as_ref()
            .map(|s| s.split_whitespace().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();

        let granted_scopes = if requested_scopes.is_empty() {
            // If no scopes requested, grant all assigned scopes
            service_account.scopes.clone()
        } else {
            // Validate requested scopes against assigned scopes
            let assigned: std::collections::HashSet<_> = service_account.scopes.iter().collect();
            let valid_scopes: Vec<_> = requested_scopes
                .iter()
                .filter(|s| assigned.contains(*s))
                .cloned()
                .collect();
            
            if valid_scopes.is_empty() {
                return Err(ClientCredentialsError::InvalidScope);
            }
            valid_scopes
        };

        // Generate JWT access token
        let access_token = self
            .generate_access_token(&service_account, &granted_scopes)
            .await?;

        // Update last_used_at
        let _ = sqlx::query(
            "UPDATE service_accounts SET last_used_at = NOW() WHERE id = $1"
        )
        .bind(&service_account.id)
        .execute(self.db.pool())
        .await;

        Ok(ClientCredentialsResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: self.token_lifetime_secs,
            scope: granted_scopes.join(" "),
        })
    }

    /// Validate client ID and secret
    async fn validate_client_credentials(
        &self,
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<ServiceAccountRow, ClientCredentialsError> {
        // Fetch service account by client_id and tenant_id
        let row: Option<ServiceAccountRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, description, client_id, client_secret_hash, 
               scopes, permissions, rate_limit_rps, rate_limit_burst, expires_at, 
               last_used_at, created_at, is_active
               FROM service_accounts 
               WHERE client_id = $1 AND tenant_id = $2"#
        )
        .bind(client_id)
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| ClientCredentialsError::Database(e.to_string()))?;

        let service_account = row.ok_or(ClientCredentialsError::InvalidClient)?;

        // Verify client secret using Argon2
        let valid = vault_core::crypto::VaultPasswordHasher::verify(
            client_secret,
            &service_account.client_secret_hash,
        )
        .map_err(|_| ClientCredentialsError::InvalidClient)?;

        if !valid {
            return Err(ClientCredentialsError::InvalidClient);
        }

        Ok(service_account)
    }

    /// Generate a JWT access token for M2M authentication
    async fn generate_access_token(
        &self,
        service_account: &ServiceAccountRow,
        scopes: &[String],
    ) -> Result<String, ClientCredentialsError> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(self.token_lifetime_secs);

        // Build custom claims for M2M
        let mut custom = std::collections::HashMap::new();
        custom.insert(
            "service_account_id".to_string(),
            serde_json::Value::String(service_account.id.clone()),
        );
        custom.insert(
            "client_id".to_string(),
            serde_json::Value::String(service_account.client_id.clone()),
        );
        custom.insert(
            "token_kind".to_string(),
            serde_json::Value::String("m2m".to_string()),
        );
        custom.insert(
            "scopes".to_string(),
            serde_json::json!(scopes),
        );
        custom.insert(
            "permissions".to_string(),
            serde_json::json!(&service_account.permissions),
        );

        // Build claims specific to M2M
        let claims = vault_core::crypto::Claims {
            // Use client_id as the subject for M2M tokens
            sub: service_account.client_id.clone(),
            tenant_id: service_account.tenant_id.clone(),
            session_id: None,
            email: None,
            email_verified: None,
            mfa_authenticated: None,
            roles: Some(service_account.permissions.clone()),
            iat: now.timestamp(),
            exp: expires_at.timestamp(),
            nbf: now.timestamp(),
            iss: self.jwt_issuer.clone(),
            aud: self.jwt_audience.clone(),
            token_type: TokenType::Access,
            jti: uuid::Uuid::new_v4().to_string(),
            custom,
            name: None,
            scope: None,
            acr: None,
            amr: None,
            step_up_expires_at: None,
        };

        // Get signing key - in production this integrates with the AuthService
        let signing_key = self.get_signing_key().await?;

        // Generate JWT
        let token = vault_core::crypto::HybridJwt::encode(&claims, &signing_key)
            .map_err(|e| ClientCredentialsError::TokenGeneration(e.to_string()))?;

        Ok(token)
    }

    /// Get the JWT signing key
    async fn get_signing_key(&self) -> Result<HybridSigningKey, ClientCredentialsError> {
        // In production, this should load from tenant key management.
        Ok(self.signing_key.clone())
    }

    /// Validate an M2M access token
    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Result<M2MTokenValidation, ClientCredentialsError> {
        // Get verifying key
        let verifying_key = self.get_verifying_key().await?;

        // Decode and validate
        let claims = vault_core::crypto::HybridJwt::decode(token, &verifying_key)
            .map_err(|_| ClientCredentialsError::InvalidToken)?;

        // Verify it's an M2M token
        let is_m2m = claims
            .custom
            .get("token_kind")
            .and_then(|v| v.as_str())
            .map(|s| s == "m2m")
            .unwrap_or(false);

        if !is_m2m {
            return Err(ClientCredentialsError::InvalidToken);
        }

        // Verify token type
        if claims.token_type != TokenType::Access {
            return Err(ClientCredentialsError::InvalidToken);
        }

        // Extract scopes from custom claims
        let scopes = claims
            .custom
            .get("scopes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let permissions = claims
            .custom
            .get("permissions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let service_account_id = claims
            .custom
            .get("service_account_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_default();

        Ok(M2MTokenValidation {
            client_id: claims.sub,
            tenant_id: claims.tenant_id,
            service_account_id,
            scopes,
            permissions,
            expires_at: DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(|| Utc::now()),
        })
    }

    /// Get the JWT verifying key
    async fn get_verifying_key(&self) -> Result<HybridVerifyingKey, ClientCredentialsError> {
        // In production, this should load from tenant key management.
        Ok(self.verifying_key.clone())
    }
}

/// Result of validating an M2M token
#[derive(Debug, Clone)]
pub struct M2MTokenValidation {
    pub client_id: String,
    pub tenant_id: String,
    pub service_account_id: String,
    pub scopes: Vec<String>,
    pub permissions: Vec<String>,
    pub expires_at: DateTime<Utc>,
}

/// Client credentials errors
#[derive(Debug, thiserror::Error)]
pub enum ClientCredentialsError {
    #[error("invalid_client")]
    InvalidClient,
    #[error("invalid_scope")]
    InvalidScope,
    #[error("unsupported_grant_type")]
    UnsupportedGrantType,
    #[error("account_expired")]
    AccountExpired,
    #[error("invalid_token")]
    InvalidToken,
    #[error("database error: {0}")]
    Database(String),
    #[error("token generation failed: {0}")]
    TokenGeneration(String),
}

// Database row type for service account queries
#[derive(sqlx::FromRow)]
struct ServiceAccountRow {
    id: String,
    tenant_id: String,
    name: String,
    description: Option<String>,
    client_id: String,
    client_secret_hash: String,
    scopes: Vec<String>,
    permissions: Vec<String>,
    rate_limit_rps: Option<i32>,
    rate_limit_burst: Option<i32>,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    is_active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_lifetime_constants() {
        assert_eq!(DEFAULT_TOKEN_LIFETIME_SECS, 3600);
        assert_eq!(MAX_TOKEN_LIFETIME_SECS, 86400);
    }
}
