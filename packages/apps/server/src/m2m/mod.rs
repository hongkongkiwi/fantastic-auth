//! Machine-to-Machine (M2M) Authentication Module
//!
//! Provides authentication for services, APIs, and IoT devices without user interaction.
//!
//! # Features
//!
//! - **Service Accounts**: Non-user entities with their own credentials
//! - **Client Credentials Flow**: OAuth 2.0 compliant token exchange
//! - **API Keys**: Simple key-based authentication for quick integration
//! - **Scope-based Permissions**: Fine-grained access control
//! - **Rate Limiting**: Per-service-account rate limits
//! - **Key Rotation**: Secure credential rotation without downtime
//!
//! # Authentication Methods
//!
//! ## 1. OAuth Client Credentials
//! ```
//! POST /oauth/token
//! Content-Type: application/x-www-form-urlencoded
//!
//! grant_type=client_credentials&
//! client_id=CLIENT_ID&
//! client_secret=CLIENT_SECRET&
//! scope=api:read%20api:write
//! ```
//!
//! ## 2. API Key
//! ```
//! GET /api/v1/protected/resource
//! Authorization: Bearer vault_m2m_tenant_abc123...
//! ```
//!
//! # Differences from User Authentication
//!
//! - No refresh tokens (request new token when needed)
//! - Shorter token lifetimes (1 hour default)
//! - Different JWT claims (`client_id` instead of `sub` for user ID)
//! - Scope-based permissions, not role-based
//! - Higher configurable rate limits
//! - No MFA required

pub mod api_keys;
pub mod client_credentials;
pub mod service_account;

pub use api_keys::{
    generate_api_key, hash_api_key, verify_api_key, ApiKey, ApiKeyError, ApiKeyManager,
    ApiKeySummary, ApiKeyWithSecret, CreateApiKeyRequest, UpdateApiKeyRequest,
    API_KEY_PREFIX, API_KEY_RANDOM_LENGTH,
};
pub use client_credentials::{
    ClientCredentialsError, ClientCredentialsRequest, ClientCredentialsResponse,
    ClientCredentialsService, ClientCredentialsValidation, M2MTokenValidation,
    TokenErrorResponse, DEFAULT_TOKEN_LIFETIME_SECS, MAX_TOKEN_LIFETIME_SECS,
};
pub use service_account::{
    AuthenticationMethod, CreateServiceAccountRequest, RateLimitConfig, ServiceAccount,
    ServiceAccountContext, ServiceAccountCredentials, ServiceAccountSummary,
    UpdateServiceAccountRequest,
};

use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};

/// M2M Authentication Service
///
/// Combines API key management and client credentials flow into a unified service.
#[derive(Clone)]
pub struct M2mAuthService {
    db: crate::db::Database,
    api_key_manager: ApiKeyManager,
    client_credentials: ClientCredentialsService,
}

impl M2mAuthService {
    /// Create a new M2M auth service
    pub fn new(
        db: crate::db::Database,
        jwt_issuer: String,
        jwt_audience: String,
    ) -> Self {
        let api_key_manager = ApiKeyManager::new(db.clone());
        let client_credentials = ClientCredentialsService::new(
            db.clone(),
            jwt_issuer,
            jwt_audience,
        );

        Self {
            db,
            api_key_manager,
            client_credentials,
        }
    }

    /// Get the API key manager
    pub fn api_keys(&self) -> &ApiKeyManager {
        &self.api_key_manager
    }

    /// Get the client credentials service
    pub fn client_credentials(&self) -> &ClientCredentialsService {
        &self.client_credentials
    }

    /// Create a new service account
    pub async fn create_service_account(
        &self,
        tenant_id: &str,
        request: CreateServiceAccountRequest,
    ) -> Result<ServiceAccountCredentials, M2mError> {
        // Generate client ID and secret
        let client_id = generate_client_id();
        let client_secret = generate_client_secret();
        
        // Hash the client secret
        let client_secret_hash = vault_core::crypto::VaultPasswordHasher::hash(&client_secret)
            .map_err(|e| M2mError::Hashing(e.to_string()))?;

        let service_account_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        // Insert into database
        sqlx::query(
            r#"INSERT INTO service_accounts 
               (id, tenant_id, name, description, client_id, client_secret_hash, 
                scopes, permissions, rate_limit_rps, rate_limit_burst, expires_at, 
                created_at, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, true)"#
        )
        .bind(&service_account_id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(&request.description)
        .bind(&client_id)
        .bind(&client_secret_hash)
        .bind(&request.scopes.clone().unwrap_or_default())
        .bind(&request.permissions.clone().unwrap_or_default())
        .bind(request.rate_limit_rps.map(|v| v as i32))
        .bind(request.rate_limit_burst.map(|v| v as i32))
        .bind(request.expires_at)
        .bind(now)
        .execute(self.db.pool())
        .await
        .map_err(|e| M2mError::Database(e.to_string()))?;

        Ok(ServiceAccountCredentials {
            id: service_account_id,
            client_id,
            client_secret, // Only returned once!
            name: request.name,
            scopes: request.scopes.unwrap_or_default(),
            permissions: request.permissions.unwrap_or_default(),
            created_at: now,
        })
    }

    /// Get a service account by ID
    pub async fn get_service_account(
        &self,
        tenant_id: &str,
        service_account_id: &str,
    ) -> Result<Option<ServiceAccount>, M2mError> {
        let row: Option<ServiceAccountRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, description, client_id, client_secret_hash, 
               scopes, permissions, rate_limit_rps, rate_limit_burst, expires_at, 
               last_used_at, created_at, is_active
               FROM service_accounts 
               WHERE id = $1 AND tenant_id = $2"#
        )
        .bind(service_account_id)
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(|e| M2mError::Database(e.to_string()))?;

        Ok(row.map(|r| r.into()))
    }

    /// Get a service account by client ID
    pub async fn get_service_account_by_client_id(
        &self,
        tenant_id: &str,
        client_id: &str,
    ) -> Result<Option<ServiceAccount>, M2mError> {
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
        .map_err(|e| M2mError::Database(e.to_string()))?;

        Ok(row.map(|r| r.into()))
    }

    /// List service accounts for a tenant
    pub async fn list_service_accounts(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> Result<(Vec<ServiceAccountSummary>, i64), M2mError> {
        let offset = (page - 1) * per_page;

        let rows: Vec<ServiceAccountRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, name, description, client_id, client_secret_hash, 
               scopes, permissions, rate_limit_rps, rate_limit_burst, expires_at, 
               last_used_at, created_at, is_active
               FROM service_accounts 
               WHERE tenant_id = $1
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3"#
        )
        .bind(tenant_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| M2mError::Database(e.to_string()))?;

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM service_accounts WHERE tenant_id = $1"
        )
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await
        .map_err(|e| M2mError::Database(e.to_string()))?;

        let summaries = rows.into_iter()
            .map(|r| ServiceAccount::from(r).into())
            .collect();

        Ok((summaries, total))
    }

    /// Update a service account
    pub async fn update_service_account(
        &self,
        tenant_id: &str,
        service_account_id: &str,
        request: UpdateServiceAccountRequest,
    ) -> Result<ServiceAccount, M2mError> {
        // Build dynamic update query
        let mut updates = Vec::new();
        let mut params: Vec<Box<dyn sqlx::Encode<'static, sqlx::Postgres> + Send>> = Vec::new();
        let mut param_idx = 1;

        if request.name.is_some() {
            updates.push(format!("name = ${}", param_idx));
            param_idx += 1;
        }
        if request.description.is_some() {
            updates.push(format!("description = ${}", param_idx));
            param_idx += 1;
        }
        if request.scopes.is_some() {
            updates.push(format!("scopes = ${}", param_idx));
            param_idx += 1;
        }
        if request.permissions.is_some() {
            updates.push(format!("permissions = ${}", param_idx));
            param_idx += 1;
        }
        if let Some(rate_limit_rps) = request.rate_limit_rps {
            updates.push(format!("rate_limit_rps = ${}", param_idx));
            param_idx += 1;
        }
        if let Some(rate_limit_burst) = request.rate_limit_burst {
            updates.push(format!("rate_limit_burst = ${}", param_idx));
            param_idx += 1;
        }
        if let Some(expires_at) = request.expires_at {
            updates.push(format!("expires_at = ${}", param_idx));
            param_idx += 1;
        }
        if let Some(is_active) = request.is_active {
            updates.push(format!("is_active = ${}", param_idx));
            param_idx += 1;
        }

        if updates.is_empty() {
            // Nothing to update, just return current
            return self
                .get_service_account(tenant_id, service_account_id)
                .await?
                .ok_or(M2mError::ServiceAccountNotFound);
        }

        let query = format!(
            "UPDATE service_accounts SET {} WHERE id = ${} AND tenant_id = ${} RETURNING id",
            updates.join(", "),
            param_idx,
            param_idx + 1
        );

        // Execute the update
        // Note: This is simplified - in production you'd use a query builder
        // or write separate queries for each combination of fields
        
        // For now, let's use a simpler approach with separate queries
        self.update_service_account_simple(tenant_id, service_account_id, request).await
    }

    /// Simplified update using separate query construction
    async fn update_service_account_simple(
        &self,
        tenant_id: &str,
        service_account_id: &str,
        request: UpdateServiceAccountRequest,
    ) -> Result<ServiceAccount, M2mError> {
        // Get current
        let current = self
            .get_service_account(tenant_id, service_account_id)
            .await?
            .ok_or(M2mError::ServiceAccountNotFound)?;

        let name = request.name.unwrap_or(current.name);
        let description = request.description.or(current.description);
        let scopes = request.scopes.unwrap_or(current.scopes);
        let permissions = request.permissions.unwrap_or(current.permissions);
        let rate_limit_rps = request.rate_limit_rps.or_else(|| current.rate_limit.as_ref().map(|r| r.requests_per_second));
        let rate_limit_burst = request.rate_limit_burst.or_else(|| current.rate_limit.as_ref().map(|r| r.burst));
        let expires_at = request.expires_at.or(current.expires_at);
        let is_active = request.is_active.unwrap_or(current.is_active);

        sqlx::query(
            r#"UPDATE service_accounts 
               SET name = $1, description = $2, scopes = $3, permissions = $4,
                   rate_limit_rps = $5, rate_limit_burst = $6, expires_at = $7, is_active = $8
               WHERE id = $9 AND tenant_id = $10"#
        )
        .bind(&name)
        .bind(&description)
        .bind(&scopes)
        .bind(&permissions)
        .bind(rate_limit_rps.map(|v| v as i32))
        .bind(rate_limit_burst.map(|v| v as i32))
        .bind(expires_at)
        .bind(is_active)
        .bind(service_account_id)
        .bind(tenant_id)
        .execute(self.db.pool())
        .await
        .map_err(|e| M2mError::Database(e.to_string()))?;

        self.get_service_account(tenant_id, service_account_id)
            .await?
            .ok_or(M2mError::ServiceAccountNotFound)
    }

    /// Delete a service account
    pub async fn delete_service_account(
        &self,
        tenant_id: &str,
        service_account_id: &str,
    ) -> Result<(), M2mError> {
        // First revoke all API keys
        let _ = self
            .api_key_manager
            .revoke_all_keys(tenant_id, service_account_id)
            .await;

        // Delete the service account
        let result = sqlx::query(
            "DELETE FROM service_accounts WHERE id = $1 AND tenant_id = $2"
        )
        .bind(service_account_id)
        .bind(tenant_id)
        .execute(self.db.pool())
        .await
        .map_err(|e| M2mError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(M2mError::ServiceAccountNotFound);
        }

        Ok(())
    }

    /// Rotate client secret for a service account
    pub async fn rotate_client_secret(
        &self,
        tenant_id: &str,
        service_account_id: &str,
    ) -> Result<String, M2mError> {
        let new_secret = generate_client_secret();
        let new_secret_hash = vault_core::crypto::VaultPasswordHasher::hash(&new_secret)
            .map_err(|e| M2mError::Hashing(e.to_string()))?;

        let result = sqlx::query(
            "UPDATE service_accounts SET client_secret_hash = $1 WHERE id = $2 AND tenant_id = $3"
        )
        .bind(&new_secret_hash)
        .bind(service_account_id)
        .bind(tenant_id)
        .execute(self.db.pool())
        .await
        .map_err(|e| M2mError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(M2mError::ServiceAccountNotFound);
        }

        Ok(new_secret)
    }
}

/// Generate a new client ID
/// 
/// SECURITY: Uses OsRng (operating system's CSPRNG) for generating client IDs.
/// While client IDs are not secrets, using a secure RNG ensures they are
/// unpredictable and prevents enumeration attacks.
fn generate_client_id() -> String {
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    
    let prefix = "vault_sa_";
    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    let random: String = rand_core::OsRng
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect();
    format!("{}{}", prefix, random.to_lowercase())
}

/// Generate a new client secret
/// 
/// SECURITY: Uses OsRng (operating system's CSPRNG) for generating client secrets.
/// Client secrets are credentials for machine-to-machine authentication and must be
/// cryptographically secure to prevent unauthorized API access.
fn generate_client_secret() -> String {
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    
    // SECURITY: Use OsRng instead of thread_rng() for cryptographic security
    // Client secrets must be unpredictable to prevent credential stuffing attacks
    let random: String = rand_core::OsRng
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();
    random
}

/// M2M errors
#[derive(Debug, thiserror::Error)]
pub enum M2mError {
    #[error("Service account not found")]
    ServiceAccountNotFound,
    #[error("Database error: {0}")]
    Database(String),
    #[error("Hashing error: {0}")]
    Hashing(String),
    #[error("API key error: {0}")]
    ApiKey(#[from] ApiKeyError),
    #[error("Client credentials error: {0}")]
    ClientCredentials(#[from] ClientCredentialsError),
}

// Database row type
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

impl From<ServiceAccountRow> for ServiceAccount {
    fn from(row: ServiceAccountRow) -> Self {
        let rate_limit = if let (Some(rps), Some(burst)) = (row.rate_limit_rps, row.rate_limit_burst) {
            Some(RateLimitConfig {
                requests_per_second: rps as u32,
                burst: burst as u32,
            })
        } else {
            None
        };

        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            description: row.description,
            client_id: row.client_id,
            client_secret_hash: row.client_secret_hash,
            scopes: row.scopes,
            permissions: row.permissions,
            rate_limit,
            expires_at: row.expires_at,
            last_used_at: row.last_used_at,
            created_at: row.created_at,
            is_active: row.is_active,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_client_id() {
        let client_id = generate_client_id();
        assert!(client_id.starts_with("vault_sa_"));
        assert_eq!(client_id.len(), 9 + 24); // prefix + random
    }

    #[test]
    fn test_generate_client_secret() {
        let secret = generate_client_secret();
        assert_eq!(secret.len(), 64);
    }
}
