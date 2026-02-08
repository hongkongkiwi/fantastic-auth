//! API Key Management
//!
//! Provides functionality for:
//! - API key generation (format: `vault_m2m_<tenant_prefix>_<random>`)
//! - Key hashing using Argon2 (like passwords)
//! - Key rotation
//! - Key revocation
//! - Scope restriction per key

use chrono::{DateTime, Duration, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use validator::Validate;

/// API key entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique identifier (UUID)
    pub id: String,
    /// Service account this key belongs to
    pub service_account_id: String,
    /// Tenant ID for RLS
    pub tenant_id: String,
    /// Argon2 hash of the key
    pub key_hash: String,
    /// Human-readable name for this key
    pub name: Option<String>,
    /// Scopes restricted to this key (overrides service account scopes)
    pub scopes: Option<Vec<String>>,
    /// When the key expires
    pub expires_at: Option<DateTime<Utc>>,
    /// Last time this key was used
    pub last_used_at: Option<DateTime<Utc>>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Whether the key is active
    pub is_active: bool,
}

/// API key summary (for list responses)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeySummary {
    pub id: String,
    pub service_account_id: String,
    pub name: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

impl From<ApiKey> for ApiKeySummary {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id,
            service_account_id: key.service_account_id,
            name: key.name,
            scopes: key.scopes,
            expires_at: key.expires_at,
            last_used_at: key.last_used_at,
            created_at: key.created_at,
            is_active: key.is_active,
        }
    }
}

/// Response with the actual API key (only shown once on creation)
#[derive(Debug, Serialize)]
pub struct ApiKeyWithSecret {
    pub id: String,
    pub service_account_id: String,
    /// The actual API key - ONLY SHOWN ONCE
    pub key: String,
    pub name: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Request to create a new API key
#[derive(Debug, Deserialize, Validate)]
pub struct CreateApiKeyRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    /// Optional scope override for this key
    pub scopes: Option<Vec<String>>,
    /// Expiration in days (None = no expiration)
    pub expires_in_days: Option<i64>,
}

/// Request to update an API key
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateApiKeyRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    pub is_active: Option<bool>,
}

/// Prefix for all M2M API keys
pub const API_KEY_PREFIX: &str = "vault_m2m_";

/// Length of the random part of the API key
pub const API_KEY_RANDOM_LENGTH: usize = 32;

/// Generate a new API key with the format: `vault_m2m_<tenant_prefix>_<random>`
///
/// Example: `vault_m2m_acme_abc123def456ghi789jkl012mno345pqr`
pub fn generate_api_key(tenant_id: &str) -> String {
    // Use first 8 chars of tenant_id as prefix (or full if shorter)
    let tenant_prefix = if tenant_id.len() > 8 {
        &tenant_id[..8]
    } else {
        tenant_id
    };

    // Generate random alphanumeric string
    let random: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(API_KEY_RANDOM_LENGTH)
        .map(char::from)
        .collect();

    format!("{}{}_{}", API_KEY_PREFIX, tenant_prefix, random)
}

/// Hash an API key using Argon2 (same as password hashing)
pub async fn hash_api_key(key: &str) -> Result<String, anyhow::Error> {
    vault_core::crypto::VaultPasswordHasher::hash(key)
        .map_err(|e| anyhow::anyhow!("Failed to hash API key: {}", e))
}

/// Verify an API key against its hash
pub async fn verify_api_key(key: &str, hash: &str) -> Result<bool, anyhow::Error> {
    vault_core::crypto::VaultPasswordHasher::verify(key, hash)
        .map_err(|e| anyhow::anyhow!("Failed to verify API key: {}", e))
}

/// API Key Manager for database operations
#[derive(Clone)]
pub struct ApiKeyManager {
    db: crate::db::Database,
}

impl ApiKeyManager {
    /// Create a new API key manager
    pub fn new(db: crate::db::Database) -> Self {
        Self { db }
    }

    /// Create a new API key for a service account
    pub async fn create_key(
        &self,
        tenant_id: &str,
        service_account_id: &str,
        request: CreateApiKeyRequest,
    ) -> Result<ApiKeyWithSecret, ApiKeyError> {
        // Validate service account exists
        let sa_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM service_accounts WHERE id = $1 AND tenant_id = $2)"
        )
        .bind(service_account_id)
        .bind(tenant_id)
        .fetch_one(self.db.pool())
        .await
        .map_err(|e| ApiKeyError::Database(e.to_string()))?;

        if !sa_exists {
            return Err(ApiKeyError::ServiceAccountNotFound);
        }

        // Generate new API key
        let key = generate_api_key(tenant_id);
        let key_hash = hash_api_key(&key)
            .await
            .map_err(|e| ApiKeyError::Hashing(e.to_string()))?;

        // Calculate expiration
        let expires_at = request.expires_in_days.map(|days| Utc::now() + Duration::days(days));

        // Insert into database
        let key_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let scopes_json = request.scopes.as_ref().map(|s| serde_json::json!(s));

        sqlx::query(
            r#"INSERT INTO api_keys 
               (id, tenant_id, service_account_id, key_hash, name, scopes, expires_at, created_at, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true)"#
        )
        .bind(&key_id)
        .bind(tenant_id)
        .bind(service_account_id)
        .bind(&key_hash)
        .bind(&request.name)
        .bind(scopes_json)
        .bind(expires_at)
        .bind(now)
        .execute(self.db.pool())
        .await
        .map_err(|e| ApiKeyError::Database(e.to_string()))?;

        Ok(ApiKeyWithSecret {
            id: key_id,
            service_account_id: service_account_id.to_string(),
            key, // Return the unhashed key - this is the only time it's visible
            name: request.name,
            scopes: request.scopes,
            expires_at,
            created_at: now,
        })
    }

    /// Validate an API key and return the associated service account info
    pub async fn validate_key(
        &self,
        tenant_id: &str,
        key: &str,
    ) -> Result<ValidatedKeyInfo, ApiKeyError> {
        // Check key format
        if !key.starts_with(API_KEY_PREFIX) {
            return Err(ApiKeyError::InvalidKey);
        }

        // Find all active keys for this tenant
        // Note: We can't query by hash directly, so we need to check each
        // In practice, you'd want to cache validated keys or use a different lookup strategy
        let keys: Vec<ApiKey> = sqlx::query_as::<_, ApiKeyRow>(
            r#"SELECT id, service_account_id, tenant_id, key_hash, name, scopes, 
               expires_at, last_used_at, created_at, is_active
               FROM api_keys 
               WHERE tenant_id = $1 AND is_active = true"#
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| ApiKeyError::Database(e.to_string()))?
        .into_iter()
        .map(|row| row.into())
        .collect();

        for api_key in keys {
            // Skip expired keys
            if let Some(expires) = api_key.expires_at {
                if Utc::now() > expires {
                    continue;
                }
            }

            // Verify key hash
            if verify_api_key(key, &api_key.key_hash).await.unwrap_or(false) {
                // Update last_used_at
                let _ = sqlx::query(
                    "UPDATE api_keys SET last_used_at = NOW() WHERE id = $1"
                )
                .bind(&api_key.id)
                .execute(self.db.pool())
                .await;

                return Ok(ValidatedKeyInfo {
                    key_id: api_key.id,
                    service_account_id: api_key.service_account_id,
                    scopes: api_key.scopes,
                });
            }
        }

        Err(ApiKeyError::InvalidKey)
    }

    /// List all API keys for a service account
    pub async fn list_keys(
        &self,
        tenant_id: &str,
        service_account_id: &str,
    ) -> Result<Vec<ApiKeySummary>, ApiKeyError> {
        let keys: Vec<ApiKey> = sqlx::query_as::<_, ApiKeyRow>(
            r#"SELECT id, service_account_id, tenant_id, key_hash, name, scopes, 
               expires_at, last_used_at, created_at, is_active
               FROM api_keys 
               WHERE tenant_id = $1 AND service_account_id = $2
               ORDER BY created_at DESC"#
        )
        .bind(tenant_id)
        .bind(service_account_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(|e| ApiKeyError::Database(e.to_string()))?
        .into_iter()
        .map(|row| row.into())
        .collect();

        Ok(keys.into_iter().map(ApiKeySummary::from).collect())
    }

    /// Revoke (deactivate) a specific API key
    pub async fn revoke_key(
        &self,
        tenant_id: &str,
        key_id: &str,
    ) -> Result<(), ApiKeyError> {
        let result = sqlx::query(
            "UPDATE api_keys SET is_active = false WHERE id = $1 AND tenant_id = $2"
        )
        .bind(key_id)
        .bind(tenant_id)
        .execute(self.db.pool())
        .await
        .map_err(|e| ApiKeyError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(ApiKeyError::KeyNotFound);
        }

        Ok(())
    }

    /// Revoke all API keys for a service account
    pub async fn revoke_all_keys(
        &self,
        tenant_id: &str,
        service_account_id: &str,
    ) -> Result<u64, ApiKeyError> {
        let result = sqlx::query(
            "UPDATE api_keys SET is_active = false WHERE service_account_id = $1 AND tenant_id = $2"
        )
        .bind(service_account_id)
        .bind(tenant_id)
        .execute(self.db.pool())
        .await
        .map_err(|e| ApiKeyError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }
}

/// Information about a validated API key
#[derive(Debug, Clone)]
pub struct ValidatedKeyInfo {
    pub key_id: String,
    pub service_account_id: String,
    pub scopes: Option<Vec<String>>,
}

/// API key errors
#[derive(Debug, thiserror::Error)]
pub enum ApiKeyError {
    #[error("Service account not found")]
    ServiceAccountNotFound,
    #[error("API key not found")]
    KeyNotFound,
    #[error("Invalid API key")]
    InvalidKey,
    #[error("Database error: {0}")]
    Database(String),
    #[error("Hashing error: {0}")]
    Hashing(String),
}

// Database row type for API key queries
#[derive(sqlx::FromRow)]
struct ApiKeyRow {
    id: String,
    service_account_id: String,
    tenant_id: String,
    key_hash: String,
    name: Option<String>,
    scopes: Option<serde_json::Value>,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    is_active: bool,
}

impl From<ApiKeyRow> for ApiKey {
    fn from(row: ApiKeyRow) -> Self {
        let scopes = row.scopes.and_then(|s| {
            serde_json::from_value::<Vec<String>>(s).ok()
        });

        Self {
            id: row.id,
            service_account_id: row.service_account_id,
            tenant_id: row.tenant_id,
            key_hash: row.key_hash,
            name: row.name,
            scopes,
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
    fn test_generate_api_key() {
        let tenant_id = "acme_corp_12345";
        let key = generate_api_key(tenant_id);

        assert!(key.starts_with(API_KEY_PREFIX));
        assert!(key.contains("acme_cor")); // First 8 chars of tenant_id
        assert_eq!(key.len(), API_KEY_PREFIX.len() + 8 + 1 + API_KEY_RANDOM_LENGTH);
    }

    #[test]
    fn test_generate_api_key_short_tenant() {
        let tenant_id = "abc";
        let key = generate_api_key(tenant_id);

        assert!(key.starts_with("vault_m2m_abc_"));
    }
}
