//! Token storage backends for authentication tokens
//!
//! Supports:
//! - In-memory storage (for development/testing)
//! - Redis storage (for production)

use crate::error::{Result, VaultError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Token types stored in the token store
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredTokenType {
    /// Email verification token
    EmailVerification,
    /// Password reset token
    PasswordReset,
    /// Magic link token
    MagicLink,
    /// MFA OTP code
    MfaCode,
    /// Refresh token metadata
    RefreshToken,
}

/// Token data stored in the token store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTokenData {
    /// User ID associated with this token
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Token type
    pub token_type: StoredTokenType,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Additional metadata (method for MFA, etc.)
    pub metadata: Option<serde_json::Value>,
}

/// Token store trait for different backends
#[async_trait]
pub trait TokenStore: Send + Sync {
    /// Store a token with its data
    async fn store(&self, token: &str, data: StoredTokenData) -> Result<()>;

    /// Get token data and optionally remove it (for one-time use tokens)
    async fn get(&self, token: &str) -> Result<Option<StoredTokenData>>;

    /// Remove a token
    async fn remove(&self, token: &str) -> Result<()>;

    /// Check if a token exists
    async fn exists(&self, token: &str) -> Result<bool>;

    /// Clean up expired tokens
    async fn cleanup_expired(&self) -> Result<u64>;
}

/// In-memory token store implementation
pub struct InMemoryTokenStore {
    store: Arc<RwLock<HashMap<String, StoredTokenData>>>,
}

impl InMemoryTokenStore {
    /// Create a new in-memory token store
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TokenStore for InMemoryTokenStore {
    async fn store(&self, token: &str, data: StoredTokenData) -> Result<()> {
        let mut store = self.store.write().await;
        store.insert(token.to_string(), data);
        Ok(())
    }

    async fn get(&self, token: &str) -> Result<Option<StoredTokenData>> {
        let store = self.store.read().await;
        Ok(store.get(token).cloned())
    }

    async fn remove(&self, token: &str) -> Result<()> {
        let mut store = self.store.write().await;
        store.remove(token);
        Ok(())
    }

    async fn exists(&self, token: &str) -> Result<bool> {
        let store = self.store.read().await;
        Ok(store.contains_key(token))
    }

    async fn cleanup_expired(&self) -> Result<u64> {
        let mut store = self.store.write().await;
        let now = Utc::now();
        let before_len = store.len();
        store.retain(|_, data| data.expires_at > now);
        let removed = before_len - store.len();
        Ok(removed as u64)
    }
}

/// Redis token store implementation
pub struct RedisTokenStore {
    client: redis::aio::ConnectionManager,
    key_prefix: String,
}

impl RedisTokenStore {
    /// Create a new Redis token store
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| VaultError::Config(format!("Invalid Redis URL: {}", e)))?;
        let conn = redis::aio::ConnectionManager::new(client)
            .await
            .map_err(|e| VaultError::ExternalService {
                service: "redis".to_string(),
                message: format!("Failed to connect: {}", e),
            })?;

        Ok(Self {
            client: conn,
            key_prefix: "vault:token:".to_string(),
        })
    }

    /// Create with custom key prefix
    pub async fn with_prefix(redis_url: &str, prefix: impl Into<String>) -> Result<Self> {
        let mut store = Self::new(redis_url).await?;
        store.key_prefix = prefix.into();
        Ok(store)
    }

    fn make_key(&self, token: &str) -> String {
        format!("{}{}", self.key_prefix, token)
    }
}

#[async_trait]
impl TokenStore for RedisTokenStore {
    async fn store(&self, token: &str, data: StoredTokenData) -> Result<()> {
        let key = self.make_key(token);
        let value = serde_json::to_string(&data).map_err(|e| VaultError::Serialization(e))?;

        let ttl = (data.expires_at - Utc::now()).num_seconds();
        if ttl <= 0 {
            return Ok(()); // Already expired, don't store
        }

        let mut conn = self.client.clone();
        redis::cmd("SETEX")
            .arg(&key)
            .arg(ttl as u64)
            .arg(&value)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| VaultError::ExternalService {
                service: "redis".to_string(),
                message: format!("Failed to store token: {}", e),
            })?;

        Ok(())
    }

    async fn get(&self, token: &str) -> Result<Option<StoredTokenData>> {
        let key = self.make_key(token);
        let mut conn = self.client.clone();

        let value: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| VaultError::ExternalService {
                service: "redis".to_string(),
                message: format!("Failed to get token: {}", e),
            })?;

        match value {
            Some(v) => {
                let data: StoredTokenData =
                    serde_json::from_str(&v).map_err(|e| VaultError::Serialization(e))?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    async fn remove(&self, token: &str) -> Result<()> {
        let key = self.make_key(token);
        let mut conn = self.client.clone();

        redis::cmd("DEL")
            .arg(&key)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| VaultError::ExternalService {
                service: "redis".to_string(),
                message: format!("Failed to remove token: {}", e),
            })?;

        Ok(())
    }

    async fn exists(&self, token: &str) -> Result<bool> {
        let key = self.make_key(token);
        let mut conn = self.client.clone();

        let exists: bool = redis::cmd("EXISTS")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| VaultError::ExternalService {
                service: "redis".to_string(),
                message: format!("Failed to check token: {}", e),
            })?;

        Ok(exists)
    }

    async fn cleanup_expired(&self) -> Result<u64> {
        // Redis handles expiration automatically via TTL
        // This method is a no-op for Redis
        Ok(0)
    }
}

/// Token store that tries Redis first, falls back to in-memory
pub struct FallbackTokenStore {
    primary: Option<RedisTokenStore>,
    fallback: InMemoryTokenStore,
}

impl FallbackTokenStore {
    /// Create a new fallback token store
    pub async fn new(redis_url: Option<&str>) -> Result<Self> {
        let primary = match redis_url {
            Some(url) => match RedisTokenStore::new(url).await {
                Ok(store) => {
                    tracing::info!("Using Redis for token storage");
                    Some(store)
                }
                Err(e) => {
                    tracing::warn!("Failed to connect to Redis, using in-memory storage: {}", e);
                    None
                }
            },
            None => {
                tracing::info!("No Redis URL provided, using in-memory storage");
                None
            }
        };

        Ok(Self {
            primary,
            fallback: InMemoryTokenStore::new(),
        })
    }

    fn get_store(&self) -> &(dyn TokenStore) {
        match &self.primary {
            Some(store) => store,
            None => &self.fallback,
        }
    }
}

#[async_trait]
impl TokenStore for FallbackTokenStore {
    async fn store(&self, token: &str, data: StoredTokenData) -> Result<()> {
        self.get_store().store(token, data).await
    }

    async fn get(&self, token: &str) -> Result<Option<StoredTokenData>> {
        self.get_store().get(token).await
    }

    async fn remove(&self, token: &str) -> Result<()> {
        self.get_store().remove(token).await
    }

    async fn exists(&self, token: &str) -> Result<bool> {
        self.get_store().exists(token).await
    }

    async fn cleanup_expired(&self) -> Result<u64> {
        self.get_store().cleanup_expired().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_in_memory_token_store() {
        let store = InMemoryTokenStore::new();

        let data = StoredTokenData {
            user_id: "user_123".to_string(),
            tenant_id: "tenant_456".to_string(),
            token_type: StoredTokenType::EmailVerification,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            metadata: None,
        };

        // Store token
        store.store("test_token", data.clone()).await.unwrap();

        // Check exists
        assert!(store.exists("test_token").await.unwrap());

        // Get token
        let retrieved = store.get("test_token").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user_123");

        // Remove token
        store.remove("test_token").await.unwrap();
        assert!(!store.exists("test_token").await.unwrap());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let store = InMemoryTokenStore::new();

        // Store expired token
        let expired_data = StoredTokenData {
            user_id: "user_123".to_string(),
            tenant_id: "tenant_456".to_string(),
            token_type: StoredTokenType::EmailVerification,
            expires_at: Utc::now() - chrono::Duration::hours(1),
            metadata: None,
        };

        store.store("expired_token", expired_data).await.unwrap();

        // Cleanup should remove it
        let removed = store.cleanup_expired().await.unwrap();
        assert_eq!(removed, 1);
        assert!(!store.exists("expired_token").await.unwrap());
    }
}
