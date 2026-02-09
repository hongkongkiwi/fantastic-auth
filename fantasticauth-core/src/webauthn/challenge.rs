//! Challenge store for WebAuthn
//!
//! Manages temporary challenges during registration and authentication.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Challenge data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChallengeData {
    /// User ID this challenge is for
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Challenge string
    pub challenge: String,
    /// Expiration timestamp
    pub expires_at: DateTime<Utc>,
}

/// Challenge store errors
#[derive(Debug, thiserror::Error)]
pub enum ChallengeStoreError {
    #[error("Challenge not found")]
    NotFound,
    #[error("Challenge expired")]
    Expired,
    #[error("Storage error: {0}")]
    Storage(String),
}

/// Challenge store trait
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    /// Store a new challenge
    async fn store_challenge(
        &self,
        challenge: &str,
        user_id: &str,
        tenant_id: &str,
        ttl_seconds: u64,
    ) -> Result<(), ChallengeStoreError>;

    /// Consume (retrieve and delete) a challenge
    async fn consume_challenge(
        &self,
        challenge: &str,
    ) -> Result<ChallengeData, ChallengeStoreError>;

    /// Get challenge without consuming
    async fn get_challenge(&self, challenge: &str) -> Result<ChallengeData, ChallengeStoreError>;

    /// Clean up expired challenges
    async fn cleanup(&self) -> Result<u64, ChallengeStoreError>;
}

/// In-memory challenge store (for development/single instance)
pub struct MemoryChallengeStore {
    challenges: RwLock<HashMap<String, ChallengeData>>,
}

impl MemoryChallengeStore {
    /// Create new memory store
    pub fn new() -> Self {
        Self {
            challenges: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ChallengeStore for MemoryChallengeStore {
    async fn store_challenge(
        &self,
        challenge: &str,
        user_id: &str,
        tenant_id: &str,
        ttl_seconds: u64,
    ) -> Result<(), ChallengeStoreError> {
        let data = ChallengeData {
            user_id: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            challenge: challenge.to_string(),
            expires_at: Utc::now() + Duration::seconds(ttl_seconds as i64),
        };

        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge.to_string(), data);

        Ok(())
    }

    async fn consume_challenge(
        &self,
        challenge: &str,
    ) -> Result<ChallengeData, ChallengeStoreError> {
        let mut challenges = self.challenges.write().await;

        let data = challenges
            .remove(challenge)
            .ok_or(ChallengeStoreError::NotFound)?;

        if Utc::now() > data.expires_at {
            return Err(ChallengeStoreError::Expired);
        }

        Ok(data)
    }

    async fn get_challenge(&self, challenge: &str) -> Result<ChallengeData, ChallengeStoreError> {
        let challenges = self.challenges.read().await;

        let data = challenges
            .get(challenge)
            .cloned()
            .ok_or(ChallengeStoreError::NotFound)?;

        if Utc::now() > data.expires_at {
            return Err(ChallengeStoreError::Expired);
        }

        Ok(data)
    }

    async fn cleanup(&self) -> Result<u64, ChallengeStoreError> {
        let mut challenges = self.challenges.write().await;
        let now = Utc::now();

        let before = challenges.len();
        challenges.retain(|_, data| data.expires_at > now);
        let after = challenges.len();

        Ok((before - after) as u64)
    }
}

/// Redis-backed challenge store (for distributed deployments)
pub struct RedisChallengeStore {
    redis: redis::aio::ConnectionManager,
    key_prefix: String,
}

impl RedisChallengeStore {
    /// Create new Redis challenge store
    pub fn new(redis: redis::aio::ConnectionManager) -> Self {
        Self {
            redis,
            key_prefix: "webauthn:challenge:".to_string(),
        }
    }

    /// With custom key prefix
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    fn key(&self, challenge: &str) -> String {
        format!("{}{}", self.key_prefix, challenge)
    }
}

#[async_trait]
impl ChallengeStore for RedisChallengeStore {
    async fn store_challenge(
        &self,
        challenge: &str,
        user_id: &str,
        tenant_id: &str,
        ttl_seconds: u64,
    ) -> Result<(), ChallengeStoreError> {
        let data = ChallengeData {
            user_id: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            challenge: challenge.to_string(),
            expires_at: Utc::now() + Duration::seconds(ttl_seconds as i64),
        };

        let value = serde_json::to_string(&data)
            .map_err(|e| ChallengeStoreError::Storage(e.to_string()))?;

        let mut conn = self.redis.clone();
        redis::cmd("SETEX")
            .arg(self.key(challenge))
            .arg(ttl_seconds as usize)
            .arg(value)
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| ChallengeStoreError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn consume_challenge(
        &self,
        challenge: &str,
    ) -> Result<ChallengeData, ChallengeStoreError> {
        let key = self.key(challenge);
        let mut conn = self.redis.clone();

        // Get and delete atomically
        let value: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| ChallengeStoreError::Storage(e.to_string()))?;

        let value = value.ok_or(ChallengeStoreError::NotFound)?;

        // Delete
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| ChallengeStoreError::Storage(e.to_string()))?;

        let data: ChallengeData = serde_json::from_str(&value)
            .map_err(|e| ChallengeStoreError::Storage(e.to_string()))?;

        if Utc::now() > data.expires_at {
            return Err(ChallengeStoreError::Expired);
        }

        Ok(data)
    }

    async fn get_challenge(&self, challenge: &str) -> Result<ChallengeData, ChallengeStoreError> {
        let mut conn = self.redis.clone();

        let value: Option<String> = redis::cmd("GET")
            .arg(self.key(challenge))
            .query_async(&mut conn)
            .await
            .map_err(|e| ChallengeStoreError::Storage(e.to_string()))?;

        let value = value.ok_or(ChallengeStoreError::NotFound)?;

        let data: ChallengeData = serde_json::from_str(&value)
            .map_err(|e| ChallengeStoreError::Storage(e.to_string()))?;

        if Utc::now() > data.expires_at {
            return Err(ChallengeStoreError::Expired);
        }

        Ok(data)
    }

    async fn cleanup(&self) -> Result<u64, ChallengeStoreError> {
        // Redis handles expiration automatically
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_challenge_store() {
        let store = MemoryChallengeStore::new();

        // Store challenge
        store
            .store_challenge("challenge123", "user456", "tenant789", 60)
            .await
            .unwrap();

        // Get challenge
        let data = store.get_challenge("challenge123").await.unwrap();
        assert_eq!(data.user_id, "user456");
        assert_eq!(data.tenant_id, "tenant789");

        // Consume challenge
        let data = store.consume_challenge("challenge123").await.unwrap();
        assert_eq!(data.user_id, "user456");

        // Should be gone
        assert!(store.get_challenge("challenge123").await.is_err());

        // Not found
        assert!(store.consume_challenge("nonexistent").await.is_err());
    }

    #[tokio::test]
    async fn test_expired_challenge() {
        let store = MemoryChallengeStore::new();

        // Store with very short TTL
        store
            .store_challenge("expiring", "user", "tenant", 0)
            .await
            .unwrap();

        // Wait a bit
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Should be expired
        assert!(store.consume_challenge("expiring").await.is_err());
    }

    #[tokio::test]
    async fn test_cleanup() {
        let store = MemoryChallengeStore::new();

        // Store challenges
        store
            .store_challenge("active", "user", "tenant", 3600)
            .await
            .unwrap();
        store
            .store_challenge("expired", "user", "tenant", 0)
            .await
            .unwrap();

        // Wait for expiration
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Cleanup
        let cleaned = store.cleanup().await.unwrap();
        assert_eq!(cleaned, 1);

        // Active should still exist
        assert!(store.get_challenge("active").await.is_ok());
    }
}
