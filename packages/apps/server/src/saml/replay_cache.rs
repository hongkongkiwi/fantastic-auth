//! SAML Replay Attack Prevention Cache
//!
//! This module provides a replay cache for SAML assertions to prevent replay attacks.
//! It supports two backends:
//! - Redis: When Redis is configured, uses Redis with TTL for distributed deployments
//! - In-Memory: Bounded LRU cache for single-node deployments or when Redis is unavailable

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use super::{SamlError, SamlResult};

/// Default TTL for replay cache entries (5 minutes)
const DEFAULT_TTL_SECONDS: u64 = 300;
/// Default maximum size for in-memory cache (10,000 entries)
const DEFAULT_MAX_MEMORY_ENTRIES: usize = 10000;
/// Redis key prefix for replay cache
const REDIS_KEY_PREFIX: &str = "saml:replay:";

/// Replay cache trait
#[async_trait::async_trait]
pub trait ReplayCache: Send + Sync {
    /// Check if an ID has been seen (replay detection)
    async fn contains(&self, id: &str) -> SamlResult<bool>;
    
    /// Add an ID to the cache
    async fn add(&self, id: &str) -> SamlResult<()>;

    /// Atomically check whether an ID exists and add it if missing.
    ///
    /// Returns `true` when the ID was already present (replay detected),
    /// and `false` when it was newly added.
    async fn check_and_add(&self, id: &str) -> SamlResult<bool>;
    
    /// Get cache statistics (for monitoring)
    async fn stats(&self) -> CacheStats;
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total entries in cache
    pub entries: usize,
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Evictions (for in-memory cache)
    pub evictions: u64,
    /// Backend type
    pub backend: String,
}

/// Redis-backed replay cache
pub struct RedisReplayCache {
    redis: redis::aio::ConnectionManager,
    ttl_seconds: u64,
    key_prefix: String,
}

impl RedisReplayCache {
    /// Create a new Redis replay cache
    pub fn new(redis: redis::aio::ConnectionManager) -> Self {
        Self {
            redis,
            ttl_seconds: DEFAULT_TTL_SECONDS,
            key_prefix: REDIS_KEY_PREFIX.to_string(),
        }
    }
    
    /// Create with custom TTL
    pub fn with_ttl(mut self, ttl_seconds: u64) -> Self {
        self.ttl_seconds = ttl_seconds;
        self
    }
    
    /// Create with custom key prefix
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }
    
    fn key(&self, id: &str) -> String {
        format!("{}{}", self.key_prefix, id)
    }
}

#[async_trait::async_trait]
impl ReplayCache for RedisReplayCache {
    async fn contains(&self, id: &str) -> SamlResult<bool> {
        let key = self.key(id);
        let mut conn = self.redis.clone();
        
        let exists: bool = redis::cmd("EXISTS")
            .arg(&key)
            .query_async(&mut conn)
            .await
            .map_err(|e| SamlError::InternalError(format!("Redis error: {}", e)))?;
        
        Ok(exists)
    }
    
    async fn add(&self, id: &str) -> SamlResult<()> {
        let key = self.key(id);
        let mut conn = self.redis.clone();
        
        redis::cmd("SETEX")
            .arg(&key)
            .arg(self.ttl_seconds)
            .arg("1")
            .query_async::<_, ()>(&mut conn)
            .await
            .map_err(|e| SamlError::InternalError(format!("Redis error: {}", e)))?;
        
        debug!(id = %id, "Added SAML assertion to Redis replay cache");
        Ok(())
    }

    async fn check_and_add(&self, id: &str) -> SamlResult<bool> {
        let key = self.key(id);
        let mut conn = self.redis.clone();

        // Atomic insert with NX to prevent race conditions between concurrent checks.
        let set_result: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("EX")
            .arg(self.ttl_seconds)
            .arg("NX")
            .query_async(&mut conn)
            .await
            .map_err(|e| SamlError::InternalError(format!("Redis error: {}", e)))?;

        Ok(set_result.is_none())
    }
    
    async fn stats(&self) -> CacheStats {
        // For Redis, we can't easily get per-key stats without scanning
        CacheStats {
            backend: "redis".to_string(),
            ..Default::default()
        }
    }
}

/// In-memory cache entry with expiration
struct MemoryCacheEntry {
    /// When this entry was added
    added_at: Instant,
    /// Time-to-live
    ttl: Duration,
}

impl MemoryCacheEntry {
    fn is_expired(&self) -> bool {
        Instant::now().duration_since(self.added_at) > self.ttl
    }
}

/// Bounded in-memory replay cache with LRU eviction
pub struct InMemoryReplayCache {
    /// The cache storage
    cache: Arc<RwLock<HashMap<String, MemoryCacheEntry>>>,
    /// Maximum number of entries
    max_entries: usize,
    /// Time-to-live for entries
    ttl: Duration,
    /// Statistics
    stats: Arc<RwLock<CacheStats>>,
}

impl InMemoryReplayCache {
    /// Create a new in-memory replay cache with default size
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_MEMORY_ENTRIES)
    }
    
    /// Create with custom capacity
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::with_capacity(max_entries))),
            max_entries,
            ttl: Duration::from_secs(DEFAULT_TTL_SECONDS),
            stats: Arc::new(RwLock::new(CacheStats {
                backend: "memory".to_string(),
                ..Default::default()
            })),
        }
    }
    
    /// Create with custom TTL
    pub fn with_ttl(mut self, ttl_seconds: u64) -> Self {
        self.ttl = Duration::from_secs(ttl_seconds);
        self
    }
    
    /// Clean up expired entries (call periodically)
    pub async fn cleanup_expired(&self) {
        let mut cache = self.cache.write().await;
        let before = cache.len();
        cache.retain(|_, entry| !entry.is_expired());
        let after = cache.len();
        
        if before > after {
            let evicted = (before - after) as u64;
            let mut stats = self.stats.write().await;
            stats.evictions += evicted;
            debug!(evicted = evicted, remaining = after, "Cleaned up expired replay cache entries");
        }
    }
    
    /// Evict oldest entries when cache is full (simple FIFO)
    async fn evict_if_needed(&self) {
        let cache = self.cache.read().await;
        if cache.len() < self.max_entries {
            return;
        }
        drop(cache);
        
        // Need to evict - remove oldest entries
        let mut cache = self.cache.write().await;
        let to_evict = cache.len() - self.max_entries + 1; // +1 to make room for new entry
        
        // Collect keys to remove (oldest first)
        let mut entries: Vec<_> = cache.iter()
            .map(|(k, v)| (k.clone(), v.added_at))
            .collect();
        entries.sort_by(|a, b| a.1.cmp(&b.1));
        
        for (key, _) in entries.into_iter().take(to_evict) {
            cache.remove(&key);
        }
        
        let mut stats = self.stats.write().await;
        stats.evictions += to_evict as u64;
        
        warn!(
            evicted = to_evict,
            max_entries = self.max_entries,
            "Replay cache full, evicted oldest entries"
        );
    }
}

impl Default for InMemoryReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ReplayCache for InMemoryReplayCache {
    async fn contains(&self, id: &str) -> SamlResult<bool> {
        // Clean up expired entries periodically (1% chance)
        if rand::random::<f32>() < 0.01 {
            self.cleanup_expired().await;
        }
        
        // SECURITY: Check cache without holding lock, then update stats separately
        // to avoid potential deadlock from inconsistent lock ordering.
        let is_replay = {
            let cache = self.cache.read().await;
            cache.get(id).map(|e| !e.is_expired()).unwrap_or(false)
        };
        
        if is_replay {
            let mut stats = self.stats.write().await;
            stats.hits += 1;
            Ok(true)
        } else {
            let mut stats = self.stats.write().await;
            stats.misses += 1;
            Ok(false)
        }
    }
    
    async fn add(&self, id: &str) -> SamlResult<()> {
        // Evict if needed before adding
        self.evict_if_needed().await;
        
        let mut cache = self.cache.write().await;
        cache.insert(id.to_string(), MemoryCacheEntry {
            added_at: Instant::now(),
            ttl: self.ttl,
        });
        
        debug!(
            id = %id,
            size = cache.len(),
            max = self.max_entries,
            "Added SAML assertion to in-memory replay cache"
        );
        
        Ok(())
    }

    async fn check_and_add(&self, id: &str) -> SamlResult<bool> {
        // First check without any locks (fast path for existing entries)
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(id) {
                if !entry.is_expired() {
                    drop(cache); // Release read lock before acquiring stats lock
                    let mut stats = self.stats.write().await;
                    stats.hits += 1;
                    return Ok(true);
                }
            }
        }

        // Not found or expired - acquire write lock for modification
        let mut cache = self.cache.write().await;
        
        // Double-check after acquiring write lock
        if let Some(entry) = cache.get(id) {
            if !entry.is_expired() {
                drop(cache);
                let mut stats = self.stats.write().await;
                stats.hits += 1;
                return Ok(true);
            }
        }

        // Ensure bounded size before adding.
        let evicted = if cache.len() >= self.max_entries {
            let to_evict = cache.len() - self.max_entries + 1;
            let mut entries: Vec<_> = cache.iter().map(|(k, v)| (k.clone(), v.added_at)).collect();
            entries.sort_by(|a, b| a.1.cmp(&b.1));
            for (key, _) in entries.into_iter().take(to_evict) {
                cache.remove(&key);
            }
            to_evict
        } else {
            0
        };

        cache.insert(
            id.to_string(),
            MemoryCacheEntry {
                added_at: Instant::now(),
                ttl: self.ttl,
            },
        );
        
        // Release cache lock before updating stats to maintain consistent lock ordering
        drop(cache);
        
        let mut stats = self.stats.write().await;
        if evicted > 0 {
            stats.evictions += evicted as u64;
        }
        stats.misses += 1;
        Ok(false)
    }
    
    async fn stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let stats = self.stats.read().await;
        
        CacheStats {
            entries: cache.len(),
            hits: stats.hits,
            misses: stats.misses,
            evictions: stats.evictions,
            backend: "memory".to_string(),
        }
    }
}

/// Create a replay cache based on available resources
/// 
/// Uses Redis if available, otherwise falls back to bounded in-memory cache
pub fn create_replay_cache(
    redis: Option<redis::aio::ConnectionManager>,
) -> Arc<dyn ReplayCache> {
    match redis {
        Some(redis_conn) => {
            tracing::info!("Using Redis for SAML replay cache");
            Arc::new(RedisReplayCache::new(redis_conn))
        }
        None => {
            tracing::info!(
                max_entries = DEFAULT_MAX_MEMORY_ENTRIES,
                "Using in-memory LRU cache for SAML replay prevention"
            );
            Arc::new(InMemoryReplayCache::new())
        }
    }
}

/// Create replay cache with custom configuration
pub fn create_replay_cache_with_config(
    redis: Option<redis::aio::ConnectionManager>,
    memory_capacity: usize,
    ttl_seconds: u64,
) -> Arc<dyn ReplayCache> {
    match redis {
        Some(redis_conn) => {
            tracing::info!("Using Redis for SAML replay cache");
            Arc::new(
                RedisReplayCache::new(redis_conn)
                    .with_ttl(ttl_seconds)
            )
        }
        None => {
            tracing::info!(
                max_entries = memory_capacity,
                "Using in-memory LRU cache for SAML replay prevention"
            );
            Arc::new(
                InMemoryReplayCache::with_capacity(memory_capacity)
                    .with_ttl(ttl_seconds)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_in_memory_replay_cache() {
        let cache = InMemoryReplayCache::with_capacity(100);
        
        // Check that ID is not in cache
        assert!(!cache.contains("test-id-1").await.unwrap());
        
        // Add ID to cache
        cache.add("test-id-1").await.unwrap();
        
        // Now it should be found
        assert!(cache.contains("test-id-1").await.unwrap());
        
        // Different ID should not be found
        assert!(!cache.contains("test-id-2").await.unwrap());
        
        // Stats should show 2 misses and 1 hit
        let stats = cache.stats().await;
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 2);
        assert_eq!(stats.entries, 1);
    }
    
    #[tokio::test]
    async fn test_in_memory_eviction() {
        let cache = InMemoryReplayCache::with_capacity(5);
        
        // Add 5 entries
        for i in 0..5 {
            cache.add(&format!("id-{}", i)).await.unwrap();
        }
        
        let stats = cache.stats().await;
        assert_eq!(stats.entries, 5);
        
        // Add one more - should evict the oldest
        cache.add("id-5").await.unwrap();
        
        let stats = cache.stats().await;
        assert_eq!(stats.entries, 5); // Still 5
        assert_eq!(stats.evictions, 1);
        
        // First entry should be evicted
        assert!(!cache.contains("id-0").await.unwrap());
        // Last entry should be present
        assert!(cache.contains("id-5").await.unwrap());
    }
}
