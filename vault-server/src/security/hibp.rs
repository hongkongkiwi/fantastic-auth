//! Have I Been Pwned (HIBP) integration for password breach checking
//!
//! Uses the k-Anonymity model to check passwords against breach databases
//! without sending the full password hash. Only the first 5 characters of
//! the SHA-1 hash are sent to the API.
//!
//! API: GET https://api.pwnedpasswords.com/range/{first5CharsOfSHA1}
//!
//! Features:
//! - Result caching to avoid duplicate checks
//! - Rate limit compliance (1.5s between requests)
//! - Timeout handling
//! - Configurable API endpoint

use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Default HIBP API endpoint
const DEFAULT_HIBP_API_URL: &str = "https://api.pwnedpasswords.com/range";

/// Default cache TTL (24 hours)
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(86400);

/// Minimum time between API requests (1.5 seconds to respect rate limits)
const MIN_REQUEST_INTERVAL: Duration = Duration::from_millis(1500);

/// Default timeout for API requests
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// HIBP client errors
#[derive(Debug, thiserror::Error)]
pub enum HibpError {
    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Rate limited
    #[error("Rate limited by HIBP API")]
    RateLimited,

    /// API returned non-success status
    #[error("HIBP API error: status={status}, message={message}")]
    ApiError { status: u16, message: String },

    /// Timeout
    #[error("Request timeout")]
    Timeout,

    /// Invalid response format
    #[error("Invalid response format: {0}")]
    InvalidResponse(String),

    /// Hash calculation error
    #[error("Hash calculation failed: {0}")]
    HashError(String),
}

/// Cache entry for HIBP results
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Breach count (0 if not found)
    count: u64,
    /// Timestamp when cached
    timestamp: Instant,
}

/// HIBP client configuration
#[derive(Debug, Clone)]
pub struct HibpConfig {
    /// API base URL
    pub api_url: String,
    /// Request timeout
    pub timeout: Duration,
    /// Cache TTL
    pub cache_ttl: Duration,
    /// Enable caching
    pub enable_cache: bool,
    /// Minimum time between requests (rate limiting)
    pub min_request_interval: Duration,
    /// User agent for requests (required by HIBP API)
    pub user_agent: String,
}

impl Default for HibpConfig {
    fn default() -> Self {
        Self {
            api_url: DEFAULT_HIBP_API_URL.to_string(),
            timeout: DEFAULT_TIMEOUT,
            cache_ttl: DEFAULT_CACHE_TTL,
            enable_cache: true,
            min_request_interval: MIN_REQUEST_INTERVAL,
            user_agent: format!(
                "Vault-Auth-Service/{} (Security Checking)",
                vault_core::VERSION
            ),
        }
    }
}

/// HIBP API client with caching and rate limiting
pub struct HibpClient {
    config: HibpConfig,
    /// In-memory cache of checked hashes
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Last request timestamp for rate limiting
    last_request: Arc<RwLock<Option<Instant>>>,
    /// HTTP client
    http_client: reqwest::Client,
}

impl HibpClient {
    /// Create a new HIBP client with default configuration
    pub fn new() -> Self {
        Self::with_config(HibpConfig::default())
    }

    /// Create a new HIBP client with custom configuration
    pub fn with_config(config: HibpConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("Failed to build HTTP client");

        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            last_request: Arc::new(RwLock::new(None)),
            http_client,
        }
    }

    /// Check if a password has been breached
    ///
    /// Returns `Ok(Some(count))` if breached (count is the number of times seen)
    /// Returns `Ok(None)` if not found in breach database
    pub async fn check_password(&self, password: &str) -> Result<Option<u64>, HibpError> {
        // Calculate SHA-1 hash of the password
        let hash = self.calculate_sha1(password)?;

        // Split into prefix (5 chars) and suffix
        let prefix = &hash[..5];
        let suffix = hash[5..].to_uppercase();

        // Check cache first
        if self.config.enable_cache {
            if let Some(count) = self.check_cache(&hash).await {
                tracing::debug!("HIBP cache hit for hash prefix: {}", prefix);
                return Ok(if count > 0 { Some(count) } else { None });
            }
        }

        // Respect rate limits
        self.rate_limit().await;

        // Make API request
        let url = format!("{}/{}", self.config.api_url, prefix);

        tracing::debug!("Checking HIBP for password hash prefix: {}", prefix);

        let response = self
            .http_client
            .get(&url)
            .header("User-Agent", &self.config.user_agent)
            .header("Add-Padding", "true") // Enable response padding for privacy
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    HibpError::Timeout
                } else {
                    HibpError::Network(e.to_string())
                }
            })?;

        // Update last request timestamp
        *self.last_request.write().await = Some(Instant::now());

        // Handle rate limiting
        if response.status().as_u16() == 429 {
            return Err(HibpError::RateLimited);
        }

        // Handle other errors
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(HibpError::ApiError { status, message });
        }

        // Parse response
        let text = response
            .text()
            .await
            .map_err(|e| HibpError::InvalidResponse(e.to_string()))?;

        let count = self.parse_response(&text, &suffix)?;

        // Cache result
        if self.config.enable_cache {
            self.cache_result(&hash, count).await;
        }

        Ok(if count > 0 { Some(count) } else { None })
    }

    /// Check multiple passwords in batch
    ///
    /// Note: This still makes individual API requests due to the k-anonymity model,
    /// but can parallelize them while respecting rate limits.
    pub async fn check_passwords(
        &self,
        passwords: &[String],
    ) -> Vec<(String, Result<Option<u64>, HibpError>)> {
        let mut results = Vec::with_capacity(passwords.len());

        for password in passwords {
            let result = self.check_password(password).await;
            results.push((password.clone(), result));
        }

        results
    }

    /// Calculate SHA-1 hash of password
    fn calculate_sha1(&self, password: &str) -> Result<String, HibpError> {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        Ok(hex::encode(result).to_uppercase())
    }

    /// Check if result is cached
    async fn check_cache(&self, hash: &str) -> Option<u64> {
        let cache = self.cache.read().await;

        if let Some(entry) = cache.get(hash) {
            // Check if entry is still valid
            if entry.timestamp.elapsed() < self.config.cache_ttl {
                return Some(entry.count);
            }
        }

        None
    }

    /// Cache a result
    async fn cache_result(&self, hash: &str, count: u64) {
        let mut cache = self.cache.write().await;
        cache.insert(
            hash.to_string(),
            CacheEntry {
                count,
                timestamp: Instant::now(),
            },
        );
    }

    /// Respect rate limits by sleeping if needed
    async fn rate_limit(&self) {
        let last = *self.last_request.read().await;

        if let Some(instant) = last {
            let elapsed = instant.elapsed();
            if elapsed < self.config.min_request_interval {
                let sleep_duration = self.config.min_request_interval - elapsed;
                tracing::debug!(
                    "Rate limiting HIBP request, sleeping for {:?}",
                    sleep_duration
                );
                tokio::time::sleep(sleep_duration).await;
            }
        }
    }

    /// Parse HIBP API response
    ///
    /// Response format:
    /// ```
    /// 0018A45C4D1DEF81644B54AB7F969B88D65:1
    /// 00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
    /// ```
    fn parse_response(&self, response: &str, suffix: &str) -> Result<u64, HibpError> {
        for line in response.lines() {
            let parts: Vec<&str> = line.split(':').collect();

            if parts.len() != 2 {
                continue;
            }

            let line_suffix = parts[0].trim();
            let count_str = parts[1].trim();

            if line_suffix == suffix {
                return count_str
                    .parse::<u64>()
                    .map_err(|e| HibpError::InvalidResponse(format!("Invalid count: {}", e)));
            }
        }

        // Not found in breach database
        Ok(0)
    }

    /// Clear expired cache entries
    pub async fn cleanup_cache(&self) {
        let mut cache = self.cache.write().await;
        let now = Instant::now();
        cache.retain(|_, entry| now.duration_since(entry.timestamp) < self.config.cache_ttl);

        tracing::debug!("HIBP cache cleaned, {} entries remaining", cache.len());
    }

    /// Get cache stats
    pub async fn cache_stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        CacheStats {
            size: cache.len(),
            breached_count: cache.values().filter(|e| e.count > 0).count(),
            clean_count: cache.values().filter(|e| e.count == 0).count(),
        }
    }
}

impl Default for HibpClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total cache entries
    pub size: usize,
    /// Number of breached passwords cached
    pub breached_count: usize,
    /// Number of clean passwords cached
    pub clean_count: usize,
}

/// No-op HIBP client for when breach checking is disabled
pub struct DisabledHibpClient;

impl DisabledHibpClient {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DisabledHibpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_sha1() {
        let client = HibpClient::new();

        // Test with known value
        let hash = client.calculate_sha1("password").unwrap();
        assert_eq!(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");

        // Should be uppercase
        assert!(hash
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_parse_response() {
        let client = HibpClient::new();

        let response = r#"
0018A45C4D1DEF81644B54AB7F969B88D65:1
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
011C045B5D7BB39B4EEF9E91475B8068E:3
"#;

        // Test existing suffix
        let count = client
            .parse_response(response, "00D4F6E8FA6EECAD2A3AA415EEC418D38EC")
            .unwrap();
        assert_eq!(count, 2);

        // Test non-existing suffix
        let count = client
            .parse_response(response, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_parse_response_invalid_lines() {
        let client = HibpClient::new();

        let response = r#"
INVALID_LINE
0018A45C4D1DEF81644B54AB7F969B88D65:1

ANOTHER_BAD_LINE
"#;

        let count = client
            .parse_response(response, "0018A45C4D1DEF81644B54AB7F969B88D65")
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_cache_operations() {
        let client = HibpClient::with_config(HibpConfig {
            enable_cache: true,
            cache_ttl: Duration::from_secs(60),
            ..Default::default()
        });

        // Initially empty
        let stats = client.cache_stats().await;
        assert_eq!(stats.size, 0);

        // Add entry
        client.cache_result("TEST_HASH_1", 5).await;

        let stats = client.cache_stats().await;
        assert_eq!(stats.size, 1);
        assert_eq!(stats.breached_count, 1);

        // Check cache hit
        let count = client.check_cache("TEST_HASH_1").await;
        assert_eq!(count, Some(5));

        // Check cache miss
        let count = client.check_cache("UNKNOWN_HASH").await;
        assert_eq!(count, None);

        // Add clean entry
        client.cache_result("TEST_HASH_2", 0).await;

        let stats = client.cache_stats().await;
        assert_eq!(stats.size, 2);
        assert_eq!(stats.clean_count, 1);
    }

    // Note: This test makes a real API call - only run when needed
    // #[tokio::test]
    // async fn test_real_api_call() {
    //     let client = HibpClient::new();
    //
    //     // "password" is definitely in the breach database
    //     let result = client.check_password("password").await.unwrap();
    //     assert!(result.is_some());
    //     assert!(result.unwrap() > 0);
    //
    //     // Random UUID is unlikely to be breached
    //     let result = client.check_password("a7f3c9e2-1d5b-4f8a-9c6e-3b2d1f5e8a7c").await.unwrap();
    //     assert!(result.is_none());
    // }
}
