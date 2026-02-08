//! Geographic Restriction Service
//!
//! Provides IP-based geographic access control using MaxMind GeoIP2 database.
//! Supports allow/block lists, VPN/proxy detection, and Redis caching.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// ISO 3166-1 alpha-2 country code (e.g., "US", "CA", "GB")
pub type CountryCode = String;

/// Geographic restriction policy type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoRestrictionPolicy {
    /// Only allow countries in the list
    AllowList,
    /// Block countries in the list
    BlockList,
}

impl Default for GeoRestrictionPolicy {
    fn default() -> Self {
        GeoRestrictionPolicy::BlockList
    }
}

/// Geographic restriction configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeoRestrictionConfig {
    /// Whether geo restrictions are enabled
    #[serde(default)]
    pub enabled: bool,
    /// Policy type: allow_list or block_list
    #[serde(default)]
    pub policy: GeoRestrictionPolicy,
    /// List of country codes (ISO 3166-1 alpha-2)
    #[serde(default)]
    pub country_list: Vec<CountryCode>,
    /// Whether to allow VPN/proxy connections
    #[serde(default = "default_allow_vpn")]
    pub allow_vpn: bool,
    /// Whether to block anonymous proxies
    #[serde(default = "default_block_anonymous_proxies")]
    pub block_anonymous_proxies: bool,
    /// Path to MaxMind GeoIP2 database file
    #[serde(default = "default_geoip_db_path")]
    pub geoip_db_path: String,
    /// Redis cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u64,
}

impl Default for GeoRestrictionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            policy: GeoRestrictionPolicy::default(),
            country_list: Vec::new(),
            allow_vpn: default_allow_vpn(),
            block_anonymous_proxies: default_block_anonymous_proxies(),
            geoip_db_path: default_geoip_db_path(),
            cache_ttl_seconds: default_cache_ttl(),
        }
    }
}

fn default_allow_vpn() -> bool {
    true
}

fn default_block_anonymous_proxies() -> bool {
    false
}

fn default_geoip_db_path() -> String {
    "/var/lib/GeoIP/GeoLite2-Country.mmdb".to_string()
}

fn default_cache_ttl() -> u64 {
    86400 // 24 hours
}

/// GeoIP lookup result
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeoIpLookupResult {
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: Option<CountryCode>,
    /// Country name
    pub country_name: Option<String>,
    /// Whether the IP is from a VPN
    pub is_vpn: bool,
    /// Whether the IP is from an anonymous proxy
    pub is_anonymous_proxy: bool,
    /// Whether the IP is from a hosting provider/datacenter
    pub is_hosting_provider: bool,
    /// Whether the IP is a Tor exit node
    pub is_tor_exit_node: bool,
    /// Autonomous System Organization
    pub aso: Option<String>,
    /// Autonomous System Number
    pub asn: Option<u32>,
}

impl GeoIpLookupResult {
    /// Create an empty result (for unknown/private IPs)
    pub fn unknown() -> Self {
        Self {
            country_code: None,
            country_name: None,
            is_vpn: false,
            is_anonymous_proxy: false,
            is_hosting_provider: false,
            is_tor_exit_node: false,
            aso: None,
            asn: None,
        }
    }

    /// Check if the IP is from any type of proxy/VPN
    pub fn is_proxy_or_vpn(&self) -> bool {
        self.is_vpn || self.is_anonymous_proxy || self.is_hosting_provider || self.is_tor_exit_node
    }
}

/// GeoIP lookup trait
#[async_trait]
pub trait GeoIpLookup: Send + Sync {
    /// Look up geographic information for an IP address
    async fn lookup(&self, ip: IpAddr) -> Result<GeoIpLookupResult, GeoError>;
}

/// MaxMind GeoIP2 lookup implementation
pub struct MaxMindGeoIp {
    reader: Arc<maxminddb::Reader<Vec<u8>>>,
}

impl MaxMindGeoIp {
    /// Create a new MaxMind GeoIP reader
    pub fn new(db_path: &Path) -> Result<Self, GeoError> {
        let reader = maxminddb::Reader::open_readfile(db_path)
            .map_err(|e| GeoError::DatabaseError(e.to_string()))?;

        Ok(Self {
            reader: Arc::new(reader),
        })
    }

    /// Create from raw bytes (useful for embedded databases)
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, GeoError> {
        let reader =
            maxminddb::Reader::open(bytes).map_err(|e| GeoError::DatabaseError(e.to_string()))?;

        Ok(Self {
            reader: Arc::new(reader),
        })
    }
}

#[async_trait]
impl GeoIpLookup for MaxMindGeoIp {
    async fn lookup(&self, ip: IpAddr) -> Result<GeoIpLookupResult, GeoError> {
        // Run the synchronous lookup in a blocking task
        let reader = self.reader.clone();

        tokio::task::spawn_blocking(move || {
            let result: Result<maxminddb::geoip2::Country, _> = reader.lookup(ip);

            match result {
                Ok(country) => {
                    let country_code = country
                        .country
                        .as_ref()
                        .and_then(|c| c.iso_code)
                        .map(|s| s.to_string());

                    let country_name = country
                        .country
                        .as_ref()
                        .and_then(|c| c.names)
                        .and_then(|n| n.get("en"))
                        .map(|s| s.to_string());

                    // Check for traits (VPN, proxy, etc.)
                    let traits = country.traits.as_ref();

                    Ok(GeoIpLookupResult {
                        country_code,
                        country_name,
                        is_vpn: traits
                            .map(|t| t.user_type == Some("corporate"))
                            .unwrap_or(false),
                        is_anonymous_proxy: traits
                            .and_then(|t| t.is_anonymous_proxy)
                            .unwrap_or(false),
                        is_hosting_provider: traits
                            .and_then(|t| t.is_hosting_provider)
                            .unwrap_or(false),
                        is_tor_exit_node: false, // Not provided by GeoIP2 Country
                        aso: None,
                        asn: None,
                    })
                }
                Err(maxminddb::MaxMindDBError::AddressNotFoundError(_)) => {
                    Ok(GeoIpLookupResult::unknown())
                }
                Err(e) => Err(GeoError::LookupError(e.to_string())),
            }
        })
        .await
        .map_err(|e| GeoError::LookupError(e.to_string()))?
    }
}

/// Cached GeoIP lookup with Redis
pub struct CachedGeoIpLookup<L: GeoIpLookup> {
    inner: L,
    redis: redis::aio::ConnectionManager,
    cache_ttl: u64,
}

impl<L: GeoIpLookup> CachedGeoIpLookup<L> {
    /// Create a new cached GeoIP lookup
    pub fn new(inner: L, redis: redis::aio::ConnectionManager, cache_ttl: u64) -> Self {
        Self {
            inner,
            redis,
            cache_ttl,
        }
    }

    /// Get cache key for an IP
    fn cache_key(ip: &IpAddr) -> String {
        format!("geoip:lookup:{}", ip)
    }
}

#[async_trait]
impl<L: GeoIpLookup> GeoIpLookup for CachedGeoIpLookup<L> {
    async fn lookup(&self, ip: IpAddr) -> Result<GeoIpLookupResult, GeoError> {
        let cache_key = Self::cache_key(&ip);
        let mut conn = self.redis.clone();

        // Try to get from cache
        let cached: Option<String> = redis::cmd("GET")
            .arg(&cache_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| GeoError::CacheError(e.to_string()))?;

        if let Some(cached_json) = cached {
            if let Ok(result) = serde_json::from_str::<GeoIpLookupResult>(&cached_json) {
                return Ok(result);
            }
        }

        // Cache miss - perform lookup
        let result = self.inner.lookup(ip).await?;

        // Cache the result
        let json =
            serde_json::to_string(&result).map_err(|e| GeoError::CacheError(e.to_string()))?;

        let _: Result<(), _> = redis::cmd("SETEX")
            .arg(&cache_key)
            .arg(self.cache_ttl)
            .arg(json)
            .query_async(&mut conn)
            .await;

        Ok(result)
    }
}

/// Geo restriction errors
#[derive(Debug, Error)]
pub enum GeoError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Lookup error: {0}")]
    LookupError(String),

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("IP blocked by geo restriction policy")]
    BlockedByPolicy,

    #[error("Anonymous proxies are not allowed")]
    AnonymousProxyBlocked,

    #[error("VPN connections are not allowed")]
    VpnBlocked,
}

/// Geographic restriction service
pub struct GeoRestrictionService<L: GeoIpLookup> {
    lookup: L,
    config: GeoRestrictionConfig,
    country_set: HashSet<CountryCode>,
}

impl<L: GeoIpLookup> GeoRestrictionService<L> {
    /// Create a new geo restriction service
    pub fn new(lookup: L, config: GeoRestrictionConfig) -> Self {
        let country_set: HashSet<CountryCode> = config.country_list.iter().cloned().collect();

        Self {
            lookup,
            config,
            country_set,
        }
    }

    /// Check if an IP address is allowed based on the configured policy
    pub async fn is_allowed(&self, ip: IpAddr) -> Result<bool, GeoError> {
        // Skip check if geo restrictions are disabled
        if !self.config.enabled {
            return Ok(true);
        }

        // Skip private IP addresses (localhost, internal networks)
        if Self::is_private_ip(ip) {
            return Ok(true);
        }

        let lookup_result = self.lookup.lookup(ip).await?;

        // Check VPN/proxy restrictions
        if lookup_result.is_vpn && !self.config.allow_vpn {
            return Err(GeoError::VpnBlocked);
        }

        if lookup_result.is_anonymous_proxy && self.config.block_anonymous_proxies {
            return Err(GeoError::AnonymousProxyBlocked);
        }

        // Get country code (default to empty if unknown)
        let country_code = lookup_result.country_code.unwrap_or_default();

        // Apply policy
        let allowed = match self.config.policy {
            GeoRestrictionPolicy::AllowList => {
                // Allow only if country is in the list (or if list is empty, allow all)
                self.country_set.is_empty() || self.country_set.contains(&country_code)
            }
            GeoRestrictionPolicy::BlockList => {
                // Block only if country is in the list
                !self.country_set.contains(&country_code)
            }
        };

        Ok(allowed)
    }

    /// Check if an IP address is allowed, returning detailed result
    pub async fn check_access(&self, ip: IpAddr) -> GeoAccessResult {
        // Skip check if geo restrictions are disabled
        if !self.config.enabled {
            return GeoAccessResult::allowed();
        }

        // Skip private IP addresses
        if Self::is_private_ip(ip) {
            return GeoAccessResult::allowed();
        }

        let lookup_result = match self.lookup.lookup(ip).await {
            Ok(result) => result,
            Err(e) => {
                return GeoAccessResult::error(e.to_string());
            }
        };

        // Check VPN/proxy restrictions
        if lookup_result.is_vpn && !self.config.allow_vpn {
            return GeoAccessResult::blocked(
                "VPN connections are not allowed",
                lookup_result.country_code,
            );
        }

        if lookup_result.is_anonymous_proxy && self.config.block_anonymous_proxies {
            return GeoAccessResult::blocked(
                "Anonymous proxies are not allowed",
                lookup_result.country_code,
            );
        }

        // Get country code
        let country_code = lookup_result.country_code.clone().unwrap_or_default();

        // Apply policy
        let allowed = match self.config.policy {
            GeoRestrictionPolicy::AllowList => {
                self.country_set.is_empty() || self.country_set.contains(&country_code)
            }
            GeoRestrictionPolicy::BlockList => !self.country_set.contains(&country_code),
        };

        if allowed {
            GeoAccessResult::allowed_with_geo(lookup_result)
        } else {
            GeoAccessResult::blocked(
                &format!("Access from country '{}' is not allowed", country_code),
                lookup_result.country_code,
            )
        }
    }

    /// Get geographic information for an IP without checking policy
    pub async fn get_geo_info(&self, ip: IpAddr) -> Result<GeoIpLookupResult, GeoError> {
        if Self::is_private_ip(ip) {
            return Ok(GeoIpLookupResult::unknown());
        }
        self.lookup.lookup(ip).await
    }

    /// Update configuration
    pub fn update_config(&mut self, config: GeoRestrictionConfig) {
        self.country_set = config.country_list.iter().cloned().collect();
        self.config = config;
    }

    /// Get current configuration
    pub fn config(&self) -> &GeoRestrictionConfig {
        &self.config
    }

    /// Check if an IP address is private (localhost, RFC 1918, etc.)
    fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(addr) => {
                addr.is_private()
                    || addr.is_loopback()
                    || addr.is_link_local()
                    || addr.is_multicast()
                    || addr.is_broadcast()
                    || addr.is_documentation()
            }
            IpAddr::V6(addr) => addr.is_loopback() || addr.is_multicast() || addr.is_unspecified(),
        }
    }
}

/// Geographic access check result
#[derive(Debug, Clone)]
pub struct GeoAccessResult {
    /// Whether access is allowed
    pub allowed: bool,
    /// Country code (if determined)
    pub country_code: Option<CountryCode>,
    /// Reason for denial (if denied)
    pub reason: Option<String>,
    /// Full geo lookup result (if available)
    pub geo_info: Option<GeoIpLookupResult>,
    /// Whether an error occurred
    pub is_error: bool,
}

impl GeoAccessResult {
    /// Create an allowed result
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            country_code: None,
            reason: None,
            geo_info: None,
            is_error: false,
        }
    }

    /// Create an allowed result with geo info
    pub fn allowed_with_geo(geo_info: GeoIpLookupResult) -> Self {
        let country_code = geo_info.country_code.clone();
        Self {
            allowed: true,
            country_code,
            reason: None,
            geo_info: Some(geo_info),
            is_error: false,
        }
    }

    /// Create a blocked result
    pub fn blocked(reason: &str, country_code: Option<CountryCode>) -> Self {
        Self {
            allowed: false,
            country_code,
            reason: Some(reason.to_string()),
            geo_info: None,
            is_error: false,
        }
    }

    /// Create an error result
    pub fn error(message: String) -> Self {
        Self {
            allowed: false,
            country_code: None,
            reason: Some(message),
            geo_info: None,
            is_error: true,
        }
    }
}

/// VPN/Proxy detection service
pub struct VpnDetector {
    /// Known VPN ASNs
    known_vpn_asns: HashSet<u32>,
    /// Known hosting provider ASNs
    known_hosting_asns: HashSet<u32>,
}

impl VpnDetector {
    /// Create a new VPN detector with default known ASNs
    pub fn new() -> Self {
        let mut known_vpn_asns = HashSet::new();
        // Add common VPN provider ASNs
        known_vpn_asns.insert(206238); // NordVPN
        known_vpn_asns.insert(9009); // M247 (used by many VPNs)
        known_vpn_asns.insert(20473); // Choopa (used by VPNs)
        known_vpn_asns.insert(140952); // ExpressVPN
        known_vpn_asns.insert(60068); // Datacamp (Surfshark)

        let mut known_hosting_asns = HashSet::new();
        // Add major cloud provider ASNs
        known_hosting_asns.insert(16509); // AWS
        known_hosting_asns.insert(15169); // Google Cloud
        known_hosting_asns.insert(8075); // Microsoft Azure
        known_hosting_asns.insert(14618); // AWS
        known_hosting_asns.insert(36351); // DigitalOcean
        known_hosting_asns.insert(14061); // DigitalOcean

        Self {
            known_vpn_asns,
            known_hosting_asns,
        }
    }

    /// Check if an ASN is a known VPN
    pub fn is_known_vpn_asn(&self, asn: u32) -> bool {
        self.known_vpn_asns.contains(&asn)
    }

    /// Check if an ASN is a known hosting provider
    pub fn is_known_hosting_asn(&self, asn: u32) -> bool {
        self.known_hosting_asns.contains(&asn)
    }

    /// Add a custom VPN ASN
    pub fn add_vpn_asn(&mut self, asn: u32) {
        self.known_vpn_asns.insert(asn);
    }

    /// Add a custom hosting ASN
    pub fn add_hosting_asn(&mut self, asn: u32) {
        self.known_hosting_asns.insert(asn);
    }
}

impl Default for VpnDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Geo restriction service factory for creating services with different lookup implementations
pub struct GeoServiceFactory;

impl GeoServiceFactory {
    /// Create a geo restriction service with MaxMind GeoIP2
    pub fn with_maxmind(
        config: GeoRestrictionConfig,
    ) -> Result<GeoRestrictionService<MaxMindGeoIp>, GeoError> {
        let lookup = MaxMindGeoIp::new(Path::new(&config.geoip_db_path))?;
        Ok(GeoRestrictionService::new(lookup, config))
    }

    /// Create a geo restriction service with MaxMind and Redis caching
    pub fn with_maxmind_cached(
        config: GeoRestrictionConfig,
        redis: redis::aio::ConnectionManager,
    ) -> Result<GeoRestrictionService<CachedGeoIpLookup<MaxMindGeoIp>>, GeoError> {
        let lookup = MaxMindGeoIp::new(Path::new(&config.geoip_db_path))?;
        let cached_lookup = CachedGeoIpLookup::new(lookup, redis, config.cache_ttl_seconds);
        Ok(GeoRestrictionService::new(cached_lookup, config))
    }
}

/// Validate a country code (ISO 3166-1 alpha-2)
pub fn validate_country_code(code: &str) -> bool {
    if code.len() != 2 {
        return false;
    }
    // Check if it's two uppercase letters
    code.chars().all(|c| c.is_ascii_uppercase())
}

/// Normalize country code to uppercase
pub fn normalize_country_code(code: &str) -> CountryCode {
    code.trim().to_uppercase()
}

/// List of all valid country codes (subset of common ones)
pub fn common_country_codes() -> Vec<(CountryCode, &'static str)> {
    vec![
        ("US".to_string(), "United States"),
        ("CA".to_string(), "Canada"),
        ("GB".to_string(), "United Kingdom"),
        ("DE".to_string(), "Germany"),
        ("FR".to_string(), "France"),
        ("ES".to_string(), "Spain"),
        ("IT".to_string(), "Italy"),
        ("NL".to_string(), "Netherlands"),
        ("AU".to_string(), "Australia"),
        ("JP".to_string(), "Japan"),
        ("CN".to_string(), "China"),
        ("IN".to_string(), "India"),
        ("BR".to_string(), "Brazil"),
        ("MX".to_string(), "Mexico"),
        ("RU".to_string(), "Russia"),
        ("KR".to_string(), "South Korea"),
        ("SG".to_string(), "Singapore"),
        ("SE".to_string(), "Sweden"),
        ("NO".to_string(), "Norway"),
        ("DK".to_string(), "Denmark"),
        ("FI".to_string(), "Finland"),
        ("CH".to_string(), "Switzerland"),
        ("AT".to_string(), "Austria"),
        ("BE".to_string(), "Belgium"),
        ("PL".to_string(), "Poland"),
        ("CZ".to_string(), "Czech Republic"),
        ("HU".to_string(), "Hungary"),
        ("RO".to_string(), "Romania"),
        ("TR".to_string(), "Turkey"),
        ("ZA".to_string(), "South Africa"),
        ("AE".to_string(), "United Arab Emirates"),
        ("SA".to_string(), "Saudi Arabia"),
        ("IL".to_string(), "Israel"),
        ("HK".to_string(), "Hong Kong"),
        ("TW".to_string(), "Taiwan"),
        ("ID".to_string(), "Indonesia"),
        ("TH".to_string(), "Thailand"),
        ("VN".to_string(), "Vietnam"),
        ("MY".to_string(), "Malaysia"),
        ("PH".to_string(), "Philippines"),
        ("NZ".to_string(), "New Zealand"),
        ("IE".to_string(), "Ireland"),
        ("PT".to_string(), "Portugal"),
        ("GR".to_string(), "Greece"),
        ("UA".to_string(), "Ukraine"),
        ("AR".to_string(), "Argentina"),
        ("CL".to_string(), "Chile"),
        ("CO".to_string(), "Colombia"),
        ("PE".to_string(), "Peru"),
        ("EG".to_string(), "Egypt"),
        ("NG".to_string(), "Nigeria"),
        ("KE".to_string(), "Kenya"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_country_code() {
        assert!(validate_country_code("US"));
        assert!(validate_country_code("GB"));
        assert!(!validate_country_code("us")); // Must be uppercase
        assert!(!validate_country_code("USA")); // Must be 2 characters
        assert!(!validate_country_code("U"));
        assert!(!validate_country_code("12")); // Must be letters
    }

    #[test]
    fn test_normalize_country_code() {
        assert_eq!(normalize_country_code("us"), "US");
        assert_eq!(normalize_country_code(" Us "), "US");
        assert_eq!(normalize_country_code("GB"), "GB");
    }

    #[test]
    fn test_is_private_ip() {
        // IPv4 private addresses
        assert!(GeoRestrictionService::<MaxMindGeoIp>::is_private_ip(
            "192.168.1.1".parse().unwrap()
        ));
        assert!(GeoRestrictionService::<MaxMindGeoIp>::is_private_ip(
            "10.0.0.1".parse().unwrap()
        ));
        assert!(GeoRestrictionService::<MaxMindGeoIp>::is_private_ip(
            "127.0.0.1".parse().unwrap()
        ));

        // IPv4 public addresses
        assert!(!GeoRestrictionService::<MaxMindGeoIp>::is_private_ip(
            "8.8.8.8".parse().unwrap()
        ));
        assert!(!GeoRestrictionService::<MaxMindGeoIp>::is_private_ip(
            "1.1.1.1".parse().unwrap()
        ));
    }

    #[test]
    fn test_geo_restriction_policy_default() {
        let policy: GeoRestrictionPolicy = Default::default();
        assert_eq!(policy, GeoRestrictionPolicy::BlockList);
    }

    #[test]
    fn test_geo_config_default() {
        let config = GeoRestrictionConfig::default();
        assert!(!config.enabled);
        assert!(config.allow_vpn);
        assert!(!config.block_anonymous_proxies);
        assert_eq!(config.cache_ttl_seconds, 86400);
    }

    #[test]
    fn test_vpn_detector() {
        let detector = VpnDetector::new();
        assert!(detector.is_known_vpn_asn(206238)); // NordVPN
        assert!(!detector.is_known_vpn_asn(12345));
        assert!(detector.is_known_hosting_asn(16509)); // AWS
    }

    #[tokio::test]
    async fn test_geo_access_result() {
        let allowed = GeoAccessResult::allowed();
        assert!(allowed.allowed);
        assert!(!allowed.is_error);

        let blocked = GeoAccessResult::blocked("Test reason", Some("US".to_string()));
        assert!(!blocked.allowed);
        assert_eq!(blocked.reason, Some("Test reason".to_string()));
        assert_eq!(blocked.country_code, Some("US".to_string()));

        let error = GeoAccessResult::error("Test error".to_string());
        assert!(!error.allowed);
        assert!(error.is_error);
    }
}
