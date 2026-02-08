//! Risk Factor Implementations
//!
//! This module provides various risk factor analyzers for risk-based authentication:
//! - Device risk (new device fingerprint)
//! - Location risk (geo anomaly, impossible travel)
//! - IP risk (VPN, proxy, Tor, known bad IPs)
//! - Time risk (unusual login time)
//! - Velocity risk (too many attempts)
//! - Credential risk (breached password)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, trace, warn};

use crate::db::Database;
use crate::security::GeoIpLookupResult;

/// Trait for risk factor analyzers
#[async_trait::async_trait]
pub trait RiskFactor: Send + Sync {
    /// Assess the risk factor
    async fn assess(&self) -> RiskFactorResult;
    /// Get the factor type
    fn factor_type(&self) -> RiskFactorType;
}

/// Types of risk factors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFactorType {
    /// New or unknown device
    NewDevice,
    /// Device reputation (known bad device)
    DeviceReputation,
    /// Location anomaly
    Location,
    /// Impossible travel (logins from distant locations too quickly)
    ImpossibleTravel,
    /// IP reputation (VPN, proxy, Tor)
    IpReputation,
    /// Unusual login time
    UnusualTime,
    /// Too many login attempts (velocity)
    Velocity,
    /// Known breached credential
    BreachedCredential,
    /// Suspicious behavior pattern
    Behavior,
}

impl RiskFactorType {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskFactorType::NewDevice => "new_device",
            RiskFactorType::DeviceReputation => "device_reputation",
            RiskFactorType::Location => "location",
            RiskFactorType::ImpossibleTravel => "impossible_travel",
            RiskFactorType::IpReputation => "ip_reputation",
            RiskFactorType::UnusualTime => "unusual_time",
            RiskFactorType::Velocity => "velocity",
            RiskFactorType::BreachedCredential => "breached_credential",
            RiskFactorType::Behavior => "behavior",
        }
    }
}

impl std::fmt::Display for RiskFactorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Result of a single risk factor assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactorResult {
    /// The risk factor type
    pub factor: RiskFactorType,
    /// Risk contribution (0-100)
    pub contribution: u8,
    /// Human-readable description
    pub description: String,
    /// Additional details
    pub details: Option<serde_json::Value>,
}

impl RiskFactorResult {
    /// Create a new risk factor result
    pub fn new(
        factor: RiskFactorType,
        contribution: u8,
        description: impl Into<String>,
    ) -> Self {
        Self {
            factor,
            contribution: contribution.min(100),
            description: description.into(),
            details: None,
        }
    }

    /// Create with zero contribution (no risk)
    pub fn none(factor: RiskFactorType) -> Self {
        Self {
            factor,
            contribution: 0,
            description: "No risk detected".to_string(),
            details: None,
        }
    }

    /// Add details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Check if this factor contributes to risk
    pub fn is_risky(&self) -> bool {
        self.contribution > 0
    }
}

// ============== Device Risk Factor ==============

/// Device risk factor analyzer
pub struct DeviceRiskFactor<C: KnownDeviceRepository> {
    repo: C,
    trust_days: u32,
}

impl<C: KnownDeviceRepository> DeviceRiskFactor<C> {
    /// Create a new device risk factor
    pub fn new(repo: C, trust_days: u32) -> Self {
        Self { repo, trust_days }
    }

    /// Assess device risk
    pub async fn assess(
        &self,
        user_id: Option<&str>,
        device_fingerprint: Option<&str>,
    ) -> RiskFactorResult {
        let fingerprint = match device_fingerprint {
            Some(fp) if !fp.is_empty() => fp,
            _ => {
                return RiskFactorResult::new(
                    RiskFactorType::NewDevice,
                    30,
                    "Unable to identify device",
                );
            }
        };

        let user_id = match user_id {
            Some(uid) if !uid.is_empty() => uid,
            _ => {
                // Unknown user, moderate risk
                return RiskFactorResult::new(
                    RiskFactorType::NewDevice,
                    25,
                    "Unknown user - device trust cannot be verified",
                );
            }
        };

        match self.repo.is_known_device(user_id, fingerprint).await {
            Ok(true) => {
                debug!("Device is known for user {}", user_id);
                RiskFactorResult::none(RiskFactorType::NewDevice)
            }
            Ok(false) => {
                debug!("New device detected for user {}", user_id);

                // Store the new device for future reference
                if let Err(e) = self.repo.record_device(user_id, fingerprint).await {
                    warn!("Failed to record new device: {}", e);
                }

                RiskFactorResult::new(
                    RiskFactorType::NewDevice,
                    35,
                    "New device detected - first time login from this device",
                )
                .with_details(serde_json::json!({
                    "device_fingerprint": fingerprint,
                    "trust_days": self.trust_days,
                }))
            }
            Err(e) => {
                warn!("Failed to check known device: {}", e);
                RiskFactorResult::new(
                    RiskFactorType::NewDevice,
                    15,
                    "Could not verify device trust",
                )
            }
        }
    }
}

/// Repository for known device operations
#[async_trait::async_trait]
pub trait KnownDeviceRepository: Send + Sync {
    /// Check if a device is known for a user
    async fn is_known_device(&self, user_id: &str, fingerprint: &str) -> anyhow::Result<bool>;
    /// Record a device for a user
    async fn record_device(&self, user_id: &str, fingerprint: &str) -> anyhow::Result<()>;
}

/// Database-backed known device checker
pub struct KnownDeviceChecker {
    db: Database,
}

impl KnownDeviceChecker {
    /// Create a new known device checker
    pub fn new(db: &Database) -> Self {
        Self { db: db.clone() }
    }
}

#[async_trait::async_trait]
impl KnownDeviceRepository for KnownDeviceChecker {
    async fn is_known_device(&self, user_id: &str, fingerprint: &str) -> anyhow::Result<bool> {
        let mut conn = self.db.pool().acquire().await?;

        let exists: bool = sqlx::query_scalar(
            r#"SELECT EXISTS(
                SELECT 1 FROM user_devices 
                WHERE user_id = $1 AND device_fingerprint = $2
            )"#,
        )
        .bind(user_id)
        .bind(fingerprint)
        .fetch_one(&mut *conn)
        .await?;

        Ok(exists)
    }

    async fn record_device(&self, user_id: &str, fingerprint: &str) -> anyhow::Result<()> {
        let mut conn = self.db.pool().acquire().await?;

        sqlx::query(
            r#"INSERT INTO user_devices (user_id, device_fingerprint, first_seen, last_seen)
               VALUES ($1, $2, NOW(), NOW())
               ON CONFLICT (user_id, device_fingerprint) 
               DO UPDATE SET last_seen = NOW()"#,
        )
        .bind(user_id)
        .bind(fingerprint)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }
}

// ============== Location Risk Factor ==============

/// Location risk factor analyzer
pub struct LocationRiskFactor;

impl LocationRiskFactor {
    /// Create a new location risk factor
    pub fn new() -> Self {
        Self
    }

    /// Assess location risk
    pub async fn assess(&self, geo_info: Option<&GeoIpLookupResult>) -> RiskFactorResult {
        let geo_info = match geo_info {
            Some(info) => info,
            None => {
                return RiskFactorResult::new(
                    RiskFactorType::Location,
                    10,
                    "Location information unavailable",
                );
            }
        };

        // Check if country is known
        match &geo_info.country_code {
            Some(country) => {
                trace!("Login from country: {}", country);
                RiskFactorResult::none(RiskFactorType::Location)
            }
            None => {
                // Unknown country is slightly suspicious
                RiskFactorResult::new(
                    RiskFactorType::Location,
                    15,
                    "Could not determine country from IP",
                )
            }
        }
    }
}

impl Default for LocationRiskFactor {
    fn default() -> Self {
        Self::new()
    }
}

// ============== IP Reputation Risk Factor ==============

/// IP reputation risk factor analyzer
pub struct IpReputationFactor;

impl IpReputationFactor {
    /// Create a new IP reputation factor
    pub fn new() -> Self {
        Self
    }

    /// Assess IP reputation risk
    pub async fn assess(&self, geo_info: Option<&GeoIpLookupResult>) -> RiskFactorResult {
        let geo_info = match geo_info {
            Some(info) => info,
            None => {
                return RiskFactorResult::new(
                    RiskFactorType::IpReputation,
                    5,
                    "IP reputation check unavailable",
                );
            }
        };

        // Check for Tor exit node
        if geo_info.is_tor_exit_node {
            return RiskFactorResult::new(
                RiskFactorType::IpReputation,
                60,
                "Tor exit node detected",
            )
            .with_details(serde_json::json!({
                "type": "tor_exit_node",
            }));
        }

        // Check for VPN
        if geo_info.is_vpn {
            return RiskFactorResult::new(
                RiskFactorType::IpReputation,
                30,
                "VPN connection detected",
            )
            .with_details(serde_json::json!({
                "type": "vpn",
            }));
        }

        // Check for anonymous proxy
        if geo_info.is_anonymous_proxy {
            return RiskFactorResult::new(
                RiskFactorType::IpReputation,
                45,
                "Anonymous proxy detected",
            )
            .with_details(serde_json::json!({
                "type": "anonymous_proxy",
            }));
        }

        // Check for hosting provider (datacenter)
        if geo_info.is_hosting_provider {
            return RiskFactorResult::new(
                RiskFactorType::IpReputation,
                25,
                "Hosting provider/datacenter IP detected",
            )
            .with_details(serde_json::json!({
                "type": "hosting_provider",
                "aso": geo_info.aso,
                "asn": geo_info.asn,
            }));
        }

        // No reputation issues
        RiskFactorResult::none(RiskFactorType::IpReputation)
    }
}

impl Default for IpReputationFactor {
    fn default() -> Self {
        Self::new()
    }
}

// ============== Time Risk Factor ==============

/// Time-based risk factor analyzer
pub struct TimeRiskFactor {
    /// Start of unusual hours (e.g., 23 for 11 PM)
    unusual_hours_start: u8,
    /// End of unusual hours (e.g., 5 for 5 AM)
    unusual_hours_end: u8,
}

impl TimeRiskFactor {
    /// Create a new time risk factor
    pub fn new(unusual_hours_start: u8, unusual_hours_end: u8) -> Self {
        Self {
            unusual_hours_start,
            unusual_hours_end,
        }
    }

    /// Assess time-based risk
    pub async fn assess(&self, login_time: DateTime<Utc>) -> RiskFactorResult {
        let hour = login_time.hour() as u8;

        // Check if it's unusual hours
        let is_unusual = if self.unusual_hours_start > self.unusual_hours_end {
            // Spanning midnight (e.g., 23:00 - 05:00)
            hour >= self.unusual_hours_start || hour < self.unusual_hours_end
        } else {
            // Within same day (e.g., 02:00 - 05:00)
            hour >= self.unusual_hours_start && hour < self.unusual_hours_end
        };

        if is_unusual {
            let risk_score = if hour >= 1 && hour < 5 {
                // Late night (1 AM - 5 AM) is higher risk
                20
            } else {
                // Evening/night (11 PM - 1 AM or 5 AM - 6 AM)
                15
            };

            RiskFactorResult::new(
                RiskFactorType::UnusualTime,
                risk_score,
                format!("Login during unusual hours ({}:00 UTC)", hour),
            )
            .with_details(serde_json::json!({
                "hour": hour,
                "is_unusual": true,
            }))
        } else {
            RiskFactorResult::none(RiskFactorType::UnusualTime)
        }
    }

    /// Check if it's a weekend
    fn is_weekend(&self, date: DateTime<Utc>) -> bool {
        let weekday = date.weekday();
        weekday == chrono::Weekday::Sat || weekday == chrono::Weekday::Sun
    }
}

// ============== Velocity Risk Factor ==============

/// Velocity risk factor analyzer
pub struct VelocityRiskFactor {
    window_seconds: u64,
    max_attempts: u32,
    cache: Arc<RwLock<HashMap<String, VelocityCacheEntry>>>,
}

#[derive(Debug, Clone)]
struct VelocityCacheEntry {
    count: u32,
    first_attempt: DateTime<Utc>,
    last_attempt: DateTime<Utc>,
}

impl VelocityRiskFactor {
    /// Create a new velocity risk factor
    pub fn new(
        window_seconds: u64,
        max_attempts: u32,
        cache: Arc<RwLock<HashMap<String, VelocityCacheEntry>>>,
    ) -> Self {
        Self {
            window_seconds,
            max_attempts,
            cache,
        }
    }

    /// Assess velocity risk
    pub async fn assess(
        &self,
        key: &str,
        failed_attempts: u32,
        now: DateTime<Utc>,
    ) -> RiskFactorResult {
        // Get or create cache entry
        let mut cache = self.cache.write().await;

        let entry = cache.entry(key.to_string()).or_insert(VelocityCacheEntry {
            count: 0,
            first_attempt: now,
            last_attempt: now,
        });

        // Check if window has expired
        let window_expired = now
            .signed_duration_since(entry.first_attempt)
            .num_seconds()
            > self.window_seconds as i64;

        if window_expired {
            // Reset the window
            entry.count = 1;
            entry.first_attempt = now;
            entry.last_attempt = now;
        } else {
            // Increment count
            entry.count += 1;
            entry.last_attempt = now;
        }

        let total_attempts = entry.count + failed_attempts;

        // Calculate risk based on attempt rate
        if total_attempts >= self.max_attempts * 3 {
            // Critical: way too many attempts
            RiskFactorResult::new(
                RiskFactorType::Velocity,
                50,
                format!("Extremely high login velocity: {} attempts", total_attempts),
            )
            .with_details(serde_json::json!({
                "total_attempts": total_attempts,
                "failed_attempts": failed_attempts,
                "window_seconds": self.window_seconds,
            }))
        } else if total_attempts >= self.max_attempts * 2 {
            // High: many attempts
            RiskFactorResult::new(
                RiskFactorType::Velocity,
                35,
                format!("High login velocity: {} attempts", total_attempts),
            )
            .with_details(serde_json::json!({
                "total_attempts": total_attempts,
                "failed_attempts": failed_attempts,
            }))
        } else if total_attempts >= self.max_attempts {
            // Medium: above threshold
            RiskFactorResult::new(
                RiskFactorType::Velocity,
                20,
                format!("Elevated login velocity: {} attempts", total_attempts),
            )
            .with_details(serde_json::json!({
                "total_attempts": total_attempts,
                "failed_attempts": failed_attempts,
            }))
        } else if failed_attempts >= 3 {
            // Some failed attempts
            RiskFactorResult::new(
                RiskFactorType::Velocity,
                10,
                format!("{} recent failed login attempts", failed_attempts),
            )
            .with_details(serde_json::json!({
                "failed_attempts": failed_attempts,
            }))
        } else {
            RiskFactorResult::none(RiskFactorType::Velocity)
        }
    }
}

// ============== Impossible Travel Risk Factor ==============

/// Impossible travel risk factor analyzer
pub struct ImpossibleTravelFactor {
    max_distance_km: f64,
    min_time_hours: f64,
}

impl ImpossibleTravelFactor {
    /// Create a new impossible travel factor
    pub fn new(max_distance_km: f64, min_time_hours: f64) -> Self {
        Self {
            max_distance_km,
            min_time_hours,
        }
    }

    /// Assess impossible travel risk
    pub async fn assess(
        &self,
        previous_login_at: Option<DateTime<Utc>>,
        previous_location: Option<(f64, f64)>,
        current_location: Option<(f64, f64)>,
    ) -> RiskFactorResult {
        // Need both locations to check
        let (prev_loc, curr_loc) = match (previous_location, current_location) {
            (Some(prev), Some(curr)) => (prev, curr),
            _ => {
                return RiskFactorResult::none(RiskFactorType::ImpossibleTravel);
            }
        };

        // Need previous login time
        let previous_time = match previous_login_at {
            Some(time) => time,
            None => {
                return RiskFactorResult::none(RiskFactorType::ImpossibleTravel);
            }
        };

        // Calculate time difference in hours
        let time_diff_hours = Utc::now()
            .signed_duration_since(previous_time)
            .num_seconds() as f64
            / 3600.0;

        // Calculate distance
        let distance_km = Self::haversine_distance(prev_loc, curr_loc);

        // Check if travel is impossible
        // Assume max speed of 900 km/h (commercial aircraft)
        let max_travel_distance = time_diff_hours * 900.0;

        if distance_km > max_travel_distance && distance_km > self.max_distance_km {
            // Impossible travel detected
            return RiskFactorResult::new(
                RiskFactorType::ImpossibleTravel,
                50,
                format!(
                    "Impossible travel detected: {} km in {:.1} hours",
                    distance_km as i32, time_diff_hours
                ),
            )
            .with_details(serde_json::json!({
                "distance_km": distance_km,
                "time_hours": time_diff_hours,
                "previous_location": prev_loc,
                "current_location": curr_loc,
            }));
        }

        // Check for suspiciously fast travel
        if distance_km > self.max_distance_km
            && time_diff_hours < self.min_time_hours
            && distance_km > 100.0
        {
            return RiskFactorResult::new(
                RiskFactorType::ImpossibleTravel,
                30,
                format!(
                    "Suspicious travel: {} km in {:.1} hours",
                    distance_km as i32, time_diff_hours
                ),
            )
            .with_details(serde_json::json!({
                "distance_km": distance_km,
                "time_hours": time_diff_hours,
            }));
        }

        RiskFactorResult::none(RiskFactorType::ImpossibleTravel)
    }

    /// Calculate haversine distance between two points
    fn haversine_distance(p1: (f64, f64), p2: (f64, f64)) -> f64 {
        let r = 6371.0; // Earth's radius in km

        let d_lat = (p2.0 - p1.0).to_radians();
        let d_lon = (p2.1 - p1.1).to_radians();

        let a = (d_lat / 2.0).sin().powi(2)
            + p1.0.to_radians().cos() * p2.0.to_radians().cos() * (d_lon / 2.0).sin().powi(2);

        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

        r * c
    }
}

// ============== Credential Risk Factor ==============

/// Credential risk factor analyzer (breached passwords)
pub struct CredentialRiskFactor;

impl CredentialRiskFactor {
    /// Create a new credential risk factor
    pub fn new() -> Self {
        Self
    }

    /// Assess credential risk
    /// 
    /// Note: In practice, this would integrate with HIBP or similar services.
    /// For now, this is a placeholder that returns no risk.
    pub async fn assess(&self, email: &str, _password: Option<&str>) -> RiskFactorResult {
        // Check for known breached credentials
        // This would typically query a breach database

        // Placeholder: no implementation yet
        RiskFactorResult::none(RiskFactorType::BreachedCredential)
    }
}

impl Default for CredentialRiskFactor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_haversine_distance() {
        // New York to London
        let nyc = (40.7128, -74.0060);
        let london = (51.5074, -0.1278);

        let distance = ImpossibleTravelFactor::haversine_distance(nyc, london);

        // Should be approximately 5570 km
        assert!(distance > 5500.0 && distance < 5600.0);
    }

    #[test]
    fn test_risk_factor_result() {
        let result = RiskFactorResult::new(RiskFactorType::NewDevice, 50, "Test description");

        assert_eq!(result.factor, RiskFactorType::NewDevice);
        assert_eq!(result.contribution, 50);
        assert!(result.is_risky());

        let none = RiskFactorResult::none(RiskFactorType::IpReputation);
        assert!(!none.is_risky());
    }

    #[test]
    fn test_risk_factor_type_str() {
        assert_eq!(RiskFactorType::NewDevice.as_str(), "new_device");
        assert_eq!(RiskFactorType::ImpossibleTravel.as_str(), "impossible_travel");
    }

    #[tokio::test]
    async fn test_time_risk_factor() {
        let factor = TimeRiskFactor::new(23, 5);

        // Test unusual hour (2 AM)
        let late_night = Utc::now()
            .date_naive()
            .and_hms_opt(2, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();

        let result = factor.assess(late_night).await;
        assert!(result.is_risky());
        assert_eq!(result.factor, RiskFactorType::UnusualTime);

        // Test normal hour (10 AM)
        let morning = Utc::now()
            .date_naive()
            .and_hms_opt(10, 0, 0)
            .unwrap()
            .and_local_timezone(Utc)
            .unwrap();

        let result = factor.assess(morning).await;
        assert!(!result.is_risky());
    }

    #[tokio::test]
    async fn test_ip_reputation_factor() {
        let factor = IpReputationFactor::new();

        // Test with Tor exit node
        let tor_geo = GeoIpLookupResult {
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            is_vpn: false,
            is_anonymous_proxy: false,
            is_hosting_provider: false,
            is_tor_exit_node: true,
            aso: None,
            asn: None,
        };

        let result = factor.assess(Some(&tor_geo)).await;
        assert!(result.is_risky());
        assert_eq!(result.contribution, 60);

        // Test with clean IP
        let clean_geo = GeoIpLookupResult {
            country_code: Some("US".to_string()),
            country_name: Some("United States".to_string()),
            is_vpn: false,
            is_anonymous_proxy: false,
            is_hosting_provider: false,
            is_tor_exit_node: false,
            aso: Some("ISP Co".to_string()),
            asn: Some(12345),
        };

        let result = factor.assess(Some(&clean_geo)).await;
        assert!(!result.is_risky());
    }

    #[tokio::test]
    async fn test_impossible_travel_factor() {
        let factor = ImpossibleTravelFactor::new(500.0, 2.0);

        // Test impossible travel (NYC to London in 30 minutes)
        let previous_time = Utc::now() - chrono::Duration::minutes(30);
        let nyc = (40.7128, -74.0060);
        let london = (51.5074, -0.1278);

        let result = factor
            .assess(Some(previous_time), Some(nyc), Some(london))
            .await;
        assert!(result.is_risky());

        // Test possible travel (NYC to London in 8 hours)
        let previous_time = Utc::now() - chrono::Duration::hours(8);
        let result = factor
            .assess(Some(previous_time), Some(nyc), Some(london))
            .await;
        assert!(!result.is_risky());

        // Test no previous location
        let result = factor.assess(None, None, Some(london)).await;
        assert!(!result.is_risky());
    }

    #[tokio::test]
    async fn test_velocity_risk_factor() {
        let cache = Arc::new(RwLock::new(HashMap::new()));
        let factor = VelocityRiskFactor::new(300, 5, cache);

        // Test normal velocity
        let result = factor.assess("user@test.com", 0, Utc::now()).await;
        assert!(!result.is_risky());

        // Test with failed attempts
        let result = factor.assess("user2@test.com", 5, Utc::now()).await;
        assert!(result.is_risky());
    }
}
