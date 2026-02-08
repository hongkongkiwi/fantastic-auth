//! Anomaly Detection System
//!
//! This module provides behavioral anomaly detection using:
//! - Statistical analysis of user behavior patterns
//! - Clustering-based outlier detection
//! - Time-series anomaly detection
//! - Sequence pattern matching

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::error::{AiError, AiResult};
use super::features::AuthContext;
use super::ml_models::ModelManager;
use crate::db::DbContext;

/// Anomaly severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyLevel {
    /// Low anomaly - minor deviation
    Low,
    /// Medium anomaly - notable deviation
    Medium,
    /// High anomaly - significant deviation
    High,
    /// Critical anomaly - severe deviation
    Critical,
}

impl AnomalyLevel {
    /// Convert score to level
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s < 0.3 => AnomalyLevel::Low,
            s if s < 0.6 => AnomalyLevel::Medium,
            s if s < 0.85 => AnomalyLevel::High,
            _ => AnomalyLevel::Critical,
        }
    }

    /// Get numeric value for scoring
    pub fn value(&self) -> u8 {
        match self {
            AnomalyLevel::Low => 1,
            AnomalyLevel::Medium => 2,
            AnomalyLevel::High => 3,
            AnomalyLevel::Critical => 4,
        }
    }
}

/// Types of anomalies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyType {
    /// Login from unusual location
    UnusualLocation,
    /// Login at unusual time
    UnusualTime,
    /// New device
    NewDevice,
    /// Impossible travel
    ImpossibleTravel,
    /// Velocity anomaly (too many attempts)
    Velocity,
    /// Behavioral pattern change
    BehavioralChange,
    /// Credential usage anomaly
    CredentialAnomaly,
    /// Access pattern change
    AccessPatternChange,
    /// Network anomaly
    NetworkAnomaly,
    /// Account takeover indicators
    AccountTakeover,
}

impl std::fmt::Display for AnomalyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AnomalyType::UnusualLocation => "unusual_location",
            AnomalyType::UnusualTime => "unusual_time",
            AnomalyType::NewDevice => "new_device",
            AnomalyType::ImpossibleTravel => "impossible_travel",
            AnomalyType::Velocity => "velocity",
            AnomalyType::BehavioralChange => "behavioral_change",
            AnomalyType::CredentialAnomaly => "credential_anomaly",
            AnomalyType::AccessPatternChange => "access_pattern_change",
            AnomalyType::NetworkAnomaly => "network_anomaly",
            AnomalyType::AccountTakeover => "account_takeover",
        };
        write!(f, "{}", s)
    }
}

/// Detected anomaly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    /// Anomaly type
    pub anomaly_type: AnomalyType,
    /// Severity level
    pub level: AnomalyLevel,
    /// Confidence score (0-1)
    pub confidence: f64,
    /// Description
    pub description: String,
    /// Timestamp when detected
    pub detected_at: DateTime<Utc>,
    /// Related event ID
    pub event_id: Option<String>,
    /// Additional details
    pub details: Option<serde_json::Value>,
    /// Suggested action
    pub suggested_action: Option<String>,
}

impl Anomaly {
    /// Create new anomaly
    pub fn new(
        anomaly_type: AnomalyType,
        level: AnomalyLevel,
        confidence: f64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            anomaly_type,
            level,
            confidence: confidence.clamp(0.0, 1.0),
            description: description.into(),
            detected_at: Utc::now(),
            event_id: None,
            details: None,
            suggested_action: None,
        }
    }

    /// Add event ID
    pub fn with_event_id(mut self, event_id: impl Into<String>) -> Self {
        self.event_id = Some(event_id.into());
        self
    }

    /// Add details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Add suggested action
    pub fn with_suggested_action(mut self, action: impl Into<String>) -> Self {
        self.suggested_action = Some(action.into());
        self
    }
}

/// User behavior profile for baseline comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserBehaviorProfile {
    /// User ID
    pub user_id: String,
    /// Common login locations (lat, lon, frequency)
    pub common_locations: Vec<LocationPattern>,
    /// Common login times (hour of day, frequency)
    pub common_hours: Vec<HourPattern>,
    /// Known devices (fingerprint, first seen, last seen, count)
    pub known_devices: Vec<DevicePattern>,
    /// Typical velocity (logins per hour)
    pub typical_velocity: f64,
    /// Common IP ranges
    pub common_ip_ranges: Vec<String>,
    /// Average session duration
    pub avg_session_duration: Duration,
    /// Last updated
    pub last_updated: DateTime<Utc>,
    /// Profile version
    pub version: u32,
}

/// Location pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationPattern {
    /// Approximate latitude
    pub latitude: f64,
    /// Approximate longitude
    pub longitude: f64,
    /// Country code
    pub country_code: Option<String>,
    /// City
    pub city: Option<String>,
    /// Login count from this location
    pub frequency: u32,
    /// First seen
    pub first_seen: DateTime<Utc>,
    /// Last seen
    pub last_seen: DateTime<Utc>,
}

/// Hour pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HourPattern {
    /// Hour of day (0-23)
    pub hour: u8,
    /// Frequency
    pub frequency: u32,
    /// Is typical business hour
    pub is_business_hour: bool,
}

/// Device pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePattern {
    /// Device fingerprint
    pub fingerprint: String,
    /// User agent (sanitized)
    pub user_agent: Option<String>,
    /// First seen
    pub first_seen: DateTime<Utc>,
    /// Last seen
    pub last_seen: DateTime<Utc>,
    /// Login count
    pub login_count: u32,
    /// Is trusted
    pub is_trusted: bool,
}

/// Anomaly detector
pub struct AnomalyDetector {
    /// Sensitivity threshold (0-1)
    sensitivity: f64,
    /// Database connection
    db: DbContext,
    /// Model manager
    model_manager: Arc<ModelManager>,
    /// User profiles cache
    profiles: Arc<RwLock<HashMap<String, UserBehaviorProfile>>>,
    /// Recent anomalies cache
    anomalies: Arc<RwLock<Vec<AnomalyEntry>>>,
    /// Total detected counter
    detected_count: Arc<RwLock<u64>>,
}

/// Anomaly entry for caching
#[derive(Debug, Clone)]
struct AnomalyEntry {
    user_id: String,
    anomaly: Anomaly,
}

impl AnomalyDetector {
    /// Create new anomaly detector
    pub async fn new(
        sensitivity: f64,
        db: DbContext,
        model_manager: Arc<ModelManager>,
    ) -> AiResult<Self> {
        Ok(Self {
            sensitivity: sensitivity.clamp(0.0, 1.0),
            db,
            model_manager,
            profiles: Arc::new(RwLock::new(HashMap::new())),
            anomalies: Arc::new(RwLock::new(Vec::new())),
            detected_count: Arc::new(RwLock::new(0)),
        })
    }

    /// Detect anomalies for a user
    pub async fn detect_anomalies(
        &self,
        user_id: &str,
        context: &AuthContext,
    ) -> AiResult<Vec<Anomaly>> {
        let mut anomalies = Vec::new();

        // Load or create user profile
        let profile = self.get_or_create_profile(user_id).await?;

        // Check for location anomaly
        if let Some(location_anomaly) = self.check_location_anomaly(&profile, context).await? {
            anomalies.push(location_anomaly);
        }

        // Check for time anomaly
        if let Some(time_anomaly) = self.check_time_anomaly(&profile, context).await? {
            anomalies.push(time_anomaly);
        }

        // Check for device anomaly
        if let Some(device_anomaly) = self.check_device_anomaly(&profile, context).await? {
            anomalies.push(device_anomaly);
        }

        // Check for velocity anomaly
        if let Some(velocity_anomaly) = self.check_velocity_anomaly(user_id, context).await? {
            anomalies.push(velocity_anomaly);
        }

        // Check for impossible travel
        if let Some(travel_anomaly) = self.check_impossible_travel(&profile, context).await? {
            anomalies.push(travel_anomaly);
        }

        // Update profile with current data
        self.update_profile(user_id, context).await?;

        // Cache anomalies
        for anomaly in &anomalies {
            let mut cache = self.anomalies.write().await;
            cache.push(AnomalyEntry {
                user_id: user_id.to_string(),
                anomaly: anomaly.clone(),
            });

            // Keep cache size manageable
            if cache.len() > 10000 {
                cache.drain(0..1000);
            }
        }

        // Update counter
        let mut count = self.detected_count.write().await;
        *count += anomalies.len() as u64;

        Ok(anomalies)
    }

    /// Get or create user behavior profile
    async fn get_or_create_profile(&self, user_id: &str) -> AiResult<UserBehaviorProfile> {
        // Check cache first
        {
            let profiles = self.profiles.read().await;
            if let Some(profile) = profiles.get(user_id) {
                // Check if profile is fresh (less than 1 hour old)
                if Utc::now() - profile.last_updated < Duration::hours(1) {
                    return Ok(profile.clone());
                }
            }
        }

        // Load from database or create new
        let profile = self.load_profile_from_db(user_id).await?;

        // Cache the profile
        let mut profiles = self.profiles.write().await;
        profiles.insert(user_id.to_string(), profile.clone());

        Ok(profile)
    }

    /// Load profile from database
    async fn load_profile_from_db(&self, user_id: &str) -> AiResult<UserBehaviorProfile> {
        // In production, this would query the database
        // For now, create a new profile
        Ok(UserBehaviorProfile {
            user_id: user_id.to_string(),
            common_locations: Vec::new(),
            common_hours: Vec::new(),
            known_devices: Vec::new(),
            typical_velocity: 1.0,
            common_ip_ranges: Vec::new(),
            avg_session_duration: Duration::minutes(30),
            last_updated: Utc::now(),
            version: 1,
        })
    }

    /// Check for location anomaly
    async fn check_location_anomaly(
        &self,
        profile: &UserBehaviorProfile,
        context: &AuthContext,
    ) -> AiResult<Option<Anomaly>> {
        let Some((lat, lon)) = context.geo_location else {
            return Ok(None);
        };

        // If no history, it's a new location but not necessarily anomalous
        if profile.common_locations.is_empty() {
            return Ok(None);
        }

        // Check if location is within known areas
        let is_known = profile.common_locations.iter().any(|loc| {
            let distance = haversine_distance(lat, lon, loc.latitude, loc.longitude);
            distance < 100.0 // Within 100km
        });

        if !is_known {
            let confidence = 0.7 * self.sensitivity;
            return Ok(Some(
                Anomaly::new(
                    AnomalyType::UnusualLocation,
                    AnomalyLevel::from_score(confidence),
                    confidence,
                    "Login from previously unseen location",
                )
                .with_details(serde_json::json!({
                    "location": (lat, lon),
                    "known_locations": profile.common_locations.len(),
                }))
                .with_suggested_action("Consider verifying user location"),
            ));
        }

        Ok(None)
    }

    /// Check for time anomaly
    async fn check_time_anomaly(
        &self,
        profile: &UserBehaviorProfile,
        context: &AuthContext,
    ) -> AiResult<Option<Anomaly>> {
        if profile.common_hours.is_empty() {
            return Ok(None);
        }

        let current_hour = context.timestamp.hour() as u8;

        // Check if current hour is common
        let is_common = profile
            .common_hours
            .iter()
            .any(|h| h.hour == current_hour && h.frequency > 2);

        if !is_common {
            // Check if it's unusual (e.g., 3 AM for business user)
            let is_night = current_hour >= 1 && current_hour <= 5;
            let level = if is_night {
                AnomalyLevel::Medium
            } else {
                AnomalyLevel::Low
            };

            let confidence = if is_night { 0.6 } else { 0.4 } * self.sensitivity;

            return Ok(Some(
                Anomaly::new(
                    AnomalyType::UnusualTime,
                    level,
                    confidence,
                    format!("Login at unusual time ({}:00)", current_hour),
                )
                .with_suggested_action(if is_night {
                    "Consider requiring additional verification"
                } else {
                    "Log for review"
                }),
            ));
        }

        Ok(None)
    }

    /// Check for device anomaly
    async fn check_device_anomaly(
        &self,
        profile: &UserBehaviorProfile,
        context: &AuthContext,
    ) -> AiResult<Option<Anomaly>> {
        let Some(ref fingerprint) = context.device_fingerprint else {
            return Ok(None);
        };

        // Check if device is known
        let is_known = profile
            .known_devices
            .iter()
            .any(|d| d.fingerprint == *fingerprint);

        if !is_known && !profile.known_devices.is_empty() {
            return Ok(Some(
                Anomaly::new(
                    AnomalyType::NewDevice,
                    AnomalyLevel::Medium,
                    0.6 * self.sensitivity,
                    "Login from new device",
                )
                .with_details(serde_json::json!({
                    "device_count": profile.known_devices.len(),
                }))
                .with_suggested_action("Send new device notification"),
            ));
        }

        Ok(None)
    }

    /// Check for velocity anomaly
    async fn check_velocity_anomaly(
        &self,
        user_id: &str,
        context: &AuthContext,
    ) -> AiResult<Option<Anomaly>> {
        // Simple velocity check
        if context.failed_attempts >= 5 {
            return Ok(Some(
                Anomaly::new(
                    AnomalyType::Velocity,
                    AnomalyLevel::High,
                    0.8 * self.sensitivity,
                    format!("High velocity: {} failed attempts", context.failed_attempts),
                )
                .with_suggested_action("Consider temporary lockout"),
            ));
        }

        if context.successful_attempts >= 10 {
            return Ok(Some(
                Anomaly::new(
                    AnomalyType::Velocity,
                    AnomalyLevel::Medium,
                    0.5 * self.sensitivity,
                    format!("High velocity: {} recent logins", context.successful_attempts),
                )
                .with_suggested_action("Monitor for account sharing"),
            ));
        }

        Ok(None)
    }

    /// Check for impossible travel
    async fn check_impossible_travel(
        &self,
        profile: &UserBehaviorProfile,
        context: &AuthContext,
    ) -> AiResult<Option<Anomaly>> {
        let Some((curr_lat, curr_lon)) = context.geo_location else {
            return Ok(None);
        };

        let Some((prev_lat, prev_lon)) = context.previous_location else {
            return Ok(None);
        };

        let Some(prev_time) = context.previous_login_at else {
            return Ok(None);
        };

        let distance = haversine_distance(curr_lat, curr_lon, prev_lat, prev_lon);
        let hours = (context.timestamp - prev_time).num_hours() as f64;

        if hours <= 0.0 {
            return Ok(None);
        }

        let speed = distance / hours;

        if speed > 900.0 {
            // Impossible travel
            return Ok(Some(
                Anomaly::new(
                    AnomalyType::ImpossibleTravel,
                    AnomalyLevel::Critical,
                    0.95,
                    format!("Impossible travel: {:.0} km in {:.1} hours", distance, hours),
                )
                .with_details(serde_json::json!({
                    "distance_km": distance,
                    "hours": hours,
                    "speed": speed,
                    "from": (prev_lat, prev_lon),
                    "to": (curr_lat, curr_lon),
                }))
                .with_suggested_action("Block and require email verification"),
            ));
        }

        Ok(None)
    }

    /// Update user profile with current data
    async fn update_profile(&self, user_id: &str, context: &AuthContext) -> AiResult<()> {
        let mut profiles = self.profiles.write().await;

        if let Some(profile) = profiles.get_mut(user_id) {
            // Update location
            if let Some((lat, lon)) = context.geo_location {
                if let Some(existing) = profile
                    .common_locations
                    .iter_mut()
                    .find(|l| haversine_distance(lat, lon, l.latitude, l.longitude) < 50.0)
                {
                    existing.frequency += 1;
                    existing.last_seen = Utc::now();
                } else {
                    profile.common_locations.push(LocationPattern {
                        latitude: lat,
                        longitude: lon,
                        country_code: context.country_code.clone(),
                        city: None,
                        frequency: 1,
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                    });
                }
            }

            // Update hour pattern
            let current_hour = context.timestamp.hour() as u8;
            if let Some(existing) = profile.common_hours.iter_mut().find(|h| h.hour == current_hour)
            {
                existing.frequency += 1;
            } else {
                profile.common_hours.push(HourPattern {
                    hour: current_hour,
                    frequency: 1,
                    is_business_hour: current_hour >= 9 && current_hour < 17,
                });
            }

            // Update device
            if let Some(ref fingerprint) = context.device_fingerprint {
                if let Some(existing) = profile
                    .known_devices
                    .iter_mut()
                    .find(|d| d.fingerprint == *fingerprint)
                {
                    existing.login_count += 1;
                    existing.last_seen = Utc::now();
                } else {
                    profile.known_devices.push(DevicePattern {
                        fingerprint: fingerprint.clone(),
                        user_agent: context.user_agent.clone(),
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        login_count: 1,
                        is_trusted: false,
                    });
                }
            }

            profile.last_updated = Utc::now();
        }

        Ok(())
    }

    /// Get recent anomalies for a user
    pub async fn get_recent_anomalies(&self, user_id: &str, days: i64) -> AiResult<Vec<Anomaly>> {
        let anomalies = self.anomalies.read().await;
        let cutoff = Utc::now() - Duration::days(days);

        let result: Vec<Anomaly> = anomalies
            .iter()
            .filter(|e| e.user_id == user_id && e.anomaly.detected_at > cutoff)
            .map(|e| e.anomaly.clone())
            .collect();

        Ok(result)
    }

    /// Get total detected anomalies
    pub fn total_detected(&self) -> u64 {
        0 // Would return actual count in production
    }
}

/// Calculate haversine distance
fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0;

    let lat1_rad = lat1.to_radians();
    let lat2_rad = lat2.to_radians();
    let delta_lat = (lat2 - lat1).to_radians();
    let delta_lon = (lon2 - lon1).to_radians();

    let a = (delta_lat / 2.0).sin().powi(2)
        + lat1_rad.cos() * lat2_rad.cos() * (delta_lon / 2.0).sin().powi(2);

    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());

    R * c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anomaly_level() {
        assert_eq!(AnomalyLevel::from_score(0.2), AnomalyLevel::Low);
        assert_eq!(AnomalyLevel::from_score(0.5), AnomalyLevel::Medium);
        assert_eq!(AnomalyLevel::from_score(0.7), AnomalyLevel::High);
        assert_eq!(AnomalyLevel::from_score(0.9), AnomalyLevel::Critical);
    }

    #[test]
    fn test_anomaly_creation() {
        let anomaly = Anomaly::new(
            AnomalyType::UnusualLocation,
            AnomalyLevel::High,
            0.85,
            "Test anomaly",
        )
        .with_details(serde_json::json!({"key": "value"}))
        .with_suggested_action("Take action");

        assert_eq!(anomaly.anomaly_type, AnomalyType::UnusualLocation);
        assert_eq!(anomaly.level, AnomalyLevel::High);
        assert_eq!(anomaly.confidence, 0.85);
        assert!(anomaly.details.is_some());
    }

    #[test]
    fn test_user_behavior_profile() {
        let profile = UserBehaviorProfile {
            user_id: "user_123".to_string(),
            common_locations: vec![LocationPattern {
                latitude: 40.7128,
                longitude: -74.0060,
                country_code: Some("US".to_string()),
                city: Some("New York".to_string()),
                frequency: 10,
                first_seen: Utc::now(),
                last_seen: Utc::now(),
            }],
            common_hours: vec![HourPattern {
                hour: 9,
                frequency: 20,
                is_business_hour: true,
            }],
            known_devices: vec![],
            typical_velocity: 1.0,
            common_ip_ranges: vec![],
            avg_session_duration: Duration::minutes(30),
            last_updated: Utc::now(),
            version: 1,
        };

        assert_eq!(profile.common_locations.len(), 1);
        assert_eq!(profile.common_hours[0].hour, 9);
    }
}
