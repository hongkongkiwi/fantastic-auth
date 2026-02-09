//! Feature extraction for ML models
//!
//! This module extracts features from authentication contexts for use in ML models.
//! Features are normalized and encoded for optimal model performance.

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

use super::error::{AiError, AiResult};

/// Authentication context for feature extraction
#[derive(Debug, Clone, Default)]
pub struct AuthContext {
    /// User ID (if known)
    pub user_id: Option<String>,
    /// IP address
    pub ip_address: Option<IpAddr>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Geographic location (latitude, longitude)
    pub geo_location: Option<(f64, f64)>,
    /// Country code
    pub country_code: Option<String>,
    /// Whether IP is from VPN/Tor/proxy
    pub is_anonymous_ip: bool,
    /// Whether IP is from hosting provider
    pub is_hosting_provider: bool,
    /// Previous login location
    pub previous_location: Option<(f64, f64)>,
    /// Previous login timestamp
    pub previous_login_at: Option<DateTime<Utc>>,
    /// Number of failed attempts recently
    pub failed_attempts: u32,
    /// Number of successful logins recently
    pub successful_attempts: u32,
    /// Whether MFA was used
    pub mfa_used: bool,
    /// Tenant ID
    pub tenant_id: String,
    /// Behavioral biometrics data
    pub behavioral_data: Option<super::behavioral::BehavioralData>,
    /// Headers from the request
    pub headers: HashMap<String, String>,
    /// Session ID (if exists)
    pub session_id: Option<String>,
    /// Authentication method used
    pub auth_method: AuthMethod,
}

/// Authentication method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AuthMethod {
    #[default]
    Password,
    OAuth,
    Saml,
    WebAuthn,
    Totp,
    EmailOtp,
    MagicLink,
    Biometric,
    ApiKey,
}

impl AuthMethod {
    /// Convert to feature value
    pub fn as_feature(&self) -> f64 {
        match self {
            AuthMethod::Password => 0.0,
            AuthMethod::OAuth => 1.0,
            AuthMethod::Saml => 2.0,
            AuthMethod::WebAuthn => 3.0,
            AuthMethod::Totp => 4.0,
            AuthMethod::EmailOtp => 5.0,
            AuthMethod::MagicLink => 6.0,
            AuthMethod::Biometric => 7.0,
            AuthMethod::ApiKey => 8.0,
        }
    }
}

/// Extracted feature vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    /// Raw feature values
    pub values: Vec<f64>,
    /// Feature names (for debugging/interpretation)
    pub names: Vec<String>,
    /// Feature version for model compatibility
    pub version: String,
}

impl FeatureVector {
    /// Create new feature vector
    pub fn new(values: Vec<f64>, names: Vec<String>) -> Self {
        Self {
            values,
            names,
            version: "1.0".to_string(),
        }
    }

    /// Get feature by name
    pub fn get(&self, name: &str) -> Option<f64> {
        self.names
            .iter()
            .position(|n| n == name)
            .map(|idx| self.values[idx])
    }

    /// Normalize all features to 0-1 range
    pub fn normalize(&mut self) {
        for val in &mut self.values {
            *val = val.clamp(0.0, 1.0);
        }
    }
}

/// Feature extractor for authentication contexts
pub struct FeatureExtractor;

impl FeatureExtractor {
    /// Extract complete feature vector from auth context
    pub fn extract(context: &AuthContext) -> AiResult<FeatureVector> {
        let mut values = Vec::new();
        let mut names = Vec::new();

        // Time-based features
        let time_features = TimeFeatures::extract(context);
        values.extend(time_features.to_vec());
        names.extend(time_features.names());

        // Geographic features
        let geo_features = GeoFeatures::extract(context)?;
        values.extend(geo_features.to_vec());
        names.extend(geo_features.names());

        // Device features
        let device_features = DeviceFeatures::extract(context)?;
        values.extend(device_features.to_vec());
        names.extend(device_features.names());

        // Velocity features
        let velocity_features = VelocityFeatures::extract(context);
        values.extend(velocity_features.to_vec());
        names.extend(velocity_features.names());

        // Auth method
        values.push(context.auth_method.as_feature() / 8.0); // Normalize to 0-1
        names.push("auth_method".to_string());

        // MFA used
        values.push(if context.mfa_used { 1.0 } else { 0.0 });
        names.push("mfa_used".to_string());

        // Anonymous IP
        values.push(if context.is_anonymous_ip { 1.0 } else { 0.0 });
        names.push("is_anonymous_ip".to_string());

        // Hosting provider
        values.push(if context.is_hosting_provider {
            1.0
        } else {
            0.0
        });
        names.push("is_hosting_provider".to_string());

        Ok(FeatureVector::new(values, names))
    }

    /// Extract lightweight features for real-time scoring
    pub fn extract_lightweight(context: &AuthContext) -> AiResult<FeatureVector> {
        let mut values = Vec::with_capacity(20);
        let mut names = Vec::with_capacity(20);

        // Hour of day (normalized)
        let hour = context.timestamp.hour() as f64 / 23.0;
        values.push(hour);
        names.push("hour".to_string());

        // Day of week (normalized)
        let day = context.timestamp.weekday().num_days_from_monday() as f64 / 6.0;
        values.push(day);
        names.push("day_of_week".to_string());

        // Weekend flag
        let is_weekend = matches!(
            context.timestamp.weekday(),
            chrono::Weekday::Sat | chrono::Weekday::Sun
        ) as i32 as f64;
        values.push(is_weekend);
        names.push("is_weekend".to_string());

        // Failed attempts (capped and normalized)
        let failed = (context.failed_attempts.min(10) as f64) / 10.0;
        values.push(failed);
        names.push("failed_attempts".to_string());

        // Anonymous IP
        values.push(if context.is_anonymous_ip { 1.0 } else { 0.0 });
        names.push("is_anonymous_ip".to_string());

        // Hosting provider
        values.push(if context.is_hosting_provider {
            1.0
        } else {
            0.0
        });
        names.push("is_hosting_provider".to_string());

        // MFA used
        values.push(if context.mfa_used { 1.0 } else { 0.0 });
        names.push("mfa_used".to_string());

        // Auth method
        values.push(context.auth_method.as_feature() / 8.0);
        names.push("auth_method".to_string());

        // Has previous location (binary)
        values.push(if context.previous_location.is_some() {
            1.0
        } else {
            0.0
        });
        names.push("has_previous_location".to_string());

        // Time since last login (normalized, capped at 30 days)
        if let Some(prev) = context.previous_login_at {
            let hours_since = (context.timestamp - prev).num_hours() as f64;
            let normalized = (hours_since / (30.0 * 24.0)).min(1.0);
            values.push(normalized);
        } else {
            values.push(1.0); // No previous login = high value
        }
        names.push("hours_since_last_login".to_string());

        Ok(FeatureVector::new(values, names))
    }
}

/// Time-based features
#[derive(Debug, Clone)]
pub struct TimeFeatures {
    /// Hour of day (0-23)
    pub hour: u8,
    /// Day of week (0-6)
    pub day_of_week: u8,
    /// Month (1-12)
    pub month: u8,
    /// Is weekend
    pub is_weekend: bool,
    /// Is night time (11 PM - 5 AM)
    pub is_night: bool,
    /// Is business hours (9 AM - 5 PM, weekdays)
    pub is_business_hours: bool,
}

impl TimeFeatures {
    /// Extract time features from context
    pub fn extract(context: &AuthContext) -> Self {
        let dt = context.timestamp;
        let hour = dt.hour() as u8;
        let day_of_week = dt.weekday().num_days_from_monday() as u8;
        let is_weekend = day_of_week == 5 || day_of_week == 6; // Sat=5, Sun=6 in chrono
        let is_night = hour >= 23 || hour < 5;
        let is_business_hours = !is_weekend && (hour >= 9 && hour < 17);

        Self {
            hour,
            day_of_week,
            month: dt.month() as u8,
            is_weekend,
            is_night,
            is_business_hours,
        }
    }

    /// Convert to feature vector (normalized)
    pub fn to_vec(&self) -> Vec<f64> {
        vec![
            self.hour as f64 / 23.0,
            self.day_of_week as f64 / 6.0,
            self.month as f64 / 12.0,
            if self.is_weekend { 1.0 } else { 0.0 },
            if self.is_night { 1.0 } else { 0.0 },
            if self.is_business_hours { 1.0 } else { 0.0 },
        ]
    }

    /// Get feature names
    pub fn names(&self) -> Vec<String> {
        vec![
            "hour".to_string(),
            "day_of_week".to_string(),
            "month".to_string(),
            "is_weekend".to_string(),
            "is_night".to_string(),
            "is_business_hours".to_string(),
        ]
    }
}

/// Geographic features
#[derive(Debug, Clone)]
pub struct GeoFeatures {
    /// Latitude (-90 to 90)
    pub latitude: Option<f64>,
    /// Longitude (-180 to 180)
    pub longitude: Option<f64>,
    /// Distance from last login (km)
    pub distance_from_last: Option<f64>,
    /// Time since last login (hours)
    pub time_since_last_hours: Option<f64>,
    /// Is impossible travel
    pub is_impossible_travel: bool,
    /// Country risk score (0-1)
    pub country_risk: f64,
}

impl GeoFeatures {
    /// Extract geographic features
    pub fn extract(context: &AuthContext) -> AiResult<Self> {
        let (lat, lon) = context.geo_location.unzip();

        let mut distance_from_last = None;
        let mut time_since_last_hours = None;
        let mut is_impossible_travel = false;

        if let (Some((curr_lat, curr_lon)), Some((prev_lat, prev_lon))) =
            (context.geo_location, context.previous_location)
        {
            let distance = haversine_distance(curr_lat, curr_lon, prev_lat, prev_lon);
            distance_from_last = Some(distance);

            if let Some(prev_time) = context.previous_login_at {
                let hours = (context.timestamp - prev_time).num_hours() as f64;
                time_since_last_hours = Some(hours);

                // Check for impossible travel (> 900 km/h)
                if hours > 0.0 {
                    let speed = distance / hours;
                    if speed > 900.0 {
                        is_impossible_travel = true;
                    }
                }
            }
        }

        // Country risk (placeholder - would use actual country risk scores)
        let country_risk = if context.country_code.as_deref() == Some("CN")
            || context.country_code.as_deref() == Some("RU")
            || context.country_code.as_deref() == Some("KP")
        {
            0.7 // Higher risk countries
        } else {
            0.3
        };

        Ok(Self {
            latitude: lat,
            longitude: lon,
            distance_from_last,
            time_since_last_hours,
            is_impossible_travel,
            country_risk,
        })
    }

    /// Convert to feature vector
    pub fn to_vec(&self) -> Vec<f64> {
        vec![
            self.latitude.map(|l| (l + 90.0) / 180.0).unwrap_or(0.5),
            self.longitude.map(|l| (l + 180.0) / 360.0).unwrap_or(0.5),
            self.distance_from_last
                .map(|d| (d / 20000.0).min(1.0))
                .unwrap_or(0.0),
            self.time_since_last_hours
                .map(|h| (h / 720.0).min(1.0))
                .unwrap_or(1.0),
            if self.is_impossible_travel { 1.0 } else { 0.0 },
            self.country_risk,
        ]
    }

    /// Get feature names
    pub fn names(&self) -> Vec<String> {
        vec![
            "latitude".to_string(),
            "longitude".to_string(),
            "distance_from_last".to_string(),
            "time_since_last".to_string(),
            "is_impossible_travel".to_string(),
            "country_risk".to_string(),
        ]
    }
}

/// Device features
#[derive(Debug, Clone)]
pub struct DeviceFeatures {
    /// Is new device (no previous fingerprint)
    pub is_new_device: bool,
    /// Device trust score (0-1)
    pub device_trust: f64,
    /// Has cookie
    pub has_cookie: bool,
    /// Is mobile device
    pub is_mobile: bool,
    /// Browser type encoded
    pub browser_type: f64,
    /// OS type encoded
    pub os_type: f64,
}

impl DeviceFeatures {
    /// Extract device features
    pub fn extract(context: &AuthContext) -> AiResult<Self> {
        let user_agent = context.user_agent.as_deref().unwrap_or("");

        // Parse user agent for device info
        let is_mobile = user_agent.to_lowercase().contains("mobile")
            || user_agent.contains("Android")
            || user_agent.contains("iPhone");

        // Detect browser
        let browser_type = if user_agent.contains("Chrome") {
            0.0
        } else if user_agent.contains("Firefox") {
            0.2
        } else if user_agent.contains("Safari") {
            0.4
        } else if user_agent.contains("Edge") {
            0.6
        } else {
            0.8 // Other/unknown
        };

        // Detect OS
        let os_type = if user_agent.contains("Windows") {
            0.0
        } else if user_agent.contains("Mac") {
            0.25
        } else if user_agent.contains("Linux") {
            0.5
        } else if user_agent.contains("Android") {
            0.75
        } else if user_agent.contains("iPhone") || user_agent.contains("iPad") {
            1.0
        } else {
            0.5 // Unknown
        };

        let is_new_device = context.device_fingerprint.is_none();
        let has_cookie = context.headers.contains_key("cookie");

        Ok(Self {
            is_new_device,
            device_trust: if is_new_device { 0.0 } else { 0.8 },
            has_cookie,
            is_mobile,
            browser_type,
            os_type,
        })
    }

    /// Convert to feature vector
    pub fn to_vec(&self) -> Vec<f64> {
        vec![
            if self.is_new_device { 1.0 } else { 0.0 },
            self.device_trust,
            if self.has_cookie { 1.0 } else { 0.0 },
            if self.is_mobile { 1.0 } else { 0.0 },
            self.browser_type,
            self.os_type,
        ]
    }

    /// Get feature names
    pub fn names(&self) -> Vec<String> {
        vec![
            "is_new_device".to_string(),
            "device_trust".to_string(),
            "has_cookie".to_string(),
            "is_mobile".to_string(),
            "browser_type".to_string(),
            "os_type".to_string(),
        ]
    }
}

/// Velocity features
#[derive(Debug, Clone)]
pub struct VelocityFeatures {
    /// Failed attempts in last hour
    pub failed_last_hour: u32,
    /// Failed attempts in last 5 minutes
    pub failed_last_5min: u32,
    /// Successful attempts in last hour
    pub success_last_hour: u32,
    /// Unique IPs in last hour
    pub unique_ips_last_hour: u32,
    /// Unique devices in last hour
    pub unique_devices_last_hour: u32,
}

impl VelocityFeatures {
    /// Extract velocity features
    pub fn extract(context: &AuthContext) -> Self {
        Self {
            failed_last_hour: context.failed_attempts,
            failed_last_5min: context.failed_attempts.min(10),
            success_last_hour: context.successful_attempts,
            unique_ips_last_hour: 1,     // Would be calculated from DB
            unique_devices_last_hour: 1, // Would be calculated from DB
        }
    }

    /// Convert to feature vector
    pub fn to_vec(&self) -> Vec<f64> {
        vec![
            (self.failed_last_hour.min(20) as f64) / 20.0,
            (self.failed_last_5min.min(10) as f64) / 10.0,
            (self.success_last_hour.min(20) as f64) / 20.0,
            (self.unique_ips_last_hour.min(10) as f64) / 10.0,
            (self.unique_devices_last_hour.min(10) as f64) / 10.0,
        ]
    }

    /// Get feature names
    pub fn names(&self) -> Vec<String> {
        vec![
            "failed_last_hour".to_string(),
            "failed_last_5min".to_string(),
            "success_last_hour".to_string(),
            "unique_ips".to_string(),
            "unique_devices".to_string(),
        ]
    }
}

/// Calculate haversine distance between two points in km
fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0; // Earth's radius in km

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
    fn test_time_features() {
        let context = AuthContext {
            timestamp: Utc::now(),
            ..Default::default()
        };

        let features = TimeFeatures::extract(&context);
        assert!(features.hour <= 23);
        assert!(features.day_of_week <= 6);
    }

    #[test]
    fn test_haversine_distance() {
        // NYC to London
        let nyc_lat = 40.7128;
        let nyc_lon = -74.0060;
        let london_lat = 51.5074;
        let london_lon = -0.1278;

        let distance = haversine_distance(nyc_lat, nyc_lon, london_lat, london_lon);
        assert!(distance > 5500.0 && distance < 5600.0);
    }

    #[test]
    fn test_feature_vector() {
        let mut fv = FeatureVector::new(
            vec![0.5, 0.3, 0.8],
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
        );

        assert_eq!(fv.get("a"), Some(0.5));
        assert_eq!(fv.get("b"), Some(0.3));
        assert_eq!(fv.get("z"), None);

        fv.normalize();
        assert_eq!(fv.values[0], 0.5); // Already in range
    }

    #[test]
    fn test_auth_method_features() {
        assert_eq!(AuthMethod::Password.as_feature(), 0.0);
        assert_eq!(AuthMethod::WebAuthn.as_feature(), 3.0);
        assert_eq!(AuthMethod::ApiKey.as_feature(), 8.0);
    }
}
