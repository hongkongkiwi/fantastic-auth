//! Risk-Based Authentication Module
//!
//! Analyzes login context and triggers additional verification for suspicious attempts.
//! Calculates risk scores (0-100) based on multiple factors including device, location,
//! IP reputation, time patterns, velocity, and credential security.
//!
//! Risk Score Thresholds:
//! - 0-30: Low risk - Allow
//! - 31-60: Medium risk - Step-up auth (MFA)
//! - 61-80: High risk - Challenge (CAPTCHA + email verification)
//! - 81-100: Critical risk - Block

pub mod actions;
pub mod factors;
pub mod scoring;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

pub use actions::{RiskAction, RiskActionExecutor};
pub use factors::{RiskFactor, RiskFactorResult};
pub use scoring::{RiskScore, RiskScoringEngine, ScoringWeights};

use crate::db::Database;
use crate::security::{
    DeviceFingerprinter, FingerprintComponents, GeoIpLookup, GeoIpLookupResult,
};

/// Risk assessment result for a login attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Unique assessment ID
    pub id: String,
    /// Overall risk score (0-100)
    pub score: RiskScore,
    /// Individual risk factors with their contributions
    pub factors: Vec<RiskFactorResult>,
    /// Recommended action based on score
    pub action: RiskAction,
    /// Timestamp of assessment
    pub timestamp: DateTime<Utc>,
    /// User ID (if known)
    pub user_id: Option<String>,
    /// Tenant ID
    pub tenant_id: String,
    /// IP address of the request
    pub ip_address: Option<String>,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Whether this assessment was stored
    pub stored: bool,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

impl RiskAssessment {
    /// Create a new risk assessment
    pub fn new(
        score: RiskScore,
        factors: Vec<RiskFactorResult>,
        action: RiskAction,
        tenant_id: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            score,
            factors,
            action,
            timestamp: Utc::now(),
            user_id: None,
            tenant_id: tenant_id.into(),
            ip_address: None,
            device_fingerprint: None,
            stored: false,
            metadata: None,
        }
    }

    /// Set user ID
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Set IP address
    pub fn with_ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set device fingerprint
    pub fn with_device_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.device_fingerprint = Some(fingerprint.into());
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Mark as stored
    pub fn mark_stored(mut self) -> Self {
        self.stored = true;
        self
    }

    /// Get the highest severity factor
    pub fn highest_severity_factor(&self) -> Option<&RiskFactorResult> {
        self.factors.iter().max_by_key(|f| f.contribution)
    }

    /// Check if a specific risk factor is present
    pub fn has_factor(&self, factor_type: &str) -> bool {
        self.factors.iter().any(|f| f.factor.as_str() == factor_type)
    }

    /// Get contribution of a specific factor
    pub fn get_factor_contribution(&self, factor_type: &str) -> Option<u8> {
        self.factors
            .iter()
            .find(|f| f.factor.as_str() == factor_type)
            .map(|f| f.contribution)
    }
}

/// Risk engine configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RiskEngineConfig {
    /// Enable/disable risk-based authentication
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Scoring weights for different factors
    #[serde(default)]
    pub weights: ScoringWeights,
    /// Thresholds for actions
    #[serde(default)]
    pub thresholds: RiskThresholds,
    /// Which risk factors to enable
    #[serde(default)]
    pub enabled_factors: EnabledFactors,
    /// Velocity check window in seconds
    #[serde(default = "default_velocity_window")]
    pub velocity_window_seconds: u64,
    /// Max attempts before velocity risk increases
    #[serde(default = "default_max_velocity_attempts")]
    pub max_velocity_attempts: u32,
    /// Time pattern check: unusual hours start
    #[serde(default = "default_unusual_hours_start")]
    pub unusual_hours_start: u8,
    /// Time pattern check: unusual hours end
    #[serde(default = "default_unusual_hours_end")]
    pub unusual_hours_end: u8,
    /// Geo anomaly: max acceptable distance (km) between logins
    #[serde(default = "default_max_distance_km")]
    pub max_distance_km: f64,
    /// Geo anomaly: min time (hours) between distant logins
    #[serde(default = "default_min_time_between_locations")]
    pub min_time_between_locations: f64,
    /// Device trust duration in days
    #[serde(default = "default_device_trust_days")]
    pub device_trust_days: u32,
}

impl Default for RiskEngineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            weights: ScoringWeights::default(),
            thresholds: RiskThresholds::default(),
            enabled_factors: EnabledFactors::default(),
            velocity_window_seconds: default_velocity_window(),
            max_velocity_attempts: default_max_velocity_attempts(),
            unusual_hours_start: default_unusual_hours_start(),
            unusual_hours_end: default_unusual_hours_end(),
            max_distance_km: default_max_distance_km(),
            min_time_between_locations: default_min_time_between_locations(),
            device_trust_days: default_device_trust_days(),
        }
    }
}

/// Risk score thresholds for different actions
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct RiskThresholds {
    /// Allow login without additional verification (default: 30)
    #[serde(default = "default_low_threshold")]
    pub low: u8,
    /// Require step-up authentication (default: 60)
    #[serde(default = "default_medium_threshold")]
    pub medium: u8,
    /// Require challenge (CAPTCHA + email) (default: 80)
    #[serde(default = "default_high_threshold")]
    pub high: u8,
    /// Block login completely (default: 90)
    #[serde(default = "default_critical_threshold")]
    pub critical: u8,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            low: default_low_threshold(),
            medium: default_medium_threshold(),
            high: default_high_threshold(),
            critical: default_critical_threshold(),
        }
    }
}

impl RiskThresholds {
    /// Determine action based on score
    pub fn action_for_score(&self, score: RiskScore) -> RiskAction {
        let value = score.value();
        if value >= self.critical {
            RiskAction::Block
        } else if value >= self.high {
            RiskAction::Challenge
        } else if value >= self.medium {
            RiskAction::StepUp
        } else {
            RiskAction::Allow
        }
    }
}

/// Enabled/disabled risk factors
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnabledFactors {
    #[serde(default = "default_true")]
    pub device: bool,
    #[serde(default = "default_true")]
    pub location: bool,
    #[serde(default = "default_true")]
    pub ip_reputation: bool,
    #[serde(default = "default_true")]
    pub time: bool,
    #[serde(default = "default_true")]
    pub velocity: bool,
    #[serde(default = "default_true")]
    pub credential: bool,
    #[serde(default = "default_true")]
    pub impossible_travel: bool,
}

impl Default for EnabledFactors {
    fn default() -> Self {
        Self {
            device: true,
            location: true,
            ip_reputation: true,
            time: true,
            velocity: true,
            credential: true,
            impossible_travel: true,
        }
    }
}

/// Login context for risk assessment
#[derive(Debug, Clone, Default)]
pub struct LoginContext {
    /// IP address
    pub ip_address: Option<IpAddr>,
    /// Request headers
    pub headers: HeaderMap,
    /// User agent string
    pub user_agent: Option<String>,
    /// Device fingerprint (if available)
    pub device_fingerprint: Option<String>,
    /// User email (for checking known devices)
    pub email: Option<String>,
    /// User ID (if already known)
    pub user_id: Option<String>,
    /// Previous login timestamp (for impossible travel)
    pub previous_login_at: Option<DateTime<Utc>>,
    /// Previous login location (latitude, longitude)
    pub previous_location: Option<(f64, f64)>,
    /// Current login time
    pub login_time: DateTime<Utc>,
    /// Number of failed attempts recently
    pub failed_attempts: u32,
    /// Whether user has MFA enabled
    pub mfa_enabled: bool,
    /// Tenant ID
    pub tenant_id: String,
}

impl LoginContext {
    /// Create a new login context
    pub fn new(tenant_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            login_time: Utc::now(),
            ..Default::default()
        }
    }

    /// Set IP address
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip_address = Some(ip);
        self
    }

    /// Set headers
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        self.headers = headers;
        self
    }

    /// Set email
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Set user ID
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Set device fingerprint
    pub fn with_device_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.device_fingerprint = Some(fingerprint.into());
        self
    }

    /// Set previous login info for impossible travel detection
    pub fn with_previous_login(
        mut self,
        timestamp: DateTime<Utc>,
        location: Option<(f64, f64)>,
    ) -> Self {
        self.previous_login_at = Some(timestamp);
        self.previous_location = location;
        self
    }

    /// Set failed attempts count
    pub fn with_failed_attempts(mut self, count: u32) -> Self {
        self.failed_attempts = count;
        self
    }

    /// Set MFA enabled status
    pub fn with_mfa_enabled(mut self, enabled: bool) -> Self {
        self.mfa_enabled = enabled;
        self
    }
}

/// Risk engine for analyzing login attempts
pub struct RiskEngine {
    /// Configuration
    config: RiskEngineConfig,
    /// Scoring engine
    scoring_engine: RiskScoringEngine,
    /// Device fingerprinter
    fingerprinter: DeviceFingerprinter,
    /// GeoIP lookup service (optional)
    geoip: Option<Arc<dyn GeoIpLookup>>,
    /// Database for persistence
    db: Database,
    /// Velocity tracking cache
    velocity_cache: Arc<RwLock<HashMap<String, VelocityEntry>>>,
}

#[derive(Debug, Clone)]
struct VelocityEntry {
    count: u32,
    window_start: DateTime<Utc>,
}

impl RiskEngine {
    /// Create a new risk engine
    pub fn new(
        config: RiskEngineConfig,
        db: Database,
        geoip: Option<Arc<dyn GeoIpLookup>>,
    ) -> Self {
        let scoring_engine = RiskScoringEngine::new(config.weights.clone());

        Self {
            config,
            scoring_engine,
            fingerprinter: DeviceFingerprinter::new(),
            geoip,
            db,
            velocity_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create with default configuration
    pub fn default_with_db(db: Database) -> Self {
        Self::new(RiskEngineConfig::default(), db, None)
    }

    /// Assess risk for a login attempt
    pub async fn assess(&self, context: LoginContext) -> RiskAssessment {
        if !self.config.enabled {
            return RiskAssessment::new(
                RiskScore::new(0),
                vec![],
                RiskAction::Allow,
                &context.tenant_id,
            );
        }

        debug!("Starting risk assessment for login attempt");

        let mut factors = Vec::new();

        // Collect device fingerprint if not provided
        let device_fingerprint = if let Some(ref fp) = context.device_fingerprint {
            Some(fp.clone())
        } else {
            self.fingerprinter
                .generate_from_headers(&context.headers, context.ip_address)
        };

        // Get GeoIP info if available
        let geo_info = if let (Some(ref geoip), Some(ip)) = (&self.geoip, context.ip_address) {
            match geoip.lookup(ip).await {
                Ok(info) => {
                    debug!("GeoIP lookup successful for {}", ip);
                    Some(info)
                }
                Err(e) => {
                    warn!("GeoIP lookup failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Evaluate device risk
        if self.config.enabled_factors.device {
            let device_factor = self.assess_device_risk(&context, &device_fingerprint).await;
            factors.push(device_factor);
        }

        // Evaluate location risk
        if self.config.enabled_factors.location {
            let location_factor =
                self.assess_location_risk(&context, geo_info.as_ref()).await;
            factors.push(location_factor);
        }

        // Evaluate IP reputation risk
        if self.config.enabled_factors.ip_reputation {
            let ip_factor = self.assess_ip_reputation_risk(&context, geo_info.as_ref()).await;
            factors.push(ip_factor);
        }

        // Evaluate time risk
        if self.config.enabled_factors.time {
            let time_factor = self.assess_time_risk(&context).await;
            factors.push(time_factor);
        }

        // Evaluate velocity risk
        if self.config.enabled_factors.velocity {
            let velocity_factor = self.assess_velocity_risk(&context).await;
            factors.push(velocity_factor);
        }

        // Evaluate impossible travel
        if self.config.enabled_factors.impossible_travel {
            let travel_factor = self
                .assess_impossible_travel(&context, geo_info.as_ref())
                .await;
            factors.push(travel_factor);
        }

        // Calculate overall score
        let score = self.scoring_engine.calculate_score(&factors);

        // Determine action
        let action = self.config.thresholds.action_for_score(score);

        info!(
            score = score.value(),
            action = ?action,
            factor_count = factors.len(),
            "Risk assessment complete"
        );

        // Build assessment
        let assessment = RiskAssessment::new(
            score,
            factors,
            action,
            &context.tenant_id,
        )
        .with_user_id(context.user_id.unwrap_or_default())
        .with_ip_address(context.ip_address.map(|ip| ip.to_string()).unwrap_or_default())
        .with_device_fingerprint(device_fingerprint.unwrap_or_default());

        // Store assessment in database (async, fire-and-forget)
        self.store_assessment(&assessment).await;

        assessment
    }

    /// Assess device risk
    async fn assess_device_risk(
        &self,
        context: &LoginContext,
        device_fingerprint: &Option<String>,
    ) -> RiskFactorResult {
        use factors::{DeviceRiskFactor, KnownDeviceChecker};

        let checker = KnownDeviceChecker::new(&self.db);
        let factor = DeviceRiskFactor::new(checker, self.config.device_trust_days);

        factor
            .assess(context.user_id.as_deref(), device_fingerprint.as_deref())
            .await
    }

    /// Assess location risk
    async fn assess_location_risk(
        &self,
        _context: &LoginContext,
        geo_info: Option<&GeoIpLookupResult>,
    ) -> RiskFactorResult {
        use factors::LocationRiskFactor;

        let factor = LocationRiskFactor::new();
        factor.assess(geo_info).await
    }

    /// Assess IP reputation risk
    async fn assess_ip_reputation_risk(
        &self,
        _context: &LoginContext,
        geo_info: Option<&GeoIpLookupResult>,
    ) -> RiskFactorResult {
        use factors::IpReputationFactor;

        let factor = IpReputationFactor::new();
        factor.assess(geo_info).await
    }

    /// Assess time-based risk
    async fn assess_time_risk(&self, context: &LoginContext) -> RiskFactorResult {
        use factors::TimeRiskFactor;

        let factor = TimeRiskFactor::new(
            self.config.unusual_hours_start,
            self.config.unusual_hours_end,
        );
        factor.assess(context.login_time).await
    }

    /// Assess velocity risk
    async fn assess_velocity_risk(&self, context: &LoginContext) -> RiskFactorResult {
        use factors::VelocityRiskFactor;

        let factor = VelocityRiskFactor::new(
            self.config.velocity_window_seconds,
            self.config.max_velocity_attempts,
            Arc::clone(&self.velocity_cache),
        );

        let key = format!(
            "{}:{}",
            context.tenant_id,
            context.email.as_deref().unwrap_or("unknown")
        );

        factor
            .assess(&key, context.failed_attempts, context.login_time)
            .await
    }

    /// Assess impossible travel risk
    async fn assess_impossible_travel(
        &self,
        context: &LoginContext,
        geo_info: Option<&GeoIpLookupResult>,
    ) -> RiskFactorResult {
        use factors::ImpossibleTravelFactor;

        let factor = ImpossibleTravelFactor::new(
            self.config.max_distance_km,
            self.config.min_time_between_locations,
        );

        let current_location = geo_info.as_ref().and_then(|g| {
            // Note: GeoIP lookup doesn't typically return lat/long directly
            // This would need a more detailed GeoIP service
            None
        });

        factor
            .assess(
                context.previous_login_at,
                context.previous_location,
                current_location,
            )
            .await
    }

    /// Store assessment in database for audit
    async fn store_assessment(&self, assessment: &RiskAssessment) {
        // Fire-and-forget storage
        let db = self.db.clone();
        let assessment = assessment.clone();

        tokio::spawn(async move {
            if let Err(e) = Self::save_assessment_to_db(&db, &assessment).await {
                tracing::error!("Failed to store risk assessment: {}", e);
            }
        });
    }

    /// Save assessment to database
    async fn save_assessment_to_db(
        db: &Database,
        assessment: &RiskAssessment,
    ) -> anyhow::Result<()> {
        let mut conn = db.pool().acquire().await?;

        sqlx::query(
            r#"INSERT INTO risk_assessments 
               (id, tenant_id, user_id, score, action, factors, ip_address, 
                device_fingerprint, timestamp, metadata)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(&assessment.id)
        .bind(&assessment.tenant_id)
        .bind(&assessment.user_id)
        .bind(assessment.score.value() as i16)
        .bind(assessment.action.as_str())
        .bind(serde_json::to_value(&assessment.factors)?)
        .bind(&assessment.ip_address)
        .bind(&assessment.device_fingerprint)
        .bind(assessment.timestamp)
        .bind(&assessment.metadata)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Update configuration
    pub fn update_config(&mut self, config: RiskEngineConfig) {
        self.config = config.clone();
        self.scoring_engine = RiskScoringEngine::new(config.weights);
    }

    /// Get current configuration
    pub fn config(&self) -> &RiskEngineConfig {
        &self.config
    }

    /// Get recent risk assessments for a user
    pub async fn get_user_assessments(
        &self,
        tenant_id: &str,
        user_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<RiskAssessment>> {
        let mut conn = self.db.pool().acquire().await?;

        let rows = sqlx::query_as::<_, RiskAssessmentRow>(
            r#"SELECT id, tenant_id, user_id, score, action, factors, ip_address,
                      device_fingerprint, timestamp, metadata
               FROM risk_assessments 
               WHERE tenant_id = $1 AND user_id = $2
               ORDER BY timestamp DESC
               LIMIT $3"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Get risk analytics for a tenant
    pub async fn get_tenant_analytics(
        &self,
        tenant_id: &str,
        days: i32,
    ) -> anyhow::Result<RiskAnalytics> {
        let mut conn = self.db.pool().acquire().await?;

        let row = sqlx::query_as::<_, RiskAnalyticsRow>(
            r#"SELECT 
                COUNT(*) as total_assessments,
                AVG(score) as avg_score,
                COUNT(CASE WHEN action = 'block' THEN 1 END) as blocked_count,
                COUNT(CASE WHEN action = 'challenge' THEN 1 END) as challenged_count,
                COUNT(CASE WHEN action = 'step_up' THEN 1 END) as step_up_count,
                COUNT(CASE WHEN action = 'allow' THEN 1 END) as allowed_count
            FROM risk_assessments 
            WHERE tenant_id = $1 AND timestamp > NOW() - INTERVAL '$2 days'"#,
        )
        .bind(tenant_id)
        .bind(days)
        .fetch_one(&mut *conn)
        .await?;

        Ok(RiskAnalytics {
            total_assessments: row.total_assessments,
            average_score: row.avg_score.unwrap_or(0.0) as f32,
            blocked_count: row.blocked_count,
            challenged_count: row.challenged_count,
            step_up_count: row.step_up_count,
            allowed_count: row.allowed_count,
        })
    }
}

/// Risk analytics for a tenant
#[derive(Debug, Clone, Serialize)]
pub struct RiskAnalytics {
    pub total_assessments: i64,
    pub average_score: f32,
    pub blocked_count: i64,
    pub challenged_count: i64,
    pub step_up_count: i64,
    pub allowed_count: i64,
}

impl RiskAnalytics {
    /// Calculate block rate percentage
    pub fn block_rate(&self) -> f32 {
        if self.total_assessments == 0 {
            0.0
        } else {
            (self.blocked_count as f32 / self.total_assessments as f32) * 100.0
        }
    }

    /// Calculate challenge rate percentage
    pub fn challenge_rate(&self) -> f32 {
        if self.total_assessments == 0 {
            0.0
        } else {
            (self.challenged_count as f32 / self.total_assessments as f32) * 100.0
        }
    }
}

// Database rows for queries - public for use in admin routes
#[derive(sqlx::FromRow)]
pub struct RiskAssessmentRow {
    pub id: String,
    pub tenant_id: String,
    pub user_id: Option<String>,
    pub score: i16,
    pub action: String,
    pub factors: serde_json::Value,
    pub ip_address: Option<String>,
    pub device_fingerprint: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

impl From<RiskAssessmentRow> for RiskAssessment {
    fn from(row: RiskAssessmentRow) -> Self {
        let factors: Vec<RiskFactorResult> =
            serde_json::from_value(row.factors).unwrap_or_default();

        RiskAssessment {
            id: row.id,
            score: RiskScore::new(row.score as u8),
            factors,
            action: RiskAction::from_str(&row.action),
            timestamp: row.timestamp,
            user_id: row.user_id,
            tenant_id: row.tenant_id,
            ip_address: row.ip_address,
            device_fingerprint: row.device_fingerprint,
            stored: true,
            metadata: row.metadata,
        }
    }
}

#[derive(sqlx::FromRow)]
pub struct RiskAnalyticsRow {
    pub total_assessments: i64,
    pub avg_score: Option<f64>,
    pub blocked_count: i64,
    pub challenged_count: i64,
    pub step_up_count: i64,
    pub allowed_count: i64,
}

// Default functions
fn default_true() -> bool {
    true
}
fn default_velocity_window() -> u64 {
    300
} // 5 minutes
fn default_max_velocity_attempts() -> u32 {
    5
}
fn default_unusual_hours_start() -> u8 {
    23
} // 11 PM
fn default_unusual_hours_end() -> u8 {
    5
} // 5 AM
fn default_max_distance_km() -> f64 {
    500.0
}
fn default_min_time_between_locations() -> f64 {
    2.0
} // 2 hours
fn default_device_trust_days() -> u32 {
    30
}
fn default_low_threshold() -> u8 {
    30
}
fn default_medium_threshold() -> u8 {
    60
}
fn default_high_threshold() -> u8 {
    80
}
fn default_critical_threshold() -> u8 {
    90
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_thresholds() {
        let thresholds = RiskThresholds::default();

        assert_eq!(thresholds.action_for_score(RiskScore::new(20)), RiskAction::Allow);
        assert_eq!(thresholds.action_for_score(RiskScore::new(45)), RiskAction::StepUp);
        assert_eq!(
            thresholds.action_for_score(RiskScore::new(75)),
            RiskAction::Challenge
        );
        assert_eq!(thresholds.action_for_score(RiskScore::new(95)), RiskAction::Block);
    }

    #[test]
    fn test_risk_score_bounds() {
        assert_eq!(RiskScore::new(0).value(), 0);
        assert_eq!(RiskScore::new(100).value(), 100);
        assert_eq!(RiskScore::new(150).value(), 100); // Clamped
    }

    #[test]
    fn test_login_context_builder() {
        let context = LoginContext::new("tenant-123")
            .with_ip("192.168.1.1".parse().unwrap())
            .with_email("user@example.com")
            .with_user_id("user-123")
            .with_failed_attempts(3)
            .with_mfa_enabled(true);

        assert_eq!(context.tenant_id, "tenant-123");
        assert_eq!(context.email, Some("user@example.com".to_string()));
        assert_eq!(context.user_id, Some("user-123".to_string()));
        assert_eq!(context.failed_attempts, 3);
        assert!(context.mfa_enabled);
    }
}
