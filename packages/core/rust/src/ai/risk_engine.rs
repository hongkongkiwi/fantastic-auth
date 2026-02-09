//! Real-Time Risk Scoring Engine
//!
//! This module provides ML-enhanced risk scoring for authentication attempts.
//! It combines rule-based scoring with ML predictions for accurate risk assessment.

use std::collections::HashMap;

use std::sync::Arc;

use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::error::AiResult;
use super::features::{AuthContext, FeatureExtractor, FeatureVector};
use super::ml_models::{EnsembleResult, ModelManager};
use super::AiSecurityConfig;
use crate::db::DbContext;

/// Risk level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Low risk (0-30)
    Low,
    /// Medium risk (31-60)
    Medium,
    /// High risk (61-80)
    High,
    /// Critical risk (81-100)
    Critical,
}

impl RiskLevel {
    /// Convert score to risk level
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=30 => RiskLevel::Low,
            31..=60 => RiskLevel::Medium,
            61..=80 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    /// Get risk level as string
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }

    /// Check if this level requires MFA
    pub fn requires_mfa(&self) -> bool {
        matches!(
            self,
            RiskLevel::Medium | RiskLevel::High | RiskLevel::Critical
        )
    }

    /// Check if this level should be blocked
    pub fn should_block(&self) -> bool {
        matches!(self, RiskLevel::Critical)
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Risk score with detailed information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Numeric score (0-100)
    pub score: u8,
    /// Risk level
    pub level: RiskLevel,
    /// Individual risk factors
    pub factors: Vec<RiskFactor>,
    /// ML confidence (0-1)
    pub ml_confidence: f64,
    /// Whether ML was used
    pub ml_enhanced: bool,
    /// Timestamp of scoring
    pub timestamp: DateTime<Utc>,
}

impl RiskScore {
    /// Create new risk score
    pub fn new(score: u8, factors: Vec<RiskFactor>) -> Self {
        let score = score.min(100);
        Self {
            score,
            level: RiskLevel::from_score(score),
            factors,
            ml_confidence: 0.0,
            ml_enhanced: false,
            timestamp: Utc::now(),
        }
    }

    /// Create with ML enhancement
    pub fn with_ml(mut self, confidence: f64) -> Self {
        self.ml_enhanced = true;
        self.ml_confidence = confidence;
        self
    }

    /// Check if score is above threshold
    pub fn above_threshold(&self, threshold: u8) -> bool {
        self.score >= threshold
    }

    /// Get highest contributing factor
    pub fn highest_factor(&self) -> Option<&RiskFactor> {
        self.factors.iter().max_by_key(|f| f.contribution)
    }

    /// Check if specific factor type is present
    pub fn has_factor(&self, factor_type: &str) -> bool {
        self.factors.iter().any(|f| f.factor_type == factor_type)
    }
}

/// Individual risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Factor type identifier
    pub factor_type: String,
    /// Risk contribution (0-100)
    pub contribution: u8,
    /// Human-readable description
    pub description: String,
    /// Raw value before scaling
    pub raw_value: Option<f64>,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

impl RiskFactor {
    /// Create new risk factor
    pub fn new(
        factor_type: impl Into<String>,
        contribution: u8,
        description: impl Into<String>,
    ) -> Self {
        Self {
            factor_type: factor_type.into(),
            contribution: contribution.min(100),
            description: description.into(),
            raw_value: None,
            metadata: None,
        }
    }

    /// Add raw value
    pub fn with_raw_value(mut self, value: f64) -> Self {
        self.raw_value = Some(value);
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

/// Action to take based on risk
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Allow the request
    Allow,
    /// Require step-up authentication
    StepUp,
    /// Require MFA
    RequireMfa,
    /// Block the request
    Block,
}

/// Action type for recommendations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    /// Allow
    Allow,
    /// Step-up auth
    StepUp,
    /// Require MFA
    RequireMfa,
    /// Block
    Block,
    /// Alert security team
    Alert,
    /// Log for review
    Log,
}

/// Risk recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskRecommendation {
    /// Type of action
    pub action_type: ActionType,
    /// Reason for recommendation
    pub reason: String,
    /// Confidence in recommendation (0-1)
    pub confidence: f64,
}

/// Complete risk decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskDecision {
    /// Final risk score
    pub score: u8,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Recommended action
    pub action: Action,
    /// Risk factors
    pub factors: Vec<RiskFactor>,
    /// Detected anomalies
    pub anomalies: Vec<super::anomaly_detection::Anomaly>,
    /// Recommendations
    pub recommendations: Vec<RiskRecommendation>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Real-time risk scoring engine
pub struct RealTimeRiskEngine {
    /// Configuration
    config: AiSecurityConfig,
    /// Database connection
    db: DbContext,
    /// Model manager
    model_manager: Arc<ModelManager>,
    /// Risk score cache (user_id -> recent scores)
    score_cache: Arc<RwLock<HashMap<String, Vec<RiskScoreEntry>>>>,
    /// Total assessments counter
    assessment_count: Arc<RwLock<u64>>,
}

/// Cached risk score entry
#[derive(Debug, Clone)]
pub struct RiskScoreEntry {
    pub score: u8,
    pub timestamp: DateTime<Utc>,
    pub context_hash: u64,
}

impl RealTimeRiskEngine {
    /// Create new risk engine
    pub async fn new(
        config: AiSecurityConfig,
        db: DbContext,
        model_manager: Arc<ModelManager>,
    ) -> AiResult<Self> {
        Ok(Self {
            config,
            db,
            model_manager,
            score_cache: Arc::new(RwLock::new(HashMap::new())),
            assessment_count: Arc::new(RwLock::new(0)),
        })
    }

    /// Calculate risk score for authentication context
    pub async fn calculate_risk(&self, context: &AuthContext) -> AiResult<RiskScore> {
        let mut factors = Vec::new();

        // Extract features
        let features = FeatureExtractor::extract(context)?;

        // Calculate rule-based score
        let rule_score = self
            .calculate_rule_based_score(context, &mut factors)
            .await?;

        // Calculate ML-enhanced score if enabled
        let (ml_score, ml_confidence) = if self.config.ml_risk_enabled {
            match self.model_manager.ensemble_predict(&features).await {
                Ok(result) => {
                    let score = (result.final_score * 100.0) as u8;
                    (score, result.confidence)
                }
                Err(e) => {
                    tracing::warn!("ML prediction failed: {}", e);
                    (rule_score, 0.0)
                }
            }
        } else {
            (rule_score, 0.0)
        };

        // Combine scores (weighted average)
        let final_score = if self.config.ml_risk_enabled && ml_confidence > 0.5 {
            // Trust ML more when confident
            ((rule_score as f64 * 0.3) + (ml_score as f64 * 0.7)) as u8
        } else {
            // Trust rule-based when ML uncertain
            ((rule_score as f64 * 0.7) + (ml_score as f64 * 0.3)) as u8
        };

        // Update counters
        let mut count = self.assessment_count.write().await;
        *count += 1;

        let score = RiskScore::new(final_score, factors).with_ml(ml_confidence);

        // Cache the score
        if let Some(ref user_id) = context.user_id {
            self.cache_score(user_id, &score, context).await;
        }

        Ok(score)
    }

    /// Calculate rule-based risk score
    async fn calculate_rule_based_score(
        &self,
        context: &AuthContext,
        factors: &mut Vec<RiskFactor>,
    ) -> AiResult<u8> {
        let mut score: u16 = 0;

        // IP reputation risk
        if context.is_anonymous_ip {
            let contribution = 25u8;
            score += contribution as u16;
            factors.push(RiskFactor::new(
                "anonymous_ip",
                contribution,
                "Connection from VPN, Tor, or proxy",
            ));
        }

        if context.is_hosting_provider {
            let contribution = 20u8;
            score += contribution as u16;
            factors.push(RiskFactor::new(
                "hosting_provider",
                contribution,
                "Connection from hosting provider/datacenter",
            ));
        }

        // Failed attempts risk
        if context.failed_attempts > 0 {
            let contribution = (context.failed_attempts * 10).min(40) as u8;
            score += contribution as u16;
            factors.push(
                RiskFactor::new(
                    "failed_attempts",
                    contribution,
                    format!("{} recent failed login attempts", context.failed_attempts),
                )
                .with_raw_value(context.failed_attempts as f64),
            );
        }

        // New device risk
        if context.device_fingerprint.is_none() {
            let contribution = 20u8;
            score += contribution as u16;
            factors.push(RiskFactor::new(
                "new_device",
                contribution,
                "New or unrecognized device",
            ));
        }

        // Impossible travel risk
        if let (Some((curr_lat, curr_lon)), Some((prev_lat, prev_lon))) =
            (context.geo_location, context.previous_location)
        {
            if let Some(prev_time) = context.previous_login_at {
                let distance = haversine_distance(curr_lat, curr_lon, prev_lat, prev_lon);
                let hours = (context.timestamp - prev_time).num_hours() as f64;

                if hours > 0.0 {
                    let speed = distance / hours;
                    if speed > 900.0 {
                        // Impossible travel
                        let contribution = 50u8;
                        score += contribution as u16;
                        factors.push(
                            RiskFactor::new(
                                "impossible_travel",
                                contribution,
                                format!(
                                    "Impossible travel: {:.0} km in {:.1} hours",
                                    distance, hours
                                ),
                            )
                            .with_metadata(serde_json::json!({
                                "distance_km": distance,
                                "hours": hours,
                                "speed": speed,
                            })),
                        );
                    } else if speed > 100.0 && hours < 2.0 {
                        // Suspicious travel
                        let contribution = 25u8;
                        score += contribution as u16;
                        factors.push(
                            RiskFactor::new(
                                "suspicious_travel",
                                contribution,
                                format!(
                                    "Suspicious travel: {:.0} km in {:.1} hours",
                                    distance, hours
                                ),
                            )
                            .with_metadata(serde_json::json!({
                                "distance_km": distance,
                                "hours": hours,
                            })),
                        );
                    }
                }
            }
        }

        // Time-based risk
        let hour = context.timestamp.hour();
        let is_night = hour >= 23 || hour < 5;
        let is_weekend = matches!(
            context.timestamp.weekday(),
            chrono::Weekday::Sat | chrono::Weekday::Sun
        );

        if is_night {
            let contribution = 15u8;
            score += contribution as u16;
            factors.push(RiskFactor::new(
                "unusual_time",
                contribution,
                "Login during unusual hours (late night)",
            ));
        }

        if is_weekend && !is_night {
            let contribution = 5u8;
            score += contribution as u16;
            factors.push(RiskFactor::new(
                "weekend_login",
                contribution,
                "Login during weekend",
            ));
        }

        // No MFA risk (if MFA is available but not used)
        if !context.mfa_used {
            let contribution = 10u8;
            score += contribution as u16;
            factors.push(RiskFactor::new(
                "no_mfa",
                contribution,
                "Multi-factor authentication not used",
            ));
        }

        // Cap at 100
        Ok(score.min(100) as u8)
    }

    /// Cache a risk score
    async fn cache_score(&self, user_id: &str, score: &RiskScore, context: &AuthContext) {
        let mut cache = self.score_cache.write().await;
        let entry = RiskScoreEntry {
            score: score.score,
            timestamp: Utc::now(),
            context_hash: self.hash_context(context),
        };

        cache
            .entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(entry);

        // Keep only recent scores (last 24 hours)
        let cutoff = Utc::now() - Duration::hours(24);
        if let Some(scores) = cache.get_mut(user_id) {
            scores.retain(|e| e.timestamp > cutoff);
        }
    }

    /// Hash context for cache lookup
    fn hash_context(&self, context: &AuthContext) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        context.ip_address.hash(&mut hasher);
        context.device_fingerprint.hash(&mut hasher);
        hasher.finish()
    }

    /// Get risk history for a user
    pub async fn get_risk_history(
        &self,
        user_id: &str,
        days: i64,
    ) -> AiResult<Vec<RiskScoreEntry>> {
        let cache = self.score_cache.read().await;
        let cutoff = Utc::now() - Duration::days(days);

        if let Some(scores) = cache.get(user_id) {
            Ok(scores
                .iter()
                .filter(|e| e.timestamp > cutoff)
                .cloned()
                .collect())
        } else {
            Ok(vec![])
        }
    }

    /// Get total assessments
    pub fn total_assessments(&self) -> u64 {
        // This would need proper sync in production
        0
    }
}

/// ML-based risk scorer for adaptive learning
pub struct MlRiskScorer {
    /// Model manager
    model_manager: Arc<ModelManager>,
    /// Learning rate for online updates
    learning_rate: f64,
    /// Historical predictions for feedback loop
    prediction_history: Arc<RwLock<Vec<HistoricalPrediction>>>,
}

/// Historical prediction for learning
#[derive(Debug, Clone)]
struct HistoricalPrediction {
    timestamp: DateTime<Utc>,
    features: FeatureVector,
    prediction: f64,
    actual_outcome: Option<bool>,
}

impl MlRiskScorer {
    /// Create new ML risk scorer
    pub fn new(model_manager: Arc<ModelManager>, learning_rate: f64) -> Self {
        Self {
            model_manager,
            learning_rate,
            prediction_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Score with continuous learning
    pub async fn score_with_learning(&self, features: &FeatureVector) -> AiResult<EnsembleResult> {
        let result = self.model_manager.ensemble_predict(features).await?;

        // Store prediction for future learning
        let mut history = self.prediction_history.write().await;
        history.push(HistoricalPrediction {
            timestamp: Utc::now(),
            features: features.clone(),
            prediction: result.final_score,
            actual_outcome: None,
        });

        // Keep history manageable
        if history.len() > 10000 {
            history.drain(0..1000);
        }

        Ok(result)
    }

    /// Provide feedback for learning
    pub async fn provide_feedback(
        &self,
        features: &FeatureVector,
        was_threat: bool,
    ) -> AiResult<()> {
        // Update prediction history with actual outcome
        let mut history = self.prediction_history.write().await;

        // Find matching prediction
        if let Some(pred) = history
            .iter_mut()
            .find(|p| p.features.values == features.values && p.actual_outcome.is_none())
        {
            pred.actual_outcome = Some(was_threat);
        }

        Ok(())
    }
}

/// Adaptive risk engine that learns from feedback
pub struct AdaptiveRiskEngine {
    /// Base risk engine
    base_engine: RealTimeRiskEngine,
    /// ML scorer with learning
    ml_scorer: MlRiskScorer,
    /// Feedback threshold for retraining
    feedback_threshold: usize,
}

impl AdaptiveRiskEngine {
    /// Create new adaptive engine
    pub async fn new(
        config: AiSecurityConfig,
        db: DbContext,
        model_manager: Arc<ModelManager>,
    ) -> AiResult<Self> {
        let base_engine = RealTimeRiskEngine::new(config, db, Arc::clone(&model_manager)).await?;
        let ml_scorer = MlRiskScorer::new(model_manager, 0.01);

        Ok(Self {
            base_engine,
            ml_scorer,
            feedback_threshold: 1000,
        })
    }

    /// Calculate risk with adaptive learning
    pub async fn calculate_risk(&self, context: &AuthContext) -> AiResult<RiskScore> {
        // Use base engine but incorporate adaptive learning
        let mut score = self.base_engine.calculate_risk(context).await?;

        // Get ML prediction with learning
        let features = FeatureExtractor::extract(context)?;
        if let Ok(ml_result) = self.ml_scorer.score_with_learning(&features).await {
            // Blend scores based on ML confidence
            if ml_result.confidence > 0.6 {
                let ml_score = (ml_result.final_score * 100.0) as u8;
                let blended = ((score.score as f64 * 0.4) + (ml_score as f64 * 0.6)) as u8;
                score.score = blended;
                score.level = RiskLevel::from_score(blended);
                score.ml_confidence = ml_result.confidence;
            }
        }

        Ok(score)
    }
}

/// Calculate haversine distance between two points
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
    fn test_risk_level() {
        assert_eq!(RiskLevel::from_score(20), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(45), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(70), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(90), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_score_creation() {
        let factors = vec![RiskFactor::new("test", 30, "Test factor")];
        let score = RiskScore::new(45, factors);

        assert_eq!(score.score, 45);
        assert_eq!(score.level, RiskLevel::Medium);
        assert!(score.has_factor("test"));
    }

    #[test]
    fn test_risk_factor() {
        let factor = RiskFactor::new("test_factor", 25, "Test description")
            .with_raw_value(0.5)
            .with_metadata(serde_json::json!({"key": "value"}));

        assert_eq!(factor.factor_type, "test_factor");
        assert_eq!(factor.contribution, 25);
        assert_eq!(factor.raw_value, Some(0.5));
        assert!(factor.metadata.is_some());
    }

    #[test]
    fn test_action_type() {
        assert!(!RiskLevel::Low.requires_mfa());
        assert!(RiskLevel::Medium.requires_mfa());
        assert!(RiskLevel::High.requires_mfa());
        assert!(RiskLevel::Critical.should_block());
    }

    #[test]
    fn test_haversine_distance() {
        let nyc = (40.7128, -74.0060);
        let london = (51.5074, -0.1278);

        let dist = haversine_distance(nyc.0, nyc.1, london.0, london.1);
        assert!(dist > 5500.0 && dist < 5600.0);
    }
}
