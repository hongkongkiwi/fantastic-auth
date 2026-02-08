//! AI-Powered Threat Detection and Security System
//!
//! This module provides machine learning-based security capabilities:
//! - Real-time risk scoring with ML-enhanced analysis
//! - Behavioral anomaly detection
//! - Attack pattern recognition
//! - Behavioral biometrics
//!
//! ## Architecture
//!
//! The AI system uses a layered approach:
//! 1. **Feature Extraction**: Raw events are converted to feature vectors
//! 2. **ML Models**: Lightweight models for real-time inference
//! 3. **Risk Scoring**: Combined rule-based and ML risk assessment
//! 4. **Threat Detection**: Pattern matching and anomaly detection
//! 5. **Response**: Automated actions based on risk levels
//!
//! ## Example Usage
//!
//! ```rust
//! use vault_core::ai::{AiSecurityEngine, RiskScore, AuthContext};
//!
//! // Create AI security engine
//! let engine = AiSecurityEngine::new(config, db, models).await?;
//!
//! // Calculate risk for authentication attempt
//! let risk = engine.calculate_risk(&auth_context).await?;
//!
//! if risk.level == RiskLevel::High {
//!     // Require additional verification
//! }
//! ```

pub mod anomaly_detection;
pub mod behavioral;
pub mod error;
pub mod features;
pub mod ml_models;
pub mod risk_engine;
pub mod threat_detection;

pub use anomaly_detection::{
    Anomaly, AnomalyDetector, AnomalyLevel, AnomalyType, UserBehaviorProfile,
};
pub use behavioral::{
    BehavioralBiometrics, BehavioralData, BehavioralPattern, BehavioralScore, KeystrokeDynamics,
    MouseDynamics, TouchDynamics,
};
pub use error::{AiError, AiResult};
pub use features::{
    AuthContext, AuthMethod, DeviceFeatures, FeatureExtractor, FeatureVector, GeoFeatures,
    TimeFeatures, VelocityFeatures,
};
pub use ml_models::{
    IsolationForestModel, LstmAnomalyDetector, ModelManager, ModelType, OnnxModel,
    RandomForestModel, RiskPredictionModel,
};
pub use risk_engine::{
    Action, ActionType, AdaptiveRiskEngine, MlRiskScorer, RealTimeRiskEngine, RiskDecision,
    RiskFactor, RiskLevel, RiskRecommendation, RiskScore, RiskScoreEntry,
};
pub use threat_detection::{
    Attack, AttackPattern, AttackSeverity, AttackSignature, AttackType, BruteForceDetector,
    CredentialStuffingDetector, SessionHijackingDetector, ThreatDetector, ThreatIntelligence,
    TimeWindow,
};

use std::sync::Arc;

use crate::db::DbContext;

/// Main AI security engine that orchestrates all AI capabilities
pub struct AiSecurityEngine {
    /// Real-time risk scoring engine
    risk_engine: Arc<RealTimeRiskEngine>,
    /// Anomaly detection system
    anomaly_detector: Arc<AnomalyDetector>,
    /// Threat detection system
    threat_detector: Arc<ThreatDetector>,
    /// Behavioral biometrics analyzer
    behavioral_biometrics: Arc<BehavioralBiometrics>,
    /// ML model manager
    model_manager: Arc<ModelManager>,
    /// Database connection
    db: DbContext,
    /// Configuration
    config: AiSecurityConfig,
}

/// Configuration for the AI security system
#[derive(Debug, Clone)]
pub struct AiSecurityConfig {
    /// Enable/disable ML risk scoring
    pub ml_risk_enabled: bool,
    /// Enable/disable anomaly detection
    pub anomaly_detection_enabled: bool,
    /// Enable/disable threat detection
    pub threat_detection_enabled: bool,
    /// Enable/disable behavioral biometrics
    pub behavioral_biometrics_enabled: bool,
    /// Risk score threshold for requiring MFA (0-100)
    pub mfa_threshold: u8,
    /// Risk score threshold for blocking (0-100)
    pub block_threshold: u8,
    /// Anomaly detection sensitivity (0.0 - 1.0)
    pub anomaly_sensitivity: f64,
    /// Time window for threat detection (seconds)
    pub threat_detection_window_secs: u64,
    /// Maximum events to keep in memory for analysis
    pub max_event_buffer_size: usize,
}

impl Default for AiSecurityConfig {
    fn default() -> Self {
        Self {
            ml_risk_enabled: true,
            anomaly_detection_enabled: true,
            threat_detection_enabled: true,
            behavioral_biometrics_enabled: true,
            mfa_threshold: 50,
            block_threshold: 80,
            anomaly_sensitivity: 0.7,
            threat_detection_window_secs: 300,
            max_event_buffer_size: 10000,
        }
    }
}

impl AiSecurityEngine {
    /// Create a new AI security engine
    pub async fn new(config: AiSecurityConfig, db: DbContext) -> AiResult<Self> {
        let model_manager = Arc::new(ModelManager::new().await?);

        let risk_engine = Arc::new(
            RealTimeRiskEngine::new(config.clone(), db.clone(), Arc::clone(&model_manager)).await?,
        );

        let anomaly_detector = Arc::new(
            AnomalyDetector::new(
                config.anomaly_sensitivity,
                db.clone(),
                Arc::clone(&model_manager),
            )
            .await?,
        );

        let threat_detector = Arc::new(
            ThreatDetector::new(
                config.threat_detection_window_secs,
                db.clone(),
                Arc::clone(&model_manager),
            )
            .await?,
        );

        let behavioral_biometrics =
            Arc::new(BehavioralBiometrics::new(Arc::clone(&model_manager), db.clone()).await?);

        Ok(Self {
            risk_engine,
            anomaly_detector,
            threat_detector,
            behavioral_biometrics,
            model_manager,
            db,
            config,
        })
    }

    /// Calculate risk score for an authentication attempt
    pub async fn calculate_risk(&self, context: &AuthContext) -> AiResult<RiskScore> {
        self.risk_engine.calculate_risk(context).await
    }

    /// Make a risk-based decision for authentication
    pub async fn evaluate_auth_attempt(
        &self,
        user_id: Option<&str>,
        context: &AuthContext,
    ) -> AiResult<RiskDecision> {
        // Calculate base risk score
        let risk = self.risk_engine.calculate_risk(context).await?;

        // Check for anomalies if user is known
        let anomalies = if let Some(uid) = user_id {
            self.anomaly_detector.detect_anomalies(uid, context).await?
        } else {
            vec![]
        };

        // Get behavioral score if enabled and we have behavioral data
        let behavioral_score = if self.config.behavioral_biometrics_enabled {
            if let Some(behavior) = &context.behavioral_data {
                if let Some(uid) = user_id {
                    Some(self.behavioral_biometrics.analyze(uid, behavior).await?)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Combine all signals for final decision
        let decision = self
            .make_decision(risk, anomalies, behavioral_score)
            .await?;

        Ok(decision)
    }

    /// Detect active threats in a time window
    pub async fn detect_threats(&self, window: TimeWindow) -> AiResult<Vec<Attack>> {
        self.threat_detector.detect_attacks(window).await
    }

    /// Record behavioral data for future analysis
    pub async fn record_behavior(&self, user_id: &str, behavior: &BehavioralData) -> AiResult<()> {
        if self.config.behavioral_biometrics_enabled {
            self.behavioral_biometrics.record(user_id, behavior).await?;
        }
        Ok(())
    }

    /// Get user risk profile
    pub async fn get_user_risk_profile(&self, user_id: &str) -> AiResult<UserRiskProfile> {
        let recent_anomalies = self
            .anomaly_detector
            .get_recent_anomalies(user_id, 30)
            .await?;

        let risk_history = self.risk_engine.get_risk_history(user_id, 30).await?;

        let avg_risk = if !risk_history.is_empty() {
            risk_history.iter().map(|r| r.score as u32).sum::<u32>() as f64
                / risk_history.len() as f64
        } else {
            0.0
        };

        let baseline_score = avg_risk as u8;
        let anomaly_count_30d = recent_anomalies.len() as u32;

        Ok(UserRiskProfile {
            user_id: user_id.to_string(),
            baseline_score,
            recent_anomalies,
            risk_history: risk_history.into_iter().map(|r| r.score).collect(),
            anomaly_count_30d,
            last_updated: chrono::Utc::now(),
        })
    }

    /// Submit feedback for model improvement
    pub async fn submit_feedback(
        &self,
        event_id: &str,
        was_threat: bool,
        notes: Option<&str>,
    ) -> AiResult<()> {
        // Store feedback for model retraining
        self.model_manager
            .record_feedback(event_id, was_threat, notes)
            .await?;

        // Update models if needed
        self.model_manager.process_feedback().await?;

        Ok(())
    }

    /// Get current system status
    pub fn status(&self) -> AiSystemStatus {
        AiSystemStatus {
            ml_risk_enabled: self.config.ml_risk_enabled,
            anomaly_detection_enabled: self.config.anomaly_detection_enabled,
            threat_detection_enabled: self.config.threat_detection_enabled,
            behavioral_biometrics_enabled: self.config.behavioral_biometrics_enabled,
            models_loaded: self.model_manager.loaded_model_count(),
            total_assessments: self.risk_engine.total_assessments(),
            total_anomalies_detected: self.anomaly_detector.total_detected(),
            total_threats_blocked: self.threat_detector.total_blocked(),
        }
    }

    /// Make final decision based on all signals
    async fn make_decision(
        &self,
        risk: RiskScore,
        anomalies: Vec<Anomaly>,
        behavioral_score: Option<BehavioralScore>,
    ) -> AiResult<RiskDecision> {
        let factors = risk.factors.clone();

        // Add anomaly-based risk
        let anomaly_risk: u8 = anomalies
            .iter()
            .map(|a| match a.level {
                AnomalyLevel::Low => 10,
                AnomalyLevel::Medium => 25,
                AnomalyLevel::High => 40,
                AnomalyLevel::Critical => 60,
            })
            .sum::<u16>()
            .min(100) as u8;

        // Add behavioral risk if available
        let behavioral_risk = behavioral_score.map(|s| s.risk_contribution()).unwrap_or(0);

        // Calculate final score
        let final_score =
            (risk.score as u16 + anomaly_risk as u16 + behavioral_risk as u16).min(100) as u8;

        // Determine action
        let action = if final_score >= self.config.block_threshold {
            Action::Block
        } else if final_score >= self.config.mfa_threshold {
            Action::RequireMfa
        } else if !anomalies.is_empty() {
            Action::StepUp
        } else {
            Action::Allow
        };

        // Build recommendations
        let mut recommendations = Vec::new();

        match action {
            Action::Block => {
                recommendations.push(RiskRecommendation {
                    action_type: ActionType::Block,
                    reason: "High risk score detected".to_string(),
                    confidence: final_score as f64 / 100.0,
                });
            }
            Action::RequireMfa => {
                recommendations.push(RiskRecommendation {
                    action_type: ActionType::RequireMfa,
                    reason: "Medium risk - additional verification required".to_string(),
                    confidence: final_score as f64 / 100.0,
                });
            }
            Action::StepUp => {
                recommendations.push(RiskRecommendation {
                    action_type: ActionType::StepUp,
                    reason: "Anomaly detected".to_string(),
                    confidence: 0.7,
                });
            }
            Action::Allow => {
                recommendations.push(RiskRecommendation {
                    action_type: ActionType::Allow,
                    reason: "Low risk".to_string(),
                    confidence: 0.95,
                });
            }
        }

        // Add anomaly recommendations
        for anomaly in &anomalies {
            recommendations.push(RiskRecommendation {
                action_type: ActionType::Alert,
                reason: format!("Anomaly: {:?}", anomaly.anomaly_type),
                confidence: anomaly.confidence,
            });
        }

        Ok(RiskDecision {
            score: final_score,
            risk_level: RiskLevel::from_score(final_score),
            action,
            factors,
            anomalies,
            recommendations,
            timestamp: chrono::Utc::now(),
        })
    }
}

/// User risk profile
#[derive(Debug, Clone)]
pub struct UserRiskProfile {
    /// User ID
    pub user_id: String,
    /// Baseline risk score (average)
    pub baseline_score: u8,
    /// Recent anomalies
    pub recent_anomalies: Vec<Anomaly>,
    /// Recent risk scores
    pub risk_history: Vec<u8>,
    /// Count of anomalies in last 30 days
    pub anomaly_count_30d: u32,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// AI system status
#[derive(Debug, Clone)]
pub struct AiSystemStatus {
    /// ML risk scoring enabled
    pub ml_risk_enabled: bool,
    /// Anomaly detection enabled
    pub anomaly_detection_enabled: bool,
    /// Threat detection enabled
    pub threat_detection_enabled: bool,
    /// Behavioral biometrics enabled
    pub behavioral_biometrics_enabled: bool,
    /// Number of models loaded
    pub models_loaded: usize,
    /// Total risk assessments performed
    pub total_assessments: u64,
    /// Total anomalies detected
    pub total_anomalies_detected: u64,
    /// Total threats blocked
    pub total_threats_blocked: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(20), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(50), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(70), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(90), RiskLevel::Critical);
    }

    #[test]
    fn test_ai_security_config_default() {
        let config = AiSecurityConfig::default();
        assert!(config.ml_risk_enabled);
        assert!(config.anomaly_detection_enabled);
        assert!(config.threat_detection_enabled);
        assert!(config.behavioral_biometrics_enabled);
        assert_eq!(config.mfa_threshold, 50);
        assert_eq!(config.block_threshold, 80);
    }
}
