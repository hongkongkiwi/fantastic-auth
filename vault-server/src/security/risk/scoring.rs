//! Risk Scoring Engine
//!
//! Calculates overall risk scores (0-100) based on weighted risk factors.
//! Supports configurable weights and multiple scoring strategies.

use serde::{Deserialize, Serialize};

use super::factors::RiskFactorResult;

/// Risk score (0-100)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RiskScore(u8);

impl RiskScore {
    /// Create a new risk score (clamped to 0-100)
    pub fn new(score: u8) -> Self {
        Self(score.min(100))
    }

    /// Get the score value
    pub fn value(&self) -> u8 {
        self.0
    }

    /// Check if score is low risk (0-30)
    pub fn is_low(&self) -> bool {
        self.0 <= 30
    }

    /// Check if score is medium risk (31-60)
    pub fn is_medium(&self) -> bool {
        self.0 > 30 && self.0 <= 60
    }

    /// Check if score is high risk (61-80)
    pub fn is_high(&self) -> bool {
        self.0 > 60 && self.0 <= 80
    }

    /// Check if score is critical risk (81-100)
    pub fn is_critical(&self) -> bool {
        self.0 > 80
    }

    /// Get risk level as string
    pub fn level(&self) -> &'static str {
        if self.is_critical() {
            "critical"
        } else if self.is_high() {
            "high"
        } else if self.is_medium() {
            "medium"
        } else {
            "low"
        }
    }

    /// Combine two scores using max (conservative)
    pub fn combine_max(a: RiskScore, b: RiskScore) -> Self {
        Self::new(a.0.max(b.0))
    }

    /// Combine two scores using average
    pub fn combine_avg(a: RiskScore, b: RiskScore) -> Self {
        Self::new(((a.0 as u16 + b.0 as u16) / 2) as u8)
    }

    /// Combine multiple scores using weighted average
    pub fn combine_weighted(scores: &[(RiskScore, f64)]) -> Self {
        if scores.is_empty() {
            return Self::new(0);
        }

        let total_weight: f64 = scores.iter().map(|(_, w)| w).sum();
        if total_weight == 0.0 {
            return Self::new(0);
        }

        let weighted_sum: f64 = scores
            .iter()
            .map(|(s, w)| s.0 as f64 * w)
            .sum();

        Self::new((weighted_sum / total_weight) as u8)
    }
}

impl Default for RiskScore {
    fn default() -> Self {
        Self::new(0)
    }
}

impl std::fmt::Display for RiskScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.0, self.level())
    }
}

/// Scoring weights for different risk factor categories
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScoringWeights {
    /// Weight for device-related risks (0.0 - 1.0)
    #[serde(default = "default_device_weight")]
    pub device: f64,
    /// Weight for location-related risks
    #[serde(default = "default_location_weight")]
    pub location: f64,
    /// Weight for IP reputation risks
    #[serde(default = "default_ip_reputation_weight")]
    pub ip_reputation: f64,
    /// Weight for time-based risks
    #[serde(default = "default_time_weight")]
    pub time: f64,
    /// Weight for velocity risks
    #[serde(default = "default_velocity_weight")]
    pub velocity: f64,
    /// Weight for impossible travel risks
    #[serde(default = "default_travel_weight")]
    pub impossible_travel: f64,
    /// Weight for credential risks
    #[serde(default = "default_credential_weight")]
    pub credential: f64,
    /// Scoring strategy
    #[serde(default)]
    pub strategy: ScoringStrategy,
}

impl Default for ScoringWeights {
    fn default() -> Self {
        Self {
            device: default_device_weight(),
            location: default_location_weight(),
            ip_reputation: default_ip_reputation_weight(),
            time: default_time_weight(),
            velocity: default_velocity_weight(),
            impossible_travel: default_travel_weight(),
            credential: default_credential_weight(),
            strategy: ScoringStrategy::default(),
        }
    }
}

impl ScoringWeights {
    /// Validate weights (sum should be close to 1.0)
    pub fn validate(&self) -> Result<(), String> {
        let sum = self.device
            + self.location
            + self.ip_reputation
            + self.time
            + self.velocity
            + self.impossible_travel
            + self.credential;

        if (sum - 1.0).abs() > 0.01 {
            Err(format!(
                "Weights should sum to 1.0, but sum to {:.2}",
                sum
            ))
        } else {
            Ok(())
        }
    }

    /// Normalize weights so they sum to 1.0
    pub fn normalize(&mut self) {
        let sum = self.device
            + self.location
            + self.ip_reputation
            + self.time
            + self.velocity
            + self.impossible_travel
            + self.credential;

        if sum > 0.0 {
            self.device /= sum;
            self.location /= sum;
            self.ip_reputation /= sum;
            self.time /= sum;
            self.velocity /= sum;
            self.impossible_travel /= sum;
            self.credential /= sum;
        }
    }

    /// Get weight for a specific factor category
    pub fn get_weight(&self, category: &str) -> f64 {
        match category {
            "device" | "new_device" | "device_reputation" => self.device,
            "location" => self.location,
            "ip_reputation" => self.ip_reputation,
            "time" | "unusual_time" => self.time,
            "velocity" => self.velocity,
            "impossible_travel" => self.impossible_travel,
            "credential" | "breached_credential" => self.credential,
            _ => 0.1, // Default small weight for unknown factors
        }
    }
}

/// Scoring strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScoringStrategy {
    /// Simple sum of contributions (default)
    Sum,
    /// Weighted average
    WeightedAverage,
    /// Maximum score (most conservative)
    Maximum,
    /// Exponential decay for multiple factors
    Exponential,
}

impl Default for ScoringStrategy {
    fn default() -> Self {
        ScoringStrategy::WeightedAverage
    }
}

/// Risk scoring engine
pub struct RiskScoringEngine {
    weights: ScoringWeights,
}

impl RiskScoringEngine {
    /// Create a new scoring engine with weights
    pub fn new(weights: ScoringWeights) -> Self {
        Self { weights }
    }

    /// Create with default weights
    pub fn default_weights() -> Self {
        Self::new(ScoringWeights::default())
    }

    /// Calculate overall risk score from factor results
    pub fn calculate_score(&self, factors: &[RiskFactorResult]) -> RiskScore {
        if factors.is_empty() {
            return RiskScore::new(0);
        }

        let score = match self.weights.strategy {
            ScoringStrategy::Sum => self.sum_score(factors),
            ScoringStrategy::WeightedAverage => self.weighted_average_score(factors),
            ScoringStrategy::Maximum => self.maximum_score(factors),
            ScoringStrategy::Exponential => self.exponential_score(factors),
        };

        RiskScore::new(score)
    }

    /// Simple sum of contributions (clamped to 100)
    fn sum_score(&self, factors: &[RiskFactorResult]) -> u8 {
        let sum: u16 = factors.iter().map(|f| f.contribution as u16).sum();
        (sum.min(100)) as u8
    }

    /// Weighted average of contributions
    fn weighted_average_score(&self, factors: &[RiskFactorResult]) -> u8 {
        let weighted_sum: f64 = factors
            .iter()
            .map(|f| {
                let weight = self.weights.get_weight(f.factor.as_str());
                f.contribution as f64 * weight
            })
            .sum();

        // Normalize by total weight
        let total_weight: f64 = factors
            .iter()
            .map(|f| self.weights.get_weight(f.factor.as_str()))
            .sum();

        if total_weight == 0.0 {
            return 0;
        }

        let normalized = weighted_sum / total_weight;
        
        // Apply scaling to ensure we can reach high scores when multiple factors present
        let scaled = if factors.len() > 1 {
            // Boost score slightly when multiple factors are present
            let multiplier = 1.0 + (factors.len() as f64 - 1.0) * 0.1;
            normalized * multiplier.min(1.5)
        } else {
            normalized
        };

        scaled.min(100.0) as u8
    }

    /// Maximum contribution (most conservative)
    fn maximum_score(&self, factors: &[RiskFactorResult]) -> u8 {
        factors
            .iter()
            .map(|f| f.contribution)
            .max()
            .unwrap_or(0)
    }

    /// Exponential scoring: scores increase non-linearly with more factors
    fn exponential_score(&self, factors: &[RiskFactorResult]) -> u8 {
        let base_score = self.weighted_average_score(factors) as f64;
        
        // Apply exponential boost based on number of risk factors
        let risky_count = factors.iter().filter(|f| f.is_risky()).count() as f64;
        let boost = 1.0 + (risky_count * 0.15);
        
        let final_score = base_score * boost;
        final_score.min(100.0) as u8
    }

    /// Update weights
    pub fn update_weights(&mut self, weights: ScoringWeights) {
        self.weights = weights;
    }

    /// Get current weights
    pub fn weights(&self) -> &ScoringWeights {
        &self.weights
    }
}

// Default weight functions
fn default_device_weight() -> f64 {
    0.25
}
fn default_location_weight() -> f64 {
    0.15
}
fn default_ip_reputation_weight() -> f64 {
    0.20
}
fn default_time_weight() -> f64 {
    0.10
}
fn default_velocity_weight() -> f64 {
    0.15
}
fn default_travel_weight() -> f64 {
    0.10
}
fn default_credential_weight() -> f64 {
    0.05
}

/// ML-enhanced scoring (placeholder for future ML model)
///
/// This struct provides an interface for ML-based risk scoring.
/// Currently implements a rule-based approach that can be extended
/// with actual ML models later.
pub struct MlRiskScorer {
    /// Model version
    pub model_version: String,
    /// Feature importance weights
    feature_weights: Vec<f64>,
}

impl MlRiskScorer {
    /// Create a new ML risk scorer
    pub fn new() -> Self {
        Self {
            model_version: "1.0.0-rule-based".to_string(),
            feature_weights: vec![
                0.25, // device
                0.15, // location
                0.20, // ip_reputation
                0.10, // time
                0.15, // velocity
                0.10, // travel
                0.05, // credential
            ],
        }
    }

    /// Score using ML model (currently rule-based)
    pub fn score(&self, features: &[f64]) -> RiskScore {
        if features.len() != self.feature_weights.len() {
            return RiskScore::new(0);
        }

        // Simple weighted dot product (placeholder for actual ML inference)
        let raw_score: f64 = features
            .iter()
            .zip(self.feature_weights.iter())
            .map(|(f, w)| f * w)
            .sum();

        // Apply sigmoid-like transformation
        let transformed = 100.0 / (1.0 + (-raw_score / 20.0).exp());

        RiskScore::new(transformed as u8)
    }

    /// Get feature importance
    pub fn feature_importance(&self) -> &[f64] {
        &self.feature_weights
    }

    /// Update model (placeholder for online learning)
    pub fn update_model(&mut self, _feedback: &[(&str, bool)]) {
        // In a real implementation, this would update the model weights
        // based on feedback (true = correct assessment, false = false positive/negative)
    }
}

impl Default for MlRiskScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::factors::{RiskFactorResult, RiskFactorType};
    use super::*;

    #[test]
    fn test_risk_score_creation() {
        assert_eq!(RiskScore::new(50).value(), 50);
        assert_eq!(RiskScore::new(150).value(), 100); // Clamped
        assert_eq!(RiskScore::new(0).value(), 0);
    }

    #[test]
    fn test_risk_score_levels() {
        let low = RiskScore::new(20);
        assert!(low.is_low());
        assert!(!low.is_medium());

        let medium = RiskScore::new(45);
        assert!(medium.is_medium());
        assert!(!medium.is_high());

        let high = RiskScore::new(70);
        assert!(high.is_high());
        assert!(!high.is_critical());

        let critical = RiskScore::new(85);
        assert!(critical.is_critical());
    }

    #[test]
    fn test_risk_score_combine() {
        let a = RiskScore::new(30);
        let b = RiskScore::new(50);

        assert_eq!(RiskScore::combine_max(a, b).value(), 50);
        assert_eq!(RiskScore::combine_avg(a, b).value(), 40);

        let combined = RiskScore::combine_weighted(&[(a, 0.3), (b, 0.7)]);
        assert_eq!(combined.value(), 44); // (30*0.3 + 50*0.7) = 44
    }

    #[test]
    fn test_scoring_weights() {
        let mut weights = ScoringWeights::default();
        
        // Should validate correctly
        assert!(weights.validate().is_ok());

        // Test weight retrieval
        assert_eq!(weights.get_weight("device"), 0.25);
        assert_eq!(weights.get_weight("new_device"), 0.25);
        assert_eq!(weights.get_weight("ip_reputation"), 0.20);
    }

    #[test]
    fn test_scoring_weights_normalization() {
        let mut weights = ScoringWeights {
            device: 2.0,
            location: 2.0,
            ip_reputation: 2.0,
            time: 2.0,
            velocity: 2.0,
            impossible_travel: 2.0,
            credential: 2.0,
            strategy: ScoringStrategy::Sum,
        };

        weights.normalize();

        assert!(weights.validate().is_ok());
        assert!((weights.device - 0.142857).abs() < 0.001);
    }

    #[test]
    fn test_scoring_engine_sum() {
        let engine = RiskScoringEngine::new(ScoringWeights {
            strategy: ScoringStrategy::Sum,
            ..Default::default()
        });

        let factors = vec![
            RiskFactorResult::new(RiskFactorType::NewDevice, 30, "Test 1"),
            RiskFactorResult::new(RiskFactorType::Location, 20, "Test 2"),
            RiskFactorResult::new(RiskFactorType::Velocity, 25, "Test 3"),
        ];

        let score = engine.calculate_score(&factors);
        assert_eq!(score.value(), 75); // 30 + 20 + 25 = 75
    }

    #[test]
    fn test_scoring_engine_maximum() {
        let engine = RiskScoringEngine::new(ScoringWeights {
            strategy: ScoringStrategy::Maximum,
            ..Default::default()
        });

        let factors = vec![
            RiskFactorResult::new(RiskFactorType::NewDevice, 30, "Test 1"),
            RiskFactorResult::new(RiskFactorType::Location, 50, "Test 2"),
            RiskFactorResult::new(RiskFactorType::Velocity, 25, "Test 3"),
        ];

        let score = engine.calculate_score(&factors);
        assert_eq!(score.value(), 50); // max of 30, 50, 25
    }

    #[test]
    fn test_scoring_engine_weighted_average() {
        let engine = RiskScoringEngine::new(ScoringWeights {
            device: 0.4,
            location: 0.3,
            velocity: 0.3,
            ..Default::default()
        });

        let factors = vec![
            RiskFactorResult::new(RiskFactorType::NewDevice, 50, "Device"),
            RiskFactorResult::new(RiskFactorType::Location, 30, "Location"),
            RiskFactorResult::new(RiskFactorType::Velocity, 20, "Velocity"),
        ];

        let score = engine.calculate_score(&factors);
        // Weighted average: (50*0.4 + 30*0.3 + 20*0.3) / 1.0 = 20 + 9 + 6 = 35
        assert_eq!(score.value(), 35);
    }

    #[test]
    fn test_scoring_engine_empty() {
        let engine = RiskScoringEngine::default_weights();
        let factors: Vec<RiskFactorResult> = vec![];

        let score = engine.calculate_score(&factors);
        assert_eq!(score.value(), 0);
    }

    #[test]
    fn test_ml_risk_scorer() {
        let scorer = MlRiskScorer::new();
        
        // Test with valid features
        let features = vec![50.0, 30.0, 20.0, 10.0, 40.0, 15.0, 5.0];
        let score = scorer.score(&features);
        
        // Score should be between 0 and 100
        assert!(score.value() > 0);
        assert!(score.value() <= 100);

        // Test with wrong number of features
        let bad_features = vec![50.0, 30.0];
        let score = scorer.score(&bad_features);
        assert_eq!(score.value(), 0);
    }

    #[test]
    fn test_risk_score_display() {
        let score = RiskScore::new(45);
        assert_eq!(format!("{}", score), "45 (medium)");
    }
}
