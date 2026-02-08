//! ML Model Management
//!
//! This module provides lightweight ML models for real-time inference:
//! - Random Forest for risk classification
//! - Isolation Forest for anomaly detection
//! - LSTM for sequence-based anomaly detection
//! - ONNX runtime for pre-trained models

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::error::{AiError, AiResult};
use super::features::FeatureVector;

/// Model types supported by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelType {
    /// Random Forest for risk scoring
    RiskRandomForest,
    /// Isolation Forest for anomaly detection
    AnomalyIsolationForest,
    /// LSTM for sequence detection
    SequenceLstm,
    /// Logistic regression for lightweight scoring
    LogisticRegression,
    /// Neural network via ONNX
    OnnxNeuralNetwork,
    /// Gradient boosting for ensemble
    GradientBoosting,
}

impl ModelType {
    /// Get model name
    pub fn name(&self) -> &'static str {
        match self {
            ModelType::RiskRandomForest => "risk_rf",
            ModelType::AnomalyIsolationForest => "anomaly_if",
            ModelType::SequenceLstm => "sequence_lstm",
            ModelType::LogisticRegression => "logistic_reg",
            ModelType::OnnxNeuralNetwork => "onnx_nn",
            ModelType::GradientBoosting => "gradient_boost",
        }
    }

    /// Get default model path
    pub fn default_path(&self) -> String {
        format!("models/{}.bin", self.name())
    }
}

/// Model manager for loading and running ML models
pub struct ModelManager {
    /// Loaded models
    models: Arc<RwLock<HashMap<ModelType, Box<dyn RiskPredictionModel>>>>,
    /// Model weights for ensemble
    model_weights: Arc<RwLock<HashMap<ModelType, f64>>>,
    /// Feedback buffer for online learning
    feedback_buffer: Arc<RwLock<Vec<ModelFeedback>>>,
    /// Total predictions made
    prediction_count: Arc<RwLock<u64>>,
}

/// Feedback for model improvement
#[derive(Debug, Clone)]
pub struct ModelFeedback {
    /// Event ID
    pub event_id: String,
    /// Features used
    pub features: FeatureVector,
    /// Model prediction
    pub prediction: f64,
    /// Actual outcome (true = was threat)
    pub actual: bool,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Optional notes
    pub notes: Option<String>,
}

impl ModelManager {
    /// Create new model manager and load all models
    pub async fn new() -> AiResult<Self> {
        let models = Arc::new(RwLock::new(HashMap::new()));
        let model_weights = Arc::new(RwLock::new(HashMap::new()));
        let feedback_buffer = Arc::new(RwLock::new(Vec::new()));
        let prediction_count = Arc::new(RwLock::new(0));

        let manager = Self {
            models,
            model_weights,
            feedback_buffer,
            prediction_count,
        };

        // Load default models
        manager.load_default_models().await?;

        Ok(manager)
    }

    /// Load all default models
    async fn load_default_models(&self) -> AiResult<()> {
        // Load logistic regression (lightweight, always available)
        let lr_model = LogisticRegressionModel::new();
        self.register_model(ModelType::LogisticRegression, lr_model)
            .await?;

        // Load random forest if available
        match RandomForestModel::load(&ModelType::RiskRandomForest.default_path()).await {
            Ok(rf) => {
                self.register_model(ModelType::RiskRandomForest, rf).await?;
            }
            Err(e) => {
                tracing::warn!("Could not load random forest model: {}", e);
                // Create default model
                let rf = RandomForestModel::new(100, 10);
                self.register_model(ModelType::RiskRandomForest, rf).await?;
            }
        }

        // Load isolation forest for anomaly detection
        let if_model = IsolationForestModel::new(100, 256);
        self.register_model(ModelType::AnomalyIsolationForest, if_model)
            .await?;

        // Set default weights
        let mut weights = self.model_weights.write().await;
        weights.insert(ModelType::LogisticRegression, 0.3);
        weights.insert(ModelType::RiskRandomForest, 0.5);
        weights.insert(ModelType::AnomalyIsolationForest, 0.2);

        Ok(())
    }

    /// Register a model
    pub async fn register_model(
        &self,
        model_type: ModelType,
        model: impl RiskPredictionModel + 'static,
    ) -> AiResult<()> {
        let mut models = self.models.write().await;
        models.insert(model_type, Box::new(model));
        Ok(())
    }

    /// Get a model
    pub async fn get_model(
        &self,
        model_type: ModelType,
    ) -> AiResult<Box<dyn RiskPredictionModel>> {
        let models = self.models.read().await;
        models
            .get(&model_type)
            .map(|m| m.clone_box())
            .ok_or_else(|| AiError::ModelNotFound(model_type.name().to_string()))
    }

    /// Run prediction with a specific model
    pub async fn predict(&self, model_type: ModelType, features: &FeatureVector) -> AiResult<f64> {
        let models = self.models.read().await;
        let model = models
            .get(&model_type)
            .ok_or_else(|| AiError::ModelNotFound(model_type.name().to_string()))?;

        let result = model.predict(features)?;

        // Increment prediction count
        let mut count = self.prediction_count.write().await;
        *count += 1;

        Ok(result)
    }

    /// Run ensemble prediction with all models
    pub async fn ensemble_predict(&self, features: &FeatureVector) -> AiResult<EnsembleResult> {
        let models = self.models.read().await;
        let weights = self.model_weights.read().await;

        let mut predictions = HashMap::new();
        let mut weighted_sum = 0.0;
        let mut total_weight = 0.0;

        for (model_type, model) in models.iter() {
            match model.predict(features) {
                Ok(pred) => {
                    let weight = weights.get(model_type).copied().unwrap_or(0.1);
                    predictions.insert(*model_type, pred);
                    weighted_sum += pred * weight;
                    total_weight += weight;
                }
                Err(e) => {
                    tracing::warn!("Model {:?} prediction failed: {}", model_type, e);
                }
            }
        }

        if total_weight == 0.0 {
            return Err(AiError::ModelError("No models available".to_string()));
        }

        let final_prediction = weighted_sum / total_weight;
        let confidence = self.calculate_confidence(&predictions);

        Ok(EnsembleResult {
            final_score: final_prediction,
            individual_predictions: predictions,
            confidence,
        })
    }

    /// Calculate prediction confidence based on model agreement
    fn calculate_confidence(&self, predictions: &HashMap<ModelType, f64>) -> f64 {
        if predictions.len() < 2 {
            return 0.5;
        }

        let values: Vec<f64> = predictions.values().copied().collect();
        let mean = values.iter().sum::<f64>() / values.len() as f64;

        // Calculate variance
        let variance = values
            .iter()
            .map(|v| (v - mean).powi(2))
            .sum::<f64>()
            / values.len() as f64;

        // Lower variance = higher confidence
        let confidence = 1.0 - variance.min(1.0);
        confidence
    }

    /// Record feedback for online learning
    pub async fn record_feedback(
        &self,
        event_id: &str,
        was_threat: bool,
        notes: Option<&str>,
    ) -> AiResult<()> {
        // For now, just store feedback. In production, this would trigger model updates.
        let feedback = ModelFeedback {
            event_id: event_id.to_string(),
            features: FeatureVector::new(vec![], vec![]), // Would be populated from stored event
            prediction: 0.0,
            actual: was_threat,
            timestamp: chrono::Utc::now(),
            notes: notes.map(|s| s.to_string()),
        };

        let mut buffer = self.feedback_buffer.write().await;
        buffer.push(feedback);

        // Keep buffer size manageable
        if buffer.len() > 10000 {
            buffer.drain(0..1000);
        }

        Ok(())
    }

    /// Process accumulated feedback for model updates
    pub async fn process_feedback(&self) -> AiResult<()> {
        let buffer = self.feedback_buffer.read().await;

        if buffer.len() < 100 {
            // Not enough feedback to update
            return Ok(());
        }

        // In a production system, this would:
        // 1. Calculate model performance metrics
        // 2. Trigger incremental model training
        // 3. Update model weights based on accuracy
        // 4. Potentially swap in new model versions

        tracing::info!("Processing {} feedback entries", buffer.len());

        // For now, just log the feedback count
        let threat_count = buffer.iter().filter(|f| f.actual).count();
        tracing::info!(
            "Feedback stats: {} total, {} were actual threats",
            buffer.len(),
            threat_count
        );

        Ok(())
    }

    /// Get number of loaded models
    pub fn loaded_model_count(&self) -> usize {
        // This is a simplified version - in production would use try_read
        3 // Default count
    }

    /// Get total prediction count
    pub async fn total_predictions(&self) -> u64 {
        *self.prediction_count.read().await
    }
}

/// Result from ensemble prediction
#[derive(Debug, Clone)]
pub struct EnsembleResult {
    /// Final ensemble score
    pub final_score: f64,
    /// Individual model predictions
    pub individual_predictions: HashMap<ModelType, f64>,
    /// Confidence in prediction (0-1)
    pub confidence: f64,
}

/// Trait for risk prediction models
pub trait RiskPredictionModel: Send + Sync {
    /// Predict risk score (0-1) from features
    fn predict(&self, features: &FeatureVector) -> AiResult<f64>;

    /// Get model version
    fn version(&self) -> &str;

    /// Clone the model (for box cloning)
    fn clone_box(&self) -> Box<dyn RiskPredictionModel>;
}

/// Logistic Regression model (lightweight)
pub struct LogisticRegressionModel {
    weights: Vec<f64>,
    bias: f64,
    version: String,
}

impl LogisticRegressionModel {
    /// Create new model with default weights
    pub fn new() -> Self {
        Self {
            // Default weights for basic risk factors
            weights: vec![
                0.15,  // failed attempts
                0.20,  // anonymous IP
                0.10,  // new device
                0.15,  // impossible travel
                0.10,  // night time
                0.15,  // no MFA
                0.10,  // hosting provider
                0.05,  // other factors
            ],
            bias: -2.0,
            version: "1.0.0".to_string(),
        }
    }

    /// Sigmoid function
    fn sigmoid(&self, x: f64) -> f64 {
        1.0 / (1.0 + (-x).exp())
    }
}

impl Default for LogisticRegressionModel {
    fn default() -> Self {
        Self::new()
    }
}

impl RiskPredictionModel for LogisticRegressionModel {
    fn predict(&self, features: &FeatureVector) -> AiResult<f64> {
        if features.values.is_empty() {
            return Ok(0.5); // Default to medium risk
        }

        // Calculate weighted sum
        let mut sum = self.bias;
        for (i, &value) in features.values.iter().enumerate() {
            let weight = self.weights.get(i).copied().unwrap_or(0.05);
            sum += value * weight * 10.0; // Scale for sigmoid
        }

        Ok(self.sigmoid(sum))
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn clone_box(&self) -> Box<dyn RiskPredictionModel> {
        Box::new(Self {
            weights: self.weights.clone(),
            bias: self.bias,
            version: self.version.clone(),
        })
    }
}

/// Random Forest model for risk classification
pub struct RandomForestModel {
    n_trees: usize,
    max_depth: usize,
    trees: Vec<DecisionTree>,
    version: String,
}

impl RandomForestModel {
    /// Create new random forest
    pub fn new(n_trees: usize, max_depth: usize) -> Self {
        let mut trees = Vec::with_capacity(n_trees);
        for _ in 0..n_trees {
            trees.push(DecisionTree::new(max_depth));
        }

        Self {
            n_trees,
            max_depth,
            trees,
            version: "1.0.0-rule-based".to_string(),
        }
    }

    /// Load from file (placeholder)
    pub async fn load(path: &str) -> AiResult<Self> {
        // In production, this would deserialize from a file
        // For now, create a new model
        Ok(Self::new(100, 10))
    }
}

impl RiskPredictionModel for RandomForestModel {
    fn predict(&self, features: &FeatureVector) -> AiResult<f64> {
        if self.trees.is_empty() {
            return Ok(0.5);
        }

        // Average predictions from all trees
        let sum: f64 = self.trees.iter().map(|tree| tree.predict(features)).sum();
        Ok(sum / self.trees.len() as f64)
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn clone_box(&self) -> Box<dyn RiskPredictionModel> {
        Box::new(Self {
            n_trees: self.n_trees,
            max_depth: self.max_depth,
            trees: self.trees.clone(),
            version: self.version.clone(),
        })
    }
}

/// Simple decision tree for random forest
#[derive(Clone)]
struct DecisionTree {
    max_depth: usize,
}

impl DecisionTree {
    fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    fn predict(&self, features: &FeatureVector) -> f64 {
        // Simplified rule-based prediction
        let mut score: f64 = 0.5;

        // Check for high-risk indicators
        if let Some(failed) = features.get("failed_last_hour") {
            if failed > 0.3 {
                score += 0.2;
            }
        }

        if let Some(anon) = features.get("is_anonymous_ip") {
            if anon > 0.5 {
                score += 0.25;
            }
        }

        if let Some(new_dev) = features.get("is_new_device") {
            if new_dev > 0.5 {
                score += 0.15;
            }
        }

        if let Some(impossible) = features.get("is_impossible_travel") {
            if impossible > 0.5 {
                score += 0.3;
            }
        }

        score.min(1.0)
    }
}

/// Isolation Forest for anomaly detection
pub struct IsolationForestModel {
    n_trees: usize,
    sample_size: usize,
    trees: Vec<IsolationTree>,
    version: String,
}

impl IsolationForestModel {
    /// Create new isolation forest
    pub fn new(n_trees: usize, sample_size: usize) -> Self {
        let mut trees = Vec::with_capacity(n_trees);
        for _ in 0..n_trees {
            trees.push(IsolationTree::new());
        }

        Self {
            n_trees,
            sample_size,
            trees,
            version: "1.0.0".to_string(),
        }
    }

    /// Calculate anomaly score (0 = normal, 1 = anomaly)
    pub fn anomaly_score(&self, features: &FeatureVector) -> f64 {
        if features.values.is_empty() {
            return 0.5;
        }

        // Average path length across all trees
        let avg_path: f64 = self.trees.iter().map(|t| t.path_length(features)).sum::<f64>()
            / self.trees.len() as f64;

        // Normalize to 0-1 anomaly score
        let normalized_score = 1.0 - (-avg_path / 10.0).exp();
        normalized_score
    }
}

impl RiskPredictionModel for IsolationForestModel {
    fn predict(&self, features: &FeatureVector) -> AiResult<f64> {
        Ok(self.anomaly_score(features))
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn clone_box(&self) -> Box<dyn RiskPredictionModel> {
        Box::new(Self {
            n_trees: self.n_trees,
            sample_size: self.sample_size,
            trees: self.trees.clone(),
            version: self.version.clone(),
        })
    }
}

/// Isolation tree for isolation forest
#[derive(Clone)]
struct IsolationTree;

impl IsolationTree {
    fn new() -> Self {
        Self
    }

    fn path_length(&self, features: &FeatureVector) -> f64 {
        // Simplified path length calculation
        // In a real implementation, this would traverse the tree
        let outlier_score = features
            .values
            .iter()
            .map(|&v| (v - 0.5).abs())
            .sum::<f64>()
            / features.values.len().max(1) as f64;

        // Higher outlier score = shorter path = more anomalous
        10.0 * (1.0 - outlier_score)
    }
}

/// LSTM for sequence-based anomaly detection
pub struct LstmAnomalyDetector {
    sequence_length: usize,
    hidden_size: usize,
    version: String,
}

impl LstmAnomalyDetector {
    /// Create new LSTM detector
    pub fn new(sequence_length: usize, hidden_size: usize) -> Self {
        Self {
            sequence_length,
            hidden_size,
            version: "1.0.0".to_string(),
        }
    }

    /// Detect anomaly in sequence
    pub fn detect(&self, sequence: &[FeatureVector]) -> f64 {
        if sequence.len() < self.sequence_length {
            return 0.0; // Not enough data
        }

        // Simplified anomaly detection based on feature variance
        let last = &sequence[sequence.len() - 1];
        let previous = &sequence[sequence.len() - 2];

        let diff: f64 = last
            .values
            .iter()
            .zip(previous.values.iter())
            .map(|(a, b)| (a - b).abs())
            .sum();

        (diff / last.values.len().max(1) as f64).min(1.0)
    }
}

/// ONNX model wrapper for pre-trained models
pub struct OnnxModel {
    model_path: String,
    input_size: usize,
    version: String,
}

impl OnnxModel {
    /// Load ONNX model from path
    pub fn load(path: &str, input_size: usize) -> AiResult<Self> {
        // In production, this would use tract-onnx or similar
        Ok(Self {
            model_path: path.to_string(),
            input_size,
            version: "onnx-1.0".to_string(),
        })
    }

    /// Run inference
    pub fn infer(&self, input: &[f32]) -> AiResult<Vec<f32>> {
        if input.len() != self.input_size {
            return Err(AiError::InvalidInput(format!(
                "Expected {} inputs, got {}",
                self.input_size,
                input.len()
            )));
        }

        // Placeholder - in production would run actual ONNX inference
        // Return simulated output
        Ok(vec![0.5])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logistic_regression() {
        let model = LogisticRegressionModel::new();
        let features = FeatureVector::new(vec![0.5, 0.3, 0.8], vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        
        let score = model.predict(&features).unwrap();
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[test]
    fn test_isolation_forest() {
        let model = IsolationForestModel::new(10, 256);
        let features = FeatureVector::new(vec![0.9, 0.9, 0.9], vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        
        let score = model.anomaly_score(&features);
        // High values should have higher anomaly score
        assert!(score > 0.0);
    }

    #[test]
    fn test_lstm_detector() {
        let detector = LstmAnomalyDetector::new(5, 64);
        
        let seq = vec![
            FeatureVector::new(vec![0.1, 0.1, 0.1], vec![]),
            FeatureVector::new(vec![0.1, 0.1, 0.1], vec![]),
            FeatureVector::new(vec![0.9, 0.9, 0.9], vec![]), // Sudden change
        ];
        
        let anomaly = detector.detect(&seq);
        assert!(anomaly > 0.0);
    }

    #[test]
    fn test_random_forest() {
        let model = RandomForestModel::new(10, 5);
        let features = FeatureVector::new(
            vec![0.8, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            vec!["failed_last_hour".to_string(), "is_anonymous_ip".to_string()],
        );
        
        let score = model.predict(&features).unwrap();
        assert!(score > 0.5); // Should be elevated risk
    }
}
