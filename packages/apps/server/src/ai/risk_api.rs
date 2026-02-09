//! Risk API Endpoints
//!
//! Provides HTTP endpoints for:
//! - Getting current risk scores
//! - User risk profiles
//! - Risk assessment history
//! - Feedback submission for model improvement

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use vault_core::ai::{
    Action, ActionType, AiSecurityConfig, Anomaly, RiskDecision, RiskFactor, RiskLevel,
    RiskRecommendation, RiskScore, UserRiskProfile,
};

use crate::routes::ApiError;
use crate::state::AppState;

/// Risk score response
#[derive(Debug, Serialize)]
pub struct RiskScoreResponse {
    /// Risk score (0-100)
    pub score: u8,
    /// Risk level
    pub level: String,
    /// Risk factors
    pub factors: Vec<RiskFactorDto>,
    /// ML confidence
    pub ml_confidence: f64,
    /// Recommended action
    pub recommended_action: String,
    /// Timestamp
    pub timestamp: String,
}

/// Risk factor DTO
#[derive(Debug, Serialize)]
pub struct RiskFactorDto {
    /// Factor type
    pub factor_type: String,
    /// Contribution to score
    pub contribution: u8,
    /// Description
    pub description: String,
}

/// Risk decision response
#[derive(Debug, Serialize)]
pub struct RiskDecisionResponse {
    /// Final risk score
    pub score: u8,
    /// Risk level
    pub level: String,
    /// Recommended action
    pub action: String,
    /// Risk factors
    pub factors: Vec<RiskFactorDto>,
    /// Detected anomalies
    pub anomalies: Vec<AnomalyDto>,
    /// Recommendations
    pub recommendations: Vec<RecommendationDto>,
}

/// Anomaly DTO
#[derive(Debug, Serialize)]
pub struct AnomalyDto {
    /// Anomaly type
    pub anomaly_type: String,
    /// Severity level
    pub level: String,
    /// Confidence
    pub confidence: f64,
    /// Description
    pub description: String,
}

/// Recommendation DTO
#[derive(Debug, Serialize)]
pub struct RecommendationDto {
    /// Action type
    pub action_type: String,
    /// Reason
    pub reason: String,
    /// Confidence
    pub confidence: f64,
}

/// User risk profile response
#[derive(Debug, Serialize)]
pub struct UserRiskProfileResponse {
    /// User ID
    pub user_id: String,
    /// Baseline score
    pub baseline_score: u8,
    /// Recent anomalies
    pub recent_anomalies: Vec<AnomalyDto>,
    /// Risk history (last 30 days)
    pub risk_history: Vec<u8>,
    /// Anomaly count
    pub anomaly_count_30d: u32,
    /// Last updated
    pub last_updated: String,
}

/// Get current risk score for request
pub async fn get_current_risk_score(
    State(state): State<AppState>,
) -> Result<Json<RiskScoreResponse>, ApiError> {
    // In production, this would analyze the current request context
    // For now, return a default low-risk score
    let response = RiskScoreResponse {
        score: 15,
        level: "low".to_string(),
        factors: vec![],
        ml_confidence: 0.95,
        recommended_action: "allow".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    Ok(Json(response))
}

/// Query parameters for risk assessments
#[derive(Debug, Deserialize)]
pub struct RiskAssessmentQuery {
    /// Tenant ID filter
    pub tenant_id: Option<String>,
    /// User ID filter
    pub user_id: Option<String>,
    /// Limit results
    pub limit: Option<i64>,
    /// Offset for pagination
    pub offset: Option<i64>,
}

/// List risk assessments
pub async fn list_risk_assessments(
    State(_state): State<AppState>,
    Query(query): Query<RiskAssessmentQuery>,
) -> Result<Json<Vec<RiskAssessmentDto>>, ApiError> {
    debug!("Listing risk assessments with query: {:?}", query);

    // In production, this would query the database
    // Return sample data for now
    let assessments = vec![
        RiskAssessmentDto {
            id: "ra_123".to_string(),
            score: 25,
            level: "low".to_string(),
            action: "allow".to_string(),
            factors: vec![],
            user_id: query.user_id.clone(),
            tenant_id: query.tenant_id.clone().unwrap_or_default(),
            ip_address: Some("192.168.1.1".to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
        },
    ];

    Ok(Json(assessments))
}

/// Risk assessment DTO
#[derive(Debug, Serialize)]
pub struct RiskAssessmentDto {
    /// Assessment ID
    pub id: String,
    /// Risk score
    pub score: u8,
    /// Risk level
    pub level: String,
    /// Action taken
    pub action: String,
    /// Risk factors
    pub factors: Vec<RiskFactorDto>,
    /// User ID
    pub user_id: Option<String>,
    /// Tenant ID
    pub tenant_id: String,
    /// IP address
    pub ip_address: Option<String>,
    /// Timestamp
    pub timestamp: String,
}

/// Get user risk profile
pub async fn get_user_risk_profile(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<UserRiskProfileResponse>, ApiError> {
    info!("Getting risk profile for user: {}", user_id);

    // Try to get from AI engine
    if let Some(ref ai_engine) = state.ai_engine {
        match ai_engine.get_user_risk_profile(&user_id).await {
            Ok(profile) => {
                let response = UserRiskProfileResponse {
                    user_id: profile.user_id,
                    baseline_score: profile.baseline_score,
                    recent_anomalies: profile
                        .recent_anomalies
                        .into_iter()
                        .map(|a| AnomalyDto {
                            anomaly_type: format!("{:?}", a.anomaly_type),
                            level: format!("{:?}", a.level).to_lowercase(),
                            confidence: a.confidence,
                            description: a.description,
                        })
                        .collect(),
                    risk_history: profile.risk_history,
                    anomaly_count_30d: profile.anomaly_count_30d,
                    last_updated: profile.last_updated.to_rfc3339(),
                };
                return Ok(Json(response));
            }
            Err(e) => {
                warn!("Failed to get risk profile from AI engine: {}", e);
            }
        }
    }

    // Return default profile if AI engine not available
    let response = UserRiskProfileResponse {
        user_id,
        baseline_score: 20,
        recent_anomalies: vec![],
        risk_history: vec![20, 15, 25, 18, 22],
        anomaly_count_30d: 0,
        last_updated: chrono::Utc::now().to_rfc3339(),
    };

    Ok(Json(response))
}

/// Risk feedback request
#[derive(Debug, Deserialize)]
pub struct RiskFeedbackRequest {
    /// Event ID
    pub event_id: String,
    /// Was this actually a threat
    pub was_threat: bool,
    /// Optional notes
    pub notes: Option<String>,
}

/// Submit feedback for risk assessment
pub async fn submit_risk_feedback(
    State(state): State<AppState>,
    Json(request): Json<RiskFeedbackRequest>,
) -> Result<Json<RiskFeedbackResponse>, ApiError> {
    info!(
        "Received risk feedback for event {}: was_threat={}",
        request.event_id, request.was_threat
    );

    // Submit to AI engine
    if let Some(ref ai_engine) = state.ai_engine {
        match ai_engine
            .submit_feedback(&request.event_id, request.was_threat, request.notes.as_deref())
            .await
        {
            Ok(_) => {
                let response = RiskFeedbackResponse {
                    success: true,
                    message: "Feedback recorded successfully".to_string(),
                };
                Ok(Json(response))
            }
            Err(e) => {
                warn!("Failed to submit feedback: {}", e);
                Err(ApiError::internal_error(format!(
                    "Failed to record feedback: {}",
                    e
                )))
            }
        }
    } else {
        // AI engine not available, but still return success
        let response = RiskFeedbackResponse {
            success: true,
            message: "Feedback noted (AI engine offline)".to_string(),
        };
        Ok(Json(response))
    }
}

/// Risk feedback response
#[derive(Debug, Serialize)]
pub struct RiskFeedbackResponse {
    /// Success flag
    pub success: bool,
    /// Message
    pub message: String,
}

/// AI system status response
#[derive(Debug, Serialize)]
pub struct AiSystemStatusResponse {
    /// System status
    pub status: String,
    /// ML risk scoring enabled
    pub ml_risk_enabled: bool,
    /// Anomaly detection enabled
    pub anomaly_detection_enabled: bool,
    /// Threat detection enabled
    pub threat_detection_enabled: bool,
    /// Behavioral biometrics enabled
    pub behavioral_biometrics_enabled: bool,
    /// Models loaded
    pub models_loaded: usize,
    /// Total assessments
    pub total_assessments: u64,
    /// Total anomalies detected
    pub total_anomalies_detected: u64,
    /// Total threats blocked
    pub total_threats_blocked: u64,
}

/// Get AI system status
pub async fn get_ai_system_status(
    State(state): State<AppState>,
) -> Result<Json<AiSystemStatusResponse>, ApiError> {
    if let Some(ref ai_engine) = state.ai_engine {
        let status = ai_engine.status();

        let response = AiSystemStatusResponse {
            status: "healthy".to_string(),
            ml_risk_enabled: status.ml_risk_enabled,
            anomaly_detection_enabled: status.anomaly_detection_enabled,
            threat_detection_enabled: status.threat_detection_enabled,
            behavioral_biometrics_enabled: status.behavioral_biometrics_enabled,
            models_loaded: status.models_loaded,
            total_assessments: status.total_assessments,
            total_anomalies_detected: status.total_anomalies_detected,
            total_threats_blocked: status.total_threats_blocked,
        };

        Ok(Json(response))
    } else {
        let response = AiSystemStatusResponse {
            status: "disabled".to_string(),
            ml_risk_enabled: false,
            anomaly_detection_enabled: false,
            threat_detection_enabled: false,
            behavioral_biometrics_enabled: false,
            models_loaded: 0,
            total_assessments: 0,
            total_anomalies_detected: 0,
            total_threats_blocked: 0,
        };

        Ok(Json(response))
    }
}

/// Helper function to convert RiskScore to DTO
fn risk_score_to_dto(score: &RiskScore) -> RiskScoreResponse {
    RiskScoreResponse {
        score: score.score,
        level: score.level.to_string(),
        factors: score
            .factors
            .iter()
            .map(|f| RiskFactorDto {
                factor_type: f.factor_type.clone(),
                contribution: f.contribution,
                description: f.description.clone(),
            })
            .collect(),
        ml_confidence: score.ml_confidence,
        recommended_action: score.level.requires_mfa().then(|| "require_mfa".to_string()).unwrap_or_else(|| "allow".to_string()),
        timestamp: score.timestamp.to_rfc3339(),
    }
}

/// Helper function to convert RiskDecision to DTO
fn risk_decision_to_dto(decision: &RiskDecision) -> RiskDecisionResponse {
    RiskDecisionResponse {
        score: decision.score,
        level: decision.risk_level.to_string(),
        action: format!("{:?}", decision.action).to_lowercase(),
        factors: decision
            .factors
            .iter()
            .map(|f| RiskFactorDto {
                factor_type: f.factor_type.clone(),
                contribution: f.contribution,
                description: f.description.clone(),
            })
            .collect(),
        anomalies: decision
            .anomalies
            .iter()
            .map(|a| AnomalyDto {
                anomaly_type: format!("{:?}", a.anomaly_type),
                level: format!("{:?}", a.level).to_lowercase(),
                confidence: a.confidence,
                description: a.description.clone(),
            })
            .collect(),
        recommendations: decision
            .recommendations
            .iter()
            .map(|r| RecommendationDto {
                action_type: format!("{:?}", r.action_type).to_lowercase(),
                reason: r.reason.clone(),
                confidence: r.confidence,
            })
            .collect(),
    }
}

/// Helper function to convert Action to string
fn action_to_string(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::StepUp => "step_up",
        Action::RequireMfa => "require_mfa",
        Action::Block => "block",
    }
}
