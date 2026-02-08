//! Threat API Endpoints
//!
//! Provides HTTP endpoints for:
//! - Getting active threats
//! - Threat details and history
//! - Resolving threats
//! - Anomaly reporting

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    response::Json,
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use vault_core::ai::{Attack, AttackType, Anomaly, TimeWindow};
use vault_core::ai::threat_detection::AttackSeverity;

use crate::routes::ApiError;
use crate::state::AppState;

/// Threat list response
#[derive(Debug, Serialize)]
pub struct ThreatListResponse {
    /// Active threats
    pub threats: Vec<ThreatDto>,
    /// Total count
    pub total: usize,
}

/// Threat DTO
#[derive(Debug, Serialize)]
pub struct ThreatDto {
    /// Threat ID
    pub id: String,
    /// Attack type
    pub attack_type: String,
    /// Severity
    pub severity: String,
    /// Status
    pub status: String,
    /// Started at
    pub started_at: String,
    /// Duration in seconds
    pub duration_seconds: i64,
    /// Source IP count
    pub source_ip_count: usize,
    /// Target count
    pub target_count: usize,
    /// Attempt count
    pub attempt_count: u64,
    /// Confidence
    pub confidence: f64,
}

/// Threat detail response
#[derive(Debug, Serialize)]
pub struct ThreatDetailResponse {
    /// Threat ID
    pub id: String,
    /// Attack type
    pub attack_type: String,
    /// Severity
    pub severity: String,
    /// Status
    pub status: String,
    /// Started at
    pub started_at: String,
    /// Ended at (if resolved)
    pub ended_at: Option<String>,
    /// Source IPs
    pub source_ips: Vec<String>,
    /// Target accounts
    pub targets: Vec<String>,
    /// Attempt count
    pub attempt_count: u64,
    /// Success rate
    pub success_rate: f64,
    /// Confidence
    pub confidence: f64,
    /// Details
    pub details: ThreatDetailsDto,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Threat details DTO
#[derive(Debug, Serialize)]
pub struct ThreatDetailsDto {
    /// Pattern description
    pub pattern: String,
    /// Average request rate
    pub avg_request_rate: f64,
    /// Geographic distribution
    pub geo_distribution: Vec<String>,
    /// Time distribution
    pub time_distribution: TimeDistributionDto,
}

/// Time distribution DTO
#[derive(Debug, Serialize)]
pub struct TimeDistributionDto {
    /// Peak hour
    pub peak_hour: u8,
    /// Is distributed
    pub is_distributed: bool,
    /// Has burst pattern
    pub has_burst_pattern: bool,
}

/// Anomaly list response
#[derive(Debug, Serialize)]
pub struct AnomalyListResponse {
    /// Anomalies
    pub anomalies: Vec<AnomalyDto>,
    /// Total count
    pub total: usize,
}

/// Anomaly DTO
#[derive(Debug, Serialize)]
pub struct AnomalyDto {
    /// Anomaly type
    pub anomaly_type: String,
    /// Level
    pub level: String,
    /// Confidence
    pub confidence: f64,
    /// Description
    pub description: String,
    /// Detected at
    pub detected_at: String,
    /// Event ID
    pub event_id: Option<String>,
    /// Suggested action
    pub suggested_action: Option<String>,
}

/// Query parameters for threats
#[derive(Debug, Deserialize)]
pub struct ThreatQuery {
    /// Include resolved threats
    pub include_resolved: Option<bool>,
    /// Filter by type
    pub attack_type: Option<String>,
    /// Filter by severity
    pub severity: Option<String>,
    /// Time window in hours
    pub hours: Option<i64>,
}

/// Get active threats
pub async fn get_active_threats(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ThreatQuery>,
) -> Result<Json<ThreatListResponse>, ApiError> {
    info!("Getting active threats with query: {:?}", query);

    // Try to get from AI engine
    if let Some(ref ai_engine) = state.ai_engine {
        let window = query
            .hours
            .map(TimeWindow::last_hours)
            .unwrap_or_else(|| TimeWindow::last_hours(24));

        match ai_engine.detect_threats(window).await {
            Ok(threats) => {
                let dtos: Vec<ThreatDto> = threats
                    .into_iter()
                    .filter(|t| {
                        query
                            .include_resolved
                            .unwrap_or(false)
                            .then(|| true)
                            .unwrap_or(t.is_active)
                    })
                    .map(|t| attack_to_dto(&t))
                    .collect();

                return Ok(Json(ThreatListResponse {
                    total: dtos.len(),
                    threats: dtos,
                }));
            }
            Err(e) => {
                warn!("Failed to get threats from AI engine: {}", e);
            }
        }
    }

    // Return empty list if AI engine not available
    Ok(Json(ThreatListResponse {
        total: 0,
        threats: vec![],
    }))
}

/// Get threat details
pub async fn get_threat_details(
    State(state): State<Arc<AppState>>,
    Path(threat_id): Path<String>,
) -> Result<Json<ThreatDetailResponse>, ApiError> {
    info!("Getting threat details for: {}", threat_id);

    // Try to get from AI engine
    if let Some(ref ai_engine) = state.ai_engine {
        // In production, would fetch specific threat by ID
        // For now, return sample data
        let response = ThreatDetailResponse {
            id: threat_id,
            attack_type: "distributed_brute_force".to_string(),
            severity: "high".to_string(),
            status: "active".to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
            ended_at: None,
            source_ips: vec!["192.168.1.1".to_string(), "10.0.0.1".to_string()],
            targets: vec!["user1@example.com".to_string()],
            attempt_count: 150,
            success_rate: 0.02,
            confidence: 0.85,
            details: ThreatDetailsDto {
                pattern: "Coordinated brute force from multiple IPs".to_string(),
                avg_request_rate: 30.0,
                geo_distribution: vec!["US".to_string(), "DE".to_string()],
                time_distribution: TimeDistributionDto {
                    peak_hour: 14,
                    is_distributed: true,
                    has_burst_pattern: false,
                },
            },
            recommendations: vec![
                "Enable IP-based blocking".to_string(),
                "Consider enabling CAPTCHA".to_string(),
            ],
        };

        return Ok(Json(response));
    }

    Err(ApiError::not_found("Threat not found"))
}

/// Resolve threat request
#[derive(Debug, Deserialize)]
pub struct ResolveThreatRequest {
    /// Resolution notes
    pub notes: Option<String>,
}

/// Resolve threat response
#[derive(Debug, Serialize)]
pub struct ResolveThreatResponse {
    /// Success
    pub success: bool,
    /// Message
    pub message: String,
}

/// Resolve a threat
pub async fn resolve_threat(
    State(state): State<Arc<AppState>>,
    Path(threat_id): Path<String>,
) -> Result<Json<ResolveThreatResponse>, ApiError> {
    info!("Resolving threat: {}", threat_id);

    // In production, would update threat status in database
    let response = ResolveThreatResponse {
        success: true,
        message: format!("Threat {} marked as resolved", threat_id),
    };

    Ok(Json(response))
}

/// Query parameters for anomalies
#[derive(Debug, Deserialize)]
pub struct AnomalyQuery {
    /// User ID filter
    pub user_id: Option<String>,
    /// Days to look back
    pub days: Option<i64>,
    /// Minimum level
    pub min_level: Option<String>,
}

/// Get recent anomalies
pub async fn get_recent_anomalies(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AnomalyQuery>,
) -> Result<Json<AnomalyListResponse>, ApiError> {
    info!("Getting recent anomalies with query: {:?}", query);

    if let (Some(ref ai_engine), Some(user_id)) = (&state.ai_engine, &query.user_id) {
        let days = query.days.unwrap_or(7);

        match ai_engine.get_user_risk_profile(user_id).await {
            Ok(profile) => {
                let anomalies: Vec<AnomalyDto> = profile
                    .recent_anomalies
                    .into_iter()
                    .map(|a| anomaly_to_dto(&a))
                    .collect();

                return Ok(Json(AnomalyListResponse {
                    total: anomalies.len(),
                    anomalies,
                }));
            }
            Err(e) => {
                warn!("Failed to get anomalies: {}", e);
            }
        }
    }

    // Return empty list
    Ok(Json(AnomalyListResponse {
        total: 0,
        anomalies: vec![],
    }))
}

/// Helper function to convert Attack to DTO
fn attack_to_dto(attack: &Attack) -> ThreatDto {
    ThreatDto {
        id: attack.id.clone(),
        attack_type: format!("{:?}", attack.attack_type).to_lowercase(),
        severity: format!("{:?}", attack.severity).to_lowercase(),
        status: if attack.is_active {
            "active"
        } else {
            "resolved"
        }
        .to_string(),
        started_at: attack.started_at.to_rfc3339(),
        duration_seconds: attack.duration().num_seconds(),
        source_ip_count: attack.source_ips.len(),
        target_count: attack.target_accounts.len(),
        attempt_count: attack.attempt_count,
        confidence: attack.confidence,
    }
}

/// Helper function to convert Anomaly to DTO
fn anomaly_to_dto(anomaly: &Anomaly) -> AnomalyDto {
    AnomalyDto {
        anomaly_type: format!("{:?}", anomaly.anomaly_type).to_lowercase(),
        level: format!("{:?}", anomaly.level).to_lowercase(),
        confidence: anomaly.confidence,
        description: anomaly.description.clone(),
        detected_at: anomaly.detected_at.to_rfc3339(),
        event_id: anomaly.event_id.clone(),
        suggested_action: anomaly.suggested_action.clone(),
    }
}
