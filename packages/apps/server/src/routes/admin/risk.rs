//! Risk-Based Authentication Admin Routes
//!
//! Provides endpoints for configuring and monitoring risk-based authentication.

use axum::{
    extract::{Path, Query, State},
    routing::{get, put},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::security::{
    EnabledFactors, RiskAnalytics, RiskEngineConfig, RiskThresholds, ScoringWeights,
};
use crate::state::{AppState, CurrentUser};

/// Risk configuration response
#[derive(Debug, Serialize)]
pub struct RiskConfigResponse {
    pub enabled: bool,
    pub weights: ScoringWeights,
    pub thresholds: RiskThresholds,
    pub enabled_factors: EnabledFactors,
    pub velocity_window_seconds: u64,
    pub max_velocity_attempts: u32,
    pub unusual_hours_start: u8,
    pub unusual_hours_end: u8,
    pub max_distance_km: f64,
    pub min_time_between_locations: f64,
    pub device_trust_days: u32,
}

impl From<RiskEngineConfig> for RiskConfigResponse {
    fn from(config: RiskEngineConfig) -> Self {
        Self {
            enabled: config.enabled,
            weights: config.weights,
            thresholds: config.thresholds,
            enabled_factors: config.enabled_factors,
            velocity_window_seconds: config.velocity_window_seconds,
            max_velocity_attempts: config.max_velocity_attempts,
            unusual_hours_start: config.unusual_hours_start,
            unusual_hours_end: config.unusual_hours_end,
            max_distance_km: config.max_distance_km,
            min_time_between_locations: config.min_time_between_locations,
            device_trust_days: config.device_trust_days,
        }
    }
}

/// Update risk configuration request
#[derive(Debug, Deserialize)]
pub struct UpdateRiskConfigRequest {
    pub enabled: Option<bool>,
    pub weights: Option<ScoringWeights>,
    pub thresholds: Option<RiskThresholds>,
    pub enabled_factors: Option<EnabledFactors>,
    pub velocity_window_seconds: Option<u64>,
    pub max_velocity_attempts: Option<u32>,
    pub unusual_hours_start: Option<u8>,
    pub unusual_hours_end: Option<u8>,
    pub max_distance_km: Option<f64>,
    pub min_time_between_locations: Option<f64>,
    pub device_trust_days: Option<u32>,
}

/// Risk analytics query parameters
#[derive(Debug, Deserialize)]
pub struct RiskAnalyticsQuery {
    /// Number of days to include (default: 30)
    #[serde(default = "default_days")]
    pub days: i32,
}

fn default_days() -> i32 {
    30
}

/// Risk analytics response
#[derive(Debug, Serialize)]
pub struct RiskAnalyticsResponse {
    pub tenant_id: String,
    pub days: i32,
    pub analytics: RiskAnalytics,
    pub block_rate: f32,
    pub challenge_rate: f32,
}

/// Risk factor summary
#[derive(Debug, Serialize)]
pub struct RiskFactorSummary {
    pub factor_type: String,
    pub total_occurrences: i64,
    pub avg_contribution: f32,
}

/// User risk summary
#[derive(Debug, Serialize)]
pub struct UserRiskSummary {
    pub user_id: String,
    pub email: String,
    pub total_assessments: i64,
    pub avg_risk_score: f32,
    pub last_assessment_at: Option<chrono::DateTime<chrono::Utc>>,
    pub highest_risk_score: i32,
}

/// Create admin routes for risk-based authentication
pub fn routes() -> Router<AppState> {
    Router::new()
        // Get current risk configuration
        .route("/config", get(get_risk_config))
        // Update risk configuration
        .route("/config", put(update_risk_config))
        // Get risk analytics
        .route("/analytics", get(get_risk_analytics))
        // Get recent risk assessments
        .route("/assessments", get(get_recent_assessments))
        // Get user risk summary
        .route("/users/:user_id", get(get_user_risk_summary))
}

/// Get risk configuration
async fn get_risk_config(
    State(state): State<AppState>,
    Extension(_admin): Extension<CurrentUser>,
) -> Result<Json<RiskConfigResponse>, ApiError> {
    // Get config from database
    let config = get_risk_config_from_db(&state, &state.config).await?;

    Ok(Json(RiskConfigResponse::from(config)))
}

/// Update risk configuration
async fn update_risk_config(
    State(state): State<AppState>,
    Extension(_admin): Extension<CurrentUser>,
    Json(req): Json<UpdateRiskConfigRequest>,
) -> Result<Json<RiskConfigResponse>, ApiError> {
    // Get current config
    let mut config = get_risk_config_from_db(&state, &state.config).await?;

    // Apply updates
    if let Some(enabled) = req.enabled {
        config.enabled = enabled;
    }
    if let Some(weights) = req.weights {
        config.weights = weights;
    }
    if let Some(thresholds) = req.thresholds {
        config.thresholds = thresholds;
    }
    if let Some(enabled_factors) = req.enabled_factors {
        config.enabled_factors = enabled_factors;
    }
    if let Some(velocity_window) = req.velocity_window_seconds {
        config.velocity_window_seconds = velocity_window;
    }
    if let Some(max_attempts) = req.max_velocity_attempts {
        config.max_velocity_attempts = max_attempts;
    }
    if let Some(start) = req.unusual_hours_start {
        config.unusual_hours_start = start;
    }
    if let Some(end) = req.unusual_hours_end {
        config.unusual_hours_end = end;
    }
    if let Some(max_distance) = req.max_distance_km {
        config.max_distance_km = max_distance;
    }
    if let Some(min_time) = req.min_time_between_locations {
        config.min_time_between_locations = min_time;
    }
    if let Some(trust_days) = req.device_trust_days {
        config.device_trust_days = trust_days;
    }

    // Save to database
    save_risk_config_to_db(&state, &config).await?;

    tracing::info!("Risk configuration updated");

    Ok(Json(RiskConfigResponse::from(config)))
}

/// Get risk analytics
async fn get_risk_analytics(
    State(state): State<AppState>,
    Extension(_admin): Extension<CurrentUser>,
    Query(query): Query<RiskAnalyticsQuery>,
) -> Result<Json<RiskAnalyticsResponse>, ApiError> {
    // Get tenant ID from admin context (use "default" as fallback)
    let tenant_id = "default".to_string();

    let analytics = state
        .risk_engine
        .get_tenant_analytics(&tenant_id, query.days)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(RiskAnalyticsResponse {
        tenant_id,
        days: query.days,
        block_rate: analytics.block_rate(),
        challenge_rate: analytics.challenge_rate(),
        analytics,
    }))
}

/// Get recent risk assessments
async fn get_recent_assessments(
    State(state): State<AppState>,
    Extension(_admin): Extension<CurrentUser>,
) -> Result<Json<Vec<crate::security::RiskAssessment>>, ApiError> {
    // Get tenant ID from admin context
    let tenant_id = "default".to_string();

    // Get recent assessments (limit to 100)
    let assessments = sqlx::query_as::<
        _,
        crate::security::risk::RiskAssessmentRow,
    >(
        r#"SELECT id, tenant_id, user_id, score, action, factors, ip_address,
                  device_fingerprint, timestamp, metadata
           FROM risk_assessments 
           WHERE tenant_id = $1
           ORDER BY timestamp DESC
           LIMIT 100"#,
    )
    .bind(&tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let assessments: Vec<crate::security::RiskAssessment> =
        assessments.into_iter().map(|r| r.into()).collect();

    Ok(Json(assessments))
}

/// Get user risk summary
async fn get_user_risk_summary(
    State(state): State<AppState>,
    Extension(_admin): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<UserRiskSummary>, ApiError> {
    // Get tenant ID from admin context
    let tenant_id = "default".to_string();

    // Get user details first
    let user_row = sqlx::query_as::<_, UserEmailRow>(
        "SELECT email FROM users WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&user_id)
    .bind(&tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let email = match user_row {
        Some(row) => row.email,
        None => return Err(ApiError::NotFound),
    };

    // Get risk summary from database
    let summary = sqlx::query_as::<_, UserRiskSummaryRow>(
        r#"SELECT 
            COUNT(*) as total_assessments,
            AVG(score) as avg_risk_score,
            MAX(timestamp) as last_assessment_at,
            MAX(score) as highest_risk_score
        FROM risk_assessments 
        WHERE tenant_id = $1 AND user_id = $2"#,
    )
    .bind(&tenant_id)
    .bind(&user_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(Json(UserRiskSummary {
        user_id,
        email,
        total_assessments: summary.total_assessments,
        avg_risk_score: summary.avg_risk_score.unwrap_or(0.0) as f32,
        last_assessment_at: summary.last_assessment_at,
        highest_risk_score: summary.highest_risk_score.unwrap_or(0),
    }))
}

// Database helper functions

async fn get_risk_config_from_db(
    _state: &AppState,
    _config: &std::sync::Arc<crate::config::Config>,
) -> Result<RiskEngineConfig, ApiError> {
    // For now, return default config
    // In production, this would load from the database
    Ok(RiskEngineConfig::default())
}

async fn save_risk_config_to_db(
    _state: &AppState,
    _config: &RiskEngineConfig,
) -> Result<(), ApiError> {
    // For now, just log the save
    // In production, this would save to risk_config table
    tracing::info!("Saving risk configuration to database");
    Ok(())
}

// Database row types
#[derive(sqlx::FromRow)]
struct UserEmailRow {
    email: String,
}

#[derive(sqlx::FromRow)]
struct UserRiskSummaryRow {
    total_assessments: i64,
    avg_risk_score: Option<f64>,
    last_assessment_at: Option<chrono::DateTime<chrono::Utc>>,
    highest_risk_score: Option<i32>,
}

// Re-export types for the risk module
pub use crate::security::risk::{RiskAssessmentRow, RiskAnalyticsRow};
