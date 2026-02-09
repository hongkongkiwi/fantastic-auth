//! AI-Powered Security Module for Vault Server
//!
//! This module provides HTTP endpoints and middleware for the AI security system:
//! - Risk score API endpoints
//! - Threat detection endpoints
//! - AI-powered authentication middleware
//! - Real-time threat monitoring

pub mod middleware;
pub mod risk_api;
pub mod threat_api;

pub use middleware::AiSecurityMiddleware;
pub use risk_api::{get_current_risk_score as get_risk_score, get_user_risk_profile, submit_risk_feedback};
pub use threat_api::{get_active_threats, get_threat_details, resolve_threat};

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use vault_core::ai::{AiSecurityConfig, AiSecurityEngine};

use crate::state::AppState;

/// AI module router
pub fn router() -> Router<AppState> {
    Router::new()
        // Risk API endpoints
        .route("/ai/risk-score", get(risk_api::get_current_risk_score))
        .route("/admin/ai/risk-profile/:user_id", get(risk_api::get_user_risk_profile))
        .route("/admin/ai/risk-assessments", get(risk_api::list_risk_assessments))
        .route("/admin/ai/feedback", post(risk_api::submit_risk_feedback))
        // Threat API endpoints
        .route("/admin/ai/threats", get(threat_api::get_active_threats))
        .route("/admin/ai/threats/:threat_id", get(threat_api::get_threat_details))
        .route("/admin/ai/threats/:threat_id/resolve", post(threat_api::resolve_threat))
        .route("/admin/ai/anomalies", get(threat_api::get_recent_anomalies))
        // System status
        .route("/admin/ai/status", get(risk_api::get_ai_system_status))
}

/// Initialize AI security engine
pub async fn initialize_ai_engine(
    config: AiSecurityConfig,
    db: vault_core::db::DbContext,
) -> anyhow::Result<Arc<AiSecurityEngine>> {
    let engine = AiSecurityEngine::new(config, db).await?;
    Ok(Arc::new(engine))
}
