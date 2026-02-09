//! Admin Security Policies Routes

use axum::{
    extract::{Path, State},
    routing::{patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/security/policies", post(create_policy))
        .route("/security/policies/:policy_id", patch(update_policy))
}

#[derive(Debug, Deserialize)]
struct CreateSecurityPolicyRequest {
    name: String,
    enabled: Option<bool>,
    conditions: serde_json::Value,
    actions: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct UpdateSecurityPolicyRequest {
    name: Option<String>,
    enabled: Option<bool>,
    conditions: Option<serde_json::Value>,
    actions: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct SecurityPolicyResponse {
    id: String,
    name: String,
    enabled: bool,
    conditions: serde_json::Value,
    actions: serde_json::Value,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

async fn create_policy(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateSecurityPolicyRequest>,
) -> Result<Json<SecurityPolicyResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(SecurityPolicyResponse {
        id: uuid::Uuid::new_v4().to_string(),
        name: req.name,
        enabled: req.enabled.unwrap_or(true),
        conditions: req.conditions,
        actions: req.actions,
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    }))
}

async fn update_policy(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(policy_id): Path<String>,
    Json(req): Json<UpdateSecurityPolicyRequest>,
) -> Result<Json<SecurityPolicyResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(SecurityPolicyResponse {
        id: policy_id,
        name: req.name.unwrap_or_else(|| "policy".to_string()),
        enabled: req.enabled.unwrap_or(true),
        conditions: req.conditions.unwrap_or_else(|| serde_json::json!({})),
        actions: req.actions.unwrap_or_else(|| serde_json::json!({})),
        created_at: chrono::Utc::now().to_rfc3339(),
        updated_at: chrono::Utc::now().to_rfc3339(),
    }))
}
