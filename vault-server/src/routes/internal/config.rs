//! Internal Config Routes
//!
//! Platform configuration and feature flags (superadmin only).

use axum::{
    extract::{Path, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Config routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/features", get(list_features).post(create_feature))
        .route(
            "/features/:key",
            get(get_feature)
                .patch(update_feature)
                .delete(delete_feature),
        )
        .route("/oauth", get(list_oauth_providers))
}

#[derive(Debug, Deserialize)]
struct CreateFeatureRequest {
    key: String,
    name: String,
    enabled: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateFeatureRequest {
    enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
struct FeatureFlagResponse {
    key: String,
    name: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct OAuthProviderResponse {
    id: String,
    name: String,
    enabled: bool,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

/// List feature flags
async fn list_features(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<FeatureFlagResponse>>, ApiError> {
    Ok(Json(vec![]))
}

/// Create feature flag
async fn create_feature(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Json(req): Json<CreateFeatureRequest>,
) -> Result<Json<FeatureFlagResponse>, ApiError> {
    Ok(Json(FeatureFlagResponse {
        key: req.key,
        name: req.name,
        enabled: req.enabled,
    }))
}

/// Get feature flag
async fn get_feature(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(key): Path<String>,
) -> Result<Json<FeatureFlagResponse>, ApiError> {
    Ok(Json(FeatureFlagResponse {
        key,
        name: "Feature".to_string(),
        enabled: false,
    }))
}

/// Update feature flag
async fn update_feature(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(key): Path<String>,
    Json(req): Json<UpdateFeatureRequest>,
) -> Result<Json<FeatureFlagResponse>, ApiError> {
    Ok(Json(FeatureFlagResponse {
        key,
        name: "Feature".to_string(),
        enabled: req.enabled.unwrap_or(false),
    }))
}

/// Delete feature flag
async fn delete_feature(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(key): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    Ok(Json(MessageResponse {
        message: format!("Feature {} deleted", key),
    }))
}

/// List OAuth providers
async fn list_oauth_providers(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<OAuthProviderResponse>>, ApiError> {
    Ok(Json(vec![
        OAuthProviderResponse {
            id: "google".to_string(),
            name: "Google".to_string(),
            enabled: true,
        },
        OAuthProviderResponse {
            id: "github".to_string(),
            name: "GitHub".to_string(),
            enabled: true,
        },
    ]))
}
