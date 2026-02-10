//! Notification Preferences Routes
//!
//! API endpoints for managing user notification preferences.
//!
//! # Routes
//!
//! - GET /me/notifications/preferences - Get current preferences
//! - PUT /me/notifications/preferences - Update preferences
//! - POST /me/notifications/subscribe - Subscribe to marketing
//! - POST /me/notifications/unsubscribe - Unsubscribe from marketing

use axum::{
    extract::{Extension, State},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

use super::{
    service::NotificationPreferencesService, UpdatePreferencesRequest,
};

/// Create notification routes
pub fn notification_routes() -> Router<AppState> {
    Router::new()
        .route("/me/notifications/preferences", get(get_preferences).put(update_preferences))
        .route("/me/notifications/subscribe", post(subscribe_marketing))
        .route("/me/notifications/unsubscribe", post(unsubscribe_marketing))
}

/// Get current user preferences
async fn get_preferences(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<PreferencesResponse>, ApiError> {
    let service = NotificationPreferencesService::new(
        crate::notifications::NotificationPreferencesRepository::from_pool(state.db.pool())
    );
    
    let prefs = service
        .get_preferences_response(&current_user.user_id)
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to get preferences: {}", e)))?;
    
    Ok(Json(prefs))
}

/// Update user preferences
async fn update_preferences(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(request): Json<UpdatePreferencesRequest>,
) -> Result<Json<PreferencesResponse>, ApiError> {
    let service = NotificationPreferencesService::new(
        crate::notifications::NotificationPreferencesRepository::from_pool(state.db.pool())
    );
    
    let prefs = service
        .update_preferences(&current_user.user_id, request)
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to update preferences: {}", e)))?;
    
    Ok(Json(prefs))
}

/// Subscribe to marketing emails
async fn subscribe_marketing(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(request): Json<SubscribeRequest>,
) -> Result<Json<PreferencesResponse>, ApiError> {
    let service = NotificationPreferencesService::new(
        crate::notifications::NotificationPreferencesRepository::from_pool(state.db.pool())
    );
    
    let categories = request.categories.unwrap_or_else(|| vec!["all".to_string()]);
    
    let prefs = service
        .subscribe_marketing(&current_user.user_id, categories)
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to subscribe: {}", e)))?;
    
    Ok(Json(prefs))
}

/// Unsubscribe from marketing emails
async fn unsubscribe_marketing(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(request): Json<UnsubscribeRequest>,
) -> Result<Json<PreferencesResponse>, ApiError> {
    let service = NotificationPreferencesService::new(
        crate::notifications::NotificationPreferencesRepository::from_pool(state.db.pool())
    );
    
    let prefs = service
        .unsubscribe_marketing(&current_user.user_id, request.categories)
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to unsubscribe: {}", e)))?;
    
    Ok(Json(prefs))
}

/// Subscribe request
#[derive(Debug, Deserialize)]
struct SubscribeRequest {
    /// Categories to subscribe to (defaults to "all")
    pub categories: Option<Vec<String>>,
}

/// Unsubscribe request
#[derive(Debug, Deserialize)]
struct UnsubscribeRequest {
    /// Categories to unsubscribe from (defaults to all)
    pub categories: Option<Vec<String>>,
}

/// Preferences response
use super::PreferencesResponse;
