//! Admin Branding Routes

use axum::{
    extract::State,
    routing::{get, patch},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/branding", get(get_branding).patch(update_branding))
        .route("/themes", get(get_theme).patch(update_theme))
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct BrandingResponse {
    #[serde(rename = "logoUrl")]
    logo_url: Option<String>,
    #[serde(rename = "faviconUrl")]
    favicon_url: Option<String>,
    #[serde(rename = "productName")]
    product_name: Option<String>,
    #[serde(rename = "supportEmail")]
    support_email: Option<String>,
    #[serde(rename = "primaryColor")]
    primary_color: Option<String>,
    #[serde(rename = "secondaryColor")]
    secondary_color: Option<String>,
    #[serde(rename = "customCss")]
    custom_css: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct ThemeResponse {
    theme: serde_json::Value,
}

async fn get_branding(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<BrandingResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Json(BrandingResponse::default()))
}

async fn update_branding(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<BrandingResponse>,
) -> Result<Json<BrandingResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Json(req))
}

async fn get_theme(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ThemeResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Json(ThemeResponse {
        theme: serde_json::json!({}),
    }))
}

async fn update_theme(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<ThemeResponse>,
) -> Result<Json<ThemeResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(Json(req))
}
