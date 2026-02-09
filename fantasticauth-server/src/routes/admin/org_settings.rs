//! Organization Settings Routes

use axum::{
    extract::{Path, State},
    routing::{get, put},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::db::set_connection_context;

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/organizations/:org_id/settings",
        get(get_org_settings).put(update_org_settings),
    )
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
struct OrgSettingsPayload {
    auth: serde_json::Value,
    security: serde_json::Value,
    branding: serde_json::Value,
    email: serde_json::Value,
    oauth: serde_json::Value,
    localization: serde_json::Value,
    webhook: serde_json::Value,
    privacy: serde_json::Value,
    advanced: serde_json::Value,
}

async fn get_org_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
) -> Result<Json<OrgSettingsPayload>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let row = sqlx::query_as::<_, OrgSettingsPayload>(
        r#"SELECT
            auth_settings as auth,
            security_settings as security,
            branding_settings as branding,
            email_settings as email,
            oauth_settings as oauth,
            localization_settings as localization,
            webhook_settings as webhook,
            privacy_settings as privacy,
            advanced_settings as advanced
        FROM organization_settings
        WHERE tenant_id = $1::uuid AND organization_id = $2::uuid"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    if let Some(settings) = row {
        return Ok(Json(settings));
    }

    Ok(Json(OrgSettingsPayload {
        auth: serde_json::json!({}),
        security: serde_json::json!({}),
        branding: serde_json::json!({}),
        email: serde_json::json!({}),
        oauth: serde_json::json!({}),
        localization: serde_json::json!({}),
        webhook: serde_json::json!({}),
        privacy: serde_json::json!({}),
        advanced: serde_json::json!({}),
    }))
}

async fn update_org_settings(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
    Json(payload): Json<OrgSettingsPayload>,
) -> Result<Json<OrgSettingsPayload>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let row = sqlx::query_as::<_, OrgSettingsPayload>(
        r#"INSERT INTO organization_settings (
                tenant_id, organization_id, auth_settings, security_settings, branding_settings,
                email_settings, oauth_settings, localization_settings, webhook_settings,
                privacy_settings, advanced_settings
            ) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT (tenant_id, organization_id) DO UPDATE SET
                auth_settings = EXCLUDED.auth_settings,
                security_settings = EXCLUDED.security_settings,
                branding_settings = EXCLUDED.branding_settings,
                email_settings = EXCLUDED.email_settings,
                oauth_settings = EXCLUDED.oauth_settings,
                localization_settings = EXCLUDED.localization_settings,
                webhook_settings = EXCLUDED.webhook_settings,
                privacy_settings = EXCLUDED.privacy_settings,
                advanced_settings = EXCLUDED.advanced_settings,
                updated_at = NOW()
            RETURNING
                auth_settings as auth,
                security_settings as security,
                branding_settings as branding,
                email_settings as email,
                oauth_settings as oauth,
                localization_settings as localization,
                webhook_settings as webhook,
                privacy_settings as privacy,
                advanced_settings as advanced"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .bind(payload.auth)
    .bind(payload.security)
    .bind(payload.branding)
    .bind(payload.email)
    .bind(payload.oauth)
    .bind(payload.localization)
    .bind(payload.webhook)
    .bind(payload.privacy)
    .bind(payload.advanced)
    .fetch_one(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(row))
}
