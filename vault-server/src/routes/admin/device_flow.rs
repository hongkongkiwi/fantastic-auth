//! Admin Device Flow Approvals

use axum::{
    extract::{Path, State},
    routing::post,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::db::set_connection_context;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/device-codes/:user_code/approve", post(approve_device_code))
        .route("/device-codes/:user_code/deny", post(deny_device_code))
}

#[derive(Debug, Deserialize)]
struct ApproveDeviceCodeRequest {
    #[serde(rename = "userId")]
    user_id: String,
}

#[derive(Debug, Serialize)]
struct DeviceCodeResponse {
    approved: bool,
}

async fn approve_device_code(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_code): Path<String>,
    Json(req): Json<ApproveDeviceCodeRequest>,
) -> Result<Json<DeviceCodeResponse>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let result = sqlx::query(
        "UPDATE oauth_device_codes SET status = 'approved', user_id = $1::uuid, approved_at = NOW() WHERE tenant_id = $2::uuid AND user_code = $3 AND status = 'pending'",
    )
    .bind(&req.user_id)
    .bind(&current_user.tenant_id)
    .bind(&user_code)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(DeviceCodeResponse {
        approved: result.rows_affected() > 0,
    }))
}

async fn deny_device_code(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_code): Path<String>,
) -> Result<Json<DeviceCodeResponse>, ApiError> {
    let mut conn = state.db.pool().acquire().await.map_err(|_| ApiError::Internal)?;
    set_connection_context(&mut conn, &current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let result = sqlx::query(
        "UPDATE oauth_device_codes SET status = 'denied', denied_at = NOW() WHERE tenant_id = $1::uuid AND user_code = $2 AND status = 'pending'",
    )
    .bind(&current_user.tenant_id)
    .bind(&user_code)
    .execute(&mut *conn)
    .await
    .map_err(|_| ApiError::Internal)?;

    Ok(Json(DeviceCodeResponse {
        approved: result.rows_affected() > 0,
    }))
}
