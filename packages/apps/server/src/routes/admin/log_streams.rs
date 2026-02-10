//! Admin Log Streaming Routes

use axum::{
    extract::{Path, State},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/log-streams", get(list_streams).post(create_stream))
        .route(
            "/log-streams/:stream_id",
            get(get_stream).patch(update_stream).delete(delete_stream),
        )
}

#[derive(Debug, Deserialize)]
struct CreateStreamRequest {
    name: String,
    #[serde(rename = "destinationType")]
    destination_type: String,
    config: serde_json::Value,
    filter: Option<serde_json::Value>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateStreamRequest {
    name: Option<String>,
    config: Option<serde_json::Value>,
    filter: Option<serde_json::Value>,
    status: Option<String>,
}

#[derive(Debug, Serialize)]
struct StreamResponse {
    id: String,
    name: String,
    #[serde(rename = "destinationType")]
    destination_type: String,
    config: serde_json::Value,
    filter: serde_json::Value,
    status: String,
    #[serde(rename = "lastDeliveredAt")]
    last_delivered_at: Option<String>,
    #[serde(rename = "lastError")]
    last_error: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
}

async fn list_streams(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<StreamResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let streams = state
        .auth_service
        .db()
        .log_streams()
        .list_streams(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(
        streams
            .into_iter()
            .map(|s| StreamResponse {
                id: s.id,
                name: s.name,
                destination_type: s.destination_type,
                config: s.config,
                filter: s.filter,
                status: s.status,
                last_delivered_at: s.last_delivered_at.map(|d| d.to_rfc3339()),
                last_error: s.last_error,
                created_at: s.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}

async fn create_stream(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateStreamRequest>,
) -> Result<Json<StreamResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let stream = state
        .auth_service
        .db()
        .log_streams()
        .create_stream(
            &current_user.tenant_id,
            &req.name,
            &req.destination_type,
            req.config,
            req.filter.unwrap_or_else(|| serde_json::json!({})),
            req.status.as_deref().unwrap_or("active"),
        )
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(StreamResponse {
        id: stream.id,
        name: stream.name,
        destination_type: stream.destination_type,
        config: stream.config,
        filter: stream.filter,
        status: stream.status,
        last_delivered_at: stream.last_delivered_at.map(|d| d.to_rfc3339()),
        last_error: stream.last_error,
        created_at: stream.created_at.to_rfc3339(),
    }))
}

async fn get_stream(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(stream_id): Path<String>,
) -> Result<Json<StreamResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let stream = state
        .auth_service
        .db()
        .log_streams()
        .get_stream(&current_user.tenant_id, &stream_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(StreamResponse {
        id: stream.id,
        name: stream.name,
        destination_type: stream.destination_type,
        config: stream.config,
        filter: stream.filter,
        status: stream.status,
        last_delivered_at: stream.last_delivered_at.map(|d| d.to_rfc3339()),
        last_error: stream.last_error,
        created_at: stream.created_at.to_rfc3339(),
    }))
}

async fn update_stream(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(stream_id): Path<String>,
    Json(req): Json<UpdateStreamRequest>,
) -> Result<Json<StreamResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let stream = state
        .auth_service
        .db()
        .log_streams()
        .update_stream(
            &current_user.tenant_id,
            &stream_id,
            req.name.as_deref(),
            req.config,
            req.filter,
            req.status.as_deref(),
        )
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(StreamResponse {
        id: stream.id,
        name: stream.name,
        destination_type: stream.destination_type,
        config: stream.config,
        filter: stream.filter,
        status: stream.status,
        last_delivered_at: stream.last_delivered_at.map(|d| d.to_rfc3339()),
        last_error: stream.last_error,
        created_at: stream.created_at.to_rfc3339(),
    }))
}

async fn delete_stream(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(stream_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .auth_service
        .db()
        .log_streams()
        .delete_stream(&current_user.tenant_id, &stream_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(serde_json::json!({"message": "Log stream deleted"})))
}
