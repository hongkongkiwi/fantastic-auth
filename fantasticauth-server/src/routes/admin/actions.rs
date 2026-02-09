//! Admin Actions/Rules Routes

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/actions", get(list_actions).post(create_action))
        .route(
            "/actions/:action_id",
            get(get_action).patch(update_action).delete(delete_action),
        )
}

#[derive(Debug, Deserialize)]
struct ListActionsQuery {
    trigger: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateActionRequest {
    name: String,
    trigger: String,
    status: Option<String>,
    runtime: Option<String>,
    #[serde(rename = "codeBase64")]
    code_base64: String,
    #[serde(rename = "timeoutMs")]
    timeout_ms: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct UpdateActionRequest {
    name: Option<String>,
    status: Option<String>,
    #[serde(rename = "codeBase64")]
    code_base64: Option<String>,
    #[serde(rename = "timeoutMs")]
    timeout_ms: Option<i32>,
}

#[derive(Debug, Serialize)]
struct ActionResponse {
    id: String,
    name: String,
    trigger: String,
    status: String,
    runtime: String,
    #[serde(rename = "timeoutMs")]
    timeout_ms: i32,
    #[serde(rename = "createdAt")]
    created_at: String,
}

async fn list_actions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListActionsQuery>,
) -> Result<Json<Vec<ActionResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let actions = state
        .auth_service
        .db()
        .actions()
        .list_actions(&current_user.tenant_id, query.trigger.as_deref())
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(
        actions
            .into_iter()
            .map(|a| ActionResponse {
                id: a.id,
                name: a.name,
                trigger: a.trigger,
                status: a.status,
                runtime: a.runtime,
                timeout_ms: a.timeout_ms,
                created_at: a.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}

async fn create_action(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateActionRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let code = base64::engine::general_purpose::STANDARD
        .decode(req.code_base64)
        .map_err(|_| ApiError::BadRequest("Invalid codeBase64".to_string()))?;

    let action = state
        .auth_service
        .db()
        .actions()
        .create_action(
            &current_user.tenant_id,
            &req.name,
            &req.trigger,
            req.status.as_deref().unwrap_or("enabled"),
            req.runtime.as_deref().unwrap_or("wasm"),
            &code,
            req.timeout_ms.unwrap_or(1000),
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(ActionResponse {
        id: action.id,
        name: action.name,
        trigger: action.trigger,
        status: action.status,
        runtime: action.runtime,
        timeout_ms: action.timeout_ms,
        created_at: action.created_at.to_rfc3339(),
    }))
}

async fn get_action(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(action_id): Path<String>,
) -> Result<Json<ActionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let action = state
        .auth_service
        .db()
        .actions()
        .get_action(&current_user.tenant_id, &action_id)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(ActionResponse {
        id: action.id,
        name: action.name,
        trigger: action.trigger,
        status: action.status,
        runtime: action.runtime,
        timeout_ms: action.timeout_ms,
        created_at: action.created_at.to_rfc3339(),
    }))
}

async fn update_action(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(action_id): Path<String>,
    Json(req): Json<UpdateActionRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let code = match req.code_base64 {
        Some(encoded) => Some(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| ApiError::BadRequest("Invalid codeBase64".to_string()))?,
        ),
        None => None,
    };

    let action = state
        .auth_service
        .db()
        .actions()
        .update_action(
            &current_user.tenant_id,
            &action_id,
            req.name.as_deref(),
            req.status.as_deref(),
            code.as_deref(),
            req.timeout_ms,
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(ActionResponse {
        id: action.id,
        name: action.name,
        trigger: action.trigger,
        status: action.status,
        runtime: action.runtime,
        timeout_ms: action.timeout_ms,
        created_at: action.created_at.to_rfc3339(),
    }))
}

async fn delete_action(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(action_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    state
        .auth_service
        .db()
        .actions()
        .delete_action(&current_user.tenant_id, &action_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({"message": "Action deleted"})))
}
