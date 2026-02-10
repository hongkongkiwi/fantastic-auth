//! Admin Audit Export Routes

use axum::{
    extract::{Path, State},
    routing::{delete, get},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/audit-logs/exports",
            get(list_audit_exports).post(create_audit_export),
        )
        .route(
            "/audit-logs/webhooks",
            get(list_audit_webhooks).post(create_audit_webhook),
        )
        .route(
            "/audit-logs/webhooks/:webhook_id",
            delete(delete_audit_webhook),
        )
}

#[derive(Debug, Deserialize)]
struct CreateAuditExportRequest {
    format: String,
    from: String,
    to: String,
}

#[derive(Debug, Serialize)]
struct AuditExportResponse {
    id: String,
    status: String,
    format: String,
    from: String,
    to: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct CreateAuditWebhookRequest {
    url: String,
    secret: String,
}

#[derive(Debug, Serialize)]
struct AuditWebhookResponse {
    id: String,
    url: String,
    status: String,
    #[serde(rename = "secretLastFour")]
    secret_last_four: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

async fn list_audit_exports(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(serde_json::json!({"data": []})))
}

async fn create_audit_export(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateAuditExportRequest>,
) -> Result<Json<AuditExportResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(AuditExportResponse {
        id: uuid::Uuid::new_v4().to_string(),
        status: "queued".to_string(),
        format: req.format,
        from: req.from,
        to: req.to,
        created_at: chrono::Utc::now().to_rfc3339(),
    }))
}

async fn list_audit_webhooks(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(Json(serde_json::json!({"data": []})))
}

async fn create_audit_webhook(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateAuditWebhookRequest>,
) -> Result<Json<AuditWebhookResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    let secret_last_four = req
        .secret
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    Ok(Json(AuditWebhookResponse {
        id: uuid::Uuid::new_v4().to_string(),
        url: req.url,
        status: "active".to_string(),
        secret_last_four,
        created_at: chrono::Utc::now().to_rfc3339(),
    }))
}

async fn delete_audit_webhook(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(_webhook_id): Path<String>,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;
    Ok(())
}
