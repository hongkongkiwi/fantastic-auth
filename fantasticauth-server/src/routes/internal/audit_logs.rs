//! Internal Audit Log Routes
//!
//! Platform-level audit log access (superadmin/internal API).

use axum::{
    extract::{Query, State},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

const PLATFORM_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";

pub fn routes() -> Router<AppState> {
    Router::new().route("/audit-logs", get(query_audit_logs))
}

#[derive(Debug, Deserialize)]
struct ListAuditQuery {
    tenant_id: Option<String>,
    user_id: Option<String>,
    page: Option<i64>,
    #[serde(rename = "per_page")]
    per_page: Option<i64>,
}

#[derive(Debug, Serialize)]
struct PaginatedAuditResponse {
    data: Vec<AuditLogResponse>,
    pagination: PaginationResponse,
}

#[derive(Debug, Serialize)]
struct PaginationResponse {
    page: i64,
    #[serde(rename = "perPage")]
    per_page: i64,
    total: i64,
    #[serde(rename = "totalPages")]
    total_pages: i64,
}

#[derive(Debug, Serialize)]
struct AuditLogResponse {
    id: String,
    timestamp: String,
    action: String,
    resource_type: String,
    resource_id: String,
    user_id: Option<String>,
    ip_address: Option<String>,
    success: bool,
}

async fn query_audit_logs(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Query(query): Query<ListAuditQuery>,
) -> Result<Json<PaginatedAuditResponse>, ApiError> {
    let tenant_id = query.tenant_id.unwrap_or_else(|| PLATFORM_TENANT_ID.to_string());
    state
        .set_tenant_context(&tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);

    let (entries, total) = state
        .db
        .audit()
        .list_filtered(&tenant_id, query.user_id.as_deref(), page, per_page)
        .await
        .map_err(|_| ApiError::Internal)?;

    let total_pages = (total + per_page - 1) / per_page;

    let data: Vec<AuditLogResponse> = entries
        .into_iter()
        .map(|e| AuditLogResponse {
            id: e.id,
            timestamp: e.timestamp.to_rfc3339(),
            action: e.action,
            resource_type: e.resource_type,
            resource_id: e.resource_id,
            user_id: e.user_id,
            ip_address: e.ip_address,
            success: e.success,
        })
        .collect();

    Ok(Json(PaginatedAuditResponse {
        data,
        pagination: PaginationResponse {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}
