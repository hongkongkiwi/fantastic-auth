//! Internal support routes

use axum::{
    extract::State,
    routing::get,
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::permissions::checker::PermissionChecker;
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

#[derive(Debug, Serialize)]
pub struct SupportTicketResponse {
    pub id: String,
    pub subject: String,
    pub status: String,
    pub priority: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct SupportIncidentResponse {
    pub id: String,
    pub title: String,
    pub status: String,
    #[serde(rename = "startedAt")]
    pub started_at: String,
}

#[derive(Debug, Serialize)]
pub struct ServiceStatusResponse {
    pub service: String,
    pub status: String,
}

#[derive(Debug, sqlx::FromRow)]
struct SupportTicketRow {
    id: String,
    subject: String,
    status: String,
    priority: String,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct SupportIncidentRow {
    id: String,
    title: String,
    status: String,
    started_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct ServiceStatusRow {
    service: String,
    status: String,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/support/tickets", get(list_tickets))
        .route("/support/incidents", get(list_incidents))
        .route("/support/status", get(list_status))
}

async fn require_support_read(
    state: &AppState,
    current_user: &CurrentUser,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let checker = PermissionChecker::new(state.db.pool().clone(), state.redis.clone());
    let allowed = checker
        .has_permission(&current_user.user_id, "settings:read")
        .await;
    if !allowed {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn list_tickets(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<SupportTicketResponse>>, ApiError> {
    require_support_read(&state, &current_user).await?;

    let rows = sqlx::query_as::<_, SupportTicketRow>(
        r#"
        SELECT id::text as id,
               subject,
               status,
               priority,
               updated_at
        FROM support_tickets
        WHERE tenant_id = $1::uuid
        ORDER BY updated_at DESC
        "#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let tickets = rows
        .into_iter()
        .map(|row| SupportTicketResponse {
            id: row.id,
            subject: row.subject,
            status: row.status,
            priority: row.priority,
            updated_at: row.updated_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(tickets))
}

async fn list_incidents(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<SupportIncidentResponse>>, ApiError> {
    require_support_read(&state, &current_user).await?;

    let rows = sqlx::query_as::<_, SupportIncidentRow>(
        r#"
        SELECT id::text as id,
               title,
               status,
               started_at
        FROM support_incidents
        WHERE tenant_id = $1::uuid
        ORDER BY started_at DESC
        "#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let incidents = rows
        .into_iter()
        .map(|row| SupportIncidentResponse {
            id: row.id,
            title: row.title,
            status: row.status,
            started_at: row.started_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(incidents))
}

async fn list_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<ServiceStatusResponse>>, ApiError> {
    require_support_read(&state, &current_user).await?;

    let rows = sqlx::query_as::<_, ServiceStatusRow>(
        r#"
        SELECT service,
               status
        FROM service_status
        WHERE tenant_id = $1::uuid
        ORDER BY service ASC
        "#,
    )
    .bind(&current_user.tenant_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let status = rows
        .into_iter()
        .map(|row| ServiceStatusResponse {
            service: row.service,
            status: row.status,
        })
        .collect();

    Ok(Json(status))
}
