//! Internal support routes

use axum::{
    extract::State,
    routing::get,
    Extension, Json, Router,
};
use serde::Serialize;

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

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/support/tickets", get(list_tickets))
        .route("/support/incidents", get(list_incidents))
        .route("/support/status", get(list_status))
}

async fn list_tickets(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<SupportTicketResponse>>, ApiError> {
    Ok(Json(vec![
        SupportTicketResponse {
            id: "SUP-1023".to_string(),
            subject: "Login failures for tenant Acme Inc".to_string(),
            status: "open".to_string(),
            priority: "high".to_string(),
            updated_at: "2024-02-08T09:20:00Z".to_string(),
        },
        SupportTicketResponse {
            id: "SUP-1019".to_string(),
            subject: "Webhook retry delays".to_string(),
            status: "pending".to_string(),
            priority: "medium".to_string(),
            updated_at: "2024-02-08T07:00:00Z".to_string(),
        },
    ]))
}

async fn list_incidents(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<SupportIncidentResponse>>, ApiError> {
    Ok(Json(vec![
        SupportIncidentResponse {
            id: "INC-3001".to_string(),
            title: "Email delivery delays".to_string(),
            status: "monitoring".to_string(),
            started_at: "2024-02-07T20:00:00Z".to_string(),
        },
        SupportIncidentResponse {
            id: "INC-2997".to_string(),
            title: "API latency spike".to_string(),
            status: "resolved".to_string(),
            started_at: "2024-02-06T08:00:00Z".to_string(),
        },
    ]))
}

async fn list_status(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<ServiceStatusResponse>>, ApiError> {
    Ok(Json(vec![
        ServiceStatusResponse {
            service: "API".to_string(),
            status: "operational".to_string(),
        },
        ServiceStatusResponse {
            service: "Auth".to_string(),
            status: "degraded".to_string(),
        },
        ServiceStatusResponse {
            service: "Billing".to_string(),
            status: "operational".to_string(),
        },
    ]))
}
