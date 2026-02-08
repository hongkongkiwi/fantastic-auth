//! Internal notifications routes

use axum::{
    extract::State,
    routing::{get, post},
    Extension, Json, Router,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

#[derive(Debug, Serialize, Clone)]
pub struct NotificationResponse {
    pub id: String,
    pub title: String,
    pub description: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub r#type: String,
    pub read: bool,
}

#[derive(Debug, Deserialize)]
struct MarkReadRequest {
    ids: Vec<String>,
}

static NOTIFICATIONS: Lazy<Mutex<Vec<NotificationResponse>>> = Lazy::new(|| {
    Mutex::new(vec![
        NotificationResponse {
            id: "notif-1".to_string(),
            title: "Billing webhook failed".to_string(),
            description: "Stripe webhook endpoint returned 500 for tenant Acme Inc.".to_string(),
            created_at: "2024-02-08T10:00:00Z".to_string(),
            r#type: "warning".to_string(),
            read: false,
        },
        NotificationResponse {
            id: "notif-2".to_string(),
            title: "New admin added".to_string(),
            description: "Jamie Liu was granted Platform Admin role.".to_string(),
            created_at: "2024-02-08T08:00:00Z".to_string(),
            r#type: "success".to_string(),
            read: false,
        },
    ])
});

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/notifications", get(list_notifications))
        .route("/notifications/mark-read", post(mark_notifications_read))
}

async fn list_notifications(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<NotificationResponse>>, ApiError> {
    let items = NOTIFICATIONS.lock().map_err(|_| ApiError::Internal)?;
    Ok(Json(items.clone()))
}

async fn mark_notifications_read(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Json(payload): Json<MarkReadRequest>,
) -> Result<Json<Vec<NotificationResponse>>, ApiError> {
    let mut items = NOTIFICATIONS.lock().map_err(|_| ApiError::Internal)?;
    for item in items.iter_mut() {
        if payload.ids.contains(&item.id) {
            item.read = true;
        }
    }
    Ok(Json(items.clone()))
}
