//! Internal roles & permissions routes

use axum::{
    extract::{Path, State},
    routing::{get, patch, post},
    Extension, Json, Router,
};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

#[derive(Debug, Serialize, Clone)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub scope: String,
    pub permissions: Vec<String>,
    pub members: i64,
    pub status: String,
}

#[derive(Debug, Deserialize)]
struct CreateRoleRequest {
    name: String,
    description: Option<String>,
    scope: Option<String>,
    permissions: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UpdateRoleRequest {
    name: Option<String>,
    description: Option<String>,
    permissions: Option<Vec<String>>,
    status: Option<String>,
}

static ROLES: Lazy<Mutex<Vec<RoleResponse>>> = Lazy::new(|| {
    Mutex::new(vec![
        RoleResponse {
            id: "role-1".to_string(),
            name: "Platform Admin".to_string(),
            description: "Full access to platform settings and data".to_string(),
            scope: "platform".to_string(),
            permissions: vec![
                "users.read".to_string(),
                "users.write".to_string(),
                "billing.write".to_string(),
            ],
            members: 4,
            status: "active".to_string(),
        },
        RoleResponse {
            id: "role-2".to_string(),
            name: "Support Agent".to_string(),
            description: "Read-only access to users and audit logs".to_string(),
            scope: "platform".to_string(),
            permissions: vec!["users.read".to_string(), "audit.read".to_string()],
            members: 8,
            status: "active".to_string(),
        },
    ])
});

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/roles", get(list_roles).post(create_role))
        .route("/roles/:role_id", patch(update_role))
}

async fn list_roles(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<RoleResponse>>, ApiError> {
    let roles = ROLES.lock().map_err(|_| ApiError::Internal)?;
    Ok(Json(roles.clone()))
}

async fn create_role(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Json(payload): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>, ApiError> {
    let mut roles = ROLES.lock().map_err(|_| ApiError::Internal)?;
    let role = RoleResponse {
        id: format!("role-{}", roles.len() + 1),
        name: payload.name,
        description: payload.description.unwrap_or_default(),
        scope: payload.scope.unwrap_or_else(|| "platform".to_string()),
        permissions: payload.permissions.unwrap_or_default(),
        members: 0,
        status: "active".to_string(),
    };
    roles.insert(0, role.clone());
    Ok(Json(role))
}

async fn update_role(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(role_id): Path<String>,
    Json(payload): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, ApiError> {
    let mut roles = ROLES.lock().map_err(|_| ApiError::Internal)?;
    let role = roles.iter_mut().find(|r| r.id == role_id);
    match role {
        Some(role) => {
            if let Some(name) = payload.name {
                role.name = name;
            }
            if let Some(description) = payload.description {
                role.description = description;
            }
            if let Some(permissions) = payload.permissions {
                role.permissions = permissions;
            }
            if let Some(status) = payload.status {
                role.status = status;
            }
            Ok(Json(role.clone()))
        }
        None => Err(ApiError::NotFound),
    }
}
