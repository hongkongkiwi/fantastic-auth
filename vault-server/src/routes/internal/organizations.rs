//! Internal organization routes

use axum::{
    extract::{Path, State},
    routing::get,
    Extension, Json, Router,
};
use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

#[derive(Debug, Serialize, Clone)]
pub struct OrganizationResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    #[serde(rename = "memberCount")]
    pub member_count: i64,
    pub role: String,
    #[serde(rename = "ssoEnabled")]
    pub sso_enabled: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct OrganizationMemberResponse {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub status: String,
    #[serde(rename = "joinedAt")]
    pub joined_at: String,
}

static ORGS: Lazy<Mutex<Vec<OrganizationResponse>>> = Lazy::new(|| {
    Mutex::new(vec![
        OrganizationResponse {
            id: "org-1".to_string(),
            name: "Acme Inc".to_string(),
            slug: "acme".to_string(),
            member_count: 38,
            role: "owner".to_string(),
            sso_enabled: true,
            created_at: "2024-02-01T10:00:00Z".to_string(),
        },
        OrganizationResponse {
            id: "org-2".to_string(),
            name: "Northwind".to_string(),
            slug: "northwind".to_string(),
            member_count: 14,
            role: "admin".to_string(),
            sso_enabled: false,
            created_at: "2024-03-18T08:30:00Z".to_string(),
        },
    ])
});

static MEMBERS: Lazy<Mutex<HashMap<String, Vec<OrganizationMemberResponse>>>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert(
        "org-1".to_string(),
        vec![
            OrganizationMemberResponse {
                id: "mem-1".to_string(),
                name: "Alex Grant".to_string(),
                email: "alex@acme.com".to_string(),
                role: "Owner".to_string(),
                status: "active".to_string(),
                joined_at: "2024-02-03T09:00:00Z".to_string(),
            },
            OrganizationMemberResponse {
                id: "mem-2".to_string(),
                name: "Jamie Liu".to_string(),
                email: "jamie@acme.com".to_string(),
                role: "Admin".to_string(),
                status: "active".to_string(),
                joined_at: "2024-02-10T09:00:00Z".to_string(),
            },
        ],
    );
    map.insert(
        "org-2".to_string(),
        vec![OrganizationMemberResponse {
            id: "mem-3".to_string(),
            name: "Taylor Reed".to_string(),
            email: "taylor@northwind.com".to_string(),
            role: "Member".to_string(),
            status: "invited".to_string(),
            joined_at: "2024-04-05T09:00:00Z".to_string(),
        }],
    );
    Mutex::new(map)
});

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/organizations", get(list_organizations))
        .route("/organizations/:org_id", get(get_organization))
        .route("/organizations/:org_id/members", get(list_members))
}

async fn list_organizations(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<OrganizationResponse>>, ApiError> {
    let orgs = ORGS.lock().map_err(|_| ApiError::Internal)?;
    Ok(Json(orgs.clone()))
}

async fn get_organization(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    let orgs = ORGS.lock().map_err(|_| ApiError::Internal)?;
    let org = orgs.iter().find(|o| o.id == org_id).cloned();
    match org {
        Some(org) => Ok(Json(org)),
        None => Err(ApiError::NotFound),
    }
}

async fn list_members(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<OrganizationMemberResponse>>, ApiError> {
    let members = MEMBERS.lock().map_err(|_| ApiError::Internal)?;
    Ok(Json(members.get(&org_id).cloned().unwrap_or_default()))
}
