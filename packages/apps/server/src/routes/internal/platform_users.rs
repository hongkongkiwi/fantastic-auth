//! Internal Platform User Routes
//!
//! Platform-level user search and management (superadmin only).

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use once_cell::sync::Lazy;
use std::sync::Mutex;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Platform user routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(search_platform_users))
        .route("/:user_id", get(get_platform_user))
}

#[derive(Debug, Deserialize)]
struct SearchUsersQuery {
    email: Option<String>,
    #[serde(rename = "tenantId")]
    tenant_id: Option<String>,
    page: Option<i64>,
    #[serde(rename = "per_page")]
    per_page: Option<i64>,
}

#[derive(Debug, Serialize, Clone)]
struct PlatformUserResponse {
    id: String,
    email: String,
    name: Option<String>,
    status: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "tenantCount")]
    tenant_count: i64,
}

#[derive(Debug, Serialize)]
struct PlatformUserDetailResponse {
    id: String,
    email: String,
    name: Option<String>,
    #[serde(rename = "emailVerified")]
    email_verified: bool,
    status: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    #[serde(rename = "lastLoginAt")]
    last_login_at: Option<String>,
    tenants: Vec<UserTenantMembership>,
    #[serde(rename = "mfaEnabled")]
    mfa_enabled: bool,
    #[serde(rename = "failedLoginAttempts")]
    failed_login_attempts: i64,
}

#[derive(Debug, Serialize, Clone)]
struct UserTenantMembership {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    #[serde(rename = "tenantName")]
    tenant_name: String,
    #[serde(rename = "tenantSlug")]
    tenant_slug: String,
    role: String,
    #[serde(rename = "joinedAt")]
    joined_at: String,
}

#[derive(Debug, Serialize)]
struct PaginatedUsersResponse {
    data: Vec<PlatformUserResponse>,
    pagination: serde_json::Value,
}

#[derive(Debug, Clone)]
struct UserRecord {
    id: String,
    email: String,
    name: Option<String>,
    status: String,
    created_at: String,
    memberships: Vec<UserTenantMembership>,
}

static USERS: Lazy<Mutex<Vec<UserRecord>>> = Lazy::new(|| {
    Mutex::new(vec![
        UserRecord {
            id: "user-1".to_string(),
            email: "alex@acme.com".to_string(),
            name: Some("Alex Grant".to_string()),
            status: "active".to_string(),
            created_at: "2024-01-10T09:00:00Z".to_string(),
            memberships: vec![UserTenantMembership {
                tenant_id: "tenant-1".to_string(),
                tenant_name: "Acme Inc".to_string(),
                tenant_slug: "acme".to_string(),
                role: "admin".to_string(),
                joined_at: "2024-01-12T09:00:00Z".to_string(),
            }],
        },
        UserRecord {
            id: "user-2".to_string(),
            email: "jamie@northwind.com".to_string(),
            name: Some("Jamie Liu".to_string()),
            status: "active".to_string(),
            created_at: "2024-02-02T09:00:00Z".to_string(),
            memberships: vec![
                UserTenantMembership {
                    tenant_id: "tenant-2".to_string(),
                    tenant_name: "Northwind".to_string(),
                    tenant_slug: "northwind".to_string(),
                    role: "member".to_string(),
                    joined_at: "2024-02-05T09:00:00Z".to_string(),
                },
                UserTenantMembership {
                    tenant_id: "tenant-3".to_string(),
                    tenant_name: "Umbrella".to_string(),
                    tenant_slug: "umbrella".to_string(),
                    role: "viewer".to_string(),
                    joined_at: "2024-03-01T09:00:00Z".to_string(),
                },
            ],
        },
    ])
});

/// Search users across platform
async fn search_platform_users(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Query(query): Query<SearchUsersQuery>,
) -> Result<Json<PaginatedUsersResponse>, ApiError> {
    let users = USERS.lock().map_err(|_| ApiError::internal())?;
    let email_filter = query.email.unwrap_or_default().to_lowercase();
    let tenant_filter = query.tenant_id;

    let mut filtered: Vec<PlatformUserResponse> = users
        .iter()
        .filter(|user| {
            let email_match = if email_filter.is_empty() {
                true
            } else {
                user.email.to_lowercase().contains(&email_filter)
            };
            let tenant_match = if let Some(ref tenant_id) = tenant_filter {
                user.memberships.iter().any(|m| m.tenant_id == *tenant_id)
            } else {
                true
            };
            email_match && tenant_match
        })
        .map(|user| PlatformUserResponse {
            id: user.id.clone(),
            email: user.email.clone(),
            name: user.name.clone(),
            status: user.status.clone(),
            created_at: user.created_at.clone(),
            tenant_count: user.memberships.len() as i64,
        })
        .collect();

    const MAX_PER_PAGE: i64 = 100;
    let per_page = query.per_page.unwrap_or(20).min(MAX_PER_PAGE);
    let page = query.page.unwrap_or(1);
    let total = filtered.len() as i64;
    let start = ((page - 1) * per_page) as usize;
    let end = (start + per_page as usize).min(filtered.len());
    if start < filtered.len() {
        filtered = filtered[start..end].to_vec();
    } else {
        filtered.clear();
    }

    Ok(Json(PaginatedUsersResponse {
        data: filtered,
        pagination: serde_json::json!({
            "page": page,
            "perPage": per_page,
            "total": total,
            "totalPages": (total as f64 / per_page as f64).ceil() as i64
        }),
    }))
}

/// Get platform user details
async fn get_platform_user(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<PlatformUserDetailResponse>, ApiError> {
    let users = USERS.lock().map_err(|_| ApiError::internal())?;
    let user = users.iter().find(|u| u.id == user_id);
    match user {
        Some(user) => Ok(Json(get_platform_user_detail(user))),
        None => Err(ApiError::NotFound),
    }
}

fn get_platform_user_detail(user: &UserRecord) -> PlatformUserDetailResponse {
    PlatformUserDetailResponse {
        id: user.id.clone(),
        email: user.email.clone(),
        name: user.name.clone(),
        email_verified: true,
        status: user.status.clone(),
        created_at: user.created_at.clone(),
        updated_at: user.created_at.clone(),
        last_login_at: Some("2024-02-08T09:00:00Z".to_string()),
        tenants: user.memberships.clone(),
        mfa_enabled: true,
        failed_login_attempts: 0,
    }
}
