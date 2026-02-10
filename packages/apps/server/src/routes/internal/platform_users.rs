//! Internal Platform User Routes
//!
//! Platform-level user search and management (superadmin only).

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;

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

#[derive(Debug, Serialize)]
struct PaginatedUsersResponse {
    data: Vec<PlatformUserResponse>,
    pagination: serde_json::Value,
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

/// Search users across platform
async fn search_platform_users(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Query(query): Query<SearchUsersQuery>,
) -> Result<Json<PaginatedUsersResponse>, ApiError> {
    const MAX_PER_PAGE: i64 = 100;
    let per_page = query.per_page.unwrap_or(20).min(MAX_PER_PAGE);
    let page = query.page.unwrap_or(1).max(1);
    let offset = (page - 1) * per_page;
    
    // Validate tenant_id format if provided
    if let Some(ref tenant_id) = query.tenant_id {
        if uuid::Uuid::parse_str(tenant_id).is_err() {
            return Err(ApiError::BadRequest("Invalid tenant ID format".to_string()));
        }
    }
    
    // Validate email format if provided
    if let Some(ref email) = query.email {
        if email.len() > 255 || !email.contains('@') {
            return Err(ApiError::BadRequest("Invalid email format".to_string()));
        }
    }
    
    // SECURITY: Use sqlx::QueryBuilder for safe dynamic query construction
    // This avoids SQL injection by using proper parameter binding
    let mut count_builder = sqlx::QueryBuilder::new(
        "SELECT COUNT(*) FROM users u WHERE u.deleted_at IS NULL"
    );
    
    if query.email.is_some() {
        count_builder.push(" AND LOWER(u.email) = LOWER(");
        count_builder.push_bind(query.email.as_ref().unwrap());
        count_builder.push(")");
    }
    
    if query.tenant_id.is_some() {
        count_builder.push(" AND EXISTS (SELECT 1 FROM tenant_users tu WHERE tu.user_id = u.id AND tu.tenant_id = ");
        count_builder.push_bind(query.tenant_id.as_ref().unwrap());
        count_builder.push(")");
    }
    
    let total: i64 = count_builder.build_query_scalar()
        .fetch_one(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to count users: {}", e);
            ApiError::internal()
        })?;
    
    // Build data query with QueryBuilder
    let mut query_builder = sqlx::QueryBuilder::new(
        r#"
        SELECT 
            u.id,
            u.email,
            u.profile->>'name' as name,
            u.status::text as status,
            u.created_at,
            (SELECT COUNT(*) FROM tenant_users tu WHERE tu.user_id = u.id) as tenant_count
        FROM users u
        WHERE u.deleted_at IS NULL
        "#
    );
    
    if query.email.is_some() {
        query_builder.push(" AND LOWER(u.email) = LOWER(");
        query_builder.push_bind(query.email.as_ref().unwrap());
        query_builder.push(")");
    }
    
    if query.tenant_id.is_some() {
        query_builder.push(" AND EXISTS (SELECT 1 FROM tenant_users tu WHERE tu.user_id = u.id AND tu.tenant_id = ");
        query_builder.push_bind(query.tenant_id.as_ref().unwrap());
        query_builder.push(")");
    }
    
    query_builder.push(" ORDER BY u.created_at DESC");
    query_builder.push(" LIMIT ");
    query_builder.push_bind(per_page);
    query_builder.push(" OFFSET ");
    query_builder.push_bind(offset);
    
    let rows = query_builder.build()
        .fetch_all(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to search users: {}", e);
            ApiError::internal()
        })?;
    
    let users: Vec<PlatformUserResponse> = rows
        .into_iter()
        .map(|row| PlatformUserResponse {
            id: row.get("id"),
            email: row.get("email"),
            name: row.get("name"),
            status: row.get("status"),
            created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            tenant_count: row.get("tenant_count"),
        })
        .collect();
    
    Ok(Json(PaginatedUsersResponse {
        data: users,
        pagination: serde_json::json!({
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": (total as f64 / per_page as f64).ceil() as i64
        }),
    }))
}

/// Get platform user details
async fn get_platform_user(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<PlatformUserDetailResponse>, ApiError> {
    // Validate UUID format
    if uuid::Uuid::parse_str(&user_id).is_err() {
        return Err(ApiError::BadRequest("Invalid user ID format".to_string()));
    }
    
    // Fetch user details
    let user_row = sqlx::query(
        r#"
        SELECT 
            u.id,
            u.email,
            u.profile->>'name' as name,
            u.email_verified,
            u.status::text as status,
            u.created_at,
            u.updated_at,
            u.last_login_at,
            u.mfa_enabled,
            u.failed_login_attempts
        FROM users u
        WHERE u.id = $1 AND u.deleted_at IS NULL
        "#
    )
    .bind(&user_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to get user: {}", e);
        ApiError::internal()
    })?;
    
    let user = match user_row {
        Some(row) => row,
        None => return Err(ApiError::NotFound),
    };
    
    // Fetch tenant memberships
    let memberships = sqlx::query(
        r#"
        SELECT 
            t.id as tenant_id,
            t.name as tenant_name,
            t.slug as tenant_slug,
            tu.role::text as role,
            tu.created_at as joined_at
        FROM tenant_users tu
        JOIN tenants t ON tu.tenant_id = t.id
        WHERE tu.user_id = $1
        ORDER BY tu.created_at DESC
        "#
    )
    .bind(&user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to get user memberships: {}", e);
        ApiError::internal()
    })?;
    
    let tenants: Vec<UserTenantMembership> = memberships
        .into_iter()
        .map(|row| UserTenantMembership {
            tenant_id: row.get("tenant_id"),
            tenant_name: row.get("tenant_name"),
            tenant_slug: row.get("tenant_slug"),
            role: row.get("role"),
            joined_at: row.get::<chrono::DateTime<chrono::Utc>, _>("joined_at").to_rfc3339(),
        })
        .collect();
    
    Ok(Json(PlatformUserDetailResponse {
        id: user.get("id"),
        email: user.get("email"),
        name: user.get("name"),
        email_verified: user.get("email_verified"),
        status: user.get("status"),
        created_at: user.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        updated_at: user.get::<chrono::DateTime<chrono::Utc>, _>("updated_at").to_rfc3339(),
        last_login_at: user.get::<Option<chrono::DateTime<chrono::Utc>>, _>("last_login_at")
            .map(|dt| dt.to_rfc3339()),
        tenants,
        mfa_enabled: user.get("mfa_enabled"),
        failed_login_attempts: user.get("failed_login_attempts"),
    }))
}
