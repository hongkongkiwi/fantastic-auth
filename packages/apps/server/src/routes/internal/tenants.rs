//! Internal Tenant Management Routes
//!
//! Platform-level tenant management (superadmin only).

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::audit::AuditLogger;
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Tenant management routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_tenants).post(create_tenant))
        .route(
            "/:tenant_id",
            get(get_tenant).patch(update_tenant).delete(delete_tenant),
        )
        .route("/:tenant_id/suspend", post(suspend_tenant))
        .route("/:tenant_id/activate", post(activate_tenant))
}

#[derive(Debug, Deserialize)]
struct ListTenantsQuery {
    page: Option<i64>,
    #[serde(rename = "per_page")]
    per_page: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CreateTenantRequest {
    name: String,
    slug: String,
}

#[derive(Debug, Deserialize)]
struct UpdateTenantRequest {
    name: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Serialize)]
struct TenantResponse {
    id: String,
    name: String,
    slug: String,
    status: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Debug, Serialize)]
struct PaginatedTenantsResponse {
    data: Vec<TenantResponse>,
    pagination: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

/// List all tenants
async fn list_tenants(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Query(query): Query<ListTenantsQuery>,
) -> Result<Json<PaginatedTenantsResponse>, ApiError> {
    const MAX_PER_PAGE: i64 = 100;
    let per_page = query.per_page.unwrap_or(20).min(MAX_PER_PAGE);
    let page = query.page.unwrap_or(1).max(1);
    let offset = (page - 1) * per_page;
    
    // Get total count
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
        .fetch_one(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to count tenants: {}", e);
            ApiError::internal()
        })?;
    
    // Fetch tenants
    let rows = sqlx::query(
        r#"
        SELECT id, name, slug, status, created_at
        FROM tenants
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#
    )
    .bind(per_page)
    .bind(offset)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to list tenants: {}", e);
        ApiError::internal()
    })?;
    
    let tenants: Vec<TenantResponse> = rows
        .into_iter()
        .map(|row| TenantResponse {
            id: row.get("id"),
            name: row.get("name"),
            slug: row.get("slug"),
            status: row.get("status"),
            created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        })
        .collect();
    
    Ok(Json(PaginatedTenantsResponse {
        data: tenants,
        pagination: serde_json::json!({
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": (total as f64 / per_page as f64).ceil() as i64
        }),
    }))
}

/// Create tenant
async fn create_tenant(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateTenantRequest>,
) -> Result<Json<TenantResponse>, ApiError> {
    // Validate slug format
    if !req.slug.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(ApiError::BadRequest(
            "Slug must contain only alphanumeric characters, hyphens, and underscores".to_string()
        ));
    }
    
    let id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    
    sqlx::query(
        r#"
        INSERT INTO tenants (id, name, slug, status, created_at, updated_at)
        VALUES ($1, $2, $3, 'active', $4, $4)
        "#
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.slug)
    .bind(&now)
    .execute(state.db.pool())
    .await
    .map_err(|e| {
        if e.to_string().contains("unique constraint") {
            ApiError::Conflict("Tenant with this slug already exists".to_string())
        } else {
            tracing::error!("Failed to create tenant: {}", e);
            ApiError::internal()
        }
    })?;
    
    // AUDIT: Log tenant creation
    let audit = AuditLogger::new(state.db.clone());
    audit.log_tenant_created(&id.to_string(), &current_user.user_id, &req.name, &req.slug);
    
    Ok(Json(TenantResponse {
        id: id.to_string(),
        name: req.name,
        slug: req.slug,
        status: "active".to_string(),
        created_at: now.to_rfc3339(),
    }))
}

/// Get tenant
async fn get_tenant(
    State(state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
) -> Result<Json<TenantResponse>, ApiError> {
    let row = sqlx::query(
        r#"
        SELECT id, name, slug, status, created_at
        FROM tenants
        WHERE id = $1
        "#
    )
    .bind(&tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to get tenant: {}", e);
        ApiError::internal()
    })?;
    
    match row {
        Some(row) => Ok(Json(TenantResponse {
            id: row.get("id"),
            name: row.get("name"),
            slug: row.get("slug"),
            status: row.get("status"),
            created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
        })),
        None => Err(ApiError::NotFound),
    }
}

/// Update tenant
async fn update_tenant(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
    Json(req): Json<UpdateTenantRequest>,
) -> Result<Json<TenantResponse>, ApiError> {
    // Validate UUID format
    let tenant_uuid = uuid::Uuid::parse_str(&tenant_id)
        .map_err(|_| ApiError::BadRequest("Invalid tenant ID format".to_string()))?;
    
    // Validate status if provided
    if let Some(ref status) = req.status {
        if !["active", "suspended"].contains(&status.as_str()) {
            return Err(ApiError::BadRequest("Invalid status. Must be 'active' or 'suspended'".to_string()));
        }
    }
    
    // SECURITY: Use parameterized query with COALESCE to avoid SQL injection
    // This approach safely handles optional updates without string concatenation
    let now = chrono::Utc::now();
    
    let row = sqlx::query(
        r#"
        UPDATE tenants 
        SET 
            name = COALESCE($1, name),
            status = COALESCE($2, status),
            updated_at = $3
        WHERE id = $4
        RETURNING id, name, slug, status, created_at
        "#
    )
    .bind(req.name.as_ref())
    .bind(req.status.as_ref())
    .bind(&now)
    .bind(&tenant_uuid)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to update tenant: {}", e);
        ApiError::internal()
    })?;
    
    match row {
        Some(row) => {
            // AUDIT: Log tenant update
            let audit = AuditLogger::new(state.db.clone());
            let changes = serde_json::json!({
                "name": req.name,
                "status": req.status,
            });
            audit.log_tenant_updated(&tenant_id, &current_user.user_id, changes);
            
            Ok(Json(TenantResponse {
                id: row.get("id"),
                name: row.get("name"),
                slug: row.get("slug"),
                status: row.get("status"),
                created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            }))
        }
        None => Err(ApiError::NotFound),
    }
}

/// Delete tenant
async fn delete_tenant(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    let result = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(&tenant_id)
        .execute(state.db.pool())
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete tenant: {}", e);
            ApiError::internal()
        })?;
    
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    
    // AUDIT: Log tenant deletion
    let audit = AuditLogger::new(state.db.clone());
    audit.log_tenant_deleted(&tenant_id, &current_user.user_id);
    
    Ok(Json(MessageResponse {
        message: format!("Tenant {} deleted", tenant_id),
    }))
}

/// Suspend tenant
async fn suspend_tenant(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
) -> Result<Json<TenantResponse>, ApiError> {
    let row = sqlx::query(
        r#"
        UPDATE tenants 
        SET status = 'suspended', updated_at = $1
        WHERE id = $2
        RETURNING id, name, slug, status, created_at
        "#
    )
    .bind(chrono::Utc::now())
    .bind(&tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to suspend tenant: {}", e);
        ApiError::internal()
    })?;
    
    match row {
        Some(row) => {
            // AUDIT: Log tenant suspension
            let audit = AuditLogger::new(state.db.clone());
            audit.log_tenant_suspended(&tenant_id, &current_user.user_id);
            
            Ok(Json(TenantResponse {
                id: row.get("id"),
                name: row.get("name"),
                slug: row.get("slug"),
                status: row.get("status"),
                created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            }))
        }
        None => Err(ApiError::NotFound),
    }
}

/// Activate tenant
async fn activate_tenant(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(tenant_id): Path<String>,
) -> Result<Json<TenantResponse>, ApiError> {
    let row = sqlx::query(
        r#"
        UPDATE tenants 
        SET status = 'active', updated_at = $1
        WHERE id = $2
        RETURNING id, name, slug, status, created_at
        "#
    )
    .bind(chrono::Utc::now())
    .bind(&tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|e| {
        tracing::error!("Failed to activate tenant: {}", e);
        ApiError::internal()
    })?;
    
    match row {
        Some(row) => {
            // AUDIT: Log tenant activation
            let audit = AuditLogger::new(state.db.clone());
            audit.log_tenant_activated(&tenant_id, &current_user.user_id);
            
            Ok(Json(TenantResponse {
                id: row.get("id"),
                name: row.get("name"),
                slug: row.get("slug"),
                status: row.get("status"),
                created_at: row.get::<chrono::DateTime<chrono::Utc>, _>("created_at").to_rfc3339(),
            }))
        }
        None => Err(ApiError::NotFound),
    }
}
