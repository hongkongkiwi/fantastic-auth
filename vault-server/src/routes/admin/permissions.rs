//! Admin Permissions Management Routes
//!
//! Provides CRUD operations for:
//! - Permissions (the atomic actions that can be performed)
//! - Roles (collections of permissions)
//! - User role assignments
//! - Resource-specific permission grants
//!
//! All endpoints require admin or superadmin privileges.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tracing::{info, warn};
use uuid::Uuid;

use crate::permissions::{
    checker::PermissionChecker,
    default_permissions, default_role_permissions,
    system_roles, Permission, PermissionResponse, ResourcePermission,
    Role, RoleResponse, system_roles::{SUPERADMIN, ADMIN, MEMBER, VIEWER},
    UserRole, UserRoleResponse,
};
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Query parameters for list endpoints
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(rename = "page")]
    page: Option<i64>,
    #[serde(rename = "limit")]
    limit: Option<i64>,
    #[serde(rename = "search")]
    search: Option<String>,
}

impl ListQuery {
    fn page(&self) -> i64 {
        self.page.unwrap_or(1).max(1)
    }
    
    fn limit(&self) -> i64 {
        self.limit.unwrap_or(50).clamp(1, 100)
    }
    
    fn offset(&self) -> i64 {
        (self.page() - 1) * self.limit()
    }
}

/// Create permission request
#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    name: String,
    description: Option<String>,
    resource_type: String,
    action: String,
}

/// Create role request
#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    name: String,
    description: Option<String>,
    permission_ids: Vec<Uuid>,
}

/// Update role request
#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    name: Option<String>,
    description: Option<String>,
    permission_ids: Option<Vec<Uuid>>,
}

/// Assign role to user request
#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    user_id: Uuid,
    role_id: Uuid,
    organization_id: Option<Uuid>,
}

/// Grant resource permission request
#[derive(Debug, Deserialize)]
pub struct GrantResourcePermissionRequest {
    user_id: Uuid,
    permission_id: Uuid,
    resource_type: String,
    resource_id: String,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Permission check request
#[derive(Debug, Deserialize)]
pub struct CheckPermissionRequest {
    user_id: Uuid,
    permission: String,
    resource_type: Option<String>,
    resource_id: Option<String>,
}

/// Permission check response
#[derive(Debug, Serialize)]
pub struct CheckPermissionResponse {
    has_permission: bool,
    user_id: String,
    permission: String,
}

/// List response wrapper
#[derive(Debug, Serialize)]
pub struct ListResponse<T> {
    data: Vec<T>,
    pagination: PaginationInfo,
}

/// Pagination info
#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    page: i64,
    limit: i64,
    total: i64,
    total_pages: i64,
}

/// Build routes for permission management
pub fn routes() -> Router<AppState> {
    Router::new()
        // Permission CRUD
        .route("/permissions", get(list_permissions).post(create_permission))
        .route("/permissions/:id", get(get_permission).delete(delete_permission))
        // Role CRUD
        .route("/roles", get(list_roles).post(create_role))
        .route("/roles/:id", get(get_role).put(update_role).delete(delete_role))
        // Role permissions
        .route("/roles/:id/permissions", get(get_role_permissions))
        .route("/roles/:id/permissions/:permission_id", put(add_permission_to_role).delete(remove_permission_from_role))
        // User roles
        .route("/user-roles", post(assign_role).get(list_user_roles))
        .route("/user-roles/:user_id/:role_id", delete(remove_role_from_user))
        .route("/users/:user_id/roles", get(get_user_roles))
        .route("/users/:user_id/permissions", get(get_user_permissions))
        // Resource permissions
        .route("/resource-permissions", post(grant_resource_permission).get(list_resource_permissions))
        .route("/resource-permissions/:id", delete(revoke_resource_permission))
        // Permission checking
        .route("/check-permission", post(check_permission))
        // System initialization
        .route("/permissions/initialize", post(initialize_default_permissions))
}

// ==================== PERMISSIONS ====================

async fn list_permissions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse<PermissionResponse>>, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let tenant_id = Uuid::parse_str(&current_user.tenant_id).ok();
    
    // Get total count
    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM permissions 
        WHERE tenant_id IS NULL OR tenant_id = $1
        "#
    )
    .bind(tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    // Fetch permissions
    let permissions: Vec<Permission> = sqlx::query_as(
        r#"
        SELECT * FROM permissions 
        WHERE tenant_id IS NULL OR tenant_id = $1
        ORDER BY resource_type, action
        LIMIT $2 OFFSET $3
        "#
    )
    .bind(tenant_id)
    .bind(query.limit())
    .bind(query.offset())
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    let total_pages = (total as f64 / query.limit() as f64).ceil() as i64;
    
    Ok(Json(ListResponse {
        data: permissions.into_iter().map(PermissionResponse::from).collect(),
        pagination: PaginationInfo {
            page: query.page(),
            limit: query.limit(),
            total,
            total_pages,
        },
    }))
}

async fn get_permission(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<PermissionResponse>, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let tenant_id = Uuid::parse_str(&current_user.tenant_id).ok();
    
    let permission: Permission = sqlx::query_as(
        r#"
        SELECT * FROM permissions 
        WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2)
        "#
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?
    .ok_or(ApiError::NotFound)?;
    
    Ok(Json(permission.into()))
}

async fn create_permission(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreatePermissionRequest>,
) -> Result<(StatusCode, Json<PermissionResponse>), ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let tenant_id = Uuid::parse_str(&current_user.tenant_id).ok();
    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    
    let permission: Permission = sqlx::query_as(
        r#"
        INSERT INTO permissions (id, tenant_id, name, description, resource_type, action, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#
    )
    .bind(id)
    .bind(tenant_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.resource_type)
    .bind(&req.action)
    .bind(now)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| {
        warn!("Failed to create permission: {}", e);
        ApiError::Internal
    })?;
    
    info!(
        user_id = %current_user.user_id,
        permission_id = %id,
        "Created permission"
    );
    
    Ok((StatusCode::CREATED, Json(permission.into())))
}

async fn delete_permission(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let tenant_id = Uuid::parse_str(&current_user.tenant_id).ok();
    
    // Don't allow deleting system permissions (those without a tenant_id)
    let result = sqlx::query(
        r#"
        DELETE FROM permissions 
        WHERE id = $1 AND tenant_id = $2
        "#
    )
    .bind(id)
    .bind(tenant_id)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    
    info!(
        user_id = %current_user.user_id,
        permission_id = %id,
        "Deleted permission"
    );
    
    Ok(StatusCode::NO_CONTENT)
}

// ==================== ROLES ====================

async fn list_roles(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse<RoleResponse>>, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let tenant_id = Uuid::parse_str(&current_user.tenant_id).ok();
    
    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM roles 
        WHERE tenant_id IS NULL OR tenant_id = $1
        "#
    )
    .bind(tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    let roles: Vec<Role> = sqlx::query_as(
        r#"
        SELECT * FROM roles 
        WHERE tenant_id IS NULL OR tenant_id = $1
        ORDER BY is_system_role DESC, name
        LIMIT $2 OFFSET $3
        "#
    )
    .bind(tenant_id)
    .bind(query.limit())
    .bind(query.offset())
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    // Fetch permissions for each role
    let mut responses = Vec::new();
    for role in roles {
        let permissions: Vec<Permission> = sqlx::query_as(
            r#"
            SELECT p.* FROM permissions p
            INNER JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = $1
            "#
        )
        .bind(role.id)
        .fetch_all(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;
        
        responses.push(RoleResponse {
            id: role.id.to_string(),
            name: role.name.clone(),
            description: role.description.clone(),
            is_system_role: role.is_system_role,
            permissions: permissions.into_iter().map(PermissionResponse::from).collect(),
            created_at: role.created_at,
            updated_at: role.updated_at,
        });
    }
    
    let total_pages = (total as f64 / query.limit() as f64).ceil() as i64;
    
    Ok(Json(ListResponse {
        data: responses,
        pagination: PaginationInfo {
            page: query.page(),
            limit: query.limit(),
            total,
            total_pages,
        },
    }))
}

async fn get_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<RoleResponse>, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let tenant_id = Uuid::parse_str(&current_user.tenant_id).ok();
    
    let role: Role = sqlx::query_as(
        r#"
        SELECT * FROM roles 
        WHERE id = $1 AND (tenant_id IS NULL OR tenant_id = $2)
        "#
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?
    .ok_or(ApiError::NotFound)?;
    
    let permissions: Vec<Permission> = sqlx::query_as(
        r#"
        SELECT p.* FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = $1
        "#
    )
    .bind(role.id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    Ok(Json(RoleResponse {
        id: role.id.to_string(),
        name: role.name,
        description: role.description,
        is_system_role: role.is_system_role,
        permissions: permissions.into_iter().map(PermissionResponse::from).collect(),
        created_at: role.created_at,
        updated_at: role.updated_at,
    }))
}

async fn create_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<RoleResponse>), ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let tenant_id = Uuid::parse_str(&current_user.tenant_id).ok();
    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    
    // Check for reserved role names
    let reserved = [SUPERADMIN, ADMIN, MEMBER, VIEWER];
    if reserved.contains(&req.name.as_str()) {
        return Err(ApiError::Conflict(
            format!("'{}' is a reserved system role name", req.name)
        ));
    }
    
    let role: Role = sqlx::query_as(
        r#"
        INSERT INTO roles (id, tenant_id, name, description, is_system_role, created_at, updated_at)
        VALUES ($1, $2, $3, $4, false, $5, $5)
        RETURNING *
        "#
    )
    .bind(id)
    .bind(tenant_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(now)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate") {
            ApiError::Conflict("Role with this name already exists".to_string())
        } else {
            ApiError::Internal
        }
    })?;
    
    // Add permissions if provided
    for perm_id in &req.permission_ids {
        sqlx::query(
            r#"
            INSERT INTO role_permissions (role_id, permission_id)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
            "#
        )
        .bind(id)
        .bind(perm_id)
        .execute(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;
    }
    
    // Fetch permissions for response
    let permissions: Vec<Permission> = sqlx::query_as(
        r#"
        SELECT p.* FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = $1
        "#
    )
    .bind(id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    info!(
        user_id = %current_user.user_id,
        role_id = %id,
        "Created role"
    );
    
    Ok((StatusCode::CREATED, Json(RoleResponse {
        id: role.id.to_string(),
        name: role.name,
        description: role.description,
        is_system_role: role.is_system_role,
        permissions: permissions.into_iter().map(PermissionResponse::from).collect(),
        created_at: role.created_at,
        updated_at: role.updated_at,
    })))
}

async fn update_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let tenant_id = Uuid::parse_str(&current_user.tenant_id).ok();
    let now = chrono::Utc::now();
    
    // Check if role exists and is not a system role
    let existing: Role = sqlx::query_as(
        r#"
        SELECT * FROM roles 
        WHERE id = $1 AND tenant_id = $2 AND is_system_role = false
        "#
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?
    .ok_or(ApiError::NotFound)?;
    
    // Update role
    let role: Role = sqlx::query_as(
        r#"
        UPDATE roles 
        SET 
            name = COALESCE($1, name),
            description = COALESCE($2, description),
            updated_at = $3
        WHERE id = $4
        RETURNING *
        "#
    )
    .bind(req.name)
    .bind(req.description)
    .bind(now)
    .bind(id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    // Update permissions if provided
    if let Some(permission_ids) = req.permission_ids {
        // Remove existing permissions
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
            .bind(id)
            .execute(state.db.pool())
            .await
            .map_err(|_| ApiError::Internal)?;
        
        // Add new permissions
        for perm_id in permission_ids {
            sqlx::query(
                r#"
                INSERT INTO role_permissions (role_id, permission_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                "#
            )
            .bind(id)
            .bind(perm_id)
            .execute(state.db.pool())
            .await
            .map_err(|_| ApiError::Internal)?;
        }
    }
    
    // Fetch permissions for response
    let permissions: Vec<Permission> = sqlx::query_as(
        r#"
        SELECT p.* FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = $1
        "#
    )
    .bind(id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    // Invalidate permission caches for users with this role
    invalidate_role_cache(&state, id).await;
    
    Ok(Json(RoleResponse {
        id: role.id.to_string(),
        name: role.name,
        description: role.description,
        is_system_role: role.is_system_role,
        permissions: permissions.into_iter().map(PermissionResponse::from).collect(),
        created_at: role.created_at,
        updated_at: role.updated_at,
    }))
}

async fn delete_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let tenant_id = Uuid::parse_str(&current_user.tenant_id).ok();
    
    let result = sqlx::query(
        r#"
        DELETE FROM roles 
        WHERE id = $1 AND tenant_id = $2 AND is_system_role = false
        "#
    )
    .bind(id)
    .bind(tenant_id)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    
    // Invalidate caches
    invalidate_role_cache(&state, id).await;
    
    Ok(StatusCode::NO_CONTENT)
}

// ==================== ROLE PERMISSIONS ====================

async fn get_role_permissions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<PermissionResponse>>, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let permissions: Vec<Permission> = sqlx::query_as(
        r#"
        SELECT p.* FROM permissions p
        INNER JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = $1
        "#
    )
    .bind(id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    Ok(Json(permissions.into_iter().map(PermissionResponse::from).collect()))
}

async fn add_permission_to_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((role_id, permission_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    sqlx::query(
        r#"
        INSERT INTO role_permissions (role_id, permission_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        "#
    )
    .bind(role_id)
    .bind(permission_id)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    // Invalidate caches
    invalidate_role_cache(&state, role_id).await;
    
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_permission_from_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((role_id, permission_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    sqlx::query(
        "DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2"
    )
    .bind(role_id)
    .bind(permission_id)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    // Invalidate caches
    invalidate_role_cache(&state, role_id).await;
    
    Ok(StatusCode::NO_CONTENT)
}

// ==================== USER ROLES ====================

async fn list_user_roles(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse<UserRoleResponse>>, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let tenant_id = Uuid::parse_str(&current_user.tenant_id).ok();
    
    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM user_roles ur
        INNER JOIN roles r ON ur.role_id = r.id
        WHERE r.tenant_id IS NULL OR r.tenant_id = $1
        "#
    )
    .bind(tenant_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    let user_roles: Vec<UserRole> = sqlx::query_as(
        r#"
        SELECT ur.* FROM user_roles ur
        INNER JOIN roles r ON ur.role_id = r.id
        WHERE r.tenant_id IS NULL OR r.tenant_id = $1
        ORDER BY ur.assigned_at DESC
        LIMIT $2 OFFSET $3
        "#
    )
    .bind(tenant_id)
    .bind(query.limit())
    .bind(query.offset())
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    let total_pages = (total as f64 / query.limit() as f64).ceil() as i64;
    
    Ok(Json(ListResponse {
        data: user_roles.into_iter().map(UserRoleResponse::from).collect(),
        pagination: PaginationInfo {
            page: query.page(),
            limit: query.limit(),
            total,
            total_pages,
        },
    }))
}

async fn assign_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<AssignRoleRequest>,
) -> Result<(StatusCode, Json<UserRoleResponse>), ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let assigned_by = Uuid::parse_str(&current_user.user_id).ok();
    let now = chrono::Utc::now();
    
    let user_role: UserRole = sqlx::query_as(
        r#"
        INSERT INTO user_roles (user_id, role_id, organization_id, assigned_at, assigned_by)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id, role_id, COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'))
        DO UPDATE SET assigned_at = EXCLUDED.assigned_at, assigned_by = EXCLUDED.assigned_by
        RETURNING *
        "#
    )
    .bind(req.user_id)
    .bind(req.role_id)
    .bind(req.organization_id)
    .bind(now)
    .bind(assigned_by)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    // Invalidate user's permission cache
    let checker = PermissionChecker::new(
        state.db.pool().clone(),
        state.redis.clone(),
    );
    checker.invalidate_cache(&req.user_id.to_string());
    let _ = checker.invalidate_redis_cache(&req.user_id.to_string()).await;
    
    info!(
        user_id = %current_user.user_id,
        target_user_id = %req.user_id,
        role_id = %req.role_id,
        "Assigned role to user"
    );
    
    Ok((StatusCode::CREATED, Json(user_role.into())))
}

async fn remove_role_from_user(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    sqlx::query(
        "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2"
    )
    .bind(user_id)
    .bind(role_id)
    .execute(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    // Invalidate user's permission cache
    let checker = PermissionChecker::new(
        state.db.pool().clone(),
        state.redis.clone(),
    );
    checker.invalidate_cache(&user_id.to_string());
    let _ = checker.invalidate_redis_cache(&user_id.to_string()).await;
    
    Ok(StatusCode::NO_CONTENT)
}

async fn get_user_roles(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<RoleResponse>>, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let checker = PermissionChecker::new(
        state.db.pool().clone(),
        state.redis.clone(),
    );
    
    let roles_with_perms = checker
        .get_user_roles_with_permissions(&user_id.to_string())
        .await
        .map_err(|_| ApiError::Internal)?;
    
    let responses: Vec<RoleResponse> = roles_with_perms
        .into_iter()
        .map(|(role, perms)| RoleResponse {
            id: role.id.to_string(),
            name: role.name,
            description: role.description,
            is_system_role: role.is_system_role,
            permissions: perms.into_iter().map(PermissionResponse::from).collect(),
            created_at: role.created_at,
            updated_at: role.updated_at,
        })
        .collect();
    
    Ok(Json(responses))
}

async fn get_user_permissions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<String>>, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let checker = PermissionChecker::new(
        state.db.pool().clone(),
        state.redis.clone(),
    );
    
    let permissions = checker
        .get_user_permissions(&user_id.to_string())
        .await
        .map_err(|_| ApiError::Internal)?;
    
    Ok(Json(permissions))
}

// ==================== RESOURCE PERMISSIONS ====================

async fn list_resource_permissions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListQuery>,
) -> Result<Json<ListResponse<ResourcePermission>>, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM resource_permissions WHERE expires_at IS NULL OR expires_at > NOW()"
    )
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    let permissions: Vec<ResourcePermission> = sqlx::query_as(
        r#"
        SELECT * FROM resource_permissions 
        WHERE expires_at IS NULL OR expires_at > NOW()
        ORDER BY granted_at DESC
        LIMIT $1 OFFSET $2
        "#
    )
    .bind(query.limit())
    .bind(query.offset())
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    let total_pages = (total as f64 / query.limit() as f64).ceil() as i64;
    
    Ok(Json(ListResponse {
        data: permissions,
        pagination: PaginationInfo {
            page: query.page(),
            limit: query.limit(),
            total,
            total_pages,
        },
    }))
}

async fn grant_resource_permission(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<GrantResourcePermissionRequest>,
) -> Result<(StatusCode, Json<ResourcePermission>), ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let granted_by = Uuid::parse_str(&current_user.user_id).ok();
    let id = Uuid::new_v4();
    let now = chrono::Utc::now();
    
    let permission: ResourcePermission = sqlx::query_as(
        r#"
        INSERT INTO resource_permissions 
            (id, user_id, permission_id, resource_type, resource_id, granted_at, granted_by, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *
        "#
    )
    .bind(id)
    .bind(req.user_id)
    .bind(req.permission_id)
    .bind(&req.resource_type)
    .bind(&req.resource_id)
    .bind(now)
    .bind(granted_by)
    .bind(req.expires_at)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    // Invalidate user's permission cache
    let checker = PermissionChecker::new(
        state.db.pool().clone(),
        state.redis.clone(),
    );
    checker.invalidate_cache(&req.user_id.to_string());
    let _ = checker.invalidate_redis_cache(&req.user_id.to_string()).await;
    
    info!(
        user_id = %current_user.user_id,
        target_user_id = %req.user_id,
        resource_type = %req.resource_type,
        resource_id = %req.resource_id,
        "Granted resource permission"
    );
    
    Ok((StatusCode::CREATED, Json(permission)))
}

async fn revoke_resource_permission(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    // Get the permission first to invalidate cache
    let perm: Option<ResourcePermission> = sqlx::query_as(
        "SELECT * FROM resource_permissions WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::Internal)?;
    
    sqlx::query("DELETE FROM resource_permissions WHERE id = $1")
        .bind(id)
        .execute(state.db.pool())
        .await
        .map_err(|_| ApiError::Internal)?;
    
    // Invalidate cache
    if let Some(p) = perm {
        let checker = PermissionChecker::new(
            state.db.pool().clone(),
            state.redis.clone(),
        );
        checker.invalidate_cache(&p.user_id.to_string());
        let _ = checker.invalidate_redis_cache(&p.user_id.to_string()).await;
    }
    
    Ok(StatusCode::NO_CONTENT)
}

// ==================== PERMISSION CHECKING ====================

async fn check_permission(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CheckPermissionRequest>,
) -> Result<Json<CheckPermissionResponse>, ApiError> {
    state.set_tenant_context(&current_user.tenant_id).await.map_err(|_| ApiError::Internal)?;
    
    let checker = PermissionChecker::new(
        state.db.pool().clone(),
        state.redis.clone(),
    );
    
    let has_permission = if let (Some(resource_type), Some(resource_id)) = 
        (req.resource_type.as_ref(), req.resource_id.as_ref()) {
        checker.has_permission_on_resource(
            &req.user_id.to_string(),
            &req.permission,
            resource_type,
            resource_id,
        ).await
    } else {
        checker.has_permission(&req.user_id.to_string(), &req.permission).await
    };
    
    Ok(Json(CheckPermissionResponse {
        has_permission,
        user_id: req.user_id.to_string(),
        permission: req.permission,
    }))
}

// ==================== SYSTEM INITIALIZATION ====================

async fn initialize_default_permissions(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Only superadmin can initialize
    let is_superadmin = current_user
        .claims
        .roles
        .as_ref()
        .map(|roles| roles.iter().any(|r| r == "superadmin"))
        .unwrap_or(false);
    
    if !is_superadmin {
        return Err(ApiError::Forbidden);
    }
    
    let mut permissions_created = 0;
    let mut roles_created = 0;
    
    // Create default permissions
    for (name, description, resource_type, action) in default_permissions() {
        let result = sqlx::query(
            r#"
            INSERT INTO permissions (id, tenant_id, name, description, resource_type, action, created_at)
            VALUES ($1, NULL, $2, $3, $4, $5, NOW())
            ON CONFLICT (name) WHERE tenant_id IS NULL DO NOTHING
            "#
        )
        .bind(Uuid::new_v4())
        .bind(name)
        .bind(description)
        .bind(resource_type)
        .bind(action)
        .execute(state.db.pool())
        .await;
        
        if let Ok(result) = result {
            if result.rows_affected() > 0 {
                permissions_created += 1;
            }
        }
    }
    
    // Create default system roles
    for role_name in [SUPERADMIN, ADMIN, MEMBER, VIEWER] {
        let role_id = Uuid::new_v4();
        
        let result = sqlx::query(
            r#"
            INSERT INTO roles (id, tenant_id, name, description, is_system_role, created_at, updated_at)
            VALUES ($1, NULL, $2, $3, true, NOW(), NOW())
            ON CONFLICT (name) WHERE tenant_id IS NULL DO NOTHING
            RETURNING id
            "#
        )
        .bind(role_id)
        .bind(role_name)
        .bind(format!("System {} role", role_name))
        .fetch_optional(state.db.pool())
        .await;
        
        if let Ok(Some(row)) = result {
            let actual_role_id: Uuid = row.try_get("id").unwrap_or(role_id);
            roles_created += 1;
            
            // Assign permissions to role
            let perm_patterns = default_role_permissions(role_name);
            for pattern in perm_patterns {
                let like_pattern = pattern.replace('*', "%");
                
                sqlx::query(
                    r#"
                    INSERT INTO role_permissions (role_id, permission_id)
                    SELECT $1, id FROM permissions 
                    WHERE name LIKE $2 AND tenant_id IS NULL
                    ON CONFLICT DO NOTHING
                    "#
                )
                .bind(actual_role_id)
                .bind(like_pattern)
                .execute(state.db.pool())
                .await
                .ok();
            }
        }
    }
    
    Ok(Json(serde_json::json!({
        "permissions_created": permissions_created,
        "roles_created": roles_created,
        "message": "Default permissions and roles initialized"
    })))
}

// ==================== HELPERS ====================

/// Invalidate permission caches for all users with a specific role
async fn invalidate_role_cache(state: &AppState, role_id: Uuid) {
    // Get all users with this role
    let user_ids: Vec<String> = sqlx::query_scalar(
        "SELECT user_id::TEXT FROM user_roles WHERE role_id = $1"
    )
    .bind(role_id)
    .fetch_all(state.db.pool())
    .await
    .unwrap_or_default();
    
    let checker = PermissionChecker::new(
        state.db.pool().clone(),
        state.redis.clone(),
    );
    
    // Invalidate each user's cache
    for user_id in user_ids {
        checker.invalidate_cache(&user_id);
        let _ = checker.invalidate_redis_cache(&user_id).await;
    }
}
