//! Permission-based authorization middleware
//!
//! Provides middleware functions for enforcing fine-grained permissions:
//! - `require_permission` - Requires a specific permission
//! - `require_any_permission` - Requires at least one of the specified permissions
//! - `require_all_permissions` - Requires all of the specified permissions
//!
//! These middlewares should be applied after `auth_middleware` as they depend
//! on the `CurrentUser` being present in request extensions.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::permissions::checker::PermissionChecker;
use crate::state::{AppState, CurrentUser};

/// Permission check result that can be stored in request extensions
#[derive(Debug, Clone)]
pub struct PermissionContext {
    /// User's effective permissions
    pub permissions: Vec<String>,
    /// Whether user is superadmin
    pub is_superadmin: bool,
}

impl PermissionContext {
    /// Create new permission context
    pub fn new(permissions: Vec<String>, is_superadmin: bool) -> Self {
        Self {
            permissions,
            is_superadmin,
        }
    }
    
    /// Check if user has a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        if self.is_superadmin {
            return true;
        }
        
        // Direct match
        if self.permissions.contains(&permission.to_string()) {
            return true;
        }
        
        // Parse and check wildcards
        let parts: Vec<&str> = permission.split(':').collect();
        if parts.len() >= 2 {
            let resource_type = parts[0];
            let action = parts[parts.len() - 1];
            
            // Check type wildcard (e.g., "document:*")
            let type_wildcard = format!("{}:*", resource_type);
            if self.permissions.contains(&type_wildcard) {
                return true;
            }
            
            // Check for global wildcard action
            for perm in &self.permissions {
                let perm_parts: Vec<&str> = perm.split(':').collect();
                if perm_parts.len() >= 2 
                    && perm_parts[0] == resource_type 
                    && perm_parts[perm_parts.len() - 1] == "*" {
                    return true;
                }
            }
        }
        
        false
    }
    
    /// Check if user has any of the specified permissions
    pub fn has_any_permission(&self, permissions: &[&str]) -> bool {
        if self.is_superadmin {
            return true;
        }
        permissions.iter().any(|p| self.has_permission(p))
    }
    
    /// Check if user has all of the specified permissions
    pub fn has_all_permissions(&self, permissions: &[&str]) -> bool {
        if self.is_superadmin {
            return true;
        }
        permissions.iter().all(|p| self.has_permission(p))
    }
}

/// Middleware that requires a specific permission
/// 
/// # Example
/// ```rust
/// use axum::{routing::get, Router};
/// use axum::middleware;
/// 
/// let app = Router::new()
///     .route("/documents", get(list_documents))
///     .layer(middleware::from_fn_with_state(
///         state.clone(),
///         require_permission("document:read")
///     ));
/// ```
pub fn require_permission(permission: &'static str) -> 
    impl Fn(State<AppState>, Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> + Clone + Send + Sync
{
    move |State(state): State<AppState>, request: Request, next: Next| {
        let required = permission;
        Box::pin(async move {
            // Get current user from extensions
            let user = request
                .extensions()
                .get::<CurrentUser>()
                .ok_or(StatusCode::UNAUTHORIZED)?;
            
            // Check permission
            let checker = PermissionChecker::new(
                state.db.pool().clone(),
                state.redis.clone(),
            );
            
            if !checker.has_permission(&user.user_id, required).await {
                tracing::warn!(
                    user_id = %user.user_id,
                    permission = %required,
                    "Permission denied"
                );
                return Err(StatusCode::FORBIDDEN);
            }
            
            Ok(next.run(request).await)
        })
    }
}

/// Middleware that requires any of the specified permissions
/// 
/// # Example
/// ```rust
/// use axum::{routing::post, Router};
/// use axum::middleware;
/// 
/// let app = Router::new()
///     .route("/documents", post(create_document))
///     .layer(middleware::from_fn_with_state(
///         state.clone(),
///         require_any_permission(&["document:create", "document:admin"])
///     ));
/// ```
pub fn require_any_permission(permissions: &'static [&'static str]) ->
    impl Fn(State<AppState>, Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> + Clone + Send + Sync
{
    move |State(state): State<AppState>, request: Request, next: Next| {
        let required = permissions;
        Box::pin(async move {
            let user = request
                .extensions()
                .get::<CurrentUser>()
                .ok_or(StatusCode::UNAUTHORIZED)?;
            
            let checker = PermissionChecker::new(
                state.db.pool().clone(),
                state.redis.clone(),
            );
            
            if !checker.has_any_permission(&user.user_id, required).await {
                tracing::warn!(
                    user_id = %user.user_id,
                    permissions = ?required,
                    "Permission denied - requires any"
                );
                return Err(StatusCode::FORBIDDEN);
            }
            
            Ok(next.run(request).await)
        })
    }
}

/// Middleware that requires all of the specified permissions
/// 
/// # Example
/// ```rust
/// use axum::{routing::put, Router};
/// use axum::middleware;
/// 
/// let app = Router::new()
///     .route("/admin/settings", put(update_settings))
///     .layer(middleware::from_fn_with_state(
///         state.clone(),
///         require_all_permissions(&["settings:write", "settings:manage"])
///     ));
/// ```
pub fn require_all_permissions(permissions: &'static [&'static str]) ->
    impl Fn(State<AppState>, Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> + Clone + Send + Sync
{
    move |State(state): State<AppState>, request: Request, next: Next| {
        let required = permissions;
        Box::pin(async move {
            let user = request
                .extensions()
                .get::<CurrentUser>()
                .ok_or(StatusCode::UNAUTHORIZED)?;
            
            let checker = PermissionChecker::new(
                state.db.pool().clone(),
                state.redis.clone(),
            );
            
            if !checker.has_all_permissions(&user.user_id, required).await {
                tracing::warn!(
                    user_id = %user.user_id,
                    permissions = ?required,
                    "Permission denied - requires all"
                );
                return Err(StatusCode::FORBIDDEN);
            }
            
            Ok(next.run(request).await)
        })
    }
}

/// Middleware that requires permission on a specific resource
/// 
/// This extracts the resource ID from the URL path and checks
/// for resource-specific permissions.
/// 
/// # Example
/// ```rust
/// use axum::{routing::delete, Router};
/// use axum::middleware;
/// 
/// let app = Router::new()
///     .route("/documents/:id", delete(delete_document))
///     .layer(middleware::from_fn_with_state(
///         state.clone(),
///         require_permission_on_resource("document", "delete")
///     ));
/// ```
pub fn require_permission_on_resource(
    resource_type: &'static str,
    action: &'static str,
) -> impl Fn(State<AppState>, Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> + Clone + Send + Sync
{
    move |State(state): State<AppState>, mut request: Request, next: Next| {
        let res_type = resource_type;
        let act = action;
        Box::pin(async move {
            let user = request
                .extensions()
                .get::<CurrentUser>()
                .ok_or(StatusCode::UNAUTHORIZED)?
                .clone();
            
            // Extract resource ID from path parameters
            let resource_id = extract_resource_id(&request, res_type)
                .ok_or_else(|| {
                    tracing::warn!("Could not extract resource ID from path");
                    StatusCode::BAD_REQUEST
                })?;
            
            let checker = PermissionChecker::new(
                state.db.pool().clone(),
                state.redis.clone(),
            );
            
            // Build permission string
            let permission = format!("{}:{}", res_type, act);
            
            if !checker.has_permission_on_resource(
                &user.user_id,
                &permission,
                res_type,
                &resource_id
            ).await {
                tracing::warn!(
                    user_id = %user.user_id,
                    resource_type = %res_type,
                    resource_id = %resource_id,
                    action = %act,
                    "Resource permission denied"
                );
                return Err(StatusCode::FORBIDDEN);
            }
            
            // Store resource context for handler
            request.extensions_mut().insert(ResourceContext {
                resource_type: res_type.to_string(),
                resource_id,
            });
            
            Ok(next.run(request).await)
        })
    }
}

/// Resource context extracted by permission middleware
#[derive(Debug, Clone)]
pub struct ResourceContext {
    pub resource_type: String,
    pub resource_id: String,
}

/// Extract resource ID from request path
/// 
/// Tries to find the resource ID in path parameters.
/// Supports common patterns like:
/// - /documents/:id
/// - /documents/:document_id
/// - /organizations/:org_id/documents/:id
fn extract_resource_id(request: &Request, resource_type: &str) -> Option<String> {
    // Get the URI path
    let path = request.uri().path();
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    
    // Look for patterns like "resource_type/:id" or ":resource_type_id"
    let singular = resource_type.trim_end_matches('s');
    let plural = format!("{}s", singular);
    let id_patterns = [
        format!("{}_id", singular),
        "id".to_string(),
        format!("{}Id", singular),
    ];
    
    // Find the resource type in the path
    for (i, segment) in segments.iter().enumerate() {
        if segment.to_lowercase() == resource_type.to_lowercase()
            || segment.to_lowercase() == singular.to_lowercase()
            || segment.to_lowercase() == plural {
            // Next segment should be the ID
            if i + 1 < segments.len() {
                return Some(segments[i + 1].to_string());
            }
        }
    }
    
    // Check if the last segment could be an ID
    if let Some(last) = segments.last() {
        // If it looks like a UUID, use it
        if looks_like_uuid(last) {
            return Some(last.to_string());
        }
    }
    
    None
}

/// Check if a string looks like a UUID
fn looks_like_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok()
}

/// Load permissions into request context middleware
/// 
/// This middleware loads the user's permissions and stores them
/// in the request extensions, making them available to handlers.
pub async fn load_permissions_middleware(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get current user
    let user = match request.extensions().get::<CurrentUser>() {
        Some(u) => u.clone(),
        None => {
            // No user, continue without permissions
            return Ok(next.run(request).await);
        }
    };
    
    // Check if superadmin
    let is_superadmin = user
        .claims
        .roles
        .as_ref()
        .map(|roles| roles.iter().any(|r| r == "superadmin"))
        .unwrap_or(false);
    
    // Load permissions
    let checker = PermissionChecker::new(
        state.db.pool().clone(),
        state.redis.clone(),
    );
    
    let permissions = checker
        .get_user_permissions(&user.user_id)
        .await
        .unwrap_or_default();
    
    // Create and store permission context
    let ctx = PermissionContext::new(permissions, is_superadmin);
    request.extensions_mut().insert(ctx);
    
    Ok(next.run(request).await)
}

/// Helper function to check permission in a handler
/// 
/// Use this when you need to check permissions dynamically
/// based on request data that isn't available at middleware time.
pub fn check_permission_in_handler(
    request: &Request,
    permission: &str,
) -> bool {
    request
        .extensions()
        .get::<PermissionContext>()
        .map(|ctx| ctx.has_permission(permission))
        .unwrap_or(false)
}

/// Extension trait for Request to easily check permissions
pub trait RequestPermissionExt {
    /// Check if the current user has a permission
    fn has_permission(&self, permission: &str) -> bool;
    /// Check if the current user has any of the permissions
    fn has_any_permission(&self, permissions: &[&str]) -> bool;
    /// Check if the current user has all of the permissions
    fn has_all_permissions(&self, permissions: &[&str]) -> bool;
    /// Get the permission context if available
    fn permission_context(&self) -> Option<&PermissionContext>;
}

impl RequestPermissionExt for Request {
    fn has_permission(&self, permission: &str) -> bool {
        self.permission_context()
            .map(|ctx| ctx.has_permission(permission))
            .unwrap_or(false)
    }
    
    fn has_any_permission(&self, permissions: &[&str]) -> bool {
        self.permission_context()
            .map(|ctx| ctx.has_any_permission(permissions))
            .unwrap_or(false)
    }
    
    fn has_all_permissions(&self, permissions: &[&str]) -> bool {
        self.permission_context()
            .map(|ctx| ctx.has_all_permissions(permissions))
            .unwrap_or(false)
    }
    
    fn permission_context(&self) -> Option<&PermissionContext> {
        self.extensions().get::<PermissionContext>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_permission_context() {
        let ctx = PermissionContext::new(
            vec![
                "document:read".to_string(),
                "document:write".to_string(),
                "user:*".to_string(),
            ],
            false,
        );
        
        assert!(ctx.has_permission("document:read"));
        assert!(ctx.has_permission("document:write"));
        assert!(!ctx.has_permission("document:delete"));
        
        // Wildcard
        assert!(ctx.has_permission("user:read"));
        assert!(ctx.has_permission("user:write"));
        assert!(ctx.has_permission("user:delete"));
        
        // Any
        assert!(ctx.has_any_permission(&["document:read", "document:delete"]));
        assert!(!ctx.has_any_permission(&["document:delete", "document:admin"]));
        
        // All
        assert!(ctx.has_all_permissions(&["document:read", "document:write"]));
        assert!(!ctx.has_all_permissions(&["document:read", "document:delete"]));
    }
    
    #[test]
    fn test_superadmin_bypass() {
        let ctx = PermissionContext::new(vec![], true);
        
        assert!(ctx.has_permission("anything:any"));
        assert!(ctx.has_any_permission(&["a:b", "c:d"]));
        assert!(ctx.has_all_permissions(&["x:y", "z:w", "not:real"]));
    }
    
    #[test]
    fn test_extract_resource_id() {
        use axum::{body::Body, extract::Request};
        
        let request = Request::builder()
            .uri("/documents/123e4567-e89b-12d3-a456-426614174000")
            .body(Body::empty())
            .expect("Failed to build test request");
        
        assert_eq!(
            extract_resource_id(&request, "document"),
            Some("123e4567-e89b-12d3-a456-426614174000".to_string())
        );
        
        let request = Request::builder()
            .uri("/api/v1/organizations/org-123/users/user-456")
            .body(Body::empty())
            .expect("Failed to build test request");
        
        assert_eq!(
            extract_resource_id(&request, "user"),
            Some("user-456".to_string())
        );
    }
    
    #[test]
    fn test_looks_like_uuid() {
        assert!(looks_like_uuid("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!looks_like_uuid("not-a-uuid"));
        assert!(!looks_like_uuid("123"));
    }
}
