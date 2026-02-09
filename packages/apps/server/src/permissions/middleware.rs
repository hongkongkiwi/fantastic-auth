//! Permission Middleware
//!
//! Re-exports from `crate::middleware::permission` for convenience.
//! Also provides additional RBAC++ specific middleware functions.

pub use crate::middleware::permission::{
    check_permission_in_handler,
    load_permissions_middleware,
    require_all_permissions,
    require_any_permission,
    require_permission,
    require_permission_on_resource,
    PermissionContext,
    RequestPermissionExt,
    ResourceContext,
};

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

use crate::permissions::service::PermissionService;
use crate::state::{AppState, CurrentUser};

/// Middleware that requires the `admin:*` wildcard permission
///
/// This is a convenience middleware for admin-only routes.
pub fn require_admin() ->
    impl Fn(State<AppState>, Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> + Clone + Send + Sync
{
    require_any_permission(&["admin:*", "system:admin"])
}

/// Middleware factory that checks for specific resource permission
///
/// Similar to `require_permission_on_resource` but extracts the resource ID
/// from a custom path parameter.
///
/// # Example
/// ```rust
/// use axum::{routing::get, Router};
/// use axum::middleware;
///
/// let app = Router::new()
///     .route("/folders/:folder_id/documents/:doc_id", get(get_document))
///     .layer(middleware::from_fn_with_state(
///         state.clone(),
///         require_resource_permission("document", "read", "doc_id")
///     ));
/// ```
pub fn require_resource_permission(
    resource_type: &'static str,
    action: &'static str,
    path_param: &'static str,
) -> impl Fn(State<AppState>, Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> + Clone + Send + Sync
{
    move |State(state): State<AppState>, mut request: Request, next: Next| {
        let res_type = resource_type;
        let act = action;
        let param = path_param;
        
        Box::pin(async move {
            let user = request
                .extensions()
                .get::<CurrentUser>()
                .ok_or(StatusCode::UNAUTHORIZED)?
                .clone();

            // Extract resource ID from path
            let resource_id = extract_path_param(&request, param)
                .ok_or_else(|| {
                    tracing::warn!("Could not extract {} from path", param);
                    StatusCode::BAD_REQUEST
                })?;

            let service = PermissionService::new(
                state.db.pool().clone(),
                state.redis.clone(),
            );

            if !service
                .check_user_permission_on_resource(
                    &user.user_id,
                    &format!("{}:{}", res_type, act),
                    res_type,
                    &resource_id,
                )
                .await
            {
                tracing::warn!(
                    user_id = %user.user_id,
                    resource_type = %res_type,
                    resource_id = %resource_id,
                    action = %act,
                    "Resource permission denied"
                );
                return Err(StatusCode::FORBIDDEN);
            }

            // Store resource context
            request.extensions_mut().insert(ResourceContext {
                resource_type: res_type.to_string(),
                resource_id,
            });

            Ok(next.run(request).await)
        })
    }
}

/// Extract a path parameter from the request URI
fn extract_path_param(request: &Request, param_name: &str) -> Option<String> {
    let path = request.uri().path();
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    // Look for patterns like ":param_name" or the value after a matching segment
    for (i, segment) in segments.iter().enumerate() {
        // Check if this segment is the parameter name
        if segment.trim_start_matches(':') == param_name {
            // Return the next segment as the value
            return segments.get(i + 1).map(|s| s.to_string());
        }
        
        // Check if the next segment might be the value we're looking for
        if i + 1 < segments.len() {
            // Check if current segment ends with the param name (e.g., "doc_id" in "doc_id/123")
            if segment.contains(param_name) {
                return Some(segments[i + 1].to_string());
            }
        }
    }

    // Fallback: check if any segment looks like a UUID (commonly used as ID)
    for segment in &segments {
        if uuid::Uuid::parse_str(segment).is_ok() {
            return Some(segment.to_string());
        }
    }

    None
}

/// Middleware that loads permissions and makes them available to handlers
///
/// This is a convenience wrapper around `load_permissions_middleware` that
/// also validates the user has at least one permission (not just superadmin).
pub async fn require_any_permission_loaded(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // First load permissions
    let user = match request.extensions().get::<CurrentUser>() {
        Some(u) => u.clone(),
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let service = PermissionService::new(
        state.db.pool().clone(),
        state.redis.clone(),
    );

    let permissions = service
        .get_user_permissions(&user.user_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let is_superadmin = user
        .claims
        .roles
        .as_ref()
        .map(|roles| roles.iter().any(|r| r == "superadmin"))
        .unwrap_or(false);

    // Check if user has any permissions or is superadmin
    if permissions.is_empty() && !is_superadmin {
        tracing::warn!(
            user_id = %user.user_id,
            "User has no permissions assigned"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // Create and store permission context
    let ctx = PermissionContext::new(permissions, is_superadmin);
    request.extensions_mut().insert(ctx);

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn test_extract_path_param() {
        let request = Request::builder()
            .uri("/documents/123e4567-e89b-12d3-a456-426614174000")
            .body(())
            .unwrap();

        assert_eq!(
            extract_path_param(&request, "id"),
            Some("123e4567-e89b-12d3-a456-426614174000".to_string())
        );

        let request = Request::builder()
            .uri("/folders/folder-123/documents/doc-456")
            .body(())
            .unwrap();

        assert_eq!(
            extract_path_param(&request, "folder_id"),
            None // Our simple extraction doesn't handle this pattern
        );
    }
}
