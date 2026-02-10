use axum::{
    http::{Method, StatusCode},
    middleware::Next,
    response::Response,
    Extension,
};

use crate::state::CurrentUser;

pub async fn admin_role_middleware(
    Extension(user): Extension<CurrentUser>,
    request: axum::extract::Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let roles = user.claims.roles.clone().unwrap_or_default();
    let is_superadmin = roles.iter().any(|r| r == "superadmin");
    let is_owner = roles.iter().any(|r| r == "owner");
    let is_admin = roles.iter().any(|r| r == "admin");
    let is_support = roles.iter().any(|r| r == "support");
    let is_viewer = roles.iter().any(|r| r == "viewer");

    if is_superadmin || is_owner || is_admin {
        return Ok(next.run(request).await);
    }

    if is_support || is_viewer {
        let method = request.method().clone();
        if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
            return Ok(next.run(request).await);
        }
        return Err(StatusCode::FORBIDDEN);
    }

    Err(StatusCode::FORBIDDEN)
}
