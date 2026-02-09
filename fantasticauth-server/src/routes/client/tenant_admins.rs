//! Client Tenant Admin Invite Acceptance

use axum::{
    extract::State,
    routing::post,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/tenant-admins/invitations/accept",
        post(accept_invitation),
    )
}

#[derive(Debug, Deserialize)]
struct AcceptInviteRequest {
    token: String,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

async fn accept_invitation(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<AcceptInviteRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let invite = state
        .auth_service
        .db()
        .tenant_admins()
        .find_invitation_by_token(&current_user.tenant_id, &req.token)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::BadRequest("Invalid or expired invitation".to_string()))?;

    if invite.email.to_lowercase() != current_user.email.to_lowercase() {
        return Err(ApiError::BadRequest(
            "Invitation email does not match current user".to_string(),
        ));
    }

    state
        .auth_service
        .db()
        .tenant_admins()
        .accept_invitation(&invite.id)
        .await
        .map_err(|_| ApiError::Internal)?;

    state
        .auth_service
        .db()
        .tenant_admins()
        .upsert_admin(&current_user.tenant_id, &current_user.user_id, &invite.role, "active")
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(MessageResponse {
        message: "Invitation accepted".to_string(),
    }))
}
