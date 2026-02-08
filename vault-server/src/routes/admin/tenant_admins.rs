//! Admin Tenant Admin Management Routes

use axum::{
    extract::{Path, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::crypto::generate_secure_random;
use vault_core::email::EmailRequest;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/tenant-admins", get(list_admins).post(create_admin))
        .route(
            "/tenant-admins/:user_id",
            patch(update_admin).delete(remove_admin),
        )
        .route("/tenant-admins/invitations", get(list_invitations).post(create_invitation))
}

#[derive(Debug, Deserialize)]
struct CreateAdminRequest {
    #[serde(rename = "userId")]
    user_id: String,
    role: String,
}

#[derive(Debug, Deserialize)]
struct UpdateAdminRequest {
    role: Option<String>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateInvitationRequest {
    email: String,
    role: String,
}

#[derive(Debug, Serialize)]
struct TenantAdminResponse {
    id: String,
    #[serde(rename = "userId")]
    user_id: String,
    role: String,
    status: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Debug, Serialize)]
struct InvitationResponse {
    id: String,
    email: String,
    role: String,
    #[serde(rename = "invitedBy")]
    invited_by: Option<String>,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

async fn list_admins(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<TenantAdminResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let admins = state
        .auth_service
        .db()
        .tenant_admins()
        .list_admins(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(
        admins
            .into_iter()
            .map(|a| TenantAdminResponse {
                id: a.id,
                user_id: a.user_id,
                role: a.role,
                status: a.status,
                created_at: a.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}

async fn create_admin(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateAdminRequest>,
) -> Result<Json<TenantAdminResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let admin = state
        .auth_service
        .db()
        .tenant_admins()
        .upsert_admin(&current_user.tenant_id, &req.user_id, &req.role, "active")
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(TenantAdminResponse {
        id: admin.id,
        user_id: admin.user_id,
        role: admin.role,
        status: admin.status,
        created_at: admin.created_at.to_rfc3339(),
    }))
}

async fn update_admin(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
    Json(req): Json<UpdateAdminRequest>,
) -> Result<Json<TenantAdminResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let admin = state
        .auth_service
        .db()
        .tenant_admins()
        .upsert_admin(
            &current_user.tenant_id,
            &user_id,
            req.role.as_deref().unwrap_or("admin"),
            req.status.as_deref().unwrap_or("active"),
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(TenantAdminResponse {
        id: admin.id,
        user_id: admin.user_id,
        role: admin.role,
        status: admin.status,
        created_at: admin.created_at.to_rfc3339(),
    }))
}

async fn remove_admin(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    state
        .auth_service
        .db()
        .tenant_admins()
        .remove_admin(&current_user.tenant_id, &user_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(serde_json::json!({"message": "Admin removed"})))
}

async fn list_invitations(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<InvitationResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let invites = state
        .auth_service
        .db()
        .tenant_admins()
        .list_invitations(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(Json(
        invites
            .into_iter()
            .map(|i| InvitationResponse {
                id: i.id,
                email: i.email,
                role: i.role,
                invited_by: i.invited_by,
                expires_at: i.expires_at.to_rfc3339(),
                created_at: i.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}

async fn create_invitation(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateInvitationRequest>,
) -> Result<Json<InvitationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    let token = generate_secure_random(32);
    let expires_at = chrono::Utc::now() + chrono::Duration::days(7);

    let invite = state
        .auth_service
        .db()
        .tenant_admins()
        .create_invitation(
            &current_user.tenant_id,
            &req.email,
            &req.role,
            &token,
            Some(&current_user.user_id),
            expires_at,
        )
        .await
        .map_err(|_| ApiError::Internal)?;

    if let Some(email_service) = state.email_service.clone() {
        if let Some(ref smtp_config) = state.config.smtp {
            let link = format!(
                "{}/admin/tenant-admins/invitations/accept?token={}&tenant_id={}",
                state.config.base_url, token, current_user.tenant_id
            );
            let html_body = format!(
                r#"<p>You have been invited to be a tenant admin.</p>
<p><a href="{}">Accept invitation</a></p>"#,
                link
            );
            let text_body = format!("Accept invitation: {}", link);

            let _ = email_service
                .send_email(EmailRequest {
                    to: req.email.clone(),
                    to_name: None,
                    subject: "Tenant admin invitation".to_string(),
                    html_body,
                    text_body,
                    from: smtp_config.from_address.clone(),
                    from_name: smtp_config.from_name.clone(),
                    reply_to: None,
                    headers: HashMap::new(),
                })
                .await;
        }
    }

    Ok(Json(InvitationResponse {
        id: invite.id,
        email: invite.email,
        role: invite.role,
        invited_by: invite.invited_by,
        expires_at: invite.expires_at.to_rfc3339(),
        created_at: invite.created_at.to_rfc3339(),
    }))
}
