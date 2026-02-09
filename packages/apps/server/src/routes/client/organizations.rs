//! Client Organization Routes
//!
//! End-user organization management endpoints.

use axum::{
    extract::{Path, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::db::organizations::OrganizationInvitation as DbOrganizationInvitation;
use vault_core::models::organization::{MembershipStatus, OrganizationInvitation, OrganizationMember, OrganizationRole};

/// Organization routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_organizations).post(create_organization))
        .route(
            "/:id",
            get(get_organization)
                .patch(update_organization)
                .delete(delete_organization),
        )
        .route("/:id/members", get(list_members).post(invite_member))
        .route(
            "/:id/members/:user_id",
            patch(update_member).delete(remove_member),
        )
        .route("/:id/invitations", get(list_invitations))
        .route("/invitations/:token/accept", post(accept_invitation))
        .route("/:id/leave", post(leave_organization))
}

#[derive(Debug, Deserialize)]
struct CreateOrgRequest {
    name: String,
    slug: String,
}

#[derive(Debug, Deserialize)]
struct UpdateOrgRequest {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InviteMemberRequest {
    email: String,
    role: String,
}

#[derive(Debug, Deserialize)]
struct UpdateMemberRequest {
    role: String,
}

#[derive(Debug, Serialize)]
struct OrganizationResponse {
    id: String,
    name: String,
    slug: String,
    role: String,
}

#[derive(Debug, Serialize)]
struct OrganizationMemberResponse {
    id: String,
    #[serde(rename = "userId")]
    user_id: String,
    email: String,
    name: Option<String>,
    role: String,
    status: String,
    #[serde(rename = "joinedAt")]
    joined_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct InvitationResponse {
    id: String,
    email: String,
    role: String,
    #[serde(rename = "invitedBy")]
    invited_by: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

/// List organizations for current user
async fn list_organizations(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<OrganizationResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let orgs = state
        .db
        .organizations()
        .list_for_user(&current_user.tenant_id, &current_user.user_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let responses: Vec<OrganizationResponse> = orgs
        .into_iter()
        .map(|o| OrganizationResponse {
            id: o.id,
            name: o.name,
            slug: o.slug,
            role: "member".to_string(),
        })
        .collect();

    Ok(Json(responses))
}

/// Get organization details
async fn get_organization(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let org = state
        .db
        .organizations()
        .get_by_id(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(OrganizationResponse {
        id: org.id,
        name: org.name,
        slug: org.slug,
        role: "member".to_string(),
    }))
}

/// Create organization
async fn create_organization(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateOrgRequest>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let org = vault_core::models::organization::Organization {
        id: uuid::Uuid::new_v4().to_string(),
        tenant_id: current_user.tenant_id.clone(),
        name: req.name,
        slug: req.slug,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        ..Default::default()
    };

    let org = state
        .db
        .organizations()
        .create(&org)
        .await
        .map_err(|_| ApiError::internal())?;

    let member = OrganizationMember {
        id: uuid::Uuid::new_v4().to_string(),
        tenant_id: current_user.tenant_id.clone(),
        organization_id: org.id.clone(),
        user_id: current_user.user_id.clone(),
        role: OrganizationRole::Owner,
        status: MembershipStatus::Active,
        invited_by: None,
        invited_at: None,
        joined_at: Some(chrono::Utc::now()),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        ..Default::default()
    };

    state
        .db
        .organizations()
        .add_member(&current_user.tenant_id, &member)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(OrganizationResponse {
        id: org.id,
        name: org.name,
        slug: org.slug,
        role: "owner".to_string(),
    }))
}

/// Update organization
async fn update_organization(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(req): Json<UpdateOrgRequest>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let mut org = state
        .db
        .organizations()
        .get_by_id(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    if let Some(name) = req.name {
        org.name = name;
    }

    let org = state
        .db
        .organizations()
        .update(&current_user.tenant_id, &org)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(OrganizationResponse {
        id: org.id,
        name: org.name,
        slug: org.slug,
        role: "member".to_string(),
    }))
}

/// Delete organization
async fn delete_organization(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .db
        .organizations()
        .delete(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(MessageResponse {
        message: "Organization deleted".to_string(),
    }))
}

/// Leave organization
async fn leave_organization(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .db
        .organizations()
        .remove_member(&current_user.tenant_id, &id, &current_user.user_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(MessageResponse {
        message: "Left organization".to_string(),
    }))
}

fn ensure_org_admin(member: &OrganizationMember) -> Result<(), ApiError> {
    match member.role {
        OrganizationRole::Owner | OrganizationRole::Admin => Ok(()),
        _ => Err(ApiError::Forbidden),
    }
}

async fn load_member(
    state: &AppState,
    tenant_id: &str,
    org_id: &str,
    user_id: &str,
) -> Result<OrganizationMember, ApiError> {
    state
        .db
        .organizations()
        .get_member(tenant_id, org_id, user_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::Forbidden)
}

/// List organization members
async fn list_members(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<Vec<OrganizationMemberResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    // Require membership
    let _member = load_member(&state, &current_user.tenant_id, &id, &current_user.user_id).await?;

    let members = state
        .db
        .organizations()
        .list_members(&current_user.tenant_id, &id)
        .await
        .map_err(|_| ApiError::internal())?;

    let mut responses = Vec::new();
    for member in members {
        if let Ok(Some(user)) = state
            .db
            .users()
            .find_by_id(&current_user.tenant_id, &member.user_id)
            .await
        {
            responses.push(OrganizationMemberResponse {
                id: member.id,
                user_id: member.user_id,
                email: user.email,
                name: user.profile.name,
                role: member.role.as_str().to_string(),
                status: member.status.as_str().to_string(),
                joined_at: member.joined_at.map(|d| d.to_rfc3339()),
            });
        }
    }

    Ok(Json(responses))
}

/// Invite member (creates invitation)
async fn invite_member(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
    Json(req): Json<InviteMemberRequest>,
) -> Result<Json<InvitationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let member = load_member(&state, &current_user.tenant_id, &id, &current_user.user_id).await?;
    ensure_org_admin(&member)?;

    let role = req
        .role
        .parse::<OrganizationRole>()
        .map_err(|_| ApiError::Validation("Invalid role".to_string()))?;

    let invitation = OrganizationInvitation::new(
        current_user.tenant_id.clone(),
        id,
        req.email,
        role,
        current_user.user_id.clone(),
    );

    let db_invitation = DbOrganizationInvitation {
        id: invitation.id.clone(),
        organization_id: invitation.organization_id.clone(),
        email: invitation.email.clone(),
        role: invitation.role.to_string(),
        invited_by: invitation.invited_by.clone(),
        token: invitation.token.clone(),
        expires_at: invitation.expires_at,
        accepted_at: invitation.accepted_at,
        created_at: invitation.created_at,
    };

    let invitation = state
        .db
        .organizations()
        .create_invitation(&current_user.tenant_id, &db_invitation)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(InvitationResponse {
        id: invitation.id,
        email: invitation.email,
        role: invitation.role,
        invited_by: invitation.invited_by,
        expires_at: invitation.expires_at.to_rfc3339(),
        created_at: invitation.created_at.to_rfc3339(),
    }))
}

/// Update member role
async fn update_member(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((id, user_id)): Path<(String, String)>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<Json<OrganizationMemberResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let member = load_member(&state, &current_user.tenant_id, &id, &current_user.user_id).await?;
    ensure_org_admin(&member)?;

    let role = req
        .role
        .parse::<OrganizationRole>()
        .map_err(|_| ApiError::Validation("Invalid role".to_string()))?;

    let updated = state
        .db
        .organizations()
        .update_member_role(&current_user.tenant_id, &id, &user_id, role)
        .await
        .map_err(|_| ApiError::internal())?;

    let user = state
        .db
        .users()
        .find_by_id(&current_user.tenant_id, &updated.user_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(OrganizationMemberResponse {
        id: updated.id,
        user_id: updated.user_id,
        email: user.email,
        name: user.profile.name,
        role: updated.role.as_str().to_string(),
        status: updated.status.as_str().to_string(),
        joined_at: updated.joined_at.map(|d| d.to_rfc3339()),
    }))
}

/// Remove member from organization
async fn remove_member(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((id, user_id)): Path<(String, String)>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let member = load_member(&state, &current_user.tenant_id, &id, &current_user.user_id).await?;
    ensure_org_admin(&member)?;

    state
        .db
        .organizations()
        .remove_member(&current_user.tenant_id, &id, &user_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(MessageResponse {
        message: format!("User {} removed from organization {}", user_id, id),
    }))
}

/// List pending invitations
async fn list_invitations(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(id): Path<String>,
) -> Result<Json<Vec<InvitationResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let member = load_member(&state, &current_user.tenant_id, &id, &current_user.user_id).await?;
    ensure_org_admin(&member)?;

    let invitations = state
        .db
        .organizations()
        .list_invitations(&current_user.tenant_id, &id, true)
        .await
        .map_err(|_| ApiError::internal())?;

    let responses = invitations
        .into_iter()
        .map(|i| InvitationResponse {
            id: i.id,
            email: i.email,
            role: i.role,
            invited_by: i.invited_by,
            expires_at: i.expires_at.to_rfc3339(),
            created_at: i.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(responses))
}

/// Accept invitation
async fn accept_invitation(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(token): Path<String>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let invitation = state
        .db
        .organizations()
        .get_invitation_by_token(&current_user.tenant_id, &token)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    if invitation.accepted_at.is_some() || invitation.expires_at < chrono::Utc::now() {
        return Err(ApiError::BadRequest("Invitation is expired".to_string()));
    }

    if invitation.email.to_lowercase() != current_user.email.to_lowercase() {
        return Err(ApiError::Forbidden);
    }

    let invitation = state
        .db
        .organizations()
        .accept_invitation(&current_user.tenant_id, &token, &current_user.user_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    let org = state
        .db
        .organizations()
        .get_by_id(&current_user.tenant_id, &invitation.organization_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(OrganizationResponse {
        id: org.id,
        name: org.name,
        slug: org.slug,
        role: invitation.role,
    }))
}
