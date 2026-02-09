//! Admin Organization Management Routes
//!
//! Full CRUD operations for managing organizations within a tenant.

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::models::organization::{MembershipStatus, OrganizationRole};

/// Organization management routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_all_organizations))
        .route(
            "/:org_id",
            get(get_organization)
                .patch(update_organization)
                .delete(delete_organization),
        )
        .route(
            "/:org_id/members",
            get(list_org_members).post(add_org_member),
        )
        .route(
            "/:org_id/members/:user_id",
            patch(update_org_member).delete(remove_org_member),
        )
        .route("/:org_id/invitations", get(list_org_invitations))
        .route(
            "/:org_id/invitations/:invitation_id",
            delete(cancel_invitation),
        )
}

// ============ Query Parameters ============

#[derive(Debug, Deserialize)]
struct ListOrgsQuery {
    page: Option<i64>,
    #[serde(rename = "per_page")]
    per_page: Option<i64>,
    status: Option<String>,
}

// ============ Request Types ============

#[derive(Debug, Deserialize)]
struct UpdateOrgRequest {
    name: Option<String>,
    description: Option<String>,
    #[serde(rename = "logoUrl")]
    logo_url: Option<String>,
    website: Option<String>,
    #[serde(rename = "maxMembers")]
    max_members: Option<i32>,
    #[serde(rename = "ssoRequired")]
    sso_required: Option<bool>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AddMemberRequest {
    #[serde(rename = "userId")]
    user_id: String,
    role: String,
}

#[derive(Debug, Deserialize)]
struct UpdateMemberRequest {
    role: String,
}

// ============ Response Types ============

#[derive(Debug, Serialize)]
struct PaginatedOrgsResponse {
    data: Vec<AdminOrganizationResponse>,
    pagination: PaginationResponse,
}

#[derive(Debug, Serialize)]
struct PaginationResponse {
    page: i64,
    #[serde(rename = "perPage")]
    per_page: i64,
    total: i64,
    #[serde(rename = "totalPages")]
    total_pages: i64,
}

#[derive(Debug, Serialize)]
struct AdminOrganizationResponse {
    id: String,
    name: String,
    slug: String,
    description: Option<String>,
    #[serde(rename = "logoUrl")]
    logo_url: Option<String>,
    website: Option<String>,
    #[serde(rename = "memberCount")]
    member_count: i64,
    #[serde(rename = "maxMembers")]
    max_members: Option<i32>,
    #[serde(rename = "ssoRequired")]
    sso_required: bool,
    status: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
    #[serde(rename = "deletedAt")]
    deleted_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct AdminOrganizationMemberResponse {
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
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Debug, Serialize)]
struct MessageResponse {
    message: String,
}

#[derive(Debug, FromRow)]
struct OrganizationAdminRow {
    id: String,
    name: String,
    slug: String,
    description: Option<String>,
    logo_url: Option<String>,
    website: Option<String>,
    max_members: Option<i32>,
    sso_required: bool,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn to_org_response(row: OrganizationAdminRow, member_count: i64) -> AdminOrganizationResponse {
    AdminOrganizationResponse {
        id: row.id,
        name: row.name,
        slug: row.slug,
        description: row.description,
        logo_url: row.logo_url,
        website: row.website,
        member_count,
        max_members: row.max_members,
        sso_required: row.sso_required,
        status: row.status,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
        deleted_at: row.deleted_at.map(|dt| dt.to_rfc3339()),
    }
}

// ============ Handlers ============

/// List all organizations
async fn list_all_organizations(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListOrgsQuery>,
) -> Result<Json<PaginatedOrgsResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);

    let offset = (page - 1) * per_page;

    let total: i64 = if let Some(status) = query.status.as_deref() {
        sqlx::query_scalar(
            r#"SELECT COUNT(*)
               FROM organizations
               WHERE tenant_id = $1::uuid AND deleted_at IS NULL AND status = $2"#,
        )
        .bind(&current_user.tenant_id)
        .bind(status)
        .fetch_one(state.db.pool())
        .await
        .map_err(|_| ApiError::internal())?
    } else {
        sqlx::query_scalar(
            r#"SELECT COUNT(*)
               FROM organizations
               WHERE tenant_id = $1::uuid AND deleted_at IS NULL"#,
        )
        .bind(&current_user.tenant_id)
        .fetch_one(state.db.pool())
        .await
        .map_err(|_| ApiError::internal())?
    };

    let orgs: Vec<OrganizationAdminRow> = if let Some(status) = query.status.as_deref() {
        sqlx::query_as(
            r#"SELECT id::text, name, slug, description, logo_url, website,
                      max_members, sso_required, status, created_at, updated_at, deleted_at
               FROM organizations
               WHERE tenant_id = $1::uuid AND deleted_at IS NULL AND status = $4
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3"#,
        )
        .bind(&current_user.tenant_id)
        .bind(per_page)
        .bind(offset)
        .bind(status)
        .fetch_all(state.db.pool())
        .await
        .map_err(|_| ApiError::internal())?
    } else {
        sqlx::query_as(
            r#"SELECT id::text, name, slug, description, logo_url, website,
                      max_members, sso_required, status, created_at, updated_at, deleted_at
               FROM organizations
               WHERE tenant_id = $1::uuid AND deleted_at IS NULL
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3"#,
        )
        .bind(&current_user.tenant_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(state.db.pool())
        .await
        .map_err(|_| ApiError::internal())?
    };

    let total_pages = (total + per_page - 1) / per_page;

    let mut data = Vec::with_capacity(orgs.len());
    for org in orgs {
        let member_count = state
            .db
            .organizations()
            .count_members(&current_user.tenant_id, &org.id, Some("active"))
            .await
            .unwrap_or(0);

        data.push(to_org_response(org, member_count));
    }

    Ok(Json(PaginatedOrgsResponse {
        data,
        pagination: PaginationResponse {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Get organization details
async fn get_organization(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
) -> Result<Json<AdminOrganizationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let org: OrganizationAdminRow = sqlx::query_as(
        r#"SELECT id::text, name, slug, description, logo_url, website,
                  max_members, sso_required, status, created_at, updated_at, deleted_at
           FROM organizations
           WHERE tenant_id = $1::uuid AND id = $2::uuid AND deleted_at IS NULL"#,
    )
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?
    .ok_or(ApiError::NotFound)?;

    let member_count = state
        .db
        .organizations()
        .count_members(&current_user.tenant_id, &org.id, Some("active"))
        .await
        .unwrap_or(0);

    Ok(Json(to_org_response(org, member_count)))
}

/// Update organization
async fn update_organization(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
    Json(req): Json<UpdateOrgRequest>,
) -> Result<Json<AdminOrganizationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let org: OrganizationAdminRow = sqlx::query_as(
        r#"UPDATE organizations
           SET name = COALESCE($1, name),
               description = COALESCE($2, description),
               logo_url = COALESCE($3, logo_url),
               website = COALESCE($4, website),
               max_members = COALESCE($5, max_members),
               sso_required = COALESCE($6, sso_required),
               status = COALESCE($7, status),
               updated_at = $8
           WHERE tenant_id = $9::uuid AND id = $10::uuid AND deleted_at IS NULL
           RETURNING id::text, name, slug, description, logo_url, website,
                     max_members, sso_required, status, created_at, updated_at, deleted_at"#,
    )
    .bind(req.name.as_deref())
    .bind(req.description.as_deref())
    .bind(req.logo_url.as_deref())
    .bind(req.website.as_deref())
    .bind(req.max_members)
    .bind(req.sso_required)
    .bind(req.status.as_deref())
    .bind(Utc::now())
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?
    .ok_or(ApiError::NotFound)?;

    let member_count = state
        .db
        .organizations()
        .count_members(&current_user.tenant_id, &org.id, Some("active"))
        .await
        .unwrap_or(0);

    Ok(Json(to_org_response(org, member_count)))
}

/// Delete organization
async fn delete_organization(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .db
        .organizations()
        .hard_delete(&current_user.tenant_id, &org_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(MessageResponse {
        message: format!("Organization {} deleted", org_id),
    }))
}

/// List organization members
async fn list_org_members(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<AdminOrganizationMemberResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let members = state
        .db
        .organizations()
        .list_members(&current_user.tenant_id, &org_id)
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
            responses.push(AdminOrganizationMemberResponse {
                id: member.id,
                user_id: member.user_id,
                email: user.email,
                name: user.profile.name,
                role: member.role.as_str().to_string(),
                status: member.status.as_str().to_string(),
                joined_at: None,
            });
        }
    }

    Ok(Json(responses))
}

/// Add member to organization
async fn add_org_member(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let role = req
        .role
        .parse::<OrganizationRole>()
        .map_err(|_| ApiError::Validation("Invalid role".to_string()))?;

    let member = vault_core::models::organization::OrganizationMember {
        id: uuid::Uuid::new_v4().to_string(),
        organization_id: org_id,
        user_id: req.user_id,
        role,
        status: MembershipStatus::Active,
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

    Ok(Json(MessageResponse {
        message: "Member added".to_string(),
    }))
}

/// Update member role
async fn update_org_member(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((org_id, user_id)): Path<(String, String)>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let role = req
        .role
        .parse::<OrganizationRole>()
        .map_err(|_| ApiError::Validation("Invalid role".to_string()))?;

    state
        .db
        .organizations()
        .update_member_role(&current_user.tenant_id, &org_id, &user_id, role)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(MessageResponse {
        message: "Member role updated".to_string(),
    }))
}

/// Remove member from organization
async fn remove_org_member(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((org_id, user_id)): Path<(String, String)>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .db
        .organizations()
        .remove_member(&current_user.tenant_id, &org_id, &user_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(MessageResponse {
        message: format!("User {} removed from organization {}", user_id, org_id),
    }))
}

/// List pending invitations
async fn list_org_invitations(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<InvitationResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let invitations = state
        .db
        .organizations()
        .list_invitations(&current_user.tenant_id, &org_id, true)
        .await
        .map_err(|_| ApiError::internal())?;

    let responses: Vec<InvitationResponse> = invitations
        .into_iter()
        .map(|i| InvitationResponse {
            id: i.id,
            email: i.email,
            role: i.role,
            expires_at: i.expires_at.to_rfc3339(),
            created_at: i.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(responses))
}

/// Cancel invitation
async fn cancel_invitation(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((org_id, invitation_id)): Path<(String, String)>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .db
        .organizations()
        .delete_invitation(&current_user.tenant_id, &org_id, &invitation_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(MessageResponse {
        message: format!("Invitation {} cancelled", invitation_id),
    }))
}
