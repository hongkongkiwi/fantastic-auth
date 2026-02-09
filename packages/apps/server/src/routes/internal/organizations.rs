//! Internal organization routes

use axum::{
    extract::{Path, State},
    routing::get,
    Extension, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::permissions::checker::PermissionChecker;
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

#[derive(Debug, Serialize, Clone)]
pub struct OrganizationResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    #[serde(rename = "memberCount")]
    pub member_count: i64,
    pub role: String,
    #[serde(rename = "ssoEnabled")]
    pub sso_enabled: bool,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct OrganizationMemberResponse {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub status: String,
    #[serde(rename = "joinedAt")]
    pub joined_at: String,
}

#[derive(Debug, sqlx::FromRow)]
struct OrganizationRow {
    id: String,
    name: String,
    slug: String,
    member_count: i64,
    role: String,
    sso_enabled: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct OrganizationMemberRow {
    id: String,
    name: String,
    email: String,
    role: String,
    status: String,
    joined_at: DateTime<Utc>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/organizations", get(list_organizations))
        .route("/organizations/:org_id", get(get_organization))
        .route("/organizations/:org_id/members", get(list_members))
}

async fn require_org_read(
    state: &AppState,
    current_user: &CurrentUser,
) -> Result<(), ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let checker = PermissionChecker::new(state.db.pool().clone(), state.redis.clone());
    let allowed = checker
        .has_permission(&current_user.user_id, "organization:read")
        .await;
    if !allowed {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn list_organizations(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<OrganizationResponse>>, ApiError> {
    require_org_read(&state, &current_user).await?;

    let rows = sqlx::query_as::<_, OrganizationRow>(
        r#"
        SELECT o.id::text as id,
               o.name,
               o.slug,
               COALESCE(m.member_count, 0) as member_count,
               COALESCE(om.role::text, 'admin') as role,
               (o.sso_required OR o.sso_config IS NOT NULL) as sso_enabled,
               o.created_at
        FROM organizations o
        LEFT JOIN (
            SELECT organization_id, COUNT(*) as member_count
            FROM organization_members
            GROUP BY organization_id
        ) m ON m.organization_id = o.id
        LEFT JOIN organization_members om
            ON om.organization_id = o.id AND om.user_id = $2::uuid
        WHERE o.tenant_id = $1::uuid AND o.deleted_at IS NULL
        ORDER BY o.created_at DESC
        "#,
    )
    .bind(&current_user.tenant_id)
    .bind(&current_user.user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let orgs = rows
        .into_iter()
        .map(|row| OrganizationResponse {
            id: row.id,
            name: row.name,
            slug: row.slug,
            member_count: row.member_count,
            role: row.role,
            sso_enabled: row.sso_enabled,
            created_at: row.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(orgs))
}

async fn get_organization(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    require_org_read(&state, &current_user).await?;

    let row = sqlx::query_as::<_, OrganizationRow>(
        r#"
        SELECT o.id::text as id,
               o.name,
               o.slug,
               COALESCE(m.member_count, 0) as member_count,
               COALESCE(om.role::text, 'admin') as role,
               (o.sso_required OR o.sso_config IS NOT NULL) as sso_enabled,
               o.created_at
        FROM organizations o
        LEFT JOIN (
            SELECT organization_id, COUNT(*) as member_count
            FROM organization_members
            GROUP BY organization_id
        ) m ON m.organization_id = o.id
        LEFT JOIN organization_members om
            ON om.organization_id = o.id AND om.user_id = $2::uuid
        WHERE o.tenant_id = $1::uuid AND o.id = $3::uuid AND o.deleted_at IS NULL
        "#,
    )
    .bind(&current_user.tenant_id)
    .bind(&current_user.user_id)
    .bind(&org_id)
    .fetch_optional(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    match row {
        Some(row) => Ok(Json(OrganizationResponse {
            id: row.id,
            name: row.name,
            slug: row.slug,
            member_count: row.member_count,
            role: row.role,
            sso_enabled: row.sso_enabled,
            created_at: row.created_at.to_rfc3339(),
        })),
        None => Err(ApiError::NotFound),
    }
}

async fn list_members(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
) -> Result<Json<Vec<OrganizationMemberResponse>>, ApiError> {
    require_org_read(&state, &current_user).await?;

    let rows = sqlx::query_as::<_, OrganizationMemberRow>(
        r#"
        SELECT om.id::text as id,
               COALESCE(u.profile->>'name', u.email) as name,
               u.email,
               om.role::text as role,
               om.status::text as status,
               COALESCE(om.joined_at, om.created_at) as joined_at
        FROM organization_members om
        JOIN users u ON u.id = om.user_id
        WHERE om.tenant_id = $1::uuid AND om.organization_id = $2::uuid
        ORDER BY COALESCE(om.joined_at, om.created_at) DESC
        "#,
    )
    .bind(&current_user.tenant_id)
    .bind(&org_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|_| ApiError::internal())?;

    let members = rows
        .into_iter()
        .map(|row| OrganizationMemberResponse {
            id: row.id,
            name: row.name,
            email: row.email,
            role: row.role,
            status: row.status,
            joined_at: row.joined_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(members))
}
