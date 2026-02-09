//! Admin Project Management Routes

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::models::project::{Project, ProjectGrant, ProjectRole, ProjectRoleAssignment, ProjectStatus};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/projects", get(list_projects).post(create_project))
        .route(
            "/projects/:project_id",
            get(get_project)
                .patch(update_project)
                .delete(delete_project),
        )
        .route(
            "/projects/:project_id/roles",
            get(list_project_roles).post(create_project_role),
        )
        .route(
            "/projects/:project_id/roles/:role_id",
            patch(update_project_role).delete(delete_project_role),
        )
        .route(
            "/projects/:project_id/assignments",
            get(list_project_assignments).post(assign_project_role),
        )
        .route(
            "/projects/:project_id/assignments/:assignment_id",
            delete(remove_project_assignment),
        )
        .route(
            "/projects/:project_id/grants",
            get(list_project_grants).post(create_project_grant),
        )
        .route(
            "/projects/:project_id/grants/:grant_id",
            delete(delete_project_grant),
        )
}

#[derive(Debug, Deserialize)]
struct ListProjectsQuery {
    #[serde(rename = "orgId")]
    organization_id: String,
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CreateProjectRequest {
    #[serde(rename = "orgId")]
    organization_id: String,
    name: String,
    slug: String,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateProjectRequest {
    name: Option<String>,
    slug: Option<String>,
    description: Option<String>,
    status: Option<String>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct ProjectResponse {
    id: String,
    #[serde(rename = "orgId")]
    organization_id: String,
    name: String,
    slug: String,
    description: Option<String>,
    status: String,
    metadata: serde_json::Value,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct CreateRoleRequest {
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateRoleRequest {
    name: Option<String>,
    description: Option<String>,
    permissions: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct ProjectRoleResponse {
    id: String,
    #[serde(rename = "projectId")]
    project_id: String,
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
    #[serde(rename = "isSystemRole")]
    is_system_role: bool,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct AssignRoleRequest {
    #[serde(rename = "roleId")]
    role_id: String,
    #[serde(rename = "userId")]
    user_id: String,
}

#[derive(Debug, Serialize)]
struct ProjectRoleAssignmentResponse {
    id: String,
    #[serde(rename = "projectId")]
    project_id: String,
    #[serde(rename = "roleId")]
    role_id: String,
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "assignedAt")]
    assigned_at: String,
    #[serde(rename = "assignedBy")]
    assigned_by: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateGrantRequest {
    #[serde(rename = "grantedOrgId")]
    granted_organization_id: String,
    #[serde(rename = "defaultRoleId")]
    default_role_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProjectGrantResponse {
    id: String,
    #[serde(rename = "projectId")]
    project_id: String,
    #[serde(rename = "grantedOrgId")]
    granted_organization_id: String,
    #[serde(rename = "defaultRoleId")]
    default_role_id: Option<String>,
    #[serde(rename = "createdAt")]
    created_at: String,
}

async fn list_projects(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Query(query): Query<ListProjectsQuery>,
) -> Result<Json<Vec<ProjectResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * per_page;

    let projects = state
        .db
        .projects()
        .list_by_org(&current_user.tenant_id, &query.organization_id, per_page, offset)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(
        projects
            .into_iter()
            .map(|p| ProjectResponse {
                id: p.id,
                organization_id: p.organization_id,
                name: p.name,
                slug: p.slug,
                description: p.description,
                status: format!("{:?}", p.status).to_lowercase(),
                metadata: p.metadata,
                created_at: p.created_at.to_rfc3339(),
                updated_at: p.updated_at.to_rfc3339(),
            })
            .collect(),
    ))
}

async fn create_project(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateProjectRequest>,
) -> Result<Json<ProjectResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let project = Project::new(&current_user.tenant_id, &req.organization_id, &req.name, &req.slug);
    let project = Project {
        description: req.description,
        ..project
    };

    let created = state
        .db
        .projects()
        .create(&project)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ProjectResponse {
        id: created.id,
        organization_id: created.organization_id,
        name: created.name,
        slug: created.slug,
        description: created.description,
        status: format!("{:?}", created.status).to_lowercase(),
        metadata: created.metadata,
        created_at: created.created_at.to_rfc3339(),
        updated_at: created.updated_at.to_rfc3339(),
    }))
}

async fn get_project(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(project_id): Path<String>,
) -> Result<Json<ProjectResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let project = state
        .db
        .projects()
        .get_by_id(&current_user.tenant_id, &project_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(ProjectResponse {
        id: project.id,
        organization_id: project.organization_id,
        name: project.name,
        slug: project.slug,
        description: project.description,
        status: format!("{:?}", project.status).to_lowercase(),
        metadata: project.metadata,
        created_at: project.created_at.to_rfc3339(),
        updated_at: project.updated_at.to_rfc3339(),
    }))
}

async fn update_project(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(project_id): Path<String>,
    Json(req): Json<UpdateProjectRequest>,
) -> Result<Json<ProjectResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let mut project = state
        .db
        .projects()
        .get_by_id(&current_user.tenant_id, &project_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    if let Some(name) = req.name {
        project.name = name;
    }
    if let Some(slug) = req.slug {
        project.slug = slug;
    }
    if let Some(description) = req.description {
        project.description = Some(description);
    }
    if let Some(status) = req.status {
        project.status = status.parse().unwrap_or(ProjectStatus::Active);
    }
    if let Some(metadata) = req.metadata {
        project.metadata = metadata;
    }

    let updated = state
        .db
        .projects()
        .update(&current_user.tenant_id, &project)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ProjectResponse {
        id: updated.id,
        organization_id: updated.organization_id,
        name: updated.name,
        slug: updated.slug,
        description: updated.description,
        status: format!("{:?}", updated.status).to_lowercase(),
        metadata: updated.metadata,
        created_at: updated.created_at.to_rfc3339(),
        updated_at: updated.updated_at.to_rfc3339(),
    }))
}

async fn delete_project(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(project_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .db
        .projects()
        .delete(&current_user.tenant_id, &project_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(serde_json::json!({"deleted": true})))
}

async fn list_project_roles(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(project_id): Path<String>,
) -> Result<Json<Vec<ProjectRoleResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let roles = state
        .db
        .projects()
        .list_roles(&current_user.tenant_id, &project_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(
        roles
            .into_iter()
            .map(|r| ProjectRoleResponse {
                id: r.id,
                project_id: r.project_id,
                name: r.name,
                description: r.description,
                permissions: r.permissions,
                is_system_role: r.is_system_role,
                created_at: r.created_at.to_rfc3339(),
                updated_at: r.updated_at.to_rfc3339(),
            })
            .collect(),
    ))
}

async fn create_project_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(project_id): Path<String>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<Json<ProjectRoleResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let now = chrono::Utc::now();
    let role = ProjectRole {
        id: uuid::Uuid::new_v4().to_string(),
        tenant_id: current_user.tenant_id.clone(),
        project_id,
        name: req.name,
        description: req.description,
        permissions: req.permissions,
        is_system_role: false,
        created_at: now,
        updated_at: now,
    };

    let created = state
        .db
        .projects()
        .create_role(&role)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ProjectRoleResponse {
        id: created.id,
        project_id: created.project_id,
        name: created.name,
        description: created.description,
        permissions: created.permissions,
        is_system_role: created.is_system_role,
        created_at: created.created_at.to_rfc3339(),
        updated_at: created.updated_at.to_rfc3339(),
    }))
}

async fn update_project_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((_project_id, role_id)): Path<(String, String)>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<ProjectRoleResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let mut role = state
        .db
        .projects()
        .get_role_by_id(&current_user.tenant_id, &role_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    if let Some(name) = req.name {
        role.name = name;
    }
    if let Some(description) = req.description {
        role.description = Some(description);
    }
    if let Some(perms) = req.permissions {
        role.permissions = perms;
    }

    let updated = state
        .db
        .projects()
        .update_role(&current_user.tenant_id, &role)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ProjectRoleResponse {
        id: updated.id,
        project_id: updated.project_id,
        name: updated.name,
        description: updated.description,
        permissions: updated.permissions,
        is_system_role: updated.is_system_role,
        created_at: updated.created_at.to_rfc3339(),
        updated_at: updated.updated_at.to_rfc3339(),
    }))
}

async fn delete_project_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((_project_id, role_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .db
        .projects()
        .delete_role(&current_user.tenant_id, &role_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(serde_json::json!({"deleted": true})))
}

async fn list_project_assignments(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(project_id): Path<String>,
) -> Result<Json<Vec<ProjectRoleAssignmentResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let assignments = state
        .db
        .projects()
        .list_assignments(&current_user.tenant_id, &project_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(
        assignments
            .into_iter()
            .map(|a| ProjectRoleAssignmentResponse {
                id: a.id,
                project_id: a.project_id,
                role_id: a.role_id,
                user_id: a.user_id,
                assigned_at: a.assigned_at.to_rfc3339(),
                assigned_by: a.assigned_by,
            })
            .collect(),
    ))
}

async fn assign_project_role(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(project_id): Path<String>,
    Json(req): Json<AssignRoleRequest>,
) -> Result<Json<ProjectRoleAssignmentResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let assignment = ProjectRoleAssignment {
        id: uuid::Uuid::new_v4().to_string(),
        tenant_id: current_user.tenant_id.clone(),
        project_id,
        role_id: req.role_id,
        user_id: req.user_id,
        assigned_at: chrono::Utc::now(),
        assigned_by: Some(current_user.user_id.clone()),
    };

    let created = state
        .db
        .projects()
        .assign_role(&assignment)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ProjectRoleAssignmentResponse {
        id: created.id,
        project_id: created.project_id,
        role_id: created.role_id,
        user_id: created.user_id,
        assigned_at: created.assigned_at.to_rfc3339(),
        assigned_by: created.assigned_by,
    }))
}

async fn remove_project_assignment(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((_project_id, assignment_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .db
        .projects()
        .remove_assignment(&current_user.tenant_id, &assignment_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(serde_json::json!({"deleted": true})))
}

async fn list_project_grants(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(project_id): Path<String>,
) -> Result<Json<Vec<ProjectGrantResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let grants = state
        .db
        .projects()
        .list_grants(&current_user.tenant_id, &project_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(
        grants
            .into_iter()
            .map(|g| ProjectGrantResponse {
                id: g.id,
                project_id: g.project_id,
                granted_organization_id: g.granted_organization_id,
                default_role_id: g.default_role_id,
                created_at: g.created_at.to_rfc3339(),
            })
            .collect(),
    ))
}

async fn create_project_grant(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(project_id): Path<String>,
    Json(req): Json<CreateGrantRequest>,
) -> Result<Json<ProjectGrantResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let grant = ProjectGrant {
        id: uuid::Uuid::new_v4().to_string(),
        tenant_id: current_user.tenant_id.clone(),
        project_id,
        granted_organization_id: req.granted_organization_id,
        default_role_id: req.default_role_id,
        created_at: chrono::Utc::now(),
    };

    let created = state
        .db
        .projects()
        .create_grant(&grant)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ProjectGrantResponse {
        id: created.id,
        project_id: created.project_id,
        granted_organization_id: created.granted_organization_id,
        default_role_id: created.default_role_id,
        created_at: created.created_at.to_rfc3339(),
    }))
}

async fn delete_project_grant(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((_project_id, grant_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .db
        .projects()
        .delete_grant(&current_user.tenant_id, &grant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(serde_json::json!({"deleted": true})))
}
