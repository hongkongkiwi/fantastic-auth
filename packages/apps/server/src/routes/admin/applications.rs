//! Admin Application Management Routes

use axum::{
    extract::{Path, Query, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};
use vault_core::models::project::{Application, ApplicationStatus, ApplicationType};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/projects/:project_id/apps",
            get(list_project_apps).post(create_project_app),
        )
        .route(
            "/apps/:app_id",
            get(get_app).patch(update_app).delete(delete_app),
        )
}

#[derive(Debug, Deserialize)]
struct ListAppsQuery {
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CreateAppRequest {
    name: String,
    #[serde(rename = "appType")]
    app_type: String,
    #[serde(rename = "orgId")]
    organization_id: String,
    settings: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct UpdateAppRequest {
    name: Option<String>,
    #[serde(rename = "appType")]
    app_type: Option<String>,
    status: Option<String>,
    settings: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct ApplicationResponse {
    id: String,
    #[serde(rename = "projectId")]
    project_id: String,
    #[serde(rename = "orgId")]
    organization_id: String,
    name: String,
    #[serde(rename = "appType")]
    app_type: String,
    status: String,
    settings: serde_json::Value,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

async fn list_project_apps(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(project_id): Path<String>,
    Query(query): Query<ListAppsQuery>,
) -> Result<Json<Vec<ApplicationResponse>>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 200);
    let offset = (page - 1) * per_page;

    let apps = state
        .db
        .applications()
        .list_by_project(&current_user.tenant_id, &project_id, per_page, offset)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(
        apps.into_iter()
            .map(|a| ApplicationResponse {
                id: a.id,
                project_id: a.project_id,
                organization_id: a.organization_id,
                name: a.name,
                app_type: format!("{:?}", a.app_type).to_lowercase(),
                status: format!("{:?}", a.status).to_lowercase(),
                settings: a.settings,
                created_at: a.created_at.to_rfc3339(),
                updated_at: a.updated_at.to_rfc3339(),
            })
            .collect(),
    ))
}

async fn create_project_app(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(project_id): Path<String>,
    Json(req): Json<CreateAppRequest>,
) -> Result<Json<ApplicationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let app_type = req.app_type.parse().unwrap_or(ApplicationType::Oidc);
    let mut app = Application::new(
        &current_user.tenant_id,
        &req.organization_id,
        &project_id,
        &req.name,
        app_type,
    );
    if let Some(settings) = req.settings {
        app.settings = settings;
    }

    let created = state
        .db
        .applications()
        .create(&app)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ApplicationResponse {
        id: created.id,
        project_id: created.project_id,
        organization_id: created.organization_id,
        name: created.name,
        app_type: format!("{:?}", created.app_type).to_lowercase(),
        status: format!("{:?}", created.status).to_lowercase(),
        settings: created.settings,
        created_at: created.created_at.to_rfc3339(),
        updated_at: created.updated_at.to_rfc3339(),
    }))
}

async fn get_app(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(app_id): Path<String>,
) -> Result<Json<ApplicationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let app = state
        .db
        .applications()
        .get_by_id(&current_user.tenant_id, &app_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(ApplicationResponse {
        id: app.id,
        project_id: app.project_id,
        organization_id: app.organization_id,
        name: app.name,
        app_type: format!("{:?}", app.app_type).to_lowercase(),
        status: format!("{:?}", app.status).to_lowercase(),
        settings: app.settings,
        created_at: app.created_at.to_rfc3339(),
        updated_at: app.updated_at.to_rfc3339(),
    }))
}

async fn update_app(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(app_id): Path<String>,
    Json(req): Json<UpdateAppRequest>,
) -> Result<Json<ApplicationResponse>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    let mut app = state
        .db
        .applications()
        .get_by_id(&current_user.tenant_id, &app_id)
        .await
        .map_err(|_| ApiError::internal())?
        .ok_or(ApiError::NotFound)?;

    if let Some(name) = req.name {
        app.name = name;
    }
    if let Some(app_type) = req.app_type {
        app.app_type = app_type.parse().unwrap_or(ApplicationType::Oidc);
    }
    if let Some(status) = req.status {
        app.status = status.parse().unwrap_or(ApplicationStatus::Active);
    }
    if let Some(settings) = req.settings {
        app.settings = settings;
    }

    let updated = state
        .db
        .applications()
        .update(&current_user.tenant_id, &app)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ApplicationResponse {
        id: updated.id,
        project_id: updated.project_id,
        organization_id: updated.organization_id,
        name: updated.name,
        app_type: format!("{:?}", updated.app_type).to_lowercase(),
        status: format!("{:?}", updated.status).to_lowercase(),
        settings: updated.settings,
        created_at: updated.created_at.to_rfc3339(),
        updated_at: updated.updated_at.to_rfc3339(),
    }))
}

async fn delete_app(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(app_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::internal())?;

    state
        .db
        .applications()
        .delete(&current_user.tenant_id, &app_id)
        .await
        .map_err(|_| ApiError::internal())?;

    Ok(Json(serde_json::json!({"deleted": true})))
}
