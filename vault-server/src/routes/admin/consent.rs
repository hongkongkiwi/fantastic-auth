//! Admin Consent Routes
//!
//! Administrative endpoints for consent management:
//! - GET /api/v1/admin/consents - List consent policies
//! - POST /api/v1/admin/consents - Create new policy version
//! - PUT /api/v1/admin/consents/:id - Update policy
//! - GET /api/v1/admin/consents/:id/stats - Consent statistics
//! - GET /api/v1/admin/consents/export/pending - List pending exports
//! - GET /api/v1/admin/consents/deletion/pending - List pending deletions

use axum::{
    extract::{Path, Query, State},
    routing::{get, post, put},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::{
    consent::{
        ConsentService, ConsentType, ConsentVersion, CreateConsentVersionRequest,
        DataExportStatus, DeletionStatus, UpdateConsentVersionRequest,
        service::{
            ConsentRequirementResponse, ConsentVersionResponse, ListConsentVersionsResponse,
        },
    },
    routes::ApiError,
    state::{AppState, CurrentUser},
};

/// Create admin consent routes
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/consents", get(list_consent_versions))
        .route("/consents", post(create_consent_version))
        .route("/consents/:id", put(update_consent_version))
        .route("/consents/:id/stats", get(get_consent_statistics))
        .route("/consents/types/:consent_type/stats", get(get_all_statistics))
        .route("/consents/export/pending", get(list_pending_exports))
        .route("/consents/deletion/pending", get(list_pending_deletions))
        .route("/consents/templates", get(list_templates))
        .route("/consents/templates/:template_key", get(get_template))
        .route("/consents/templates/:template_key/render", post(render_template))
}

// ============ Query Parameters ============

#[derive(Debug, Deserialize)]
struct ListConsentQuery {
    #[serde(rename = "consentType")]
    consent_type: Option<String>,
    page: Option<i64>,
    #[serde(rename = "perPage")]
    per_page: Option<i64>,
}

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
struct CreateConsentVersionBody {
    #[serde(rename = "consentType")]
    consent_type: String,
    version: String,
    title: String,
    content: String,
    summary: Option<String>,
    #[serde(rename = "effectiveDate")]
    effective_date: chrono::DateTime<chrono::Utc>,
    url: Option<String>,
    #[serde(rename = "makeCurrent")]
    make_current: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct UpdateConsentVersionBody {
    title: Option<String>,
    content: Option<String>,
    summary: Option<String>,
    url: Option<String>,
    #[serde(rename = "makeCurrent")]
    make_current: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ConsentStatisticsResponse {
    #[serde(rename = "consentType")]
    consent_type: String,
    version: String,
    #[serde(rename = "totalUsers")]
    total_users: i64,
    #[serde(rename = "grantedCount")]
    granted_count: i64,
    #[serde(rename = "withdrawnCount")]
    withdrawn_count: i64,
    #[serde(rename = "pendingCount")]
    pending_count: i64,
    #[serde(rename = "consentRate")]
    consent_rate: f64,
}

#[derive(Debug, Serialize)]
struct ListStatisticsResponse {
    statistics: Vec<ConsentStatisticsResponse>,
}

#[derive(Debug, Serialize)]
struct DataExportListItem {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub status: DataExportStatus,
    #[serde(rename = "requestedAt")]
    pub requested_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "completedAt")]
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
struct DeletionRequestListItem {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub status: DeletionStatus,
    #[serde(rename = "requestedAt")]
    pub requested_at: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "scheduledDeletionAt")]
    pub scheduled_deletion_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
struct TemplatesListResponse {
    templates: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TemplateResponse {
    pub key: String,
    pub schema: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct RenderTemplateBody {
    pub values: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct RenderTemplateResponse {
    pub rendered: String,
}

// ============ Handlers ============

/// GET /api/v1/admin/consents
/// List consent policies/versions
async fn list_consent_versions(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Query(query): Query<ListConsentQuery>,
) -> Result<Json<ListConsentVersionsResponse>, ApiError> {
    let consent_type = query
        .consent_type
        .map(|t| t.parse::<ConsentType>())
        .transpose()
        .map_err(|e| ApiError::Validation(format!("Invalid consent type: {}", e)))?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);

    let consent_service = create_consent_service(&state).await?;

    let response = consent_service
        .list_consent_versions(&user.tenant_id, consent_type, page, per_page)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list consent versions: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(response))
}

/// POST /api/v1/admin/consents
/// Create new policy version
async fn create_consent_version(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(body): Json<CreateConsentVersionBody>,
) -> Result<Json<ConsentVersionResponse>, ApiError> {
    // Parse consent type
    let consent_type = body
        .consent_type
        .parse::<ConsentType>()
        .map_err(|e| ApiError::Validation(format!("Invalid consent type: {}", e)))?;

    let consent_service = create_consent_service(&state).await?;

    let request = CreateConsentVersionRequest {
        consent_type,
        version: body.version,
        title: body.title,
        content: body.content,
        summary: body.summary,
        effective_date: body.effective_date,
        url: body.url,
        make_current: body.make_current.unwrap_or(false),
    };

    let response = consent_service
        .create_consent_version(&user.tenant_id, request)
        .await
        .map_err(|e| match e {
            super::ConsentError::InvalidVersionFormat(v) => {
                ApiError::Validation(format!("Invalid version format: {}", v))
            }
            _ => {
                tracing::error!("Failed to create consent version: {}", e);
                ApiError::Internal
            }
        })?;

    // Log the action
    crate::audit::log_admin_event(
        &state,
        &user.tenant_id,
        &user.user_id,
        "consent_version_created",
        &response.id,
        &serde_json::json!({
            "consent_type": response.consent_type,
            "version": response.version,
        }),
    )
    .await;

    Ok(Json(response))
}

/// PUT /api/v1/admin/consents/:id
/// Update policy version
async fn update_consent_version(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(version_id): Path<String>,
    Json(body): Json<UpdateConsentVersionBody>,
) -> Result<Json<ConsentVersionResponse>, ApiError> {
    let consent_service = create_consent_service(&state).await?;

    let request = UpdateConsentVersionRequest {
        title: body.title,
        content: body.content,
        summary: body.summary,
        url: body.url,
        make_current: body.make_current,
    };

    let response = consent_service
        .update_consent_version(&version_id, request)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update consent version: {}", e);
            ApiError::Internal
        })?;

    // Log the action
    crate::audit::log_admin_event(
        &state,
        &user.tenant_id,
        &user.user_id,
        "consent_version_updated",
        &version_id,
        &serde_json::json!({
            "consent_type": response.consent_type,
            "version": response.version,
        }),
    )
    .await;

    Ok(Json(response))
}

/// GET /api/v1/admin/consents/:id/stats
/// Get consent statistics for a specific version
async fn get_consent_statistics(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(version_id): Path<String>,
) -> Result<Json<ConsentStatisticsResponse>, ApiError> {
    let consent_service = create_consent_service(&state).await?;

    let stats = consent_service
        .get_consent_statistics(&user.tenant_id, &version_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get consent statistics: {}", e);
            ApiError::Internal
        })?;

    match stats {
        Some(s) => Ok(Json(ConsentStatisticsResponse {
            consent_type: s.consent_type.to_string(),
            version: s.version,
            total_users: s.total_users,
            granted_count: s.granted_count,
            withdrawn_count: s.withdrawn_count,
            pending_count: s.pending_count,
            consent_rate: s.consent_rate,
        })),
        None => Err(ApiError::NotFound),
    }
}

/// GET /api/v1/admin/consents/types/:consent_type/stats
/// Get statistics for all versions of a consent type
async fn get_all_statistics(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(consent_type_str): Path<String>,
) -> Result<Json<ListStatisticsResponse>, ApiError> {
    let consent_type = consent_type_str
        .parse::<ConsentType>()
        .map_err(|e| ApiError::Validation(format!("Invalid consent type: {}", e)))?;

    let consent_service = create_consent_service(&state).await?;

    let stats = consent_service
        .get_all_statistics(&user.tenant_id, consent_type)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get consent statistics: {}", e);
            ApiError::Internal
        })?;

    let responses: Vec<ConsentStatisticsResponse> = stats
        .into_iter()
        .map(|s| ConsentStatisticsResponse {
            consent_type: s.consent_type.to_string(),
            version: s.version,
            total_users: s.total_users,
            granted_count: s.granted_count,
            withdrawn_count: s.withdrawn_count,
            pending_count: s.pending_count,
            consent_rate: s.consent_rate,
        })
        .collect();

    Ok(Json(ListStatisticsResponse {
        statistics: responses,
    }))
}

/// GET /api/v1/admin/consents/export/pending
/// List pending data export requests
async fn list_pending_exports(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<Vec<DataExportListItem>>, ApiError> {
    let repository = crate::consent::ConsentRepository::new(state.db.pool().clone());

    let exports = repository
        .get_pending_exports()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get pending exports: {}", e);
            ApiError::Internal
        })?;

    let items: Vec<DataExportListItem> = exports
        .into_iter()
        .map(|e| DataExportListItem {
            id: e.id,
            user_id: e.user_id,
            status: e.status,
            requested_at: e.requested_at,
            completed_at: e.completed_at,
        })
        .collect();

    Ok(Json(items))
}

/// GET /api/v1/admin/consents/deletion/pending
/// List pending deletion requests
async fn list_pending_deletions(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<Vec<DeletionRequestListItem>>, ApiError> {
    let repository = crate::consent::ConsentRepository::new(state.db.pool().clone());

    let deletions = repository
        .get_pending_deletions()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get pending deletions: {}", e);
            ApiError::Internal
        })?;

    let items: Vec<DeletionRequestListItem> = deletions
        .into_iter()
        .map(|d| DeletionRequestListItem {
            id: d.id,
            user_id: d.user_id,
            status: d.status,
            requested_at: d.requested_at,
            scheduled_deletion_at: d.scheduled_deletion_at,
        })
        .collect();

    Ok(Json(items))
}

/// GET /api/v1/admin/consents/templates
/// List available templates
async fn list_templates() -> Result<Json<TemplatesListResponse>, ApiError> {
    let templates = crate::consent::get_available_templates();

    Ok(Json(TemplatesListResponse { templates }))
}

/// GET /api/v1/admin/consents/templates/:template_key
/// Get template schema
async fn get_template(
    Path(template_key): Path<String>,
) -> Result<Json<TemplateResponse>, ApiError> {
    let schema = crate::consent::get_template_schema(&template_key);

    Ok(Json(TemplateResponse {
        key: template_key,
        schema,
    }))
}

/// POST /api/v1/admin/consents/templates/:template_key/render
/// Render a template with values
async fn render_template(
    Path(template_key): Path<String>,
    Json(body): Json<RenderTemplateBody>,
) -> Result<Json<RenderTemplateResponse>, ApiError> {
    let rendered = crate::consent::render_template(&template_key, &body.values)
        .map_err(|e| ApiError::BadRequest(format!("Template rendering failed: {}", e)))?;

    Ok(Json(RenderTemplateResponse { rendered }))
}

// ============ Helpers ============

/// Create consent service from app state
async fn create_consent_service(state: &AppState) -> Result<ConsentService, ApiError> {
    let repository = crate::consent::ConsentRepository::new(state.db.pool().clone());
    let config = crate::consent::ConsentConfig::default();
    let manager = crate::consent::ConsentManager::new(repository, config);

    Ok(ConsentService::new(manager))
}

// Extension trait for audit logging
mod audit_ext {
    use super::*;

    pub async fn log_admin_event(
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        action: &str,
        resource_id: &str,
        details: &serde_json::Value,
    ) {
        let audit = crate::audit::AuditLogger::new(state.db.clone());
        audit
            .log(
                tenant_id,
                crate::audit::AuditAction::from(action),
                crate::audit::ResourceType::Consent,
                resource_id,
                Some(user_id),
                None,
                None,
                true,
                None,
                Some(details.clone()),
            )
            .await;
    }
}

use audit_ext::*;

// Import consent module
use crate::consent;
