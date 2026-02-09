//! Admin Organization Domains Routes
//!
//! API endpoints for managing and verifying organization domains.
//! All routes are prefixed with `/api/v1/admin`.

use axum::{
    extract::{Path, State},
    routing::{delete, get, patch, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::audit::{AuditAction, AuditLogger, ResourceType};
use crate::domains::models::{CreateDomainRequest, UpdateDomainRequest};
use crate::domains::service::DomainService;
use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Create admin domain routes
///
/// Routes:
/// - GET    /organizations/:org_id/domains           - List domains
/// - POST   /organizations/:org_id/domains           - Add domain
/// - DELETE /organizations/:org_id/domains/:domain_id - Remove domain
/// - POST   /organizations/:org_id/domains/:domain_id/verify       - Verify domain (any method)
/// - POST   /organizations/:org_id/domains/:domain_id/verify-dns   - Verify via DNS
/// - POST   /organizations/:org_id/domains/:domain_id/verify-html  - Verify via HTML meta
/// - POST   /organizations/:org_id/domains/:domain_id/verify-file  - Verify via file upload
/// - PATCH  /organizations/:org_id/domains/:domain_id              - Update domain settings
pub fn routes() -> Router<AppState> {
    Router::new()
        .route(
            "/organizations/:org_id/domains",
            get(list_org_domains).post(create_org_domain),
        )
        .route(
            "/organizations/:org_id/domains/:domain_id",
            delete(delete_org_domain).patch(update_org_domain),
        )
        .route(
            "/organizations/:org_id/domains/:domain_id/verify",
            post(verify_org_domain_any),
        )
        .route(
            "/organizations/:org_id/domains/:domain_id/verify-dns",
            post(verify_org_domain_dns),
        )
        .route(
            "/organizations/:org_id/domains/:domain_id/verify-html",
            post(verify_org_domain_html),
        )
        .route(
            "/organizations/:org_id/domains/:domain_id/verify-file",
            post(verify_org_domain_file),
        )
}

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
struct CreateDomainRequestBody {
    domain: String,
    #[serde(rename = "autoEnrollEnabled")]
    auto_enroll_enabled: Option<bool>,
    #[serde(rename = "defaultRole")]
    default_role: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateDomainRequestBody {
    #[serde(rename = "autoEnrollEnabled")]
    auto_enroll_enabled: Option<bool>,
    #[serde(rename = "defaultRole")]
    default_role: Option<String>,
}

#[derive(Debug, Serialize)]
struct DomainListResponse {
    data: Vec<crate::domains::models::DomainResponse>,
}

#[derive(Debug, Serialize)]
struct VerificationResponse {
    success: bool,
    #[serde(rename = "verificationMethod")]
    method: String,
    message: String,
    #[serde(rename = "recordsFound")]
    records_found: Option<Vec<String>>,
}

impl From<crate::domains::verification::VerificationResult> for VerificationResponse {
    fn from(result: crate::domains::verification::VerificationResult) -> Self {
        Self {
            success: result.success,
            method: result.method.as_str().to_string(),
            message: result.message,
            records_found: result.records_found,
        }
    }
}

// ============ Handlers ============

/// List all domains for an organization
async fn list_org_domains(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
) -> Result<Json<DomainListResponse>, ApiError> {
    // Set tenant context
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Initialize domain service
    let domain_service = DomainService::new(state.db.pool().clone().into())
        .await
        .map_err(|_| ApiError::Internal)?;

    // Fetch domains
    let domains = domain_service
        .list_domains(&current_user.tenant_id, &org_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to list domains: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(DomainListResponse { data: domains }))
}

/// Create a new domain for an organization
async fn create_org_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(org_id): Path<String>,
    Json(req): Json<CreateDomainRequestBody>,
) -> Result<Json<crate::domains::models::DomainResponse>, ApiError> {
    // Set tenant context
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Initialize domain service
    let domain_service = DomainService::new(state.db.pool().clone().into())
        .await
        .map_err(|_| ApiError::Internal)?;

    // Create domain
    let create_request = CreateDomainRequest {
        domain: req.domain,
        auto_enroll_enabled: req.auto_enroll_enabled,
        default_role: req.default_role,
    };

    let domain = domain_service
        .create_domain(&current_user.tenant_id, &org_id, create_request)
        .await
        .map_err(|e| {
            tracing::error!("Failed to create domain: {}", e);
            if e.to_string().contains("already registered") {
                ApiError::Conflict(e.to_string())
            } else if e.to_string().contains("Invalid domain") {
                ApiError::Validation(e.to_string())
            } else {
                ApiError::Internal
            }
        })?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::DomainCreated,
        ResourceType::Domain,
        &domain.id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "domain_id": domain.id,
            "domain": domain.domain,
            "organization_id": org_id,
        })),
    );

    Ok(Json(domain))
}

/// Delete a domain from an organization
async fn delete_org_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((org_id, domain_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Set tenant context
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Initialize domain service
    let domain_service = DomainService::new(state.db.pool().clone().into())
        .await
        .map_err(|_| ApiError::Internal)?;

    // Delete domain
    domain_service
        .delete_domain(&current_user.tenant_id, &org_id, &domain_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete domain: {}", e);
            if e.to_string().contains("does not belong") {
                ApiError::Forbidden
            } else {
                ApiError::Internal
            }
        })?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::DomainDeleted,
        ResourceType::Domain,
        &domain_id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "domain_id": domain_id,
            "organization_id": org_id,
        })),
    );

    Ok(Json(serde_json::json!({
        "message": "Domain deleted successfully"
    })))
}

/// Update domain settings
async fn update_org_domain(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((org_id, domain_id)): Path<(String, String)>,
    Json(req): Json<UpdateDomainRequestBody>,
) -> Result<Json<crate::domains::models::DomainResponse>, ApiError> {
    // Set tenant context
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Initialize domain service
    let domain_service = DomainService::new(state.db.pool().clone().into())
        .await
        .map_err(|_| ApiError::Internal)?;

    // Update domain
    let update_request = UpdateDomainRequest {
        auto_enroll_enabled: req.auto_enroll_enabled,
        default_role: req.default_role,
    };

    let domain = domain_service
        .update_domain(&current_user.tenant_id, &org_id, &domain_id, update_request)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update domain: {}", e);
            if e.to_string().contains("does not belong") {
                ApiError::Forbidden
            } else {
                ApiError::Internal
            }
        })?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    audit.log(
        &current_user.tenant_id,
        AuditAction::DomainUpdated,
        ResourceType::Domain,
        &domain_id,
        Some(current_user.user_id.clone()),
        None,
        None,
        true,
        None,
        Some(serde_json::json!({
            "domain_id": domain_id,
            "organization_id": org_id,
            "auto_enroll_enabled": domain.auto_enroll_enabled,
            "default_role": domain.default_role,
        })),
    );

    Ok(Json(domain))
}

/// Verify domain using any available method
async fn verify_org_domain_any(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((org_id, domain_id)): Path<(String, String)>,
) -> Result<Json<VerificationResponse>, ApiError> {
    verify_domain_with_method(
        state,
        current_user,
        org_id,
        domain_id,
        VerificationMethod::Any,
    )
    .await
}

/// Verify domain via DNS TXT record
async fn verify_org_domain_dns(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((org_id, domain_id)): Path<(String, String)>,
) -> Result<Json<VerificationResponse>, ApiError> {
    verify_domain_with_method(
        state,
        current_user,
        org_id,
        domain_id,
        VerificationMethod::Dns,
    )
    .await
}

/// Verify domain via HTML meta tag
async fn verify_org_domain_html(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((org_id, domain_id)): Path<(String, String)>,
) -> Result<Json<VerificationResponse>, ApiError> {
    verify_domain_with_method(
        state,
        current_user,
        org_id,
        domain_id,
        VerificationMethod::Html,
    )
    .await
}

/// Verify domain via file upload
async fn verify_org_domain_file(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path((org_id, domain_id)): Path<(String, String)>,
) -> Result<Json<VerificationResponse>, ApiError> {
    verify_domain_with_method(
        state,
        current_user,
        org_id,
        domain_id,
        VerificationMethod::File,
    )
    .await
}

/// Verification methods
#[derive(Debug, Clone, Copy)]
enum VerificationMethod {
    Any,
    Dns,
    Html,
    File,
}

/// Generic domain verification handler
async fn verify_domain_with_method(
    state: AppState,
    current_user: CurrentUser,
    org_id: String,
    domain_id: String,
    method: VerificationMethod,
) -> Result<Json<VerificationResponse>, ApiError> {
    // Set tenant context
    state
        .set_tenant_context(&current_user.tenant_id)
        .await
        .map_err(|_| ApiError::Internal)?;

    // Initialize domain service
    let domain_service = DomainService::new(state.db.pool().clone().into())
        .await
        .map_err(|_| ApiError::Internal)?;

    // Perform verification
    let result = match method {
        VerificationMethod::Any => {
            domain_service
                .verify_domain_any(&current_user.tenant_id, &org_id, &domain_id)
                .await
        }
        VerificationMethod::Dns => {
            domain_service
                .verify_domain_dns(&current_user.tenant_id, &org_id, &domain_id)
                .await
        }
        VerificationMethod::Html => {
            domain_service
                .verify_domain_html(&current_user.tenant_id, &org_id, &domain_id)
                .await
        }
        VerificationMethod::File => {
            domain_service
                .verify_domain_file(&current_user.tenant_id, &org_id, &domain_id)
                .await
        }
    };

    let result = result.map_err(|e| {
        tracing::error!("Failed to verify domain: {}", e);
        if e.to_string().contains("not found") {
            ApiError::NotFound
        } else if e.to_string().contains("does not belong") {
            ApiError::Forbidden
        } else {
            ApiError::Internal
        }
    })?;

    // Log the action
    let audit = AuditLogger::new(state.db.clone());
    let action = if result.success {
        AuditAction::DomainVerified
    } else {
        AuditAction::DomainVerificationFailed
    };

    audit.log(
        &current_user.tenant_id,
        action,
        ResourceType::Domain,
        &domain_id,
        Some(current_user.user_id.clone()),
        None,
        None,
        result.success,
        if result.success {
            None
        } else {
            Some(result.message.clone())
        },
        Some(serde_json::json!({
            "domain_id": domain_id,
            "organization_id": org_id,
            "method": result.method.as_str(),
            "records_found": result.records_found,
        })),
    );

    // Trigger webhook if verification succeeded
    if result.success {
        if let Ok(Some(domain)) = domain_service
            .get_domain(&current_user.tenant_id, &domain_id)
            .await
        {
            crate::domains::service::webhook_events_ext::trigger_domain_verified(
                &state,
                &current_user.tenant_id,
                &domain_id,
                &domain.domain,
                &org_id,
                result.method.as_str(),
            )
            .await;
        }
    }

    Ok(Json(result.into()))
}
