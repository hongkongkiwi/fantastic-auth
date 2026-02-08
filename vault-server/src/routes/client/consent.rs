//! Client Consent Routes
//!
//! Endpoints for user consent management:
//! - GET /api/v1/consents - Get current consent requirements
//! - POST /api/v1/consents - Submit consent
//! - GET /api/v1/users/me/consents - Get user's consent history
//! - POST /api/v1/users/me/consents/:type/withdraw - Withdraw consent
//! - GET /api/v1/consents/export - Export my data (GDPR)
//! - POST /api/v1/users/me/delete - Request account deletion (GDPR)

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::{
    consent::{
        ConsentContext, ConsentService, ConsentType, RequestDeletionRequest,
        SubmitConsentRequest, service::{
            ConsentRequirementResponse, DataExportResponse, DataExportStatusResponse,
            DeletionResponse, DeletionStatusResponse, UserConsentsResponse,
        },
    },
    routes::ApiError,
    state::AppState,
};
use crate::state::CurrentUser;

/// Create client consent routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // Public endpoints
        .route("/consents", get(get_consent_requirements))
        // Authenticated endpoints
        .route("/consents", post(submit_consent))
        .route("/users/me/consents", get(get_my_consents))
        .route("/users/me/consents/:consent_type/withdraw", post(withdraw_consent))
        .route("/consents/export", get(request_data_export))
        .route("/consents/export/:export_id", get(get_export_status))
        .route("/users/me/delete", post(request_account_deletion))
        .route("/users/me/delete/cancel", post(cancel_deletion))
        .route("/users/me/delete/status", get(get_deletion_status))
}

// ============ Request/Response Types ============

#[derive(Debug, Deserialize)]
struct SubmitConsentRequestBody {
    #[serde(rename = "consentType")]
    consent_type: String,
    granted: bool,
    #[serde(rename = "versionId")]
    version_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct SubmitConsentResponse {
    success: bool,
    message: String,
    #[serde(rename = "consentType")]
    consent_type: String,
    granted: bool,
}

#[derive(Debug, Serialize)]
struct WithdrawConsentResponse {
    success: bool,
    message: String,
    #[serde(rename = "consentType")]
    consent_type: String,
}

#[derive(Debug, Serialize)]
struct ConsentRequirementsResponse {
    #[serde(rename = "requiredConsents")]
    required_consents: Vec<ConsentRequirementResponse>,
}

#[derive(Debug, Deserialize)]
struct CancelDeletionRequestBody {
    token: String,
}

#[derive(Debug, Serialize)]
struct CancelDeletionResponse {
    success: bool,
    message: String,
}

// ============ Handlers ============

/// GET /api/v1/consents
/// Get current consent requirements (public endpoint)
async fn get_consent_requirements(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ConsentRequirementsResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&headers);

    let consent_service = create_consent_service(&state).await?;

    let requirements = consent_service
        .get_consent_requirements(&tenant_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get consent requirements: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(ConsentRequirementsResponse {
        required_consents: requirements,
    }))
}

/// POST /api/v1/consents
/// Submit consent (authenticated)
async fn submit_consent(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SubmitConsentRequestBody>,
) -> Result<Json<SubmitConsentResponse>, ApiError> {
    // Parse consent type
    let consent_type = body
        .consent_type
        .parse::<ConsentType>()
        .map_err(|e| ApiError::Validation(format!("Invalid consent type: {}", e)))?;

    let consent_service = create_consent_service(&state).await?;

    // Build consent context from request
    let context = build_consent_context(&headers);

    let request = SubmitConsentRequest {
        consent_type,
        granted: body.granted,
        version_id: body.version_id,
    };

    let record = consent_service
        .manager()
        .submit_consent(&user.user_id, request, context)
        .await
        .map_err(|e| match e {
            super::ConsentError::CannotWithdrawRequired(_) => {
                ApiError::BadRequest("Cannot withdraw required consent".to_string())
            }
            super::ConsentError::VersionNotFound(msg) => ApiError::NotFound,
            _ => {
                tracing::error!("Failed to submit consent: {}", e);
                ApiError::Internal
            }
        })?;

    // Log the consent action
    crate::audit::log_action(
        &state,
        &user.tenant_id,
        &user.user_id,
        "consent_submitted",
        &record.id,
        true,
    )
    .await;

    Ok(Json(SubmitConsentResponse {
        success: true,
        message: if record.granted {
            format!("Consent granted for {}", consent_type.display_name())
        } else {
            format!("Consent declined for {}", consent_type.display_name())
        },
        consent_type: body.consent_type,
        granted: record.granted,
    }))
}

/// GET /api/v1/users/me/consents
/// Get user's consent history and status
async fn get_my_consents(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<UserConsentsResponse>, ApiError> {
    let consent_service = create_consent_service(&state).await?;

    let response = consent_service
        .get_user_consents(&user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user consents: {}", e);
            ApiError::Internal
        })?;

    Ok(Json(response))
}

/// POST /api/v1/users/me/consents/:consent_type/withdraw
/// Withdraw consent
async fn withdraw_consent(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(consent_type_str): Path<String>,
) -> Result<Json<WithdrawConsentResponse>, ApiError> {
    // Parse consent type
    let consent_type = consent_type_str
        .parse::<ConsentType>()
        .map_err(|e| ApiError::Validation(format!("Invalid consent type: {}", e)))?;

    let consent_service = create_consent_service(&state).await?;

    let record = consent_service
        .withdraw_consent(&user.user_id, consent_type)
        .await
        .map_err(|e| match e {
            super::ConsentError::CannotWithdrawRequired(_) => {
                ApiError::BadRequest("Cannot withdraw required consent".to_string())
            }
            _ => {
                tracing::error!("Failed to withdraw consent: {}", e);
                ApiError::Internal
            }
        })?;

    // Log the withdrawal
    crate::audit::log_action(
        &state,
        &user.tenant_id,
        &user.user_id,
        "consent_withdrawn",
        &record.id,
        true,
    )
    .await;

    Ok(Json(WithdrawConsentResponse {
        success: true,
        message: format!("Consent withdrawn for {}", consent_type.display_name()),
        consent_type: consent_type_str,
    }))
}

/// GET /api/v1/consents/export
/// Request data export (GDPR Article 20)
async fn request_data_export(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<DataExportResponse>, ApiError> {
    let consent_service = create_consent_service(&state).await?;

    let response = consent_service
        .request_data_export(&user.user_id)
        .await
        .map_err(|e| match e {
            super::ConsentError::Internal(msg) if msg.contains("already in progress") => {
                ApiError::Conflict("Export already in progress".to_string())
            }
            _ => {
                tracing::error!("Failed to request data export: {}", e);
                ApiError::Internal
            }
        })?;

    // Log the export request
    crate::audit::log_action(
        &state,
        &user.tenant_id,
        &user.user_id,
        "data_export_requested",
        &response.id,
        true,
    )
    .await;

    Ok(Json(response))
}

/// GET /api/v1/consents/export/:export_id
/// Get export status
async fn get_export_status(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Path(export_id): Path<String>,
) -> Result<Json<DataExportStatusResponse>, ApiError> {
    let consent_service = create_consent_service(&state).await?;

    let status = consent_service
        .get_export_status(&export_id, &user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get export status: {}", e);
            ApiError::Internal
        })?;

    match status {
        Some(s) => Ok(Json(s)),
        None => Err(ApiError::NotFound),
    }
}

/// POST /api/v1/users/me/delete
/// Request account deletion (GDPR Article 17)
async fn request_account_deletion(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(body): Json<RequestDeletionRequest>,
) -> Result<Json<DeletionResponse>, ApiError> {
    let consent_service = create_consent_service(&state).await?;

    let response = consent_service
        .request_account_deletion(&user.user_id, body.reason.as_deref())
        .await
        .map_err(|e| match e {
            super::ConsentError::Internal(msg) if msg.contains("already pending") => {
                ApiError::Conflict("Deletion request already pending".to_string())
            }
            _ => {
                tracing::error!("Failed to request account deletion: {}", e);
                ApiError::Internal
            }
        })?;

    // Log the deletion request
    crate::audit::log_action(
        &state,
        &user.tenant_id,
        &user.user_id,
        "deletion_requested",
        &response.id,
        true,
    )
    .await;

    // Trigger webhook for deletion request
    crate::webhooks::events::trigger_event(
        &state,
        &user.tenant_id,
        "user.deletion_requested",
        &serde_json::json!({
            "user_id": user.user_id,
            "deletion_id": response.id,
            "scheduled_deletion_at": response.scheduled_deletion_at,
        }),
    )
    .await;

    Ok(Json(response))
}

/// POST /api/v1/users/me/delete/cancel
/// Cancel deletion request
async fn cancel_deletion(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
    Json(body): Json<CancelDeletionRequestBody>,
) -> Result<Json<CancelDeletionResponse>, ApiError> {
    let consent_service = create_consent_service(&state).await?;

    consent_service
        .cancel_deletion(&user.user_id, &body.token)
        .await
        .map_err(|e| match e {
            super::ConsentError::DeletionAlreadyCancelled => {
                ApiError::BadRequest("Deletion request already cancelled".to_string())
            }
            super::ConsentError::DeletionAlreadyCompleted => {
                ApiError::BadRequest("Deletion already completed".to_string())
            }
            super::ConsentError::DeletionRequestNotFound(_) => ApiError::NotFound,
            _ => {
                tracing::error!("Failed to cancel deletion: {}", e);
                ApiError::Internal
            }
        })?;

    // Log the cancellation
    crate::audit::log_action(
        &state,
        &user.tenant_id,
        &user.user_id,
        "deletion_cancelled",
        &body.token,
        true,
    )
    .await;

    Ok(Json(CancelDeletionResponse {
        success: true,
        message: "Account deletion request has been cancelled".to_string(),
    }))
}

/// GET /api/v1/users/me/delete/status
/// Get deletion request status
async fn get_deletion_status(
    State(state): State<AppState>,
    Extension(user): Extension<CurrentUser>,
) -> Result<Json<DeletionStatusResponse>, ApiError> {
    let consent_service = create_consent_service(&state).await?;

    let status = consent_service
        .get_deletion_status(&user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get deletion status: {}", e);
            ApiError::Internal
        })?;

    match status {
        Some(s) => Ok(Json(s)),
        None => Err(ApiError::NotFound),
    }
}

// ============ Helpers ============

/// Extract tenant ID from headers
fn extract_tenant_id(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("X-Tenant-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "default".to_string())
}

/// Build consent context from request headers
fn build_consent_context(headers: &axum::http::HeaderMap) -> ConsentContext {
    let ip_address = headers
        .get("X-Forwarded-For")
        .or_else(|| headers.get("X-Real-IP"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

    let user_agent = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Get jurisdiction from CF-IPCountry or similar header
    let jurisdiction = headers
        .get("CF-IPCountry")
        .or_else(|| headers.get("X-Country-Code"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    ConsentContext {
        ip_address,
        user_agent,
        jurisdiction,
    }
}

/// Create consent service from app state
async fn create_consent_service(state: &AppState) -> Result<ConsentService, ApiError> {
    let repository =
        crate::consent::ConsentRepository::new(state.db.pool().clone());

    let config = crate::consent::ConsentConfig::default();
    let manager = crate::consent::ConsentManager::new(repository, config);

    Ok(ConsentService::new(manager))
}

// Extension trait for audit logging
mod audit_ext {
    use super::*;

    pub async fn log_action(
        state: &AppState,
        tenant_id: &str,
        user_id: &str,
        action: &str,
        resource_id: &str,
        success: bool,
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
                success,
                None,
                None,
            )
            .await;
    }
}

use audit_ext::*;

// Import consent module for error types
use crate::consent;
