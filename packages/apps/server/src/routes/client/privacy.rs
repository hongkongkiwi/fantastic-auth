//! Privacy & Data Management Routes
//!
//! GDPR compliance endpoints for data export, account deletion,
//! and consent management.

use axum::{
    extract::{Extension, Path, State},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::routes::ApiError;
use crate::state::{AppState, CurrentUser};

/// Data export request
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DataExportRequest {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "requestedAt")]
    pub requested_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
    pub status: String,
    #[serde(rename = "downloadUrl")]
    pub download_url: Option<String>,
    #[serde(rename = "dataCategories")]
    pub data_categories: Vec<String>,
}

/// Create export request
#[derive(Debug, Deserialize)]
pub struct CreateExportRequest {
    #[serde(rename = "dataCategories")]
    pub data_categories: Option<Vec<String>>,
    #[serde(rename = "format")]
    pub format: Option<String>,
}

/// Export response
#[derive(Debug, Serialize)]
pub struct ExportResponse {
    pub success: bool,
    pub message: String,
    pub export: Option<DataExportRequest>,
}

/// Account deletion request
#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    #[serde(rename = "confirmationText")]
    pub confirmation_text: String,
    pub reason: Option<String>,
    #[serde(rename = "feedback")]
    pub feedback: Option<String>,
}

/// Deletion response
#[derive(Debug, Serialize)]
pub struct DeletionResponse {
    pub success: bool,
    pub message: String,
    #[serde(rename = "scheduledAt")]
    pub scheduled_at: DateTime<Utc>,
    #[serde(rename = "gracePeriodDays")]
    pub grace_period_days: i32,
}

/// Consent record
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ConsentRecord {
    pub id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "consentType")]
    pub consent_type: String,
    pub granted: bool,
    #[serde(rename = "grantedAt")]
    pub granted_at: Option<DateTime<Utc>>,
    #[serde(rename = "withdrawnAt")]
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub version: String,
}

/// Update consent request
#[derive(Debug, Deserialize)]
pub struct UpdateConsentRequest {
    pub granted: bool,
}

/// Consent response
#[derive(Debug, Serialize)]
pub struct ConsentResponse {
    pub success: bool,
    pub consents: Vec<ConsentRecord>,
}

/// Privacy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacySettings {
    #[serde(rename = "profileVisibility")]
    pub profile_visibility: String,
    #[serde(rename = "activityTracking")]
    pub activity_tracking: bool,
    #[serde(rename = "analyticsConsent")]
    pub analytics_consent: bool,
    #[serde(rename = "marketingConsent")]
    pub marketing_consent: bool,
    #[serde(rename = "thirdPartySharing")]
    pub third_party_sharing: bool,
}

/// Create privacy routes
pub fn routes() -> Router<AppState> {
    Router::new()
        // Data export
        .route("/me/privacy/exports", get(list_my_exports).post(request_my_export))
        .route("/me/privacy/exports/:export_id", get(get_my_export_status))
        // Account deletion
        .route("/me/privacy/account", delete(delete_my_account))
        // Consent management
        .route("/me/privacy/consents", get(list_my_consents))
        .route("/me/privacy/consents/:consent_type", post(update_my_consent))
        // Privacy settings
        .route("/me/privacy/settings", get(get_my_privacy_settings).put(update_my_privacy_settings))
}

/// List data exports for current user
async fn list_my_exports(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<Vec<DataExportRequest>>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    let exports: Vec<DataExportRequest> = sqlx::query_as::<_, DataExportRequest>(
        r#"
        SELECT 
            e.id::text as id,
            e.user_id::text as user_id,
            e.requested_at,
            e.expires_at,
            e.status,
            e.download_url,
            e.data_categories
        FROM privacy_exports e
        WHERE e.user_id = $1
        ORDER BY e.requested_at DESC
        "#
    )
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    Ok(Json(exports))
}

/// Request a new data export
async fn request_my_export(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<CreateExportRequest>,
) -> Result<Json<ExportResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    let export_id = Uuid::new_v4();
    let data_categories = req.data_categories.unwrap_or_else(|| {
        vec![
            "profile".to_string(),
            "sessions".to_string(),
            "devices".to_string(),
            "consents".to_string(),
        ]
    });

    // Insert export request with pending status
    let export: DataExportRequest = sqlx::query_as::<_, DataExportRequest>(
        r#"
        INSERT INTO privacy_exports (
            id, user_id, data_categories, status, 
            requested_at, expires_at
        ) VALUES ($1, $2, $3, 'pending', NOW(), NOW() + INTERVAL '30 days')
        RETURNING 
            id::text as id,
            user_id::text as user_id,
            requested_at,
            expires_at,
            status,
            download_url,
            data_categories
        "#
    )
    .bind(export_id)
    .bind(user_id)
    .bind(&data_categories)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    // In a real implementation, this would trigger a background job
    // to generate the export file

    Ok(Json(ExportResponse {
        success: true,
        message: "Data export requested. You will receive an email when it's ready.".to_string(),
        export: Some(export),
    }))
}

/// Get export status
async fn get_my_export_status(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(export_id): Path<Uuid>,
) -> Result<Json<DataExportRequest>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    let export: DataExportRequest = sqlx::query_as::<_, DataExportRequest>(
        r#"
        SELECT 
            e.id::text as id,
            e.user_id::text as user_id,
            e.requested_at,
            e.expires_at,
            e.status,
            e.download_url,
            e.data_categories
        FROM privacy_exports e
        WHERE e.id = $1 AND e.user_id = $2
        "#
    )
    .bind(export_id)
    .bind(user_id)
    .fetch_one(state.db.pool())
    .await
    .map_err(|_| ApiError::not_found("Export not found"))?;

    Ok(Json(export))
}

/// Request account deletion
/// 
/// This operation is performed within a database transaction to ensure
/// atomicity - either both the deletion request is recorded AND sessions
/// are revoked, or neither happens.
async fn delete_my_account(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Json(req): Json<DeleteAccountRequest>,
) -> Result<Json<DeletionResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    // Verify confirmation text
    if req.confirmation_text != "DELETE MY ACCOUNT" {
        return Err(ApiError::bad_request("Invalid confirmation text"));
    }

    // Schedule account for deletion (30-day grace period)
    let scheduled_at = Utc::now();
    const GRACE_PERIOD_DAYS: i64 = 30;

    // Start a database transaction for atomicity
    let mut tx = state.db.pool()
        .begin()
        .await
        .map_err(|e| ApiError::internal_error(format!("Failed to start transaction: {}", e)))?;

    // Insert deletion request
    let deletion_result = sqlx::query(
        r#"
        INSERT INTO deletion_requests (
            user_id, reason, feedback, 
            requested_at, scheduled_deletion_at, status
        ) VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '30 days', 'pending')
        ON CONFLICT (user_id) DO UPDATE SET
            status = 'pending',
            requested_at = NOW(),
            scheduled_deletion_at = NOW() + INTERVAL '30 days'
        "#
    )
    .bind(user_id)
    .bind(&req.reason)
    .bind(&req.feedback)
    .execute(&mut *tx)
    .await;

    if let Err(e) = deletion_result {
        if let Err(rollback_err) = tx.rollback().await {
            tracing::error!("Transaction rollback failed after deletion error: {}", rollback_err);
        }
        return Err(ApiError::internal_error(format!("Failed to record deletion request: {}", e)));
    }

    // Revoke all active sessions
    let session_result = sqlx::query(
        r#"
        UPDATE user_sessions 
        SET status = 'revoked', revoked_at = NOW()
        WHERE user_id = $1 AND status = 'active'
        "#
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await;

    if let Err(e) = session_result {
        if let Err(rollback_err) = tx.rollback().await {
            tracing::error!("Transaction rollback failed after session revoke error: {}", rollback_err);
        }
        return Err(ApiError::internal_error(format!("Failed to revoke sessions: {}", e)));
    }

    // Commit the transaction
    if let Err(e) = tx.commit().await {
        return Err(ApiError::internal_error(format!("Failed to commit transaction: {}", e)));
    }

    Ok(Json(DeletionResponse {
        success: true,
        message: format!("Account scheduled for deletion in {} days. You can cancel this during the grace period.", GRACE_PERIOD_DAYS),
        scheduled_at,
        grace_period_days: GRACE_PERIOD_DAYS as i32,
    }))
}

/// List consent records for current user
async fn list_my_consents(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<ConsentResponse>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    let consents: Vec<ConsentRecord> = sqlx::query_as::<_, ConsentRecord>(
        r#"
        SELECT 
            c.id::text as id,
            c.user_id::text as user_id,
            c.consent_type,
            c.granted,
            c.granted_at,
            c.withdrawn_at,
            c.version
        FROM consent_records c
        WHERE c.user_id = $1
        ORDER BY c.consent_type
        "#
    )
    .bind(user_id)
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    Ok(Json(ConsentResponse {
        success: true,
        consents,
    }))
}

/// Update consent for a specific type
async fn update_my_consent(
    State(state): State<AppState>,
    Extension(current_user): Extension<CurrentUser>,
    Path(consent_type): Path<String>,
    Json(req): Json<UpdateConsentRequest>,
) -> Result<Json<ConsentRecord>, ApiError> {
    let user_id = Uuid::parse_str(&current_user.user_id)
        .map_err(|_| ApiError::bad_request("Invalid user ID"))?;

    let consent_id = Uuid::new_v4();
    let now = Utc::now();

    let consent: ConsentRecord = sqlx::query_as::<_, ConsentRecord>(
        r#"
        INSERT INTO consent_records (
            id, user_id, consent_type, granted,
            granted_at, withdrawn_at, version, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, '1.0', $7)
        ON CONFLICT (user_id, consent_type) DO UPDATE SET
            granted = $4,
            granted_at = $5,
            withdrawn_at = $6,
            updated_at = $7
        RETURNING 
            id::text as id,
            user_id::text as user_id,
            consent_type,
            granted,
            granted_at,
            withdrawn_at,
            version
        "#
    )
    .bind(consent_id)
    .bind(user_id)
    .bind(&consent_type)
    .bind(req.granted)
    .bind(if req.granted { Some(now) } else { None })
    .bind(if !req.granted { Some(now) } else { None })
    .bind(now)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::internal_error(format!("Database error: {}", e)))?;

    Ok(Json(consent))
}

/// Get privacy settings for current user
async fn get_my_privacy_settings(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
) -> Result<Json<PrivacySettings>, ApiError> {
    // Return default settings (can be stored in database later)
    Ok(Json(PrivacySettings {
        profile_visibility: "private".to_string(),
        activity_tracking: false,
        analytics_consent: false,
        marketing_consent: false,
        third_party_sharing: false,
    }))
}

/// Update privacy settings
async fn update_my_privacy_settings(
    State(_state): State<AppState>,
    Extension(_current_user): Extension<CurrentUser>,
    Json(settings): Json<PrivacySettings>,
) -> Result<Json<PrivacySettings>, ApiError> {
    // Validate settings
    let valid_visibilities = ["public", "private", "friends"];
    if !valid_visibilities.contains(&settings.profile_visibility.as_str()) {
        return Err(ApiError::bad_request("Invalid profile visibility"));
    }

    // Return the settings (can be stored in database later)
    Ok(Json(settings))
}
