//! Consent Service
//!
//! Service layer for consent-related business logic including:
//! - Data export generation
//! - Account deletion processing
//! - Consent policy management

use chrono::{Duration, Utc};
use serde_json::json;
use std::{path::PathBuf, sync::Arc};

use super::{
    ConsentConfig, ConsentContext, ConsentError, ConsentManager, ConsentRepository,
    ConsentResult, ConsentType, ConsentVersion, CookieCategory, CookieConsentConfig,
    CreateConsentVersionRequest, DataExportRequest, DataExportStatus, DeletionRequest,
    DeletionStatus, ExportMetadata, PendingConsent, SubmitConsentRequest, UpdateConsentVersionRequest,
    UserConsentStatus, UserDataExport, check_consent,
};

/// Consent service for business logic
pub struct ConsentService {
    manager: ConsentManager,
}

impl ConsentService {
    /// Create a new consent service
    pub fn new(manager: ConsentManager) -> Self {
        Self { manager }
    }

    /// Get consent manager
    pub fn manager(&self) -> &ConsentManager {
        &self.manager
    }

    // ==================== User Operations ====================

    /// Get current consent requirements for a tenant
    pub async fn get_consent_requirements(
        &self,
        tenant_id: &str,
    ) -> ConsentResult<Vec<ConsentRequirementResponse>> {
        let versions = self
            .manager
            .repository()
            .get_all_current_versions(tenant_id)
            .await?;

        let mut requirements = Vec::new();
        for version in versions {
            requirements.push(ConsentRequirementResponse {
                consent_type: version.consent_type,
                consent_type_display: version.consent_type.display_name().to_string(),
                version: version.version,
                title: version.title,
                effective_date: version.effective_date,
                url: version.url,
                required: version.required,
                summary: version.summary,
            });
        }

        Ok(requirements)
    }

    /// Submit multiple consents at once (e.g., during registration)
    pub async fn submit_consents(
        &self,
        user_id: &str,
        requests: Vec<SubmitConsentRequest>,
        context: ConsentContext,
    ) -> ConsentResult<Vec<super::ConsentRecord>> {
        let mut records = Vec::new();

        for request in requests {
            let record = self.manager.submit_consent(user_id, request, context.clone()).await?;
            records.push(record);
        }

        Ok(records)
    }

    /// Get user's consent status with pending items
    pub async fn get_user_consents(
        &self,
        user_id: &str,
    ) -> ConsentResult<UserConsentsResponse> {
        let required_consents = self.manager.get_user_consent_status(user_id).await?;
        let pending_consents = self.manager.get_pending_consents(user_id).await?;

        Ok(UserConsentsResponse {
            required_consents,
            pending_consents,
        })
    }

    /// Withdraw consent
    pub async fn withdraw_consent(
        &self,
        user_id: &str,
        consent_type: ConsentType,
    ) -> ConsentResult<super::ConsentRecord> {
        self.manager.withdraw_consent(user_id, consent_type).await
    }

    /// Get consent history
    pub async fn get_consent_history(
        &self,
        user_id: &str,
    ) -> ConsentResult<Vec<ConsentHistoryResponse>> {
        let history = self.manager.get_consent_history(user_id).await?;

        let responses: Vec<ConsentHistoryResponse> = history
            .into_iter()
            .map(|h| ConsentHistoryResponse {
                id: h.consent_id,
                consent_type: h.consent_type,
                consent_type_display: h.consent_type.display_name().to_string(),
                version: h.version,
                title: h.title,
                granted: h.granted,
                granted_at: h.granted_at,
                withdrawn_at: h.withdrawn_at,
                is_current: h.is_current,
                required: h.required,
            })
            .collect();

        Ok(responses)
    }

    // ==================== Data Export (GDPR Article 20) ====================

    /// Request data export
    pub async fn request_data_export(&self, user_id: &str) -> ConsentResult<DataExportResponse> {
        let request = self.manager.request_data_export(user_id).await?;

        // Start async export generation
        // In production, this would be queued to a background job
        tokio::spawn(generate_data_export(
            self.manager.repository().clone(),
            request.id.clone(),
            user_id.to_string(),
        ));

        Ok(DataExportResponse {
            id: request.id,
            status: request.status,
            requested_at: request.requested_at,
            message: "Your data export is being prepared. Check back later for download link."
                .to_string(),
        })
    }

    /// Get export status
    pub async fn get_export_status(
        &self,
        export_id: &str,
        user_id: &str,
    ) -> ConsentResult<Option<DataExportStatusResponse>> {
        let request = self.manager.get_export_request(export_id, user_id).await?;

        Ok(request.map(|r| DataExportStatusResponse {
            id: r.id,
            status: r.status,
            requested_at: r.requested_at,
            completed_at: r.completed_at,
            download_url: r.download_url,
            expires_at: r.expires_at,
        }))
    }

    /// Generate user data export
    pub async fn generate_user_export(
        &self,
        user_id: &str,
    ) -> ConsentResult<UserDataExport> {
        let repo = self.manager.repository();

        // Get all user data
        let profile = repo
            .get_user_profile_export(user_id)
            .await?
            .map(|p| serde_json::to_value(p).unwrap_or_default())
            .unwrap_or_default();

        let sessions: Vec<serde_json::Value> = repo
            .get_user_sessions_export(user_id)
            .await?
            .into_iter()
            .map(|s| serde_json::to_value(s).unwrap_or_default())
            .collect();

        let audit_logs: Vec<serde_json::Value> = repo
            .get_user_audit_logs_export(user_id)
            .await?
            .into_iter()
            .map(|a| serde_json::to_value(a).unwrap_or_default())
            .collect();

        let consents: Vec<serde_json::Value> = repo
            .get_user_consent_history_export(user_id)
            .await?
            .into_iter()
            .map(|c| serde_json::to_value(c).unwrap_or_default())
            .collect();

        let organizations: Vec<serde_json::Value> = repo
            .get_user_organizations_export(user_id)
            .await?
            .into_iter()
            .map(|o| serde_json::to_value(o).unwrap_or_default())
            .collect();

        let oauth_connections: Vec<serde_json::Value> = repo
            .get_user_oauth_export(user_id)
            .await?
            .into_iter()
            .map(|o| serde_json::to_value(o).unwrap_or_default())
            .collect();

        let metadata = ExportMetadata {
            user_id: user_id.to_string(),
            generated_at: Utc::now(),
            version: "1.0".to_string(),
            categories: vec![
                "profile".to_string(),
                "sessions".to_string(),
                "audit_logs".to_string(),
                "consents".to_string(),
                "organizations".to_string(),
                "oauth_connections".to_string(),
            ],
        };

        Ok(UserDataExport {
            metadata,
            profile,
            sessions,
            audit_logs,
            consents,
            organizations,
            oauth_connections,
            additional_data: json!({}),
        })
    }

    // ==================== Account Deletion (GDPR Article 17) ====================

    /// Request account deletion
    pub async fn request_account_deletion(
        &self,
        user_id: &str,
        reason: Option<&str>,
    ) -> ConsentResult<DeletionResponse> {
        let request = self.manager.request_account_deletion(user_id, reason).await?;

        Ok(DeletionResponse {
            id: request.id,
            status: request.status,
            requested_at: request.requested_at,
            scheduled_deletion_at: request.scheduled_deletion_at,
            cancellation_token: request.cancellation_token,
            message: format!(
                "Your account deletion request has been received. Your account will be deleted on {}. Use the cancellation token to cancel this request before then.",
                request.scheduled_deletion_at.format("%Y-%m-%d")
            ),
        })
    }

    /// Cancel deletion request
    pub async fn cancel_deletion(
        &self,
        user_id: &str,
        token: &str,
    ) -> ConsentResult<DeletionResponse> {
        let request = self.manager.cancel_deletion(user_id, token).await?;

        Ok(DeletionResponse {
            id: request.id,
            status: request.status,
            requested_at: request.requested_at,
            scheduled_deletion_at: request.scheduled_deletion_at,
            cancellation_token: request.cancellation_token,
            message: "Your account deletion request has been cancelled.".to_string(),
        })
    }

    /// Get deletion status
    pub async fn get_deletion_status(
        &self,
        user_id: &str,
    ) -> ConsentResult<Option<DeletionStatusResponse>> {
        let request = self.manager.get_active_deletion(user_id).await?;

        Ok(request.map(|r| DeletionStatusResponse {
            id: r.id,
            status: r.status,
            requested_at: r.requested_at,
            scheduled_deletion_at: r.scheduled_deletion_at,
            days_remaining: (r.scheduled_deletion_at - Utc::now()).num_days().max(0) as i32,
        }))
    }

    // ==================== Admin Operations ====================

    /// Create consent version
    pub async fn create_consent_version(
        &self,
        tenant_id: &str,
        request: CreateConsentVersionRequest,
    ) -> ConsentResult<ConsentVersionResponse> {
        let repo = self.manager.repository();

        // Validate version format (simple semver check)
        if !is_valid_version(&request.version) {
            return Err(ConsentError::InvalidVersionFormat(request.version));
        }

        let version_id = uuid::Uuid::new_v4().to_string();

        // Create the version
        let row = repo
            .create_consent_version(
                &version_id,
                tenant_id,
                request.consent_type,
                &request.version,
                &request.title,
                &request.content,
                request.summary.as_deref(),
                request.effective_date,
                request.url.as_deref(),
                request.consent_type.is_required(),
            )
            .await?;

        // If make_current is true, set as current version
        if request.make_current {
            repo.set_current_version(tenant_id, request.consent_type, &version_id)
                .await?;
        }

        Ok(ConsentVersionResponse {
            id: row.id,
            consent_type: row.consent_type,
            consent_type_display: row.consent_type.display_name().to_string(),
            version: row.version,
            title: row.title,
            summary: row.summary,
            effective_date: row.effective_date,
            url: row.url,
            is_current: row.is_current,
            required: row.required,
            created_at: row.created_at,
        })
    }

    /// Update consent version
    pub async fn update_consent_version(
        &self,
        version_id: &str,
        request: UpdateConsentVersionRequest,
    ) -> ConsentResult<ConsentVersionResponse> {
        let repo = self.manager.repository();

        let row = repo
            .update_consent_version(
                version_id,
                request.title.as_deref(),
                request.content.as_deref(),
                request.summary.as_deref(),
                request.url.as_deref(),
            )
            .await?;

        // Handle make_current if specified
        if let Some(true) = request.make_current {
            repo.set_current_version(&row.tenant_id, row.consent_type, version_id)
                .await?;
            // Refresh the row to get updated is_current
            let updated = repo.get_version_by_id(version_id).await?;
            if let Some(updated) = updated {
                return Ok(ConsentVersionResponse {
                    id: updated.id,
                    consent_type: updated.consent_type,
                    consent_type_display: updated.consent_type.display_name().to_string(),
                    version: updated.version,
                    title: updated.title,
                    summary: updated.summary,
                    effective_date: updated.effective_date,
                    url: updated.url,
                    is_current: updated.is_current,
                    required: updated.required,
                    created_at: updated.created_at,
                });
            }
        }

        Ok(ConsentVersionResponse {
            id: row.id,
            consent_type: row.consent_type,
            consent_type_display: row.consent_type.display_name().to_string(),
            version: row.version,
            title: row.title,
            summary: row.summary,
            effective_date: row.effective_date,
            url: row.url,
            is_current: row.is_current,
            required: row.required,
            created_at: row.created_at,
        })
    }

    /// List consent versions
    pub async fn list_consent_versions(
        &self,
        tenant_id: &str,
        consent_type: Option<ConsentType>,
        page: i64,
        per_page: i64,
    ) -> ConsentResult<ListConsentVersionsResponse> {
        let (rows, total) = self
            .manager
            .repository()
            .list_consent_versions(tenant_id, consent_type, page, per_page)
            .await?;

        let versions: Vec<ConsentVersionResponse> = rows
            .into_iter()
            .map(|r| ConsentVersionResponse {
                id: r.id,
                consent_type: r.consent_type,
                consent_type_display: r.consent_type.display_name().to_string(),
                version: r.version,
                title: r.title,
                summary: r.summary,
                effective_date: r.effective_date,
                url: r.url,
                is_current: r.is_current,
                required: r.required,
                created_at: r.created_at,
            })
            .collect();

        Ok(ListConsentVersionsResponse {
            versions,
            total,
            page,
            per_page,
            total_pages: (total as f64 / per_page as f64).ceil() as i64,
        })
    }

    /// Get consent statistics
    pub async fn get_consent_statistics(
        &self,
        tenant_id: &str,
        version_id: &str,
    ) -> ConsentResult<Option<super::ConsentStatistics>> {
        let row = self
            .manager
            .repository()
            .get_consent_statistics(tenant_id, version_id)
            .await?;

        Ok(row.map(|r| {
            let consent_rate = if r.total_users > 0 {
                (r.granted_count as f64 / r.total_users as f64) * 100.0
            } else {
                0.0
            };

            super::ConsentStatistics {
                consent_type: r.consent_type,
                version: r.version,
                total_users: r.total_users,
                granted_count: r.granted_count,
                withdrawn_count: r.withdrawn_count,
                pending_count: r.pending_count,
                consent_rate,
            }
        }))
    }

    /// Get all statistics for a consent type
    pub async fn get_all_statistics(
        &self,
        tenant_id: &str,
        consent_type: ConsentType,
    ) -> ConsentResult<Vec<super::ConsentStatistics>> {
        let rows = self
            .manager
            .repository()
            .get_all_statistics(tenant_id, consent_type)
            .await?;

        let stats: Vec<super::ConsentStatistics> = rows
            .into_iter()
            .map(|r| {
                let consent_rate = if r.total_users > 0 {
                    (r.granted_count as f64 / r.total_users as f64) * 100.0
                } else {
                    0.0
                };

                super::ConsentStatistics {
                    consent_type: r.consent_type,
                    version: r.version,
                    total_users: r.total_users,
                    granted_count: r.granted_count,
                    withdrawn_count: r.withdrawn_count,
                    pending_count: r.pending_count,
                    consent_rate,
                }
            })
            .collect();

        Ok(stats)
    }

    /// Get cookie consent configuration
    pub async fn get_cookie_consent_config(&self, tenant_id: &str) -> ConsentResult<CookieConsentConfig> {
        let config = self.manager.repository().get_tenant_config(tenant_id).await?;
        
        let cookie_config: CookieConsentConfig = serde_json::from_value(config.cookie_config)
            .unwrap_or_default();
        
        Ok(cookie_config)
    }
}

/// Generate data export in background
async fn generate_data_export(repo: ConsentRepository, export_id: String, user_id: String) {
    tracing::info!("Starting data export generation for user {}", user_id);

    // Update status to processing
    if let Err(e) = repo
        .update_export_status(
            &export_id,
            DataExportStatus::Processing,
            None,
            None,
            None,
        )
        .await
    {
        tracing::error!("Failed to update export status: {}", e);
        return;
    }

    let export_dir = PathBuf::from("./data/consent-exports");
    if let Err(e) = tokio::fs::create_dir_all(&export_dir).await {
        tracing::error!("Failed to create consent export directory: {}", e);
        let _ = repo
            .update_export_status(
                &export_id,
                DataExportStatus::Failed,
                None,
                None,
                Some(&format!("Failed to create export directory: {}", e)),
            )
            .await;
        return;
    }

    let export_payload = match build_export_payload(&repo, &user_id).await {
        Ok(payload) => payload,
        Err(e) => {
            tracing::error!("Failed to build consent export payload: {}", e);
            let _ = repo
                .update_export_status(
                    &export_id,
                    DataExportStatus::Failed,
                    None,
                    None,
                    Some(&e.to_string()),
                )
                .await;
            return;
        }
    };

    let export_file = export_dir.join(format!("{}.json", export_id));
    let json_bytes = match serde_json::to_vec_pretty(&export_payload) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Failed to serialize export payload: {}", e);
            let _ = repo
                .update_export_status(
                    &export_id,
                    DataExportStatus::Failed,
                    None,
                    None,
                    Some(&format!("Serialization failed: {}", e)),
                )
                .await;
            return;
        }
    };

    if let Err(e) = tokio::fs::write(&export_file, json_bytes).await {
        tracing::error!("Failed to write export file: {}", e);
        let _ = repo
            .update_export_status(
                &export_id,
                DataExportStatus::Failed,
                None,
                None,
                Some(&format!("File write failed: {}", e)),
            )
            .await;
        return;
    }

    // Generate download URL and expiry
    let expires_at = Utc::now() + Duration::days(7);
    let download_url = format!("/api/v1/consents/export/{}/download", export_id);

    if let Err(e) = repo
        .update_export_status(
            &export_id,
            DataExportStatus::Ready,
            Some(&download_url),
            Some(expires_at),
            None,
        )
        .await
    {
        tracing::error!("Failed to finalize export: {}", e);
        let _ = repo
            .update_export_status(
                &export_id,
                DataExportStatus::Failed,
                None,
                None,
                Some(&e.to_string()),
            )
            .await;
    } else {
        tracing::info!("Data export {} completed successfully", export_id);
    }
}

async fn build_export_payload(
    repo: &ConsentRepository,
    user_id: &str,
) -> ConsentResult<serde_json::Value> {
    let profile = repo
        .get_user_profile_export(user_id)
        .await?
        .map(|p| serde_json::to_value(p).unwrap_or_default())
        .unwrap_or_default();

    let sessions: Vec<serde_json::Value> = repo
        .get_user_sessions_export(user_id)
        .await?
        .into_iter()
        .map(|s| serde_json::to_value(s).unwrap_or_default())
        .collect();

    let audit_logs: Vec<serde_json::Value> = repo
        .get_user_audit_logs_export(user_id)
        .await?
        .into_iter()
        .map(|a| serde_json::to_value(a).unwrap_or_default())
        .collect();

    let consents: Vec<serde_json::Value> = repo
        .get_user_consent_history_export(user_id)
        .await?
        .into_iter()
        .map(|c| serde_json::to_value(c).unwrap_or_default())
        .collect();

    let organizations: Vec<serde_json::Value> = repo
        .get_user_organizations_export(user_id)
        .await?
        .into_iter()
        .map(|o| serde_json::to_value(o).unwrap_or_default())
        .collect();

    let oauth_connections: Vec<serde_json::Value> = repo
        .get_user_oauth_export(user_id)
        .await?
        .into_iter()
        .map(|o| serde_json::to_value(o).unwrap_or_default())
        .collect();

    Ok(json!({
        "metadata": {
            "user_id": user_id,
            "generated_at": Utc::now(),
            "version": "1.0",
            "categories": [
                "profile",
                "sessions",
                "audit_logs",
                "consents",
                "organizations",
                "oauth_connections"
            ]
        },
        "profile": profile,
        "sessions": sessions,
        "audit_logs": audit_logs,
        "consents": consents,
        "organizations": organizations,
        "oauth_connections": oauth_connections,
        "additional_data": {}
    }))
}

/// Validate version string format (simple semver)
fn is_valid_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return false;
    }

    for part in parts {
        if part.parse::<u32>().is_err() {
            return false;
        }
    }

    true
}

// ==================== Response Types ====================

/// Consent requirement response
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConsentRequirementResponse {
    pub consent_type: ConsentType,
    pub consent_type_display: String,
    pub version: String,
    pub title: String,
    #[serde(rename = "effectiveDate")]
    pub effective_date: chrono::DateTime<Utc>,
    pub url: Option<String>,
    pub required: bool,
    pub summary: Option<String>,
}

/// User consents response
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserConsentsResponse {
    #[serde(rename = "requiredConsents")]
    pub required_consents: Vec<UserConsentStatus>,
    #[serde(rename = "pendingConsents")]
    pub pending_consents: Vec<PendingConsent>,
}

/// Consent history response
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConsentHistoryResponse {
    pub id: String,
    pub consent_type: ConsentType,
    #[serde(rename = "consentTypeDisplay")]
    pub consent_type_display: String,
    pub version: String,
    pub title: String,
    pub granted: bool,
    #[serde(rename = "grantedAt")]
    pub granted_at: chrono::DateTime<Utc>,
    #[serde(rename = "withdrawnAt")]
    pub withdrawn_at: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "isCurrent")]
    pub is_current: bool,
    pub required: bool,
}

/// Data export response
#[derive(Debug, Clone, serde::Serialize)]
pub struct DataExportResponse {
    pub id: String,
    pub status: DataExportStatus,
    #[serde(rename = "requestedAt")]
    pub requested_at: chrono::DateTime<Utc>,
    pub message: String,
}

/// Data export status response
#[derive(Debug, Clone, serde::Serialize)]
pub struct DataExportStatusResponse {
    pub id: String,
    pub status: DataExportStatus,
    #[serde(rename = "requestedAt")]
    pub requested_at: chrono::DateTime<Utc>,
    #[serde(rename = "completedAt")]
    pub completed_at: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "downloadUrl")]
    pub download_url: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

/// Deletion response
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeletionResponse {
    pub id: String,
    pub status: DeletionStatus,
    #[serde(rename = "requestedAt")]
    pub requested_at: chrono::DateTime<Utc>,
    #[serde(rename = "scheduledDeletionAt")]
    pub scheduled_deletion_at: chrono::DateTime<Utc>,
    #[serde(rename = "cancellationToken")]
    pub cancellation_token: String,
    pub message: String,
}

/// Deletion status response
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeletionStatusResponse {
    pub id: String,
    pub status: DeletionStatus,
    #[serde(rename = "requestedAt")]
    pub requested_at: chrono::DateTime<Utc>,
    #[serde(rename = "scheduledDeletionAt")]
    pub scheduled_deletion_at: chrono::DateTime<Utc>,
    #[serde(rename = "daysRemaining")]
    pub days_remaining: i32,
}

/// Consent version response
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConsentVersionResponse {
    pub id: String,
    pub consent_type: ConsentType,
    #[serde(rename = "consentTypeDisplay")]
    pub consent_type_display: String,
    pub version: String,
    pub title: String,
    pub summary: Option<String>,
    #[serde(rename = "effectiveDate")]
    pub effective_date: chrono::DateTime<Utc>,
    pub url: Option<String>,
    #[serde(rename = "isCurrent")]
    pub is_current: bool,
    pub required: bool,
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<Utc>,
}

/// List consent versions response
#[derive(Debug, Clone, serde::Serialize)]
pub struct ListConsentVersionsResponse {
    pub versions: Vec<ConsentVersionResponse>,
    pub total: i64,
    pub page: i64,
    #[serde(rename = "perPage")]
    pub per_page: i64,
    #[serde(rename = "totalPages")]
    pub total_pages: i64,
}
