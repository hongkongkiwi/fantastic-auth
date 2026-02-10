//! Consent Manager
//!
//! High-level consent management operations.


use super::{
    ConsentConfig, ConsentContext, ConsentRecord, ConsentRepository, ConsentRequirement,
    ConsentResult, ConsentType, ConsentVersion, ConsentVersionSummary, DataExportRequest,
    DataExportStatus, DeletionRequest, DeletionStatus, PendingConsent, SubmitConsentRequest,
    UserConsentDetail, UserConsentStatus, check_consent,
};

/// Consent manager for handling consent operations
#[derive(Clone)]
pub struct ConsentManager {
    repository: ConsentRepository,
    config: ConsentConfig,
}

impl ConsentManager {
    /// Create a new consent manager
    pub fn new(repository: ConsentRepository, config: ConsentConfig) -> Self {
        Self {
            repository,
            config,
        }
    }

    /// Check if user has given required consent
    pub async fn check_consent(
        &self,
        user_id: &str,
        requirement: &ConsentRequirement,
    ) -> ConsentResult<()> {
        // Get current version for this consent type
        // We need tenant_id here - this is a simplified check
        // In production, you'd need to look up the tenant from user_id
        let tenant_id = self.get_user_tenant(user_id).await?;

        let current_version = self
            .repository
            .get_current_version(&tenant_id, requirement.consent_type)
            .await?;

        let version = match current_version {
            Some(v) => v,
            None => {
                // No consent version defined, allow if not required
                if requirement.consent_type.is_required() {
                    return Err(super::ConsentError::ConsentRequired(
                        requirement.consent_type,
                    ));
                }
                return Ok(());
            }
        };

        // Get user's consent record
        let user_consent = self
            .repository
            .get_user_consent(user_id, &version.id)
            .await?;

        // Check consent validity
        let consent_record = user_consent.clone().map(Into::into);
        check_consent(consent_record.as_ref(), requirement, &version.version)
    }

    /// Submit user consent
    pub async fn submit_consent(
        &self,
        user_id: &str,
        request: SubmitConsentRequest,
        context: ConsentContext,
    ) -> ConsentResult<ConsentRecord> {
        let tenant_id = self.get_user_tenant(user_id).await?;

        // Get the version to consent to
        let version_id = match request.version_id {
            Some(id) => id,
            None => {
                // Get current version for this type
                let version = self
                    .repository
                    .get_current_version(&tenant_id, request.consent_type)
                    .await?
                    .ok_or_else(|| {
                        super::ConsentError::VersionNotFound(
                            format!("No current version for {:?}", request.consent_type),
                        )
                    })?;
                version.id
            }
        };

        // Get the version to check if it's required
        let version = self
            .repository
            .get_version_by_id(&version_id)
            .await?
            .ok_or_else(|| super::ConsentError::VersionNotFound(version_id.clone()))?;

        // Cannot withdraw required consent
        if !request.granted && version.required {
            return Err(super::ConsentError::CannotWithdrawRequired(
                request.consent_type,
            ));
        }

        // Record the consent
        let consent_id = uuid::Uuid::new_v4().to_string();
        let row = self
            .repository
            .record_consent(
                &consent_id,
                user_id,
                &version_id,
                request.granted,
                context.ip_address.as_deref(),
                context.user_agent.as_deref(),
                context.jurisdiction.as_deref(),
            )
            .await?;

        Ok(row.into())
    }

    /// Withdraw consent
    pub async fn withdraw_consent(
        &self,
        user_id: &str,
        consent_type: ConsentType,
    ) -> ConsentResult<ConsentRecord> {
        let tenant_id = self.get_user_tenant(user_id).await?;

        // Get current version for this type
        let version = self
            .repository
            .get_current_version(&tenant_id, consent_type)
            .await?
            .ok_or_else(|| {
                super::ConsentError::VersionNotFound(format!(
                    "No current version for {:?}",
                    consent_type
                ))
            })?;

        // Cannot withdraw required consent
        if version.required {
            return Err(super::ConsentError::CannotWithdrawRequired(consent_type));
        }

        let row = self
            .repository
            .withdraw_consent(user_id, &version.id)
            .await?;

        Ok(row.into())
    }

    /// Get user's consent status for all types
    pub async fn get_user_consent_status(
        &self,
        user_id: &str,
    ) -> ConsentResult<Vec<UserConsentStatus>> {
        let tenant_id = self.get_user_tenant(user_id).await?;

        // Get all current versions
        let versions = self
            .repository
            .get_all_current_versions(&tenant_id)
            .await?;

        let mut statuses = Vec::new();
        for version in versions {
            let has_consented = self
                .repository
                .has_consented_to_current(user_id, &tenant_id, version.consent_type)
                .await?;

            let user_consent = if has_consented {
                self.repository
                    .get_user_consent(user_id, &version.id)
                    .await?
                    .map(|r| UserConsentDetail {
                        id: r.id,
                        version: version.version.clone(),
                        granted: r.granted,
                        granted_at: r.granted_at,
                        withdrawn_at: r.withdrawn_at,
                    })
            } else {
                None
            };

            statuses.push(UserConsentStatus {
                consent_type: version.consent_type,
                current_version: ConsentVersionSummary {
                    id: version.id,
                    version: version.version,
                    title: version.title,
                    effective_date: version.effective_date,
                    url: version.url,
                },
                has_consented,
                user_consent,
                required: version.required,
            });
        }

        Ok(statuses)
    }

    /// Get pending consents for a user
    pub async fn get_pending_consents(&self, user_id: &str) -> ConsentResult<Vec<PendingConsent>> {
        let tenant_id = self.get_user_tenant(user_id).await?;

        let pending = self
            .repository
            .get_pending_consents(user_id, &tenant_id)
            .await?;

        let mut result = Vec::new();
        for (version, _) in pending {
            let reason = if self
                .repository
                .get_user_consent_history(user_id)
                .await?
                .is_empty()
            {
                "first_time"
            } else {
                "new_version"
            }
            .to_string();

            result.push(PendingConsent {
                consent_type: version.consent_type,
                version: ConsentVersionSummary {
                    id: version.id,
                    version: version.version,
                    title: version.title,
                    effective_date: version.effective_date,
                    url: version.url,
                },
                required: version.required,
                reason,
            });
        }

        Ok(result)
    }

    /// Get user's consent history
    pub async fn get_consent_history(
        &self,
        user_id: &str,
    ) -> ConsentResult<Vec<super::models::UserConsentWithVersionRow>> {
        self.repository.get_user_consent_history(user_id).await
    }

    /// Request data export (GDPR Article 20)
    pub async fn request_data_export(&self, user_id: &str) -> ConsentResult<DataExportRequest> {
        let tenant_id = self.get_user_tenant(user_id).await?;

        // Check for existing pending exports
        let existing = self.repository.get_user_export_requests(user_id).await?;
        for export in existing {
            if export.status == DataExportStatus::Pending
                || export.status == DataExportStatus::Processing
            {
                return Err(super::ConsentError::Internal(
                    "Export already in progress".to_string(),
                ));
            }
        }

        let export_id = uuid::Uuid::new_v4().to_string();
        let row = self
            .repository
            .create_export_request(&export_id, user_id, &tenant_id)
            .await?;

        Ok(row.into())
    }

    /// Get export request status
    pub async fn get_export_request(
        &self,
        export_id: &str,
        user_id: &str,
    ) -> ConsentResult<Option<DataExportRequest>> {
        let row = self.repository.get_export_request(export_id, user_id).await?;
        Ok(row.map(|r| r.into()))
    }

    /// Request account deletion (GDPR Article 17)
    pub async fn request_account_deletion(
        &self,
        user_id: &str,
        reason: Option<&str>,
    ) -> ConsentResult<DeletionRequest> {
        let tenant_id = self.get_user_tenant(user_id).await?;

        // Check for existing active deletion request
        let existing = self.repository.get_user_active_deletion(user_id).await?;
        if existing.is_some() {
            return Err(super::ConsentError::Internal(
                "Deletion request already pending".to_string(),
            ));
        }

        let deletion_id = uuid::Uuid::new_v4().to_string();
        let cancellation_token = uuid::Uuid::new_v4().to_string();

        // Get tenant config for grace period
        let config = self.repository.get_tenant_config(&tenant_id).await?;

        let row = self
            .repository
            .create_deletion_request(
                &deletion_id,
                user_id,
                &tenant_id,
                &cancellation_token,
                reason,
                config.deletion_grace_period_days as i64,
            )
            .await?;

        Ok(row.into())
    }

    /// Cancel deletion request
    pub async fn cancel_deletion(
        &self,
        user_id: &str,
        token: &str,
    ) -> ConsentResult<DeletionRequest> {
        // Get the deletion request
        let request = self
            .repository
            .get_deletion_by_token(token)
            .await?
            .ok_or_else(|| super::ConsentError::DeletionRequestNotFound(token.to_string()))?;

        // Verify user owns this request
        if request.user_id != user_id {
            return Err(super::ConsentError::DeletionRequestNotFound(
                token.to_string(),
            ));
        }

        // Check status
        if request.status == DeletionStatus::Cancelled {
            return Err(super::ConsentError::DeletionAlreadyCancelled);
        }

        if request.status == DeletionStatus::Completed {
            return Err(super::ConsentError::DeletionAlreadyCompleted);
        }

        let row = self
            .repository
            .cancel_deletion(&request.id, token)
            .await?;

        Ok(row.into())
    }

    /// Get active deletion request for user
    pub async fn get_active_deletion(&self, user_id: &str) -> ConsentResult<Option<DeletionRequest>> {
        let row = self.repository.get_user_active_deletion(user_id).await?;
        Ok(row.map(|r| r.into()))
    }

    /// Helper to get user's tenant ID
    async fn get_user_tenant(&self, user_id: &str) -> ConsentResult<String> {
        // Query the users table to get the tenant_id for this user
        let tenant_id: Option<String> = sqlx::query_scalar(
            "SELECT tenant_id::text FROM users WHERE id = $1"
        )
        .bind(user_id)
        .fetch_optional(self.repository.pool())
        .await?;
        
        tenant_id.ok_or_else(|| super::ConsentError::UserNotFound(user_id.to_string()))
    }

    /// Get repository reference
    pub fn repository(&self) -> &ConsentRepository {
        &self.repository
    }

    /// Get config
    pub fn config(&self) -> &ConsentConfig {
        &self.config
    }
}

impl From<UserConsentRow> for ConsentRecord {
    fn from(row: UserConsentRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            consent_version_id: row.consent_version_id,
            granted: row.granted,
            granted_at: row.granted_at,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
            jurisdiction: row.jurisdiction,
        }
    }
}

use super::models::*;

impl From<ConsentVersionRow> for ConsentVersion {
    fn from(row: ConsentVersionRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            consent_type: row.consent_type,
            version: row.version,
            title: row.title,
            content: row.content,
            summary: row.summary,
            effective_date: row.effective_date,
            url: row.url,
            is_current: row.is_current,
            required: row.required,
            created_at: row.created_at,
        }
    }
}

impl From<DataExportRequestRow> for DataExportRequest {
    fn from(row: DataExportRequestRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            tenant_id: row.tenant_id,
            status: row.status,
            requested_at: row.requested_at,
            completed_at: row.completed_at,
            download_url: row.download_url,
            expires_at: row.expires_at,
        }
    }
}

impl From<DeletionRequestRow> for DeletionRequest {
    fn from(row: DeletionRequestRow) -> Self {
        Self {
            id: row.id,
            user_id: row.user_id,
            tenant_id: row.tenant_id,
            status: row.status,
            requested_at: row.requested_at,
            scheduled_deletion_at: row.scheduled_deletion_at,
            deleted_at: row.deleted_at,
            cancellation_token: row.cancellation_token,
            reason: row.reason,
        }
    }
}
