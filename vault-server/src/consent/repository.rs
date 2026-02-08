//! Consent Repository
//!
//! Database access layer for consent management.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;

use super::models::*;
use super::{ConsentResult, ConsentType};

/// Repository for consent-related database operations
#[derive(Clone)]
pub struct ConsentRepository {
    pool: PgPool,
}

impl ConsentRepository {
    /// Create a new consent repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ==================== Consent Versions ====================

    /// Create a new consent version
    pub async fn create_consent_version(
        &self,
        id: &str,
        tenant_id: &str,
        consent_type: ConsentType,
        version: &str,
        title: &str,
        content: &str,
        summary: Option<&str>,
        effective_date: DateTime<Utc>,
        url: Option<&str>,
        required: bool,
    ) -> ConsentResult<ConsentVersionRow> {
        let row = sqlx::query_as::<_, ConsentVersionRow>(
            r#"INSERT INTO consent_versions 
               (id, tenant_id, consent_type, version, title, content, summary, 
                effective_date, url, is_current, required, created_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
               RETURNING id, tenant_id, consent_type, version, title, content, summary,
                         effective_date, url, is_current, required, created_at"#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(consent_type)
        .bind(version)
        .bind(title)
        .bind(content)
        .bind(summary)
        .bind(effective_date)
        .bind(url)
        .bind(true) // is_current
        .bind(required)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Get current consent version for a type
    pub async fn get_current_version(
        &self,
        tenant_id: &str,
        consent_type: ConsentType,
    ) -> ConsentResult<Option<ConsentVersionRow>> {
        let row = sqlx::query_as::<_, ConsentVersionRow>(
            r#"SELECT id, tenant_id, consent_type, version, title, content, summary,
                      effective_date, url, is_current, required, created_at
               FROM consent_versions 
               WHERE tenant_id = $1 AND consent_type = $2 AND is_current = true
               ORDER BY effective_date DESC
               LIMIT 1"#,
        )
        .bind(tenant_id)
        .bind(consent_type)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Get all current consent versions for a tenant
    pub async fn get_all_current_versions(
        &self,
        tenant_id: &str,
    ) -> ConsentResult<Vec<ConsentVersionRow>> {
        let rows = sqlx::query_as::<_, ConsentVersionRow>(
            r#"SELECT id, tenant_id, consent_type, version, title, content, summary,
                      effective_date, url, is_current, required, created_at
               FROM consent_versions 
               WHERE tenant_id = $1 AND is_current = true
               ORDER BY consent_type"#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Get consent version by ID
    pub async fn get_version_by_id(&self, id: &str) -> ConsentResult<Option<ConsentVersionRow>> {
        let row = sqlx::query_as::<_, ConsentVersionRow>(
            r#"SELECT id, tenant_id, consent_type, version, title, content, summary,
                      effective_date, url, is_current, required, created_at
               FROM consent_versions 
               WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// List all consent versions for a tenant (with pagination)
    pub async fn list_consent_versions(
        &self,
        tenant_id: &str,
        consent_type: Option<ConsentType>,
        page: i64,
        per_page: i64,
    ) -> ConsentResult<(Vec<ConsentVersionRow>, i64)> {
        let offset = (page - 1) * per_page;

        let (rows, total) = match consent_type {
            Some(ct) => {
                let rows = sqlx::query_as::<_, ConsentVersionRow>(
                    r#"SELECT id, tenant_id, consent_type, version, title, content, summary,
                              effective_date, url, is_current, required, created_at
                       FROM consent_versions 
                       WHERE tenant_id = $1 AND consent_type = $2
                       ORDER BY effective_date DESC
                       LIMIT $3 OFFSET $4"#,
                )
                .bind(tenant_id)
                .bind(ct)
                .bind(per_page)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?;

                let total: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM consent_versions WHERE tenant_id = $1 AND consent_type = $2",
                )
                .bind(tenant_id)
                .bind(ct)
                .fetch_one(&self.pool)
                .await?;

                (rows, total)
            }
            None => {
                let rows = sqlx::query_as::<_, ConsentVersionRow>(
                    r#"SELECT id, tenant_id, consent_type, version, title, content, summary,
                              effective_date, url, is_current, required, created_at
                       FROM consent_versions 
                       WHERE tenant_id = $1
                       ORDER BY consent_type, effective_date DESC
                       LIMIT $2 OFFSET $3"#,
                )
                .bind(tenant_id)
                .bind(per_page)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?;

                let total: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM consent_versions WHERE tenant_id = $1")
                        .bind(tenant_id)
                        .fetch_one(&self.pool)
                        .await?;

                (rows, total)
            }
        };

        Ok((rows, total))
    }

    /// Update consent version
    pub async fn update_consent_version(
        &self,
        id: &str,
        title: Option<&str>,
        content: Option<&str>,
        summary: Option<&str>,
        url: Option<&str>,
    ) -> ConsentResult<ConsentVersionRow> {
        let row = sqlx::query_as::<_, ConsentVersionRow>(
            r#"UPDATE consent_versions 
               SET title = COALESCE($2, title),
                   content = COALESCE($3, content),
                   summary = COALESCE($4, summary),
                   url = COALESCE($5, url)
               WHERE id = $1
               RETURNING id, tenant_id, consent_type, version, title, content, summary,
                         effective_date, url, is_current, required, created_at"#,
        )
        .bind(id)
        .bind(title)
        .bind(content)
        .bind(summary)
        .bind(url)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Set current version for a consent type
    /// This will unset the current flag on all other versions of this type
    pub async fn set_current_version(
        &self,
        tenant_id: &str,
        consent_type: ConsentType,
        version_id: &str,
    ) -> ConsentResult<()> {
        let mut tx = self.pool.begin().await?;

        // Unset current on all versions of this type
        sqlx::query(
            "UPDATE consent_versions SET is_current = false WHERE tenant_id = $1 AND consent_type = $2",
        )
        .bind(tenant_id)
        .bind(consent_type)
        .execute(&mut *tx)
        .await?;

        // Set current on the specified version
        sqlx::query("UPDATE consent_versions SET is_current = true WHERE id = $1")
            .bind(version_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    // ==================== User Consents ====================

    /// Record user consent
    pub async fn record_consent(
        &self,
        id: &str,
        user_id: &str,
        consent_version_id: &str,
        granted: bool,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        jurisdiction: Option<&str>,
    ) -> ConsentResult<UserConsentRow> {
        let row = sqlx::query_as::<_, UserConsentRow>(
            r#"INSERT INTO user_consents 
               (id, user_id, consent_version_id, granted, granted_at, ip_address, user_agent, jurisdiction, withdrawn_at)
               VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, NULL)
               ON CONFLICT (user_id, consent_version_id) 
               DO UPDATE SET granted = $4, granted_at = NOW(), ip_address = $5, user_agent = $6, jurisdiction = $7, withdrawn_at = NULL
               RETURNING id, user_id, consent_version_id, granted, granted_at, ip_address, user_agent, jurisdiction, withdrawn_at"#,
        )
        .bind(id)
        .bind(user_id)
        .bind(consent_version_id)
        .bind(granted)
        .bind(ip_address)
        .bind(user_agent)
        .bind(jurisdiction)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Withdraw consent
    pub async fn withdraw_consent(
        &self,
        user_id: &str,
        consent_version_id: &str,
    ) -> ConsentResult<UserConsentRow> {
        let row = sqlx::query_as::<_, UserConsentRow>(
            r#"UPDATE user_consents 
               SET granted = false, withdrawn_at = NOW()
               WHERE user_id = $1 AND consent_version_id = $2
               RETURNING id, user_id, consent_version_id, granted, granted_at, ip_address, user_agent, jurisdiction, withdrawn_at"#,
        )
        .bind(user_id)
        .bind(consent_version_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Get user's consent for a specific version
    pub async fn get_user_consent(
        &self,
        user_id: &str,
        consent_version_id: &str,
    ) -> ConsentResult<Option<UserConsentRow>> {
        let row = sqlx::query_as::<_, UserConsentRow>(
            r#"SELECT id, user_id, consent_version_id, granted, granted_at, ip_address, user_agent, jurisdiction, withdrawn_at
               FROM user_consents 
               WHERE user_id = $1 AND consent_version_id = $2"#,
        )
        .bind(user_id)
        .bind(consent_version_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Get user's consent history with version info
    pub async fn get_user_consent_history(
        &self,
        user_id: &str,
    ) -> ConsentResult<Vec<UserConsentWithVersionRow>> {
        let rows = sqlx::query_as::<_, UserConsentWithVersionRow>(
            r#"SELECT uc.id as consent_id, uc.user_id, uc.granted, uc.granted_at, uc.withdrawn_at,
                      uc.ip_address, uc.user_agent,
                      cv.id as version_id, cv.consent_type, cv.version, cv.title, 
                      cv.effective_date, cv.is_current, cv.required
               FROM user_consents uc
               JOIN consent_versions cv ON uc.consent_version_id = cv.id
               WHERE uc.user_id = $1
               ORDER BY uc.granted_at DESC"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Check if user has consented to current version
    pub async fn has_consented_to_current(
        &self,
        user_id: &str,
        tenant_id: &str,
        consent_type: ConsentType,
    ) -> ConsentResult<bool> {
        let result: Option<(bool,)> = sqlx::query_as(
            r#"SELECT uc.granted
               FROM user_consents uc
               JOIN consent_versions cv ON uc.consent_version_id = cv.id
               WHERE uc.user_id = $1 
                 AND cv.tenant_id = $2 
                 AND cv.consent_type = $3 
                 AND cv.is_current = true"#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(consent_type)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result.map(|r| r.0).unwrap_or(false))
    }

    /// Get pending consents for a user
    pub async fn get_pending_consents(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> ConsentResult<Vec<(ConsentVersionRow, bool)>> {
        // Get all current versions and whether user has consented
        let rows = sqlx::query_as::<_, ConsentVersionRow>(
            r#"SELECT cv.id, cv.tenant_id, cv.consent_type, cv.version, cv.title, cv.content, cv.summary,
                      cv.effective_date, cv.url, cv.is_current, cv.required, cv.created_at
               FROM consent_versions cv
               WHERE cv.tenant_id = $1 AND cv.is_current = true
                 AND cv.effective_date <= NOW()"#,
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let mut pending = Vec::new();
        for version in rows {
            let has_consented = self
                .has_consented_to_current(user_id, tenant_id, version.consent_type)
                .await?;
            if !has_consented {
                pending.push((version, false));
            }
        }

        Ok(pending)
    }

    // ==================== Statistics ====================

    /// Get consent statistics
    pub async fn get_consent_statistics(
        &self,
        tenant_id: &str,
        version_id: &str,
    ) -> ConsentResult<Option<ConsentStatsRow>> {
        let row = sqlx::query_as::<_, ConsentStatsRow>(
            r#"SELECT 
                  cv.consent_type,
                  cv.version,
                  COUNT(DISTINCT u.id) as total_users,
                  COUNT(DISTINCT CASE WHEN uc.granted = true THEN uc.user_id END) as granted_count,
                  COUNT(DISTINCT CASE WHEN uc.granted = false AND uc.withdrawn_at IS NOT NULL THEN uc.user_id END) as withdrawn_count,
                  COUNT(DISTINCT u.id) - COUNT(DISTINCT uc.user_id) as pending_count
               FROM consent_versions cv
               CROSS JOIN users u
               LEFT JOIN user_consents uc ON uc.consent_version_id = cv.id AND uc.user_id = u.id
               WHERE cv.id = $1 AND cv.tenant_id = $2 AND u.tenant_id = $2 AND u.deleted_at IS NULL
               GROUP BY cv.consent_type, cv.version"#,
        )
        .bind(version_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Get all statistics for a consent type
    pub async fn get_all_statistics(
        &self,
        tenant_id: &str,
        consent_type: ConsentType,
    ) -> ConsentResult<Vec<ConsentStatsRow>> {
        let rows = sqlx::query_as::<_, ConsentStatsRow>(
            r#"SELECT 
                  cv.consent_type,
                  cv.version,
                  COUNT(DISTINCT u.id) as total_users,
                  COUNT(DISTINCT CASE WHEN uc.granted = true THEN uc.user_id END) as granted_count,
                  COUNT(DISTINCT CASE WHEN uc.granted = false AND uc.withdrawn_at IS NOT NULL THEN uc.user_id END) as withdrawn_count,
                  COUNT(DISTINCT u.id) - COUNT(DISTINCT uc.user_id) as pending_count
               FROM consent_versions cv
               CROSS JOIN users u
               LEFT JOIN user_consents uc ON uc.consent_version_id = cv.id AND uc.user_id = u.id
               WHERE cv.tenant_id = $1 AND cv.consent_type = $2 AND u.tenant_id = $1 AND u.deleted_at IS NULL
               GROUP BY cv.consent_type, cv.version, cv.effective_date
               ORDER BY cv.effective_date DESC"#,
        )
        .bind(tenant_id)
        .bind(consent_type)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    // ==================== Data Export ====================

    /// Create data export request
    pub async fn create_export_request(
        &self,
        id: &str,
        user_id: &str,
        tenant_id: &str,
    ) -> ConsentResult<DataExportRequestRow> {
        let row = sqlx::query_as::<_, DataExportRequestRow>(
            r#"INSERT INTO data_export_requests 
               (id, user_id, tenant_id, status, requested_at, completed_at, download_url, expires_at)
               VALUES ($1, $2, $3, 'pending', NOW(), NULL, NULL, NULL)
               RETURNING id, user_id, tenant_id, status, requested_at, completed_at, download_url, expires_at, error_message"#,
        )
        .bind(id)
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Get export request by ID
    pub async fn get_export_request(
        &self,
        id: &str,
        user_id: &str,
    ) -> ConsentResult<Option<DataExportRequestRow>> {
        let row = sqlx::query_as::<_, DataExportRequestRow>(
            r#"SELECT id, user_id, tenant_id, status, requested_at, completed_at, download_url, expires_at, error_message
               FROM data_export_requests 
               WHERE id = $1 AND user_id = $2"#,
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Update export request status
    pub async fn update_export_status(
        &self,
        id: &str,
        status: super::DataExportStatus,
        download_url: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
        error_message: Option<&str>,
    ) -> ConsentResult<()> {
        sqlx::query(
            r#"UPDATE data_export_requests 
               SET status = $2, 
                   completed_at = CASE WHEN $2 = 'ready' THEN NOW() ELSE completed_at END,
                   download_url = COALESCE($3, download_url),
                   expires_at = COALESCE($4, expires_at),
                   error_message = $5
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(status)
        .bind(download_url)
        .bind(expires_at)
        .bind(error_message)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get user's export requests
    pub async fn get_user_export_requests(
        &self,
        user_id: &str,
    ) -> ConsentResult<Vec<DataExportRequestRow>> {
        let rows = sqlx::query_as::<_, DataExportRequestRow>(
            r#"SELECT id, user_id, tenant_id, status, requested_at, completed_at, download_url, expires_at, error_message
               FROM data_export_requests 
               WHERE user_id = $1
               ORDER BY requested_at DESC"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Get pending export requests
    pub async fn get_pending_exports(&self) -> ConsentResult<Vec<DataExportRequestRow>> {
        let rows = sqlx::query_as::<_, DataExportRequestRow>(
            r#"SELECT id, user_id, tenant_id, status, requested_at, completed_at, download_url, expires_at, error_message
               FROM data_export_requests 
               WHERE status = 'pending'
               ORDER BY requested_at ASC
               LIMIT 10"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    // ==================== Account Deletion ====================

    /// Create deletion request
    pub async fn create_deletion_request(
        &self,
        id: &str,
        user_id: &str,
        tenant_id: &str,
        cancellation_token: &str,
        reason: Option<&str>,
        grace_period_days: i64,
    ) -> ConsentResult<DeletionRequestRow> {
        let scheduled_deletion = Utc::now() + Duration::days(grace_period_days);

        let row = sqlx::query_as::<_, DeletionRequestRow>(
            r#"INSERT INTO deletion_requests 
               (id, user_id, tenant_id, status, requested_at, scheduled_deletion_at, deleted_at, cancellation_token, reason)
               VALUES ($1, $2, $3, 'pending', NOW(), $4, NULL, $5, $6)
               RETURNING id, user_id, tenant_id, status, requested_at, scheduled_deletion_at, deleted_at, cancellation_token, reason, error_message"#,
        )
        .bind(id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(scheduled_deletion)
        .bind(cancellation_token)
        .bind(reason)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Get deletion request by ID
    pub async fn get_deletion_request(
        &self,
        id: &str,
    ) -> ConsentResult<Option<DeletionRequestRow>> {
        let row = sqlx::query_as::<_, DeletionRequestRow>(
            r#"SELECT id, user_id, tenant_id, status, requested_at, scheduled_deletion_at, deleted_at, cancellation_token, reason, error_message
               FROM deletion_requests 
               WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Get deletion request by cancellation token
    pub async fn get_deletion_by_token(
        &self,
        token: &str,
    ) -> ConsentResult<Option<DeletionRequestRow>> {
        let row = sqlx::query_as::<_, DeletionRequestRow>(
            r#"SELECT id, user_id, tenant_id, status, requested_at, scheduled_deletion_at, deleted_at, cancellation_token, reason, error_message
               FROM deletion_requests 
               WHERE cancellation_token = $1"#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Get user's active deletion request
    pub async fn get_user_active_deletion(
        &self,
        user_id: &str,
    ) -> ConsentResult<Option<DeletionRequestRow>> {
        let row = sqlx::query_as::<_, DeletionRequestRow>(
            r#"SELECT id, user_id, tenant_id, status, requested_at, scheduled_deletion_at, deleted_at, cancellation_token, reason, error_message
               FROM deletion_requests 
               WHERE user_id = $1 AND status IN ('pending', 'processing')
               ORDER BY requested_at DESC
               LIMIT 1"#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Cancel deletion request
    pub async fn cancel_deletion(
        &self,
        id: &str,
        cancellation_token: &str,
    ) -> ConsentResult<DeletionRequestRow> {
        let row = sqlx::query_as::<_, DeletionRequestRow>(
            r#"UPDATE deletion_requests 
               SET status = 'cancelled'
               WHERE id = $1 AND cancellation_token = $2 AND status = 'pending'
               RETURNING id, user_id, tenant_id, status, requested_at, scheduled_deletion_at, deleted_at, cancellation_token, reason, error_message"#,
        )
        .bind(id)
        .bind(cancellation_token)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Update deletion status
    pub async fn update_deletion_status(
        &self,
        id: &str,
        status: super::DeletionStatus,
        error_message: Option<&str>,
    ) -> ConsentResult<()> {
        sqlx::query(
            r#"UPDATE deletion_requests 
               SET status = $2, 
                   deleted_at = CASE WHEN $2 = 'completed' THEN NOW() ELSE deleted_at END,
                   error_message = $3
               WHERE id = $1"#,
        )
        .bind(id)
        .bind(status)
        .bind(error_message)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get pending deletions (scheduled for today or earlier)
    pub async fn get_pending_deletions(&self) -> ConsentResult<Vec<DeletionRequestRow>> {
        let rows = sqlx::query_as::<_, DeletionRequestRow>(
            r#"SELECT id, user_id, tenant_id, status, requested_at, scheduled_deletion_at, deleted_at, cancellation_token, reason, error_message
               FROM deletion_requests 
               WHERE status = 'pending' AND scheduled_deletion_at <= NOW()
               ORDER BY scheduled_deletion_at ASC
               LIMIT 50"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    // ==================== Data Export Helpers ====================

    /// Get user profile for export
    pub async fn get_user_profile_export(
        &self,
        user_id: &str,
    ) -> ConsentResult<Option<UserProfileExport>> {
        let row = sqlx::query_as::<_, UserProfileExport>(
            r#"SELECT id, email, email_verified, email_verified_at, status, profile, 
                      mfa_enabled, last_login_at, created_at, updated_at
               FROM users 
               WHERE id = $1"#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    /// Get user sessions for export
    pub async fn get_user_sessions_export(
        &self,
        user_id: &str,
    ) -> ConsentResult<Vec<SessionExport>> {
        let rows = sqlx::query_as::<_, SessionExport>(
            r#"SELECT id, status, ip_address, user_agent, device_info, 
                      mfa_verified, created_at, last_activity_at, expires_at
               FROM sessions 
               WHERE user_id = $1
               ORDER BY created_at DESC"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Get user audit logs for export
    pub async fn get_user_audit_logs_export(
        &self,
        user_id: &str,
    ) -> ConsentResult<Vec<AuditLogExport>> {
        let rows = sqlx::query_as::<_, AuditLogExport>(
            r#"SELECT id, timestamp, action, resource_type, resource_id, 
                      ip_address, user_agent, success, metadata
               FROM audit_logs 
               WHERE user_id = $1
               ORDER BY timestamp DESC
               LIMIT 1000"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Get user consent history for export
    pub async fn get_user_consent_history_export(
        &self,
        user_id: &str,
    ) -> ConsentResult<Vec<ConsentHistoryExport>> {
        let rows = sqlx::query_as::<_, ConsentHistoryExport>(
            r#"SELECT cv.consent_type::text, cv.version, uc.granted, 
                      uc.granted_at, uc.withdrawn_at, uc.ip_address
               FROM user_consents uc
               JOIN consent_versions cv ON uc.consent_version_id = cv.id
               WHERE uc.user_id = $1
               ORDER BY uc.granted_at DESC"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Get user organizations for export
    pub async fn get_user_organizations_export(
        &self,
        user_id: &str,
    ) -> ConsentResult<Vec<OrganizationExport>> {
        let rows = sqlx::query_as::<_, OrganizationExport>(
            r#"SELECT o.id, o.name, o.slug, om.role::text, om.status::text, om.joined_at
               FROM organizations o
               JOIN organization_members om ON o.id = om.organization_id
               WHERE om.user_id = $1 AND o.deleted_at IS NULL
               ORDER BY om.joined_at DESC"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Get user OAuth connections for export
    pub async fn get_user_oauth_export(
        &self,
        user_id: &str,
    ) -> ConsentResult<Vec<OAuthConnectionExport>> {
        let rows = sqlx::query_as::<_, OAuthConnectionExport>(
            r#"SELECT id, provider, provider_user_id, email, created_at, last_used_at
               FROM oauth_connections 
               WHERE user_id = $1
               ORDER BY created_at DESC"#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    // ==================== Tenant Config ====================

    /// Get or create tenant consent config
    pub async fn get_tenant_config(&self, tenant_id: &str) -> ConsentResult<TenantConsentConfigRow> {
        let row = sqlx::query_as::<_, TenantConsentConfigRow>(
            r#"INSERT INTO tenant_consent_configs 
               (tenant_id, deletion_grace_period_days, export_retention_days, require_explicit_consent, default_jurisdiction, cookie_config, updated_at)
               VALUES ($1, 30, 7, true, 'GDPR', '{}', NOW())
               ON CONFLICT (tenant_id) DO UPDATE SET tenant_id = $1
               RETURNING tenant_id, deletion_grace_period_days, export_retention_days, require_explicit_consent, default_jurisdiction, cookie_config, updated_at"#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    /// Update tenant consent config
    pub async fn update_tenant_config(
        &self,
        tenant_id: &str,
        deletion_grace_period_days: Option<i32>,
        export_retention_days: Option<i32>,
        require_explicit_consent: Option<bool>,
        default_jurisdiction: Option<&str>,
        cookie_config: Option<serde_json::Value>,
    ) -> ConsentResult<TenantConsentConfigRow> {
        let row = sqlx::query_as::<_, TenantConsentConfigRow>(
            r#"INSERT INTO tenant_consent_configs 
               (tenant_id, deletion_grace_period_days, export_retention_days, require_explicit_consent, default_jurisdiction, cookie_config, updated_at)
               VALUES ($1, COALESCE($2, 30), COALESCE($3, 7), COALESCE($4, true), COALESCE($5, 'GDPR'), COALESCE($6, '{}'), NOW())
               ON CONFLICT (tenant_id) DO UPDATE SET
                   deletion_grace_period_days = COALESCE($2, tenant_consent_configs.deletion_grace_period_days),
                   export_retention_days = COALESCE($3, tenant_consent_configs.export_retention_days),
                   require_explicit_consent = COALESCE($4, tenant_consent_configs.require_explicit_consent),
                   default_jurisdiction = COALESCE($5, tenant_consent_configs.default_jurisdiction),
                   cookie_config = COALESCE($6, tenant_consent_configs.cookie_config),
                   updated_at = NOW()
               RETURNING tenant_id, deletion_grace_period_days, export_retention_days, require_explicit_consent, default_jurisdiction, cookie_config, updated_at"#,
        )
        .bind(tenant_id)
        .bind(deletion_grace_period_days)
        .bind(export_retention_days)
        .bind(require_explicit_consent)
        .bind(default_jurisdiction)
        .bind(cookie_config)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }
}

impl From<Arc<PgPool>> for ConsentRepository {
    fn from(pool: Arc<PgPool>) -> Self {
        Self::new((*pool).clone())
    }
}
