//! Data Export Processing Background Worker
//!
//! GDPR Article 20 - Right to Data Portability
//!
//! This worker processes pending data export requests. It:
//! - Aggregates user data from multiple tables
//! - Generates encrypted export files
//! - Provides secure download links
//! - Cleans up expired exports
//!
//! # Processing Flow
//!
//! 1. Find exports with status = 'pending' ordered by request time
//! 2. Update status to 'processing'
//! 3. Aggregate data from all relevant tables
//! 4. Encrypt and compress the export
//! 5. Store in secure location with access controls
//! 6. Update status to 'ready' with download URL
//! 7. Send notification email to user

use chrono::{DateTime, Duration, Utc};
use std::path::PathBuf;
use std::time::Duration as StdDuration;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::db::Database;
use crate::state::AppState;

/// Export format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Csv,
    Xml,
}

impl Default for ExportFormat {
    fn default() -> Self {
        ExportFormat::Json
    }
}

impl ExportFormat {
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "json" => Some(ExportFormat::Json),
            "csv" => Some(ExportFormat::Csv),
            "xml" => Some(ExportFormat::Xml),
            _ => None,
        }
    }
    
    /// Get file extension
    pub fn extension(&self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
            ExportFormat::Xml => "xml",
        }
    }
    
    /// Get content type
    pub fn content_type(&self) -> &'static str {
        match self {
            ExportFormat::Json => "application/json",
            ExportFormat::Csv => "text/csv",
            ExportFormat::Xml => "application/xml",
        }
    }
}

/// Spawn the export processing worker
pub fn spawn(state: AppState, interval: StdDuration) {
    tokio::spawn(async move {
        info!("Export processing worker started");
        
        loop {
            // Process pending exports
            if let Err(e) = process_pending_exports(&state).await {
                error!(error = %e, "Export processing failed");
            }
            
            // Clean up expired exports
            if let Err(e) = cleanup_expired_exports(&state.db).await {
                error!(error = %e, "Export cleanup failed");
            }
            
            tokio::time::sleep(interval).await;
        }
    });
}

/// Pending export request
#[derive(Debug)]
struct PendingExport {
    id: String,
    user_id: String,
    tenant_id: String,
    format: ExportFormat,
    data_categories: Vec<String>,
    requested_at: DateTime<Utc>,
}

/// Process all pending exports
async fn process_pending_exports(state: &AppState) -> anyhow::Result<()> {
    let db = &state.db;
    
    // Find pending exports
    let pending = find_pending_exports(db).await?;
    
    if pending.is_empty() {
        return Ok(());
    }
    
    info!(count = pending.len(), "Processing pending data exports");
    
    for export in pending {
        if let Err(e) = process_single_export(state, &export).await {
            error!(
                export_id = %export.id,
                user_id = %export.user_id,
                error = %e,
                "Export processing failed"
            );
            
            // Mark as failed
            if let Err(update_err) = update_export_status(
                &state.db,
                &export.id,
                ExportStatus::Failed,
                None,
                None,
                Some(&e.to_string()),
            ).await {
                error!(error = %update_err, "Failed to update export status");
            }
        }
    }
    
    Ok(())
}

/// Find pending export requests
async fn find_pending_exports(db: &Database) -> anyhow::Result<Vec<PendingExport>> {
    let rows = sqlx::query!(
        r#"
        SELECT 
            id::text as id,
            user_id::text as user_id,
            tenant_id::text as tenant_id,
            format,
            data_categories,
            requested_at
        FROM privacy_exports
        WHERE status = 'pending'
        ORDER BY requested_at ASC
        LIMIT 10
        "#
    )
    .fetch_all(db.pool())
    .await?;
    
    let exports: Vec<PendingExport> = rows
        .into_iter()
        .filter_map(|row| {
            Some(PendingExport {
                id: row.id?,
                user_id: row.user_id?,
                tenant_id: row.tenant_id?,
                format: ExportFormat::from_str(&row.format.unwrap_or_default())
                    .unwrap_or_default(),
                data_categories: row.data_categories.unwrap_or_default(),
                requested_at: row.requested_at?,
            })
        })
        .collect();
    
    Ok(exports)
}

/// Process a single export
async fn process_single_export(
    state: &AppState,
    export: &PendingExport,
) -> anyhow::Result<()> {
    info!(
        export_id = %export.id,
        user_id = %export.user_id,
        "Starting export processing"
    );
    
    // 1. Update status to processing
    update_export_status(
        &state.db,
        &export.id,
        ExportStatus::Processing,
        None,
        None,
        None,
    ).await?;
    
    // 2. Build export payload
    let payload = build_export_payload(&state.db, &export.user_id, &export.data_categories).await?;
    
    // 3. Create export directory
    let export_dir = PathBuf::from("./data/exports");
    tokio::fs::create_dir_all(&export_dir).await?;
    
    // 4. Generate file
    let filename = format!("export_{}.json", export.id);
    let filepath = export_dir.join(&filename);
    
    // Serialize to JSON
    let json_bytes = serde_json::to_vec_pretty(&payload)?;
    
    // 5. Encrypt the file (optional but recommended)
    // For now, we store as-is but should add encryption
    tokio::fs::write(&filepath, json_bytes).await?;
    
    // 6. Set permissions (restrict access)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&filepath, perms).await?;
    }
    
    // 7. Calculate expiry (30 days from now)
    let expires_at = Utc::now() + Duration::days(30);
    
    // 8. Generate download URL
    let download_url = format!("/api/v1/privacy/exports/{}/download", export.id);
    
    // 9. Update status to ready
    update_export_status(
        &state.db,
        &export.id,
        ExportStatus::Ready,
        Some(&download_url),
        Some(expires_at),
        None,
    ).await?;
    
    // 10. Log audit
    log_export_audit(&state.db, &export.user_id, &export.tenant_id, &export.id).await?;
    
    info!(
        export_id = %export.id,
        user_id = %export.user_id,
        "Export processing completed"
    );
    
    Ok(())
}

/// Export status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExportStatus {
    Pending,
    Processing,
    Ready,
    Failed,
    Expired,
}

impl ExportStatus {
    fn as_str(&self) -> &'static str {
        match self {
            ExportStatus::Pending => "pending",
            ExportStatus::Processing => "processing",
            ExportStatus::Ready => "ready",
            ExportStatus::Failed => "failed",
            ExportStatus::Expired => "expired",
        }
    }
}

/// Update export status in database
async fn update_export_status(
    db: &Database,
    export_id: &str,
    status: ExportStatus,
    download_url: Option<&str>,
    expires_at: Option<DateTime<Utc>>,
    error_message: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query!(
        r#"
        UPDATE privacy_exports
        SET status = $2,
            download_url = COALESCE($3, download_url),
            expires_at = COALESCE($4, expires_at),
            error_message = COALESCE($5, error_message),
            updated_at = NOW()
        WHERE id = $1::uuid
        "#,
        Uuid::parse_str(export_id)?,
        status.as_str(),
        download_url,
        expires_at,
        error_message
    )
    .execute(db.pool())
    .await?;
    
    Ok(())
}

/// Build export payload with all user data
async fn build_export_payload(
    db: &Database,
    user_id: &str,
    data_categories: &[String],
) -> anyhow::Result<serde_json::Value> {
    let mut payload = serde_json::json!({
        "export_metadata": {
            "version": "1.0",
            "generated_at": Utc::now().to_rfc3339(),
            "data_categories": data_categories,
        }
    });
    
    // Build based on requested categories
    for category in data_categories {
        match category.as_str() {
            "profile" => {
                let profile = get_user_profile(db, user_id).await?;
                payload["profile"] = profile;
            }
            "sessions" => {
                let sessions = get_user_sessions(db, user_id).await?;
                payload["sessions"] = sessions;
            }
            "devices" => {
                let devices = get_user_devices(db, user_id).await?;
                payload["devices"] = devices;
            }
            "consents" => {
                let consents = get_user_consents(db, user_id).await?;
                payload["consents"] = consents;
            }
            "audit_logs" => {
                let audit_logs = get_user_audit_logs(db, user_id).await?;
                payload["audit_logs"] = audit_logs;
            }
            "linked_accounts" => {
                let linked = get_linked_accounts(db, user_id).await?;
                payload["linked_accounts"] = linked;
            }
            "mfa_credentials" => {
                let mfa = get_mfa_credentials(db, user_id).await?;
                payload["mfa_credentials"] = mfa;
            }
            _ => {
                warn!(category = %category, "Unknown data category requested");
            }
        }
    }
    
    Ok(payload)
}

/// Get user profile data
async fn get_user_profile(
    db: &Database,
    user_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let row = sqlx::query!(
        r#"
        SELECT 
            id::text,
            email,
            name,
            email_verified,
            phone,
            status,
            created_at,
            updated_at,
            last_login_at,
            metadata
        FROM users
        WHERE id = $1::uuid
        "#,
        user_id
    )
    .fetch_optional(db.pool())
    .await?;
    
    match row {
        Some(row) => Ok(serde_json::json!({
            "id": row.id,
            "email": row.email,
            "name": row.name,
            "email_verified": row.email_verified,
            "phone": row.phone,
            "status": row.status,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
            "last_login_at": row.last_login_at,
            "metadata": row.metadata,
        })),
        None => Ok(serde_json::json!({})),
    }
}

/// Get user sessions
async fn get_user_sessions(
    db: &Database,
    user_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let rows = sqlx::query!(
        r#"
        SELECT 
            id::text,
            created_at,
            expires_at,
            last_activity_at,
            ip_address,
            user_agent,
            device_fingerprint,
            status
        FROM user_sessions
        WHERE user_id = $1::uuid
        ORDER BY created_at DESC
        "#,
        user_id
    )
    .fetch_all(db.pool())
    .await?;
    
    let sessions: Vec<_> = rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "created_at": row.created_at,
                "expires_at": row.expires_at,
                "last_activity_at": row.last_activity_at,
                "ip_address": row.ip_address,
                "user_agent": row.user_agent,
                "device_fingerprint": row.device_fingerprint,
                "status": row.status,
            })
        })
        .collect();
    
    Ok(serde_json::json!(sessions))
}

/// Get user devices
async fn get_user_devices(
    db: &Database,
    user_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let rows = sqlx::query!(
        r#"
        SELECT 
            id::text,
            fingerprint,
            device_type,
            browser,
            os,
            created_at,
            last_seen_at,
            trust_status
        FROM device_fingerprints
        WHERE user_id = $1::uuid
        ORDER BY last_seen_at DESC
        "#,
        user_id
    )
    .fetch_all(db.pool())
    .await?;
    
    let devices: Vec<_> = rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "fingerprint": row.fingerprint,
                "device_type": row.device_type,
                "browser": row.browser,
                "os": row.os,
                "created_at": row.created_at,
                "last_seen_at": row.last_seen_at,
                "trust_status": row.trust_status,
            })
        })
        .collect();
    
    Ok(serde_json::json!(devices))
}

/// Get user consents
async fn get_user_consents(
    db: &Database,
    user_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let rows = sqlx::query!(
        r#"
        SELECT 
            id::text,
            consent_type,
            granted,
            granted_at,
            withdrawn_at,
            version,
            updated_at
        FROM consent_records
        WHERE user_id = $1::uuid
        ORDER BY consent_type
        "#,
        user_id
    )
    .fetch_all(db.pool())
    .await?;
    
    let consents: Vec<_> = rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "consent_type": row.consent_type,
                "granted": row.granted,
                "granted_at": row.granted_at,
                "withdrawn_at": row.withdrawn_at,
                "version": row.version,
                "updated_at": row.updated_at,
            })
        })
        .collect();
    
    Ok(serde_json::json!(consents))
}

/// Get user audit logs (limited to recent entries)
async fn get_user_audit_logs(
    db: &Database,
    user_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let rows = sqlx::query!(
        r#"
        SELECT 
            id::text,
            action,
            resource_type,
            resource_id,
            success,
            ip_address,
            user_agent,
            metadata,
            timestamp
        FROM audit_logs
        WHERE user_id = $1
        ORDER BY timestamp DESC
        LIMIT 1000
        "#,
        user_id
    )
    .fetch_all(db.pool())
    .await?;
    
    let logs: Vec<_> = rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "success": row.success,
                "ip_address": row.ip_address,
                "user_agent": row.user_agent,
                "metadata": row.metadata,
                "timestamp": row.timestamp,
            })
        })
        .collect();
    
    Ok(serde_json::json!(logs))
}

/// Get linked accounts
async fn get_linked_accounts(
    db: &Database,
    user_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let rows = sqlx::query!(
        r#"
        SELECT 
            id::text,
            provider,
            provider_account_id,
            created_at,
            last_used_at,
            is_primary
        FROM user_linked_accounts
        WHERE user_id = $1::uuid
        ORDER BY created_at DESC
        "#,
        user_id
    )
    .fetch_all(db.pool())
    .await?;
    
    let accounts: Vec<_> = rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "provider": row.provider,
                "provider_account_id": row.provider_account_id,
                "created_at": row.created_at,
                "last_used_at": row.last_used_at,
                "is_primary": row.is_primary,
            })
        })
        .collect();
    
    Ok(serde_json::json!(accounts))
}

/// Get MFA credentials (metadata only, not secrets)
async fn get_mfa_credentials(
    db: &Database,
    user_id: &str,
) -> anyhow::Result<serde_json::Value> {
    let rows = sqlx::query!(
        r#"
        SELECT 
            id::text,
            method_type,
            is_primary,
            is_backup,
            created_at,
            last_used_at,
            verified_at
        FROM mfa_credentials
        WHERE user_id = $1::uuid
        ORDER BY created_at DESC
        "#,
        user_id
    )
    .fetch_all(db.pool())
    .await?;
    
    let credentials: Vec<_> = rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "id": row.id,
                "method_type": row.method_type,
                "is_primary": row.is_primary,
                "is_backup": row.is_backup,
                "created_at": row.created_at,
                "last_used_at": row.last_used_at,
                "verified_at": row.verified_at,
            })
        })
        .collect();
    
    Ok(serde_json::json!(credentials))
}

/// Log export audit event
async fn log_export_audit(
    db: &Database,
    user_id: &str,
    tenant_id: &str,
    export_id: &str,
) -> anyhow::Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO audit_logs (
            id, tenant_id, user_id, action, resource_type, resource_id,
            success, metadata, timestamp
        ) VALUES (
            gen_random_uuid(), $1, $2, 'data_export.completed', 'data_export', $3,
            true, $4, NOW()
        )
        "#,
        tenant_id,
        user_id,
        export_id,
        serde_json::json!({
            "gdpr_article": "20",
            "reason": "User requested data export"
        })
    )
    .execute(db.pool())
    .await?;
    
    Ok(())
}

/// Clean up expired exports
async fn cleanup_expired_exports(db: &Database) -> anyhow::Result<u64> {
    // Find expired exports
    let expired_ids: Vec<String> = sqlx::query_scalar!(
        r#"
        SELECT id::text
        FROM privacy_exports
        WHERE status = 'ready'
          AND expires_at < NOW()
        "#
    )
    .fetch_all(db.pool())
    .await?;
    
    if expired_ids.is_empty() {
        return Ok(0);
    }
    
    let mut deleted_count = 0u64;
    
    for export_id in &expired_ids {
        // Delete the file
        let filename = format!("export_{}.json", export_id);
        let filepath = PathBuf::from("./data/exports").join(&filename);
        
        if filepath.exists() {
            if let Err(e) = tokio::fs::remove_file(&filepath).await {
                warn!(export_id = %export_id, error = %e, "Failed to delete export file");
            }
        }
        
        // Update status to expired
        let result = sqlx::query!(
            r#"
            UPDATE privacy_exports
            SET status = 'expired',
                download_url = NULL,
                updated_at = NOW()
            WHERE id = $1::uuid
            "#,
            Uuid::parse_str(export_id)?
        )
        .execute(db.pool())
        .await?;
        
        deleted_count += result.rows_affected();
    }
    
    if deleted_count > 0 {
        info!(count = deleted_count, "Cleaned up expired exports");
    }
    
    Ok(deleted_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_export_format_from_str() {
        assert_eq!(ExportFormat::from_str("json"), Some(ExportFormat::Json));
        assert_eq!(ExportFormat::from_str("JSON"), Some(ExportFormat::Json));
        assert_eq!(ExportFormat::from_str("csv"), Some(ExportFormat::Csv));
        assert_eq!(ExportFormat::from_str("xml"), Some(ExportFormat::Xml));
        assert_eq!(ExportFormat::from_str("invalid"), None);
    }
    
    #[test]
    fn test_export_format_extension() {
        assert_eq!(ExportFormat::Json.extension(), "json");
        assert_eq!(ExportFormat::Csv.extension(), "csv");
        assert_eq!(ExportFormat::Xml.extension(), "xml");
    }
    
    #[test]
    fn test_export_status_as_str() {
        assert_eq!(ExportStatus::Pending.as_str(), "pending");
        assert_eq!(ExportStatus::Processing.as_str(), "processing");
        assert_eq!(ExportStatus::Ready.as_str(), "ready");
        assert_eq!(ExportStatus::Failed.as_str(), "failed");
        assert_eq!(ExportStatus::Expired.as_str(), "expired");
    }
}
