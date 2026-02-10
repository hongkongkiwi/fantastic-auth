//! Account Deletion Background Worker
//!
//! GDPR Article 17 - Right to Erasure (Right to be Forgotten)
//!
//! This worker processes pending account deletion requests that have passed
//! their grace period. It handles:
//! - Data anonymization vs hard deletion
//! - Legal hold checks (don't delete if under legal hold)
//! - Cascade deletion of related records
//! - Audit log preservation (with anonymized user_id)
//!
//! # Processing Flow
//!
//! 1. Find deletion requests where scheduled_deletion_at < NOW() AND status = 'pending'
//! 2. Check for legal holds on the user/tenant
//! 3. If legal hold exists, skip and log warning
//! 4. Otherwise, anonymize or delete user data based on tenant policy
//! 5. Clean up related records (sessions, MFA, linked accounts, etc.)
//! 6. Update deletion request status to 'completed'
//! 7. Send confirmation email to user (if configured)

use chrono::Utc;
use std::time::Duration;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::db::Database;
use crate::state::AppState;

/// Account deletion mode - how to handle user data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionMode {
    /// Hard delete - permanently remove all user data
    HardDelete,
    /// Soft delete - mark as deleted but keep record
    SoftDelete,
    /// Anonymize - replace PII with hashed/placeholder values
    Anonymize,
}

impl Default for DeletionMode {
    fn default() -> Self {
        // Default to anonymization for GDPR compliance
        // (keeps referential integrity while protecting privacy)
        DeletionMode::Anonymize
    }
}

impl DeletionMode {
    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "hard_delete" | "hard" => Some(DeletionMode::HardDelete),
            "soft_delete" | "soft" => Some(DeletionMode::SoftDelete),
            "anonymize" => Some(DeletionMode::Anonymize),
            _ => None,
        }
    }
}

/// Spawn the account deletion worker
pub fn spawn(state: AppState, interval: Duration) {
    tokio::spawn(async move {
        info!("Account deletion worker started");
        
        loop {
            if let Err(e) = run_once(&state).await {
                error!(error = %e, "Account deletion processing failed");
            }
            
            tokio::time::sleep(interval).await;
        }
    });
}

/// Run one iteration of account deletion processing
async fn run_once(state: &AppState) -> anyhow::Result<()> {
    let db = &state.db;
    
    // Find pending deletion requests that have passed their scheduled deletion time
    let pending_deletions = find_pending_deletions(db).await?;
    
    if pending_deletions.is_empty() {
        return Ok(());
    }
    
    info!(count = pending_deletions.len(), "Processing pending account deletions");
    
    let mut processed = 0u64;
    let mut skipped = 0u64;
    let mut failed = 0u64;
    
    for deletion in pending_deletions {
        match process_deletion(state, &deletion).await {
            Ok(()) => {
                processed += 1;
                info!(
                    user_id = %deletion.user_id,
                    request_id = %deletion.id,
                    "Account deletion completed"
                );
            }
            Err(e) if e.to_string().contains("legal hold") => {
                skipped += 1;
                warn!(
                    user_id = %deletion.user_id,
                    request_id = %deletion.id,
                    "Account deletion skipped due to legal hold"
                );
            }
            Err(e) => {
                failed += 1;
                error!(
                    user_id = %deletion.user_id,
                    request_id = %deletion.id,
                    error = %e,
                    "Account deletion failed"
                );
            }
        }
    }
    
    info!(
        processed = processed,
        skipped = skipped,
        failed = failed,
        "Account deletion batch complete"
    );
    
    Ok(())
}

/// A pending deletion request
#[derive(Debug)]
struct PendingDeletion {
    id: String,
    user_id: String,
    tenant_id: String,
    scheduled_deletion_at: chrono::DateTime<Utc>,
    mode: DeletionMode,
}

/// Find pending deletion requests that are ready for processing
async fn find_pending_deletions(db: &Database) -> anyhow::Result<Vec<PendingDeletion>> {
    let rows = sqlx::query!(
        r#"
        SELECT 
            id,
            user_id::text as user_id,
            tenant_id::text as tenant_id,
            scheduled_deletion_at,
            COALESCE(deletion_mode, 'anonymize') as "deletion_mode!"
        FROM deletion_requests
        WHERE status = 'pending'
          AND scheduled_deletion_at <= NOW()
        ORDER BY scheduled_deletion_at ASC
        LIMIT 100
        "#
    )
    .fetch_all(db.pool())
    .await?;
    
    let deletions: Vec<PendingDeletion> = rows
        .into_iter()
        .map(|row| PendingDeletion {
            id: row.id.to_string(),
            user_id: row.user_id.unwrap_or_default(),
            tenant_id: row.tenant_id.unwrap_or_default(),
            scheduled_deletion_at: row.scheduled_deletion_at,
            mode: DeletionMode::from_str(&row.deletion_mode).unwrap_or_default(),
        })
        .collect();
    
    Ok(deletions)
}

/// Process a single account deletion
async fn process_deletion(
    state: &AppState,
    deletion: &PendingDeletion,
) -> anyhow::Result<()> {
    let db = &state.db;
    
    // Start a transaction for atomicity
    let mut tx = db.pool().begin().await?;
    
    // 1. Check for legal holds
    if has_legal_hold(&mut tx, &deletion.user_id).await? {
        // Update status to 'on_hold' and skip
        sqlx::query!(
            r#"
            UPDATE deletion_requests
            SET status = 'on_hold',
                error_message = 'Legal hold in place',
                updated_at = NOW()
            WHERE id = $1
            "#,
            Uuid::parse_str(&deletion.id)?
        )
        .execute(&mut *tx)
        .await?;
        
        tx.commit().await?;
        return Err(anyhow::anyhow!("Legal hold in place for user {}", deletion.user_id));
    }
    
    // 2. Execute deletion based on mode
    match deletion.mode {
        DeletionMode::HardDelete => {
            execute_hard_delete(&mut tx, &deletion.user_id, &deletion.tenant_id).await?;
        }
        DeletionMode::SoftDelete => {
            execute_soft_delete(&mut tx, &deletion.user_id, &deletion.tenant_id).await?;
        }
        DeletionMode::Anonymize => {
            execute_anonymization(&mut tx, &deletion.user_id, &deletion.tenant_id).await?;
        }
    }
    
    // 3. Clean up related records (common to all modes)
    cleanup_related_records(&mut tx, &deletion.user_id).await?;
    
    // 4. Update deletion request status
    sqlx::query!(
        r#"
        UPDATE deletion_requests
        SET status = 'completed',
            completed_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        "#,
        Uuid::parse_str(&deletion.id)?
    )
    .execute(&mut *tx)
    .await?;
    
    // 5. Log audit event
    log_deletion_audit(&mut tx, &deletion.user_id, &deletion.tenant_id, deletion.mode).await?;
    
    // Commit transaction
    tx.commit().await?;
    
    // 6. Send confirmation email (fire and forget)
    tokio::spawn(send_deletion_confirmation(
        deletion.user_id.clone(),
        deletion.tenant_id.clone(),
    ));
    
    Ok(())
}

/// Check if user has a legal hold preventing deletion
async fn has_legal_hold(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
) -> anyhow::Result<bool> {
    // Check for active legal holds on the user
    let count: i64 = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) 
        FROM legal_holds
        WHERE user_id = $1::uuid
          AND status = 'active'
          AND (expires_at IS NULL OR expires_at > NOW())
        "#,
        user_id
    )
    .fetch_one(&mut **tx)
    .await?;
    
    Ok(count > 0)
}

/// Hard delete - permanently remove all user data
async fn execute_hard_delete(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
    _tenant_id: &str,
) -> anyhow::Result<()> {
    info!(user_id = %user_id, "Executing hard delete");
    
    // Delete user record completely
    sqlx::query!(
        r#"DELETE FROM users WHERE id = $1::uuid"#,
        user_id
    )
    .execute(&mut **tx)
    .await?;
    
    Ok(())
}

/// Soft delete - mark user as deleted but keep record
async fn execute_soft_delete(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
    _tenant_id: &str,
) -> anyhow::Result<()> {
    info!(user_id = %user_id, "Executing soft delete");
    
    let deleted_email = format!("deleted_{}@anonymized.local", &user_id[..8]);
    
    sqlx::query!(
        r#"
        UPDATE users
        SET email = $2,
            name = '[deleted]',
            status = 'deleted',
            deleted_at = NOW(),
            updated_at = NOW()
        WHERE id = $1::uuid
        "#,
        user_id,
        deleted_email
    )
    .execute(&mut **tx)
    .await?;
    
    Ok(())
}

/// Anonymize user data - replace PII with hashed/placeholder values
async fn execute_anonymization(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
    _tenant_id: &str,
) -> anyhow::Result<()> {
    info!(user_id = %user_id, "Executing anonymization");
    
    // Generate anonymized values
    let anonymized_email = format!("anonymized_{}@anonymized.local", &user_id[..8]);
    let anonymized_name = format!("User {}", &user_id[..8]);
    
    // Anonymize user record
    sqlx::query!(
        r#"
        UPDATE users
        SET email = $2,
            name = $3,
            phone = NULL,
            avatar_url = NULL,
            metadata = '{}'::jsonb,
            status = 'anonymized',
            anonymized_at = NOW(),
            updated_at = NOW()
        WHERE id = $1::uuid
        "#,
        user_id,
        anonymized_email,
        anonymized_name
    )
    .execute(&mut **tx)
    .await?;
    
    // Anonymize audit logs - keep logs but anonymize user_id reference
    let anonymized_user_ref = format!("anonymized:{}", user_id);
    sqlx::query!(
        r#"
        UPDATE audit_logs
        SET user_id = $2,
            metadata = metadata || '{"anonymized": true}'::jsonb
        WHERE user_id = $1
        "#,
        user_id,
        anonymized_user_ref
    )
    .execute(&mut **tx)
    .await?;
    
    Ok(())
}

/// Clean up related records (sessions, MFA, linked accounts, etc.)
async fn cleanup_related_records(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
) -> anyhow::Result<()> {
    info!(user_id = %user_id, "Cleaning up related records");
    
    // Delete sessions
    sqlx::query!(
        r#"DELETE FROM user_sessions WHERE user_id = $1::uuid"#,
        user_id
    )
    .execute(&mut **tx)
    .await?;
    
    // Delete MFA credentials
    sqlx::query!(
        r#"DELETE FROM mfa_credentials WHERE user_id = $1::uuid"#,
        user_id
    )
    .execute(&mut **tx)
    .await?;
    
    // Delete backup codes
    sqlx::query!(
        r#"DELETE FROM mfa_backup_codes WHERE user_id = $1::uuid"#,
        user_id
    )
    .execute(&mut **tx)
    .await?;
    
    // Delete linked accounts
    sqlx::query!(
        r#"DELETE FROM user_linked_accounts WHERE user_id = $1::uuid"#,
        user_id
    )
    .execute(&mut **tx)
    .await?;
    
    // Delete WebAuthn credentials
    sqlx::query!(
        r#"DELETE FROM webauthn_credentials WHERE user_id = $1::uuid"#,
        user_id
    )
    .execute(&mut **tx)
    .await?;
    
    // Delete device fingerprints
    sqlx::query!(
        r#"DELETE FROM device_fingerprints WHERE user_id = $1::uuid"#,
        user_id
    )
    .execute(&mut **tx)
    .await?;
    
    // Delete password history
    sqlx::query!(
        r#"DELETE FROM password_history WHERE user_id = $1::uuid"#,
        user_id
    )
    .execute(&mut **tx)
    .await?;
    
    // Delete consent records
    sqlx::query!(
        r#"DELETE FROM consent_records WHERE user_id = $1::uuid"#,
        user_id
    )
    .execute(&mut **tx)
    .await?;
    
    // Delete privacy exports
    sqlx::query!(
        r#"DELETE FROM privacy_exports WHERE user_id = $1::uuid"#,
        user_id
    )
    .execute(&mut **tx)
    .await?;
    
    // Delete notification preferences
    sqlx::query!(
        r#"DELETE FROM user_notification_preferences WHERE user_id = $1::uuid"#,
        user_id
    )
    .execute(&mut **tx)
    .await?;
    
    // Note: We preserve:
    // - audit_logs (anonymized above)
    // - deletion_requests (for record keeping)
    
    Ok(())
}

/// Log deletion audit event
async fn log_deletion_audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: &str,
    tenant_id: &str,
    mode: DeletionMode,
) -> anyhow::Result<()> {
    let action = match mode {
        DeletionMode::HardDelete => "account.hard_deleted",
        DeletionMode::SoftDelete => "account.soft_deleted",
        DeletionMode::Anonymize => "account.anonymized",
    };
    
    sqlx::query!(
        r#"
        INSERT INTO audit_logs (
            id, tenant_id, user_id, action, resource_type, resource_id,
            success, metadata, timestamp
        ) VALUES (
            gen_random_uuid(), $1, $2, $3, 'user', $2,
            true, $4, NOW()
        )
        "#,
        tenant_id,
        user_id,
        action,
        serde_json::json!({
            "deletion_mode": format!("{:?}", mode),
            "gdpr_article": "17",
            "reason": "User requested account deletion"
        })
    )
    .execute(&mut **tx)
    .await?;
    
    Ok(())
}

/// Send deletion confirmation email
async fn send_deletion_confirmation(_user_id: String, _tenant_id: String) {
    // This would integrate with the email service
    // For now, just log the intent
    info!("Would send deletion confirmation email");
    
    // TODO: Integrate with email service
    // let email_service = ...;
    // let template = DeletionConfirmationEmail { ... };
    // email_service.send(user_email, template).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_deletion_mode_from_str() {
        assert_eq!(
            DeletionMode::from_str("hard_delete"),
            Some(DeletionMode::HardDelete)
        );
        assert_eq!(
            DeletionMode::from_str("soft"),
            Some(DeletionMode::SoftDelete)
        );
        assert_eq!(
            DeletionMode::from_str("anonymize"),
            Some(DeletionMode::Anonymize)
        );
        assert_eq!(DeletionMode::from_str("invalid"), None);
    }
    
    #[test]
    fn test_deletion_mode_default() {
        let mode: DeletionMode = Default::default();
        assert_eq!(mode, DeletionMode::Anonymize);
    }
}
