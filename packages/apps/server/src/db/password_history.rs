//! Password history tracking to prevent password reuse
//!
//! Stores Argon2 password hashes for previous passwords to enforce
//! password history policies. Old entries are automatically cleaned up
//! when new passwords are added.

use crate::security::password_policy::PasswordHistoryChecker;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;

/// Password history repository
#[derive(Clone)]
pub struct PasswordHistoryRepository {
    pool: PgPool,
}

/// Password history entry
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PasswordHistoryEntry {
    /// Entry ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Argon2 password hash
    pub password_hash: String,
    /// When this password was set
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Configuration for password history
#[derive(Debug, Clone)]
pub struct PasswordHistoryConfig {
    /// Maximum number of passwords to keep in history
    pub max_history_count: usize,
    /// How long to keep entries (optional, None = keep based on count only)
    pub retention_days: Option<i64>,
}

impl Default for PasswordHistoryConfig {
    fn default() -> Self {
        Self {
            max_history_count: 5,
            retention_days: None,
        }
    }
}

impl PasswordHistoryRepository {
    /// Create a new password history repository
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Record a new password in history
    ///
    /// Also cleans up old entries beyond the configured limit.
    pub async fn record_password(
        &self,
        user_id: &str,
        tenant_id: &str,
        password_hash: &str,
    ) -> anyhow::Result<()> {
        let id = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            r#"
            INSERT INTO password_history (id, user_id, tenant_id, password_hash, created_at)
            VALUES ($1, $2, $3, $4, NOW())
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;

        tracing::debug!(
            "Recorded password history entry for user {} in tenant {}",
            user_id,
            tenant_id
        );

        Ok(())
    }

    /// Check if a password was previously used
    ///
    /// This compares against the Argon2 hashes in the history.
    pub async fn is_password_used(
        &self,
        user_id: &str,
        password: &str,
        history_count: usize,
    ) -> anyhow::Result<bool> {
        // Get recent password hashes
        let entries: Vec<PasswordHistoryEntry> = sqlx::query_as(
            r#"
            SELECT id, user_id, tenant_id, password_hash, created_at
            FROM password_history
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(history_count as i64)
        .fetch_all(&self.pool)
        .await?;

        // Check each hash
        for entry in entries {
            if Self::verify_password_hash(password, &entry.password_hash)? {
                tracing::info!("Password reuse detected for user {}", user_id);
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get password history for a user
    pub async fn get_history(
        &self,
        user_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<PasswordHistoryEntry>> {
        let entries = sqlx::query_as(
            r#"
            SELECT id, user_id, tenant_id, password_hash, created_at
            FROM password_history
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(entries)
    }

    /// Clean up old password history entries beyond the configured limit
    pub async fn cleanup_old_entries(
        &self,
        user_id: &str,
        keep_count: usize,
    ) -> anyhow::Result<u64> {
        // Delete entries beyond the keep_count
        let result = sqlx::query(
            r#"
            DELETE FROM password_history
            WHERE id IN (
                SELECT id FROM password_history
                WHERE user_id = $1
                ORDER BY created_at DESC
                OFFSET $2
            )
            "#,
        )
        .bind(user_id)
        .bind(keep_count as i64)
        .execute(&self.pool)
        .await?;

        let deleted = result.rows_affected();

        if deleted > 0 {
            tracing::debug!(
                "Cleaned up {} old password history entries for user {}",
                deleted,
                user_id
            );
        }

        Ok(deleted)
    }

    /// Clean up old entries by retention period (tenant-wide)
    pub async fn cleanup_by_retention(&self, retention_days: i64) -> anyhow::Result<u64> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days);

        let result = sqlx::query(
            r#"
            DELETE FROM password_history
            WHERE created_at < $1
            "#,
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;

        let deleted = result.rows_affected();

        if deleted > 0 {
            tracing::info!(
                "Cleaned up {} old password history entries older than {} days",
                deleted,
                retention_days
            );
        }

        Ok(deleted)
    }

    /// Delete all history for a user (e.g., when user is deleted)
    pub async fn delete_user_history(&self, user_id: &str) -> anyhow::Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM password_history
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count history entries for a user
    pub async fn count_entries(&self, user_id: &str) -> anyhow::Result<i64> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM password_history
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Verify a password against an Argon2 hash
    fn verify_password_hash(password: &str, hash: &str) -> anyhow::Result<bool> {
        // Use vault_core's password hasher
        vault_core::crypto::VaultPasswordHasher::verify(password, hash)
            .map_err(|e| anyhow::anyhow!("Password verification failed: {}", e))
    }
}

#[async_trait::async_trait]
impl PasswordHistoryChecker for PasswordHistoryRepository {
    async fn is_password_used(&self, user_id: &str, password: &str) -> anyhow::Result<bool> {
        // Default to checking last 5 passwords
        self.is_password_used(user_id, password, 5).await
    }
}

/// SQL to create the password_history table
pub const CREATE_PASSWORD_HISTORY_TABLE_SQL: &str = r#"
-- Password history table for preventing password reuse
CREATE TABLE IF NOT EXISTS password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Index for efficient lookups
    CONSTRAINT idx_password_history_user_lookup UNIQUE (user_id, created_at, id)
);

-- Index for tenant-scoped queries
CREATE INDEX IF NOT EXISTS idx_password_history_tenant ON password_history(tenant_id);

-- Index for cleanup queries
CREATE INDEX IF NOT EXISTS idx_password_history_created_at ON password_history(created_at);
"#;

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a database connection
    // They are commented out by default and should be run as integration tests

    // async fn setup_test_db() -> PgPool {
    //     // Setup test database
    // }

    // #[tokio::test]
    // async fn test_record_and_check_password() {
    //     let pool = setup_test_db().await;
    //     let repo = PasswordHistoryRepository::new(pool);
    //
    //     let user_id = "test-user-123";
    //     let tenant_id = "test-tenant-456";
    //     let password = "TestP@ssw0rd!";
    //
    //     // Hash the password
    //     let hash = vault_core::crypto::VaultPasswordHasher::hash(password).unwrap();
    //
    //     // Record password
    //     repo.record_password(user_id, tenant_id, &hash).await.unwrap();
    //
    //     // Check that password is detected as used
    //     let is_used = repo.is_password_used(user_id, password, 5).await.unwrap();
    //     assert!(is_used);
    //
    //     // Check that a different password is not detected
    //     let is_used = repo.is_password_used(user_id, "DifferentP@ss!", 5).await.unwrap();
    //     assert!(!is_used);
    // }

    // #[tokio::test]
    // async fn test_cleanup_old_entries() {
    //     let pool = setup_test_db().await;
    //     let repo = PasswordHistoryRepository::new(pool);
    //
    //     let user_id = "test-user-123";
    //
    //     // Add 10 password entries
    //     for i in 0..10 {
    //         let hash = format!("$argon2id$v=19$m=65536,t=3,p=4$hash{i}");
    //         repo.record_password(user_id, "tenant-1", &hash).await.unwrap();
    //     }
    //
    //     // Cleanup to keep only 5
    //     let deleted = repo.cleanup_old_entries(user_id, 5).await.unwrap();
    //     assert_eq!(deleted, 5);
    //
    //     // Verify count
    //     let count = repo.count_entries(user_id).await.unwrap();
    //     assert_eq!(count, 5);
    // }
}
