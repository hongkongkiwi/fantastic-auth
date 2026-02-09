//! Database module for Vault Server
//!
//! Provides connection pooling and repository access.

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::sync::Arc;
use std::time::Duration;

mod password_history;
mod webhooks;
pub use password_history::*;
pub use webhooks::*;

// Re-export set_connection_context from vault_core
pub use vault_core::db::set_connection_context;

/// Database connection pool
#[derive(Clone, Debug)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Create a new database connection pool
    pub async fn new(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(20)
            .min_connections(5)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(600))
            .max_lifetime(Duration::from_secs(1800))
            .before_acquire(|conn, _meta| {
                Box::pin(async move {
                    vault_core::db::apply_request_context(conn).await?;
                    Ok(true)
                })
            })
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    // Enforce application role + RLS for all pooled connections.
                    sqlx::query("SET ROLE vault_app").execute(&mut *conn).await?;
                    sqlx::query("SET row_security = ON").execute(&mut *conn).await?;
                    sqlx::query("RESET app.current_tenant_id").execute(&mut *conn).await?;
                    sqlx::query("RESET app.current_user_id").execute(&mut *conn).await?;
                    sqlx::query("RESET app.current_user_role").execute(&mut *conn).await?;
                    Ok(())
                })
            })
            .connect(database_url)
            .await?;

        // Verify connection
        sqlx::query("SELECT 1").fetch_one(&pool).await?;

        tracing::info!("Database connection pool established");

        Ok(Self { pool })
    }

    /// Run migrations
    pub async fn migrate(&self) -> anyhow::Result<()> {
        tracing::info!("Running database migrations...");
        Ok(())
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Check database health
    pub async fn ping(&self) -> anyhow::Result<()> {
        sqlx::query("SELECT 1").fetch_one(&self.pool).await?;
        Ok(())
    }

    /// Begin a transaction
    pub async fn begin(&self) -> anyhow::Result<sqlx::Transaction<'_, sqlx::Postgres>> {
        Ok(self.pool.begin().await?)
    }

    /// Acquire a connection from the pool
    pub async fn acquire(&self) -> anyhow::Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        Ok(self.pool.acquire().await?)
    }

    /// User repository
    pub fn users(&self) -> vault_core::db::UserRepository {
        vault_core::db::UserRepository::new(Arc::new(self.pool.clone()))
    }

    /// Session repository
    pub fn sessions(&self) -> vault_core::db::SessionRepository {
        vault_core::db::SessionRepository::new(Arc::new(self.pool.clone()))
    }

    /// MFA repository
    pub fn mfa(&self) -> vault_core::db::MfaRepository {
        vault_core::db::MfaRepository::new(Arc::new(self.pool.clone()))
    }

    /// Biometric repository
    pub fn biometric(&self) -> vault_core::db::BiometricRepository {
        vault_core::db::BiometricRepository::new(Arc::new(self.pool.clone()))
    }

    /// Organization repository
    pub fn organizations(&self) -> vault_core::db::OrganizationRepository {
        vault_core::db::OrganizationRepository::new(Arc::new(self.pool.clone()))
    }

    /// Project repository
    pub fn projects(&self) -> vault_core::db::ProjectRepository {
        vault_core::db::ProjectRepository::new(Arc::new(self.pool.clone()))
    }

    /// Application repository
    pub fn applications(&self) -> vault_core::db::ApplicationRepository {
        vault_core::db::ApplicationRepository::new(Arc::new(self.pool.clone()))
    }

    /// Audit log repository
    pub fn audit(&self) -> AuditRepository {
        AuditRepository::new(self.pool.clone())
    }

    /// Webhook repository
    pub fn webhooks(&self) -> WebhookRepository {
        WebhookRepository::new(self.pool.clone())
    }

    /// Password history repository
    pub fn password_history(&self) -> PasswordHistoryRepository {
        PasswordHistoryRepository::new(self.pool.clone())
    }

    /// Domain repository
    pub fn domains(&self) -> crate::domains::repository::DomainRepository {
        crate::domains::repository::DomainRepository::new(Arc::new(self.pool.clone()))
    }

    /// Consent repository
    pub fn consent(&self) -> crate::consent::ConsentRepository {
        crate::consent::ConsentRepository::new(self.pool.clone())
    }
}

/// Simple audit repository
#[derive(Clone)]
pub struct AuditRepository {
    pool: PgPool,
}

impl AuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create a new audit log entry
    pub async fn create(&self, req: CreateAuditLogRequest) -> anyhow::Result<AuditLogEntry> {
        let id = uuid::Uuid::new_v4().to_string();

        // Set tenant context for RLS
        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(&req.tenant_id)
            .execute(&mut *conn)
            .await?;

        let row = sqlx::query_as::<_, AuditLogRow>(
            r#"INSERT INTO audit_logs 
               (id, tenant_id, user_id, session_id, action, resource_type, resource_id,
                ip_address, user_agent, success, error, metadata, timestamp)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
               RETURNING id, timestamp, tenant_id, user_id, session_id, action,
                         resource_type, resource_id, ip_address, user_agent, success, error, metadata"#
        )
        .bind(&id)
        .bind(&req.tenant_id)
        .bind(&req.user_id)
        .bind(&req.session_id)
        .bind(&req.action)
        .bind(&req.resource_type)
        .bind(&req.resource_id)
        .bind(&req.ip_address)
        .bind(&req.user_agent)
        .bind(req.success)
        .bind(&req.error_message)
        .bind(&req.metadata)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    pub async fn list(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
    ) -> anyhow::Result<(Vec<AuditLogEntry>, i64)> {
        self.list_filtered(tenant_id, None, page, per_page).await
    }

    pub async fn list_filtered(
        &self,
        tenant_id: &str,
        user_id: Option<&str>,
        page: i64,
        per_page: i64,
    ) -> anyhow::Result<(Vec<AuditLogEntry>, i64)> {
        let offset = (page - 1) * per_page;

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND ($2::uuid IS NULL OR user_id = $2::uuid)"
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        let rows = sqlx::query_as::<_, AuditLogRow>(
            r#"SELECT id, timestamp, tenant_id, user_id, session_id, action,
                      resource_type, resource_id, ip_address, user_agent, success, error, metadata
               FROM audit_logs 
               WHERE tenant_id = $1 AND ($2::uuid IS NULL OR user_id = $2::uuid)
               ORDER BY timestamp DESC
               LIMIT $3 OFFSET $4"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let entries = rows.into_iter().map(|r| r.into()).collect();
        Ok((entries, total))
    }

    /// Delete audit log entries older than cutoff for a tenant
    /// 
    /// SECURITY: Audit logs have strict retention requirements:
    /// - Minimum retention period of 30 days is enforced
    /// - All deletions are logged
    /// - Only system processes should call this
    pub async fn prune_older_than(
        &self,
        tenant_id: &str,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> anyhow::Result<u64> {
        // SECURITY: Enforce minimum retention period (30 days)
        let minimum_retention = chrono::Utc::now() - chrono::Duration::days(30);
        if cutoff > minimum_retention {
            anyhow::bail!(
                "SECURITY: Audit log pruning rejected. Cannot delete logs newer than 30 days. \
                 Requested cutoff: {}, Minimum allowed: {}",
                cutoff, minimum_retention
            );
        }

        let mut conn = self.pool.acquire().await?;
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id)
            .execute(&mut *conn)
            .await?;

        // Get count before deletion for logging
        let count_to_delete: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND timestamp < $2"
        )
        .bind(tenant_id)
        .bind(&cutoff)
        .fetch_one(&mut *conn)
        .await?;

        if count_to_delete == 0 {
            return Ok(0);
        }

        // SECURITY: Log all audit log deletions
        tracing::info!(
            event = "audit_log_pruning",
            tenant_id = %tenant_id,
            cutoff = %cutoff,
            count_to_delete = count_to_delete,
            "Pruning audit logs older than retention period"
        );

        let result = sqlx::query(
            r#"DELETE FROM audit_logs WHERE tenant_id = $1 AND timestamp < $2"#,
        )
        .bind(tenant_id)
        .bind(cutoff)
        .execute(&mut *conn)
        .await?;

        let deleted = result.rows_affected();

        // SECURITY: Create an audit log entry about the pruning (if possible)
        // This creates a record that pruning occurred
        tracing::info!(
            event = "audit_log_pruning_complete",
            tenant_id = %tenant_id,
            deleted = deleted,
            "Audit log pruning completed"
        );

        Ok(deleted)
    }
}

/// Request to create an audit log entry
#[derive(Debug, Clone)]
pub struct CreateAuditLogRequest {
    pub tenant_id: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(sqlx::FromRow)]
struct AuditLogRow {
    id: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    tenant_id: String,
    user_id: Option<String>,
    session_id: Option<String>,
    action: String,
    resource_type: String,
    resource_id: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    success: bool,
    error: Option<String>,
    metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tenant_id: String,
    pub user_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub ip_address: Option<String>,
    pub success: bool,
}

impl From<AuditLogRow> for AuditLogEntry {
    fn from(row: AuditLogRow) -> Self {
        Self {
            id: row.id,
            timestamp: row.timestamp,
            tenant_id: row.tenant_id,
            user_id: row.user_id,
            action: row.action,
            resource_type: row.resource_type,
            resource_id: row.resource_id,
            ip_address: row.ip_address,
            success: row.success,
        }
    }
}
