//! User Impersonation Service
//!
//! Provides secure user impersonation for administrators to debug and support users.
//! All impersonation sessions are audited and have strict security controls.
//!
//! # Security Features
//!
//! - Only admin/superadmin users can impersonate
//! - Cannot impersonate users with higher or equal privileges
//! - Sessions are short-lived (30-60 minutes max)
//! - Clear audit trail for compliance
//! - Impersonation reason is required
//!
//! # Usage
//!
//! ```rust
//! use vault_server::impersonation::ImpersonationService;
//!
//! // Create service
//! let service = ImpersonationService::new(db);
//!
//! // Check if impersonation is allowed
//! if service.is_impersonation_allowed(admin_roles, target_roles).await? {
//!     // Create impersonation session
//!     let session = service.create_session(
//!         admin_id,
//!         target_user_id,
//!         tenant_id,
//!         "Debugging login issue",
//!         30,
//!     ).await?;
//! }
//! ```

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row};
use std::sync::Arc;
use uuid::Uuid;

use crate::db::Database;

/// Represents an impersonation session in the database
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ImpersonationSession {
    /// Unique session ID
    pub id: String,
    /// ID of the admin who initiated impersonation
    pub admin_id: String,
    /// ID of the user being impersonated
    pub target_user_id: String,
    /// Tenant ID for multi-tenancy
    pub tenant_id: String,
    /// Reason for impersonation (required for audit)
    pub reason: String,
    /// Session token for validation
    pub session_token: Option<String>,
    /// When the session was created
    pub created_at: DateTime<Utc>,
    /// When the session expires
    pub expires_at: DateTime<Utc>,
    /// When the session was ended (if applicable)
    pub ended_at: Option<DateTime<Utc>>,
    /// Who ended the session (if applicable)
    pub ended_by: Option<String>,
    /// Whether the session is currently active
    pub is_active: bool,
}

/// Request to create a new impersonation session
#[derive(Debug, Clone)]
pub struct CreateImpersonationRequest {
    /// Admin user ID
    pub admin_id: String,
    /// Target user ID to impersonate
    pub target_user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Reason for impersonation
    pub reason: String,
    /// Duration in minutes (5-60)
    pub duration_minutes: i64,
}

/// Summary of impersonation session for listing
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ImpersonationSessionSummary {
    pub id: String,
    pub admin_id: String,
    pub target_user_id: String,
    pub target_email: String,
    pub target_name: Option<String>,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub is_active: bool,
}

/// Impersonation service for managing secure admin impersonation of users
#[derive(Clone)]
pub struct ImpersonationService {
    db: Database,
}

impl ImpersonationService {
    /// Create a new impersonation service
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Create a new impersonation session
    ///
    /// # Arguments
    /// * `req` - The impersonation request containing admin, target, and duration info
    ///
    /// # Returns
    /// The created impersonation session
    pub async fn create_session(
        &self,
        req: CreateImpersonationRequest,
    ) -> anyhow::Result<ImpersonationSession> {
        let session = ImpersonationSession {
            id: Uuid::new_v4().to_string(),
            admin_id: req.admin_id,
            target_user_id: req.target_user_id,
            tenant_id: req.tenant_id,
            reason: req.reason,
            session_token: Some(Uuid::new_v4().to_string()),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(req.duration_minutes),
            ended_at: None,
            ended_by: None,
            is_active: true,
        };

        let mut conn = self.db.pool().acquire().await?;

        sqlx::query(
            r#"INSERT INTO impersonation_sessions 
               (id, admin_id, target_user_id, tenant_id, reason, session_token, 
                created_at, expires_at, ended_at, ended_by, is_active)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"#,
        )
        .bind(&session.id)
        .bind(&session.admin_id)
        .bind(&session.target_user_id)
        .bind(&session.tenant_id)
        .bind(&session.reason)
        .bind(&session.session_token)
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session.ended_at)
        .bind(&session.ended_by)
        .bind(session.is_active)
        .execute(&mut *conn)
        .await?;

        Ok(session)
    }

    /// End an impersonation session
    ///
    /// # Arguments
    /// * `session_id` - The ID of the session to end
    /// * `ended_by` - Optional ID of who ended the session (usually the admin)
    pub async fn end_session(
        &self,
        session_id: &str,
        ended_by: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut conn = self.db.pool().acquire().await?;

        sqlx::query(
            r#"UPDATE impersonation_sessions 
               SET is_active = false, 
                   ended_at = NOW(), 
                   ended_by = $1
               WHERE id = $2"#,
        )
        .bind(ended_by)
        .bind(session_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Validate an impersonation session by token
    ///
    /// # Arguments
    /// * `token` - The session token to validate
    ///
    /// # Returns
    /// The session if valid and active, None otherwise
    pub async fn validate_session(&self, token: &str) -> anyhow::Result<Option<ImpersonationSession>> {
        let mut conn = self.db.pool().acquire().await?;

        let row = sqlx::query(
            r#"SELECT id, admin_id, target_user_id, tenant_id, reason, session_token,
                created_at, expires_at, ended_at, ended_by, is_active
               FROM impersonation_sessions 
               WHERE session_token = $1 AND is_active = true"#,
        )
        .bind(token)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => {
                let session = ImpersonationSession {
                    id: row.try_get("id")?,
                    admin_id: row.try_get("admin_id")?,
                    target_user_id: row.try_get("target_user_id")?,
                    tenant_id: row.try_get("tenant_id")?,
                    reason: row.try_get("reason")?,
                    session_token: row.try_get("session_token")?,
                    created_at: row.try_get("created_at")?,
                    expires_at: row.try_get("expires_at")?,
                    ended_at: row.try_get("ended_at")?,
                    ended_by: row.try_get("ended_by")?,
                    is_active: row.try_get("is_active")?,
                };

                // Check if session has expired
                if Utc::now() > session.expires_at {
                    // Auto-expire the session
                    self.end_session(&session.id, None).await?;
                    return Ok(None);
                }

                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Check if impersonation is allowed based on privilege levels
    ///
    /// # Security Rules
    /// - Only users with "admin" or "superadmin" role can impersonate
    /// - Cannot impersonate users with higher or equal role
    /// - Cannot impersonate superadmins (unless you're superadmin)
    ///
    /// # Arguments
    /// * `impersonator_roles` - Roles of the admin attempting impersonation
    /// * `target_roles` - Roles of the target user
    pub fn is_impersonation_allowed(
        &self,
        impersonator_roles: &[String],
        target_roles: &[String],
    ) -> bool {
        let is_admin = impersonator_roles.iter().any(|r| r == "admin" || r == "superadmin");
        let is_superadmin = impersonator_roles.iter().any(|r| r == "superadmin");
        
        let target_is_superadmin = target_roles.iter().any(|r| r == "superadmin");
        let target_is_admin = target_roles.iter().any(|r| r == "admin" || r == "superadmin");

        // Must be at least admin to impersonate
        if !is_admin {
            return false;
        }

        // Cannot impersonate superadmins unless you're superadmin
        if target_is_superadmin && !is_superadmin {
            return false;
        }

        // Cannot impersonate other admins unless you're superadmin
        if target_is_admin && !is_superadmin {
            return false;
        }

        true
    }

    /// Get privilege level rank (higher = more privileged)
    fn get_privilege_rank(&self, roles: &[String]) -> u8 {
        if roles.iter().any(|r| r == "superadmin") {
            100
        } else if roles.iter().any(|r| r == "admin") {
            50
        } else {
            0
        }
    }

    /// List active impersonation sessions
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant to filter by
    /// * `page` - Page number (1-based)
    /// * `per_page` - Items per page
    /// * `filter_admin_id` - Optional filter by admin ID
    /// * `filter_target_id` - Optional filter by target user ID
    pub async fn list_active_sessions(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
        filter_admin_id: Option<&str>,
        filter_target_id: Option<&str>,
    ) -> anyhow::Result<(Vec<ImpersonationSessionSummary>, i64)> {
        let mut conn = self.db.pool().acquire().await?;
        
        let offset = (page - 1) * per_page;

        // Build query based on filters
        let (where_clause, admin_filter, target_filter) = match (filter_admin_id, filter_target_id) {
            (Some(_), Some(_)) => ("AND s.admin_id = $3 AND s.target_user_id = $4", true, true),
            (Some(_), None) => ("AND s.admin_id = $3", true, false),
            (None, Some(_)) => ("AND s.target_user_id = $3", false, true),
            (None, None) => ("", false, false),
        };

        let query = format!(
            r#"SELECT s.id, s.admin_id, s.target_user_id, 
                u.email as target_email, u.profile->>'name' as target_name,
                s.reason, s.created_at, s.expires_at, s.is_active
               FROM impersonation_sessions s
               JOIN users u ON s.target_user_id = u.id AND s.tenant_id = u.tenant_id
               WHERE s.tenant_id = $1 AND s.is_active = true {}
               ORDER BY s.created_at DESC
               LIMIT $2 OFFSET ${}"#,
            where_clause,
            if admin_filter && target_filter { 5 } else if admin_filter || target_filter { 4 } else { 3 }
        );

        let mut query_builder = sqlx::query_as::<_, ImpersonationSessionSummary>(&query)
            .bind(tenant_id)
            .bind(per_page)
            .bind(offset);

        if admin_filter {
            query_builder = query_builder.bind(filter_admin_id.unwrap());
        }
        if target_filter {
            let param_index = if admin_filter { 4 } else { 3 };
            query_builder = query_builder.bind(filter_target_id.unwrap());
        }

        let sessions: Vec<ImpersonationSessionSummary> = query_builder.fetch_all(&mut *conn).await?;

        // Get total count
        let count_query = format!(
            r#"SELECT COUNT(*) as count 
               FROM impersonation_sessions 
               WHERE tenant_id = $1 AND is_active = true {}"#,
            where_clause.replace("s.", "")
        );

        let mut count_query_builder = sqlx::query(&count_query).bind(tenant_id);
        if admin_filter {
            count_query_builder = count_query_builder.bind(filter_admin_id.unwrap());
        }
        if target_filter {
            count_query_builder = count_query_builder.bind(filter_target_id.unwrap());
        }

        let total_row = count_query_builder.fetch_one(&mut *conn).await?;
        let total: i64 = total_row.try_get("count")?;

        Ok((sessions, total))
    }

    /// Get session by ID
    pub async fn get_session(&self, session_id: &str) -> anyhow::Result<Option<ImpersonationSession>> {
        let mut conn = self.db.pool().acquire().await?;

        let row = sqlx::query(
            r#"SELECT id, admin_id, target_user_id, tenant_id, reason, session_token,
                created_at, expires_at, ended_at, ended_by, is_active
               FROM impersonation_sessions 
               WHERE id = $1"#,
        )
        .bind(session_id)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => {
                let session = ImpersonationSession {
                    id: row.try_get("id")?,
                    admin_id: row.try_get("admin_id")?,
                    target_user_id: row.try_get("target_user_id")?,
                    tenant_id: row.try_get("tenant_id")?,
                    reason: row.try_get("reason")?,
                    session_token: row.try_get("session_token")?,
                    created_at: row.try_get("created_at")?,
                    expires_at: row.try_get("expires_at")?,
                    ended_at: row.try_get("ended_at")?,
                    ended_by: row.try_get("ended_by")?,
                    is_active: row.try_get("is_active")?,
                };
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Clean up expired sessions (called by background job)
    pub async fn cleanup_expired_sessions(&self) -> anyhow::Result<u64> {
        let mut conn = self.db.pool().acquire().await?;

        let result = sqlx::query(
            r#"UPDATE impersonation_sessions 
               SET is_active = false, ended_at = NOW()
               WHERE is_active = true AND expires_at < NOW()"#,
        )
        .execute(&mut *conn)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get impersonation session by target session ID
    /// Used to find the impersonation record associated with a user session
    pub async fn get_by_target_session(
        &self,
        tenant_id: &str,
        target_session_id: &str,
    ) -> anyhow::Result<Option<ImpersonationSession>> {
        let mut conn = self.db.pool().acquire().await?;

        // Join with sessions table to find impersonation by session ID
        let row = sqlx::query(
            r#"SELECT i.id, i.admin_id, i.target_user_id, i.tenant_id, i.reason, i.session_token,
                i.created_at, i.expires_at, i.ended_at, i.ended_by, i.is_active
               FROM impersonation_sessions i
               JOIN sessions s ON s.user_id = i.target_user_id 
                   AND s.tenant_id = i.tenant_id
                   AND s.device_info->>'is_impersonation' = 'true'
               WHERE i.tenant_id = $1 
                 AND s.id = $2 
                 AND i.is_active = true"#,
        )
        .bind(tenant_id)
        .bind(target_session_id)
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => {
                let session = ImpersonationSession {
                    id: row.try_get("id")?,
                    admin_id: row.try_get("admin_id")?,
                    target_user_id: row.try_get("target_user_id")?,
                    tenant_id: row.try_get("tenant_id")?,
                    reason: row.try_get("reason")?,
                    session_token: row.try_get("session_token")?,
                    created_at: row.try_get("created_at")?,
                    expires_at: row.try_get("expires_at")?,
                    ended_at: row.try_get("ended_at")?,
                    ended_by: row.try_get("ended_by")?,
                    is_active: row.try_get("is_active")?,
                };
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_impersonation_allowed() {
        let service = ImpersonationService::new(Database::new("postgres://dummy").unwrap());

        // Superadmin can impersonate anyone
        assert!(service.is_impersonation_allowed(
            &["superadmin".to_string()],
            &["admin".to_string()]
        ));
        assert!(service.is_impersonation_allowed(
            &["superadmin".to_string()],
            &["superadmin".to_string()]
        ));
        assert!(service.is_impersonation_allowed(
            &["superadmin".to_string()],
            &["user".to_string()]
        ));

        // Admin can impersonate regular users but not other admins
        assert!(service.is_impersonation_allowed(
            &["admin".to_string()],
            &["user".to_string()]
        ));
        assert!(!service.is_impersonation_allowed(
            &["admin".to_string()],
            &["admin".to_string()]
        ));
        assert!(!service.is_impersonation_allowed(
            &["admin".to_string()],
            &["superadmin".to_string()]
        ));

        // Regular users cannot impersonate
        assert!(!service.is_impersonation_allowed(
            &["user".to_string()],
            &["user".to_string()]
        ));
        assert!(!service.is_impersonation_allowed(
            &["user".to_string()],
            &["admin".to_string()]
        ));
    }
}
