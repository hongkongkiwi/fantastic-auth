//! Session repository implementation

use crate::db::set_connection_context;
use crate::error::{Result, VaultError};
use sqlx::{FromRow, PgPool, Row};
use std::sync::Arc;

/// SQL column list for session queries
/// 
/// This constant eliminates duplication across all session queries.
/// When adding new columns, update this constant and the Session struct.
const SESSION_COLUMNS: &str = r#"
    id::text as id, 
    tenant_id::text as tenant_id, 
    user_id::text as user_id, 
    status as "status: SessionStatus", 
    access_token_jti, 
    refresh_token_hash, 
    token_family,
    ip_address, 
    user_agent, 
    device_fingerprint, 
    device_info, 
    location,
    mfa_verified, 
    mfa_verified_at, 
    created_at, 
    updated_at, 
    last_activity_at,
    expires_at, 
    revoked_at, 
    revoked_reason,
    created_ip, 
    created_device_hash, 
    bind_to_ip, 
    bind_to_device, 
    binding_violation_count
"#;

/// Repository for session operations
pub struct SessionRepository {
    pool: Arc<PgPool>,
}

/// Session status
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "session_status", rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Expired,
    Revoked,
    Rotated,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Active => write!(f, "active"),
            SessionStatus::Expired => write!(f, "expired"),
            SessionStatus::Revoked => write!(f, "revoked"),
            SessionStatus::Rotated => write!(f, "rotated"),
        }
    }
}

/// Session row from database
#[derive(Debug, FromRow)]
pub struct Session {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub status: SessionStatus,
    pub access_token_jti: String,
    pub refresh_token_hash: String,
    pub token_family: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_fingerprint: Option<String>,
    pub device_info: serde_json::Value,
    pub location: Option<serde_json::Value>,
    pub mfa_verified: bool,
    pub mfa_verified_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub last_activity_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_reason: Option<String>,
    // Session binding fields
    pub created_ip: Option<String>,
    pub created_device_hash: Option<String>,
    pub bind_to_ip: bool,
    pub bind_to_device: bool,
    pub binding_violation_count: i32,
}

/// Create session request
#[derive(Debug, Clone)]
pub struct CreateSessionRequest {
    pub tenant_id: String,
    pub user_id: String,
    pub access_token_jti: String,
    pub refresh_token_hash: String,
    pub token_family: String,
    pub ip_address: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
    pub device_fingerprint: Option<String>,
    pub device_info: serde_json::Value,
    pub location: Option<serde_json::Value>,
    pub mfa_verified: bool,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    // Session binding fields
    pub bind_to_ip: bool,
    pub bind_to_device: bool,
}

impl SessionRepository {
    /// Create a new session repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    async fn tenant_conn(
        &self,
        tenant_id: &str,
    ) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        let mut conn = self.pool.acquire().await?;
        set_connection_context(&mut conn, tenant_id).await?;
        Ok(conn)
    }

    /// Create a new session
    pub async fn create(&self, req: CreateSessionRequest) -> Result<Session> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(&req.tenant_id).await?;

        // Use the IP as created_ip and device_fingerprint as created_device_hash
        let created_ip = req.ip_address.map(|ip| ip.to_string());
        let created_device_hash = req.device_fingerprint.clone();

        let session = sqlx::query_as::<_, Session>(
            r#"
            INSERT INTO sessions (
                id, tenant_id, user_id, status, access_token_jti, refresh_token_hash,
                token_family, ip_address, user_agent, device_fingerprint, device_info,
                location, mfa_verified, mfa_verified_at, created_at, last_activity_at,
                expires_at, revoked_at, revoked_reason,
                created_ip, created_device_hash, bind_to_ip, bind_to_device, binding_violation_count
            ) VALUES (
                $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8::inet, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
                $20::inet, $21, $22, $23, $24
            )
            RETURNING 
                $SESSION_COLUMNS
            "#
        )
        .bind(&id)
        .bind(&req.tenant_id)
        .bind(&req.user_id)
        .bind(SessionStatus::Active)
        .bind(&req.access_token_jti)
        .bind(&req.refresh_token_hash)
        .bind(&req.token_family)
        .bind(req.ip_address.map(|ip| ip.to_string()))
        .bind(&req.user_agent)
        .bind(&req.device_fingerprint)
        .bind(&req.device_info)
        .bind(&req.location)
        .bind(req.mfa_verified)
        .bind(if req.mfa_verified { Some(now) } else { None })
        .bind(now)
        .bind(now)
        .bind(req.expires_at)
        .bind(None::<chrono::DateTime<chrono::Utc>>)
        .bind(None::<String>)
        .bind(&created_ip)
        .bind(&created_device_hash)
        .bind(req.bind_to_ip)
        .bind(req.bind_to_device)
        .bind(0i32)
        .fetch_one(&mut *conn)
        .await?;

        Ok(session)
    }

    /// Find session by ID
    pub async fn find_by_id(&self, tenant_id: &str, session_id: &str) -> Result<Session> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let session = sqlx::query_as::<_, Session>(
            r#"
            SELECT 
                $SESSION_COLUMNS
            FROM sessions 
            WHERE tenant_id = $1 AND id = $2
            "#
        )
        .bind(tenant_id)
        .bind(session_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| VaultError::not_found("Session", session_id))?;

        Ok(session)
    }

    /// Find session by refresh token hash
    pub async fn find_by_refresh_token_hash(&self, tenant_id: &str, hash: &str) -> Result<Session> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let session = sqlx::query_as::<_, Session>(
            r#"
            SELECT 
                $SESSION_COLUMNS
            FROM sessions 
            WHERE tenant_id = $1 AND refresh_token_hash = $2 AND status = 'active'
            "#
        )
        .bind(tenant_id)
        .bind(hash)
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| VaultError::authentication("Invalid session"))?;

        Ok(session)
    }

    /// Rotate session tokens atomically
    /// 
    /// SECURITY: This implements refresh token rotation to prevent replay attacks.
    /// The old refresh token hash is validated, and new tokens are generated.
    /// Returns the updated session with new token hashes.
    pub async fn rotate_tokens(
        &self,
        tenant_id: &str,
        session_id: &str,
        old_refresh_token_hash: &str,
        new_access_token_jti: String,
        new_refresh_token_hash: String,
    ) -> Result<Session> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        // SECURITY: Atomically update only if the old hash matches
        // This prevents race conditions and replay attacks
        let session = sqlx::query_as::<_, Session>(
            r#"
            UPDATE sessions SET
                access_token_jti = $4,
                refresh_token_hash = $5,
                updated_at = $6,
                last_activity_at = $6
            WHERE tenant_id = $1 AND id = $2 AND refresh_token_hash = $3 AND status = 'active'
            RETURNING 
                $SESSION_COLUMNS
            "#
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(old_refresh_token_hash)
        .bind(new_access_token_jti)
        .bind(new_refresh_token_hash)
        .bind(now)
        .fetch_optional(&mut *conn)
        .await?;

        match session {
            Some(s) => Ok(s),
            None => Err(VaultError::authentication("Invalid or reused refresh token")),
        }
    }

    /// Update session (for token rotation)
    pub async fn update(
        &self,
        tenant_id: &str,
        session_id: &str,
        access_token_jti: Option<String>,
        refresh_token_hash: Option<String>,
    ) -> Result<Session> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        let session = sqlx::query_as::<_, Session>(
            r#"
            UPDATE sessions SET
                access_token_jti = COALESCE($3, access_token_jti),
                refresh_token_hash = COALESCE($4, refresh_token_hash),
                updated_at = $5
            WHERE tenant_id = $1 AND id = $2
            RETURNING 
                $SESSION_COLUMNS
            "#
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(access_token_jti)
        .bind(refresh_token_hash)
        .bind(now)
        .fetch_one(&mut *conn)
        .await?;

        Ok(session)
    }

    /// Update last activity
    pub async fn update_activity(&self, tenant_id: &str, session_id: &str) -> Result<()> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        sqlx::query(
            "UPDATE sessions SET last_activity_at = $2, updated_at = $2 WHERE tenant_id = $1 AND id = $3"
        )
        .bind(tenant_id)
        .bind(now)
        .bind(session_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Revoke session
    pub async fn revoke(
        &self,
        tenant_id: &str,
        session_id: &str,
        reason: Option<&str>,
    ) -> Result<()> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        sqlx::query(
            r#"
            UPDATE sessions SET
                status = 'revoked',
                revoked_at = $2,
                revoked_reason = $3,
                updated_at = $2
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(now)
        .bind(reason)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Revoke all sessions for user except current
    pub async fn revoke_all_except(
        &self,
        tenant_id: &str,
        user_id: &str,
        except_session_id: &str,
        reason: Option<&str>,
    ) -> Result<u64> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        let result = sqlx::query(
            r#"
            UPDATE sessions SET
                status = 'revoked',
                revoked_at = $3,
                revoked_reason = $4,
                updated_at = $3
            WHERE tenant_id = $1 AND user_id = $2 AND id != $3 AND status = 'active'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(except_session_id)
        .bind(now)
        .bind(reason)
        .execute(&mut *conn)
        .await?;

        Ok(result.rows_affected())
    }

    /// Revoke all sessions for user
    pub async fn revoke_all_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        reason: Option<&str>,
    ) -> Result<u64> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        let result = sqlx::query(
            r#"
            UPDATE sessions SET
                status = 'revoked',
                revoked_at = $2,
                revoked_reason = $3,
                updated_at = $2
            WHERE tenant_id = $1 AND user_id = $2 AND status = 'active'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(now)
        .bind(reason)
        .execute(&mut *conn)
        .await?;

        Ok(result.rows_affected())
    }

    /// List sessions for user
    pub async fn list_by_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        active_only: bool,
    ) -> Result<Vec<Session>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let mut query = r#"
            SELECT 
                $SESSION_COLUMNS
            FROM sessions 
            WHERE tenant_id = $1 AND user_id = $2
        "#.to_string();

        if active_only {
            query.push_str(" AND status = 'active' AND expires_at > NOW()");
        }

        query.push_str(" ORDER BY created_at DESC");

        let sessions: Vec<Session> = sqlx::query_as(&query)
            .bind(tenant_id)
            .bind(user_id)
            .fetch_all(&mut *conn)
            .await?;

        Ok(sessions)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired(&self, batch_size: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM sessions 
            WHERE status IN ('expired', 'revoked', 'rotated')
               OR (status = 'active' AND expires_at < NOW() - INTERVAL '7 days')
            LIMIT $1
            "#,
        )
        .bind(batch_size)
        .execute(&*self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // =========================================================================
    // Session Limit Methods - Concurrent Session Management
    // =========================================================================

    /// Atomically check session limits and revoke oldest if needed
    /// 
    /// SECURITY: Uses PostgreSQL advisory locks to prevent race conditions
    /// where concurrent logins could exceed session limits.
    /// 
    /// Returns Ok(true) if a session slot is available/created, Ok(false) if limit reached
    pub async fn check_and_enforce_session_limit(
        &self,
        tenant_id: &str,
        user_id: &str,
        max_sessions: usize,
        eviction_policy: &str,
    ) -> Result<bool> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        // SECURITY: Use advisory lock to prevent race conditions
        // Lock ID is based on hash of tenant_id + user_id for uniqueness
        let lock_id = Self::compute_advisory_lock_id(tenant_id, user_id);
        
        // Acquire exclusive lock (blocks concurrent checks for same user)
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_id)
            .execute(&mut *conn)
            .await?;

        // Now safely count active sessions
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) 
            FROM sessions 
            WHERE tenant_id = $1 
              AND user_id = $2 
              AND status = 'active' 
              AND expires_at > NOW()
            "#
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;

        let current_count = count as usize;

        if current_count < max_sessions {
            // Slot available
            return Ok(true);
        }

        // At or over limit - apply eviction policy
        match eviction_policy {
            "oldest_first" => {
                // Revoke oldest sessions to make room
                let to_keep = max_sessions.saturating_sub(1);
                let result = sqlx::query(
                    r#"
                    UPDATE sessions SET
                        status = 'revoked',
                        revoked_at = NOW(),
                        revoked_reason = 'session_limit_eviction',
                        updated_at = NOW()
                    WHERE id IN (
                        SELECT id FROM sessions
                        WHERE tenant_id = $1 
                          AND user_id = $2 
                          AND status = 'active' 
                          AND expires_at > NOW()
                        ORDER BY created_at ASC
                        OFFSET $3
                    )
                    "#
                )
                .bind(tenant_id)
                .bind(user_id)
                .bind(to_keep as i64)
                .execute(&mut *conn)
                .await?;

                tracing::info!(
                    "Session limit eviction: revoked {} sessions for user {}",
                    result.rows_affected(),
                    user_id
                );
                
                // Return true if we made room
                Ok(result.rows_affected() > 0 || current_count < max_sessions)
            }
            "deny_new" => {
                // Deny new session
                Ok(false)
            }
            _ => {
                // Default: deny new
                Ok(false)
            }
        }
    }

    /// Compute advisory lock ID from tenant_id and user_id
    fn compute_advisory_lock_id(tenant_id: &str, user_id: &str) -> i64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        tenant_id.hash(&mut hasher);
        user_id.hash(&mut hasher);
        // Ensure positive value (PostgreSQL advisory locks use signed 64-bit)
        (hasher.finish() & 0x7FFF_FFFF_FFFF_FFFF) as i64
    }

    /// Count active sessions for a user
    pub async fn count_active_sessions_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<i64> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) 
            FROM sessions 
            WHERE tenant_id = $1 
              AND user_id = $2 
              AND status = 'active' 
              AND expires_at > NOW()
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count)
    }

    /// Get the oldest active session for a user
    pub async fn get_oldest_session_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Option<Session>> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let session = sqlx::query_as::<_, Session>(
            r#"
            SELECT 
                $SESSION_COLUMNS
            FROM sessions 
            WHERE tenant_id = $1 
              AND user_id = $2 
              AND status = 'active' 
              AND expires_at > NOW()
            ORDER BY created_at ASC
            LIMIT 1
            "#
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(session)
    }

    /// Get oldest active sessions for a user (for batch revocation)
    pub async fn get_oldest_sessions_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        limit: i64,
    ) -> Result<Vec<Session>> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let sessions: Vec<Session> = sqlx::query_as::<_, Session>(
            r#"
            SELECT 
                $SESSION_COLUMNS
            FROM sessions 
            WHERE tenant_id = $1 
              AND user_id = $2 
              AND status = 'active' 
              AND expires_at > NOW()
            ORDER BY created_at ASC
            LIMIT $3
            "#
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;

        Ok(sessions)
    }

    /// Revoke oldest sessions for a user to keep only a specified count
    /// Returns the number of sessions revoked
    pub async fn revoke_oldest_sessions_for_user(
        &self,
        tenant_id: &str,
        user_id: &str,
        keep_count: usize,
    ) -> Result<u64> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        // Revoke sessions that are beyond the keep_count oldest
        let result = sqlx::query(
            r#"
            UPDATE sessions SET
                status = 'revoked',
                revoked_at = $4,
                revoked_reason = $5,
                updated_at = $4
            WHERE id IN (
                SELECT id FROM sessions
                WHERE tenant_id = $1 
                  AND user_id = $2 
                  AND status = 'active' 
                  AND expires_at > NOW()
                ORDER BY created_at ASC
                OFFSET $3
            )
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(keep_count as i64)
        .bind(now)
        .bind("session_limit_eviction")
        .execute(&mut *conn)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count active sessions for a user from a specific IP address
    pub async fn count_active_sessions_for_user_by_ip(
        &self,
        tenant_id: &str,
        user_id: &str,
        ip_address: &str,
    ) -> Result<i64> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) 
            FROM sessions 
            WHERE tenant_id = $1 
              AND user_id = $2 
              AND status = 'active' 
              AND expires_at > NOW()
              AND ip_address = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(ip_address)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count)
    }

    /// Mark expired sessions
    pub async fn mark_expired(&self) -> Result<u64> {
        let result = sqlx::query(
            r#"
            UPDATE sessions SET
                status = 'expired'
            WHERE status = 'active' AND expires_at < NOW()
            "#,
        )
        .execute(&*self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get session statistics
    pub async fn get_stats(&self) -> Result<SessionStats> {
        let row = sqlx::query(
            r#"
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'active') as active,
                COUNT(*) FILTER (WHERE status = 'revoked') as revoked,
                COUNT(*) FILTER (WHERE status = 'expired') as expired,
                COUNT(*) FILTER (WHERE mfa_verified = true) as mfa_verified
            FROM sessions
            "#,
        )
        .fetch_one(&*self.pool)
        .await?;

        Ok(SessionStats {
            total: row.try_get("total")?,
            active: row.try_get("active")?,
            revoked: row.try_get("revoked")?,
            expired: row.try_get("expired")?,
            mfa_verified: row.try_get("mfa_verified")?,
        })
    }
}

/// Session statistics
#[derive(Debug, Clone)]
pub struct SessionStats {
    pub total: i64,
    pub active: i64,
    pub revoked: i64,
    pub expired: i64,
    pub mfa_verified: i64,
}

// =========================================================================
// Route-facing methods - these provide the exact signatures expected by routes
// =========================================================================

impl SessionRepository {
    /// List sessions for a user with tenant filtering (route-facing)
    /// Returns active sessions for the given user and tenant
    pub async fn list_by_user_for_routes(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<Vec<Session>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let sessions: Vec<Session> = sqlx::query_as(
            r#"
            SELECT 
                $SESSION_COLUMNS
            FROM sessions 
            WHERE user_id = $1 AND tenant_id = $2 AND status = 'active' AND expires_at > NOW()
            ORDER BY created_at DESC
            "#
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(sessions)
    }

    /// Revoke session with tenant filtering (route-facing)
    /// Returns true if session was found and revoked, false otherwise
    pub async fn revoke_for_routes(&self, session_id: &str, tenant_id: &str) -> Result<bool> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        let result = sqlx::query(
            r#"
            UPDATE sessions SET
                status = 'revoked',
                revoked_at = $3,
                updated_at = $3
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            "#,
        )
        .bind(session_id)
        .bind(tenant_id)
        .bind(now)
        .execute(&mut *conn)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Revoke all sessions for a user with tenant filtering and optional exception (route-facing)
    /// Returns the number of sessions revoked
    pub async fn revoke_all_for_user_for_routes(
        &self,
        user_id: &str,
        tenant_id: &str,
        except_session: Option<&str>,
    ) -> Result<u64> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        if let Some(except_id) = except_session {
            let result = sqlx::query(
                r#"
                UPDATE sessions SET
                    status = 'revoked',
                    revoked_at = $4,
                    updated_at = $4
                WHERE user_id = $1 AND tenant_id = $2 AND id != $3 AND status = 'active'
                "#,
            )
            .bind(user_id)
            .bind(tenant_id)
            .bind(except_id)
            .bind(now)
            .execute(&mut *conn)
            .await?;

            Ok(result.rows_affected())
        } else {
            let result = sqlx::query(
                r#"
            UPDATE sessions SET
                status = 'revoked',
                revoked_at = $3,
                updated_at = $3
            WHERE user_id = $1 AND tenant_id = $2 AND status = 'active'
            "#,
            )
            .bind(user_id)
            .bind(tenant_id)
            .bind(now)
            .execute(&mut *conn)
            .await?;

            Ok(result.rows_affected())
        }
    }

    // =========================================================================
    // Session Binding Methods
    // =========================================================================

    /// Increment binding violation count for a session
    pub async fn increment_violation_count(
        &self,
        tenant_id: &str,
        session_id: &str,
    ) -> Result<i32> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let count: i32 = sqlx::query_scalar(
            r#"
            UPDATE sessions 
            SET binding_violation_count = binding_violation_count + 1,
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING binding_violation_count
            "#,
        )
        .bind(tenant_id)
        .bind(session_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count)
    }

    /// Update session binding settings
    pub async fn update_binding_settings(
        &self,
        tenant_id: &str,
        session_id: &str,
        bind_to_ip: Option<bool>,
        bind_to_device: Option<bool>,
    ) -> Result<Session> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let session = sqlx::query_as::<_, Session>(
            r#"
            UPDATE sessions SET
                bind_to_ip = COALESCE($3, bind_to_ip),
                bind_to_device = COALESCE($4, bind_to_device),
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING 
                $SESSION_COLUMNS
            "#
        )
        .bind(tenant_id)
        .bind(session_id)
        .bind(bind_to_ip)
        .bind(bind_to_device)
        .fetch_one(&mut *conn)
        .await?;

        Ok(session)
    }

    /// Get session binding info for a user
    pub async fn get_user_binding_settings(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<UserBindingSettings> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let settings = sqlx::query_as::<_, UserBindingSettings>(
            r#"
            SELECT 
                require_email_verification_new_device,
                allow_single_session_per_device,
                session_binding_level
            FROM user_settings
            WHERE tenant_id = $1 AND user_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(settings)
    }

    /// Update user binding settings
    pub async fn update_user_binding_settings(
        &self,
        tenant_id: &str,
        user_id: &str,
        require_email_verification: Option<bool>,
        single_session_per_device: Option<bool>,
        binding_level: Option<String>,
    ) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        sqlx::query(
            r#"
            INSERT INTO user_settings (
                tenant_id, user_id, 
                require_email_verification_new_device,
                allow_single_session_per_device,
                session_binding_level,
                updated_at
            ) VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (tenant_id, user_id) 
            DO UPDATE SET
                require_email_verification_new_device = COALESCE($3, user_settings.require_email_verification_new_device),
                allow_single_session_per_device = COALESCE($4, user_settings.allow_single_session_per_device),
                session_binding_level = COALESCE($5, user_settings.session_binding_level),
                updated_at = NOW()
            "#
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(require_email_verification)
        .bind(single_session_per_device)
        .bind(binding_level)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }
}

/// User binding settings
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserBindingSettings {
    pub require_email_verification_new_device: bool,
    pub allow_single_session_per_device: bool,
    pub session_binding_level: String,
}
