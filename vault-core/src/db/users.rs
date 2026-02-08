//! User repository implementation

use crate::db::set_connection_context;
use crate::error::{Result, VaultError};
use crate::models::user::{MfaMethod, User, UserStatus};
use sqlx::{FromRow, PgPool, Row};
use std::sync::Arc;

/// Repository for user operations
pub struct UserRepository {
    pool: Arc<PgPool>,
}

/// User row from database (public version without sensitive fields)
#[derive(Debug, FromRow)]
pub struct UserRow {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub email_verified: bool,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// User row with password hash for authentication
#[derive(Debug, FromRow)]
pub struct UserWithPasswordRow {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub email_verified: bool,
    pub status: String,
    pub password_hash: String,
    pub failed_login_attempts: i32,
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_ip: Option<String>,
    pub profile: serde_json::Value,
    pub mfa_enabled: bool,
    pub mfa_methods: sqlx::types::Json<Vec<String>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        User {
            id: row.id,
            tenant_id: row.tenant_id,
            email: row.email,
            email_verified: row.email_verified,
            status: row.status.parse().unwrap_or(UserStatus::Active),
            created_at: row.created_at,
            updated_at: row.updated_at,
            ..Default::default()
        }
    }
}

impl From<UserWithPasswordRow> for User {
    fn from(row: UserWithPasswordRow) -> Self {
        // Convert Vec<String> to Vec<MfaMethod>
        let mfa_methods: Vec<MfaMethod> = row
            .mfa_methods
            .0
            .into_iter()
            .filter_map(|s| match s.as_str() {
                "totp" => Some(MfaMethod::Totp),
                "email" => Some(MfaMethod::Email),
                "sms" => Some(MfaMethod::Sms),
                "webauthn" => Some(MfaMethod::Webauthn),
                "backup_codes" => Some(MfaMethod::BackupCodes),
                _ => None,
            })
            .collect();

        User {
            id: row.id,
            tenant_id: row.tenant_id,
            email: row.email,
            email_verified: row.email_verified,
            status: row.status.parse().unwrap_or(UserStatus::Active),
            failed_login_attempts: row.failed_login_attempts,
            locked_until: row.locked_until,
            last_login_at: row.last_login_at,
            last_ip: row.last_ip,
            profile: serde_json::from_value(row.profile).unwrap_or_default(),
            mfa_enabled: row.mfa_enabled,
            mfa_methods,
            created_at: row.created_at,
            updated_at: row.updated_at,
            ..Default::default()
        }
    }
}

/// Request to create a new user
#[derive(Debug, Clone)]
pub struct CreateUserRequest {
    pub tenant_id: String,
    pub email: String,
    pub password_hash: Option<String>,
    pub email_verified: bool,
    pub profile: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

impl UserRepository {
    /// Create a new user repository
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

    /// Create a new user
    pub async fn create(&self, req: CreateUserRequest) -> Result<User> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(&req.tenant_id).await?;

        let row = sqlx::query_as::<_, UserWithPasswordRow>(
            r#"WITH _ AS (
                    SELECT set_config('app.current_tenant_id', $13, false)
                )
                INSERT INTO users (
                id, tenant_id, email, password_hash, email_verified, 
                status, profile, mfa_enabled, mfa_methods, metadata, created_at, updated_at
               )
               VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::user_status, $7, $8, $9, $10, $11, $12)
               RETURNING id::text as id, tenant_id::text as tenant_id, email, email_verified,
                        status::text as status, password_hash,
                        failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                        profile, mfa_enabled, mfa_methods, created_at, updated_at"#
        )
        .bind(&id)
        .bind(&req.tenant_id)
        .bind(&req.email)
        .bind(&req.password_hash)
        .bind(req.email_verified)
        .bind(UserStatus::Pending)
        .bind(req.profile.unwrap_or_else(|| serde_json::json!({})))
        .bind(false)
        .bind(serde_json::json!([]))
        .bind(req.metadata.unwrap_or_else(|| serde_json::json!({})))
        .bind(now)
        .bind(now)
        .bind(&req.tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Get user by ID
    pub async fn find_by_id(&self, tenant_id: &str, id: &str) -> Result<Option<User>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, UserWithPasswordRow>(
            "SELECT id::text as id, tenant_id::text as tenant_id, email, email_verified,
                    status::text as status, password_hash,
                    failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                    profile, mfa_enabled, mfa_methods, created_at, updated_at 
             FROM users 
             WHERE tenant_id = $1::uuid AND id = $2::uuid AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Get user by email
    pub async fn find_by_email(&self, tenant_id: &str, email: &str) -> Result<Option<User>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, UserWithPasswordRow>(
            "SELECT id::text as id, tenant_id::text as tenant_id, email, email_verified,
                    status::text as status, password_hash,
                    failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                    profile, mfa_enabled, mfa_methods, created_at, updated_at 
             FROM users 
             WHERE tenant_id = $1::uuid AND email = $2 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .bind(email.to_lowercase())
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Get user by email with password hash (legacy signature with tenant filter)
    pub async fn find_by_email_with_password_legacy(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<(User, Option<String>)> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, UserWithPasswordRow>(
            "SELECT id::text as id, tenant_id::text as tenant_id, email, email_verified,
                    status::text as status, password_hash,
                    failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                    profile, mfa_enabled, mfa_methods, created_at, updated_at 
             FROM users 
             WHERE tenant_id = $1::uuid AND email = $2 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .bind(email.to_lowercase())
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| VaultError::authentication("Invalid credentials"))?;

        let password_hash = if row.password_hash.is_empty() {
            None
        } else {
            Some(row.password_hash.clone())
        };

        let user: User = row.into();
        Ok((user, password_hash))
    }

    /// Record successful login
    pub async fn record_login_success(
        &self,
        tenant_id: &str,
        user_id: &str,
        ip: Option<std::net::IpAddr>,
    ) -> Result<()> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        sqlx::query(
            r#"UPDATE users SET
                last_login_at = $1,
                last_ip = $2,
                failed_login_attempts = 0,
                locked_until = NULL,
                updated_at = $1
            WHERE tenant_id = $3::uuid AND id = $4::uuid"#,
        )
        .bind(now)
        .bind(ip.map(|i| i.to_string()))
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Record failed login attempt
    pub async fn record_login_failure(&self, tenant_id: &str, user_id: &str) -> Result<()> {
        let now = chrono::Utc::now();
        let lockout_duration = chrono::Duration::minutes(30);
        let mut conn = self.tenant_conn(tenant_id).await?;

        sqlx::query(
            r#"UPDATE users SET
                failed_login_attempts = failed_login_attempts + 1,
                locked_until = CASE 
                    WHEN failed_login_attempts >= 4 THEN $1
                    ELSE locked_until
                END,
                updated_at = $2
            WHERE tenant_id = $3::uuid AND id = $4::uuid"#,
        )
        .bind(now + lockout_duration)
        .bind(now)
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Update user
    pub async fn update(&self, tenant_id: &str, user: &User) -> Result<User> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, UserWithPasswordRow>(
            r#"UPDATE users 
               SET email = $1, email_verified = $2, status = $3, updated_at = $4,
                   profile = $5, mfa_enabled = $6
               WHERE tenant_id = $7::uuid AND id = $8::uuid AND deleted_at IS NULL
               RETURNING id::text as id, tenant_id::text as tenant_id, email, email_verified,
                        status::text as status, password_hash,
                        failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                        profile, mfa_enabled, mfa_methods, created_at, updated_at"#
        )
        .bind(&user.email)
        .bind(user.email_verified)
        .bind(user.status.as_str())
        .bind(chrono::Utc::now())
        .bind(serde_json::to_value(&user.profile)?)
        .bind(user.mfa_enabled)
        .bind(tenant_id)
        .bind(&user.id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Delete user (soft delete)
    pub async fn delete(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            "UPDATE users SET deleted_at = $1, status = 'deleted', updated_at = $1 WHERE tenant_id = $2::uuid AND id = $3::uuid"
        )
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Verify email
    pub async fn verify_email(&self, tenant_id: &str, user_id: &str) -> Result<()> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        sqlx::query(
            r#"UPDATE users SET
                email_verified = true,
                email_verified_at = $1,
                status = CASE WHEN status = 'pending' THEN 'active' ELSE status END,
                updated_at = $1
            WHERE tenant_id = $2::uuid AND id = $3::uuid"#,
        )
        .bind(now)
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Update password
    pub async fn update_password(
        &self,
        tenant_id: &str,
        user_id: &str,
        password_hash: &str,
    ) -> Result<()> {
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;

        sqlx::query(
            r#"UPDATE users SET
                password_hash = $1,
                password_changed_at = $2,
                password_change_required = false,
                updated_at = $2
            WHERE tenant_id = $3::uuid AND id = $4::uuid"#,
        )
        .bind(password_hash)
        .bind(now)
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Enable MFA
    pub async fn enable_mfa(&self, tenant_id: &str, id: &str, _mfa_secret: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            "UPDATE users SET mfa_enabled = true, updated_at = $1 WHERE tenant_id = $2::uuid AND id = $3::uuid"
        )
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Disable MFA
    pub async fn disable_mfa(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            "UPDATE users SET mfa_enabled = false, updated_at = $1 WHERE tenant_id = $2::uuid AND id = $3::uuid"
        )
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Check if email exists
    pub async fn email_exists(&self, tenant_id: &str, email: &str) -> Result<bool> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM users WHERE tenant_id = $1::uuid AND email = $2 AND deleted_at IS NULL"
        )
        .bind(tenant_id)
        .bind(email.to_lowercase())
        .fetch_one(&mut *conn)
        .await?;

        Ok(count > 0)
    }

    /// Get user statistics
    pub async fn get_stats(&self, tenant_id: &str) -> Result<UserStats> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query(
            r#"
            SELECT 
                COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'active') as active,
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'suspended') as suspended,
                COUNT(*) FILTER (WHERE email_verified = true) as verified,
                COUNT(*) FILTER (WHERE mfa_enabled = true) as mfa_enabled,
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24 hours') as new_today
            FROM users 
            WHERE tenant_id = $1::uuid AND deleted_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(UserStats {
            total: row.try_get("total")?,
            active: row.try_get("active")?,
            pending: row.try_get("pending")?,
            suspended: row.try_get("suspended")?,
            verified: row.try_get("verified")?,
            mfa_enabled: row.try_get("mfa_enabled")?,
            new_today: row.try_get("new_today")?,
        })
    }

    /// List users with pagination and filters
    pub async fn list(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
        status: Option<&str>,
        email: Option<&str>,
    ) -> Result<(Vec<User>, i64)> {
        let offset = (page - 1) * per_page;
        let mut conn = self.tenant_conn(tenant_id).await?;

        // Build query dynamically
        let mut where_clauses = vec![
            "tenant_id = $1::uuid".to_string(),
            "deleted_at IS NULL".to_string(),
        ];
        let mut params: Vec<Box<dyn std::any::Any + Send + Sync>> =
            vec![Box::new(tenant_id.to_string())];

        let mut param_idx = 2;
        if let Some(s) = status {
            where_clauses.push(format!("status = ${}", param_idx));
            params.push(Box::new(s.to_string()));
            param_idx += 1;
        }
        if let Some(e) = email {
            where_clauses.push(format!("email ILIKE ${}", param_idx));
            params.push(Box::new(format!("%{}%", e)));
            param_idx += 1;
        }

        let where_clause = where_clauses.join(" AND ");

        // Get total count
        let count_query = format!("SELECT COUNT(*) FROM users WHERE {}", where_clause);
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_query);
        for param in &params {
            count_q = count_q.bind(param.downcast_ref::<String>().unwrap());
        }
        let total: i64 = count_q.fetch_one(&mut *conn).await?;

        // Get users
        let query = format!(
            r#"SELECT id::text as id, tenant_id::text as tenant_id, email, email_verified,
                status::text as status, password_hash,
                failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                profile, mfa_enabled, mfa_methods, created_at, updated_at
             FROM users 
             WHERE {}
             ORDER BY created_at DESC
             LIMIT ${} OFFSET ${}"#,
            where_clause,
            param_idx,
            param_idx + 1
        );

        let mut q = sqlx::query_as::<_, UserWithPasswordRow>(&query);
        for param in &params {
            q = q.bind(param.downcast_ref::<String>().unwrap());
        }
        q = q.bind(per_page).bind(offset);

        let rows = q.fetch_all(&mut *conn).await?;
        let users: Vec<User> = rows.into_iter().map(|r| r.into()).collect();

        Ok((users, total))
    }

    /// Update user status
    pub async fn update_status(
        &self,
        tenant_id: &str,
        user_id: &str,
        status: UserStatus,
    ) -> Result<User> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, UserWithPasswordRow>(
            r#"UPDATE users 
               SET status = $1::user_status, updated_at = $2
               WHERE tenant_id = $3::uuid AND id = $4::uuid AND deleted_at IS NULL
               RETURNING id::text as id, tenant_id::text as tenant_id, email, email_verified,
                        status::text as status, password_hash,
                        failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                        profile, mfa_enabled, mfa_methods, created_at, updated_at"#
        )
        .bind(status)
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Hard delete user (admin only)
    pub async fn hard_delete(&self, tenant_id: &str, user_id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        // First delete related records
        sqlx::query("DELETE FROM sessions WHERE user_id = $1::uuid")
            .bind(user_id)
            .execute(&mut *conn)
            .await?;

        sqlx::query("DELETE FROM organization_members WHERE user_id = $1::uuid")
            .bind(user_id)
            .execute(&mut *conn)
            .await?;

        sqlx::query("DELETE FROM oauth_connections WHERE user_id = $1::uuid")
            .bind(user_id)
            .execute(&mut *conn)
            .await?;

        // Then delete the user
        sqlx::query("DELETE FROM users WHERE tenant_id = $1::uuid AND id = $2::uuid")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }

    /// Count user's organization memberships
    pub async fn count_organizations(&self, tenant_id: &str, user_id: &str) -> Result<i64> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM organization_members WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND status = 'active'"
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count)
    }

    // =========================================================================
    // Route-facing methods - these provide the exact signatures expected by routes
    // =========================================================================

    /// Find user by email with password hash (route-facing with tenant_id)
    /// Returns (User, Option<password_hash>) for the given tenant
    pub async fn find_by_email_with_password(
        &self,
        tenant_id: &str,
        email: &str,
    ) -> Result<(User, Option<String>)> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, UserWithPasswordRow>(
            "SELECT id::text as id, tenant_id::text as tenant_id, email, email_verified,
                    status::text as status, password_hash,
                    failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                    profile, mfa_enabled, mfa_methods, created_at, updated_at 
             FROM users 
             WHERE tenant_id = $1::uuid AND email = $2 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .bind(email.to_lowercase())
        .fetch_optional(&mut *conn)
        .await?;

        match row {
            Some(row) => {
                let password_hash = if row.password_hash.is_empty() {
                    None
                } else {
                    Some(row.password_hash.clone())
                };
                let user: User = row.into();
                Ok((user, password_hash))
            }
            None => Err(VaultError::not_found("User", email)),
        }
    }
}

/// User statistics
#[derive(Debug, Clone)]
pub struct UserStats {
    pub total: i64,
    pub active: i64,
    pub pending: i64,
    pub suspended: i64,
    pub verified: i64,
    pub mfa_enabled: i64,
    pub new_today: i64,
}

/// MFA configuration for a user
#[derive(Debug, Clone)]
pub struct MfaConfig {
    pub user_id: String,
    pub config: serde_json::Value,
}

impl UserRepository {
    /// Get MFA configuration for a user
    pub async fn get_mfa_config(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<serde_json::Value> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let config: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT mfa_config FROM users WHERE tenant_id = $1::uuid AND id = $2::uuid",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(config.unwrap_or_else(|| serde_json::json!({})))
    }

    /// Update MFA configuration for a user
    pub async fn update_mfa_config(
        &self,
        tenant_id: &str,
        user_id: &str,
        config: &serde_json::Value,
    ) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            "UPDATE users SET mfa_config = $1, updated_at = $2 WHERE tenant_id = $3::uuid AND id = $4::uuid"
        )
        .bind(config)
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Clear Email OTP code after use
    pub async fn clear_email_otp(&self, tenant_id: &str, user_id: &str) -> Result<()> {
        let config = self.get_mfa_config(tenant_id, user_id).await?;

        if let Some(mut email_config) = config.get("email").cloned() {
            if let Some(obj) = email_config.as_object_mut() {
                obj.remove("current_code");
                obj.insert("used_at".to_string(), serde_json::json!(chrono::Utc::now()));

                let new_config = serde_json::json!({
                    "email": email_config
                });
                self.update_mfa_config(tenant_id, user_id, &new_config)
                    .await?;
            }
        }

        Ok(())
    }

    /// Clear SMS OTP code after use
    pub async fn clear_sms_otp(&self, tenant_id: &str, user_id: &str) -> Result<()> {
        let config = self.get_mfa_config(tenant_id, user_id).await?;

        if let Some(mut sms_config) = config.get("sms").cloned() {
            if let Some(obj) = sms_config.as_object_mut() {
                obj.remove("current_code");
                obj.insert("used_at".to_string(), serde_json::json!(chrono::Utc::now()));

                let new_config = serde_json::json!({
                    "sms": sms_config
                });
                self.update_mfa_config(tenant_id, user_id, &new_config)
                    .await?;
            }
        }

        Ok(())
    }

    /// Consume a backup code (remove from available codes)
    pub async fn consume_backup_code(
        &self,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> Result<()> {
        use crate::auth::mfa::hash_backup_codes;

        let config = self.get_mfa_config(tenant_id, user_id).await?;

        if let Some(backup_config) = config.get("backup_codes") {
            if let Some(codes) = backup_config.get("codes").and_then(|c| c.as_array()) {
                // Find and remove the used code
                let normalized_code = code.to_uppercase().replace('-', "");

                let remaining_codes: Vec<String> = codes
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter(|hashed| {
                        !crate::crypto::VaultPasswordHasher::verify(&normalized_code, hashed)
                            .unwrap_or(false)
                    })
                    .map(|s| s.to_string())
                    .collect();

                let new_config = serde_json::json!({
                    "backup_codes": {
                        "codes": remaining_codes,
                        "used_count": backup_config.get("used_count")
                            .and_then(|u| u.as_u64())
                            .unwrap_or(0) + 1
                    }
                });

                self.update_mfa_config(tenant_id, user_id, &new_config)
                    .await?;
            }
        }

        Ok(())
    }

    /// Update pending phone number (for SMS MFA setup)
    pub async fn update_pending_phone(&self, tenant_id: &str, user_id: &str, phone: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE users 
            SET profile = jsonb_set(
                COALESCE(profile, '{}'::jsonb),
                '{pending_phone_number}',
                $1::jsonb
            ),
            updated_at = $2
            WHERE tenant_id = $3::uuid AND id = $4::uuid
            "#
        )
        .bind(serde_json::json!(phone))
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
        
        Ok(())
    }

    /// Update phone number and verification status
    pub async fn update_phone_number(
        &self, 
        tenant_id: &str, 
        user_id: &str, 
        phone: &str,
        verified: bool
    ) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            r#"
            UPDATE users 
            SET profile = jsonb_set(
                jsonb_set(
                    COALESCE(profile, '{}'::jsonb),
                    '{phone_number}',
                    $1::jsonb
                ),
                '{phone_number_verified}',
                $2::jsonb
            ),
            updated_at = $3
            WHERE tenant_id = $4::uuid AND id = $5::uuid
            "#
        )
        .bind(serde_json::json!(phone))
        .bind(serde_json::json!(verified))
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
        
        Ok(())
    }

    /// Get user's phone number
    pub async fn get_phone_number(&self, tenant_id: &str, user_id: &str) -> Result<Option<String>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let profile: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT profile FROM users WHERE tenant_id = $1::uuid AND id = $2::uuid"
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;
        
        Ok(profile
            .and_then(|p| p.get("phone_number").cloned())
            .and_then(|p| p.as_str().map(|s| s.to_string())))
    }

    // ==================== Web3 Wallet Methods ====================

    /// Find user by wallet address
    pub async fn find_by_wallet(
        &self,
        tenant_id: &str,
        wallet_address: &str,
    ) -> Result<Option<User>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        
        // Normalize address to lowercase
        let normalized_address = wallet_address.to_lowercase();
        
        let row = sqlx::query_as::<_, UserWithPasswordRow>(
            "SELECT id::text as id, tenant_id::text as tenant_id, email, email_verified,
                    status::text as status, password_hash,
                    failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                    profile, mfa_enabled, mfa_methods, created_at, updated_at 
             FROM users 
             WHERE tenant_id = $1::uuid 
               AND LOWER(wallet_address) = $2 
               AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .bind(normalized_address)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Link wallet to existing user
    pub async fn link_wallet(
        &self,
        tenant_id: &str,
        user_id: &str,
        wallet_address: &str,
        chain_id: i32,
        verification_method: &str,
    ) -> Result<User> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let now = chrono::Utc::now();
        
        // Normalize address to lowercase
        let normalized_address = wallet_address.to_lowercase();
        
        let row = sqlx::query_as::<_, UserWithPasswordRow>(
            r#"UPDATE users 
               SET wallet_address = $1,
                   chain_id = $2,
                   wallet_verified_at = $3,
                   wallet_verification_method = $4,
                   updated_at = $5
               WHERE tenant_id = $6::uuid AND id = $7::uuid AND deleted_at IS NULL
               RETURNING id::text as id, tenant_id::text as tenant_id, email, email_verified,
                        status::text as status, password_hash,
                        failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                        profile, mfa_enabled, mfa_methods, created_at, updated_at"#
        )
        .bind(normalized_address)
        .bind(chain_id)
        .bind(now)
        .bind(verification_method)
        .bind(now)
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Unlink wallet from user
    pub async fn unlink_wallet(&self, tenant_id: &str, user_id: &str) -> Result<User> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        
        let row = sqlx::query_as::<_, UserWithPasswordRow>(
            r#"UPDATE users 
               SET wallet_address = NULL,
                   chain_id = NULL,
                   wallet_verified_at = NULL,
                   wallet_verification_method = NULL,
                   updated_at = $1
               WHERE tenant_id = $2::uuid AND id = $3::uuid AND deleted_at IS NULL
               RETURNING id::text as id, tenant_id::text as tenant_id, email, email_verified,
                        status::text as status, password_hash,
                        failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                        profile, mfa_enabled, mfa_methods, created_at, updated_at"#
        )
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Check if wallet address is already linked to another user
    pub async fn is_wallet_linked(
        &self,
        tenant_id: &str,
        wallet_address: &str,
        exclude_user_id: Option<&str>,
    ) -> Result<bool> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        
        // Normalize address to lowercase
        let normalized_address = wallet_address.to_lowercase();
        
        let query = match exclude_user_id {
            Some(_) => {
                "SELECT COUNT(*) FROM users 
                 WHERE tenant_id = $1::uuid 
                   AND LOWER(wallet_address) = $2 
                   AND id != $3::uuid 
                   AND deleted_at IS NULL"
            }
            None => {
                "SELECT COUNT(*) FROM users 
                 WHERE tenant_id = $1::uuid 
                   AND LOWER(wallet_address) = $2 
                   AND deleted_at IS NULL"
            }
        };
        
        let count: i64 = if let Some(exclude_id) = exclude_user_id {
            sqlx::query_scalar(query)
                .bind(tenant_id)
                .bind(normalized_address)
                .bind(exclude_id)
                .fetch_one(&mut *conn)
                .await?
        } else {
            sqlx::query_scalar(query)
                .bind(tenant_id)
                .bind(normalized_address)
                .fetch_one(&mut *conn)
                .await?
        };

        Ok(count > 0)
    }

    /// Create a new user from Web3 authentication
    pub async fn create_from_web3(
        &self,
        tenant_id: &str,
        wallet_address: &str,
        chain_id: i32,
        email: Option<String>,
    ) -> Result<User> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let mut conn = self.tenant_conn(tenant_id).await?;
        
        // Normalize address to lowercase
        let normalized_address = wallet_address.to_lowercase();
        
        // Generate a placeholder email if none provided
        let user_email = email.unwrap_or_else(|| {
            format!("{}@wallet.local", &normalized_address[..20])
        });

        let row = sqlx::query_as::<_, UserWithPasswordRow>(
            r#"WITH _ AS (
                    SELECT set_config('app.current_tenant_id', $13, false)
                )
                INSERT INTO users (
                id, tenant_id, email, password_hash, email_verified, 
                status, profile, mfa_enabled, mfa_methods, metadata,
                wallet_address, chain_id, wallet_verified_at, wallet_verification_method,
                created_at, updated_at
               )
               VALUES ($1::uuid, $2::uuid, $3, NULL, FALSE, 
                       'active'::user_status, $4, FALSE, $5, $6,
                       $7, $8, $9, $10, $11, $12)
               RETURNING id::text as id, tenant_id::text as tenant_id, email, email_verified,
                        status::text as status, password_hash,
                        failed_login_attempts, locked_until, last_login_at, last_ip::text as last_ip,
                        profile, mfa_enabled, mfa_methods, created_at, updated_at"#
        )
        .bind(&id)
        .bind(&tenant_id)
        .bind(&user_email)
        .bind(serde_json::json!({}))
        .bind(serde_json::json!([]))
        .bind(serde_json::json!({}))
        .bind(&normalized_address)
        .bind(chain_id)
        .bind(now)
        .bind("siwe")
        .bind(now)
        .bind(now)
        .bind(&tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }
}
