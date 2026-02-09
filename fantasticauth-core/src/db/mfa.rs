//! MFA repository for managing TOTP, WebAuthn, and backup codes

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;

/// MFA method types
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "mfa_method", rename_all = "snake_case")]
pub enum MfaMethodType {
    Totp,
    Email,
    Sms,
    Webauthn,
    BackupCodes,
}

impl MfaMethodType {
    pub fn as_str(&self) -> &'static str {
        match self {
            MfaMethodType::Totp => "totp",
            MfaMethodType::Email => "email",
            MfaMethodType::Sms => "sms",
            MfaMethodType::Webauthn => "webauthn",
            MfaMethodType::BackupCodes => "backup_codes",
        }
    }
}

/// MFA method record
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MfaMethod {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub method_type: MfaMethodType,
    pub secret_encrypted: Option<String>,
    pub public_key: Option<String>,
    pub credential_id: Option<String>,
    pub verified: bool,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Backup code record
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BackupCode {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub code_hash: String,
    pub used: bool,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// MFA Repository
#[derive(Clone)]
pub struct MfaRepository {
    pool: Arc<PgPool>,
}

impl MfaRepository {
    /// Create new MFA repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Get all MFA methods for a user
    pub async fn get_user_methods(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<MfaMethod>, sqlx::Error> {
        let methods = sqlx::query_as::<_, MfaMethod>(
            r#"
            SELECT id, user_id, tenant_id, method_type, secret_encrypted,
                   public_key, credential_id, verified, enabled, created_at,
                   updated_at, last_used_at
            FROM user_mfa_methods
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;

        Ok(methods)
    }

    /// Get enabled MFA methods for a user
    pub async fn get_enabled_methods(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<MfaMethod>, sqlx::Error> {
        let methods = sqlx::query_as::<_, MfaMethod>(
            r#"
            SELECT id, user_id, tenant_id, method_type, secret_encrypted,
                   public_key, credential_id, verified, enabled, created_at,
                   updated_at, last_used_at
            FROM user_mfa_methods
            WHERE tenant_id = $1 AND user_id = $2 AND enabled = true
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;

        Ok(methods)
    }

    /// Check if user has MFA enabled
    pub async fn is_mfa_enabled(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM user_mfa_methods
            WHERE tenant_id = $1 AND user_id = $2 AND enabled = true
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&*self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Create TOTP method
    pub async fn create_totp_method(
        &self,
        tenant_id: &str,
        user_id: &str,
        secret_encrypted: &str,
    ) -> Result<MfaMethod, sqlx::Error> {
        let id = uuid::Uuid::new_v4().to_string();

        let method = sqlx::query_as::<_, MfaMethod>(
            r#"
            INSERT INTO user_mfa_methods (
                id, user_id, tenant_id, method_type, secret_encrypted,
                verified, enabled, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, false, false, NOW(), NOW())
            RETURNING id, user_id, tenant_id, method_type, secret_encrypted,
                      public_key, credential_id, verified, enabled, created_at,
                      updated_at, last_used_at
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(MfaMethodType::Totp)
        .bind(secret_encrypted)
        .fetch_one(&*self.pool)
        .await?;

        Ok(method)
    }

    /// Create WebAuthn method
    pub async fn create_webauthn_method(
        &self,
        tenant_id: &str,
        user_id: &str,
        credential_id: &str,
        public_key: &str,
    ) -> Result<MfaMethod, sqlx::Error> {
        let id = uuid::Uuid::new_v4().to_string();

        let method = sqlx::query_as::<_, MfaMethod>(
            r#"
            INSERT INTO user_mfa_methods (
                id, user_id, tenant_id, method_type, credential_id,
                public_key, verified, enabled, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, true, true, NOW(), NOW())
            RETURNING id, user_id, tenant_id, method_type, secret_encrypted,
                      public_key, credential_id, verified, enabled, created_at,
                      updated_at, last_used_at
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(MfaMethodType::Webauthn)
        .bind(credential_id)
        .bind(public_key)
        .fetch_one(&*self.pool)
        .await?;

        Ok(method)
    }

    /// Verify and enable TOTP method
    pub async fn verify_totp_method(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE user_mfa_methods
            SET verified = true, enabled = true, updated_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND method_type = 'totp'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Disable MFA method
    pub async fn disable_method(
        &self,
        tenant_id: &str,
        user_id: &str,
        method_type: MfaMethodType,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM user_mfa_methods
            WHERE tenant_id = $1 AND user_id = $2 AND method_type = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(method_type)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Get TOTP secret for user
    pub async fn get_totp_secret(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let secret: Option<String> = sqlx::query_scalar(
            r#"
            SELECT secret_encrypted FROM user_mfa_methods
            WHERE tenant_id = $1 AND user_id = $2 AND method_type = 'totp' AND enabled = true
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(secret)
    }

    /// Create backup codes
    pub async fn create_backup_codes(
        &self,
        tenant_id: &str,
        user_id: &str,
        code_hashes: &[String],
    ) -> Result<Vec<BackupCode>, sqlx::Error> {
        let mut codes = Vec::new();

        for hash in code_hashes {
            let id = uuid::Uuid::new_v4().to_string();

            let code = sqlx::query_as::<_, BackupCode>(
                r#"
                INSERT INTO user_backup_codes (id, user_id, tenant_id, code_hash, used, created_at)
                VALUES ($1, $2, $3, $4, false, NOW())
                RETURNING id, user_id, tenant_id, code_hash, used, used_at, created_at
                "#,
            )
            .bind(&id)
            .bind(user_id)
            .bind(tenant_id)
            .bind(hash)
            .fetch_one(&*self.pool)
            .await?;

            codes.push(code);
        }

        Ok(codes)
    }

    /// Get unused backup codes for user
    pub async fn get_backup_codes(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<BackupCode>, sqlx::Error> {
        let codes = sqlx::query_as::<_, BackupCode>(
            r#"
            SELECT id, user_id, tenant_id, code_hash, used, used_at, created_at
            FROM user_backup_codes
            WHERE tenant_id = $1 AND user_id = $2 AND used = false
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;

        Ok(codes)
    }

    /// Verify and consume a backup code (Argon2id hashes)
    pub async fn verify_backup_code(
        &self,
        tenant_id: &str,
        user_id: &str,
        code: &str,
    ) -> Result<bool, sqlx::Error> {
        let codes = sqlx::query_as::<_, BackupCode>(
            r#"
            SELECT id, user_id, tenant_id, code_hash, used, used_at, created_at
            FROM user_backup_codes
            WHERE tenant_id = $1 AND user_id = $2 AND used = false
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;

        let normalized = code.to_uppercase().replace('-', "");

        for code_row in codes {
            if crate::crypto::VaultPasswordHasher::verify(&normalized, &code_row.code_hash)
                .unwrap_or(false)
            {
                let result = sqlx::query(
                    r#"
                    UPDATE user_backup_codes
                    SET used = true, used_at = NOW()
                    WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND used = false
                    "#,
                )
                .bind(tenant_id)
                .bind(user_id)
                .bind(&code_row.id)
                .execute(&*self.pool)
                .await?;

                return Ok(result.rows_affected() > 0);
            }
        }

        Ok(false)
    }

    /// Mark method as used
    pub async fn mark_method_used(
        &self,
        tenant_id: &str,
        user_id: &str,
        method_type: MfaMethodType,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE user_mfa_methods
            SET last_used_at = NOW(), updated_at = NOW()
            WHERE tenant_id = $1 AND user_id = $2 AND method_type = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(method_type)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Delete all backup codes for user
    pub async fn delete_backup_codes(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM user_backup_codes
            WHERE tenant_id = $1 AND user_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Create SMS MFA method
    pub async fn create_sms_method(
        &self,
        tenant_id: &str,
        user_id: &str,
        phone_number: &str,
    ) -> Result<MfaMethod, sqlx::Error> {
        let id = uuid::Uuid::new_v4().to_string();

        let method = sqlx::query_as::<_, MfaMethod>(
            r#"
            INSERT INTO user_mfa_methods (
                id, user_id, tenant_id, method_type, public_key,
                verified, enabled, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, true, true, NOW(), NOW())
            ON CONFLICT (user_id, tenant_id, method_type) 
            DO UPDATE SET 
                public_key = EXCLUDED.public_key,
                verified = true,
                enabled = true,
                updated_at = NOW()
            RETURNING id, user_id, tenant_id, method_type, secret_encrypted,
                      public_key, credential_id, verified, enabled, created_at,
                      updated_at, last_used_at
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(MfaMethodType::Sms)
        .bind(phone_number)
        .fetch_one(&*self.pool)
        .await?;

        Ok(method)
    }

    /// Create Email MFA method
    pub async fn create_email_method(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<MfaMethod, sqlx::Error> {
        let id = uuid::Uuid::new_v4().to_string();

        let method = sqlx::query_as::<_, MfaMethod>(
            r#"
            INSERT INTO user_mfa_methods (
                id, user_id, tenant_id, method_type,
                verified, enabled, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, true, true, NOW(), NOW())
            ON CONFLICT (user_id, tenant_id, method_type) 
            DO UPDATE SET 
                verified = true,
                enabled = true,
                updated_at = NOW()
            RETURNING id, user_id, tenant_id, method_type, secret_encrypted,
                      public_key, credential_id, verified, enabled, created_at,
                      updated_at, last_used_at
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(tenant_id)
        .bind(MfaMethodType::Email)
        .fetch_one(&*self.pool)
        .await?;

        Ok(method)
    }

    /// Get SMS phone number for user
    pub async fn get_sms_phone_number(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let phone: Option<String> = sqlx::query_scalar(
            r#"
            SELECT public_key FROM user_mfa_methods
            WHERE tenant_id = $1 AND user_id = $2 AND method_type = 'sms' AND enabled = true
            LIMIT 1
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(phone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would go here with a test database
}
