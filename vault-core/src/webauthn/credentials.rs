//! Credential store for WebAuthn
//!
//! Manages persistent storage of WebAuthn credentials.

use super::StoredCredential;
use async_trait::async_trait;
use sqlx::FromRow;

/// Credential store errors
#[derive(Debug, thiserror::Error)]
pub enum CredentialStoreError {
    #[error("Credential not found")]
    NotFound,
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Duplicate credential")]
    Duplicate,
}

/// Credential store trait
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// Store a new credential
    async fn store_credential(
        &self,
        credential: StoredCredential,
    ) -> Result<(), CredentialStoreError>;

    /// Get credential by ID
    async fn get_credential(
        &self,
        credential_id: &str,
    ) -> Result<StoredCredential, CredentialStoreError>;

    /// Get all credentials for a user
    async fn get_credentials_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StoredCredential>, CredentialStoreError>;

    /// Update credential (e.g., sign count)
    async fn update_credential(
        &self,
        credential: StoredCredential,
    ) -> Result<(), CredentialStoreError>;

    /// Delete credential
    async fn delete_credential(&self, credential_id: &str) -> Result<(), CredentialStoreError>;

    /// Delete all credentials for a user
    async fn delete_credentials_for_user(&self, user_id: &str)
        -> Result<u64, CredentialStoreError>;
}

/// SQLx row representation of a credential
#[derive(Debug, FromRow)]
struct CredentialRow {
    credential_id: String,
    user_id: String,
    tenant_id: String,
    public_key: Vec<u8>,
    sign_count: i32,
    aaguid: Option<String>,
    name: Option<String>,
    is_passkey: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<CredentialRow> for StoredCredential {
    fn from(row: CredentialRow) -> Self {
        Self {
            credential_id: row.credential_id,
            user_id: row.user_id,
            tenant_id: row.tenant_id,
            public_key: row.public_key,
            sign_count: row.sign_count as u32,
            aaguid: row.aaguid,
            name: row.name,
            is_passkey: row.is_passkey,
            created_at: row.created_at,
            last_used_at: row.last_used_at,
        }
    }
}

/// SQLx-backed credential store
pub struct SqlxCredentialStore {
    pool: sqlx::PgPool,
}

impl SqlxCredentialStore {
    /// Create new SQLx credential store
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CredentialStore for SqlxCredentialStore {
    async fn store_credential(
        &self,
        credential: StoredCredential,
    ) -> Result<(), CredentialStoreError> {
        sqlx::query(
            r#"
            INSERT INTO webauthn_credentials (
                credential_id, user_id, tenant_id, public_key,
                sign_count, aaguid, name, is_passkey, created_at, last_used_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(&credential.credential_id)
        .bind(&credential.user_id)
        .bind(&credential.tenant_id)
        .bind(&credential.public_key)
        .bind(credential.sign_count as i32)
        .bind(&credential.aaguid)
        .bind(&credential.name)
        .bind(credential.is_passkey)
        .bind(credential.created_at)
        .bind(credential.last_used_at)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) if db_err.message().contains("unique constraint") => {
                CredentialStoreError::Duplicate
            }
            _ => CredentialStoreError::Storage(e.to_string()),
        })?;

        Ok(())
    }

    async fn get_credential(
        &self,
        credential_id: &str,
    ) -> Result<StoredCredential, CredentialStoreError> {
        let row = sqlx::query_as::<_, CredentialRow>(
            r#"
            SELECT 
                credential_id, user_id, tenant_id, public_key,
                sign_count, aaguid, name, is_passkey, created_at, last_used_at
            FROM webauthn_credentials
            WHERE credential_id = $1
            "#,
        )
        .bind(credential_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => CredentialStoreError::NotFound,
            _ => CredentialStoreError::Storage(e.to_string()),
        })?;

        Ok(row.into())
    }

    async fn get_credentials_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<StoredCredential>, CredentialStoreError> {
        let rows = sqlx::query_as::<_, CredentialRow>(
            r#"
            SELECT 
                credential_id, user_id, tenant_id, public_key,
                sign_count, aaguid, name, is_passkey, created_at, last_used_at
            FROM webauthn_credentials
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| CredentialStoreError::Storage(e.to_string()))?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn update_credential(
        &self,
        credential: StoredCredential,
    ) -> Result<(), CredentialStoreError> {
        sqlx::query(
            r#"
            UPDATE webauthn_credentials
            SET sign_count = $1, last_used_at = $2
            WHERE credential_id = $3
            "#,
        )
        .bind(credential.sign_count as i32)
        .bind(credential.last_used_at)
        .bind(&credential.credential_id)
        .execute(&self.pool)
        .await
        .map_err(|e| CredentialStoreError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn delete_credential(&self, credential_id: &str) -> Result<(), CredentialStoreError> {
        sqlx::query("DELETE FROM webauthn_credentials WHERE credential_id = $1")
            .bind(credential_id)
            .execute(&self.pool)
            .await
            .map_err(|e| CredentialStoreError::Storage(e.to_string()))?;

        Ok(())
    }

    async fn delete_credentials_for_user(
        &self,
        user_id: &str,
    ) -> Result<u64, CredentialStoreError> {
        let result = sqlx::query("DELETE FROM webauthn_credentials WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| CredentialStoreError::Storage(e.to_string()))?;

        Ok(result.rows_affected())
    }
}
