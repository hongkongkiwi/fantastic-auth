//! Biometric authentication repository

use crate::auth::biometric::{
    BiometricChallenge, BiometricError, BiometricKey, BiometricKeyStore, BiometricType,
    ChallengeStore,
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;

/// Biometric key record from database
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BiometricKeyRecord {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub public_key: Vec<u8>,
    pub key_id: String,
    pub device_name: String,
    pub biometric_type: BiometricType,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl From<BiometricKeyRecord> for BiometricKey {
    fn from(record: BiometricKeyRecord) -> Self {
        Self {
            id: record.id,
            user_id: record.user_id,
            tenant_id: record.tenant_id,
            public_key: record.public_key,
            key_id: record.key_id,
            device_name: record.device_name,
            biometric_type: record.biometric_type,
            created_at: record.created_at,
            last_used_at: record.last_used_at,
        }
    }
}

/// Challenge record from database
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChallengeRecord {
    pub key_id: String,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
}

/// Biometric repository for database operations
#[derive(Clone)]
pub struct BiometricRepository {
    pool: Arc<PgPool>,
}

impl BiometricRepository {
    /// Create a new biometric repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Create a new biometric key
    pub async fn create_key(&self, key: &BiometricKey) -> Result<BiometricKeyRecord, sqlx::Error> {
        let record = sqlx::query_as::<_, BiometricKeyRecord>(
            r#"
            INSERT INTO biometric_keys (
                id, user_id, tenant_id, public_key, key_id, device_name, 
                biometric_type, created_at, last_used_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, user_id, tenant_id, public_key, key_id, device_name,
                      biometric_type, created_at, last_used_at
            "#,
        )
        .bind(&key.id)
        .bind(&key.user_id)
        .bind(&key.tenant_id)
        .bind(&key.public_key)
        .bind(&key.key_id)
        .bind(&key.device_name)
        .bind(key.biometric_type)
        .bind(key.created_at)
        .bind(key.last_used_at)
        .fetch_one(&*self.pool)
        .await?;

        Ok(record)
    }

    /// Get a biometric key by key_id
    pub async fn get_key_by_key_id(
        &self,
        key_id: &str,
    ) -> Result<Option<BiometricKeyRecord>, sqlx::Error> {
        let record = sqlx::query_as::<_, BiometricKeyRecord>(
            r#"
            SELECT id, user_id, tenant_id, public_key, key_id, device_name,
                   biometric_type, created_at, last_used_at
            FROM biometric_keys
            WHERE key_id = $1
            "#,
        )
        .bind(key_id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(record)
    }

    /// Get all biometric keys for a user
    pub async fn get_keys_for_user(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<Vec<BiometricKeyRecord>, sqlx::Error> {
        let records = sqlx::query_as::<_, BiometricKeyRecord>(
            r#"
            SELECT id, user_id, tenant_id, public_key, key_id, device_name,
                   biometric_type, created_at, last_used_at
            FROM biometric_keys
            WHERE user_id = $1 AND tenant_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&*self.pool)
        .await?;

        Ok(records)
    }

    /// Delete a biometric key
    pub async fn delete_key(&self, key_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            DELETE FROM biometric_keys
            WHERE key_id = $1
            "#,
        )
        .bind(key_id)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Update last used timestamp
    pub async fn update_last_used(&self, key_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE biometric_keys
            SET last_used_at = NOW()
            WHERE key_id = $1
            "#,
        )
        .bind(key_id)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Store a challenge
    pub async fn store_challenge(
        &self,
        key_id: &str,
        challenge: &BiometricChallenge,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO biometric_challenges (key_id, challenge, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (key_id) DO UPDATE SET
                challenge = EXCLUDED.challenge,
                expires_at = EXCLUDED.expires_at,
                created_at = NOW()
            "#,
        )
        .bind(key_id)
        .bind(&challenge.challenge)
        .bind(challenge.expires_at)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Get and remove a challenge
    pub async fn get_challenge(
        &self,
        key_id: &str,
    ) -> Result<Option<BiometricChallenge>, sqlx::Error> {
        // Use a transaction to get and delete in one operation
        let mut tx = self.pool.begin().await?;

        let record: Option<ChallengeRecord> = sqlx::query_as(
            r#"
            SELECT key_id, challenge, expires_at
            FROM biometric_challenges
            WHERE key_id = $1
            "#,
        )
        .bind(key_id)
        .fetch_optional(&mut *tx)
        .await?;

        if record.is_some() {
            sqlx::query(
                r#"
                DELETE FROM biometric_challenges
                WHERE key_id = $1
                "#,
            )
            .bind(key_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(record.map(|r| BiometricChallenge {
            challenge: r.challenge,
            expires_at: r.expires_at,
        }))
    }

    /// Clean up expired challenges
    pub async fn cleanup_expired_challenges(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM biometric_challenges
            WHERE expires_at < NOW()
            "#,
        )
        .execute(&*self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count biometric keys for a user
    pub async fn count_keys_for_user(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> Result<i64, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM biometric_keys
            WHERE user_id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(&*self.pool)
        .await?;

        Ok(count)
    }
}

#[async_trait::async_trait]
impl BiometricKeyStore for BiometricRepository {
    async fn store_key(&self, key: &BiometricKey) -> std::result::Result<(), BiometricError> {
        self.create_key(key).await.map_err(BiometricError::from)?;
        Ok(())
    }

    async fn get_key_by_key_id(
        &self,
        key_id: &str,
    ) -> std::result::Result<Option<BiometricKey>, BiometricError> {
        let record = self
            .get_key_by_key_id(key_id)
            .await
            .map_err(BiometricError::from)?;
        Ok(record.map(|r| r.into()))
    }

    async fn get_keys_for_user(
        &self,
        user_id: &str,
        tenant_id: &str,
    ) -> std::result::Result<Vec<BiometricKey>, BiometricError> {
        let records = self
            .get_keys_for_user(user_id, tenant_id)
            .await
            .map_err(BiometricError::from)?;
        Ok(records.into_iter().map(|r| r.into()).collect())
    }

    async fn delete_key(&self, key_id: &str) -> std::result::Result<(), BiometricError> {
        BiometricRepository::delete_key(self, key_id)
            .await
            .map_err(BiometricError::from)
    }

    async fn update_last_used(&self, key_id: &str) -> std::result::Result<(), BiometricError> {
        BiometricRepository::update_last_used(self, key_id)
            .await
            .map_err(BiometricError::from)
    }
}

#[async_trait::async_trait]
impl ChallengeStore for BiometricRepository {
    async fn store_challenge(
        &self,
        key_id: &str,
        challenge: &BiometricChallenge,
    ) -> std::result::Result<(), BiometricError> {
        BiometricRepository::store_challenge(self, key_id, challenge)
            .await
            .map_err(BiometricError::from)
    }

    async fn get_challenge(
        &self,
        key_id: &str,
    ) -> std::result::Result<Option<BiometricChallenge>, BiometricError> {
        BiometricRepository::get_challenge(self, key_id)
            .await
            .map_err(BiometricError::from)
    }

    async fn cleanup_expired(&self) -> std::result::Result<u64, BiometricError> {
        BiometricRepository::cleanup_expired_challenges(self)
            .await
            .map_err(BiometricError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would go here with a test database
}
