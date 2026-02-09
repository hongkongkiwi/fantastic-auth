//! Account Linking Service
//!
//! Provides functionality for users to link multiple authentication methods
//! (OAuth providers, email, phone) to a single account.

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use std::sync::Arc;

/// Represents a linked authentication account
#[derive(Debug, Clone, FromRow)]
pub struct LinkedAccount {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_account_id: String,
    pub provider_data: serde_json::Value,
    pub is_verified: bool,
    pub is_primary: bool,
    pub linked_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Provider types for account linking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProvider {
    Google,
    GitHub,
    Microsoft,
    Apple,
    Email,
    Phone,
    WebAuthn,
    Saml,
}

impl AuthProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthProvider::Google => "google",
            AuthProvider::GitHub => "github",
            AuthProvider::Microsoft => "microsoft",
            AuthProvider::Apple => "apple",
            AuthProvider::Email => "email",
            AuthProvider::Phone => "phone",
            AuthProvider::WebAuthn => "webauthn",
            AuthProvider::Saml => "saml",
        }
    }
}

impl std::str::FromStr for AuthProvider {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "google" => Ok(AuthProvider::Google),
            "github" => Ok(AuthProvider::GitHub),
            "microsoft" => Ok(AuthProvider::Microsoft),
            "apple" => Ok(AuthProvider::Apple),
            "email" => Ok(AuthProvider::Email),
            "phone" => Ok(AuthProvider::Phone),
            "webauthn" => Ok(AuthProvider::WebAuthn),
            "saml" => Ok(AuthProvider::Saml),
            _ => Err(format!("Unknown auth provider: {}", s)),
        }
    }
}

/// Request to link a new account
#[derive(Debug, Clone)]
pub struct LinkAccountRequest {
    pub tenant_id: String,
    pub user_id: String,
    pub provider: AuthProvider,
    pub provider_account_id: String,
    pub provider_data: Option<serde_json::Value>,
    pub is_verified: bool,
}

/// Error types for account linking operations
#[derive(Debug, thiserror::Error)]
pub enum AccountLinkingError {
    #[error("Account already linked to another user")]
    AlreadyLinked,
    #[error("Account is already linked to this user")]
    AlreadyLinkedToUser,
    #[error("Cannot unlink primary authentication method")]
    CannotUnlinkPrimary,
    #[error("Cannot unlink last authentication method")]
    CannotUnlinkLast,
    #[error("Account not found")]
    NotFound,
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Validation error: {0}")]
    Validation(String),
}

/// Account linking service for managing linked authentication methods
#[derive(Clone)]
pub struct AccountLinkingService {
    pool: Arc<PgPool>,
}

impl AccountLinkingService {
    /// Create a new account linking service
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Link a new authentication method to a user
    ///
    /// # Arguments
    /// * `req` - The link account request
    ///
    /// # Returns
    /// * `Ok(LinkedAccount)` - The newly linked account
    /// * `Err(AccountLinkingError)` - If the account is already linked or validation fails
    pub async fn link_account(
        &self,
        req: LinkAccountRequest,
    ) -> Result<LinkedAccount, AccountLinkingError> {
        // Check if this provider account is already linked to any user
        let existing = self
            .find_account_by_provider(&req.tenant_id, req.provider, &req.provider_account_id)
            .await?;

        if let Some(existing) = existing {
            if existing.user_id == req.user_id {
                return Err(AccountLinkingError::AlreadyLinkedToUser);
            } else {
                return Err(AccountLinkingError::AlreadyLinked);
            }
        }

        // Check if this is the first linked account (make it primary)
        let existing_accounts = self
            .list_linked_accounts(&req.tenant_id, &req.user_id)
            .await?;
        let is_primary = existing_accounts.is_empty();

        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        let account = sqlx::query_as::<_, LinkedAccount>(
            r#"INSERT INTO user_linked_accounts (
                id, tenant_id, user_id, provider, provider_account_id,
                provider_data, is_verified, is_primary, linked_at, created_at, updated_at
            ) VALUES (
                $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11
            ) RETURNING 
                id::text, tenant_id::text, user_id::text, provider, provider_account_id,
                provider_data, is_verified, is_primary, linked_at, last_used_at, created_at, updated_at"#
        )
        .bind(&id)
        .bind(&req.tenant_id)
        .bind(&req.user_id)
        .bind(req.provider.as_str())
        .bind(&req.provider_account_id)
        .bind(req.provider_data.unwrap_or_else(|| serde_json::json!({})))
        .bind(req.is_verified)
        .bind(is_primary)
        .bind(now)
        .bind(now)
        .bind(now)
        .fetch_one(&*self.pool)
        .await?;

        tracing::info!(
            "Linked {} account to user {} in tenant {}",
            req.provider.as_str(),
            req.user_id,
            req.tenant_id
        );

        Ok(account)
    }

    /// Unlink an authentication method from a user
    ///
    /// # Security
    /// - Cannot unlink the last authentication method
    /// - Cannot unlink the primary authentication method without setting a new primary
    pub async fn unlink_account(
        &self,
        tenant_id: &str,
        user_id: &str,
        provider: AuthProvider,
    ) -> Result<(), AccountLinkingError> {
        // Get all linked accounts
        let accounts = self.list_linked_accounts(tenant_id, user_id).await?;

        // Check if this is the last authentication method
        if accounts.len() <= 1 {
            return Err(AccountLinkingError::CannotUnlinkLast);
        }

        // Find the account to unlink
        let account_to_unlink = accounts
            .iter()
            .find(|a| a.provider == provider.as_str())
            .ok_or(AccountLinkingError::NotFound)?;

        // Check if this is the primary account
        if account_to_unlink.is_primary {
            return Err(AccountLinkingError::CannotUnlinkPrimary);
        }

        // Delete the linked account
        sqlx::query(
            "DELETE FROM user_linked_accounts 
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND provider = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(provider.as_str())
        .execute(&*self.pool)
        .await?;

        tracing::info!(
            "Unlinked {} account from user {} in tenant {}",
            provider.as_str(),
            user_id,
            tenant_id
        );

        Ok(())
    }

    /// Find a linked account by provider and provider account ID
    pub async fn find_account_by_provider(
        &self,
        tenant_id: &str,
        provider: AuthProvider,
        provider_account_id: &str,
    ) -> Result<Option<LinkedAccount>, AccountLinkingError> {
        let account = sqlx::query_as::<_, LinkedAccount>(
            r#"SELECT 
                id::text, tenant_id::text, user_id::text, provider, provider_account_id,
                provider_data, is_verified, is_primary, linked_at, last_used_at, created_at, updated_at
             FROM user_linked_accounts 
             WHERE tenant_id = $1::uuid 
               AND provider = $2 
               AND provider_account_id = $3"#
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(provider_account_id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(account)
    }

    /// List all linked accounts for a user
    pub async fn list_linked_accounts(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<Vec<LinkedAccount>, AccountLinkingError> {
        let accounts = sqlx::query_as::<_, LinkedAccount>(
            r#"SELECT 
                id::text, tenant_id::text, user_id::text, provider, provider_account_id,
                provider_data, is_verified, is_primary, linked_at, last_used_at, created_at, updated_at
             FROM user_linked_accounts 
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid
             ORDER BY is_primary DESC, linked_at ASC"#
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;

        Ok(accounts)
    }

    /// Set a linked account as the primary authentication method
    pub async fn set_primary_account(
        &self,
        tenant_id: &str,
        user_id: &str,
        provider: AuthProvider,
    ) -> Result<(), AccountLinkingError> {
        // Begin transaction
        let mut tx = self.pool.begin().await?;

        // Clear existing primary
        sqlx::query(
            "UPDATE user_linked_accounts 
             SET is_primary = FALSE, updated_at = NOW()
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        // Set new primary
        let result = sqlx::query(
            "UPDATE user_linked_accounts 
             SET is_primary = TRUE, updated_at = NOW()
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND provider = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(provider.as_str())
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            tx.rollback().await?;
            return Err(AccountLinkingError::NotFound);
        }

        tx.commit().await?;

        tracing::info!(
            "Set {} as primary authentication for user {} in tenant {}",
            provider.as_str(),
            user_id,
            tenant_id
        );

        Ok(())
    }

    /// Update the last used timestamp for a linked account
    pub async fn update_last_used(
        &self,
        tenant_id: &str,
        user_id: &str,
        provider: AuthProvider,
    ) -> Result<(), AccountLinkingError> {
        sqlx::query(
            "UPDATE user_linked_accounts 
             SET last_used_at = NOW()
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND provider = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(provider.as_str())
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    /// Count linked accounts for a user
    pub async fn count_linked_accounts(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<i64, AccountLinkingError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_linked_accounts 
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&*self.pool)
        .await?;

        Ok(count)
    }

    /// Check if a user has a specific provider linked
    pub async fn has_provider_linked(
        &self,
        tenant_id: &str,
        user_id: &str,
        provider: AuthProvider,
    ) -> Result<bool, AccountLinkingError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_linked_accounts 
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND provider = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(provider.as_str())
        .fetch_one(&*self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Find user by linked account (for login with linked identity)
    pub async fn find_user_by_linked_account(
        &self,
        tenant_id: &str,
        provider: AuthProvider,
        provider_account_id: &str,
    ) -> Result<Option<String>, AccountLinkingError> {
        let user_id: Option<String> = sqlx::query_scalar(
            r#"SELECT user_id::text FROM user_linked_accounts 
             WHERE tenant_id = $1::uuid 
               AND provider = $2 
               AND provider_account_id = $3
               AND is_verified = TRUE"#,
        )
        .bind(tenant_id)
        .bind(provider.as_str())
        .bind(provider_account_id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(user_id)
    }

    /// Merge two accounts - transfer all linked accounts from source to target
    /// This is used when a user wants to merge duplicate accounts
    pub async fn merge_accounts(
        &self,
        tenant_id: &str,
        source_user_id: &str,
        target_user_id: &str,
    ) -> Result<(), AccountLinkingError> {
        let mut tx = self.pool.begin().await?;

        // Get all linked accounts from source user
        let source_accounts = sqlx::query_as::<_, LinkedAccount>(
            r#"SELECT 
                id::text, tenant_id::text, user_id::text, provider, provider_account_id,
                provider_data, is_verified, is_primary, linked_at, last_used_at, created_at, updated_at
             FROM user_linked_accounts 
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid"#
        )
        .bind(tenant_id)
        .bind(source_user_id)
        .fetch_all(&mut *tx)
        .await?;

        for account in source_accounts {
            // Check if target user already has this provider linked
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT id::text FROM user_linked_accounts 
                 WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND provider = $3",
            )
            .bind(tenant_id)
            .bind(target_user_id)
            .bind(&account.provider)
            .fetch_optional(&mut *tx)
            .await?;

            if existing.is_none() {
                // Transfer the linked account
                sqlx::query(
                    "UPDATE user_linked_accounts 
                     SET user_id = $1::uuid, is_primary = FALSE, updated_at = NOW()
                     WHERE id = $2::uuid",
                )
                .bind(target_user_id)
                .bind(&account.id)
                .execute(&mut *tx)
                .await?;
            } else {
                // Delete the duplicate
                sqlx::query("DELETE FROM user_linked_accounts WHERE id = $1::uuid")
                    .bind(&account.id)
                    .execute(&mut *tx)
                    .await?;
            }
        }

        tx.commit().await?;

        tracing::info!(
            "Merged linked accounts from user {} to user {} in tenant {}",
            source_user_id,
            target_user_id,
            tenant_id
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_provider_from_str() {
        assert_eq!(
            AuthProvider::from_str("google").unwrap(),
            AuthProvider::Google
        );
        assert_eq!(
            AuthProvider::from_str("GitHub").unwrap(),
            AuthProvider::GitHub
        );
        assert_eq!(
            AuthProvider::from_str("EMAIL").unwrap(),
            AuthProvider::Email
        );
        assert!(AuthProvider::from_str("unknown").is_err());
    }

    #[test]
    fn test_auth_provider_as_str() {
        assert_eq!(AuthProvider::Google.as_str(), "google");
        assert_eq!(AuthProvider::WebAuthn.as_str(), "webauthn");
    }
}
