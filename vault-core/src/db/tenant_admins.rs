use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::sync::Arc;

use crate::crypto::VaultPasswordHasher;
use crate::error::{Result, VaultError};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantAdmin {
    pub id: String,
    pub tenant_id: String,
    pub user_id: String,
    pub role: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantAdminInvitation {
    pub id: String,
    pub tenant_id: String,
    pub email: String,
    pub role: String,
    pub token_hash: String,
    pub invited_by: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

pub struct TenantAdminRepository {
    pool: Arc<PgPool>,
}

impl TenantAdminRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    pub async fn list_admins(&self, tenant_id: &str) -> Result<Vec<TenantAdmin>> {
        let admins = sqlx::query_as::<_, TenantAdmin>(
            r#"
            SELECT id::text, tenant_id::text, user_id::text, role::text, status::text, created_at, updated_at
            FROM tenant_admins
            WHERE tenant_id = $1::uuid
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&*self.pool)
        .await?;

        Ok(admins)
    }

    pub async fn get_roles_for_user(&self, tenant_id: &str, user_id: &str) -> Result<Vec<String>> {
        let roles: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT role::text
            FROM tenant_admins
            WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND status = 'active'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;

        Ok(roles)
    }

    pub async fn upsert_admin(
        &self,
        tenant_id: &str,
        user_id: &str,
        role: &str,
        status: &str,
    ) -> Result<TenantAdmin> {
        let admin = sqlx::query_as::<_, TenantAdmin>(
            r#"
            INSERT INTO tenant_admins (tenant_id, user_id, role, status, created_at, updated_at)
            VALUES ($1::uuid, $2::uuid, $3::tenant_admin_role, $4::tenant_admin_status, NOW(), NOW())
            ON CONFLICT (tenant_id, user_id)
            DO UPDATE SET role = EXCLUDED.role, status = EXCLUDED.status, updated_at = NOW()
            RETURNING id::text, tenant_id::text, user_id::text, role::text, status::text, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(role)
        .bind(status)
        .fetch_one(&*self.pool)
        .await?;

        Ok(admin)
    }

    pub async fn remove_admin(&self, tenant_id: &str, user_id: &str) -> Result<()> {
        sqlx::query(
            r#"DELETE FROM tenant_admins WHERE tenant_id = $1::uuid AND user_id = $2::uuid"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_invitation(
        &self,
        tenant_id: &str,
        email: &str,
        role: &str,
        token: &str,
        invited_by: Option<&str>,
        expires_at: DateTime<Utc>,
    ) -> Result<TenantAdminInvitation> {
        let token_hash = VaultPasswordHasher::hash(token)?;

        let invitation = sqlx::query_as::<_, TenantAdminInvitation>(
            r#"
            INSERT INTO tenant_admin_invitations (
                tenant_id, email, role, token_hash, invited_by, expires_at, created_at
            ) VALUES ($1::uuid, $2, $3::tenant_admin_role, $4, $5::uuid, $6, NOW())
            ON CONFLICT (tenant_id, email)
            DO UPDATE SET role = EXCLUDED.role, token_hash = EXCLUDED.token_hash, invited_by = EXCLUDED.invited_by,
                expires_at = EXCLUDED.expires_at, accepted_at = NULL, created_at = NOW()
            RETURNING id::text, tenant_id::text, email, role::text, token_hash, invited_by::text, expires_at, accepted_at, created_at
            "#,
        )
        .bind(tenant_id)
        .bind(email.to_lowercase())
        .bind(role)
        .bind(&token_hash)
        .bind(invited_by)
        .bind(expires_at)
        .fetch_one(&*self.pool)
        .await?;

        Ok(invitation)
    }

    pub async fn list_invitations(&self, tenant_id: &str) -> Result<Vec<TenantAdminInvitation>> {
        let invites = sqlx::query_as::<_, TenantAdminInvitation>(
            r#"
            SELECT id::text, tenant_id::text, email, role::text, token_hash, invited_by::text, expires_at, accepted_at, created_at
            FROM tenant_admin_invitations
            WHERE tenant_id = $1::uuid
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&*self.pool)
        .await?;

        Ok(invites)
    }

    pub async fn find_invitation_by_token(
        &self,
        tenant_id: &str,
        token: &str,
    ) -> Result<Option<TenantAdminInvitation>> {
        let invites = sqlx::query_as::<_, TenantAdminInvitation>(
            r#"
            SELECT id::text, tenant_id::text, email, role::text, token_hash, invited_by::text, expires_at, accepted_at, created_at
            FROM tenant_admin_invitations
            WHERE tenant_id = $1::uuid AND accepted_at IS NULL AND expires_at > NOW()
            "#,
        )
        .bind(tenant_id)
        .fetch_all(&*self.pool)
        .await?;

        for invite in invites {
            if VaultPasswordHasher::verify(token, &invite.token_hash)? {
                return Ok(Some(invite));
            }
        }

        Ok(None)
    }

    pub async fn accept_invitation(&self, invitation_id: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE tenant_admin_invitations
            SET accepted_at = NOW()
            WHERE id = $1::uuid
            "#,
        )
        .bind(invitation_id)
        .execute(&*self.pool)
        .await?;

        Ok(())
    }
}
