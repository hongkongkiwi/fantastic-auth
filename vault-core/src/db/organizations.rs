//! Organization repository implementation

use crate::db::set_connection_context;
use crate::error::Result;
use crate::models::organization::{
    MembershipStatus, Organization, OrganizationMember, OrganizationRole,
};
use sqlx::{FromRow, PgPool};
use std::sync::Arc;

/// Repository for organization operations
pub struct OrganizationRepository {
    pool: Arc<PgPool>,
}

/// Organization row from database
#[derive(Debug, FromRow)]
struct OrganizationRow {
    id: String,
    tenant_id: String,
    name: String,
    slug: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<OrganizationRow> for Organization {
    fn from(row: OrganizationRow) -> Self {
        Organization {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            slug: row.slug,
            created_at: row.created_at,
            updated_at: row.updated_at,
            ..Default::default()
        }
    }
}

/// Organization member row from database
#[derive(Debug, FromRow)]
struct OrganizationMemberRow {
    id: String,
    organization_id: String,
    user_id: String,
    role: String,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<OrganizationMemberRow> for OrganizationMember {
    fn from(row: OrganizationMemberRow) -> Self {
        OrganizationMember {
            id: row.id,
            organization_id: row.organization_id,
            user_id: row.user_id,
            role: row.role.parse().unwrap_or(OrganizationRole::Member),
            status: row.status.parse().unwrap_or(MembershipStatus::Active),
            created_at: row.created_at,
            updated_at: row.updated_at,
            ..Default::default()
        }
    }
}

impl OrganizationRepository {
    /// Create a new organization repository
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

    /// Create a new organization
    pub async fn create(&self, org: &Organization) -> Result<Organization> {
        let mut conn = self.tenant_conn(&org.tenant_id).await?;
        let row = sqlx::query_as::<_, OrganizationRow>(
            r#"INSERT INTO organizations (id, tenant_id, name, slug, created_at, updated_at)
               VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)
               RETURNING id::text as id, tenant_id::text as tenant_id, name, slug,
                        created_at, updated_at"#,
        )
        .bind(&org.id)
        .bind(&org.tenant_id)
        .bind(&org.name)
        .bind(&org.slug)
        .bind(org.created_at)
        .bind(org.updated_at)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Get organization by ID
    pub async fn get_by_id(&self, tenant_id: &str, id: &str) -> Result<Option<Organization>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, OrganizationRow>(
            r#"SELECT id::text as id, tenant_id::text as tenant_id, name, slug,
                created_at, updated_at 
             FROM organizations 
             WHERE tenant_id = $1::uuid AND id = $2::uuid AND deleted_at IS NULL"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Get organization by slug
    pub async fn get_by_slug(&self, tenant_id: &str, slug: &str) -> Result<Option<Organization>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, OrganizationRow>(
            r#"SELECT id::text as id, tenant_id::text as tenant_id, name, slug,
                created_at, updated_at 
             FROM organizations 
             WHERE tenant_id = $1::uuid AND slug = $2 AND deleted_at IS NULL"#,
        )
        .bind(tenant_id)
        .bind(slug)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Update organization
    pub async fn update(&self, tenant_id: &str, org: &Organization) -> Result<Organization> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, OrganizationRow>(
            r#"UPDATE organizations 
               SET name = $1, slug = $2, updated_at = $3
               WHERE tenant_id = $4::uuid AND id = $5::uuid AND deleted_at IS NULL
               RETURNING id::text as id, tenant_id::text as tenant_id, name, slug,
                        created_at, updated_at"#,
        )
        .bind(&org.name)
        .bind(&org.slug)
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(&org.id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Delete organization (soft delete)
    pub async fn delete(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            "UPDATE organizations SET deleted_at = $1 WHERE tenant_id = $2::uuid AND id = $3::uuid",
        )
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// List organizations for tenant
    pub async fn list(
        &self,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Organization>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, OrganizationRow>(
            r#"SELECT id::text as id, tenant_id::text as tenant_id, name, slug, created_at, updated_at 
             FROM organizations 
             WHERE tenant_id = $1::uuid AND deleted_at IS NULL
             ORDER BY created_at DESC
             LIMIT $2 OFFSET $3"#
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Add member to organization
    pub async fn add_member(
        &self,
        tenant_id: &str,
        member: &OrganizationMember,
    ) -> Result<OrganizationMember> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, OrganizationMemberRow>(
            r#"INSERT INTO organization_members (id, tenant_id, organization_id, user_id, role, status, created_at, updated_at)
               VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::org_role, $6::membership_status, $7, $8)
               RETURNING id::text as id, organization_id::text as organization_id,
                        user_id::text as user_id, role::text as role, status::text as status,
                        created_at, updated_at"#
        )
        .bind(&member.id)
        .bind(&member.tenant_id)
        .bind(&member.organization_id)
        .bind(&member.user_id)
        .bind(member.role)
        .bind(member.status)
        .bind(member.created_at)
        .bind(member.updated_at)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Get organization member
    pub async fn get_member(
        &self,
        tenant_id: &str,
        org_id: &str,
        user_id: &str,
    ) -> Result<Option<OrganizationMember>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, OrganizationMemberRow>(
            r#"SELECT id::text as id, organization_id::text as organization_id,
                user_id::text as user_id, role::text as role, status::text as status,
                created_at, updated_at 
             FROM organization_members 
             WHERE organization_id = $1::uuid AND user_id = $2::uuid"#
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Update member role
    pub async fn update_member_role(
        &self,
        tenant_id: &str,
        org_id: &str,
        user_id: &str,
        role: OrganizationRole,
    ) -> Result<OrganizationMember> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, OrganizationMemberRow>(
            r#"UPDATE organization_members 
               SET role = $1::org_role, updated_at = $2
               WHERE organization_id = $3::uuid AND user_id = $4::uuid
               RETURNING id::text as id, organization_id::text as organization_id,
                        user_id::text as user_id, role::text as role, status::text as status,
                        created_at, updated_at"#
        )
        .bind(role)
        .bind(chrono::Utc::now())
        .bind(org_id)
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Remove member from organization
    pub async fn remove_member(&self, tenant_id: &str, org_id: &str, user_id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            "DELETE FROM organization_members WHERE organization_id = $1::uuid AND user_id = $2::uuid"
        )
        .bind(org_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// List members of organization
    pub async fn list_members(
        &self,
        tenant_id: &str,
        org_id: &str,
    ) -> Result<Vec<OrganizationMember>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, OrganizationMemberRow>(
            r#"SELECT id::text as id, organization_id::text as organization_id,
                user_id::text as user_id, role::text as role, status::text as status,
                created_at, updated_at 
             FROM organization_members 
             WHERE organization_id = $1::uuid
             ORDER BY created_at DESC"#
        )
        .bind(org_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// List organizations for user
    pub async fn list_for_user(&self, tenant_id: &str, user_id: &str) -> Result<Vec<Organization>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let rows = sqlx::query_as::<_, OrganizationRow>(
            r#"SELECT o.id::text as id, o.tenant_id::text as tenant_id, o.name, o.slug,
                o.created_at, o.updated_at 
             FROM organizations o
             JOIN organization_members om ON o.id = om.organization_id
             WHERE o.tenant_id = $1::uuid AND om.user_id = $2::uuid AND o.deleted_at IS NULL
             ORDER BY o.created_at DESC"#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Count total organizations for tenant
    pub async fn count(&self, tenant_id: &str, status: Option<&str>) -> Result<i64> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let mut query =
            "SELECT COUNT(*) FROM organizations WHERE tenant_id = $1::uuid AND deleted_at IS NULL"
                .to_string();

        if status.is_some() {
            query.push_str(" AND status = $2");
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);
        if let Some(s) = status {
            q = q.bind(s);
        }

        let count = q.fetch_one(&mut *conn).await?;
        Ok(count)
    }

    /// List organizations with pagination
    pub async fn list_paginated(
        &self,
        tenant_id: &str,
        page: i64,
        per_page: i64,
        status: Option<&str>,
    ) -> Result<(Vec<Organization>, i64)> {
        let offset = (page - 1) * per_page;
        let mut conn = self.tenant_conn(tenant_id).await?;
        let total = self.count(tenant_id, status).await?;

        let mut query = r#"
            SELECT id::text as id, tenant_id::text as tenant_id, name, slug,
                   created_at, updated_at 
            FROM organizations 
            WHERE tenant_id = $1::uuid AND deleted_at IS NULL
        "#
        .to_string();

        if status.is_some() {
            query.push_str(" AND status = $4");
        }

        query.push_str(" ORDER BY created_at DESC LIMIT $2 OFFSET $3");

        let mut q = sqlx::query_as::<_, OrganizationRow>(&query)
            .bind(tenant_id)
            .bind(per_page)
            .bind(offset);

        if let Some(s) = status {
            q = q.bind(s);
        }

        let rows = q.fetch_all(&mut *conn).await?;

        Ok((rows.into_iter().map(Into::into).collect(), total))
    }

    /// Update organization status
    pub async fn update_status(
        &self,
        tenant_id: &str,
        id: &str,
        status: &str,
    ) -> Result<Organization> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, OrganizationRow>(
            r#"UPDATE organizations 
               SET status = $1, updated_at = $2
               WHERE tenant_id = $3::uuid AND id = $4::uuid AND deleted_at IS NULL
               RETURNING id::text as id, tenant_id::text as tenant_id, name, slug,
                        created_at, updated_at"#,
        )
        .bind(status)
        .bind(chrono::Utc::now())
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Hard delete organization (admin only)
    pub async fn hard_delete(&self, tenant_id: &str, id: &str) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        // First delete related records
        sqlx::query("DELETE FROM organization_members WHERE organization_id = $1::uuid")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        sqlx::query("DELETE FROM organization_invitations WHERE organization_id = $1::uuid")
            .bind(id)
            .execute(&mut *conn)
            .await?;

        // Then delete the organization
        sqlx::query("DELETE FROM organizations WHERE tenant_id = $1::uuid AND id = $2::uuid")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }

    /// Count members in organization
    pub async fn count_members(
        &self,
        tenant_id: &str,
        org_id: &str,
        status: Option<&str>,
    ) -> Result<i64> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let mut query =
            "SELECT COUNT(*) FROM organization_members WHERE organization_id = $1::uuid"
                .to_string();

        if status.is_some() {
            query.push_str(" AND status = $2");
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(org_id);
        if let Some(s) = status {
            q = q.bind(s);
        }

        let count = q.fetch_one(&mut *conn).await?;
        Ok(count)
    }

    /// List invitations for organization
    pub async fn list_invitations(
        &self,
        tenant_id: &str,
        org_id: &str,
        pending_only: bool,
    ) -> Result<Vec<OrganizationInvitation>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let mut query = r#"
            SELECT id::text as id, organization_id::text as organization_id, email,
                   role::text as role, invited_by::text as invited_by, token, 
                   expires_at, accepted_at, created_at
            FROM organization_invitations 
            WHERE organization_id = $1::uuid
        "#
        .to_string();

        if pending_only {
            query.push_str(" AND accepted_at IS NULL AND expires_at > NOW()");
        }

        query.push_str(" ORDER BY created_at DESC");

        let rows = sqlx::query_as::<_, OrganizationInvitationRow>(&query)
            .bind(org_id)
            .fetch_all(&mut *conn)
            .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Delete invitation
    pub async fn delete_invitation(
        &self,
        tenant_id: &str,
        org_id: &str,
        invitation_id: &str,
    ) -> Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        sqlx::query(
            "DELETE FROM organization_invitations WHERE organization_id = $1::uuid AND id = $2::uuid"
        )
        .bind(org_id)
        .bind(invitation_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Create invitation
    pub async fn create_invitation(
        &self,
        tenant_id: &str,
        invitation: &OrganizationInvitation,
    ) -> Result<OrganizationInvitation> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, OrganizationInvitationRow>(
            r#"INSERT INTO organization_invitations (
                    id, tenant_id, organization_id, email, role, invited_by, token, expires_at, created_at
               )
               VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::org_role, $6::uuid, $7, $8, $9)
               RETURNING id::text as id, organization_id::text as organization_id, email,
                        role::text as role, invited_by::text as invited_by, token,
                        expires_at, accepted_at, created_at"#
        )
        .bind(&invitation.id)
        .bind(tenant_id)
        .bind(&invitation.organization_id)
        .bind(&invitation.email)
        .bind(invitation.role.clone())
        .bind(&invitation.invited_by)
        .bind(&invitation.token)
        .bind(invitation.expires_at)
        .bind(invitation.created_at)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Get invitation by token
    pub async fn get_invitation_by_token(
        &self,
        tenant_id: &str,
        token: &str,
    ) -> Result<Option<OrganizationInvitation>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        let row = sqlx::query_as::<_, OrganizationInvitationRow>(
            r#"SELECT id::text as id, organization_id::text as organization_id, email,
                       role::text as role, invited_by::text as invited_by, token,
                       expires_at, accepted_at, created_at
               FROM organization_invitations
               WHERE tenant_id = $1::uuid AND token = $2"#
        )
        .bind(tenant_id)
        .bind(token)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Accept invitation by token and create membership
    pub async fn accept_invitation(
        &self,
        tenant_id: &str,
        token: &str,
        user_id: &str,
    ) -> Result<Option<OrganizationInvitation>> {
        let mut conn = self.tenant_conn(tenant_id).await?;
        use sqlx::Acquire;
        let mut tx = conn.begin().await?;

        let invitation = sqlx::query_as::<_, OrganizationInvitationRow>(
            r#"SELECT id::text as id, organization_id::text as organization_id, email,
                       role::text as role, invited_by::text as invited_by, token,
                       expires_at, accepted_at, created_at
               FROM organization_invitations
               WHERE tenant_id = $1::uuid
                 AND token = $2
                 AND accepted_at IS NULL
                 AND expires_at > NOW()"#
        )
        .bind(tenant_id)
        .bind(token)
        .fetch_optional(&mut *tx)
        .await?;

        let invitation = match invitation {
            Some(i) => i,
            None => {
                tx.rollback().await?;
                return Ok(None);
            }
        };

        let now = chrono::Utc::now();

        sqlx::query(
            r#"INSERT INTO organization_members (
                    id, tenant_id, organization_id, user_id, role, status,
                    invited_by, invited_at, joined_at, created_at, updated_at
               )
               VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::org_role, $6::membership_status,
                       $7::uuid, $8, $9, $10, $11)
               ON CONFLICT (organization_id, user_id) DO UPDATE SET
                    role = EXCLUDED.role,
                    status = EXCLUDED.status,
                    invited_by = EXCLUDED.invited_by,
                    invited_at = EXCLUDED.invited_at,
                    joined_at = EXCLUDED.joined_at,
                    updated_at = EXCLUDED.updated_at"#
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(tenant_id)
        .bind(&invitation.organization_id)
        .bind(user_id)
        .bind(invitation.role.parse::<OrganizationRole>().unwrap_or(OrganizationRole::Member))
        .bind(MembershipStatus::Active)
        .bind(&invitation.invited_by)
        .bind(invitation.created_at)
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        let updated = sqlx::query_as::<_, OrganizationInvitationRow>(
            r#"UPDATE organization_invitations
               SET accepted_at = $1
               WHERE tenant_id = $2::uuid AND id = $3::uuid
               RETURNING id::text as id, organization_id::text as organization_id, email,
                        role::text as role, invited_by::text as invited_by, token,
                        expires_at, accepted_at, created_at"#
        )
        .bind(now)
        .bind(tenant_id)
        .bind(&invitation.id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(Some(updated.into()))
    }
}

/// Organization invitation row
#[derive(Debug, FromRow)]
struct OrganizationInvitationRow {
    id: String,
    organization_id: String,
    email: String,
    role: String,
    invited_by: String,
    token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
    accepted_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// Organization invitation
#[derive(Debug, Clone)]
pub struct OrganizationInvitation {
    pub id: String,
    pub organization_id: String,
    pub email: String,
    pub role: String,
    pub invited_by: String,
    pub token: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub accepted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<OrganizationInvitationRow> for OrganizationInvitation {
    fn from(row: OrganizationInvitationRow) -> Self {
        OrganizationInvitation {
            id: row.id,
            organization_id: row.organization_id,
            email: row.email,
            role: row.role,
            invited_by: row.invited_by,
            token: row.token,
            expires_at: row.expires_at,
            accepted_at: row.accepted_at,
            created_at: row.created_at,
        }
    }
}
