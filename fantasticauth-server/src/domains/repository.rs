//! Domain repository for database operations

use crate::domains::models::{DomainStatus, OrganizationDomain, VerificationMethod};
use sqlx::{FromRow, PgPool};
use std::sync::Arc;
use vault_core::db::set_connection_context;

/// Repository for organization domain operations
#[derive(Clone)]
pub struct DomainRepository {
    pool: Arc<PgPool>,
}

/// Domain row from database
#[derive(Debug, FromRow)]
struct OrganizationDomainRow {
    id: String,
    organization_id: String,
    tenant_id: String,
    domain: String,
    status: String,
    verification_method: String,
    verification_token: String,
    verified_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    auto_enroll_enabled: bool,
    default_role: String,
    dns_hostname: Option<String>,
    file_path: Option<String>,
    html_meta_content: Option<String>,
}

impl From<OrganizationDomainRow> for OrganizationDomain {
    fn from(row: OrganizationDomainRow) -> Self {
        OrganizationDomain {
            id: row.id,
            organization_id: row.organization_id,
            tenant_id: row.tenant_id,
            domain: row.domain,
            status: row.status.parse().unwrap_or(DomainStatus::Pending),
            verification_method: row
                .verification_method
                .parse()
                .unwrap_or(VerificationMethod::Dns),
            verification_token: row.verification_token,
            verified_at: row.verified_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            auto_enroll_enabled: row.auto_enroll_enabled,
            default_role: row.default_role,
            dns_hostname: row.dns_hostname,
            file_path: row.file_path,
            html_meta_content: row.html_meta_content,
        }
    }
}

impl DomainRepository {
    /// Create a new domain repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Get a connection with tenant context set
    async fn tenant_conn(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        let mut conn = self.pool.acquire().await?;
        set_connection_context(&mut conn, tenant_id).await?;
        Ok(conn)
    }

    /// Create a new domain
    pub async fn create(&self, domain: &OrganizationDomain) -> anyhow::Result<OrganizationDomain> {
        let mut conn = self.tenant_conn(&domain.tenant_id).await?;

        let row = sqlx::query_as::<_, OrganizationDomainRow>(
            r#"INSERT INTO organization_domains (
                id, organization_id, tenant_id, domain, status, verification_method,
                verification_token, verified_at, created_at, updated_at,
                auto_enroll_enabled, default_role, dns_hostname, file_path, html_meta_content
            ) VALUES (
                $1::uuid, $2::uuid, $3::uuid, $4, $5::domain_status, $6::verification_method,
                $7, $8, $9, $10, $11, $12, $13, $14, $15
            ) RETURNING 
                id::text as id, organization_id::text as organization_id, tenant_id::text as tenant_id,
                domain, status::text as status, verification_method::text as verification_method,
                verification_token, verified_at, created_at, updated_at,
                auto_enroll_enabled, default_role, dns_hostname, file_path, html_meta_content"#
        )
        .bind(&domain.id)
        .bind(&domain.organization_id)
        .bind(&domain.tenant_id)
        .bind(&domain.domain)
        .bind(domain.status)
        .bind(domain.verification_method)
        .bind(&domain.verification_token)
        .bind(domain.verified_at)
        .bind(domain.created_at)
        .bind(domain.updated_at)
        .bind(domain.auto_enroll_enabled)
        .bind(&domain.default_role)
        .bind(&domain.dns_hostname)
        .bind(&domain.file_path)
        .bind(&domain.html_meta_content)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Get domain by ID
    pub async fn get_by_id(
        &self,
        tenant_id: &str,
        domain_id: &str,
    ) -> anyhow::Result<Option<OrganizationDomain>> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let row = sqlx::query_as::<_, OrganizationDomainRow>(
            r#"SELECT 
                id::text as id, organization_id::text as organization_id, tenant_id::text as tenant_id,
                domain, status::text as status, verification_method::text as verification_method,
                verification_token, verified_at, created_at, updated_at,
                auto_enroll_enabled, default_role, dns_hostname, file_path, html_meta_content
            FROM organization_domains 
            WHERE tenant_id = $1::uuid AND id = $2::uuid"#
        )
        .bind(tenant_id)
        .bind(domain_id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Get domain by organization ID and domain name
    pub async fn get_by_domain(
        &self,
        tenant_id: &str,
        organization_id: &str,
        domain: &str,
    ) -> anyhow::Result<Option<OrganizationDomain>> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let row = sqlx::query_as::<_, OrganizationDomainRow>(
            r#"SELECT 
                id::text as id, organization_id::text as organization_id, tenant_id::text as tenant_id,
                domain, status::text as status, verification_method::text as verification_method,
                verification_token, verified_at, created_at, updated_at,
                auto_enroll_enabled, default_role, dns_hostname, file_path, html_meta_content
            FROM organization_domains 
            WHERE tenant_id = $1::uuid 
              AND organization_id = $2::uuid
              AND domain = $3"#
        )
        .bind(tenant_id)
        .bind(organization_id)
        .bind(domain)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    /// Get verified domain by domain name (for auto-enrollment lookup)
    pub async fn get_verified_by_domain(
        &self,
        domain: &str,
    ) -> anyhow::Result<Option<OrganizationDomain>> {
        // This query doesn't need tenant context as we're looking up by domain
        let row = sqlx::query_as::<_, OrganizationDomainRow>(
            r#"SELECT 
                id::text as id, organization_id::text as organization_id, tenant_id::text as tenant_id,
                domain, status::text as status, verification_method::text as verification_method,
                verification_token, verified_at, created_at, updated_at,
                auto_enroll_enabled, default_role, dns_hostname, file_path, html_meta_content
            FROM organization_domains 
            WHERE domain = $1 
              AND status = 'verified'
              AND auto_enroll_enabled = true"#
        )
        .bind(domain)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    /// List domains for organization
    pub async fn list_for_organization(
        &self,
        tenant_id: &str,
        organization_id: &str,
    ) -> anyhow::Result<Vec<OrganizationDomain>> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let rows = sqlx::query_as::<_, OrganizationDomainRow>(
            r#"SELECT 
                id::text as id, organization_id::text as organization_id, tenant_id::text as tenant_id,
                domain, status::text as status, verification_method::text as verification_method,
                verification_token, verified_at, created_at, updated_at,
                auto_enroll_enabled, default_role, dns_hostname, file_path, html_meta_content
            FROM organization_domains 
            WHERE tenant_id = $1::uuid AND organization_id = $2::uuid
            ORDER BY created_at DESC"#
        )
        .bind(tenant_id)
        .bind(organization_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Update domain status
    pub async fn update_status(
        &self,
        tenant_id: &str,
        domain_id: &str,
        status: DomainStatus,
        method: Option<VerificationMethod>,
    ) -> anyhow::Result<OrganizationDomain> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let verified_at = if status == DomainStatus::Verified {
            Some(chrono::Utc::now())
        } else {
            None
        };

        let row = sqlx::query_as::<_, OrganizationDomainRow>(
            r#"UPDATE organization_domains 
            SET status = $1::domain_status,
                verification_method = COALESCE($2::verification_method, verification_method),
                verified_at = COALESCE($3, verified_at),
                updated_at = NOW()
            WHERE tenant_id = $4::uuid AND id = $5::uuid
            RETURNING 
                id::text as id, organization_id::text as organization_id, tenant_id::text as tenant_id,
                domain, status::text as status, verification_method::text as verification_method,
                verification_token, verified_at, created_at, updated_at,
                auto_enroll_enabled, default_role, dns_hostname, file_path, html_meta_content"#
        )
        .bind(status)
        .bind(method)
        .bind(verified_at)
        .bind(tenant_id)
        .bind(domain_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Update domain settings
    pub async fn update_settings(
        &self,
        tenant_id: &str,
        domain_id: &str,
        auto_enroll_enabled: Option<bool>,
        default_role: Option<String>,
    ) -> anyhow::Result<OrganizationDomain> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let row = sqlx::query_as::<_, OrganizationDomainRow>(
            r#"UPDATE organization_domains 
            SET auto_enroll_enabled = COALESCE($1, auto_enroll_enabled),
                default_role = COALESCE($2, default_role),
                updated_at = NOW()
            WHERE tenant_id = $3::uuid AND id = $4::uuid
            RETURNING 
                id::text as id, organization_id::text as organization_id, tenant_id::text as tenant_id,
                domain, status::text as status, verification_method::text as verification_method,
                verification_token, verified_at, created_at, updated_at,
                auto_enroll_enabled, default_role, dns_hostname, file_path, html_meta_content"#
        )
        .bind(auto_enroll_enabled)
        .bind(default_role)
        .bind(tenant_id)
        .bind(domain_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    /// Delete domain
    pub async fn delete(&self, tenant_id: &str, domain_id: &str) -> anyhow::Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        sqlx::query(
            "DELETE FROM organization_domains WHERE tenant_id = $1::uuid AND id = $2::uuid",
        )
        .bind(tenant_id)
        .bind(domain_id)
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    /// Count domains for organization
    pub async fn count_for_organization(
        &self,
        tenant_id: &str,
        organization_id: &str,
    ) -> anyhow::Result<i64> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM organization_domains WHERE tenant_id = $1::uuid AND organization_id = $2::uuid"
        )
        .bind(tenant_id)
        .bind(organization_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(count)
    }

    /// Check if domain exists for organization
    pub async fn exists(
        &self,
        tenant_id: &str,
        organization_id: &str,
        domain: &str,
    ) -> anyhow::Result<bool> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM organization_domains WHERE tenant_id = $1::uuid AND organization_id = $2::uuid AND domain = $3)"
        )
        .bind(tenant_id)
        .bind(organization_id)
        .bind(domain)
        .fetch_one(&mut *conn)
        .await?;

        Ok(exists)
    }

    /// Get all verified domains with auto-enrollment enabled
    pub async fn get_auto_enrollment_domains(
        &self,
        domain: &str,
    ) -> anyhow::Result<Vec<OrganizationDomain>> {
        let rows = sqlx::query_as::<_, OrganizationDomainRow>(
            r#"SELECT 
                id::text as id, organization_id::text as organization_id, tenant_id::text as tenant_id,
                domain, status::text as status, verification_method::text as verification_method,
                verification_token, verified_at, created_at, updated_at,
                auto_enroll_enabled, default_role, dns_hostname, file_path, html_meta_content
            FROM organization_domains 
            WHERE domain = $1 
              AND status = 'verified'
              AND auto_enroll_enabled = true
            ORDER BY created_at ASC"#
        )
        .bind(domain)
        .fetch_all(&*self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }
}
