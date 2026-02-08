//! Custom Domain Repository Implementation
//!
//! SQLx-based repository for custom domain operations.

use super::custom::{
    CustomDomain, CustomDomainRepository, CustomDomainStatus, DomainBranding, TenantDomainInfo,
};
use sqlx::{FromRow, PgPool, Row};
use std::sync::Arc;
use vault_core::db::set_connection_context;

/// Database row for custom domains
#[derive(Debug, FromRow)]
struct CustomDomainRow {
    id: String,
    tenant_id: String,
    domain: String,
    status: String,
    verification_token: String,
    verified_at: Option<chrono::DateTime<chrono::Utc>>,
    ssl_provider: String,
    certificate_path: Option<String>,
    private_key_path: Option<String>,
    certificate_chain_path: Option<String>,
    certificate_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    auto_ssl: bool,
    force_https: bool,
    target_cname: Option<String>,
    last_dns_check_at: Option<chrono::DateTime<chrono::Utc>>,
    last_dns_check_result: Option<bool>,
    last_dns_error: Option<String>,
    brand_logo_url: Option<String>,
    brand_primary_color: Option<String>,
    brand_page_title: Option<String>,
    brand_favicon_url: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    created_by: Option<String>,
}

impl From<CustomDomainRow> for CustomDomain {
    fn from(row: CustomDomainRow) -> Self {
        CustomDomain {
            id: row.id,
            tenant_id: row.tenant_id,
            domain: row.domain,
            status: row.status.parse().unwrap_or(CustomDomainStatus::Pending),
            verification_token: row.verification_token,
            verified_at: row.verified_at,
            ssl_provider: row.ssl_provider.parse().unwrap_or_default(),
            certificate_path: row.certificate_path,
            private_key_path: row.private_key_path,
            certificate_chain_path: row.certificate_chain_path,
            certificate_expires_at: row.certificate_expires_at,
            auto_ssl: row.auto_ssl,
            force_https: row.force_https,
            target_cname: row.target_cname,
            last_dns_check_at: row.last_dns_check_at,
            last_dns_check_result: row.last_dns_check_result,
            last_dns_error: row.last_dns_error,
            brand_logo_url: row.brand_logo_url,
            brand_primary_color: row.brand_primary_color,
            brand_page_title: row.brand_page_title,
            brand_favicon_url: row.brand_favicon_url,
            created_at: row.created_at,
            updated_at: row.updated_at,
            created_by: row.created_by,
        }
    }
}

/// SQLx implementation of custom domain repository
#[derive(Clone)]
pub struct SqlxCustomDomainRepository {
    pool: Arc<PgPool>,
}

impl SqlxCustomDomainRepository {
    /// Create a new repository
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Get connection with tenant context set
    async fn tenant_conn(
        &self,
        tenant_id: &str,
    ) -> anyhow::Result<sqlx::pool::PoolConnection<sqlx::Postgres>> {
        let mut conn = self.pool.acquire().await?;
        set_connection_context(&mut conn, tenant_id).await?;
        Ok(conn)
    }
}

#[async_trait::async_trait]
impl CustomDomainRepository for SqlxCustomDomainRepository {
    async fn create(&self, domain: &CustomDomain) -> anyhow::Result<CustomDomain> {
        let mut conn = self.tenant_conn(&domain.tenant_id).await?;

        let row = sqlx::query_as::<_, CustomDomainRow>(
            r#"INSERT INTO custom_domains (
                id, tenant_id, domain, status, verification_token, verified_at,
                ssl_provider, certificate_path, private_key_path, certificate_chain_path,
                certificate_expires_at, auto_ssl, force_https, target_cname,
                last_dns_check_at, last_dns_check_result, last_dns_error,
                brand_logo_url, brand_primary_color, brand_page_title, brand_favicon_url,
                created_at, updated_at, created_by
            ) VALUES (
                $1::uuid, $2::uuid, $3, $4::custom_domain_status, $5, $6,
                $7::ssl_provider, $8, $9, $10, $11, $12, $13, $14,
                $15, $16, $17, $18, $19, $20, $21, $22, $23, $24::uuid
            ) RETURNING 
                id::text as id, tenant_id::text as tenant_id, domain, status::text as status,
                verification_token, verified_at,
                ssl_provider::text as ssl_provider, certificate_path, private_key_path,
                certificate_chain_path, certificate_expires_at, auto_ssl, force_https,
                target_cname, last_dns_check_at, last_dns_check_result, last_dns_error,
                brand_logo_url, brand_primary_color, brand_page_title, brand_favicon_url,
                created_at, updated_at, created_by::text as created_by"#,
        )
        .bind(&domain.id)
        .bind(&domain.tenant_id)
        .bind(&domain.domain)
        .bind(domain.status)
        .bind(&domain.verification_token)
        .bind(domain.verified_at)
        .bind(domain.ssl_provider)
        .bind(&domain.certificate_path)
        .bind(&domain.private_key_path)
        .bind(&domain.certificate_chain_path)
        .bind(domain.certificate_expires_at)
        .bind(domain.auto_ssl)
        .bind(domain.force_https)
        .bind(&domain.target_cname)
        .bind(domain.last_dns_check_at)
        .bind(domain.last_dns_check_result)
        .bind(&domain.last_dns_error)
        .bind(&domain.brand_logo_url)
        .bind(&domain.brand_primary_color)
        .bind(&domain.brand_page_title)
        .bind(&domain.brand_favicon_url)
        .bind(domain.created_at)
        .bind(domain.updated_at)
        .bind(&domain.created_by)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    async fn get_by_id(&self, tenant_id: &str, id: &str) -> anyhow::Result<Option<CustomDomain>> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let row = sqlx::query_as::<_, CustomDomainRow>(
            r#"SELECT 
                id::text as id, tenant_id::text as tenant_id, domain, status::text as status,
                verification_token, verified_at,
                ssl_provider::text as ssl_provider, certificate_path, private_key_path,
                certificate_chain_path, certificate_expires_at, auto_ssl, force_https,
                target_cname, last_dns_check_at, last_dns_check_result, last_dns_error,
                brand_logo_url, brand_primary_color, brand_page_title, brand_favicon_url,
                created_at, updated_at, created_by::text as created_by
            FROM custom_domains 
            WHERE tenant_id = $1::uuid AND id = $2::uuid"#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    async fn get_by_domain(&self, domain: &str) -> anyhow::Result<Option<CustomDomain>> {
        // This query doesn't need tenant context as we're looking up by domain
        let row = sqlx::query_as::<_, CustomDomainRow>(
            r#"SELECT 
                id::text as id, tenant_id::text as tenant_id, domain, status::text as status,
                verification_token, verified_at,
                ssl_provider::text as ssl_provider, certificate_path, private_key_path,
                certificate_chain_path, certificate_expires_at, auto_ssl, force_https,
                target_cname, last_dns_check_at, last_dns_check_result, last_dns_error,
                brand_logo_url, brand_primary_color, brand_page_title, brand_favicon_url,
                created_at, updated_at, created_by::text as created_by
            FROM custom_domains 
            WHERE domain = $1"#,
        )
        .bind(domain.to_lowercase())
        .fetch_optional(&*self.pool)
        .await?;

        Ok(row.map(Into::into))
    }

    async fn get_by_domain_for_tenant(
        &self,
        tenant_id: &str,
        domain: &str,
    ) -> anyhow::Result<Option<CustomDomain>> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let row = sqlx::query_as::<_, CustomDomainRow>(
            r#"SELECT 
                id::text as id, tenant_id::text as tenant_id, domain, status::text as status,
                verification_token, verified_at,
                ssl_provider::text as ssl_provider, certificate_path, private_key_path,
                certificate_chain_path, certificate_expires_at, auto_ssl, force_https,
                target_cname, last_dns_check_at, last_dns_check_result, last_dns_error,
                brand_logo_url, brand_primary_color, brand_page_title, brand_favicon_url,
                created_at, updated_at, created_by::text as created_by
            FROM custom_domains 
            WHERE tenant_id = $1::uuid AND domain = $2"#,
        )
        .bind(tenant_id)
        .bind(domain.to_lowercase())
        .fetch_optional(&mut *conn)
        .await?;

        Ok(row.map(Into::into))
    }

    async fn list_for_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<CustomDomain>> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let rows = sqlx::query_as::<_, CustomDomainRow>(
            r#"SELECT 
                id::text as id, tenant_id::text as tenant_id, domain, status::text as status,
                verification_token, verified_at,
                ssl_provider::text as ssl_provider, certificate_path, private_key_path,
                certificate_chain_path, certificate_expires_at, auto_ssl, force_https,
                target_cname, last_dns_check_at, last_dns_check_result, last_dns_error,
                brand_logo_url, brand_primary_color, brand_page_title, brand_favicon_url,
                created_at, updated_at, created_by::text as created_by
            FROM custom_domains 
            WHERE tenant_id = $1::uuid
            ORDER BY created_at DESC"#,
        )
        .bind(tenant_id)
        .fetch_all(&mut *conn)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn update(&self, domain: &CustomDomain) -> anyhow::Result<CustomDomain> {
        let mut conn = self.tenant_conn(&domain.tenant_id).await?;

        let row = sqlx::query_as::<_, CustomDomainRow>(
            r#"UPDATE custom_domains SET
                domain = $1,
                status = $2::custom_domain_status,
                verified_at = $3,
                ssl_provider = $4::ssl_provider,
                certificate_path = $5,
                private_key_path = $6,
                certificate_chain_path = $7,
                certificate_expires_at = $8,
                auto_ssl = $9,
                force_https = $10,
                target_cname = $11,
                last_dns_check_at = $12,
                last_dns_check_result = $13,
                last_dns_error = $14,
                brand_logo_url = $15,
                brand_primary_color = $16,
                brand_page_title = $17,
                brand_favicon_url = $18,
                updated_at = NOW()
            WHERE id = $19::uuid AND tenant_id = $20::uuid
            RETURNING 
                id::text as id, tenant_id::text as tenant_id, domain, status::text as status,
                verification_token, verified_at,
                ssl_provider::text as ssl_provider, certificate_path, private_key_path,
                certificate_chain_path, certificate_expires_at, auto_ssl, force_https,
                target_cname, last_dns_check_at, last_dns_check_result, last_dns_error,
                brand_logo_url, brand_primary_color, brand_page_title, brand_favicon_url,
                created_at, updated_at, created_by::text as created_by"#,
        )
        .bind(&domain.domain)
        .bind(domain.status)
        .bind(domain.verified_at)
        .bind(domain.ssl_provider)
        .bind(&domain.certificate_path)
        .bind(&domain.private_key_path)
        .bind(&domain.certificate_chain_path)
        .bind(domain.certificate_expires_at)
        .bind(domain.auto_ssl)
        .bind(domain.force_https)
        .bind(&domain.target_cname)
        .bind(domain.last_dns_check_at)
        .bind(domain.last_dns_check_result)
        .bind(&domain.last_dns_error)
        .bind(&domain.brand_logo_url)
        .bind(&domain.brand_primary_color)
        .bind(&domain.brand_page_title)
        .bind(&domain.brand_favicon_url)
        .bind(&domain.id)
        .bind(&domain.tenant_id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    async fn update_status(
        &self,
        tenant_id: &str,
        id: &str,
        status: CustomDomainStatus,
    ) -> anyhow::Result<CustomDomain> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let verified_at = if status == CustomDomainStatus::Active {
            Some(chrono::Utc::now())
        } else {
            None
        };

        let row = sqlx::query_as::<_, CustomDomainRow>(
            r#"UPDATE custom_domains 
            SET status = $1::custom_domain_status,
                verified_at = COALESCE($2, verified_at),
                updated_at = NOW()
            WHERE tenant_id = $3::uuid AND id = $4::uuid
            RETURNING 
                id::text as id, tenant_id::text as tenant_id, domain, status::text as status,
                verification_token, verified_at,
                ssl_provider::text as ssl_provider, certificate_path, private_key_path,
                certificate_chain_path, certificate_expires_at, auto_ssl, force_https,
                target_cname, last_dns_check_at, last_dns_check_result, last_dns_error,
                brand_logo_url, brand_primary_color, brand_page_title, brand_favicon_url,
                created_at, updated_at, created_by::text as created_by"#,
        )
        .bind(status)
        .bind(verified_at)
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    async fn update_dns_check(
        &self,
        tenant_id: &str,
        id: &str,
        success: bool,
        error: Option<String>,
    ) -> anyhow::Result<CustomDomain> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        let row = sqlx::query_as::<_, CustomDomainRow>(
            r#"UPDATE custom_domains 
            SET last_dns_check_at = NOW(),
                last_dns_check_result = $1,
                last_dns_error = $2,
                updated_at = NOW()
            WHERE tenant_id = $3::uuid AND id = $4::uuid
            RETURNING 
                id::text as id, tenant_id::text as tenant_id, domain, status::text as status,
                verification_token, verified_at,
                ssl_provider::text as ssl_provider, certificate_path, private_key_path,
                certificate_chain_path, certificate_expires_at, auto_ssl, force_https,
                target_cname, last_dns_check_at, last_dns_check_result, last_dns_error,
                brand_logo_url, brand_primary_color, brand_page_title, brand_favicon_url,
                created_at, updated_at, created_by::text as created_by"#,
        )
        .bind(success)
        .bind(error)
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;

        Ok(row.into())
    }

    async fn delete(&self, tenant_id: &str, id: &str) -> anyhow::Result<()> {
        let mut conn = self.tenant_conn(tenant_id).await?;

        sqlx::query("DELETE FROM custom_domains WHERE tenant_id = $1::uuid AND id = $2::uuid")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }

    async fn get_domains_needing_renewal(&self) -> anyhow::Result<Vec<CustomDomain>> {
        // Get domains where certificate expires within 30 days or has no certificate
        let rows = sqlx::query_as::<_, CustomDomainRow>(
            r#"SELECT 
                id::text as id, tenant_id::text as tenant_id, domain, status::text as status,
                verification_token, verified_at,
                ssl_provider::text as ssl_provider, certificate_path, private_key_path,
                certificate_chain_path, certificate_expires_at, auto_ssl, force_https,
                target_cname, last_dns_check_at, last_dns_check_result, last_dns_error,
                brand_logo_url, brand_primary_color, brand_page_title, brand_favicon_url,
                created_at, updated_at, created_by::text as created_by
            FROM custom_domains 
            WHERE status = 'active'
              AND auto_ssl = true
              AND ssl_provider = 'lets_encrypt'
              AND (
                  certificate_expires_at IS NULL
                  OR certificate_expires_at < NOW() + INTERVAL '30 days'
              )
            ORDER BY certificate_expires_at ASC NULLS FIRST"#,
        )
        .fetch_all(&*self.pool)
        .await?;

        Ok(rows.into_iter().map(Into::into).collect())
    }

    async fn get_tenant_by_domain(&self, domain: &str) -> anyhow::Result<Option<TenantDomainInfo>> {
        // Use the database function for efficient lookup
        let row = sqlx::query("SELECT * FROM get_tenant_by_custom_domain($1)")
            .bind(domain.to_lowercase())
            .fetch_optional(&*self.pool)
            .await?;

        match row {
            Some(r) => {
                let tenant_id: String = r.try_get("tenant_id")?;
                let custom_domain_id: String = r.try_get("custom_domain_id")?;
                let force_https: bool = r.try_get("force_https")?;

                let branding = DomainBranding {
                    logo_url: r.try_get("brand_logo_url").ok(),
                    primary_color: r.try_get("brand_primary_color").ok(),
                    page_title: r.try_get("brand_page_title").ok(),
                    favicon_url: r.try_get("brand_favicon_url").ok(),
                };

                Ok(Some(TenantDomainInfo {
                    tenant_id,
                    custom_domain_id,
                    force_https,
                    branding,
                }))
            }
            None => Ok(None),
        }
    }
}
