//! Home Realm Discovery
//!
//! Determines the Identity Provider based on email domain or other hints.
//! This enables automatic routing of authentication requests to the
//! appropriate external IdP without requiring user intervention.

use std::collections::HashMap;

use crate::db::Database;
use crate::federation::{FederationError, FederationResult};

/// Home Realm Discovery service
#[derive(Debug, Clone)]
pub struct HomeRealmDiscovery {
    db: Database,
}

/// Realm mapping between domain and IdP
#[derive(Debug, Clone)]
pub struct RealmMapping {
    pub id: String,
    pub tenant_id: String,
    pub domain: String,
    pub provider_id: String,
    pub is_default: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl HomeRealmDiscovery {
    /// Create a new Home Realm Discovery service
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Find the IdP for an email domain
    pub async fn discover(&self, email: &str) -> FederationResult<Option<RealmMapping>> {
        // Extract domain from email
        let domain = self.extract_domain(email)
            .ok_or_else(|| FederationError::DiscoveryFailed(
                format!("Invalid email format: {}", email)
            ))?;

        self.discover_by_domain(domain).await
    }

    /// Find the IdP for a domain directly
    pub async fn discover_by_domain(&self, domain: &str) -> FederationResult<Option<RealmMapping>> {
        // First check realm_mappings table
        let row = sqlx::query_as::<_, RealmMappingRow>(
            r#"
            SELECT id, tenant_id, domain, provider_id, is_default, created_at
            FROM realm_mappings
            WHERE domain = $1
            ORDER BY is_default DESC
            LIMIT 1
            "#
        )
        .bind(domain.to_lowercase())
        .fetch_optional(self.db.pool())
        .await?;

        if let Some(mapping) = row {
            return Ok(Some(mapping.into()));
        }

        // Fallback to idp_domains table (legacy support)
        let row = sqlx::query_as::<_, RealmMappingRow>(
            r#"
            SELECT d.id, d.tenant_id, d.domain, d.provider_id, false as is_default, d.created_at
            FROM idp_domains d
            JOIN idp_providers p ON p.id = d.provider_id
            WHERE d.domain = $1 AND p.status = 'active'
            LIMIT 1
            "#
        )
        .bind(domain.to_lowercase())
        .fetch_optional(self.db.pool())
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Extract domain from email address
    pub fn extract_domain<'a>(&self, email: &'a str) -> Option<&'a str> {
        email.split('@').nth(1)
    }

    /// Get default IdP for tenant
    pub async fn get_default(&self, tenant_id: &str) -> FederationResult<Option<RealmMapping>> {
        let row = sqlx::query_as::<_, RealmMappingRow>(
            r#"
            SELECT id, tenant_id, domain, provider_id, is_default, created_at
            FROM realm_mappings
            WHERE tenant_id = $1 AND is_default = true
            LIMIT 1
            "#
        )
        .bind(tenant_id)
        .fetch_optional(self.db.pool())
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Create a realm mapping
    pub async fn create_mapping(
        &self,
        tenant_id: &str,
        domain: &str,
        provider_id: &str,
        is_default: bool,
    ) -> FederationResult<RealmMapping> {
        // If this is set as default, unset any existing default
        if is_default {
            sqlx::query(
                "UPDATE realm_mappings SET is_default = false WHERE tenant_id = $1 AND is_default = true"
            )
            .bind(tenant_id)
            .execute(self.db.pool())
            .await?;
        }

        // Check if mapping already exists for this domain
        let existing: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM realm_mappings WHERE tenant_id = $1 AND domain = $2"
        )
        .bind(tenant_id)
        .bind(domain.to_lowercase())
        .fetch_optional(self.db.pool())
        .await?;

        if let Some((id,)) = existing {
            // Update existing mapping
            sqlx::query(
                "UPDATE realm_mappings SET provider_id = $1, is_default = $2 WHERE id = $3"
            )
            .bind(provider_id)
            .bind(is_default)
            .bind(&id)
            .execute(self.db.pool())
            .await?;

            return Ok(RealmMapping {
                id,
                tenant_id: tenant_id.to_string(),
                domain: domain.to_lowercase(),
                provider_id: provider_id.to_string(),
                is_default,
                created_at: chrono::Utc::now(),
            });
        }

        // Create new mapping
        let id = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            r#"
            INSERT INTO realm_mappings (id, tenant_id, domain, provider_id, is_default)
            VALUES ($1, $2, $3, $4, $5)
            "#
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(domain.to_lowercase())
        .bind(provider_id)
        .bind(is_default)
        .execute(self.db.pool())
        .await?;

        Ok(RealmMapping {
            id,
            tenant_id: tenant_id.to_string(),
            domain: domain.to_lowercase(),
            provider_id: provider_id.to_string(),
            is_default,
            created_at: chrono::Utc::now(),
        })
    }

    /// Update a realm mapping
    pub async fn update_mapping(
        &self,
        mapping_id: &str,
        provider_id: Option<&str>,
        is_default: Option<bool>,
    ) -> FederationResult<Option<RealmMapping>> {
        if let Some(provider) = provider_id {
            sqlx::query("UPDATE realm_mappings SET provider_id = $1 WHERE id = $2")
                .bind(provider)
                .bind(mapping_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(default) = is_default {
            if default {
                // Get tenant_id first
                let tenant_id: Option<(String,)> = sqlx::query_as(
                    "SELECT tenant_id FROM realm_mappings WHERE id = $1"
                )
                .bind(mapping_id)
                .fetch_optional(self.db.pool())
                .await?;

                if let Some((tenant_id,)) = tenant_id {
                    sqlx::query(
                        "UPDATE realm_mappings SET is_default = false WHERE tenant_id = $1 AND is_default = true"
                    )
                    .bind(&tenant_id)
                    .execute(self.db.pool())
                    .await?;
                }
            }

            sqlx::query("UPDATE realm_mappings SET is_default = $1 WHERE id = $2")
                .bind(default)
                .bind(mapping_id)
                .execute(self.db.pool())
                .await?;
        }

        // Return updated mapping
        let row = sqlx::query_as::<_, RealmMappingRow>(
            "SELECT id, tenant_id, domain, provider_id, is_default, created_at FROM realm_mappings WHERE id = $1"
        )
        .bind(mapping_id)
        .fetch_optional(self.db.pool())
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Delete a realm mapping
    pub async fn delete_mapping(&self, mapping_id: &str) -> FederationResult<()> {
        sqlx::query("DELETE FROM realm_mappings WHERE id = $1")
            .bind(mapping_id)
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    /// List all realm mappings for a tenant
    pub async fn list_mappings(&self, tenant_id: &str) -> FederationResult<Vec<RealmMapping>> {
        let rows = sqlx::query_as::<_, RealmMappingRow>(
            r#"
            SELECT id, tenant_id, domain, provider_id, is_default, created_at
            FROM realm_mappings
            WHERE tenant_id = $1
            ORDER BY is_default DESC, domain ASC
            "#
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Batch discover IdPs for multiple emails
    pub async fn batch_discover(&self, emails: &[String]) -> FederationResult<HashMap<String, Option<RealmMapping>>> {
        let mut results = HashMap::new();

        for email in emails {
            let mapping = self.discover(email).await?;
            results.insert(email.clone(), mapping);
        }

        Ok(results)
    }

    /// Check if a domain has an associated IdP
    pub async fn is_domain_configured(&self, domain: &str) -> FederationResult<bool> {
        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM realm_mappings 
            WHERE domain = $1
            UNION ALL
            SELECT COUNT(*) FROM idp_domains 
            WHERE domain = $1
            "#
        )
        .bind(domain.to_lowercase())
        .fetch_one(self.db.pool())
        .await?;

        Ok(count.0 > 0)
    }
}

// Database row types

#[derive(sqlx::FromRow)]
struct RealmMappingRow {
    id: String,
    tenant_id: String,
    domain: String,
    provider_id: String,
    is_default: bool,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<RealmMappingRow> for RealmMapping {
    fn from(row: RealmMappingRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            domain: row.domain,
            provider_id: row.provider_id,
            is_default: row.is_default,
            created_at: row.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_extract_domain() {
        // Helper function to extract domain
        fn extract_domain(email: &str) -> Option<&str> {
            email.split('@').nth(1)
        }

        let email = "user@example.com";
        assert_eq!(extract_domain(email), Some("example.com"));

        let email2 = "user@sub.example.com";
        assert_eq!(extract_domain(email2), Some("sub.example.com"));

        let invalid = "not-an-email";
        assert_eq!(extract_domain(invalid), None);
    }
}
