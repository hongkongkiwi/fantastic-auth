//! Trust Relationships
//!
//! Manages trust relationships with external Identity Providers.
//! Handles certificate validation, metadata refresh, and trust levels.

use chrono::{DateTime, Utc};
use base64::Engine;

use crate::db::Database;
use crate::federation::{FederationError, FederationResult, FederatedProvider};

/// Trust manager for handling IdP trust relationships
#[derive(Debug, Clone)]
pub struct TrustManager {
    db: Database,
}

/// Trust relationship with an external IdP
#[derive(Debug, Clone)]
pub struct TrustRelationship {
    pub id: String,
    pub tenant_id: String,
    pub provider_id: String,
    pub metadata_url: Option<String>,
    pub metadata_xml: Option<String>,
    pub certificate_fingerprint: String,
    pub trust_level: TrustLevel,
    pub auto_provision_users: bool,
    pub allowed_claims: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Trust levels for IdP relationships
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// Full trust - accept all claims without verification
    Full,
    /// Partial trust - verify specific claims
    Partial,
    /// Minimal trust - only trust subject identifier
    Minimal,
}

impl TrustLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Full => "full",
            TrustLevel::Partial => "partial",
            TrustLevel::Minimal => "minimal",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "full" => Some(TrustLevel::Full),
            "partial" => Some(TrustLevel::Partial),
            "minimal" => Some(TrustLevel::Minimal),
            _ => None,
        }
    }
}

/// Certificate validation result
#[derive(Debug, Clone)]
pub struct CertValidationResult {
    pub valid: bool,
    pub fingerprint: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub errors: Vec<String>,
}

impl TrustManager {
    /// Create a new trust manager
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Create a trust relationship
    pub async fn create_trust(
        &self,
        tenant_id: &str,
        provider_id: &str,
        metadata_url: Option<&str>,
        metadata_xml: Option<&str>,
        certificate_fingerprint: &str,
        trust_level: TrustLevel,
        auto_provision_users: bool,
        allowed_claims: Vec<String>,
    ) -> FederationResult<TrustRelationship> {
        let id = uuid::Uuid::new_v4().to_string();

        sqlx::query(
            r#"
            INSERT INTO trust_relationships 
            (id, tenant_id, provider_id, metadata_url, metadata_xml, certificate_fingerprint,
             trust_level, auto_provision_users, allowed_claims)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(provider_id)
        .bind(metadata_url)
        .bind(metadata_xml)
        .bind(certificate_fingerprint)
        .bind(trust_level.as_str())
        .bind(auto_provision_users)
        .bind(&allowed_claims)
        .execute(self.db.pool())
        .await?;

        Ok(TrustRelationship {
            id,
            tenant_id: tenant_id.to_string(),
            provider_id: provider_id.to_string(),
            metadata_url: metadata_url.map(|s| s.to_string()),
            metadata_xml: metadata_xml.map(|s| s.to_string()),
            certificate_fingerprint: certificate_fingerprint.to_string(),
            trust_level,
            auto_provision_users,
            allowed_claims,
            created_at: Utc::now(),
            updated_at: None,
        })
    }

    /// Get trust relationship by ID
    pub async fn get_trust(&self, trust_id: &str) -> FederationResult<Option<TrustRelationship>> {
        let row = sqlx::query_as::<_, TrustRelationshipRow>(
            r#"
            SELECT id, tenant_id, provider_id, metadata_url, metadata_xml, certificate_fingerprint,
                   trust_level, auto_provision_users, allowed_claims, created_at, updated_at
            FROM trust_relationships
            WHERE id = $1
            "#
        )
        .bind(trust_id)
        .fetch_optional(self.db.pool())
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Get trust relationship for a provider
    pub async fn get_trust_for_provider(&self, provider_id: &str) -> FederationResult<Option<TrustRelationship>> {
        let row = sqlx::query_as::<_, TrustRelationshipRow>(
            r#"
            SELECT id, tenant_id, provider_id, metadata_url, metadata_xml, certificate_fingerprint,
                   trust_level, auto_provision_users, allowed_claims, created_at, updated_at
            FROM trust_relationships
            WHERE provider_id = $1
            LIMIT 1
            "#
        )
        .bind(provider_id)
        .fetch_optional(self.db.pool())
        .await?;

        Ok(row.map(|r| r.into()))
    }

    /// Update trust relationship
    pub async fn update_trust(
        &self,
        trust_id: &str,
        updates: TrustUpdates,
    ) -> FederationResult<TrustRelationship> {
        if let Some(ref metadata_url) = updates.metadata_url {
            sqlx::query("UPDATE trust_relationships SET metadata_url = $1 WHERE id = $2")
                .bind(metadata_url)
                .bind(trust_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(ref metadata_xml) = updates.metadata_xml {
            sqlx::query("UPDATE trust_relationships SET metadata_xml = $1 WHERE id = $2")
                .bind(metadata_xml)
                .bind(trust_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(ref fingerprint) = updates.certificate_fingerprint {
            sqlx::query("UPDATE trust_relationships SET certificate_fingerprint = $1 WHERE id = $2")
                .bind(fingerprint)
                .bind(trust_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(trust_level) = updates.trust_level {
            sqlx::query("UPDATE trust_relationships SET trust_level = $1 WHERE id = $2")
                .bind(trust_level.as_str())
                .bind(trust_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(auto_provision) = updates.auto_provision_users {
            sqlx::query("UPDATE trust_relationships SET auto_provision_users = $1 WHERE id = $2")
                .bind(auto_provision)
                .bind(trust_id)
                .execute(self.db.pool())
                .await?;
        }

        if let Some(ref allowed_claims) = updates.allowed_claims {
            sqlx::query("UPDATE trust_relationships SET allowed_claims = $1 WHERE id = $2")
                .bind(allowed_claims)
                .bind(trust_id)
                .execute(self.db.pool())
                .await?;
        }

        self.get_trust(trust_id)
            .await?
            .ok_or_else(|| FederationError::Internal("Trust not found after update".to_string()))
    }

    /// Delete trust relationship
    pub async fn delete_trust(&self, trust_id: &str) -> FederationResult<()> {
        sqlx::query("DELETE FROM trust_relationships WHERE id = $1")
            .bind(trust_id)
            .execute(self.db.pool())
            .await?;
        Ok(())
    }

    /// List trust relationships for a tenant
    pub async fn list_trusts(&self, tenant_id: &str) -> FederationResult<Vec<TrustRelationship>> {
        let rows = sqlx::query_as::<_, TrustRelationshipRow>(
            r#"
            SELECT id, tenant_id, provider_id, metadata_url, metadata_xml, certificate_fingerprint,
                   trust_level, auto_provision_users, allowed_claims, created_at, updated_at
            FROM trust_relationships
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            "#
        )
        .bind(tenant_id)
        .fetch_all(self.db.pool())
        .await?;

        Ok(rows.into_iter().map(|r| r.into()).collect())
    }

    /// Validate trust for a provider
    pub async fn validate_trust(
        &self,
        provider: &FederatedProvider,
        certificate: &str,
    ) -> FederationResult<CertValidationResult> {
        // Get trust relationship
        let trust = self.get_trust_for_provider(&provider.id).await?;

        // Calculate certificate fingerprint
        let fingerprint = self.calculate_fingerprint(certificate);

        let mut errors = Vec::new();
        let mut valid = true;

        // If trust relationship exists, verify fingerprint
        if let Some(trust) = trust {
            if trust.certificate_fingerprint != fingerprint {
                errors.push("Certificate fingerprint mismatch".to_string());
                valid = false;
            }

            // Check trust level
            match trust.trust_level {
                TrustLevel::Full => {
                    // No additional checks needed
                }
                TrustLevel::Partial => {
                    // Additional verification could be done here
                }
                TrustLevel::Minimal => {
                    // Minimal trust - only validate fingerprint
                }
            }
        }

        // Parse certificate for additional info (placeholder)
        // In production, use x509-parser or similar

        Ok(CertValidationResult {
            valid,
            fingerprint,
            expires_at: None, // Would be parsed from certificate
            issuer: None,
            subject: None,
            errors,
        })
    }

    /// Update trust metadata from URL
    pub async fn refresh_metadata(&self, trust_id: &str) -> FederationResult<()> {
        let trust = self.get_trust(trust_id).await?
            .ok_or_else(|| FederationError::Internal("Trust not found".to_string()))?;

        let metadata_url = trust.metadata_url
            .ok_or_else(|| FederationError::InvalidConfiguration("No metadata URL configured".to_string()))?;

        // Fetch metadata
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| FederationError::Internal(format!("Failed to create HTTP client: {}", e)))?;

        let metadata = client.get(&metadata_url)
            .send()
            .await
            .map_err(|e| FederationError::Internal(format!("Failed to fetch metadata: {}", e)))?
            .text()
            .await
            .map_err(|e| FederationError::Internal(format!("Failed to read metadata: {}", e)))?;

        // Update metadata in database
        sqlx::query("UPDATE trust_relationships SET metadata_xml = $1, updated_at = NOW() WHERE id = $2")
            .bind(&metadata)
            .bind(trust_id)
            .execute(self.db.pool())
            .await?;

        // Extract and update certificate fingerprint if present
        if let Some(fingerprint) = self.extract_fingerprint_from_metadata(&metadata) {
            sqlx::query("UPDATE trust_relationships SET certificate_fingerprint = $1 WHERE id = $2")
                .bind(&fingerprint)
                .bind(trust_id)
                .execute(self.db.pool())
                .await?;
        }

        Ok(())
    }

    /// Calculate SHA-256 fingerprint of a certificate
    fn calculate_fingerprint(&self, certificate: &str) -> String {
        // Remove PEM headers if present
        let cert_data = certificate
            .lines()
            .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
            .collect::<String>();

        // Decode base64
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&cert_data) {
            // Calculate SHA-256 hash
            let hash = ring::digest::digest(&ring::digest::SHA256, &decoded);
            // Format as colon-separated hex
            hash.as_ref()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":")
        } else {
            // Fallback: hash the raw string
            let hash = ring::digest::digest(&ring::digest::SHA256, certificate.as_bytes());
            hash.as_ref()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":")
        }
    }

    /// Extract certificate fingerprint from SAML metadata
    fn extract_fingerprint_from_metadata(&self, metadata: &str) -> Option<String> {
        // Simple XML parsing to extract X509Certificate
        // In production, use proper XML parsing
        if let Some(start) = metadata.find("<X509Certificate>") {
            if let Some(end) = metadata.find("</X509Certificate>") {
                let cert_start = start + "<X509Certificate>".len();
                let cert = &metadata[cert_start..end];
                
                // Wrap in PEM format
                let pem = format!(
                    "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
                    cert
                );
                
                return Some(self.calculate_fingerprint(&pem));
            }
        }
        None
    }

    /// Check if a claim is allowed based on trust level
    pub fn is_claim_allowed(&self, trust: &TrustRelationship, claim: &str) -> bool {
        match trust.trust_level {
            TrustLevel::Full => true,
            TrustLevel::Partial => trust.allowed_claims.contains(&claim.to_string()),
            TrustLevel::Minimal => {
                // Only allow essential claims
                matches!(claim, "sub" | "email" | "name_id")
            }
        }
    }

    /// Filter claims based on trust level
    pub fn filter_claims(
        &self,
        trust: &TrustRelationship,
        claims: &std::collections::HashMap<String, String>,
    ) -> std::collections::HashMap<String, String> {
        claims
            .iter()
            .filter(|(k, _)| self.is_claim_allowed(trust, k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// Updates for a trust relationship
#[derive(Debug, Clone, Default)]
pub struct TrustUpdates {
    pub metadata_url: Option<String>,
    pub metadata_xml: Option<String>,
    pub certificate_fingerprint: Option<String>,
    pub trust_level: Option<TrustLevel>,
    pub auto_provision_users: Option<bool>,
    pub allowed_claims: Option<Vec<String>>,
}

// Database row types

#[derive(sqlx::FromRow)]
struct TrustRelationshipRow {
    id: String,
    tenant_id: String,
    provider_id: String,
    metadata_url: Option<String>,
    metadata_xml: Option<String>,
    certificate_fingerprint: String,
    trust_level: String,
    auto_provision_users: bool,
    allowed_claims: Vec<String>,
    created_at: DateTime<Utc>,
    updated_at: Option<DateTime<Utc>>,
}

impl From<TrustRelationshipRow> for TrustRelationship {
    fn from(row: TrustRelationshipRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            provider_id: row.provider_id,
            metadata_url: row.metadata_url,
            metadata_xml: row.metadata_xml,
            certificate_fingerprint: row.certificate_fingerprint,
            trust_level: TrustLevel::from_str(&row.trust_level).unwrap_or(TrustLevel::Minimal),
            auto_provision_users: row.auto_provision_users,
            allowed_claims: row.allowed_claims,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trust_level_from_str() {
        assert_eq!(TrustLevel::from_str("full"), Some(TrustLevel::Full));
        assert_eq!(TrustLevel::from_str("partial"), Some(TrustLevel::Partial));
        assert_eq!(TrustLevel::from_str("minimal"), Some(TrustLevel::Minimal));
        assert_eq!(TrustLevel::from_str("unknown"), None);
    }

    #[test]
    fn test_trust_level_as_str() {
        assert_eq!(TrustLevel::Full.as_str(), "full");
        assert_eq!(TrustLevel::Partial.as_str(), "partial");
        assert_eq!(TrustLevel::Minimal.as_str(), "minimal");
    }
}
