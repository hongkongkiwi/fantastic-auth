//! Custom Domain Service
//!
//! High-level service for managing custom domains, including DNS verification,
//! SSL certificate management, and tenant routing.

use super::custom::{
    CustomDomain, CustomDomainDnsVerifier, CustomDomainRepository, CustomDomainStatus,
    DnsVerificationResult, DomainBranding, DomainValidationError, DomainValidator, SslProvider,
    TenantDomainInfo,
};
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Custom domain service
#[derive(Clone)]
pub struct CustomDomainService<R: CustomDomainRepository> {
    repository: R,
    dns_verifier: CustomDomainDnsVerifier,
    config: CustomDomainConfig,
}

/// Custom domain configuration
#[derive(Debug, Clone)]
pub struct CustomDomainConfig {
    /// Base domain for CNAME target (e.g., "vault.example.com")
    pub base_domain: String,
    /// SSL certificate storage path
    pub cert_storage_path: String,
    /// Whether to automatically verify DNS on creation
    pub auto_verify_dns: bool,
    /// Enable SSL/TLS (set to false if behind reverse proxy)
    pub enable_ssl: bool,
}

impl Default for CustomDomainConfig {
    fn default() -> Self {
        Self {
            base_domain: "vault.example.com".to_string(),
            cert_storage_path: "/etc/vault/certs".to_string(),
            auto_verify_dns: false,
            enable_ssl: false, // Default to false (assume reverse proxy handles SSL)
        }
    }
}

impl<R: CustomDomainRepository> CustomDomainService<R> {
    /// Create a new custom domain service
    pub async fn new(repository: R, config: CustomDomainConfig) -> anyhow::Result<Self> {
        let dns_verifier = CustomDomainDnsVerifier::new().await?;

        Ok(Self {
            repository,
            dns_verifier,
            config,
        })
    }

    /// Create a new custom domain
    pub async fn create_domain(
        &self,
        tenant_id: &str,
        domain_name: &str,
        created_by: Option<&str>,
    ) -> anyhow::Result<CustomDomain> {
        // Validate domain format
        let sanitized = DomainValidator::sanitize(domain_name);
        DomainValidator::validate_format(&sanitized)?;

        // Check if domain already exists
        if let Some(existing) = self.repository.get_by_domain(&sanitized).await? {
            if existing.tenant_id != tenant_id {
                anyhow::bail!(
                    "Domain '{}' is already registered by another tenant",
                    sanitized
                );
            } else {
                anyhow::bail!(
                    "Domain '{}' is already registered for this tenant",
                    sanitized
                );
            }
        }

        // Create the domain
        let target_cname = self.config.base_domain.clone();
        let mut domain = CustomDomain::new(tenant_id, &sanitized, &target_cname);
        domain.created_by = created_by.map(|s| s.to_string());

        // Save to database
        let domain = self.repository.create(&domain).await?;

        info!(
            "Created custom domain '{}' for tenant {}",
            domain.domain, tenant_id
        );

        // Optionally auto-verify DNS
        if self.config.auto_verify_dns {
            let _ = self.verify_dns(tenant_id, &domain.id).await;
        }

        Ok(domain)
    }

    /// Get a custom domain by ID
    pub async fn get_domain(
        &self,
        tenant_id: &str,
        domain_id: &str,
    ) -> anyhow::Result<Option<CustomDomain>> {
        self.repository.get_by_id(tenant_id, domain_id).await
    }

    /// Get a custom domain by domain name (for any tenant - used for routing)
    pub async fn get_domain_by_name(&self, domain: &str) -> anyhow::Result<Option<CustomDomain>> {
        self.repository
            .get_by_domain(&DomainValidator::sanitize(domain))
            .await
    }

    /// List all custom domains for a tenant
    pub async fn list_domains(&self, tenant_id: &str) -> anyhow::Result<Vec<CustomDomain>> {
        self.repository.list_for_tenant(tenant_id).await
    }

    /// Delete a custom domain
    pub async fn delete_domain(&self, tenant_id: &str, domain_id: &str) -> anyhow::Result<()> {
        // Get the domain first to verify ownership
        let domain = self
            .repository
            .get_by_id(tenant_id, domain_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Domain not found"))?;

        // Clean up SSL certificates if they exist
        if let Some(ref cert_path) = domain.certificate_path {
            if let Err(e) = tokio::fs::remove_file(cert_path).await {
                warn!("Failed to remove certificate file: {}", e);
            }
        }
        if let Some(ref key_path) = domain.private_key_path {
            if let Err(e) = tokio::fs::remove_file(key_path).await {
                warn!("Failed to remove private key file: {}", e);
            }
        }

        // Delete from database
        self.repository.delete(tenant_id, domain_id).await?;

        info!("Deleted custom domain '{}'", domain.domain);

        Ok(())
    }

    /// Verify DNS configuration for a domain
    pub async fn verify_dns(
        &self,
        tenant_id: &str,
        domain_id: &str,
    ) -> anyhow::Result<DnsVerificationResult> {
        let domain = self
            .repository
            .get_by_id(tenant_id, domain_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Domain not found"))?;

        let expected_target = domain.expected_cname();

        // Perform DNS verification
        let result = self
            .dns_verifier
            .verify_cname(&domain.domain, &expected_target)
            .await?;

        // Update DNS check result in database
        let error = result.error.clone();
        self.repository
            .update_dns_check(tenant_id, domain_id, result.success, error.clone())
            .await?;

        if result.success {
            // Mark as verified if DNS check passed
            let mut updated = domain;
            updated.mark_verified();
            self.repository.update(&updated).await?;

            info!(
                "DNS verification successful for domain '{}'",
                updated.domain
            );

            // If SSL is enabled and auto-managed, trigger SSL provisioning
            if self.config.enable_ssl && updated.auto_ssl {
                // This would trigger SSL certificate provisioning
                // For now, just log it
                info!("SSL provisioning would be triggered for {}", updated.domain);
            }
        } else {
            warn!(
                "DNS verification failed for domain '{}': {:?}",
                domain.domain, error
            );
        }

        Ok(result)
    }

    /// Check DNS status without updating database
    pub async fn check_dns_status(&self, domain: &str) -> anyhow::Result<DnsVerificationResult> {
        let sanitized = DomainValidator::sanitize(domain);
        self.dns_verifier.check_dns(&sanitized).await
    }

    /// Get DNS instructions for a domain
    pub fn get_dns_instructions(&self, domain: &CustomDomain) -> DnsInstructions {
        DnsInstructions {
            domain: domain.domain.clone(),
            record_type: "CNAME".to_string(),
            name: domain.domain.clone(),
            value: domain.expected_cname(),
            verification_token: domain.verification_token.clone(),
            alternative_records: vec![
                AlternativeRecord {
                    record_type: "A".to_string(),
                    description: "Point to your server's IP address".to_string(),
                },
                AlternativeRecord {
                    record_type: "AAAA".to_string(),
                    description: "Point to your server's IPv6 address".to_string(),
                },
            ],
        }
    }

    /// Update domain branding
    pub async fn update_branding(
        &self,
        tenant_id: &str,
        domain_id: &str,
        branding: DomainBranding,
    ) -> anyhow::Result<CustomDomain> {
        let mut domain = self
            .repository
            .get_by_id(tenant_id, domain_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Domain not found"))?;

        domain.set_branding(branding);
        self.repository.update(&domain).await
    }

    /// Update SSL settings
    pub async fn update_ssl_settings(
        &self,
        tenant_id: &str,
        domain_id: &str,
        auto_ssl: bool,
        force_https: bool,
    ) -> anyhow::Result<CustomDomain> {
        let mut domain = self
            .repository
            .get_by_id(tenant_id, domain_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Domain not found"))?;

        domain.auto_ssl = auto_ssl;
        domain.force_https = force_https;
        domain.updated_at = chrono::Utc::now();

        self.repository.update(&domain).await
    }

    /// Upload custom SSL certificate
    pub async fn upload_custom_certificate(
        &self,
        tenant_id: &str,
        domain_id: &str,
        certificate: &str,
        private_key: &str,
        chain: Option<&str>,
    ) -> anyhow::Result<CustomDomain> {
        let domain = self
            .repository
            .get_by_id(tenant_id, domain_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Domain not found"))?;

        // Store certificate files
        let cert_path = format!("{}/{}-cert.pem", self.config.cert_storage_path, domain_id);
        let key_path = format!("{}/{}-key.pem", self.config.cert_storage_path, domain_id);
        let chain_path =
            chain.map(|_| format!("{}/{}-chain.pem", self.config.cert_storage_path, domain_id));

        // Write files (in production, ensure secure permissions)
        tokio::fs::create_dir_all(&self.config.cert_storage_path).await?;
        tokio::fs::write(&cert_path, certificate).await?;
        tokio::fs::write(&key_path, private_key).await?;
        if let Some(ref chain_path) = chain_path {
            tokio::fs::write(chain_path, chain.unwrap()).await?;
        }

        // Update domain with certificate info
        let mut updated = domain;
        updated.ssl_provider = SslProvider::Custom;
        updated.set_custom_certificate(&cert_path, &key_path, chain_path);
        updated.status = CustomDomainStatus::Active;
        updated.verified_at = Some(chrono::Utc::now());

        self.repository.update(&updated).await
    }

    /// Regenerate SSL certificate (for Let's Encrypt)
    pub async fn regenerate_ssl(
        &self,
        tenant_id: &str,
        domain_id: &str,
    ) -> anyhow::Result<CustomDomain> {
        let domain = self
            .repository
            .get_by_id(tenant_id, domain_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Domain not found"))?;

        if !domain.status.is_active() {
            anyhow::bail!("Domain must be active before SSL can be generated");
        }

        // Mark SSL as pending
        let mut updated = domain;
        updated.mark_ssl_pending();
        let updated = self.repository.update(&updated).await?;

        // In a real implementation, this would trigger ACME client
        // For now, just log and return
        info!("SSL regeneration requested for domain '{}'", updated.domain);

        Ok(updated)
    }

    /// Get SSL status for a domain
    pub async fn get_ssl_status(
        &self,
        tenant_id: &str,
        domain_id: &str,
    ) -> anyhow::Result<SslStatus> {
        let domain = self
            .repository
            .get_by_id(tenant_id, domain_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Domain not found"))?;

        let status = SslStatus {
            provider: domain.ssl_provider.as_str().to_string(),
            auto_ssl: domain.auto_ssl,
            force_https: domain.force_https,
            certificate_expires_at: domain.certificate_expires_at.map(|d| d.to_rfc3339()),
            days_until_expiry: domain.certificate_expires_at.map(|expiry| {
                let days = (expiry - chrono::Utc::now()).num_days();
                if days < 0 {
                    0
                } else {
                    days as u32
                }
            }),
            needs_renewal: domain.needs_renewal(),
        };

        Ok(status)
    }

    /// Get tenant info by domain (for routing)
    pub async fn get_tenant_by_domain(
        &self,
        domain: &str,
    ) -> anyhow::Result<Option<TenantDomainInfo>> {
        self.repository
            .get_tenant_by_domain(&DomainValidator::sanitize(domain))
            .await
    }

    /// Process domains needing certificate renewal
    pub async fn process_renewals(&self) -> anyhow::Result<Vec<RenewalResult>> {
        let domains = self.repository.get_domains_needing_renewal().await?;
        let mut results = Vec::new();

        for domain in domains {
            info!("Processing renewal for domain '{}'", domain.domain);

            // In a real implementation, this would use ACME client to renew
            // For now, just log and create a result
            let result = RenewalResult {
                domain_id: domain.id.clone(),
                domain: domain.domain.clone(),
                success: false, // Would be true if ACME succeeded
                message: "ACME renewal not implemented".to_string(),
            };

            results.push(result);
        }

        Ok(results)
    }
}

/// DNS instructions for domain setup
#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsInstructions {
    pub domain: String,
    pub record_type: String,
    pub name: String,
    pub value: String,
    pub verification_token: String,
    pub alternative_records: Vec<AlternativeRecord>,
}

/// Alternative DNS record option
#[derive(Debug, Clone, serde::Serialize)]
pub struct AlternativeRecord {
    pub record_type: String,
    pub description: String,
}

/// SSL status information
#[derive(Debug, Clone, serde::Serialize)]
pub struct SslStatus {
    pub provider: String,
    pub auto_ssl: bool,
    pub force_https: bool,
    pub certificate_expires_at: Option<String>,
    pub days_until_expiry: Option<u32>,
    pub needs_renewal: bool,
}

/// Certificate renewal result
#[derive(Debug, Clone)]
pub struct RenewalResult {
    pub domain_id: String,
    pub domain: String,
    pub success: bool,
    pub message: String,
}

/// Service factory for creating service with Sqlx repository
pub struct CustomDomainServiceFactory;

impl CustomDomainServiceFactory {
    /// Create a service with Sqlx repository
    pub async fn create_sqlx(
        pool: Arc<PgPool>,
        config: CustomDomainConfig,
    ) -> anyhow::Result<CustomDomainService<super::SqlxCustomDomainRepository>> {
        let repository = super::SqlxCustomDomainRepository::new(pool);
        CustomDomainService::new(repository, config).await
    }
}

/// Error type for custom domain operations
#[derive(Debug, thiserror::Error)]
pub enum CustomDomainError {
    #[error("Domain validation failed: {0}")]
    Validation(#[from] DomainValidationError),
    #[error("Domain not found")]
    NotFound,
    #[error("Domain already exists")]
    AlreadyExists,
    #[error("DNS verification failed: {0}")]
    DnsVerification(String),
    #[error("SSL provisioning failed: {0}")]
    SslProvisioning(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_domain_config_default() {
        let config = CustomDomainConfig::default();
        assert_eq!(config.base_domain, "vault.example.com");
        assert!(!config.enable_ssl);
    }

    #[tokio::test]
    async fn test_dns_instructions() {
        let domain = CustomDomain::new("tenant1", "auth.example.com", "vault.example.com");
        let service_config = CustomDomainConfig::default();
        let instructions = CustomDomainService::<crate::domains::SqlxCustomDomainRepository>::get_dns_instructions(
            &CustomDomainService {
                repository: crate::domains::SqlxCustomDomainRepository::new(Arc::new(
                    sqlx::Pool::connect_lazy("postgres://localhost/test").unwrap(),
                )),
                dns_verifier: CustomDomainDnsVerifier::new().await.unwrap(),
                config: service_config,
            },
            &domain,
        );

        assert_eq!(instructions.domain, "auth.example.com");
        assert_eq!(instructions.value, "vault.example.com");
    }
}
