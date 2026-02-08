//! Custom Domain (White-Label) Support
//!
//! Allows tenants to use their own domains (e.g., auth.company.com) for authentication pages.
//! Includes domain validation, DNS CNAME verification, and SSL certificate management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Custom domain status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "custom_domain_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CustomDomainStatus {
    /// Domain added but DNS not yet verified
    Pending,
    /// Domain verified and active
    Active,
    /// Verification or SSL error
    Error,
    /// SSL certificate pending
    SslPending,
    /// SSL certificate issuance failed
    SslFailed,
}

impl CustomDomainStatus {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Error => "error",
            Self::SslPending => "ssl_pending",
            Self::SslFailed => "ssl_failed",
        }
    }

    /// Check if domain is active
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Check if domain has SSL issues
    pub fn has_ssl_issue(&self) -> bool {
        matches!(self, Self::SslFailed | Self::SslPending)
    }
}

impl std::str::FromStr for CustomDomainStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "error" => Ok(Self::Error),
            "ssl_pending" => Ok(Self::SslPending),
            "ssl_failed" => Ok(Self::SslFailed),
            _ => Err(format!("Unknown custom domain status: {}", s)),
        }
    }
}

impl Default for CustomDomainStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// SSL provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "ssl_provider", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SslProvider {
    /// Let's Encrypt automatic SSL
    LetsEncrypt,
    /// Custom uploaded certificate
    Custom,
    /// No SSL (behind reverse proxy)
    None,
}

impl SslProvider {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LetsEncrypt => "lets_encrypt",
            Self::Custom => "custom",
            Self::None => "none",
        }
    }

    /// Check if SSL is managed automatically
    pub fn is_auto(&self) -> bool {
        matches!(self, Self::LetsEncrypt)
    }
}

impl Default for SslProvider {
    fn default() -> Self {
        Self::LetsEncrypt
    }
}

impl std::str::FromStr for SslProvider {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "lets_encrypt" => Ok(Self::LetsEncrypt),
            "custom" => Ok(Self::Custom),
            "none" => Ok(Self::None),
            _ => Err(format!("Unknown SSL provider: {}", s)),
        }
    }
}

/// Custom domain model
#[derive(Debug, Clone, Default, Serialize, Deserialize, FromRow)]
pub struct CustomDomain {
    /// Unique identifier
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Domain name (e.g., "auth.company.com")
    pub domain: String,
    /// Verification status
    pub status: CustomDomainStatus,
    /// Verification token
    pub verification_token: String,
    /// When the domain was verified
    pub verified_at: Option<DateTime<Utc>>,

    /// SSL provider
    pub ssl_provider: SslProvider,
    /// Path to certificate file
    pub certificate_path: Option<String>,
    /// Path to private key file
    pub private_key_path: Option<String>,
    /// Path to certificate chain file
    pub certificate_chain_path: Option<String>,
    /// When the certificate expires
    pub certificate_expires_at: Option<DateTime<Utc>>,
    /// Whether to auto-manage SSL
    pub auto_ssl: bool,
    /// Whether to force HTTPS
    pub force_https: bool,

    /// Expected CNAME target (e.g., "vault.example.com")
    pub target_cname: Option<String>,
    /// Last DNS check timestamp
    pub last_dns_check_at: Option<DateTime<Utc>>,
    /// Last DNS check result
    pub last_dns_check_result: Option<bool>,
    /// Last DNS error message
    pub last_dns_error: Option<String>,

    /// Brand logo URL for hosted pages
    pub brand_logo_url: Option<String>,
    /// Brand primary color (hex)
    pub brand_primary_color: Option<String>,
    /// Brand page title
    pub brand_page_title: Option<String>,
    /// Brand favicon URL
    pub brand_favicon_url: Option<String>,

    /// When the domain was created
    pub created_at: DateTime<Utc>,
    /// When the domain was last updated
    pub updated_at: DateTime<Utc>,
    /// User ID who created the domain
    pub created_by: Option<String>,
}

impl CustomDomain {
    /// Create a new custom domain
    pub fn new(
        tenant_id: impl Into<String>,
        domain: impl Into<String>,
        target_cname: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        let domain_str = domain.into().to_lowercase().trim().to_string();
        let token = generate_verification_token();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.into(),
            domain: domain_str,
            status: CustomDomainStatus::Pending,
            verification_token: token,
            verified_at: None,
            ssl_provider: SslProvider::LetsEncrypt,
            certificate_path: None,
            private_key_path: None,
            certificate_chain_path: None,
            certificate_expires_at: None,
            auto_ssl: true,
            force_https: true,
            target_cname: Some(target_cname.into()),
            last_dns_check_at: None,
            last_dns_check_result: None,
            last_dns_error: None,
            brand_logo_url: None,
            brand_primary_color: None,
            brand_page_title: None,
            brand_favicon_url: None,
            created_at: now,
            updated_at: now,
            created_by: None,
        }
    }

    /// Mark domain as verified
    pub fn mark_verified(&mut self) {
        self.status = CustomDomainStatus::Active;
        self.verified_at = Some(Utc::now());
        self.updated_at = Utc::now();
        self.last_dns_check_result = Some(true);
        self.last_dns_error = None;
    }

    /// Mark domain as having an error
    pub fn mark_error(&mut self, error: impl Into<String>) {
        self.status = CustomDomainStatus::Error;
        self.updated_at = Utc::now();
        self.last_dns_error = Some(error.into());
        self.last_dns_check_result = Some(false);
    }

    /// Mark SSL as pending
    pub fn mark_ssl_pending(&mut self) {
        self.status = CustomDomainStatus::SslPending;
        self.updated_at = Utc::now();
    }

    /// Mark SSL as failed
    pub fn mark_ssl_failed(&mut self, error: impl Into<String>) {
        self.status = CustomDomainStatus::SslFailed;
        self.updated_at = Utc::now();
        error!("SSL failed for domain {}: {}", self.domain, error.into());
    }

    /// Update certificate information
    pub fn set_certificate(
        &mut self,
        cert_path: impl Into<String>,
        key_path: impl Into<String>,
        expires_at: DateTime<Utc>,
    ) {
        self.certificate_path = Some(cert_path.into());
        self.private_key_path = Some(key_path.into());
        self.certificate_expires_at = Some(expires_at);
        self.updated_at = Utc::now();

        // If we were in SSL pending state, move to active
        if matches!(self.status, CustomDomainStatus::SslPending) {
            self.status = CustomDomainStatus::Active;
        }
    }

    /// Set custom certificate paths
    pub fn set_custom_certificate(
        &mut self,
        cert_path: impl Into<String>,
        key_path: impl Into<String>,
        chain_path: Option<String>,
    ) {
        self.ssl_provider = SslProvider::Custom;
        self.certificate_path = Some(cert_path.into());
        self.private_key_path = Some(key_path.into());
        self.certificate_chain_path = chain_path;
        self.updated_at = Utc::now();
    }

    /// Update DNS check result
    pub fn update_dns_check(&mut self, success: bool, error: Option<String>) {
        self.last_dns_check_at = Some(Utc::now());
        self.last_dns_check_result = Some(success);
        self.last_dns_error = error;
        self.updated_at = Utc::now();
    }

    /// Check if certificate needs renewal (expires within 30 days)
    pub fn needs_renewal(&self) -> bool {
        if !self.auto_ssl {
            return false;
        }

        match self.certificate_expires_at {
            Some(expires) => {
                let days_until_expiry = (expires - Utc::now()).num_days();
                days_until_expiry <= 30
            }
            None => true, // No certificate, needs one
        }
    }

    /// Get the expected DNS CNAME record
    pub fn expected_cname(&self) -> String {
        self.target_cname
            .clone()
            .unwrap_or_else(|| "vault.example.com".to_string())
    }

    /// Get branding configuration
    pub fn get_branding(&self) -> DomainBranding {
        DomainBranding {
            logo_url: self.brand_logo_url.clone(),
            primary_color: self.brand_primary_color.clone(),
            page_title: self.brand_page_title.clone(),
            favicon_url: self.brand_favicon_url.clone(),
        }
    }

    /// Update branding
    pub fn set_branding(&mut self, branding: DomainBranding) {
        self.brand_logo_url = branding.logo_url;
        self.brand_primary_color = branding.primary_color;
        self.brand_page_title = branding.page_title;
        self.brand_favicon_url = branding.favicon_url;
        self.updated_at = Utc::now();
    }

    /// Check if domain is valid for use
    pub fn is_ready(&self) -> bool {
        self.status == CustomDomainStatus::Active
    }
}

/// Domain branding configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainBranding {
    /// Logo URL
    pub logo_url: Option<String>,
    /// Primary color (hex)
    pub primary_color: Option<String>,
    /// Page title
    pub page_title: Option<String>,
    /// Favicon URL
    pub favicon_url: Option<String>,
}

/// DNS verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsVerificationResult {
    /// Whether verification succeeded
    pub success: bool,
    /// CNAME record found
    pub cname_record: Option<String>,
    /// A records found
    pub a_records: Vec<String>,
    /// AAAA records found
    pub aaaa_records: Vec<String>,
    /// Error message if failed
    pub error: Option<String>,
    /// DNS lookup timestamp
    pub checked_at: DateTime<Utc>,
}

/// Domain validator
pub struct DomainValidator;

impl DomainValidator {
    /// Validate domain format
    pub fn validate_format(domain: &str) -> Result<(), DomainValidationError> {
        let domain = domain.trim().to_lowercase();

        // Must not be empty
        if domain.is_empty() {
            return Err(DomainValidationError::Empty);
        }

        // Must not exceed 253 characters
        if domain.len() > 253 {
            return Err(DomainValidationError::TooLong);
        }

        // Must contain at least one dot
        if !domain.contains('.') {
            return Err(DomainValidationError::NoDot);
        }

        // Must not start or end with a dot
        if domain.starts_with('.') || domain.ends_with('.') {
            return Err(DomainValidationError::InvalidChars);
        }

        // Must not have consecutive dots
        if domain.contains("..") {
            return Err(DomainValidationError::InvalidChars);
        }

        // Validate each label
        for label in domain.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(DomainValidationError::LabelTooLong);
            }

            // Labels must start and end with alphanumeric
            let first_char = label.chars().next().unwrap();
            let last_char = label.chars().last().unwrap();

            if !first_char.is_alphanumeric() || !last_char.is_alphanumeric() {
                return Err(DomainValidationError::InvalidChars);
            }

            // Labels can only contain alphanumeric and hyphens
            for c in label.chars() {
                if !c.is_alphanumeric() && c != '-' {
                    return Err(DomainValidationError::InvalidChars);
                }
            }
        }

        // Check against public suffix list (basic check for common suffixes)
        if Self::is_public_suffix(&domain) {
            return Err(DomainValidationError::PublicSuffix);
        }

        Ok(())
    }

    /// Check if domain is a public suffix (simplified check)
    fn is_public_suffix(domain: &str) -> bool {
        let public_suffixes = [
            "com", "org", "net", "edu", "gov", "io", "co", "app", "dev", "cloud", "co.uk",
            "com.au", "co.jp", "com.br", "co.in", "co.nz", "co.za",
        ];

        let suffix: &str = domain
            .split('.')
            .skip(1)
            .collect::<Vec<_>>()
            .join(".")
            .as_str();
        public_suffixes
            .iter()
            .any(|&ps| suffix == ps || domain == ps)
    }

    /// Check if domain is an IP address
    pub fn is_ip_address(domain: &str) -> bool {
        domain.parse::<std::net::IpAddr>().is_ok()
    }

    /// Sanitize domain input
    pub fn sanitize(domain: &str) -> String {
        domain
            .trim()
            .to_lowercase()
            .replace("http://", "")
            .replace("https://", "")
            .replace("www.", "")
            .trim_end_matches('/')
            .to_string()
    }
}

/// Domain validation error
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DomainValidationError {
    /// Domain is empty
    Empty,
    /// Domain is too long
    TooLong,
    /// Label is too long
    LabelTooLong,
    /// Missing dot in domain
    NoDot,
    /// Invalid characters
    InvalidChars,
    /// Domain is a public suffix
    PublicSuffix,
    /// Domain is an IP address
    IpAddress,
    /// Domain is blacklisted
    Blacklisted,
}

impl std::fmt::Display for DomainValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "Domain cannot be empty"),
            Self::TooLong => write!(f, "Domain must not exceed 253 characters"),
            Self::LabelTooLong => write!(f, "Domain label must not exceed 63 characters"),
            Self::NoDot => write!(f, "Domain must contain at least one dot"),
            Self::InvalidChars => {
                write!(f, "Domain contains invalid characters")
            }
            Self::PublicSuffix => write!(f, "Domain is a public suffix"),
            Self::IpAddress => write!(f, "IP addresses are not allowed"),
            Self::Blacklisted => write!(f, "Domain is blacklisted"),
        }
    }
}

impl std::error::Error for DomainValidationError {}

/// Custom domain repository trait
#[async_trait::async_trait]
pub trait CustomDomainRepository: Send + Sync {
    /// Create a new custom domain
    async fn create(&self, domain: &CustomDomain) -> anyhow::Result<CustomDomain>;

    /// Get custom domain by ID
    async fn get_by_id(&self, tenant_id: &str, id: &str) -> anyhow::Result<Option<CustomDomain>>;

    /// Get custom domain by domain name
    async fn get_by_domain(&self, domain: &str) -> anyhow::Result<Option<CustomDomain>>;

    /// Get custom domain by domain name for a tenant
    async fn get_by_domain_for_tenant(
        &self,
        tenant_id: &str,
        domain: &str,
    ) -> anyhow::Result<Option<CustomDomain>>;

    /// List all custom domains for a tenant
    async fn list_for_tenant(&self, tenant_id: &str) -> anyhow::Result<Vec<CustomDomain>>;

    /// Update custom domain
    async fn update(&self, domain: &CustomDomain) -> anyhow::Result<CustomDomain>;

    /// Update domain status
    async fn update_status(
        &self,
        tenant_id: &str,
        id: &str,
        status: CustomDomainStatus,
    ) -> anyhow::Result<CustomDomain>;

    /// Update DNS check result
    async fn update_dns_check(
        &self,
        tenant_id: &str,
        id: &str,
        success: bool,
        error: Option<String>,
    ) -> anyhow::Result<CustomDomain>;

    /// Delete custom domain
    async fn delete(&self, tenant_id: &str, id: &str) -> anyhow::Result<()>;

    /// Get domains needing certificate renewal
    async fn get_domains_needing_renewal(&self) -> anyhow::Result<Vec<CustomDomain>>;

    /// Get tenant lookup info by domain (for routing)
    async fn get_tenant_by_domain(&self, domain: &str) -> anyhow::Result<Option<TenantDomainInfo>>;
}

/// Tenant domain info for routing
#[derive(Debug, Clone)]
pub struct TenantDomainInfo {
    pub tenant_id: String,
    pub custom_domain_id: String,
    pub force_https: bool,
    pub branding: DomainBranding,
}

/// Generate a verification token
fn generate_verification_token() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const TOKEN_LEN: usize = 32;

    let mut rng = rand::thread_rng();
    (0..TOKEN_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// DNS record verifier for custom domains
pub struct CustomDomainDnsVerifier {
    resolver: trust_dns_resolver::TokioAsyncResolver,
    timeout: Duration,
}

impl CustomDomainDnsVerifier {
    /// Create a new DNS verifier
    pub async fn new() -> anyhow::Result<Self> {
        let resolver = trust_dns_resolver::TokioAsyncResolver::tokio_from_system_conf()?;

        Ok(Self {
            resolver,
            timeout: Duration::from_secs(30),
        })
    }

    /// Verify domain CNAME record
    pub async fn verify_cname(
        &self,
        domain: &str,
        expected_target: &str,
    ) -> anyhow::Result<DnsVerificationResult> {
        let domain = domain.trim().to_lowercase();
        let expected = expected_target.trim().to_lowercase().trim_end_matches('.');

        info!(
            "Checking CNAME record for {}: expecting '{}'",
            domain, expected
        );

        // Try CNAME lookup first
        let cname_result =
            tokio::time::timeout(self.timeout, self.resolver.cname_lookup(&domain)).await;

        match cname_result {
            Ok(Ok(cname_lookup)) => {
                for cname in cname_lookup.iter() {
                    let target = cname.to_string().trim_end_matches('.').to_lowercase();
                    debug!("Found CNAME for {}: {}", domain, target);

                    if target == expected {
                        info!("CNAME verification successful for {}", domain);
                        return Ok(DnsVerificationResult {
                            success: true,
                            cname_record: Some(target),
                            a_records: vec![],
                            aaaa_records: vec![],
                            error: None,
                            checked_at: Utc::now(),
                        });
                    }
                }

                // CNAME exists but doesn't match
                let found = cname_lookup
                    .iter()
                    .next()
                    .map(|c| c.to_string().trim_end_matches('.').to_string());

                warn!(
                    "CNAME verification failed for {}: expected '{}', found '{:?}'",
                    domain, expected, found
                );

                Ok(DnsVerificationResult {
                    success: false,
                    cname_record: found,
                    a_records: vec![],
                    aaaa_records: vec![],
                    error: Some(format!("CNAME does not point to {}", expected_target)),
                    checked_at: Utc::now(),
                })
            }
            _ => {
                // No CNAME found, check for A/AAAA records as fallback
                debug!("No CNAME found for {}, checking A/AAAA records", domain);
                self.verify_a_records(&domain, expected_target).await
            }
        }
    }

    /// Verify A/AAAA records as alternative to CNAME
    async fn verify_a_records(
        &self,
        domain: &str,
        expected_target: &str,
    ) -> anyhow::Result<DnsVerificationResult> {
        // Lookup A records
        let a_result = tokio::time::timeout(self.timeout, self.resolver.ipv4_lookup(domain)).await;
        let mut a_records = Vec::new();

        if let Ok(Ok(lookup)) = a_result {
            for record in lookup.iter() {
                a_records.push(record.to_string());
            }
        }

        // Lookup AAAA records
        let aaaa_result =
            tokio::time::timeout(self.timeout, self.resolver.ipv6_lookup(domain)).await;
        let mut aaaa_records = Vec::new();

        if let Ok(Ok(lookup)) = aaaa_result {
            for record in lookup.iter() {
                aaaa_records.push(record.to_string());
            }
        }

        // Check if any A/AAAA records resolve to the expected target
        // Note: In production, you'd need to resolve the expected_target to compare IPs
        if !a_records.is_empty() || !aaaa_records.is_empty() {
            info!(
                "A/AAAA records found for {}: A={:?}, AAAA={:?}",
                domain, a_records, aaaa_records
            );

            // For now, we accept A/AAAA as valid if they exist
            // In a real implementation, you'd verify they point to your infrastructure IPs
            Ok(DnsVerificationResult {
                success: true,
                cname_record: None,
                a_records,
                aaaa_records,
                error: None,
                checked_at: Utc::now(),
            })
        } else {
            warn!("No DNS records found for {}", domain);
            Ok(DnsVerificationResult {
                success: false,
                cname_record: None,
                a_records,
                aaaa_records,
                error: Some(
                    "No CNAME, A, or AAAA records found. Please configure DNS for this domain."
                        .to_string(),
                ),
                checked_at: Utc::now(),
            })
        }
    }

    /// Check if domain has valid DNS configuration
    pub async fn check_dns(&self, domain: &str) -> anyhow::Result<DnsVerificationResult> {
        let domain = domain.trim().to_lowercase();

        // Check CNAME
        let cname_result =
            tokio::time::timeout(self.timeout, self.resolver.cname_lookup(&domain)).await;

        if let Ok(Ok(lookup)) = cname_result {
            if let Some(cname) = lookup.iter().next() {
                return Ok(DnsVerificationResult {
                    success: true,
                    cname_record: Some(cname.to_string().trim_end_matches('.').to_string()),
                    a_records: vec![],
                    aaaa_records: vec![],
                    error: None,
                    checked_at: Utc::now(),
                });
            }
        }

        // Check A/AAAA
        self.verify_a_records(&domain, "").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_validation_valid() {
        assert!(DomainValidator::validate_format("auth.company.com").is_ok());
        assert!(DomainValidator::validate_format("login.example.org").is_ok());
        assert!(DomainValidator::validate_format("secure-auth.my-app.io").is_ok());
    }

    #[test]
    fn test_domain_validation_invalid() {
        assert_eq!(
            DomainValidator::validate_format(""),
            Err(DomainValidationError::Empty)
        );
        assert_eq!(
            DomainValidator::validate_format("nodot"),
            Err(DomainValidationError::NoDot)
        );
        assert_eq!(
            DomainValidator::validate_format(".startswithdot.com"),
            Err(DomainValidationError::InvalidChars)
        );
        assert_eq!(
            DomainValidator::validate_format("endswithdot.com."),
            Err(DomainValidationError::InvalidChars)
        );
        assert_eq!(
            DomainValidator::validate_format("double..dots.com"),
            Err(DomainValidationError::InvalidChars)
        );
    }

    #[test]
    fn test_domain_sanitization() {
        assert_eq!(
            DomainValidator::sanitize("  https://Auth.Company.COM/  "),
            "auth.company.com"
        );
        assert_eq!(
            DomainValidator::sanitize("http://www.example.com"),
            "example.com"
        );
    }

    #[test]
    fn test_custom_domain_status() {
        assert!(CustomDomainStatus::Active.is_active());
        assert!(!CustomDomainStatus::Pending.is_active());
        assert!(CustomDomainStatus::SslFailed.has_ssl_issue());
    }

    #[test]
    fn test_needs_renewal() {
        let mut domain = CustomDomain::new("tenant1", "auth.example.com", "vault.example.com");

        // No certificate, needs renewal
        assert!(domain.needs_renewal());

        // Certificate expires in 60 days
        domain.certificate_expires_at = Some(Utc::now() + chrono::Duration::days(60));
        assert!(!domain.needs_renewal());

        // Certificate expires in 10 days
        domain.certificate_expires_at = Some(Utc::now() + chrono::Duration::days(10));
        assert!(domain.needs_renewal());

        // Auto SSL disabled
        domain.auto_ssl = false;
        assert!(!domain.needs_renewal());
    }
}
