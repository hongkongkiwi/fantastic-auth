//! Domain verification models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Domain verification status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "domain_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum DomainStatus {
    /// Domain added but not yet verified
    Pending,
    /// Domain verified successfully
    Verified,
    /// Verification failed
    Failed,
    /// Verification expired
    Expired,
}

impl DomainStatus {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

impl std::str::FromStr for DomainStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "verified" => Ok(Self::Verified),
            "failed" => Ok(Self::Failed),
            "expired" => Ok(Self::Expired),
            _ => Err(format!("Unknown domain status: {}", s)),
        }
    }
}

impl Default for DomainStatus {
    fn default() -> Self {
        Self::Pending
    }
}

/// Domain verification method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "verification_method", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// DNS TXT record verification
    Dns,
    /// HTML meta tag verification
    HtmlMeta,
    /// File upload verification
    File,
}

impl VerificationMethod {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::HtmlMeta => "html_meta",
            Self::File => "file",
        }
    }
}

impl std::str::FromStr for VerificationMethod {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "dns" => Ok(Self::Dns),
            "html_meta" => Ok(Self::HtmlMeta),
            "file" => Ok(Self::File),
            _ => Err(format!("Unknown verification method: {}", s)),
        }
    }
}

impl Default for VerificationMethod {
    fn default() -> Self {
        Self::Dns
    }
}

/// Organization domain model
#[derive(Debug, Clone, Default, Serialize, Deserialize, FromRow)]
pub struct OrganizationDomain {
    /// Unique identifier
    pub id: String,
    /// Organization ID
    pub organization_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Domain name (e.g., "company.com")
    pub domain: String,
    /// Verification status
    pub status: DomainStatus,
    /// Verification method used
    pub verification_method: VerificationMethod,
    /// Verification token (e.g., "vault-verify=abc123xyz")
    pub verification_token: String,
    /// When the domain was verified
    pub verified_at: Option<DateTime<Utc>>,
    /// When the domain was created
    pub created_at: DateTime<Utc>,
    /// When the domain was last updated
    pub updated_at: DateTime<Utc>,
    /// Whether auto-enrollment is enabled
    pub auto_enroll_enabled: bool,
    /// Default role for auto-enrolled users
    pub default_role: String,
    /// DNS verification hostname (e.g., "_vault.company.com")
    pub dns_hostname: Option<String>,
    /// File verification path
    pub file_path: Option<String>,
    /// HTML meta tag content
    pub html_meta_content: Option<String>,
}

impl OrganizationDomain {
    /// Create a new organization domain
    pub fn new(
        tenant_id: impl Into<String>,
        organization_id: impl Into<String>,
        domain: impl Into<String>,
        verification_token: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        let domain_str = domain.into();
        let token = verification_token.into();

        // Generate DNS hostname
        let dns_hostname = format!("_vault.{}", domain_str);

        // Generate file path
        let file_path = format!("/.well-known/vault-verify-{}", &token[..16]);

        // Generate HTML meta content
        let html_meta_content = token.clone();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            organization_id: organization_id.into(),
            tenant_id: tenant_id.into(),
            domain: domain_str,
            status: DomainStatus::Pending,
            verification_method: VerificationMethod::Dns,
            verification_token: token,
            verified_at: None,
            created_at: now,
            updated_at: now,
            auto_enroll_enabled: true,
            default_role: "member".to_string(),
            dns_hostname: Some(dns_hostname),
            file_path: Some(file_path),
            html_meta_content: Some(html_meta_content),
        }
    }

    /// Mark domain as verified
    pub fn mark_verified(&mut self, method: VerificationMethod) {
        self.status = DomainStatus::Verified;
        self.verification_method = method;
        self.verified_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Mark domain as failed
    pub fn mark_failed(&mut self) {
        self.status = DomainStatus::Failed;
        self.updated_at = Utc::now();
    }

    /// Mark domain as expired
    pub fn mark_expired(&mut self) {
        self.status = DomainStatus::Expired;
        self.updated_at = Utc::now();
    }

    /// Check if domain is verified
    pub fn is_verified(&self) -> bool {
        matches!(self.status, DomainStatus::Verified)
    }

    /// Get the expected DNS TXT record value
    pub fn dns_txt_record(&self) -> String {
        format!("vault-verify={}", self.verification_token)
    }

    /// Get the expected HTML meta tag
    pub fn html_meta_tag(&self) -> String {
        format!(
            r#"<meta name="vault-verification" content="{}" />"#,
            self.verification_token
        )
    }

    /// Set default role for auto-enrollment
    pub fn set_default_role(&mut self, role: impl Into<String>) {
        self.default_role = role.into();
        self.updated_at = Utc::now();
    }

    /// Enable/disable auto-enrollment
    pub fn set_auto_enroll(&mut self, enabled: bool) {
        self.auto_enroll_enabled = enabled;
        self.updated_at = Utc::now();
    }
}

/// Domain verification attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationAttempt {
    /// Unique identifier
    pub id: String,
    /// Domain ID
    pub domain_id: String,
    /// Attempted method
    pub method: VerificationMethod,
    /// Whether the attempt succeeded
    pub success: bool,
    /// Error message if failed
    pub error_message: Option<String>,
    /// DNS records found (for DNS verification)
    pub dns_records: Option<Vec<String>>,
    /// Attempt timestamp
    pub attempted_at: DateTime<Utc>,
}

impl VerificationAttempt {
    /// Create a new verification attempt
    pub fn new(domain_id: impl Into<String>, method: VerificationMethod) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            domain_id: domain_id.into(),
            method,
            success: false,
            error_message: None,
            dns_records: None,
            attempted_at: Utc::now(),
        }
    }

    /// Mark as successful
    pub fn succeed(mut self) -> Self {
        self.success = true;
        self
    }

    /// Mark as failed with error
    pub fn fail(mut self, error: impl Into<String>) -> Self {
        self.success = false;
        self.error_message = Some(error.into());
        self
    }

    /// Set DNS records found
    pub fn with_dns_records(mut self, records: Vec<String>) -> Self {
        self.dns_records = Some(records);
        self
    }
}

/// Request to create a domain
#[derive(Debug, Clone, Deserialize)]
pub struct CreateDomainRequest {
    pub domain: String,
    pub auto_enroll_enabled: Option<bool>,
    pub default_role: Option<String>,
}

/// Request to update a domain
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateDomainRequest {
    pub auto_enroll_enabled: Option<bool>,
    pub default_role: Option<String>,
}

/// Domain response for API
#[derive(Debug, Clone, Serialize)]
pub struct DomainResponse {
    pub id: String,
    pub domain: String,
    #[serde(rename = "organizationId")]
    pub organization_id: String,
    pub status: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "autoEnrollEnabled")]
    pub auto_enroll_enabled: bool,
    #[serde(rename = "defaultRole")]
    pub default_role: String,
    #[serde(rename = "dnsInstructions")]
    pub dns_instructions: Option<DnsInstructions>,
    #[serde(rename = "htmlMetaInstructions")]
    pub html_meta_instructions: Option<HtmlMetaInstructions>,
    #[serde(rename = "fileInstructions")]
    pub file_instructions: Option<FileInstructions>,
}

impl From<OrganizationDomain> for DomainResponse {
    fn from(domain: OrganizationDomain) -> Self {
        let dns_instructions = if domain.status == DomainStatus::Pending {
            Some(DnsInstructions {
                hostname: domain.dns_hostname.clone().unwrap_or_default(),
                txt_record: domain.dns_txt_record(),
            })
        } else {
            None
        };

        let html_meta_instructions = if domain.status == DomainStatus::Pending {
            Some(HtmlMetaInstructions {
                meta_tag: domain.html_meta_tag(),
            })
        } else {
            None
        };

        let file_instructions = if domain.status == DomainStatus::Pending {
            Some(FileInstructions {
                file_path: domain.file_path.clone().unwrap_or_default(),
                file_content: domain.verification_token.clone(),
            })
        } else {
            None
        };

        Self {
            id: domain.id,
            domain: domain.domain,
            organization_id: domain.organization_id,
            status: domain.status.as_str().to_string(),
            verification_method: domain.verification_method.as_str().to_string(),
            verified_at: domain.verified_at.map(|d| d.to_rfc3339()),
            created_at: domain.created_at.to_rfc3339(),
            updated_at: domain.updated_at.to_rfc3339(),
            auto_enroll_enabled: domain.auto_enroll_enabled,
            default_role: domain.default_role,
            dns_instructions,
            html_meta_instructions,
            file_instructions,
        }
    }
}

/// DNS verification instructions
#[derive(Debug, Clone, Serialize)]
pub struct DnsInstructions {
    pub hostname: String,
    #[serde(rename = "txtRecord")]
    pub txt_record: String,
}

/// HTML meta verification instructions
#[derive(Debug, Clone, Serialize)]
pub struct HtmlMetaInstructions {
    #[serde(rename = "metaTag")]
    pub meta_tag: String,
}

/// File verification instructions
#[derive(Debug, Clone, Serialize)]
pub struct FileInstructions {
    #[serde(rename = "filePath")]
    pub file_path: String,
    #[serde(rename = "fileContent")]
    pub file_content: String,
}

/// Request to verify domain via DNS
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyDnsRequest {
    #[serde(rename = "verificationMethod")]
    pub verification_method: Option<String>,
}

/// Auto-enrollment result
#[derive(Debug, Clone)]
pub struct AutoEnrollmentResult {
    pub enrolled: bool,
    pub organization_id: Option<String>,
    pub role: Option<String>,
}
