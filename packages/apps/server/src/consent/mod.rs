//! Consent Management Module
//!
//! Provides GDPR/CCPA compliant consent tracking and management.
//! Features:
//! - Versioned consent policies
//! - User consent records
//! - Consent withdrawal
//! - Data export (GDPR right to data portability)
//! - Account deletion (GDPR right to erasure)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod manager;
pub mod models;
pub mod repository;
pub mod service;
pub mod templates;

pub use manager::ConsentManager;
pub use models::*;
pub use repository::ConsentRepository;
pub use service::ConsentService;
pub use templates::{PrivacyPolicyTemplate, get_available_templates, get_template_schema, render_template};

/// Consent type enum representing different categories of consent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "consent_type", rename_all = "snake_case")]
pub enum ConsentType {
    /// Terms of Service acceptance
    TermsOfService,
    /// Privacy Policy acceptance
    PrivacyPolicy,
    /// Marketing communications consent
    Marketing,
    /// Analytics/tracking consent
    Analytics,
    /// Cookie usage consent
    Cookies,
    /// Third-party data sharing
    DataSharing,
    /// Personalized advertising
    Advertising,
}

impl ConsentType {
    /// Get display name for the consent type
    pub fn display_name(&self) -> &'static str {
        match self {
            ConsentType::TermsOfService => "Terms of Service",
            ConsentType::PrivacyPolicy => "Privacy Policy",
            ConsentType::Marketing => "Marketing Communications",
            ConsentType::Analytics => "Analytics & Performance",
            ConsentType::Cookies => "Cookie Usage",
            ConsentType::DataSharing => "Third-Party Data Sharing",
            ConsentType::Advertising => "Personalized Advertising",
        }
    }

    /// Check if this consent type is required (cannot opt-out)
    pub fn is_required(&self) -> bool {
        matches!(self, ConsentType::TermsOfService | ConsentType::PrivacyPolicy)
    }

    /// Get all consent types
    pub fn all() -> Vec<ConsentType> {
        vec![
            ConsentType::TermsOfService,
            ConsentType::PrivacyPolicy,
            ConsentType::Marketing,
            ConsentType::Analytics,
            ConsentType::Cookies,
            ConsentType::DataSharing,
            ConsentType::Advertising,
        ]
    }

    /// Get optional consent types (can be opted out)
    pub fn optional() -> Vec<ConsentType> {
        Self::all()
            .into_iter()
            .filter(|t| !t.is_required())
            .collect()
    }
}

impl std::fmt::Display for ConsentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl std::str::FromStr for ConsentType {
    type Err = ConsentError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terms_of_service" | "tos" | "terms" => Ok(ConsentType::TermsOfService),
            "privacy_policy" | "privacy" => Ok(ConsentType::PrivacyPolicy),
            "marketing" => Ok(ConsentType::Marketing),
            "analytics" => Ok(ConsentType::Analytics),
            "cookies" | "cookie" => Ok(ConsentType::Cookies),
            "data_sharing" | "data-sharing" => Ok(ConsentType::DataSharing),
            "advertising" | "ads" => Ok(ConsentType::Advertising),
            _ => Err(ConsentError::InvalidConsentType(s.to_string())),
        }
    }
}

/// Consent record for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    /// Unique identifier
    pub id: String,
    /// User ID who gave consent
    pub user_id: String,
    /// Consent version ID
    pub consent_version_id: String,
    /// Whether consent was granted (true) or withdrawn (false)
    pub granted: bool,
    /// When consent was recorded
    pub granted_at: DateTime<Utc>,
    /// IP address when consent was given
    pub ip_address: Option<String>,
    /// User agent when consent was given
    pub user_agent: Option<String>,
    /// Country/region for jurisdiction tracking
    pub jurisdiction: Option<String>,
}

/// Consent version (policy version)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentVersion {
    /// Unique identifier
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Type of consent
    pub consent_type: ConsentType,
    /// Version string (e.g., "2.1")
    pub version: String,
    /// Title of the policy
    pub title: String,
    /// Full content (markdown/HTML)
    pub content: String,
    /// Summary for display
    pub summary: Option<String>,
    /// When this version becomes effective
    pub effective_date: DateTime<Utc>,
    /// URL to full policy
    pub url: Option<String>,
    /// Whether this is the current active version
    pub is_current: bool,
    /// Whether this consent type is required
    pub required: bool,
    /// Created at
    pub created_at: DateTime<Utc>,
}

/// User consent status for a specific consent type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConsentStatus {
    /// Consent type
    pub consent_type: ConsentType,
    /// Current version information
    pub current_version: ConsentVersionSummary,
    /// Whether user has consented to current version
    pub has_consented: bool,
    /// User's current consent record (if any)
    pub user_consent: Option<UserConsentDetail>,
    /// Whether consent is required
    pub required: bool,
}

/// Summary of a consent version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentVersionSummary {
    /// Version ID
    pub id: String,
    /// Version string
    pub version: String,
    /// Title
    pub title: String,
    /// Effective date
    pub effective_date: DateTime<Utc>,
    /// URL to policy
    pub url: Option<String>,
}

/// Detailed user consent information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserConsentDetail {
    /// Consent record ID
    pub id: String,
    /// Version consented to
    pub version: String,
    /// Whether consent was granted
    pub granted: bool,
    /// When consent was given
    pub granted_at: DateTime<Utc>,
    /// When consent was withdrawn (if applicable)
    pub withdrawn_at: Option<DateTime<Utc>>,
}

/// Consent requirement for operations
#[derive(Debug, Clone)]
pub struct ConsentRequirement {
    /// Type of consent required
    pub consent_type: ConsentType,
    /// Minimum version required (if None, any version accepted)
    pub min_version: Option<String>,
    /// Error message if consent not granted
    pub error_message: String,
}

impl ConsentRequirement {
    /// Create a new consent requirement
    pub fn new(consent_type: ConsentType) -> Self {
        Self {
            consent_type,
            min_version: None,
            error_message: format!("Consent required: {}", consent_type.display_name()),
        }
    }

    /// Set minimum version required
    pub fn min_version(mut self, version: impl Into<String>) -> Self {
        self.min_version = Some(version.into());
        self
    }

    /// Set custom error message
    pub fn error_message(mut self, message: impl Into<String>) -> Self {
        self.error_message = message.into();
        self
    }
}

/// Consent statistics for admin dashboard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentStatistics {
    /// Consent type
    pub consent_type: ConsentType,
    /// Version string
    pub version: String,
    /// Total users who have seen this version
    pub total_users: i64,
    /// Users who have granted consent
    pub granted_count: i64,
    /// Users who have withdrawn consent
    pub withdrawn_count: i64,
    /// Users who haven't responded
    pub pending_count: i64,
    /// Consent rate percentage
    pub consent_rate: f64,
}

/// Pending consent for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingConsent {
    /// Consent type
    pub consent_type: ConsentType,
    /// Version information
    pub version: ConsentVersionSummary,
    /// Whether consent is required
    pub required: bool,
    /// Reason for requiring consent (e.g., "new_version", "first_time")
    pub reason: String,
}

/// Data export request (GDPR Article 20)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataExportRequest {
    /// Request ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Request status
    pub status: DataExportStatus,
    /// Requested at
    pub requested_at: DateTime<Utc>,
    /// Completed at
    pub completed_at: Option<DateTime<Utc>>,
    /// Download URL (temporary)
    pub download_url: Option<String>,
    /// Expires at
    pub expires_at: Option<DateTime<Utc>>,
}

/// Data export status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "data_export_status", rename_all = "snake_case")]
pub enum DataExportStatus {
    /// Request received, pending processing
    Pending,
    /// Currently being prepared
    Processing,
    /// Ready for download
    Ready,
    /// Downloaded by user
    Downloaded,
    /// Expired
    Expired,
    /// Failed to generate
    Failed,
}

/// Account deletion request (GDPR Article 17)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionRequest {
    /// Request ID
    pub id: String,
    /// User ID
    pub user_id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Request status
    pub status: DeletionStatus,
    /// Requested at
    pub requested_at: DateTime<Utc>,
    /// Scheduled deletion date (after grace period)
    pub scheduled_deletion_at: DateTime<Utc>,
    /// Actually deleted at
    pub deleted_at: Option<DateTime<Utc>>,
    /// Cancellation token (to cancel deletion)
    pub cancellation_token: String,
    /// Reason for deletion (optional)
    pub reason: Option<String>,
}

/// Account deletion status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "deletion_status", rename_all = "snake_case")]
pub enum DeletionStatus {
    /// Pending during grace period
    Pending,
    /// User cancelled the request
    Cancelled,
    /// Deletion in progress
    Processing,
    /// Successfully deleted
    Completed,
    /// Failed to delete
    Failed,
}

/// Complete user data export (GDPR Article 20)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDataExport {
    /// Export metadata
    pub metadata: ExportMetadata,
    /// User profile data
    pub profile: serde_json::Value,
    /// Sessions
    pub sessions: Vec<serde_json::Value>,
    /// Audit logs
    pub audit_logs: Vec<serde_json::Value>,
    /// Consent history
    pub consents: Vec<serde_json::Value>,
    /// Organizations
    pub organizations: Vec<serde_json::Value>,
    /// OAuth connections
    pub oauth_connections: Vec<serde_json::Value>,
    /// Additional data
    pub additional_data: serde_json::Value,
}

/// Export metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportMetadata {
    /// User ID
    pub user_id: String,
    /// Export generated at
    pub generated_at: DateTime<Utc>,
    /// Version of export format
    pub version: String,
    /// Data categories included
    pub categories: Vec<String>,
}

/// Consent error types
#[derive(Debug, thiserror::Error)]
pub enum ConsentError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Consent version not found: {0}")]
    VersionNotFound(String),

    #[error("Consent record not found: {0}")]
    RecordNotFound(String),

    #[error("Invalid consent type: {0}")]
    InvalidConsentType(String),

    #[error("Consent required: {0}")]
    ConsentRequired(ConsentType),

    #[error("Consent version outdated: current={current}, required>={required}")]
    VersionOutdated { current: String, required: String },

    #[error("Cannot withdraw required consent: {0}")]
    CannotWithdrawRequired(ConsentType),

    #[error("Data export not found: {0}")]
    ExportNotFound(String),

    #[error("Deletion request not found: {0}")]
    DeletionRequestNotFound(String),

    #[error("Deletion request already cancelled")]
    DeletionAlreadyCancelled,

    #[error("Deletion request already completed")]
    DeletionAlreadyCompleted,

    #[error("Invalid version format: {0}")]
    InvalidVersionFormat(String),

    #[error("Export generation failed: {0}")]
    ExportGenerationFailed(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("User not found: {0}")]
    UserNotFound(String),
}

/// Result type for consent operations
pub type ConsentResult<T> = Result<T, ConsentError>;

/// Context for recording consent
#[derive(Debug, Clone)]
pub struct ConsentContext {
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Country/jurisdiction
    pub jurisdiction: Option<String>,
}

impl Default for ConsentContext {
    fn default() -> Self {
        Self {
            ip_address: None,
            user_agent: None,
            jurisdiction: None,
        }
    }
}

/// Submit consent request
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitConsentRequest {
    /// Consent type
    pub consent_type: ConsentType,
    /// Whether consent is granted
    pub granted: bool,
    /// Version being consented to (if None, uses current version)
    pub version_id: Option<String>,
}

/// Bulk submit consent request
#[derive(Debug, Clone, Deserialize)]
pub struct BulkSubmitConsentRequest {
    /// List of consent submissions
    pub consents: Vec<SubmitConsentRequest>,
}

/// Create consent version request (admin)
#[derive(Debug, Clone, Deserialize)]
pub struct CreateConsentVersionRequest {
    /// Consent type
    pub consent_type: ConsentType,
    /// Version string
    pub version: String,
    /// Title
    pub title: String,
    /// Content
    pub content: String,
    /// Summary
    pub summary: Option<String>,
    /// Effective date
    pub effective_date: DateTime<Utc>,
    /// URL to full policy
    pub url: Option<String>,
    /// Whether this should become the current version
    pub make_current: bool,
}

/// Update consent version request (admin)
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateConsentVersionRequest {
    /// Title
    pub title: Option<String>,
    /// Content
    pub content: Option<String>,
    /// Summary
    pub summary: Option<String>,
    /// URL
    pub url: Option<String>,
    /// Make current
    pub make_current: Option<bool>,
}

/// Request account deletion
#[derive(Debug, Clone, Deserialize)]
pub struct RequestDeletionRequest {
    /// Reason for deletion (optional)
    pub reason: Option<String>,
}

/// Cancel deletion request
#[derive(Debug, Clone, Deserialize)]
pub struct CancelDeletionRequest {
    /// Cancellation token
    pub token: String,
}

/// Consent configuration for tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentConfig {
    /// Grace period for account deletion in days
    pub deletion_grace_period_days: i32,
    /// Export retention days
    pub export_retention_days: i32,
    /// Whether to require explicit consent for all types
    pub require_explicit_consent: bool,
    /// Default jurisdiction
    pub default_jurisdiction: String,
    /// Cookie consent configuration
    pub cookie_consent: CookieConsentConfig,
}

impl Default for ConsentConfig {
    fn default() -> Self {
        Self {
            deletion_grace_period_days: 30,
            export_retention_days: 7,
            require_explicit_consent: true,
            default_jurisdiction: "GDPR".to_string(),
            cookie_consent: CookieConsentConfig::default(),
        }
    }
}

/// Cookie consent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieConsentConfig {
    /// Cookie banner enabled
    pub banner_enabled: bool,
    /// Cookie categories
    pub categories: Vec<CookieCategory>,
}

impl Default for CookieConsentConfig {
    fn default() -> Self {
        Self {
            banner_enabled: true,
            categories: vec![
                CookieCategory::necessary(),
                CookieCategory::analytics(),
                CookieCategory::marketing(),
            ],
        }
    }
}

/// Cookie category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CookieCategory {
    /// Category ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Description
    pub description: String,
    /// Whether required
    pub required: bool,
}

impl CookieCategory {
    /// Necessary cookies (required)
    pub fn necessary() -> Self {
        Self {
            id: "necessary".to_string(),
            name: "Necessary".to_string(),
            description: "Essential cookies required for the site to function.".to_string(),
            required: true,
        }
    }

    /// Analytics cookies
    pub fn analytics() -> Self {
        Self {
            id: "analytics".to_string(),
            name: "Analytics".to_string(),
            description: "Help us understand how visitors interact with our website.".to_string(),
            required: false,
        }
    }

    /// Marketing cookies
    pub fn marketing() -> Self {
        Self {
            id: "marketing".to_string(),
            name: "Marketing".to_string(),
            description: "Used to deliver personalized advertisements.".to_string(),
            required: false,
        }
    }
}

/// Check if consent is valid for an operation
pub fn check_consent(
    user_consent: Option<&ConsentRecord>,
    requirement: &ConsentRequirement,
    current_version: &str,
) -> ConsentResult<()> {
    let consent = match user_consent {
        Some(c) if c.granted => c,
        Some(_) => return Err(ConsentError::ConsentRequired(requirement.consent_type)),
        None => return Err(ConsentError::ConsentRequired(requirement.consent_type)),
    };

    // Check version requirement if specified
    if let Some(ref min_version) = requirement.min_version {
        if !version_meets_requirement(&consent.consent_version_id, min_version) {
            return Err(ConsentError::VersionOutdated {
                current: consent.consent_version_id.clone(),
                required: min_version.clone(),
            });
        }
    }

    Ok(())
}

/// Check if a version meets minimum requirement
/// Simple semver-like comparison (major.minor.patch)
fn version_meets_requirement(current: &str, required: &str) -> bool {
    let parse_version = |v: &str| {
        v.split('.')
            .map(|n| n.parse::<u32>().unwrap_or(0))
            .collect::<Vec<_>>()
    };

    let current_parts = parse_version(current);
    let required_parts = parse_version(required);

    for (c, r) in current_parts.iter().zip(required_parts.iter()) {
        match c.cmp(r) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }

    current_parts.len() >= required_parts.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison() {
        assert!(version_meets_requirement("2.0", "1.0"));
        assert!(version_meets_requirement("2.1", "2.0"));
        assert!(version_meets_requirement("2.0", "2.0"));
        assert!(!version_meets_requirement("1.9", "2.0"));
        assert!(!version_meets_requirement("1.0", "1.0.1"));
        assert!(version_meets_requirement("1.0.1", "1.0"));
    }

    #[test]
    fn test_consent_type_parsing() {
        assert_eq!(
            "marketing".parse::<ConsentType>().unwrap(),
            ConsentType::Marketing
        );
        assert_eq!(
            "privacy_policy".parse::<ConsentType>().unwrap(),
            ConsentType::PrivacyPolicy
        );
        assert!("invalid".parse::<ConsentType>().is_err());
    }

    #[test]
    fn test_required_consents() {
        assert!(ConsentType::TermsOfService.is_required());
        assert!(ConsentType::PrivacyPolicy.is_required());
        assert!(!ConsentType::Marketing.is_required());
        assert!(!ConsentType::Analytics.is_required());
    }
}
