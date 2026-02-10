//! Consent Models
//!
//! Database models for consent management.

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::{ConsentType, DataExportStatus, DeletionStatus};

/// Database record for consent versions
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConsentVersionRow {
    pub id: String,
    pub tenant_id: String,
    pub consent_type: ConsentType,
    pub version: String,
    pub title: String,
    pub content: String,
    pub summary: Option<String>,
    pub effective_date: DateTime<Utc>,
    pub url: Option<String>,
    pub is_current: bool,
    pub required: bool,
    pub created_at: DateTime<Utc>,
}

/// Database record for user consents
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserConsentRow {
    pub id: String,
    pub user_id: String,
    pub consent_version_id: String,
    pub granted: bool,
    pub granted_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub jurisdiction: Option<String>,
    pub withdrawn_at: Option<DateTime<Utc>>,
}

/// Database record for data export requests
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DataExportRequestRow {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub status: DataExportStatus,
    pub requested_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub download_url: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

/// Database record for deletion requests
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeletionRequestRow {
    pub id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub status: DeletionStatus,
    pub requested_at: DateTime<Utc>,
    pub scheduled_deletion_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub cancellation_token: String,
    pub reason: Option<String>,
    pub error_message: Option<String>,
}

/// Database record for consent with version info (joined query)
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserConsentWithVersionRow {
    // Consent fields
    pub consent_id: String,
    pub user_id: String,
    pub granted: bool,
    pub granted_at: DateTime<Utc>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    // Version fields
    pub version_id: String,
    pub consent_type: ConsentType,
    pub version: String,
    pub title: String,
    pub effective_date: DateTime<Utc>,
    pub is_current: bool,
    pub required: bool,
}

/// Statistics row for consent dashboard
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ConsentStatsRow {
    pub consent_type: ConsentType,
    pub version: String,
    pub total_users: i64,
    pub granted_count: i64,
    pub withdrawn_count: i64,
    pub pending_count: i64,
}

/// User data for export (profile)
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct UserProfileExport {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub status: String,
    pub profile: serde_json::Value,
    pub mfa_enabled: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Session data for export
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct SessionExport {
    pub id: String,
    pub status: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub device_info: Option<serde_json::Value>,
    pub mfa_verified: bool,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Audit log data for export
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct AuditLogExport {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub metadata: Option<serde_json::Value>,
}

/// Organization membership for export
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct OrganizationExport {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub role: String,
    pub status: String,
    pub joined_at: Option<DateTime<Utc>>,
}

/// OAuth connection for export
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct OAuthConnectionExport {
    pub id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Consent history for export
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct ConsentHistoryExport {
    pub consent_type: String,
    pub version: String,
    pub granted: bool,
    pub granted_at: DateTime<Utc>,
    pub withdrawn_at: Option<DateTime<Utc>>,
    pub ip_address: Option<String>,
}

/// Tenant consent configuration row
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantConsentConfigRow {
    pub tenant_id: String,
    pub deletion_grace_period_days: i32,
    pub export_retention_days: i32,
    pub require_explicit_consent: bool,
    pub default_jurisdiction: String,
    pub cookie_config: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}
