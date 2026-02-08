//! Service Account Model
//!
//! Represents a non-user entity (service, API, IoT device) that can authenticate
//! using client credentials or API keys.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

/// Rate limit configuration for a service account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Requests per second allowed
    pub requests_per_second: u32,
    /// Burst capacity for rate limiting
    pub burst: u32,
}

/// Service account entity for M2M authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccount {
    /// Unique identifier (UUID)
    pub id: String,
    /// Tenant this service account belongs to
    pub tenant_id: String,
    /// Human-readable name
    pub name: String,
    /// Optional description
    pub description: Option<String>,
    /// Client ID for OAuth client credentials flow
    pub client_id: String,
    /// Argon2 hash of client secret
    pub client_secret_hash: String,
    /// Scopes assigned to this service account
    pub scopes: Vec<String>,
    /// Permissions assigned (e.g., "api:read", "api:write")
    pub permissions: Vec<String>,
    /// Rate limit configuration
    pub rate_limit: Option<RateLimitConfig>,
    /// When the service account expires (optional)
    pub expires_at: Option<DateTime<Utc>>,
    /// Last time this account was used
    pub last_used_at: Option<DateTime<Utc>>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Whether the account is active
    pub is_active: bool,
}

/// Service account summary (for list responses, excludes sensitive fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccountSummary {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: Option<String>,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub permissions: Vec<String>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub is_active: bool,
}

impl From<ServiceAccount> for ServiceAccountSummary {
    fn from(sa: ServiceAccount) -> Self {
        Self {
            id: sa.id,
            tenant_id: sa.tenant_id,
            name: sa.name,
            description: sa.description,
            client_id: sa.client_id,
            scopes: sa.scopes,
            permissions: sa.permissions,
            rate_limit_rps: sa.rate_limit.as_ref().map(|r| r.requests_per_second),
            rate_limit_burst: sa.rate_limit.as_ref().map(|r| r.burst),
            expires_at: sa.expires_at,
            last_used_at: sa.last_used_at,
            created_at: sa.created_at,
            is_active: sa.is_active,
        }
    }
}

/// Request to create a new service account
#[derive(Debug, Deserialize, Validate)]
pub struct CreateServiceAccountRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub permissions: Option<Vec<String>>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to update a service account
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateServiceAccountRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    pub description: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub permissions: Option<Vec<String>>,
    pub rate_limit_rps: Option<u32>,
    pub rate_limit_burst: Option<u32>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: Option<bool>,
}

/// Response with credentials (only shown once on creation)
#[derive(Debug, Serialize)]
pub struct ServiceAccountCredentials {
    pub id: String,
    pub client_id: String,
    /// Client secret - ONLY SHOWN ONCE
    pub client_secret: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Context for an authenticated service account (stored in request extensions)
#[derive(Debug, Clone)]
pub struct ServiceAccountContext {
    pub service_account_id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub permissions: Vec<String>,
    pub authenticated_via: AuthenticationMethod,
}

/// How the service account was authenticated
#[derive(Debug, Clone)]
pub enum AuthenticationMethod {
    /// Authenticated via API key
    ApiKey { key_id: String },
    /// Authenticated via OAuth client credentials
    ClientCredentials,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_account_creation() {
        let sa = ServiceAccount {
            id: "test-id".to_string(),
            tenant_id: "tenant-1".to_string(),
            name: "Test Service".to_string(),
            description: Some("A test service".to_string()),
            client_id: "client_123".to_string(),
            client_secret_hash: "hash123".to_string(),
            scopes: vec!["api:read".to_string()],
            permissions: vec!["read:data".to_string()],
            rate_limit: Some(RateLimitConfig {
                requests_per_second: 100,
                burst: 200,
            }),
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
            is_active: true,
        };

        assert_eq!(sa.id, "test-id");
        assert_eq!(sa.tenant_id, "tenant-1");
        assert!(sa.is_active);
    }

    #[test]
    fn test_service_account_summary_conversion() {
        let sa = ServiceAccount {
            id: "test-id".to_string(),
            tenant_id: "tenant-1".to_string(),
            name: "Test Service".to_string(),
            description: None,
            client_id: "client_123".to_string(),
            client_secret_hash: "secret_hash".to_string(),
            scopes: vec!["api:read".to_string()],
            permissions: vec!["read:data".to_string()],
            rate_limit: Some(RateLimitConfig {
                requests_per_second: 50,
                burst: 100,
            }),
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
            is_active: true,
        };

        let summary: ServiceAccountSummary = sa.into();
        assert_eq!(summary.rate_limit_rps, Some(50));
        assert_eq!(summary.rate_limit_burst, Some(100));
    }
}
