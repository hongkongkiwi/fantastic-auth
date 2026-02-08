//! Data models for Vault

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod organization;
pub mod session;
pub mod user;

pub use organization::{Organization, OrganizationMember, OrganizationRole};
pub use session::Session;
pub use user::{User, UserProfile, UserStatus};

/// Common traits for database models
pub trait Model {
    /// Get the unique identifier
    fn id(&self) -> &str;

    /// Get the creation timestamp
    fn created_at(&self) -> DateTime<Utc>;

    /// Get the last update timestamp
    fn updated_at(&self) -> DateTime<Utc>;
}

/// Pagination parameters
#[derive(Debug, Clone, Copy)]
pub struct Pagination {
    /// Page number (1-based)
    pub page: u32,
    /// Items per page
    pub per_page: u32,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: 20,
        }
    }
}

impl Pagination {
    /// Create new pagination
    pub fn new(page: u32, per_page: u32) -> Self {
        Self {
            page: page.max(1),
            per_page: per_page.clamp(1, 100),
        }
    }

    /// Get offset for database query
    pub fn offset(&self) -> i64 {
        ((self.page - 1) * self.per_page) as i64
    }

    /// Get limit for database query
    pub fn limit(&self) -> i64 {
        self.per_page as i64
    }
}

/// Paginated response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paginated<T> {
    /// Items in current page
    pub items: Vec<T>,
    /// Total number of items
    pub total: i64,
    /// Current page
    pub page: u32,
    /// Items per page
    pub per_page: u32,
    /// Total number of pages
    pub total_pages: u32,
}

impl<T> Paginated<T> {
    /// Create new paginated response
    pub fn new(items: Vec<T>, total: i64, page: u32, per_page: u32) -> Self {
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        Self {
            items,
            total,
            page,
            per_page,
            total_pages,
        }
    }
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unique ID
    pub id: String,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Tenant ID
    pub tenant_id: String,
    /// User ID (if applicable)
    pub user_id: Option<String>,
    /// Session ID (if applicable)
    pub session_id: Option<String>,
    /// Action performed
    pub action: String,
    /// Resource type
    pub resource_type: String,
    /// Resource ID
    pub resource_id: String,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Success or failure
    pub success: bool,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

impl AuditLogEntry {
    /// Create new audit log entry
    pub fn new(
        tenant_id: impl Into<String>,
        action: impl Into<String>,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            tenant_id: tenant_id.into(),
            user_id: None,
            session_id: None,
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            ip_address: None,
            user_agent: None,
            success: true,
            error: None,
            metadata: None,
        }
    }

    /// Set user ID
    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Set session ID
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Set IP address
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set user agent
    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = Some(ua.into());
        self
    }

    /// Mark as failed
    pub fn failed(mut self, error: impl Into<String>) -> Self {
        self.success = false;
        self.error = Some(error.into());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, metadata: impl Into<serde_json::Value>) -> Self {
        self.metadata = Some(metadata.into());
        self
    }
}
