//! Session model for user session management

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Session status
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "session_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Active and valid
    #[default]
    Active,
    /// Expired naturally
    Expired,
    /// Revoked by user or admin
    Revoked,
    /// Replaced by new session (refresh token rotation)
    Rotated,
}

impl SessionStatus {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Rotated => "rotated",
        }
    }
}

impl std::str::FromStr for SessionStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            "rotated" => Ok(Self::Rotated),
            _ => Err(format!("Unknown status: {}", s)),
        }
    }
}

/// User session
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// User ID
    pub user_id: String,
    /// Session status
    pub status: SessionStatus,
    /// Access token JWT ID
    pub access_token_jti: String,
    /// Refresh token hash (for rotation detection)
    pub refresh_token_hash: String,
    /// Token family for rotation chain
    pub token_family: String,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
    /// Device info (parsed from user agent)
    pub device_info: Option<DeviceInfo>,
    /// Geographic location
    pub location: Option<GeoLocation>,
    /// MFA authenticated in this session
    pub mfa_verified: bool,
    /// MFA verified at
    pub mfa_verified_at: Option<DateTime<Utc>>,
    /// Session created at
    pub created_at: DateTime<Utc>,
    /// Updated at
    pub updated_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity_at: DateTime<Utc>,
    /// Expires at
    pub expires_at: DateTime<Utc>,
    /// Revoked at
    pub revoked_at: Option<DateTime<Utc>>,
    /// Revocation reason
    pub revoked_reason: Option<String>,
}

/// Device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Device type (desktop, mobile, tablet)
    pub device_type: String,
    /// Operating system
    pub os: String,
    /// OS version
    pub os_version: Option<String>,
    /// Browser name
    pub browser: String,
    /// Browser version
    pub browser_version: Option<String>,
    /// Device brand/model (if mobile)
    pub device_model: Option<String>,
    /// Is mobile device
    pub is_mobile: bool,
    /// Is bot/crawler
    pub is_bot: bool,
}

/// Geographic location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLocation {
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: Option<String>,
    /// Country name
    pub country_name: Option<String>,
    /// Region/state
    pub region: Option<String>,
    /// City
    pub city: Option<String>,
    /// Latitude
    pub latitude: Option<f64>,
    /// Longitude
    pub longitude: Option<f64>,
    /// Timezone
    pub timezone: Option<String>,
}

impl Session {
    /// Create a new session
    pub fn new(
        tenant_id: impl Into<String>,
        user_id: impl Into<String>,
        access_token_jti: impl Into<String>,
        refresh_token_hash: impl Into<String>,
        token_family: impl Into<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.into(),
            user_id: user_id.into(),
            status: SessionStatus::Active,
            access_token_jti: access_token_jti.into(),
            refresh_token_hash: refresh_token_hash.into(),
            token_family: token_family.into(),
            ip_address: None,
            user_agent: None,
            device_fingerprint: None,
            device_info: None,
            location: None,
            mfa_verified: false,
            mfa_verified_at: None,
            created_at: now,
            updated_at: now,
            last_activity_at: now,
            expires_at: now + chrono::Duration::days(7),
            revoked_at: None,
            revoked_reason: None,
        }
    }

    /// Set device information
    pub fn with_device(mut self, ip: impl Into<String>, user_agent: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self.user_agent = Some(user_agent.into());
        // Device fingerprint could be hash of IP + User-Agent
        self.device_fingerprint = Some(self.compute_fingerprint());
        self
    }

    /// Compute device fingerprint
    fn compute_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};

        let input = format!(
            "{}:{}",
            self.ip_address.as_deref().unwrap_or(""),
            self.user_agent.as_deref().unwrap_or("")
        );

        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex::encode(&hasher.finalize()[..16]) // First 16 bytes = 32 hex chars
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        self.status == SessionStatus::Active && Utc::now() < self.expires_at
    }

    /// Record activity
    pub fn record_activity(&mut self) {
        self.last_activity_at = Utc::now();
    }

    /// Revoke the session
    pub fn revoke(&mut self, reason: impl Into<String>) {
        self.status = SessionStatus::Revoked;
        self.revoked_at = Some(Utc::now());
        self.revoked_reason = Some(reason.into());
    }

    /// Mark as rotated (new session created via refresh)
    pub fn mark_rotated(&mut self) {
        self.status = SessionStatus::Rotated;
    }

    /// Mark as expired
    pub fn mark_expired(&mut self) {
        if self.status == SessionStatus::Active {
            self.status = SessionStatus::Expired;
        }
    }

    /// Mark MFA as verified
    pub fn mark_mfa_verified(&mut self) {
        self.mfa_verified = true;
        self.mfa_verified_at = Some(Utc::now());
    }

    /// Extend session expiration
    pub fn extend(&mut self, duration: chrono::Duration) {
        self.expires_at = Utc::now() + duration;
    }

    /// Check if session is from the same device (fingerprint match)
    pub fn same_device(&self, other: &Session) -> bool {
        match (&self.device_fingerprint, &other.device_fingerprint) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }
}

impl super::Model for Session {
    fn id(&self) -> &str {
        &self.id
    }

    fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }
}

/// Session list filters
#[derive(Debug, Clone, Default)]
pub struct SessionFilters {
    /// Filter by status
    pub status: Option<SessionStatus>,
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Only active sessions
    pub active_only: bool,
    /// Created after
    pub created_after: Option<DateTime<Utc>>,
    /// Created before
    pub created_before: Option<DateTime<Utc>>,
}

/// Revoke session request
#[derive(Debug, Clone, Deserialize)]
pub struct RevokeSessionRequest {
    /// Reason for revocation
    pub reason: Option<String>,
    /// Revoke all other sessions (logout everywhere)
    pub all_except_current: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new(
            "tenant_123",
            "user_456",
            "jti_789",
            "refresh_hash",
            "family_abc",
        );

        assert_eq!(session.tenant_id, "tenant_123");
        assert_eq!(session.user_id, "user_456");
        assert!(session.is_active());
        assert!(!session.mfa_verified);
    }

    #[test]
    fn test_session_with_device() {
        let session = Session::new(
            "tenant_123",
            "user_456",
            "jti_789",
            "refresh_hash",
            "family_abc",
        )
        .with_device("192.168.1.1", "Mozilla/5.0...");

        assert_eq!(session.ip_address, Some("192.168.1.1".to_string()));
        assert!(session.user_agent.is_some());
        assert!(session.device_fingerprint.is_some());
    }

    #[test]
    fn test_session_revocation() {
        let mut session = Session::new(
            "tenant_123",
            "user_456",
            "jti_789",
            "refresh_hash",
            "family_abc",
        );

        assert!(session.is_active());
        session.revoke("User logged out");
        assert!(!session.is_active());
        assert_eq!(session.status, SessionStatus::Revoked);
        assert!(session.revoked_at.is_some());
    }

    #[test]
    fn test_session_expiration() {
        let mut session = Session::new(
            "tenant_123",
            "user_456",
            "jti_789",
            "refresh_hash",
            "family_abc",
        );

        // Set expiration in the past
        session.expires_at = Utc::now() - chrono::Duration::hours(1);
        assert!(!session.is_active());
    }

    #[test]
    fn test_session_mfa() {
        let mut session = Session::new(
            "tenant_123",
            "user_456",
            "jti_789",
            "refresh_hash",
            "family_abc",
        );

        assert!(!session.mfa_verified);
        session.mark_mfa_verified();
        assert!(session.mfa_verified);
        assert!(session.mfa_verified_at.is_some());
    }

    #[test]
    fn test_device_fingerprint() {
        let session1 = Session::new(
            "tenant_123",
            "user_456",
            "jti_789",
            "refresh_hash",
            "family_abc",
        )
        .with_device("192.168.1.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

        let session2 = Session::new(
            "tenant_123",
            "user_456",
            "jti_790",
            "refresh_hash2",
            "family_abc",
        )
        .with_device("192.168.1.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

        let session3 = Session::new(
            "tenant_123",
            "user_456",
            "jti_791",
            "refresh_hash3",
            "family_def",
        )
        .with_device("192.168.1.2", "Mozilla/5.0 (Macintosh; Intel Mac OS X)");

        assert!(session1.same_device(&session2));
        assert!(!session1.same_device(&session3));
    }
}
