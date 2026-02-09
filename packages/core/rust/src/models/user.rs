//! User model and related types

use crate::error::{Result, VaultError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use validator::Validate;

/// User account status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    /// Email verification pending
    Pending,
    /// Active and can log in
    Active,
    /// Suspended by admin
    Suspended,
    /// Deactivated by user
    Deactivated,
    /// Deleted (soft delete)
    Deleted,
}

impl Default for UserStatus {
    fn default() -> Self {
        Self::Pending
    }
}

impl UserStatus {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deactivated => "deactivated",
            Self::Deleted => "deleted",
        }
    }
}

impl std::str::FromStr for UserStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "deactivated" => Ok(Self::Deactivated),
            "deleted" => Ok(Self::Deleted),
            _ => Err(format!("Unknown status: {}", s)),
        }
    }
}

impl fmt::Display for UserStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserStatus::Pending => write!(f, "pending"),
            UserStatus::Active => write!(f, "active"),
            UserStatus::Suspended => write!(f, "suspended"),
            UserStatus::Deactivated => write!(f, "deactivated"),
            UserStatus::Deleted => write!(f, "deleted"),
        }
    }
}

use std::fmt;

/// User profile information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserProfile {
    /// Full name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Given/first name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    /// Family/last name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Middle name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    /// Nickname
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// Preferred username
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// Profile URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Picture URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    /// Website URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// Gender
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    /// Birthdate (YYYY-MM-DD)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<String>,
    /// Timezone
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    /// Locale (e.g., en-US)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Phone number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// Whether phone number is verified
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    /// Address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    /// Custom attributes
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Physical address
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Address {
    /// Full mailing address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// Street address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    /// City or locality
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// State or province
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Zip or postal code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    /// Country
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// User account
#[derive(Debug, Clone, Default, Serialize, Deserialize, Validate, sqlx::FromRow)]
pub struct User {
    /// Unique identifier
    pub id: String,
    /// Tenant ID
    pub tenant_id: String,
    /// Email address (unique within tenant)
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    /// Whether email is verified
    pub email_verified: bool,
    /// Email verification timestamp
    pub email_verified_at: Option<DateTime<Utc>>,
    /// Hashed password (None for OAuth-only users)
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    /// User status
    pub status: UserStatus,
    /// Profile information
    pub profile: UserProfile,
    /// MFA settings
    pub mfa_enabled: bool,
    /// MFA methods configured
    pub mfa_methods: Vec<MfaMethod>,
    /// Last login timestamp
    pub last_login_at: Option<DateTime<Utc>>,
    /// Last IP address
    pub last_ip: Option<String>,
    /// Failed login attempts
    pub failed_login_attempts: i32,
    /// Lockout until timestamp
    pub locked_until: Option<DateTime<Utc>>,
    /// Password changed timestamp
    pub password_changed_at: Option<DateTime<Utc>>,
    /// Must change password on next login
    pub password_change_required: bool,
    /// Connected OAuth accounts
    pub oauth_connections: Vec<OAuthConnection>,
    /// User metadata (custom JSON)
    pub metadata: serde_json::Value,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
    /// Soft delete timestamp
    pub deleted_at: Option<DateTime<Utc>>,
    /// Wallet address (Ethereum or Solana)
    pub wallet_address: Option<String>,
    /// Chain ID for EVM chains
    pub chain_id: Option<i32>,
    /// When the wallet was verified
    pub wallet_verified_at: Option<DateTime<Utc>>,
    /// Wallet verification method
    pub wallet_verification_method: Option<String>,
}

/// MFA method type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "mfa_method", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum MfaMethod {
    /// Time-based OTP (TOTP)
    Totp,
    /// Email OTP
    Email,
    /// SMS OTP
    Sms,
    /// WebAuthn/Security key
    Webauthn,
    /// Backup codes
    BackupCodes,
}

/// MFA method configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaMethodConfig {
    /// Method type
    pub method: MfaMethod,
    /// Whether this method is enabled
    pub enabled: bool,
    /// When this method was added
    pub added_at: DateTime<Utc>,
    /// Method-specific data
    pub data: MfaMethodData,
}

/// MFA method-specific data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MfaMethodData {
    /// TOTP configuration
    Totp {
        /// Secret key (encrypted)
        secret: String,
        /// Recovery codes (hashed)
        recovery_codes: Vec<String>,
    },
    /// Email configuration
    Email {
        /// Email address used for MFA
        email: String,
    },
    /// SMS configuration
    Sms {
        /// Phone number
        phone_number: String,
    },
    /// WebAuthn configuration
    Webauthn {
        /// Credential ID
        credential_id: String,
        /// Public key
        public_key: String,
        /// AAGUID
        aaguid: Option<String>,
        /// Device name
        name: String,
    },
    /// Backup codes
    BackupCodes {
        /// Hashed backup codes
        codes: Vec<String>,
    },
}

/// OAuth connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthConnection {
    /// Provider (e.g., "google", "github")
    pub provider: String,
    /// Provider's user ID
    pub provider_user_id: String,
    /// Provider username
    pub provider_username: Option<String>,
    /// Email from provider
    pub email: Option<String>,
    /// Access token (encrypted)
    #[serde(skip_serializing)]
    pub access_token: Option<String>,
    /// Refresh token (encrypted)
    #[serde(skip_serializing)]
    pub refresh_token: Option<String>,
    /// Token expiry
    pub token_expires_at: Option<DateTime<Utc>>,
    /// Raw user data from provider
    pub raw_data: Option<serde_json::Value>,
    /// When connection was created
    pub created_at: DateTime<Utc>,
    /// When connection was last used
    pub last_used_at: Option<DateTime<Utc>>,
}

impl User {
    /// Create a new user
    pub fn new(
        tenant_id: impl Into<String>,
        email: impl Into<String>,
        password_hash: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.into(),
            email: email.into(),
            email_verified: false,
            email_verified_at: None,
            password_hash,
            status: UserStatus::Pending,
            profile: UserProfile::default(),
            mfa_enabled: false,
            mfa_methods: Vec::new(),
            last_login_at: None,
            last_ip: None,
            failed_login_attempts: 0,
            locked_until: None,
            password_changed_at: None,
            password_change_required: false,
            oauth_connections: Vec::new(),
            metadata: serde_json::Value::Object(serde_json::Map::new()),
            created_at: now,
            updated_at: now,
            deleted_at: None,
            wallet_address: None,
            chain_id: None,
            wallet_verified_at: None,
            wallet_verification_method: None,
        }
    }

    /// Check if user can authenticate
    pub fn can_authenticate(&self) -> bool {
        matches!(self.status, UserStatus::Active) && !self.is_locked() && self.deleted_at.is_none()
    }

    /// Check if account is locked
    pub fn is_locked(&self) -> bool {
        match self.locked_until {
            Some(locked_until) => Utc::now() < locked_until,
            None => false,
        }
    }

    /// Record failed login attempt
    pub fn record_failed_login(&mut self) {
        self.failed_login_attempts += 1;

        // Lock after 5 failed attempts for 30 minutes
        if self.failed_login_attempts >= 5 {
            self.locked_until = Some(Utc::now() + chrono::Duration::minutes(30));
        }

        self.updated_at = Utc::now();
    }

    /// Record successful login
    pub fn record_successful_login(&mut self, ip: Option<String>) {
        self.failed_login_attempts = 0;
        self.locked_until = None;
        self.last_login_at = Some(Utc::now());
        self.last_ip = ip;
        self.updated_at = Utc::now();
    }

    /// Activate user (after email verification)
    pub fn activate(&mut self) {
        if matches!(self.status, UserStatus::Pending) {
            self.status = UserStatus::Active;
            self.email_verified = true;
            self.email_verified_at = Some(Utc::now());
            self.updated_at = Utc::now();
        }
    }

    /// Suspend user (admin action)
    pub fn suspend(&mut self) {
        self.status = UserStatus::Suspended;
        self.updated_at = Utc::now();
    }

    /// Deactivate user (user-initiated)
    pub fn deactivate(&mut self) {
        self.status = UserStatus::Deactivated;
        self.updated_at = Utc::now();
    }

    /// Soft delete user
    pub fn delete(&mut self) {
        self.status = UserStatus::Deleted;
        self.deleted_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Update password
    pub fn update_password(&mut self, password_hash: impl Into<String>) {
        self.password_hash = Some(password_hash.into());
        self.password_changed_at = Some(Utc::now());
        self.password_change_required = false;
        self.updated_at = Utc::now();
    }

    /// Check if password needs changing
    pub fn password_expired(&self, max_age_days: i64) -> bool {
        match self.password_changed_at {
            Some(changed_at) => {
                let age = Utc::now() - changed_at;
                age.num_days() > max_age_days
            }
            None => true, // Never changed = expired
        }
    }

    /// Add OAuth connection
    pub fn add_oauth_connection(&mut self, connection: OAuthConnection) {
        // Remove existing connection for same provider
        self.oauth_connections
            .retain(|c| c.provider != connection.provider);
        self.oauth_connections.push(connection);
        self.updated_at = Utc::now();
    }

    /// Get OAuth connection by provider
    pub fn get_oauth_connection(&self, provider: &str) -> Option<&OAuthConnection> {
        self.oauth_connections
            .iter()
            .find(|c| c.provider == provider)
    }

    /// Enable MFA method
    pub fn enable_mfa(&mut self, method: MfaMethod) {
        if !self.mfa_methods.contains(&method) {
            self.mfa_methods.push(method);
        }
        self.mfa_enabled = true;
        self.updated_at = Utc::now();
    }

    /// Disable MFA
    pub fn disable_mfa(&mut self) {
        self.mfa_enabled = false;
        self.mfa_methods.clear();
        self.updated_at = Utc::now();
    }

    /// Update profile
    pub fn update_profile(&mut self, profile: UserProfile) {
        self.profile = profile;
        self.updated_at = Utc::now();
    }

    /// Validate email format
    pub fn validate_email(&self) -> Result<()> {
        if self.email.is_empty() {
            return Err(VaultError::validation("Email is required"));
        }

        // Basic email validation regex
        let email_regex = regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
            .expect("Valid regex");

        if !email_regex.is_match(&self.email) {
            return Err(VaultError::validation("Invalid email format"));
        }

        Ok(())
    }
}

impl super::Model for User {
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

/// User creation request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateUserRequest {
    pub tenant_id: String,
    #[validate(email)]
    pub email: String,
    pub password_hash: Option<String>,
    pub email_verified: bool,
    pub profile: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
}

/// User update request
#[derive(Debug, Clone, Default, Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(email)]
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub profile: Option<serde_json::Value>,
    pub status: Option<UserStatus>,
    pub mfa_enabled: Option<bool>,
    pub metadata: Option<serde_json::Value>,
}

/// Change password request
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    #[validate(length(min = 12, message = "New password must be at least 12 characters"))]
    pub new_password: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new("tenant_123", "test@example.com", None);
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.status, UserStatus::Pending);
        assert!(!user.email_verified);
        assert!(user.can_authenticate() == false); // Pending status
    }

    #[test]
    fn test_user_activation() {
        let mut user = User::new("tenant_123", "test@example.com", None);
        user.activate();
        assert_eq!(user.status, UserStatus::Active);
        assert!(user.email_verified);
        assert!(user.can_authenticate());
    }

    #[test]
    fn test_login_attempts() {
        let mut user = User::new("tenant_123", "test@example.com", None);
        user.activate();

        // Record failed attempts
        for _ in 0..5 {
            user.record_failed_login();
        }

        assert!(user.is_locked());
        assert!(!user.can_authenticate());

        // Successful login resets
        user.record_successful_login(None);
        assert!(!user.is_locked());
        assert_eq!(user.failed_login_attempts, 0);
    }

    #[test]
    fn test_password_expiry() {
        let mut user = User::new("tenant_123", "test@example.com", None);

        // No password change = expired
        assert!(user.password_expired(90));

        // Recent change = not expired
        user.update_password("hash123");
        assert!(!user.password_expired(90));
    }

    #[test]
    fn test_oauth_connection() {
        let mut user = User::new("tenant_123", "test@example.com", None);

        let connection = OAuthConnection {
            provider: "google".to_string(),
            provider_user_id: "12345".to_string(),
            provider_username: Some("testuser".to_string()),
            email: Some("test@example.com".to_string()),
            access_token: None,
            refresh_token: None,
            token_expires_at: None,
            raw_data: None,
            created_at: Utc::now(),
            last_used_at: None,
        };

        user.add_oauth_connection(connection);
        assert_eq!(user.oauth_connections.len(), 1);
        assert!(user.get_oauth_connection("google").is_some());
    }
}
